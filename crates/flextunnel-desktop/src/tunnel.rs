//! Background tunnel controller: a supervisor thread routing UI commands to
//! one session per connected profile, each on its own OS thread running its
//! own Tokio runtime whose threads are named `tunnel-<profile>` — so every
//! log line a session emits (core internals included) is attributed to its
//! profile by thread name (see `logging`). Status is published as per-profile
//! snapshots the UI polls each frame. Each session owns its `ProxyClient`
//! future, so dropping it (disconnect/shutdown) tears down the accept loops
//! and the connection manager together, followed by a graceful endpoint
//! close.

use crate::config::Profile;
use flextunnel_core::forwards::{ForwardManager, ForwardStatus, PortForward};
use flextunnel_core::proxy::{ClientAuth, ClientConfig, ProxyClient, TunnelRoutes};
use flextunnel_core::transport::endpoint::{RelayConfig, create_client_endpoint};
use flextunnel_core::transport::paths::ConnectionSnapshot;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

pub type ProfileId = String;

/// Bound on the GUI thread's wait for a connection-path reply (see
/// [`Controller::query_conn_path`]). Must exceed the custom-relay `/healthz`
/// probe budget (relays checked in parallel, ~3s worst case) the session now
/// awaits before replying; it exists to fail open (empty result) rather than
/// hang if a session stalls.
const CONN_PATH_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Phase {
    Idle,
    Connecting,
    Connected,
    Reconnecting,
    Failed,
}

#[derive(Clone)]
pub struct Snapshot {
    pub phase: Phase,
    pub connected_since: Option<Instant>,
    pub socks_addr: Option<SocketAddr>,
    pub http_addr: Option<SocketAddr>,
    pub routes: TunnelRoutes,
    pub last_error: Option<String>,
    /// Live status per running forward; empty while no session runs, which the
    /// UI renders as "stopped".
    pub forwards: Vec<ForwardStatus>,
}

impl Default for Snapshot {
    fn default() -> Self {
        Self {
            phase: Phase::Idle,
            connected_since: None,
            socks_addr: None,
            http_addr: None,
            routes: TunnelRoutes::default(),
            last_error: None,
            forwards: Vec::new(),
        }
    }
}

impl Snapshot {
    /// Shared idle snapshot for profiles that never ran a session, so views
    /// can borrow a `&Snapshot` uniformly.
    pub fn empty() -> &'static Snapshot {
        static EMPTY: std::sync::OnceLock<Snapshot> = std::sync::OnceLock::new();
        EMPTY.get_or_init(Snapshot::default)
    }
}

enum Command {
    /// Start a session for the profile, authenticating with the given secret
    /// key (resolved by the UI from the profile's shared auth-key reference).
    Connect(Box<Profile>, String),
    Disconnect(ProfileId),
    /// Replace one profile's desired forward list (the UI sends the full list
    /// after every add/edit/delete/toggle); applied live mid-session.
    SetForwards(ProfileId, Vec<PortForward>),
    /// Disconnect and drop the profile's snapshot slot (profile deleted).
    RemoveProfile(ProfileId),
    /// One-shot request for the profile's current iroh connection path(s),
    /// answered on the reply channel (the UI's connection-path CTA). Empty when
    /// no session is running. A `std` channel (not tokio `oneshot`) so the GUI
    /// caller can wait with a bounded [`std::sync::mpsc::Receiver::recv_timeout`].
    QueryConnPath(ProfileId, std::sync::mpsc::Sender<ConnectionSnapshot>),
    Shutdown,
}

enum SessionCmd {
    Disconnect,
    SetForwards(Vec<PortForward>),
    /// Answer the reply channel with the live connection's path snapshot, once.
    QueryConnPath(std::sync::mpsc::Sender<ConnectionSnapshot>),
    Shutdown,
}

type SharedSnapshots = Arc<Mutex<HashMap<ProfileId, Snapshot>>>;

/// One profile's slot in the shared snapshot map, written by its session task.
#[derive(Clone)]
struct SnapshotSlot {
    shared: SharedSnapshots,
    id: ProfileId,
}

impl SnapshotSlot {
    fn update<F: FnOnce(&mut Snapshot)>(&self, f: F) {
        let mut map = match self.shared.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        f(map.entry(self.id.clone()).or_default());
    }
}

pub struct Controller {
    tx: mpsc::Sender<Command>,
    shared: SharedSnapshots,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Controller {
    pub fn start() -> Self {
        let (tx, rx) = mpsc::channel(16);
        let shared: SharedSnapshots = Arc::new(Mutex::new(HashMap::new()));
        let worker_shared = shared.clone();
        // The supervisor only routes commands; sessions get their own
        // runtimes, so a single-threaded one suffices here.
        let thread = std::thread::Builder::new()
            .name("tunnel".into())
            .spawn(move || {
                match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                    Ok(rt) => rt.block_on(run_loop(rx, worker_shared)),
                    Err(e) => log::error!("Failed to build the Tokio runtime: {e:#}"),
                }
            })
            .expect("spawn tunnel thread");
        Self {
            tx,
            shared,
            thread: Some(thread),
        }
    }

    pub fn snapshots(&self) -> HashMap<ProfileId, Snapshot> {
        self.shared
            .lock()
            .map(|s| s.clone())
            .unwrap_or_else(|poisoned| poisoned.into_inner().clone())
    }

    pub fn connect(&self, profile: Profile, auth_key: String) {
        let _ = self
            .tx
            .blocking_send(Command::Connect(Box::new(profile), auth_key));
    }

    pub fn disconnect(&self, id: &str) {
        let _ = self.tx.blocking_send(Command::Disconnect(id.into()));
    }

    pub fn set_forwards(&self, id: &str, forwards: Vec<PortForward>) {
        let _ = self
            .tx
            .blocking_send(Command::SetForwards(id.into(), forwards));
    }

    pub fn remove_profile(&self, id: &str) {
        let _ = self.tx.blocking_send(Command::RemoveProfile(id.into()));
    }

    /// Fetch the profile's current iroh connection path(s), once. Returns empty
    /// when no session is running, the request can't be sent, or the session
    /// doesn't answer within [`CONN_PATH_TIMEOUT`]. The round-trip is a channel
    /// hop (normally sub-millisecond), but the deadline is what guarantees a
    /// wedged session can never freeze the GUI thread calling this from
    /// `App::update`.
    pub fn query_conn_path(&self, id: &str) -> ConnectionSnapshot {
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        if self
            .tx
            .blocking_send(Command::QueryConnPath(id.into(), reply_tx))
            .is_err()
        {
            return ConnectionSnapshot::default();
        }
        reply_rx.recv_timeout(CONN_PATH_TIMEOUT).unwrap_or_default()
    }

    /// Stop all sessions and join the worker thread (blocks briefly for the
    /// bounded graceful endpoint closes).
    pub fn shutdown(&mut self) {
        let _ = self.tx.blocking_send(Command::Shutdown);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Bind a local listener, mapping the common taken-port case to a clear
/// session error.
async fn bind_local(addr: SocketAddr, label: &str) -> Result<tokio::net::TcpListener, String> {
    tokio::net::TcpListener::bind(addr).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::AddrInUse {
            format!("{label} port {} is already in use — another flextunnel?", addr.port())
        } else {
            format!("Failed to bind the {label} listener on {addr}: {e}")
        }
    })
}

struct SessionHandle {
    tx: mpsc::Sender<SessionCmd>,
    /// Resolves when the session's thread finishes (its receiver dropping
    /// also marks `tx` closed).
    done: tokio::sync::oneshot::Receiver<()>,
    /// For the supervisor's duplicate-server guard and its error message.
    server_node_id: String,
    profile_name: String,
}

/// Spawn one profile's session on its own OS thread with its own runtime, all
/// threads named `tunnel-<profile>` so the logger can attribute every line
/// the session emits. `None` when the thread could not be spawned (the
/// snapshot is set to Failed instead).
fn spawn_session(
    profile: Profile,
    auth_key: String,
    shared: &SharedSnapshots,
) -> Option<SessionHandle> {
    let (tx, session_rx) = mpsc::channel(8);
    let (done_tx, done) = tokio::sync::oneshot::channel();
    let slot = SnapshotSlot {
        shared: shared.clone(),
        id: profile.id.clone(),
    };
    let error_slot = slot.clone();
    let server_node_id = profile.server_node_id.clone();
    let profile_name = profile.name.clone();
    let thread_name = format!("tunnel-{}", profile.name);
    let runtime_name = thread_name.clone();
    let spawned = std::thread::Builder::new().name(thread_name).spawn(move || {
        // One worker is plenty for a tunnel session; multi_thread (rather
        // than current_thread) keeps the runtime semantics identical to the
        // other flextunnel binaries.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name(runtime_name)
            .enable_all()
            .build();
        match runtime {
            Ok(rt) => rt.block_on(run_session(profile, auth_key, session_rx, slot)),
            Err(e) => {
                log::error!("Failed to build the session runtime: {e:#}");
                slot.update(|s| {
                    s.phase = Phase::Failed;
                    s.last_error = Some(format!("Failed to start: {e:#}"));
                });
            }
        }
        let _ = done_tx.send(());
    });
    match spawned {
        Ok(_) => Some(SessionHandle {
            tx,
            done,
            server_node_id,
            profile_name,
        }),
        Err(e) => {
            log::error!("Failed to spawn the session thread: {e:#}");
            error_slot.update(|s| {
                s.phase = Phase::Failed;
                s.last_error = Some(format!("Failed to start: {e:#}"));
            });
            None
        }
    }
}

/// Supervisor: routes profile-scoped commands to per-profile sessions.
async fn run_loop(mut rx: mpsc::Receiver<Command>, shared: SharedSnapshots) {
    let mut sessions: HashMap<ProfileId, SessionHandle> = HashMap::new();
    loop {
        let cmd = rx.recv().await;
        // An ended session drops its receiver, closing the sender.
        sessions.retain(|_, handle| !handle.tx.is_closed());
        match cmd {
            Some(Command::Connect(profile, auth_key)) => {
                if sessions.contains_key(&profile.id) {
                    log::warn!("Profile \"{}\" is already running a session", profile.name);
                    continue;
                }
                // Backend duplicate-server guard: whatever path asked for the
                // connection, never run two sessions against one server.
                if let Some(other) = sessions
                    .values()
                    .find(|h| h.server_node_id == profile.server_node_id)
                {
                    let reason = format!(
                        "Profile \"{}\" is already connected to this server",
                        other.profile_name
                    );
                    log::error!("Not connecting \"{}\": {reason}", profile.name);
                    SnapshotSlot {
                        shared: shared.clone(),
                        id: profile.id.clone(),
                    }
                    .update(|s| {
                        *s = Snapshot {
                            phase: Phase::Failed,
                            last_error: Some(reason),
                            ..Snapshot::default()
                        };
                    });
                    continue;
                }
                let id = profile.id.clone();
                if let Some(handle) = spawn_session(*profile, auth_key, &shared) {
                    sessions.insert(id, handle);
                }
            }
            Some(Command::Disconnect(id)) => {
                if let Some(handle) = sessions.get(&id) {
                    let _ = handle.tx.send(SessionCmd::Disconnect).await;
                }
            }
            Some(Command::SetForwards(id, forwards)) => {
                if let Some(handle) = sessions.get(&id) {
                    let _ = handle.tx.send(SessionCmd::SetForwards(forwards)).await;
                }
                // No session: nothing to do — forwards travel inside the
                // profile on the next Connect.
            }
            Some(Command::QueryConnPath(id, reply)) => {
                if let Some(handle) = sessions.get(&id) {
                    let _ = handle.tx.send(SessionCmd::QueryConnPath(reply)).await;
                }
                // No session: `reply` drops, and the caller gets an empty Vec.
            }
            Some(Command::RemoveProfile(id)) => {
                if let Some(handle) = sessions.remove(&id) {
                    let _ = handle.tx.send(SessionCmd::Disconnect).await;
                    // Drop the slot only after the session's final writes, or
                    // they would recreate it.
                    let shared = shared.clone();
                    tokio::spawn(async move {
                        let _ = handle.done.await;
                        remove_slot(&shared, &id);
                    });
                } else {
                    remove_slot(&shared, &id);
                }
            }
            Some(Command::Shutdown) | None => break,
        }
    }
    // Bounded grace so quitting stays responsive: ask every session to stop,
    // give the graceful endpoint closes a shared deadline, then return — the
    // process is going away anyway.
    for handle in sessions.values() {
        let _ = handle.tx.send(SessionCmd::Shutdown).await;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    for (_, handle) in sessions {
        let _ = tokio::time::timeout_at(deadline, handle.done).await;
    }
}

fn remove_slot(shared: &SharedSnapshots, id: &str) {
    let mut map = match shared.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    map.remove(id);
}

/// Publish the manager's current per-forward statuses to the snapshot.
fn refresh_forward_statuses(slot: &SnapshotSlot, fwd_mgr: &ForwardManager) {
    let statuses = fwd_mgr.statuses();
    slot.update(|s| s.forwards = statuses);
}

async fn run_session(
    profile: Profile,
    auth_key: String,
    mut rx: mpsc::Receiver<SessionCmd>,
    slot: SnapshotSlot,
) {
    let mut forwards = profile.forwards.clone();
    let socks_addr = profile
        .socks_port
        .map(|port| SocketAddr::from(([127, 0, 0, 1], port)));
    let http_addr = profile.http_port.map(|p| SocketAddr::from(([127, 0, 0, 1], p)));
    slot.update(|s| {
        *s = Snapshot {
            phase: Phase::Connecting,
            socks_addr,
            http_addr,
            ..Snapshot::default()
        };
    });

    // Endpoint creation can block for up to ~10s (the relay online-wait), so
    // it races the command channel — otherwise a Disconnect or app quit issued
    // during it would stall until it finished. It runs as a spawned task
    // rather than a raced future because cancelling it by drop could drop a
    // bound endpoint without `close()`, which is fatal under panic=abort (see
    // the CLI's run_client); on a stop the task finishes on its own and the
    // endpoint is closed gracefully.
    let relay_config = match RelayConfig::from_urls_with_token(
        &profile.relay_urls,
        profile.relay_auth_token.clone(),
    ) {
        Ok(relay_config) => relay_config,
        Err(e) => {
            log::error!("Invalid relay configuration: {e:#}");
            slot.update(|s| {
                s.phase = Phase::Failed;
                s.last_error = Some(format!("{e:#}"));
            });
            return;
        }
    };
    // The key form validated the secret on save, but a corrupted keychain
    // entry can still surface here — fail the session cleanly rather than
    // panic.
    let client_key = match flextunnel_core::auth::ClientKey::from_secret_str(auth_key.trim()) {
        Ok(key) => key,
        Err(e) => {
            log::error!("Invalid client auth key: {e:#}");
            slot.update(|s| {
                s.phase = Phase::Failed;
                s.last_error = Some(format!("Invalid client auth key: {e:#}"));
            });
            return;
        }
    };
    let mut create = tokio::spawn({
        let relay_config = relay_config.clone();
        async move { create_client_endpoint(&relay_config).await }
    });
    let endpoint = loop {
        tokio::select! {
            created = &mut create => match created.map_err(anyhow::Error::from) {
                Ok(Ok(endpoint)) => break endpoint,
                Ok(Err(e)) | Err(e) => {
                    log::error!("Failed to create the iroh endpoint: {e:#}");
                    slot.update(|s| {
                        s.phase = Phase::Failed;
                        s.last_error = Some(format!("{e:#}"));
                    });
                    return;
                }
            },
            cmd = rx.recv() => match cmd {
                Some(SessionCmd::Disconnect) => {
                    log::info!("Disconnecting \"{}\"", profile.name);
                    slot.update(|s| s.phase = Phase::Idle);
                    // The UI already shows Idle and this session makes no
                    // further snapshot writes, so release the command channel
                    // now — an immediate reconnect may start a fresh session
                    // while this thread lingers briefly (bounded — the
                    // session runtime dies with the thread, so a detached
                    // close task would be cut off) to close the endpoint
                    // gracefully when creation finishes quickly.
                    drop(rx);
                    let _ = tokio::time::timeout(Duration::from_secs(2), async {
                        if let Ok(Ok(endpoint)) = create.await {
                            endpoint.close().await;
                        }
                    })
                    .await;
                    return;
                }
                Some(SessionCmd::SetForwards(f)) => forwards = f,
                // No connection yet during endpoint creation — report none.
                Some(SessionCmd::QueryConnPath(reply)) => {
                    let _ = reply.send(ConnectionSnapshot::default());
                }
                Some(SessionCmd::Shutdown) | None => {
                    // Bounded grace so quitting stays responsive: close
                    // cleanly when creation finishes quickly, otherwise just
                    // exit — the process is going away anyway.
                    let _ = tokio::time::timeout(Duration::from_secs(2), async {
                        if let Ok(Ok(endpoint)) = create.await {
                            endpoint.close().await;
                        }
                    })
                    .await;
                    return;
                }
            }
        }
    };
    log::info!(
        "flextunnel client node id for \"{}\": {}",
        profile.name,
        endpoint.id()
    );

    let client = ProxyClient::new(ClientConfig {
        server_node_id: profile.server_node_id.clone(),
        auth: ClientAuth::Key(Box::new(client_key)),
        socks_listen: socks_addr,
        http_listen: http_addr,
        relay_urls: profile.relay_urls.clone(),
        relay_auth_token: profile.relay_auth_token.clone(),
        auto_reconnect: true,
        max_reconnect_attempts: None,
    });
    let routes = client.routes();

    // Bind enabled proxy front-ends before any forward listener exists. A
    // taken proxy port fails the session before forwards come up.
    let listeners = async {
        let socks = match socks_addr {
            Some(addr) => Some(bind_local(addr, "SOCKS").await?),
            None => None,
        };
        let http = match http_addr {
            Some(addr) => Some(bind_local(addr, "HTTP").await?),
            None => None,
        };
        Ok::<_, String>((socks, http))
    };
    let (socks_listener, http_listener) = match listeners.await {
        Ok(listeners) => listeners,
        Err(reason) => {
            log::error!("{reason}");
            slot.update(|s| {
                s.phase = Phase::Failed;
                s.last_error = Some(reason);
            });
            endpoint.close().await;
            return;
        }
    };

    // Forwards run for the whole session (including reconnect gaps — the SOCKS
    // listener above stays bound); they die with the manager when the session
    // ends.
    let mut fwd_mgr = ForwardManager::new(
        tokio::runtime::Handle::current(),
        client.server_forwarder(),
        &forwards,
    );

    let run = client.run_with_optional_listeners(&endpoint, socks_listener, http_listener);
    tokio::pin!(run);
    let mut ticker = tokio::time::interval(Duration::from_millis(500));
    let mut ever_connected = false;

    loop {
        tokio::select! {
            res = &mut run => {
                match res {
                    Ok(()) => slot.update(|s| s.phase = Phase::Idle),
                    Err(e) => {
                        log::error!("Client error: {e}");
                        slot.update(|s| {
                            s.phase = Phase::Failed;
                            s.last_error = Some(e.to_string());
                        });
                    }
                }
                break;
            }
            _ = ticker.tick() => {
                let routes = routes
                    .lock()
                    .map(|r| r.clone())
                    .unwrap_or_default();
                ever_connected |= routes.connected;
                slot.update(|s| {
                    if routes.connected {
                        if s.phase != Phase::Connected {
                            s.connected_since = Some(Instant::now());
                        }
                        s.phase = Phase::Connected;
                    } else {
                        s.connected_since = None;
                        s.phase = if ever_connected {
                            Phase::Reconnecting
                        } else {
                            Phase::Connecting
                        };
                    }
                    s.routes = routes;
                });
                refresh_forward_statuses(&slot, &fwd_mgr);
            }
            cmd = rx.recv() => match cmd {
                Some(SessionCmd::Disconnect) => {
                    log::info!("Disconnecting \"{}\"", profile.name);
                    slot.update(|s| s.phase = Phase::Idle);
                    break;
                }
                Some(SessionCmd::SetForwards(f)) => {
                    forwards = f;
                    fwd_mgr.apply(&forwards);
                    refresh_forward_statuses(&slot, &fwd_mgr);
                }
                Some(SessionCmd::QueryConnPath(reply)) => {
                    let _ = reply.send(client.connection_snapshot().await);
                }
                Some(SessionCmd::Shutdown) | None => {
                    slot.update(|s| s.phase = Phase::Idle);
                    break;
                }
            }
        }
    }

    // The select loop is done with `run`; dropping it cancels the client.
    // Tear the forward listeners down with the session so their rows read
    // "stopped" immediately, then close the endpoint gracefully before it is
    // dropped (see the CLI's run_client for why an ungraceful drop is fatal
    // under panic=abort).
    drop(fwd_mgr);
    endpoint.close().await;
    slot.update(|s| {
        s.routes.connected = false;
        s.connected_since = None;
        s.forwards.clear();
    });
}
