//! The headless `flextunnel client start` session: proxy front-ends (both
//! optional), server-direct port forwards, and the control channel that
//! `flextunnel client control` attaches to.
//!
//! Mirrors the desktop client's per-profile session (`flextunnel-desktop`'s
//! `tunnel.rs`): bind the enabled listeners, run the reconnecting client, poll
//! routes/forward state on a ticker, and serve status/mutation commands — here
//! arriving over the IPC socket instead of a GUI channel.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

use flextunnel_core::forwards::{
    ForwardManager, ForwardState, ForwardStatus, PortForward, disable_failed_forwards,
    validate_label, validate_remote_host,
};
use flextunnel_core::iroh::SecretKey;
use flextunnel_core::proxy::{ClientAuth, ClientConfig, ProxyClient, reserved};
use flextunnel_core::transport::endpoint::{ClientEndpoint, RelayConfig};
use flextunnel_core::transport::paths::{ConnPath, ConnPathKind};
use flextunnel_core::{app, auth, config};

use crate::ipc::{
    self, ForwardRow, ForwardRowState, IpcCmd, Mutation, Phase, StatusSnapshot, WireBridge,
    WireConnPath, WireConnSnapshot, WireCustomRelay, WireForward, WireRoutes,
};
use crate::{forwards as store, instance, lock};

pub async fn run(r: config::ResolvedClient) -> Result<()> {
    let server_node_id = r.server_node_id.clone().context(
        "The client requires a server node id (--server-node-id or server_node_id in the config).",
    )?;
    // A profile's server id never changes, so its prefix is the client's
    // on-disk identity: lock, control socket, and forwards file.
    let key = instance::instance_key(&server_node_id)?;
    let client_key = resolve_client_key(&r)?;
    // The public half is what the server operator needs on their
    // authorized-keys file — never a secret, so log it plainly.
    log::info!("Client auth public key: {}", client_key.public_str());

    // Held for the process lifetime; also what makes removing a stale control
    // socket safe (see ipc.rs).
    let _lock = lock::acquire_client(&key)?;

    // All forwards load disabled (`enabled` is never persisted) — enabling is
    // an explicit per-session action, like the desktop.
    let forwards = store::load(&key)?;
    if let Err(e) = validate_loaded(&forwards) {
        let path = store::forwards_path(&key)?;
        anyhow::bail!("Invalid port forwards in {}: {e}", path.display());
    }
    if !forwards.is_empty() {
        log::info!(
            "Loaded {} port forward(s) (disabled) from {}",
            forwards.len(),
            store::forwards_path(&key)?.display()
        );
    }

    // The routed set (tunnel set) is configured on the server and pushed
    // during the handshake (see ProxyClient::handshake).
    let runtime = build_session(
        r,
        server_node_id,
        SessionAuth::Key(client_key),
        key.clone(),
        forwards,
        true,
    )
    .await?;
    if runtime.state.socks_addr.is_none() && runtime.state.http_addr.is_none() {
        log::info!("No local proxy listeners configured; running in port-forward-only mode");
    }

    // Serve the control socket others attach to; a detaching panel never stops
    // the tunnel, and the loop keeps running when the channel closes.
    drive_session(runtime, move |tx, _initial| {
        ipc::spawn_ipc_server(&key, tx).map(IpcSink::Socket)
    })
    .await
}

/// Resolve the client auth keypair: exactly one of the inline secret or the
/// key file. Normal sessions only — quick mode has no keypair (its credential
/// is the client's endpoint id, allowlisted on the quick server).
fn resolve_client_key(r: &config::ResolvedClient) -> Result<auth::ClientKey> {
    if r.auth_key.is_some() && r.auth_key_file.is_some() {
        anyhow::bail!("Provide only one of auth_key or auth_key_file, not both");
    }
    if let Some(secret) = &r.auth_key {
        auth::ClientKey::from_secret_str(secret.trim()).context("Invalid client secret key")
    } else if let Some(path) = &r.auth_key_file {
        auth::load_client_key_from_file(path).context("Failed to load the client key file")
    } else {
        anyhow::bail!(
            "The client requires an authentication keypair.\n\
             Generate one with: flexaccess-keys generate-auth-key -o <FILE>\n\
             Then pass --auth-key-file <FILE> (or --auth-key <SECRET>), or set \
             auth_key_file/auth_key in the config, and put the key's public half \
             (`flexaccess-keys show-auth-key --private-key-file <FILE>`) on the \
             server's authorized_keys_file."
        )
    }
}

/// The self-contained `flextunnel client start --quick` session: an ephemeral
/// client that runs the live control panel in *this* terminal instead of
/// detaching. Unlike [`run`] it takes **no single-instance lock**, loads and
/// writes **no forwards file**, and exposes **no control socket** — nothing is
/// persisted and nothing else can attach. The panel and the session talk over an
/// in-process channel; quitting the panel drops its sender, closing the channel,
/// which shuts the session down — so the tunnel disconnects rather than detaching.
///
/// `client_secret` is the session's pre-generated identity, whose endpoint id
/// the caller already printed for the user to allowlist on the quick server —
/// that id (not a keypair) is the quick client's credential, so the endpoint must
/// bind with exactly this secret.
pub async fn run_quick(r: config::ResolvedClient, client_secret: SecretKey) -> Result<()> {
    let server_node_id = r.server_node_id.clone().context(
        "The client requires a server node id (--server-node-id or server_node_id in the config).",
    )?;
    // Display-only in quick mode (no lock/socket/forwards paths are derived from
    // it); computing it also validates the id shape up front.
    let key = instance::instance_key(&server_node_id)?;

    // Forwards are ephemeral: none are loaded, none are saved (`persist=false`).
    // They can still be added/edited live in the panel, in memory only.
    let runtime = build_session(
        r,
        server_node_id,
        SessionAuth::Quick(client_secret),
        key,
        Vec::new(),
        false,
    )
    .await?;

    // Drive the self-contained panel over an in-process channel — no socket is
    // exposed, so `flextunnel client control` cannot attach. The panel runs a
    // blocking ratatui loop on a dedicated thread and owns the only command
    // sender: when the user quits, that sender drops, closing the channel, and
    // the loop treats that as the disconnect signal.
    drive_session(runtime, |tx, initial| {
        Ok(IpcSink::Panel(tokio::task::spawn_blocking(move || {
            crate::tui::run_quick_panel(tx, initial)
        })))
    })
    .await
}

/// The assembled per-session runtime that [`drive_session`] consumes: the iroh
/// endpoint, the proxy client and its live routes, the bound proxy listeners,
/// the forward manager + set, and the status/mutation state.
struct SessionRuntime {
    endpoint: ClientEndpoint,
    client: std::sync::Arc<ProxyClient>,
    routes: std::sync::Arc<std::sync::Mutex<flextunnel_core::proxy::TunnelRoutes>>,
    socks_listener: Option<tokio::net::TcpListener>,
    http_listener: Option<tokio::net::TcpListener>,
    fwd_mgr: ForwardManager,
    forwards: Vec<PortForward>,
    state: SessionState,
}

/// How a session authenticates, coupling the credential to the endpoint
/// identity it requires so the two cannot be mixed and matched: a keypair
/// session dials from an anonymous ephemeral endpoint, while a quick session
/// must bind its endpoint to the fixed secret whose id the quick server
/// allowlisted — the id *is* the credential.
enum SessionAuth {
    /// Normal session: signed keypair credential over the client ALPN.
    Key(auth::ClientKey),
    /// Quick session: no keypair; the endpoint binds to this secret and its
    /// endpoint id is checked against the quick server's allowlist.
    Quick(SecretKey),
}

/// Create the iroh endpoint, bind the enabled proxy front-ends (127.0.0.1 only,
/// like the desktop client — unauthenticated, never exposed off-machine), and
/// assemble the [`SessionRuntime`]. Shared by [`run`] and [`run_quick`]; the
/// caller supplies the [`SessionAuth`] (which also determines the endpoint's
/// identity), the instance `key` (status display), the initial `forwards`, and
/// whether mutations `persist`. On any failure past endpoint creation the
/// endpoint is closed gracefully before returning.
async fn build_session(
    r: config::ResolvedClient,
    server_node_id: String,
    auth: SessionAuth,
    key: String,
    forwards: Vec<PortForward>,
    persist: bool,
) -> Result<SessionRuntime> {
    let relay_config = RelayConfig::from_urls_with_token(&r.relay_urls, r.relay_auth_token.clone())
        .context("Invalid relay configuration")?;
    let (endpoint, auth) = match auth {
        SessionAuth::Key(client_key) => (
            ClientEndpoint::create(&relay_config).await,
            ClientAuth::Key(Box::new(client_key)),
        ),
        SessionAuth::Quick(secret) => (
            ClientEndpoint::create_quick(&relay_config, secret).await,
            ClientAuth::QuickAllowlisted,
        ),
    };
    let endpoint = endpoint.context("Failed to create iroh endpoint")?;
    log::info!("flextunnel client Node ID: {}", endpoint.id());

    let socks_bind = r.socks_port.map(|p| SocketAddr::from(([127, 0, 0, 1], p)));
    let http_bind = r.http_port.map(|p| SocketAddr::from(([127, 0, 0, 1], p)));

    let client = std::sync::Arc::new(ProxyClient::new(ClientConfig {
        server_node_id: server_node_id.clone(),
        auth,
        socks_listen: socks_bind,
        http_listen: http_bind,
        relay_urls: r.relay_urls,
        relay_auth_token: r.relay_auth_token,
        auto_reconnect: r.auto_reconnect,
        max_reconnect_attempts: r.max_reconnect_attempts,
    }));
    let routes = client.routes();

    // Bind the enabled proxy front-ends before anything else can take the
    // ports; a taken port fails startup with a clear message.
    let listeners = async {
        let socks = match socks_bind {
            Some(addr) => Some(bind_local(addr, "SOCKS").await?),
            None => None,
        };
        let http = match http_bind {
            Some(addr) => Some(bind_local(addr, "HTTP").await?),
            None => None,
        };
        anyhow::Ok((socks, http))
    };
    let (socks_listener, http_listener) = match listeners.await {
        Ok(listeners) => listeners,
        Err(e) => {
            endpoint.close().await;
            return Err(e);
        }
    };
    let socks_addr = local_addr(&socks_listener);
    let http_addr = local_addr(&http_listener);

    // Forwards run for the whole session (including reconnect gaps); they die
    // with the manager when the session ends.
    let fwd_mgr = ForwardManager::new(
        tokio::runtime::Handle::current(),
        client.server_forwarder(),
        &forwards,
    );

    let state = SessionState {
        instance: key,
        name: r.name,
        server_node_id,
        client_node_id: endpoint.id().to_string(),
        socks_addr,
        http_addr,
        ever_connected: false,
        connected_since: None,
        last_error: None,
        disabled_reasons: HashMap::new(),
        persist,
    };

    Ok(SessionRuntime {
        endpoint,
        client,
        routes,
        socks_listener,
        http_listener,
        fwd_mgr,
        forwards,
        state,
    })
}

/// Where the session's control channel is served — the only structural
/// difference between a normal and a quick session's loop.
enum IpcSink {
    /// A control socket others attach to; a detaching panel never stops the
    /// tunnel, and the guard removes the socket on teardown.
    Socket(ipc::IpcServerGuard),
    /// The self-contained quick panel; when it quits (its sender drops, closing
    /// the channel) the tunnel disconnects, and the task is joined on teardown
    /// so the terminal is always restored.
    Panel(tokio::task::JoinHandle<Result<()>>),
}

/// Run the session's `tokio::select!` loop until the client future ends, a
/// shutdown signal arrives, or (panel only) the control channel closes; then
/// tear everything down and close the endpoint gracefully. `make_sink` wires the
/// freshly-created command channel to its consumer — the control socket server,
/// or the quick panel seeded with `initial` — keeping the differing IPC/panel
/// setup in the wrappers.
async fn drive_session(
    runtime: SessionRuntime,
    make_sink: impl FnOnce(mpsc::Sender<IpcCmd>, StatusSnapshot) -> Result<IpcSink>,
) -> Result<()> {
    let SessionRuntime {
        endpoint,
        client,
        routes,
        socks_listener,
        http_listener,
        mut fwd_mgr,
        mut forwards,
        mut state,
    } = runtime;

    let (ipc_tx, mut ipc_rx) = mpsc::channel(8);
    let initial = state.snapshot(&routes, &forwards, &fwd_mgr);
    // Any failure past endpoint creation must still close the endpoint
    // gracefully (fatal under panic=abort otherwise).
    let sink = match make_sink(ipc_tx, initial) {
        Ok(sink) => sink,
        Err(e) => {
            drop(fwd_mgr);
            endpoint.close().await;
            return Err(e);
        }
    };
    // A closed control channel means the quick panel quit → disconnect. A normal
    // session's IPC accept task holds its sender while the guard lives, so the
    // channel never closes there and the `None` arm stays a no-op.
    let quit_on_ipc_close = matches!(sink, IpcSink::Panel(_));

    let run = client.run_with_optional_listeners(&endpoint, socks_listener, http_listener);
    tokio::pin!(run);
    let mut ticker = tokio::time::interval(Duration::from_millis(500));

    let res = loop {
        tokio::select! {
            res = &mut run => {
                break res.map_err(|e| anyhow::anyhow!("Client error: {e}"));
            }
            _ = ticker.tick() => {
                // A forward whose listener failed to bind flips back off, with
                // the reason retained for its status row (desktop parity).
                let failed = disable_failed_forwards(&mut forwards, &fwd_mgr.statuses());
                if !failed.is_empty() {
                    for (id, reason) in failed {
                        log::warn!("Port forward disabled: {reason}");
                        state.disabled_reasons.insert(id, reason);
                    }
                    fwd_mgr.apply(&forwards);
                }
                state.observe_connection(routes.lock().map(|r| r.connected).unwrap_or(false));
                // The reconnect loop rebuilds the endpoint after repeated
                // failures, which changes the (ephemeral) node id — keep the
                // status display current.
                state.client_node_id = endpoint.id().to_string();
            }
            cmd = ipc_rx.recv() => match cmd {
                Some(IpcCmd::Status(reply)) => {
                    let _ = reply.send(state.snapshot(&routes, &forwards, &fwd_mgr));
                }
                // On-demand connection snapshot: paths + custom-relay /healthz.
                // Off-loaded to a task (never on the polled Status path, and
                // never awaited in-loop) because the health probe does on-demand
                // HTTP; ~3s worst case would otherwise stall the client run,
                // ticker, and shutdown futures this select is also driving.
                Some(IpcCmd::ConnPath(reply)) => {
                    let client = std::sync::Arc::clone(&client);
                    tokio::spawn(async move {
                        let snap = client.connection_snapshot().await;
                        let _ = reply.send(WireConnSnapshot {
                            paths: snap.paths.iter().map(wire_conn_path).collect(),
                            custom_relays: snap
                                .custom_relays
                                .into_iter()
                                .map(|r| WireCustomRelay {
                                    url: r.url,
                                    working: r.working,
                                    error: r.error,
                                })
                                .collect(),
                        });
                    });
                }
                Some(IpcCmd::Mutate(mutation, reply)) => {
                    let result = state
                        .apply_mutation(mutation, &mut forwards, &mut fwd_mgr)
                        .map(|()| state.snapshot(&routes, &forwards, &fwd_mgr));
                    let _ = reply.send(result);
                }
                None => {
                    if quit_on_ipc_close {
                        break Ok(());
                    }
                }
            },
            sig = app::shutdown_signal() => {
                // Break (not return) even on a signal-handler error so the
                // graceful endpoint close below still runs.
                if sig.is_ok() {
                    log::info!("Received shutdown signal, stopping client");
                }
                break sig;
            }
        }
    };

    // Close the channel so a quick panel still waiting on a reply (or issuing
    // its next request) unblocks and exits, tear down forwards and the control
    // socket, then close the endpoint gracefully — bounded so a slow teardown
    // can't leave the client hung (a second signal or timeout forces exit, just
    // like the server). Finally join the panel (if any) so the terminal is
    // restored; a graceful close completes well before that, so the normal path
    // reaches it.
    drop(ipc_rx);
    drop(fwd_mgr);
    let panel = match sink {
        IpcSink::Socket(guard) => {
            drop(guard);
            None
        }
        IpcSink::Panel(panel) => Some(panel),
    };
    crate::close_endpoint_or_exit(&endpoint.endpoint()).await;
    if let Some(panel) = panel {
        let _ = panel.await;
    }
    res
}

/// Bind a local listener, mapping the common taken-port case to a clear error.
async fn bind_local(addr: SocketAddr, label: &str) -> Result<tokio::net::TcpListener> {
    tokio::net::TcpListener::bind(addr).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::AddrInUse {
            anyhow::anyhow!(
                "{label} port {} is already in use — another flextunnel?",
                addr.port()
            )
        } else {
            anyhow::anyhow!("Failed to bind the {label} listener on {addr}: {e}")
        }
    })
}

fn local_addr(listener: &Option<tokio::net::TcpListener>) -> Option<SocketAddr> {
    listener.as_ref().and_then(|l| l.local_addr().ok())
}

/// Session-scoped status/mutation state shared by the ticker and the IPC arms.
struct SessionState {
    /// The server-id-prefix instance key (see `instance.rs`).
    instance: String,
    /// Friendly profile name from the config, display-only.
    name: Option<String>,
    server_node_id: String,
    client_node_id: String,
    socks_addr: Option<SocketAddr>,
    http_addr: Option<SocketAddr>,
    ever_connected: bool,
    connected_since: Option<Instant>,
    last_error: Option<String>,
    /// Retained bind-failure reasons of auto-disabled forwards, keyed by
    /// forward id; cleared when the forward is re-enabled, edited, or deleted.
    disabled_reasons: HashMap<String, String>,
    /// Whether forward Add/Update/Delete are written to the forwards file. True
    /// for a normal session; false for the ephemeral quick panel, whose forwards
    /// live only in memory (nothing is persisted).
    persist: bool,
}

impl SessionState {
    fn observe_connection(&mut self, connected: bool) {
        if connected {
            self.ever_connected = true;
            if self.connected_since.is_none() {
                self.connected_since = Some(Instant::now());
            }
        } else {
            self.connected_since = None;
        }
    }

    fn phase(&self, connected: bool) -> Phase {
        if connected {
            Phase::Connected
        } else if self.ever_connected {
            Phase::Reconnecting
        } else {
            Phase::Connecting
        }
    }

    fn snapshot(
        &self,
        routes: &std::sync::Arc<std::sync::Mutex<flextunnel_core::proxy::TunnelRoutes>>,
        forwards: &[PortForward],
        fwd_mgr: &ForwardManager,
    ) -> StatusSnapshot {
        let routes = routes.lock().map(|r| r.clone()).unwrap_or_default();
        let statuses = fwd_mgr.statuses();
        StatusSnapshot {
            instance: self.instance.clone(),
            name: self.name.clone(),
            phase: self.phase(routes.connected),
            connected_secs: self.connected_since.map(|t| t.elapsed().as_secs()),
            server_node_id: self.server_node_id.clone(),
            client_node_id: self.client_node_id.clone(),
            socks_addr: self.socks_addr,
            http_addr: self.http_addr,
            status_page_host: reserved::STATUS_HOST.to_string(),
            last_error: self.last_error.clone(),
            routes: wire_routes(routes),
            forwards: forwards
                .iter()
                .map(|f| self.forward_row(f, &statuses))
                .collect(),
        }
    }

    fn forward_row(&self, forward: &PortForward, statuses: &[ForwardStatus]) -> ForwardRow {
        let status = statuses.iter().find(|s| s.id == forward.id);
        let (state, error, active, last_conn_error) = if !forward.enabled {
            (
                ForwardRowState::Stopped,
                self.disabled_reasons.get(&forward.id).cloned(),
                0,
                None,
            )
        } else {
            match status {
                // Enabled but not yet reconciled into the manager: starting.
                None => (ForwardRowState::Starting, None, 0, None),
                Some(s) => match &s.state {
                    ForwardState::Starting => {
                        (ForwardRowState::Starting, None, s.active, s.last_conn_error.clone())
                    }
                    ForwardState::Listening => {
                        (ForwardRowState::Listening, None, s.active, s.last_conn_error.clone())
                    }
                    ForwardState::Failed(reason) => (
                        ForwardRowState::Failed,
                        Some(reason.clone()),
                        s.active,
                        s.last_conn_error.clone(),
                    ),
                },
            }
        };
        ForwardRow {
            forward: wire_forward(forward),
            state,
            error,
            active,
            last_conn_error,
        }
    }

    /// Validate and apply one forward mutation, reconcile the listeners, and
    /// persist (Add/Update/Delete only — `enabled` is never persisted, so
    /// toggles don't touch the file).
    fn apply_mutation(
        &mut self,
        mutation: Mutation,
        forwards: &mut Vec<PortForward>,
        fwd_mgr: &mut ForwardManager,
    ) -> Result<(), String> {
        // `enabled` is never persisted, so a toggle is live-only: apply it
        // directly and skip the save path entirely.
        if let Mutation::SetEnabled(id, enabled) = mutation {
            let forward = forwards
                .iter_mut()
                .find(|f| f.id == id)
                .ok_or_else(|| format!("No forward with id {id:?}"))?;
            forward.enabled = enabled;
            if enabled {
                self.disabled_reasons.remove(&id);
            }
            fwd_mgr.apply(forwards);
            return Ok(());
        }

        // Add/Update/Delete change the forward set. Stage the change on a clone
        // and, when persisting, save *first*: if the save fails, live state and
        // listeners are untouched, so they never diverge from the file on disk.
        let mut staged = forwards.clone();
        // The id whose retained bind-failure reason to clear on commit (an
        // edit or delete supersedes it); `None` for an add.
        let reason_to_clear = match mutation {
            Mutation::Add(wire) => {
                let mut forward = validated(wire, &staged, None)?;
                if forward.id.is_empty() {
                    forward.id = PortForward::new_id();
                } else if staged.iter().any(|f| f.id == forward.id) {
                    return Err(format!("A forward with id {:?} already exists", forward.id));
                }
                staged.push(forward);
                None
            }
            Mutation::Update(wire) => {
                let id = wire.id.clone();
                let forward = validated(wire, &staged, Some(&id))?;
                let slot = staged
                    .iter_mut()
                    .find(|f| f.id == id)
                    .ok_or_else(|| format!("No forward with id {id:?}"))?;
                *slot = forward;
                Some(id)
            }
            Mutation::Delete(id) => {
                let before = staged.len();
                staged.retain(|f| f.id != id);
                if staged.len() == before {
                    return Err(format!("No forward with id {id:?}"));
                }
                Some(id)
            }
            Mutation::SetEnabled(..) => unreachable!("handled above"),
        };

        if self.persist
            && let Err(e) = store::save(&self.instance, &staged)
        {
            log::warn!("Failed to persist port forwards: {e:#}");
            return Err(format!("Failed to save forwards: {e:#}"));
        }

        // Committed: swap in the staged set, reconcile the listeners, and only
        // now apply the matching `disabled_reasons` update.
        *forwards = staged;
        fwd_mgr.apply(forwards);
        if let Some(id) = reason_to_clear {
            self.disabled_reasons.remove(&id);
        }
        Ok(())
    }
}

/// Reject a persisted forwards file that breaks the invariants the running
/// client and the TUI assume: nonempty and unique ids, valid remote hosts and
/// labels, and nonzero, unique local ports (plus nonzero remote ports). The
/// file is program-written (only by the running client, always after
/// [`validated`]), so a violation means corruption or a hand-edit — treated
/// like a corrupt config: a startup error, not a silent load.
fn validate_loaded(forwards: &[PortForward]) -> Result<(), String> {
    let mut seen_ids = std::collections::HashSet::new();
    let mut seen_ports = std::collections::HashSet::new();
    for f in forwards {
        if f.id.is_empty() {
            return Err("a forward has an empty id".into());
        }
        if !seen_ids.insert(f.id.as_str()) {
            return Err(format!("duplicate forward id {:?}", f.id));
        }
        validate_label(&f.label).map_err(|e| format!("forward {:?}: {e}", f.id))?;
        validate_remote_host(&f.remote_host).map_err(|e| format!("forward {:?}: {e}", f.id))?;
        if f.local_port == 0 {
            return Err(format!("forward {:?} has a local port of 0", f.id));
        }
        if f.remote_port == 0 {
            return Err(format!("forward {:?} has a remote port of 0", f.id));
        }
        if !seen_ports.insert(f.local_port) {
            return Err(format!("duplicate local port {}", f.local_port));
        }
    }
    Ok(())
}

/// Server-side (authoritative) validation of a wire forward; the TUI form
/// runs the same core validators for instant feedback.
fn validated(
    wire: WireForward,
    forwards: &[PortForward],
    editing_id: Option<&str>,
) -> Result<PortForward, String> {
    let label = validate_label(&wire.label)?;
    let remote_host = validate_remote_host(&wire.remote_host)?;
    if wire.local_port == 0 {
        return Err("Local port must be 1-65535".into());
    }
    if wire.remote_port == 0 {
        return Err("Remote port must be 1-65535".into());
    }
    if let Some(owner) = forwards
        .iter()
        .filter(|f| editing_id != Some(f.id.as_str()))
        .find(|f| f.local_port == wire.local_port)
    {
        return Err(format!(
            "Local port {} is already used by {}",
            wire.local_port,
            owner.display_name()
        ));
    }
    Ok(PortForward {
        id: wire.id,
        label,
        local_port: wire.local_port,
        remote_host,
        remote_port: wire.remote_port,
        enabled: wire.enabled,
    })
}

fn wire_forward(f: &PortForward) -> WireForward {
    WireForward {
        id: f.id.clone(),
        label: f.label.clone(),
        local_port: f.local_port,
        remote_host: f.remote_host.clone(),
        remote_port: f.remote_port,
        enabled: f.enabled,
    }
}

fn wire_conn_path(p: &ConnPath) -> WireConnPath {
    WireConnPath {
        kind: match p.kind {
            ConnPathKind::Direct => "direct",
            ConnPathKind::Relay => "relay",
            ConnPathKind::Other => "other",
        }
        .to_string(),
        display: p.display.clone(),
        selected: p.selected,
    }
}

fn wire_routes(routes: flextunnel_core::proxy::TunnelRoutes) -> WireRoutes {
    WireRoutes {
        domains: routes.domains,
        cidrs: routes.cidrs,
        host_aliases: routes.host_aliases,
        dns_forwards: routes.dns_forwards,
        bridges: routes
            .bridges
            .into_iter()
            .map(|b| WireBridge {
                name: b.name,
                endpoint_id: b.endpoint_id,
                domains: b.domains,
                cidrs: b.cidrs,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(id: &str, local_port: u16) -> WireForward {
        WireForward {
            id: id.into(),
            label: String::new(),
            local_port,
            remote_host: "db.internal".into(),
            remote_port: 5432,
            enabled: false,
        }
    }

    fn existing(id: &str, local_port: u16) -> PortForward {
        PortForward {
            id: id.into(),
            label: String::new(),
            local_port,
            remote_host: "other.internal".into(),
            remote_port: 80,
            enabled: false,
        }
    }

    #[test]
    fn validated_enforces_ports_host_and_uniqueness() {
        let current = vec![existing("a", 5000)];

        assert!(validated(wire("", 5001), &current, None).is_ok());
        assert!(validated(wire("", 0), &current, None).is_err());
        assert!(validated(wire("", 5000), &current, None).is_err(), "taken port");
        // Updating the owner itself may keep its port.
        assert!(validated(wire("a", 5000), &current, Some("a")).is_ok());

        let mut bad_host = wire("", 5001);
        bad_host.remote_host = "bad..host".into();
        assert!(validated(bad_host, &current, None).is_err());

        let mut bad_remote = wire("", 5001);
        bad_remote.remote_port = 0;
        assert!(validated(bad_remote, &current, None).is_err());
    }

    #[test]
    fn validate_loaded_rejects_broken_persisted_data() {
        let ok = vec![existing("a", 5000), existing("b", 5001)];
        assert!(validate_loaded(&ok).is_ok());

        assert!(validate_loaded(&[existing("", 5000)]).is_err(), "empty id");
        assert!(
            validate_loaded(&[existing("a", 5000), existing("a", 5002)]).is_err(),
            "duplicate id"
        );
        assert!(
            validate_loaded(&[existing("a", 5000), existing("b", 5000)]).is_err(),
            "duplicate local port"
        );
        assert!(validate_loaded(&[existing("a", 0)]).is_err(), "zero local port");

        let mut zero_remote = existing("a", 5000);
        zero_remote.remote_port = 0;
        assert!(validate_loaded(&[zero_remote]).is_err(), "zero remote port");

        let mut bad_host = existing("a", 5000);
        bad_host.remote_host = "bad..host".into();
        assert!(validate_loaded(&[bad_host]).is_err(), "bad host");
    }

    #[test]
    fn host_and_label_are_normalized() {
        let mut w = wire("", 5001);
        w.label = "  db  ".into();
        w.remote_host = " [2001:db8::1] ".into();
        let f = validated(w, &[], None).unwrap();
        assert_eq!(f.label, "db");
        assert_eq!(f.remote_host, "2001:db8::1");
    }

    fn session_state(instance: &str, persist: bool) -> SessionState {
        SessionState {
            instance: instance.into(),
            name: None,
            server_node_id: "server".into(),
            client_node_id: "client".into(),
            socks_addr: None,
            http_addr: None,
            ever_connected: false,
            connected_since: None,
            last_error: None,
            disabled_reasons: HashMap::new(),
            persist,
        }
    }

    /// The quick panel edits forwards in memory only: an Add applies to the live
    /// set but writes no `forwards-<key>.json`. (With `persist=false` nothing is
    /// written, so on success this touches no disk; the file is removed
    /// defensively in case a regression re-enables the save.)
    #[tokio::test]
    async fn quick_session_does_not_persist_forward_edits() {
        use flextunnel_core::proxy::{ClientAuth, ClientConfig, ProxyClient};

        let key = "quickpersisttestkey0";
        let path = store::forwards_path(key).unwrap();
        let _ = std::fs::remove_file(&path);

        let client = ProxyClient::new(ClientConfig {
            server_node_id: "server".into(),
            auth: ClientAuth::QuickAllowlisted,
            socks_listen: None,
            http_listen: None,
            relay_urls: Vec::new(),
            relay_auth_token: None,
            auto_reconnect: false,
            max_reconnect_attempts: None,
        });
        let mut fwd_mgr = ForwardManager::new(
            tokio::runtime::Handle::current(),
            client.server_forwarder(),
            &[],
        );
        let mut state = session_state(key, false);

        let mut forwards = Vec::new();
        state
            .apply_mutation(Mutation::Add(wire("", 5555)), &mut forwards, &mut fwd_mgr)
            .expect("in-memory add should succeed");
        assert_eq!(forwards.len(), 1, "the forward is applied in memory");
        assert!(!path.exists(), "quick mode must not write the forwards file");

        let _ = std::fs::remove_file(&path);
    }
}
