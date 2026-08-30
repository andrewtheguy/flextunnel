//! Server-direct local TCP port forwarding.
//!
//! Each configured loopback listener opens a data bi-stream on the client's
//! authenticated iroh connection and sends the target directly to the server.
//! No local SOCKS5 listener or handshake is involved. The server remains the
//! authority: it enforces its routed set before resolving or dialing the target.
//!
//! A forward binds both loopback stacks (`127.0.0.1` and `[::1]`). Each stack
//! binds and recovers independently — one stack stuck reclaiming its port never
//! blocks accepts on the other — and concurrent relays are capped per forward.

use super::client::{AcceptOutcome, AcceptRetry, ServerForwarder};
use super::signaling::Target;
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Handle;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::{JoinHandle, JoinSet};

/// One server-direct local forward.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardSpec {
    pub id: String,
    pub local_port: u16,
    pub target: Target,
}

/// Live state of one forward listener.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForwardState {
    Starting,
    Listening,
    Failed(String),
}

/// Snapshot of one forward's listener and relay state.
#[derive(Clone, Debug)]
pub struct ForwardStatus {
    pub id: String,
    pub state: ForwardState,
    pub active: usize,
    pub last_conn_error: Option<String>,
}

const STACK_V4: usize = 0;
const STACK_V6: usize = 1;

/// Bind/accept health of one loopback stack's listener.
#[derive(Default)]
struct StackHealth {
    up: bool,
    error: Option<(io::ErrorKind, String)>,
}

impl StackHealth {
    fn up() -> Self {
        Self {
            up: true,
            error: None,
        }
    }

    fn down(e: &io::Error) -> Self {
        Self {
            up: false,
            error: Some((e.kind(), e.to_string())),
        }
    }
}

struct ForwardShared {
    port: u16,
    state: Mutex<ForwardState>,
    stacks: Mutex<[StackHealth; 2]>,
    active: AtomicUsize,
    last_conn_error: Mutex<Option<String>>,
}

impl ForwardShared {
    fn new(port: u16) -> Self {
        Self {
            port,
            state: Mutex::new(ForwardState::Starting),
            stacks: Mutex::new(Default::default()),
            active: AtomicUsize::new(0),
            last_conn_error: Mutex::new(None),
        }
    }

    /// Record one stack's health and refold the forward state: listening while
    /// either stack is bound, failed once both are down, and starting until
    /// both have resolved their first bind.
    fn set_stack(&self, stack: usize, health: StackHealth) {
        let mut stacks = lock(&self.stacks);
        stacks[stack] = health;
        *lock(&self.state) = if stacks.iter().any(|s| s.up) {
            ForwardState::Listening
        } else if stacks.iter().all(|s| s.error.is_some()) {
            let in_use = stacks
                .iter()
                .any(|s| matches!(s.error, Some((io::ErrorKind::AddrInUse, _))));
            let reason = if in_use {
                format!("port {} is in use", self.port)
            } else {
                let (_, msg) = stacks[STACK_V4].error.as_ref().unwrap();
                msg.clone()
            };
            ForwardState::Failed(reason)
        } else {
            ForwardState::Starting
        };
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// First delay between listener (re)bind attempts while a forward's port is
/// unavailable; doubles up to [`FORWARD_REBIND_MAX_BACKOFF`].
const FORWARD_REBIND_BASE_BACKOFF: Duration = Duration::from_millis(250);
/// Ceiling on the rebind backoff — keeps a forward whose port is held by
/// another process from spinning while still reclaiming it promptly once free.
const FORWARD_REBIND_MAX_BACKOFF: Duration = Duration::from_secs(5);

/// Backoff before the `attempt`-th (0-based) rebind retry.
fn rebind_backoff(attempt: u32) -> Duration {
    (FORWARD_REBIND_BASE_BACKOFF * (1u32 << attempt.min(5))).min(FORWARD_REBIND_MAX_BACKOFF)
}

/// Cap on concurrent relayed connections per forward. Backpressure, not an
/// error: at the cap the forward stops accepting (connections wait in the
/// kernel backlog) until a relay closes, so a runaway client can't exhaust the
/// process's file descriptors.
const MAX_ACTIVE_RELAYS_PER_FORWARD: usize = 128;

struct ForwardTask {
    spec: ForwardSpec,
    handle: JoinHandle<()>,
    shared: Arc<ForwardShared>,
}

/// Owns and reconciles server-direct listener tasks.
///
/// The runtime handle makes [`apply`](Self::apply) safe to call from a foreign
/// thread (the iOS FFI does this from Swift's main actor).
pub struct ForwardManager {
    runtime: Handle,
    forwarder: ServerForwarder,
    tasks: HashMap<String, ForwardTask>,
}

impl ForwardManager {
    pub fn new(runtime: Handle, forwarder: ServerForwarder, forwards: &[ForwardSpec]) -> Self {
        let mut manager = Self {
            runtime,
            forwarder,
            tasks: HashMap::new(),
        };
        manager.apply(forwards);
        manager
    }

    /// Reconcile listeners with the complete desired set.
    pub fn apply(&mut self, forwards: &[ForwardSpec]) {
        let desired: HashMap<&str, &ForwardSpec> =
            forwards.iter().map(|f| (f.id.as_str(), f)).collect();
        self.tasks.retain(|id, task| match desired.get(id.as_str()) {
            Some(spec) if **spec == task.spec => true,
            _ => {
                task.handle.abort();
                false
            }
        });
        for spec in forwards {
            if self.tasks.contains_key(&spec.id) {
                continue;
            }
            let shared = Arc::new(ForwardShared::new(spec.local_port));
            let handle = self.runtime.spawn(run_forward(
                spec.clone(),
                self.forwarder.clone(),
                shared.clone(),
            ));
            self.tasks.insert(
                spec.id.clone(),
                ForwardTask {
                    spec: spec.clone(),
                    handle,
                    shared,
                },
            );
        }
    }

    pub fn statuses(&self) -> Vec<ForwardStatus> {
        self.tasks
            .iter()
            .map(|(id, task)| ForwardStatus {
                id: id.clone(),
                state: lock(&task.shared.state).clone(),
                active: task.shared.active.load(Ordering::Relaxed),
                last_conn_error: lock(&task.shared.last_conn_error).clone(),
            })
            .collect()
    }
}

impl Drop for ForwardManager {
    fn drop(&mut self) {
        for task in self.tasks.values() {
            task.handle.abort();
        }
    }
}

struct ActiveGuard(Arc<ForwardShared>);

impl ActiveGuard {
    fn new(shared: Arc<ForwardShared>) -> Self {
        shared.active.fetch_add(1, Ordering::Relaxed);
        Self(shared)
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Drive one loopback stack of a forward: bind, accept, and hand each accepted
/// connection to the forward's relay loop.
///
/// Binding retries **until it succeeds**, folding initial-bind failures and
/// mid-session listener deaths (an abort burst or broken accept — the
/// signature of a socket the OS defuncted underneath us, as iOS does on
/// suspend) into one reclaim loop paced by [`rebind_backoff`]. Unlike the
/// SOCKS5 front-end — whose accept loop ends the whole session on a rebind
/// failure, so the embedder's health probe relaunches it — an individual
/// forward has no session-level restart to fall back on. Giving up after a few
/// attempts would leave it dead but still "enabled", recoverable only by
/// toggling it off and on, which is exactly the stuck-forever symptom this
/// avoids. The stacks recover independently: one stack sleeping between
/// reclaim attempts never blocks accepts on the other.
async fn run_stack(
    addr: SocketAddr,
    stack: usize,
    shared: Arc<ForwardShared>,
    accepted: mpsc::Sender<TcpStream>,
) {
    let port = shared.port;
    let label = if stack == STACK_V4 {
        "Forward IPv4"
    } else {
        "Forward IPv6"
    };
    let mut retry = AcceptRetry::new(label);
    'bind: loop {
        let mut attempt: u32 = 0;
        let listener = loop {
            match TcpListener::bind(addr).await {
                Ok(listener) => break listener,
                Err(e) => {
                    if attempt == 0 {
                        log::warn!("Forward localhost:{port} failed to bind {addr}; retrying: {e}");
                    } else {
                        log::debug!("Forward localhost:{port} bind {addr} retry failed: {e}");
                    }
                    shared.set_stack(stack, StackHealth::down(&e));
                    tokio::time::sleep(rebind_backoff(attempt)).await;
                    attempt = attempt.saturating_add(1);
                }
            }
        };
        retry.record_rebind();
        shared.set_stack(stack, StackHealth::up());
        log::info!("Forward localhost:{port} listening on {addr}");
        loop {
            match listener.accept().await {
                Ok((inbound, _)) => {
                    retry.record_success();
                    if accepted.send(inbound).await.is_err() {
                        // The forward task is gone; nothing left to serve.
                        return;
                    }
                }
                Err(e) => match retry.record_error(&e) {
                    AcceptOutcome::Rebind => {
                        log::warn!(
                            "Forward localhost:{port} listener on {addr} is dead ({e}); rebinding"
                        );
                        shared.set_stack(stack, StackHealth::down(&e));
                        // Re-enter the bind loop, dropping the dead socket
                        // first; it still owns the port.
                        continue 'bind;
                    }
                    AcceptOutcome::Retry => retry.wait_retry(&e).await,
                },
            }
        }
    }
}

async fn run_forward(spec: ForwardSpec, forwarder: ServerForwarder, shared: Arc<ForwardShared>) {
    let port = spec.local_port;
    log::info!(
        "Forwarding localhost:{port} → {:?} directly through the server",
        spec.target
    );
    // Capacity 1: once the relay cap pauses this loop, at most one accepted
    // connection queues here before the stacks stop accepting too.
    let (accepted_tx, mut accepted_rx) = mpsc::channel(1);
    // Owning the stack tasks ties their lifetime to this task's: aborting the
    // forward aborts its listeners. The ids identify which stack a supervised
    // termination came from.
    let mut stacks = JoinSet::new();
    let v4_task = stacks
        .spawn(run_stack(
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            STACK_V4,
            shared.clone(),
            accepted_tx.clone(),
        ))
        .id();
    stacks.spawn(run_stack(
        SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
        STACK_V6,
        shared.clone(),
        accepted_tx,
    ));
    let limiter = Arc::new(Semaphore::new(MAX_ACTIVE_RELAYS_PER_FORWARD));
    let mut relays = JoinSet::new();
    let mut warned_saturated = false;
    loop {
        let inbound = tokio::select! {
            inbound = accepted_rx.recv() => match inbound {
                // Both stack tasks are gone (reaped by the supervision arm
                // below, or torn down with this task); nothing left to serve.
                Some(inbound) => inbound,
                None => return,
            },
            Some(_) = relays.join_next(), if !relays.is_empty() => continue,
            // Supervise the stacks: a stack task ending here is abnormal — a
            // normal `run_stack` return only happens once this task is already
            // gone, so this is a panic (debug builds unwind into a JoinError;
            // the iOS release profile aborts before reaching it). Mark the
            // stack down so statuses() stops reporting a dead listener as
            // Listening.
            Some(ended) = stacks.join_next_with_id() => {
                let (id, detail) = match ended {
                    Ok((id, ())) => (id, "ended unexpectedly".to_string()),
                    Err(e) => (e.id(), format!("failed: {e}")),
                };
                let stack = if id == v4_task { STACK_V4 } else { STACK_V6 };
                let label = if stack == STACK_V4 { "IPv4" } else { "IPv6" };
                log::error!("Forward localhost:{port} {label} listener task {detail}");
                shared.set_stack(
                    stack,
                    StackHealth::down(&io::Error::other(format!("{label} listener task {detail}"))),
                );
                continue;
            }
        };
        if limiter.available_permits() == 0 {
            if !warned_saturated {
                warned_saturated = true;
                log::warn!(
                    "Forward localhost:{port} reached {MAX_ACTIVE_RELAYS_PER_FORWARD} \
                     concurrent connections; pausing accepts until one closes"
                );
            }
        } else {
            warned_saturated = false;
        }
        let permit = limiter
            .clone()
            .acquire_owned()
            .await
            .expect("relay limiter is never closed");
        let shared = shared.clone();
        let forwarder = forwarder.clone();
        let target = spec.target.clone();
        relays.spawn(async move {
            let _permit = permit;
            let _guard = ActiveGuard::new(shared.clone());
            match forwarder.relay(inbound, &target).await {
                Ok(()) => *lock(&shared.last_conn_error) = None,
                Err(e) => {
                    log::warn!("Forward localhost:{port}: {e}");
                    *lock(&shared.last_conn_error) = Some(e.to_string());
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rebind_backoff_grows_and_caps() {
        assert_eq!(rebind_backoff(0), FORWARD_REBIND_BASE_BACKOFF);
        assert_eq!(rebind_backoff(1), FORWARD_REBIND_BASE_BACKOFF * 2);
        // Doubling is clamped to the ceiling, and stays there for large attempts.
        assert_eq!(rebind_backoff(5), FORWARD_REBIND_MAX_BACKOFF);
        assert_eq!(rebind_backoff(50), FORWARD_REBIND_MAX_BACKOFF);
    }

    #[test]
    fn folded_state_tracks_stack_health() {
        let shared = ForwardShared::new(8080);
        assert_eq!(*lock(&shared.state), ForwardState::Starting);
        // One stack resolving down keeps it starting until the other resolves.
        let in_use = io::Error::new(io::ErrorKind::AddrInUse, "taken");
        shared.set_stack(STACK_V4, StackHealth::down(&in_use));
        assert_eq!(*lock(&shared.state), ForwardState::Starting);
        shared.set_stack(STACK_V6, StackHealth::up());
        assert_eq!(*lock(&shared.state), ForwardState::Listening);
        // Both down, either with AddrInUse, folds to the port-in-use reason.
        shared.set_stack(STACK_V6, StackHealth::down(&io::Error::other("defunct")));
        assert_eq!(
            *lock(&shared.state),
            ForwardState::Failed("port 8080 is in use".into())
        );
        // Either stack recovering flips it back to listening.
        shared.set_stack(STACK_V4, StackHealth::up());
        assert_eq!(*lock(&shared.state), ForwardState::Listening);
    }

    /// Wait until the forward folds to `state`, or panic after ~5s.
    async fn wait_for_state(shared: &ForwardShared, state: ForwardState) {
        for _ in 0..100 {
            if *lock(&shared.state) == state {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!(
            "forward never reached {state:?}; last: {:?}",
            *lock(&shared.state)
        );
    }

    /// A stack whose port is held — at initial bind or after the OS defuncts a
    /// bound socket, one shared reclaim loop — must keep retrying and self-heal
    /// once the port frees, never park permanently. This is the regression
    /// guard for the stuck-until-toggled bug.
    #[tokio::test]
    async fn stack_reclaims_its_port_once_freed() {
        // Occupy an ephemeral loopback port so the first binds fail.
        let occupier = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = occupier.local_addr().unwrap();
        let shared = Arc::new(ForwardShared::new(addr.port()));
        // Only the v4 stack runs; mark v6 down so the folded state reflects v4.
        shared.set_stack(STACK_V6, StackHealth::down(&io::Error::other("unused")));
        let (tx, mut rx) = mpsc::channel(1);
        let stack = tokio::spawn(run_stack(addr, STACK_V4, shared.clone(), tx));

        // Let several bind attempts fail, then free the port.
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert_eq!(
            *lock(&shared.state),
            ForwardState::Failed(format!("port {} is in use", addr.port()))
        );
        drop(occupier);

        wait_for_state(&shared, ForwardState::Listening).await;
        TcpStream::connect(addr).await.unwrap();
        rx.recv().await.expect("accepted connection should be handed off");
        stack.abort();
    }

    /// One stack stuck reclaiming its port must not block the other: the
    /// forward stays listening and accepting on the healthy stack. (Both
    /// stacks bind IPv4 loopback here so the test doesn't depend on ::1;
    /// `run_stack` only uses the index as its health slot.)
    #[tokio::test]
    async fn one_stuck_stack_does_not_block_the_other() {
        let occupier = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let held_addr = occupier.local_addr().unwrap();
        // Reserve a distinct free port for the healthy stack (probe-and-drop;
        // the reuse race is negligible for a test).
        let probe = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let free_addr = probe.local_addr().unwrap();
        drop(probe);

        let shared = Arc::new(ForwardShared::new(held_addr.port()));
        let (tx, mut rx) = mpsc::channel(1);
        let stuck = tokio::spawn(run_stack(held_addr, STACK_V4, shared.clone(), tx.clone()));
        let healthy = tokio::spawn(run_stack(free_addr, STACK_V6, shared.clone(), tx));

        wait_for_state(&shared, ForwardState::Listening).await;
        TcpStream::connect(free_addr).await.unwrap();
        rx.recv()
            .await
            .expect("healthy stack should accept while the other reclaims");
        assert!(
            !lock(&shared.stacks)[STACK_V4].up,
            "occupied stack must still be down"
        );
        stuck.abort();
        healthy.abort();
    }
}
