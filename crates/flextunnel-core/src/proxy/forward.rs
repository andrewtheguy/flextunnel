//! Server-direct local TCP port forwarding.
//!
//! Each configured loopback listener opens a data bi-stream on the client's
//! authenticated iroh connection and sends the target directly to the server.
//! No local SOCKS5 listener or handshake is involved. The server remains the
//! authority: it enforces its routed set before resolving or dialing the target.

use super::client::{AcceptOutcome, AcceptRetry, ServerForwarder, rebind_listener};
use super::signaling::Target;
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Handle;
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

struct ForwardShared {
    state: Mutex<ForwardState>,
    active: AtomicUsize,
    last_conn_error: Mutex<Option<String>>,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// First delay between listener rebind attempts while a forward's port is
/// unavailable; doubles up to [`FORWARD_REBIND_MAX_BACKOFF`].
const FORWARD_REBIND_BASE_BACKOFF: Duration = Duration::from_millis(250);
/// Ceiling on the rebind backoff — keeps a forward whose port is held by
/// another process from spinning while still reclaiming it promptly once free.
const FORWARD_REBIND_MAX_BACKOFF: Duration = Duration::from_secs(5);

/// Backoff before the `attempt`-th (0-based) rebind retry.
fn rebind_backoff(attempt: u32) -> Duration {
    (FORWARD_REBIND_BASE_BACKOFF * (1u32 << attempt.min(5))).min(FORWARD_REBIND_MAX_BACKOFF)
}

struct ForwardTask {
    spec: ForwardSpec,
    handle: JoinHandle<()>,
    shared: Arc<ForwardShared>,
}

/// Owns and reconciles server-direct listener tasks.
///
/// The runtime handle makes [`apply`](Self::apply) safe to call from a foreign
/// thread (e.g. a GUI's main thread).
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
            let shared = Arc::new(ForwardShared {
                state: Mutex::new(ForwardState::Starting),
                active: AtomicUsize::new(0),
                last_conn_error: Mutex::new(None),
            });
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

async fn accept_on(listener: Option<&TcpListener>) -> io::Result<(TcpStream, SocketAddr)> {
    match listener {
        Some(listener) => listener.accept().await,
        None => std::future::pending().await,
    }
}

/// Handle a failed `accept()` on one of the forward's loopback listeners.
///
/// Classifies the error like the client's front-end loops: a broken listener
/// (or an abort burst — the signature of a socket the OS defuncted underneath
/// us, as iOS does on suspend) is rebound in place; transient failures back off
/// and retry.
///
/// Rebinding retries **until it succeeds**, marking the forward
/// [`ForwardState::Failed`] while its port is unavailable and restoring
/// [`ForwardState::Listening`] once rebound. Unlike the SOCKS5 front-end — whose
/// accept loop ends the whole session on a rebind failure, so the embedder's
/// health probe relaunches it — an individual forward has no session-level
/// restart to fall back on. Giving up after a few attempts would leave it dead
/// but still "enabled", recoverable only by toggling it off and on, which is
/// exactly the stuck-forever symptom this avoids.
async fn handle_accept_error(
    listener: &mut Option<TcpListener>,
    addr: SocketAddr,
    retry: &mut AcceptRetry,
    e: &io::Error,
    port: u16,
    shared: &ForwardShared,
) {
    match retry.record_error(e) {
        AcceptOutcome::Rebind => {
            log::warn!("Forward localhost:{port} listener on {addr} is dead ({e}); rebinding");
            // Drop the dead socket first; it still owns the port.
            *listener = None;
            let mut attempt: u32 = 0;
            loop {
                match rebind_listener(addr).await {
                    Ok(rebound) => {
                        *listener = Some(rebound);
                        retry.record_rebind();
                        log::info!("Forward localhost:{port} listener rebound on {addr}");
                        *lock(&shared.state) = ForwardState::Listening;
                        return;
                    }
                    Err(err) => {
                        let reason = format!("listener on {addr} is down; retrying: {err}");
                        if attempt == 0 {
                            log::error!("Forward localhost:{port} {reason}");
                        } else {
                            log::debug!("Forward localhost:{port} {reason}");
                        }
                        *lock(&shared.state) = ForwardState::Failed(reason);
                        tokio::time::sleep(rebind_backoff(attempt)).await;
                        attempt = attempt.saturating_add(1);
                    }
                }
            }
        }
        AcceptOutcome::Retry => retry.wait_retry(e).await,
    }
}

async fn run_forward(
    spec: ForwardSpec,
    forwarder: ServerForwarder,
    shared: Arc<ForwardShared>,
) {
    let port = spec.local_port;
    let v4_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let v6_addr = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    let v4 = TcpListener::bind(v4_addr).await;
    let v6 = TcpListener::bind(v6_addr).await;
    let (mut v4, mut v6) = match (v4, v6) {
        (Err(e4), Err(e6)) => {
            let reason = if e4.kind() == io::ErrorKind::AddrInUse
                || e6.kind() == io::ErrorKind::AddrInUse
            {
                format!("port {port} is in use")
            } else {
                e4.to_string()
            };
            log::error!("Forward localhost:{port} failed to bind: {reason}");
            *lock(&shared.state) = ForwardState::Failed(reason);
            return;
        }
        (v4, v6) => (v4.ok(), v6.ok()),
    };
    *lock(&shared.state) = ForwardState::Listening;
    log::info!(
        "Forwarding localhost:{port} → {:?} directly through the server ({}{})",
        spec.target,
        if v4.is_some() { "IPv4" } else { "" },
        match (&v4, &v6) {
            (Some(_), Some(_)) => "+IPv6",
            (None, Some(_)) => "IPv6",
            _ => "",
        }
    );

    let mut v4_retry = AcceptRetry::new("Forward IPv4");
    let mut v6_retry = AcceptRetry::new("Forward IPv6");
    let mut relays = JoinSet::new();
    loop {
        let (is_v4, accepted) = tokio::select! {
            accepted = accept_on(v4.as_ref()) => (true, accepted),
            accepted = accept_on(v6.as_ref()) => (false, accepted),
            Some(_) = relays.join_next(), if !relays.is_empty() => continue,
        };
        let inbound = match accepted {
            Ok((inbound, _)) => {
                if is_v4 { v4_retry.record_success() } else { v6_retry.record_success() }
                inbound
            }
            Err(e) => {
                let (listener, addr, retry) = if is_v4 {
                    (&mut v4, v4_addr, &mut v4_retry)
                } else {
                    (&mut v6, v6_addr, &mut v6_retry)
                };
                handle_accept_error(listener, addr, retry, &e, port, &shared).await;
                continue;
            }
        };
        let shared = shared.clone();
        let forwarder = forwarder.clone();
        let target = spec.target.clone();
        relays.spawn(async move {
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

    /// A dead listener whose port is momentarily held (e.g. the defunct socket
    /// after iOS resume, or another process) must keep retrying and self-heal
    /// once the port frees — never park permanently in `Failed`. This is the
    /// regression guard for the stuck-until-toggled bug.
    #[tokio::test]
    async fn rebind_retries_until_the_port_frees() {
        // Occupy an ephemeral loopback port so the first rebinds fail.
        let occupier = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = occupier.local_addr().unwrap();

        // Free the port shortly, after several rebind attempts have failed.
        let freer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(700)).await;
            drop(occupier);
        });

        let shared = ForwardShared {
            state: Mutex::new(ForwardState::Listening),
            active: AtomicUsize::new(0),
            last_conn_error: Mutex::new(None),
        };
        let mut listener: Option<TcpListener> = None;
        let mut retry = AcceptRetry::new("test");
        // A non-abort error classifies as Broken → immediate Rebind outcome.
        let err = io::Error::other("listener defunct");

        handle_accept_error(&mut listener, addr, &mut retry, &err, addr.port(), &shared).await;

        assert!(listener.is_some(), "listener should be rebound, not parked None");
        assert_eq!(*lock(&shared.state), ForwardState::Listening);
        freer.await.unwrap();
    }
}
