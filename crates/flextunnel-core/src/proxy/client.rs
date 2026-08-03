//! flextunnel client: local SOCKS5 and optional HTTP proxy listeners whose
//! routed requests are tunneled over a single iroh QUIC connection to the
//! server, one bi-stream per proxied connection.

use crate::error::{ProxyError, ProxyResult};
use crate::proxy::signaling::{self, ControlMsg, Hello, Target};
use crate::proxy::{dial, http, reserved, socks5, RoutedSet};
use crate::transport::endpoint::RelayConfig;
use crate::transport::paths::{connection_paths, ConnPath, ConnectionSnapshot};
use crate::transport::{HEARTBEAT_INTERVAL, LIVENESS_WINDOW};
use anyhow::Result;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl};
use rand::Rng;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;

/// Reconnect backoff: base 1s, doubling per attempt, capped at 60s.
const RECONNECT_BACKOFF_MAX: u64 = 60;
/// Max jitter (ms) added to each backoff to avoid thundering reconnects.
const RECONNECT_JITTER_MAX_MS: u64 = 500;
/// Deadline for the server's handshake response. The QUIC keep-alive keeps the
/// connection from idling out, so without this a server that accepts the
/// connection but never replies on the stream would hang the client forever.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Deadline for `Endpoint::connect` (address discovery + QUIC handshake). The
/// discovery phase awaits DNS/pkarr/mDNS lookups with no deadline of its own,
/// and on a wedged endpoint (seen on iOS after the OS suspends the process and
/// invalidates the socket state underneath it) that future can pend forever —
/// which would stall the reconnect loop permanently instead of retrying. The
/// retry then nudges `Endpoint::network_change()` to rebind the dead
/// transports (see `manage_connection`), so the wedge is repaired rather than
/// merely timed out again.
/// Generous: a healthy connect through discovery + relay completes well within.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Connect to `addr` bounded by [`CONNECT_TIMEOUT`], mapping both the timeout and
/// the underlying connect error to a signaling error. Shared by the client and
/// agent `establish()` flows.
pub(crate) async fn connect_with_timeout(
    endpoint: &Endpoint,
    addr: EndpointAddr,
) -> ProxyResult<Connection> {
    tokio::time::timeout(CONNECT_TIMEOUT, endpoint.connect(addr, crate::transport::ALPN))
        .await
        .map_err(|_| {
            ProxyError::Signaling(format!(
                "timed out connecting to server after {}s",
                CONNECT_TIMEOUT.as_secs()
            ))
        })?
        .map_err(|e| ProxyError::Signaling(format!("Failed to connect to server: {e}")))
}
/// Deadline for opening a tunnel stream and receiving the server's CONNECT
/// reply. Must exceed the server's own connect timeout (it replies only after
/// dialing the target, up to ~10s), so a legitimately slow target isn't cut
/// off; without it a server that stalls after accepting the stream would hang
/// the local SOCKS5 connection forever.
const TUNNEL_OPEN_TIMEOUT: Duration = Duration::from_secs(30);
/// Deadline for the local app to complete its SOCKS5 handshake (method
/// negotiation + CONNECT request). A peer that connects to the loopback
/// listener but sends nothing would otherwise pin the spawned task and socket
/// forever; generous since this is loopback.
const LOCAL_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Pause before retrying `accept()` after a transient failure. Matters most
/// for fd exhaustion (EMFILE/ENFILE — easy to hit under macOS's default
/// 256-fd soft limit): the listener is still healthy, and apps retrying their
/// failed connections make it worse, so back off long enough for in-flight
/// connections to close and free descriptors instead of exiting the client.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(250);
/// Warn on the 1st transient accept failure of a burst and then every Nth —
/// one warn per ~10s at [`ACCEPT_RETRY_DELAY`] pacing — so sustained fd
/// exhaustion doesn't flood the log; the in-between retries log at debug.
const ACCEPT_RETRY_WARN_EVERY: u64 = 40;
/// Consecutive aborted accepts after which the listener itself is presumed
/// dead and rebound. A peer aborting a queued connection between the kernel
/// accepting it and us reading it yields the same error *occasionally*; a
/// listener socket the OS invalidated underneath us — iOS marks every socket
/// of a suspended process defunct, and `accept()` on one fails with
/// ECONNABORTED forever — yields it on *every* call. A short uniform burst
/// (~1s at [`ACCEPT_RETRY_DELAY`] pacing) separates the two.
const REBIND_AFTER_CONSECUTIVE_ABORTS: u64 = 4;

/// The live QUIC connection shared with the always-on accept loop; `None` while
/// disconnected (during a drop/backoff), so off-list targets still connect
/// directly and on-list targets get a clean unreachable reply.
type SharedConn = Arc<Mutex<Option<Connection>>>;
/// The route policy (tunnel set) shared with the accept loop. `None` until the
/// first handshake learns it, then `Some` for the rest of the process — retained
/// across drops so split-tunnel routing keeps working while the connection is
/// down. While it is `None` the client **fails closed**: no connection is routed
/// (directly or tunneled) before the policy is known, so nothing leaks out.
type SharedRoutedSet = Arc<Mutex<Option<Arc<RoutedSet>>>>;

/// Configuration for the proxy client.
pub struct ClientConfig {
    /// Server's iroh EndpointId (as a string).
    pub server_node_id: String,
    /// Authentication token sent in the connection handshake.
    pub auth_token: String,
    /// Local address the optional SOCKS5 listener binds to. CLI clients always
    /// set this; GUI forwarding-only sessions may leave it disabled.
    pub socks_listen: Option<SocketAddr>,
    /// Local address for the optional HTTP proxy listener (CONNECT tunneling +
    /// absolute-URI plain-HTTP forwarding). `None` leaves the HTTP front-end
    /// disabled.
    pub http_listen: Option<SocketAddr>,
    /// Relay URL hints (optional). Empty selects the default iroh relays.
    pub relay_urls: Vec<String>,
    /// Shared bearer token sent to every custom relay's WebSocket upgrade.
    /// Only valid alongside custom `relay_urls`; ignored with the default relays.
    pub relay_auth_token: Option<String>,
    /// Reconnect with backoff on a transient failure instead of exiting.
    pub auto_reconnect: bool,
    /// Cap on reconnect attempts between successful connections (unlimited if None).
    pub max_reconnect_attempts: Option<NonZeroU32>,
}

/// Cloneable handle for opening a target directly on the client's live,
/// authenticated server connection. It deliberately bypasses all local proxy
/// front-ends and always asks the server to connect; the server's routed-set
/// whitelist remains authoritative and rejects off-list targets.
#[derive(Clone)]
pub struct ServerForwarder {
    current: SharedConn,
}

impl ServerForwarder {
    /// Open one server-side target and return its raw bidirectional byte stream.
    pub async fn connect(
        &self,
        target: &signaling::Target,
    ) -> Result<tokio::io::Join<RecvStream, SendStream>> {
        let conn = self
            .current
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .ok_or_else(|| anyhow::anyhow!("tunnel is not connected"))?;
        let opened = tokio::time::timeout(TUNNEL_OPEN_TIMEOUT, open_tunnel(&conn, target))
            .await
            .map_err(|_| anyhow::anyhow!("timed out opening server-direct forward"))??;
        let (send, recv, rep) = opened;
        if rep != signaling::REP_SUCCESS {
            anyhow::bail!("server rejected target: {}", socks5::describe_reply(rep));
        }
        Ok(tokio::io::join(recv, send))
    }

    /// Open `target` and splice it with one accepted local connection.
    pub async fn relay<S>(&self, mut local: S, target: &signaling::Target) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut tunnel = self.connect(target).await?;
        tokio::io::copy_bidirectional(&mut local, &mut tunnel).await?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn connected(connection: Connection) -> Self {
        Self {
            current: Arc::new(Mutex::new(Some(connection))),
        }
    }
}

/// Exponential backoff with jitter for the Nth (1-based) reconnect attempt.
///
/// Shared with [`crate::proxy::agent`], whose reconnect policy mirrors the
/// client's.
pub(crate) fn calculate_backoff(attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(6); // cap the doubling at 2^6 = 64
    let secs = (1u64 << shift).min(RECONNECT_BACKOFF_MAX);
    let jitter = rand::rng().random_range(0..=RECONNECT_JITTER_MAX_MS);
    Duration::from_secs(secs) + Duration::from_millis(jitter)
}

/// Snapshot of what the tunnel currently forwards: the split-tunnel set the
/// server pushed on the last successful handshake, plus whether a connection is
/// live right now. Shared with embedders so the app can display the routed
/// domains/CIDRs. An empty set while `connected` is true means the server runs
/// no routed set and everything is tunneled.
#[derive(Clone, Default)]
pub struct TunnelRoutes {
    pub connected: bool,
    pub domains: Vec<String>,
    pub cidrs: Vec<String>,
    /// Server-side host aliases (`alias -> target`), informational only — the
    /// server resolves them; shown in client status UIs like the server status
    /// page shows them.
    pub host_aliases: Vec<(String, String)>,
    /// Reverse-routing (agent) routes, informational only. Each carries a live
    /// `connected` flag: seeded from the handshake and refreshed on every
    /// heartbeat ack (see [`client_heartbeat_loop`]). Consumers should render
    /// state via [`TunnelRoutes::agent_states`], which downgrades a stale view to
    /// [`AgentConnState::Unknown`] rather than trusting the raw flag.
    pub agent_aliases: Vec<AgentAlias>,
    /// When the agent connected-state was last refreshed by a heartbeat ack (or
    /// seeded at handshake). `None` before the first refresh. Used to detect a
    /// stale view — see [`TunnelRoutes::agent_states`].
    pub agent_status_updated: Option<Instant>,
    /// Server-side conditional DNS forwards as `(suffix, upstream servers)`
    /// pairs, sorted by suffix. Informational only — the server does the
    /// resolution; shown in client status UIs like the server status page shows
    /// them. Empty when the server configures no `[dns_forwards]`.
    pub dns_forwards: Vec<(String, Vec<String>)>,
    /// Server-side outbound bridge routes (targets forwarded to another
    /// server), sorted by name. Informational only — the server does the
    /// forwarding; shown in client status UIs like the server status page shows
    /// them. Empty when the server configures no `[bridges]`.
    pub bridges: Vec<signaling::BridgeSummary>,
}

/// How long the client's connected-agent view stays trustworthy after the last
/// heartbeat ack refreshed it. Past this, [`TunnelRoutes::agent_states`] reports
/// [`AgentConnState::Unknown`] instead of a stale connected/disconnected. Set to
/// 3× the heartbeat interval so a single late/dropped ack doesn't flip the UI to
/// unknown, while still surfacing a genuinely lagging view before the connection
/// itself is declared lost (`LIVENESS_WINDOW`).
pub const AGENT_STATUS_STALE_AFTER: Duration =
    Duration::from_secs(HEARTBEAT_INTERVAL.as_secs() * 3);

/// A reverse-routing (agent) alias plus whether its backing agent is connected
/// to the server right now. The connected flag tracks the server's passive
/// agent-registry view, delivered over the heartbeat control stream.
#[derive(Clone, Default)]
pub struct AgentAlias {
    pub name: String,
    pub connected: bool,
}

/// Display-resolved connection state of an agent route, accounting for view
/// staleness — see [`TunnelRoutes::agent_states`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentConnState {
    /// The backing agent was connected as of the last fresh update.
    Connected,
    /// The backing agent was disconnected as of the last fresh update.
    Disconnected,
    /// The view is stale (or the tunnel is down): the true state is unknown.
    Unknown,
}

impl AgentConnState {
    /// Lowercase wire/JSON token, for status UIs.
    pub fn as_str(self) -> &'static str {
        match self {
            AgentConnState::Connected => "connected",
            AgentConnState::Disconnected => "disconnected",
            AgentConnState::Unknown => "unknown",
        }
    }
}

impl TunnelRoutes {
    /// Resolve each agent route to a display state as of `now`. The state is
    /// [`AgentConnState::Unknown`] when the tunnel is down or the last heartbeat
    /// refresh is older than [`AGENT_STATUS_STALE_AFTER`]; otherwise it reflects
    /// the last-known connected flag. Pass `Instant::now()`.
    pub fn agent_states(&self, now: Instant) -> Vec<(String, AgentConnState)> {
        let fresh = self.connected
            && self
                .agent_status_updated
                .is_some_and(|t| now.saturating_duration_since(t) <= AGENT_STATUS_STALE_AFTER);
        self.agent_aliases
            .iter()
            .map(|a| {
                let state = if !fresh {
                    AgentConnState::Unknown
                } else if a.connected {
                    AgentConnState::Connected
                } else {
                    AgentConnState::Disconnected
                };
                (a.name.clone(), state)
            })
            .collect()
    }
}

/// Client-side history of server instance nonces observed for the configured
/// server id, used to detect a *duplicate server*.
///
/// A single server that merely restarts emits a strictly-growing sequence of
/// fresh random nonces (a previous one never reappears, 2⁻¹²⁸). A client
/// bouncing between two servers that share one identity sees a previously-seen
/// nonce **reappear** after a different one — that flip-flop is the signal.
#[derive(Default)]
struct ServerNonceTracker {
    /// Distinct nonces seen, in first-seen order.
    history: Vec<u128>,
    /// The most recently observed nonce.
    last: Option<u128>,
}

pub struct ProxyClient {
    config: ClientConfig,
    routes: Arc<Mutex<TunnelRoutes>>,
    /// The live server connection, published by the connection manager while
    /// up and `None` during a drop/backoff. Also the accept loops' routing
    /// handle; held as a field so status callers (the desktop's connection-path
    /// CTA) can snapshot its iroh paths on demand via [`Self::conn_paths`].
    current: SharedConn,
    /// Random per-process identity of this client, sent in every `Hello` so the
    /// server can tell a benign reconnect (same nonce) from two distinct client
    /// processes sharing a node id (different nonces → a duplicate-client bug).
    instance_nonce: u128,
    /// Observed server-nonce history for duplicate-server detection.
    nonce_tracker: Mutex<ServerNonceTracker>,
    /// Latches once a duplicate server has been observed; thereafter every
    /// `Hello` carries the advisory so the server can self-block.
    duplicate_server: AtomicBool,
}

impl ProxyClient {
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config,
            routes: Arc::new(Mutex::new(TunnelRoutes::default())),
            current: Arc::new(Mutex::new(None)),
            instance_nonce: rand::rng().random(),
            nonce_tracker: Mutex::new(ServerNonceTracker::default()),
            duplicate_server: AtomicBool::new(false),
        }
    }

    /// Record a server instance nonce observed in a `HelloResponse` and apply the
    /// reappearance rule. Latches [`Self::duplicate_server`] on a confirmed
    /// duplicate; a plain change (restart or first sight of a second instance) is
    /// only logged. Returns `true` only when this call *newly* latched the flag,
    /// so the caller can force an immediate reconnect to get the advisory out.
    fn observe_server_nonce(&self, nonce: u128) -> bool {
        let mut t = self.nonce_tracker.lock().expect("nonce tracker lock");
        let mut newly_flagged = false;
        match t.last {
            Some(last) if last == nonce => return false, // same server as last time
            Some(_) => {
                if t.history.contains(&nonce) {
                    // A previously-seen nonce reappeared after a different one:
                    // two concurrent servers share this identity.
                    newly_flagged = !self.duplicate_server.swap(true, Ordering::Relaxed);
                    if newly_flagged {
                        log::error!(
                            "Duplicate server id detected: server instance nonce {nonce} \
                             reappeared after a different one — two servers appear to share \
                             this identity. Advising the server to self-block."
                        );
                    }
                } else {
                    log::warn!(
                        "Server identity nonce changed ({nonce}) — a restart, or possibly \
                         a second server sharing this id; watching for a reappearance."
                    );
                    t.history.push(nonce);
                }
            }
            None => t.history.push(nonce), // first observation this process
        }
        t.last = Some(nonce);
        newly_flagged
    }

    /// Shared handle to the live tunnel set, for callers (status UIs) that want to
    /// display what is routed. Refreshed on every (re)connect.
    pub fn routes(&self) -> Arc<Mutex<TunnelRoutes>> {
        self.routes.clone()
    }

    /// Snapshot the current connection's iroh paths (relay/direct) for a status
    /// UI. Empty while disconnected (during a drop/backoff or before the first
    /// connect). Cheap and synchronous — [`connection_paths`] reads a
    /// point-in-time snapshot, so no background watcher is involved.
    pub fn conn_paths(&self) -> Vec<ConnPath> {
        match self.current.lock().expect("connection lock").as_ref() {
            Some(conn) => connection_paths(conn),
            None => Vec::new(),
        }
    }

    /// Build a full connection snapshot — the iroh paths plus an on-demand
    /// `/healthz` probe of each configured custom relay — for a status UI.
    ///
    /// Async because the relay health check performs on-demand HTTP; awaited when
    /// a snapshot is built so it never blocks the runtime. Returns an empty
    /// snapshot while disconnected (custom-relay health is only reported while the
    /// tunnel is up, matching the paths list). The connection is cloned out from
    /// under the std lock before the `.await`, so the lock is never held across it.
    pub async fn connection_snapshot(&self) -> ConnectionSnapshot {
        let conn = self
            .current
            .lock()
            .expect("connection lock")
            .as_ref()
            .cloned();
        let Some(conn) = conn else {
            return ConnectionSnapshot::default();
        };
        // relay_urls were parse-validated at connect time; fall back to the
        // default relays (no custom health) if they somehow don't re-parse.
        let relay_config = RelayConfig::from_urls_with_token(
            &self.config.relay_urls,
            self.config.relay_auth_token.clone(),
        )
        .unwrap_or_default();
        crate::transport::paths::connection_snapshot(&conn, &relay_config).await
    }

    /// A cloneable server-direct forwarding handle sharing this client's live
    /// connection and reconnect lifecycle.
    pub fn server_forwarder(&self) -> ServerForwarder {
        ServerForwarder {
            current: self.current.clone(),
        }
    }

    /// Flip the connected flag without disturbing the last-known route set.
    fn set_connected(&self, connected: bool) {
        if let Ok(mut routes) = self.routes.lock() {
            routes.connected = connected;
        }
    }

    /// Bind the local SOCKS5 listener (and the optional HTTP listener) once, then
    /// connect to the server and serve them. Reconnect policy (matching ezvpn):
    /// the **first** connection must succeed — if it fails, exit immediately (a
    /// bad node id, wrong relay, or down server is not worth retrying blindly).
    /// Once connected at least once, transient drops are retried with exponential
    /// backoff, indefinitely (unless `--max-reconnect-attempts` caps it or
    /// `--no-auto-reconnect` is set). The listeners stay bound across reconnects:
    /// off-list targets keep connecting directly, while on-list requests fail with
    /// network-unreachable until the tunnel recovers.
    pub async fn run(&self, endpoint: &Endpoint) -> ProxyResult<()> {
        let socks = match self.config.socks_listen {
            Some(addr) => Some(TcpListener::bind(addr).await?),
            None => None,
        };
        let http = match self.config.http_listen {
            Some(addr) => Some(TcpListener::bind(addr).await?),
            None => None,
        };
        self.run_with_optional_listeners(endpoint, socks, http).await
    }

    /// Serve on an already-bound SOCKS5 listener (see [`run`](Self::run) for the
    /// reconnect policy). Callers that need the actual bound address — e.g. an
    /// embedder binding to an ephemeral `127.0.0.1:0` and reporting the chosen port —
    /// bind the [`TcpListener`] themselves, read `local_addr()`, then hand it
    /// here. `run` is the thin convenience wrapper that binds `socks_listen`.
    /// This path never enables the HTTP front-end.
    pub async fn run_with_listener(
        &self,
        endpoint: &Endpoint,
        listener: TcpListener,
    ) -> ProxyResult<()> {
        self.run_with_listeners(endpoint, listener, None).await
    }

    /// Serve the SOCKS5 listener and, when present, the HTTP CONNECT listener,
    /// both multiplexed over the same reconnecting server connection.
    ///
    /// Public for callers that must own the enabled proxy ports before starting
    /// the reconnecting session. Server-direct port forwards do not use either
    /// proxy listener.
    pub async fn run_with_listeners(
        &self,
        endpoint: &Endpoint,
        socks_listener: TcpListener,
        http_listener: Option<TcpListener>,
    ) -> ProxyResult<()> {
        self.run_with_optional_listeners(
            endpoint,
            Some(socks_listener),
            http_listener,
        )
        .await
    }

    /// Serve any enabled local proxy front-ends while maintaining the server
    /// connection. Both may be absent for a forwarding-only GUI session.
    pub async fn run_with_optional_listeners(
        &self,
        endpoint: &Endpoint,
        socks_listener: Option<TcpListener>,
        http_listener: Option<TcpListener>,
    ) -> ProxyResult<()> {
        self.run_with_optional_listeners_ext(
            endpoint,
            socks_listener,
            http_listener,
            #[cfg(unix)]
            None,
        )
        .await
    }

    /// Like [`run_with_listeners`](Self::run_with_listeners) but also serves a
    /// SOCKS5 front-end on an optional **Unix domain socket** listener. An
    /// embedder can use this to expose the proxy over a socket file with
    /// filesystem permissions (reachable only by the owning user/app) instead of
    /// a loopback TCP port (reachable by any local process). Both front-ends speak the
    /// same SOCKS5 protocol and share the one live tunnel + route policy.
    ///
    /// The extra Unix-domain listener is Unix-only; there is no Windows
    /// equivalent (a named-pipe front-end was considered but dropped for lack of
    /// a clear use case), so on Windows this takes the same arguments as
    /// [`run_with_listeners`].
    pub async fn run_with_listeners_ext(
        &self,
        endpoint: &Endpoint,
        socks_listener: TcpListener,
        http_listener: Option<TcpListener>,
        #[cfg(unix)] unix_listener: Option<UnixListener>,
    ) -> ProxyResult<()> {
        self.run_with_optional_listeners_ext(
            endpoint,
            Some(socks_listener),
            http_listener,
            #[cfg(unix)]
            unix_listener,
        )
        .await
    }

    async fn run_with_optional_listeners_ext(
        &self,
        endpoint: &Endpoint,
        socks_listener: Option<TcpListener>,
        http_listener: Option<TcpListener>,
        #[cfg(unix)] unix_listener: Option<UnixListener>,
    ) -> ProxyResult<()> {
        if let Some(l) = &socks_listener {
            log::info!(
                "SOCKS5 proxy listening on {} (TCP CONNECT only)",
                l.local_addr()?
            );
        }
        if let Some(l) = &http_listener {
            log::info!(
                "HTTP proxy listening on {} (CONNECT tunneling + plain-HTTP forwarding)",
                l.local_addr()?
            );
        }
        #[cfg(unix)]
        if let Some(l) = &unix_listener {
            log::info!("SOCKS5 proxy also listening on unix socket {:?}", l.local_addr()?);
        }

        // Shared state between the always-on accept loops and the connection
        // manager: the current live connection (None during a drop/backoff) and
        // the route policy (None until the first handshake learns it). Keeping the
        // accept loops independent of the connection is what lets off-list targets
        // keep connecting directly while the tunnel is down — only on-list targets
        // fail until it recovers. The policy starts None so the client fails closed
        // until it is known. `current` is the client's own field so status callers
        // can snapshot the connection's paths (see [`Self::conn_paths`]).
        let current = self.current.clone();
        let routed_set: SharedRoutedSet = Arc::new(Mutex::new(None));

        // The HTTP branch is inert (never resolves) when no HTTP listener is
        // bound, so the `select!` shape is the same either way.
        let http_accept = async {
            match http_listener {
                Some(l) => accept_loop(l, &current, &routed_set, HttpProto).await,
                None => std::future::pending::<ProxyResult<()>>().await,
            }
        };

        let socks_accept = async {
            match socks_listener {
                Some(l) => accept_loop(l, &current, &routed_set, Socks5Proto).await,
                None => std::future::pending::<ProxyResult<()>>().await,
            }
        };

        // Same for the optional Unix-domain SOCKS5 front-end. Unix only: on other
        // platforms this branch is inert (there is no Unix-domain listener), so
        // the `select!` shape stays identical.
        let unix_accept = async {
            #[cfg(unix)]
            if let Some(l) = unix_listener {
                return accept_loop_unix(l, &current, &routed_set).await;
            }
            std::future::pending::<ProxyResult<()>>().await
        };

        // One task, N concurrent futures. When the manager returns (a fatal
        // first-connect failure or a clean stop) the accept loops are dropped with
        // it, so `flextunnel_stop`'s `task.abort()` tears everything down — no
        // orphaned accept task.
        tokio::select! {
            r = self.manage_connection(endpoint, &current, &routed_set) => r,
            r = socks_accept => r,
            r = http_accept => r,
            r = unix_accept => r,
        }
    }

    /// Maintain the server connection: (re)establish + authenticate, publish the
    /// live connection and tunnel set for the accept loop, and reconnect with
    /// backoff on drops. Reconnect policy is unchanged: the **first** connection
    /// must succeed (fail fast); once connected, transient drops are retried.
    async fn manage_connection(
        &self,
        endpoint: &Endpoint,
        current: &SharedConn,
        routed_set_shared: &SharedRoutedSet,
    ) -> ProxyResult<()> {
        let mut ever_connected = false;
        let mut attempt: u32 = 0;
        loop {
            // Until (re)authenticated, nothing is being forwarded.
            self.set_connected(false);
            *current.lock().expect("connection lock") = None;

            // Retrying after a failure: the endpoint's UDP sockets may be dead
            // underneath it (iOS defuncts them while the process is suspended;
            // a sleeping laptop can do the same) and iroh cannot always detect
            // that by itself, leaving reconnects wedged forever. Nudging it
            // re-checks and rebinds the transports — harmless when nothing
            // actually changed.
            if attempt > 0 {
                endpoint.network_change().await;
            }

            // Establish (connect + auth). The handshake also learns the server's
            // tunnel set (drives split-tunneling) and returns the control-stream
            // halves kept open for heartbeats.
            let (connection, routed_set, ctrl_send, ctrl_recv) = match self.establish(endpoint).await
            {
                Ok(established) => {
                    ever_connected = true;
                    attempt = 0; // reset backoff on a successful connection
                    established
                }
                Err(e) => match self.handle_failure(e, ever_connected, &mut attempt) {
                    Ok(backoff) => {
                        tokio::time::sleep(backoff).await;
                        continue;
                    }
                    Err(fatal) => return Err(fatal),
                },
            };

            // Publish the live connection + route policy so the accept loop routes
            // against them; the policy is retained on the next drop (never reset to
            // None once known, so we only fail closed before the *first* connect).
            *routed_set_shared.lock().expect("routed-set lock") = Some(routed_set);
            *current.lock().expect("connection lock") = Some(connection.clone());

            // Keep the connection alive until it drops, then reconnect (or exit).
            let maintained = self.maintain(&connection, ctrl_send, ctrl_recv).await;
            // The connection is no longer live; clear the externally visible flag and the
            // shared handle so on-list targets fail cleanly during the gap.
            self.set_connected(false);
            *current.lock().expect("connection lock") = None;
            if let Err(e) = maintained {
                match self.handle_failure(e, ever_connected, &mut attempt) {
                    Ok(backoff) => {
                        tokio::time::sleep(backoff).await;
                        continue;
                    }
                    Err(fatal) => return Err(fatal),
                }
            } else {
                return Ok(());
            }
        }
    }

    /// Decide what to do with a connection error: `Ok(backoff)` to retry after
    /// the given delay, or `Err(e)` to give up.
    ///
    /// Gives up when: the first connection never succeeded (`!ever_connected` —
    /// fail fast), auto-reconnect is disabled, the error is permanent
    /// (auth/config), or an explicit attempt cap was reached. Otherwise retries.
    fn handle_failure(
        &self,
        e: ProxyError,
        ever_connected: bool,
        attempt: &mut u32,
    ) -> Result<Duration, ProxyError> {
        if !ever_connected || !self.config.auto_reconnect || !e.is_recoverable() {
            return Err(e);
        }
        *attempt += 1;
        if let Some(max) = self.config.max_reconnect_attempts
            && *attempt > max.get()
        {
            log::error!("Giving up after {} reconnect attempt(s): {e}", max.get());
            return Err(e);
        }
        let backoff = calculate_backoff(*attempt);
        log::warn!(
            "Connection lost ({e}); reconnecting in {:.1}s (attempt {})",
            backoff.as_secs_f64(),
            *attempt
        );
        Ok(backoff)
    }

    /// Connect to the server and complete the auth handshake, returning the
    /// connection, the routed set the server pushed, and the control-stream halves
    /// (kept open for heartbeats).
    async fn establish(
        &self,
        endpoint: &Endpoint,
    ) -> ProxyResult<(Connection, Arc<RoutedSet>, SendStream, RecvStream)> {
        let endpoint_addr = self.resolve_server_addr()?;
        let connection = connect_with_timeout(endpoint, endpoint_addr).await?;
        log::info!("Connected to server, authenticating...");
        let (routed_set, send, recv) = self.handshake(&connection).await?;
        log::info!("Authenticated.");
        Ok((connection, Arc::new(routed_set), send, recv))
    }

    /// Keep the connection alive: run the heartbeat and watch for the QUIC
    /// connection closing, whichever ends first. (Accepting local connections is
    /// handled independently by [`accept_loop`] so it survives a drop.)
    async fn maintain(
        &self,
        connection: &Connection,
        ctrl_send: SendStream,
        ctrl_recv: RecvStream,
    ) -> ProxyResult<()> {
        // Log the selected path (relay/direct) and any later switch, for the
        // lifetime of this connection. Guard is dropped when `maintain` returns.
        let _path_watcher = crate::transport::paths::watch_connection_paths(connection);
        tokio::select! {
            r = client_heartbeat_loop(ctrl_send, ctrl_recv, Some(self.routes.clone())) => r,
            reason = connection.closed() => Err(ProxyError::ConnectionLost(reason.to_string())),
        }
    }

    /// Resolve the server's `EndpointAddr`, attaching relay hints if given.
    fn resolve_server_addr(&self) -> ProxyResult<EndpointAddr> {
        let server_id: EndpointId = self.config.server_node_id.parse().map_err(|e| {
            ProxyError::config_with_source(
                format!("Invalid server node ID: {}", self.config.server_node_id),
                e,
            )
        })?;
        log::info!("Connecting to flextunnel server: {server_id}");

        if self.config.relay_urls.is_empty() {
            return Ok(EndpointAddr::new(server_id));
        }
        let mut addr = EndpointAddr::new(server_id);
        for relay_url_str in &self.config.relay_urls {
            let relay_url: RelayUrl = relay_url_str.parse().map_err(|e| {
                ProxyError::config_with_source(format!("Invalid relay URL: {relay_url_str}"), e)
            })?;
            addr = addr.with_relay_url(relay_url);
        }
        log::info!("Using {} relay hint(s)", self.config.relay_urls.len());
        Ok(addr)
    }

    /// Perform the connection-level auth handshake on the first bi-stream,
    /// returning the routed set (the tunnel set) the server pushed plus the
    /// control-stream halves — the stream is **not** closed; it stays open as the
    /// heartbeat channel. The client uses the routed set to split-tunnel; it
    /// configures no list of its own (the server is the single source of truth).
    async fn handshake(
        &self,
        connection: &Connection,
    ) -> ProxyResult<(RoutedSet, SendStream, RecvStream)> {
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|e| ProxyError::Signaling(format!("Failed to open handshake stream: {e}")))?;

        let mut hello = Hello::new(self.config.auth_token.clone(), self.instance_nonce);
        hello.duplicate_server_observed = self.duplicate_server.load(Ordering::Relaxed);
        signaling::write_message(&mut send, &signaling::encode_hello(&hello)?).await?;
        send.flush().await?;

        let data = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            signaling::read_message(&mut recv, signaling::MAX_HANDSHAKE_SIZE),
        )
        .await
        .map_err(|_| {
            ProxyError::Signaling("timed out waiting for server handshake response".into())
        })??;
        let response = signaling::decode_hello_response(&data)?;

        // Record the server's instance nonce (drives duplicate-server detection)
        // before the accept/reject branch so a rejection still updates history.
        let newly_flagged_duplicate = self.observe_server_nonce(response.server_instance_nonce);

        if !response.accepted {
            let reason = response.reject_reason.unwrap_or_else(|| "unknown".to_string());
            return Err(ProxyError::AuthenticationFailed(reason));
        }

        // The `Hello` already sent on this handshake could not carry the advisory
        // (the duplicate was only detected from this very response). Drop the
        // connection with a recoverable error so we reconnect immediately and the
        // next `Hello` advises the server to self-block — rather than waiting for a
        // natural disconnect that may never come while this connection is healthy.
        if newly_flagged_duplicate {
            return Err(ProxyError::ConnectionLost(
                "duplicate server id detected; reconnecting to advise the server to self-block"
                    .into(),
            ));
        }

        // Build the tunnel set from the server's pushed list. The server
        // validated these rules at startup, so a parse failure here is not
        // expected; surface it as a signaling error rather than panicking.
        let routed_set = RoutedSet::new(&response.routed_domains, &response.routed_cidrs)
            .map_err(|e| ProxyError::Signaling(format!("server pushed an invalid routed set: {e}")))?;
        // The tunnel set is required. The server validates this at startup, but
        // guard here too so a misconfigured/old server surfaces clearly instead of
        // the client silently direct-connecting everything.
        if routed_set.is_empty() {
            return Err(ProxyError::Signaling(
                "server pushed an empty tunnel set (configure a routed set, or \"*\" + 0.0.0.0/0 for full tunnel)".into(),
            ));
        }
        log::info!(
            "Server tunnel set: {} domain rule(s), {} CIDR(s) — off-list targets connect directly",
            response.routed_domains.len(),
            response.routed_cidrs.len()
        );

        // Publish the live tunnel set so status UIs can show what's forwarded.
        // Agent routes carry a connected flag seeded from the handshake's
        // `connected_agents` subset; the heartbeat loop keeps it fresh.
        if let Ok(mut routes) = self.routes.lock() {
            routes.connected = true;
            routes.domains = response.routed_domains.clone();
            routes.cidrs = response.routed_cidrs.clone();
            routes.host_aliases = response.host_aliases.clone();
            routes.agent_aliases = response
                .agent_aliases
                .iter()
                .map(|name| AgentAlias {
                    connected: response.connected_agents.contains(name),
                    name: name.clone(),
                })
                .collect();
            routes.agent_status_updated = Some(Instant::now());
            routes.dns_forwards = response.dns_forwards.clone();
            routes.bridges = response.bridges.clone();
        }
        Ok((routed_set, send, recv))
    }
}

/// Client-side heartbeat loop over the retained control stream: send a
/// `Heartbeat` every [`HEARTBEAT_INTERVAL`] and await its `HeartbeatAck` within
/// [`LIVENESS_WINDOW`]. A missing ack (or stream error) returns
/// [`ProxyError::ConnectionLost`] (recoverable), which drives the reconnect loop.
///
/// Each ack also carries the server's live connected-agent alias list; when
/// `routes` is `Some`, the matching entries' `connected` flags are refreshed so
/// the status UI stays current. Agents pass `None` (they don't display it).
///
/// Shared with [`crate::proxy::agent`]: an agent also sends heartbeats over its
/// retained control stream, so it reuses this loop (passing `None` for `routes`).
pub(crate) async fn client_heartbeat_loop(
    mut send: SendStream,
    mut recv: RecvStream,
    routes: Option<Arc<Mutex<TunnelRoutes>>>,
) -> ProxyResult<()> {
    let mut seq: u64 = 0;
    loop {
        tokio::time::sleep(HEARTBEAT_INTERVAL).await;
        seq = seq.wrapping_add(1);
        signaling::write_message(
            &mut send,
            &signaling::encode_control(&ControlMsg::Heartbeat { seq })?,
        )
        .await?;
        send.flush().await?;

        let data = tokio::time::timeout(
            LIVENESS_WINDOW,
            signaling::read_message(&mut recv, signaling::MAX_CONTROL_MSG_SIZE),
        )
        .await
        .map_err(|_| ProxyError::ConnectionLost("heartbeat ack timed out".into()))?
        .map_err(|e| ProxyError::ConnectionLost(format!("control stream closed: {e}")))?;
        // The liveness probe is only satisfied by the ack for *this* heartbeat.
        // A wrong-seq ack or any other control frame means the channel is out of
        // sync — treat it as a lost connection so we reconnect rather than count a
        // stale/unexpected message as liveness.
        match signaling::decode_control(&data)? {
            ControlMsg::HeartbeatAck {
                seq: ack,
                connected_agents,
            } if ack == seq => {
                if let Some(routes) = &routes
                    && let Ok(mut routes) = routes.lock()
                {
                    for alias in &mut routes.agent_aliases {
                        alias.connected = connected_agents.contains(&alias.name);
                    }
                    routes.agent_status_updated = Some(Instant::now());
                }
            }
            other => {
                return Err(ProxyError::ConnectionLost(format!(
                    "expected HeartbeatAck({seq}), got {other:?}"
                )));
            }
        }
    }
}

/// A local front-end request resolved to a wire [`Target`], plus how to begin
/// the upstream exchange once connected.
struct LocalRequest {
    target: Target,
    /// Bytes to write upstream before splicing: the rewritten request head of
    /// an HTTP plain-forward, whose reply is the origin's own response. `None`
    /// for pure tunnels (SOCKS5, HTTP CONNECT), which instead answer the local
    /// app with a success reply.
    upstream_preamble: Option<Vec<u8>>,
}

/// A local front-end protocol (SOCKS5 or HTTP). The protocols differ only in
/// how they parse a local request into a [`LocalRequest`] and how they answer
/// with a server reply code; everything after that — the route policy,
/// split-tunnel dial, tunnel open, and byte pipe — is shared (see
/// [`handle_local_conn`]).
///
/// Methods return `impl Future + Send` (not bare `async fn`) so the futures are
/// `Send`, which [`accept_loop`] needs to `tokio::spawn` a generic handler.
/// The local front-end stream can be a TCP loopback socket or a Unix domain
/// socket (see [`accept_loop`] / [`accept_loop_unix`]), so the request parsing
/// and byte-splicing are generic over any async stream.
trait LocalStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<S: AsyncRead + AsyncWrite + Unpin + Send> LocalStream for S {}

trait LocalProto: Clone + Send + Sync + 'static {
    /// Parse the local handshake into a [`LocalRequest`]. Any error the caller
    /// can't yet answer with a reply code (a bad request, an unsupported
    /// method) must be written to `stream` here before returning `Err`, mirroring
    /// how [`socks5::read_connect_request`] writes its own error replies.
    fn read_request<S: LocalStream>(
        &self,
        stream: &mut S,
    ) -> impl Future<Output = Result<LocalRequest>> + Send;

    /// Answer the local app with the response corresponding to server reply
    /// code `rep` ([`signaling::REP_SUCCESS`] et al.).
    fn reply<S: LocalStream>(
        &self,
        stream: &mut S,
        rep: u8,
    ) -> impl Future<Output = io::Result<()>> + Send;
}

/// SOCKS5 front-end (RFC 1928): method negotiation + CONNECT parsing, 10-byte
/// reply frames.
#[derive(Clone)]
struct Socks5Proto;

impl LocalProto for Socks5Proto {
    async fn read_request<S: LocalStream>(&self, stream: &mut S) -> Result<LocalRequest> {
        socks5::negotiate_method(stream).await?;
        Ok(LocalRequest {
            target: socks5::read_connect_request(stream).await?,
            upstream_preamble: None,
        })
    }

    async fn reply<S: LocalStream>(&self, stream: &mut S, rep: u8) -> io::Result<()> {
        socks5::write_reply(stream, rep).await
    }
}

/// HTTP proxy front-end: `CONNECT host:port` tunneling and absolute-URI
/// plain-HTTP forwarding, HTTP status-line replies.
#[derive(Clone)]
struct HttpProto;

impl LocalProto for HttpProto {
    async fn read_request<S: LocalStream>(&self, stream: &mut S) -> Result<LocalRequest> {
        Ok(match http::read_request(stream).await? {
            http::HttpRequest::Connect(target) => LocalRequest {
                target,
                upstream_preamble: None,
            },
            http::HttpRequest::Forward { target, head } => LocalRequest {
                target,
                upstream_preamble: Some(head),
            },
        })
    }

    async fn reply<S: LocalStream>(&self, stream: &mut S, rep: u8) -> io::Result<()> {
        http::write_reply(stream, rep).await
    }
}

/// How a failed `accept()` should be handled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AcceptFailure {
    /// fd exhaustion (EMFILE per-process / ENFILE system-wide; no stable
    /// `io::ErrorKind` exists for these, so the raw OS codes are matched). The
    /// listener itself is healthy — retry, and never rebind: replacing the
    /// socket wouldn't free descriptors, and dropping it would throw away the
    /// queued backlog for nothing.
    ResourcePressure,
    /// An aborted/reset accept: either a benign per-connection race (the peer
    /// gave up between the kernel queuing the connection and us accepting it)
    /// or a defunct listener failing every call — indistinguishable from one
    /// error alone, so retry and rebind only after a
    /// [`REBIND_AFTER_CONSECUTIVE_ABORTS`] burst.
    Aborted,
    /// The listener socket itself is broken (e.g. EBADF/EINVAL after the OS
    /// invalidated it) — rebind immediately.
    Broken,
}

fn classify_accept_error(e: &io::Error) -> AcceptFailure {
    #[cfg(unix)]
    if matches!(e.raw_os_error(), Some(libc::EMFILE) | Some(libc::ENFILE)) {
        return AcceptFailure::ResourcePressure;
    }
    #[cfg(windows)]
    {
        const WSAEMFILE: i32 = 10024;
        if e.raw_os_error() == Some(WSAEMFILE) {
            return AcceptFailure::ResourcePressure;
        }
    }
    match e.kind() {
        io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::Interrupted => AcceptFailure::Aborted,
        _ => AcceptFailure::Broken,
    }
}

/// Bind a replacement for a dead local listener. One retry after
/// [`ACCEPT_RETRY_DELAY`] absorbs a lingering-socket race; a second failure is
/// fatal — the port is genuinely gone (taken by another process), so ending
/// the client (and with it the embedder's health probe) beats serving nothing
/// while looking alive.
pub(crate) async fn rebind_listener(addr: SocketAddr) -> ProxyResult<TcpListener> {
    if let Ok(listener) = TcpListener::bind(addr).await {
        return Ok(listener);
    }
    tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
    Ok(TcpListener::bind(addr).await?)
}

/// What an accept error means for the loop after the failure state machine has
/// digested it.
pub(crate) enum AcceptOutcome {
    /// The listener is dead (broken, or an abort burst): rebind it in place.
    Rebind,
    /// A transient failure: back off and retry the same listener.
    Retry,
}

/// Shared accept-failure state machine for the local listeners. Tracks the
/// consecutive-failure and consecutive-abort counters and turns each accept
/// result into the rebind-or-retry decision, so [`accept_loop`] and
/// [`accept_loop_unix`] carry only their transport-specific accept, rebind, and
/// log-label differences. `label` prefixes the recovery/retry log lines
/// (e.g. "Local proxy" / "Unix SOCKS5").
pub(crate) struct AcceptRetry {
    label: &'static str,
    consecutive_failures: u64,
    consecutive_aborts: u64,
}

impl AcceptRetry {
    pub(crate) fn new(label: &'static str) -> Self {
        Self {
            label,
            consecutive_failures: 0,
            consecutive_aborts: 0,
        }
    }

    /// Record a successful accept, logging recovery if we had been failing.
    pub(crate) fn record_success(&mut self) {
        if self.consecutive_failures > 0 {
            log::info!(
                "{} accepting again after {} failed attempt(s)",
                self.label,
                self.consecutive_failures
            );
            self.consecutive_failures = 0;
        }
        self.consecutive_aborts = 0;
    }

    /// Record an accept error and decide whether to rebind or retry.
    pub(crate) fn record_error(&mut self, e: &io::Error) -> AcceptOutcome {
        let failure = classify_accept_error(e);
        self.consecutive_aborts = match failure {
            AcceptFailure::Aborted => self.consecutive_aborts + 1,
            _ => 0,
        };
        if failure == AcceptFailure::Broken
            || self.consecutive_aborts >= REBIND_AFTER_CONSECUTIVE_ABORTS
        {
            AcceptOutcome::Rebind
        } else {
            AcceptOutcome::Retry
        }
    }

    /// Reset the counters after a successful rebind.
    pub(crate) fn record_rebind(&mut self) {
        self.consecutive_failures = 0;
        self.consecutive_aborts = 0;
    }

    /// Log the retry (warn periodically, debug otherwise) and back off.
    pub(crate) async fn wait_retry(&mut self, e: &io::Error) {
        if self.consecutive_failures.is_multiple_of(ACCEPT_RETRY_WARN_EVERY) {
            log::warn!(
                "{} accept failed ({e}); retrying every {}ms",
                self.label,
                ACCEPT_RETRY_DELAY.as_millis()
            );
        } else {
            log::debug!("{} accept failed ({e}); retrying", self.label);
        }
        self.consecutive_failures += 1;
        tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
    }
}

/// Accept loop for a local front-end listener. Each accepted connection is
/// handled by [`handle_local_conn`] parameterized on `proto`. Shared verbatim by
/// the SOCKS5 and HTTP listeners.
///
/// Failure policy (see [`AcceptFailure`]): resource pressure and one-off
/// aborts are retried after [`ACCEPT_RETRY_DELAY`]; a broken listener — or an
/// abort burst, the signature of a socket the OS invalidated underneath us
/// (iOS defuncts every socket of a suspended process, and the health probe
/// would otherwise keep reading "alive" while nothing can connect) — is
/// **rebound** in place on the same address. Returns only when a rebind fails.
async fn accept_loop<P: LocalProto>(
    mut listener: TcpListener,
    current: &SharedConn,
    routed_set_shared: &SharedRoutedSet,
    proto: P,
) -> ProxyResult<()> {
    let addr = listener.local_addr()?;
    let mut retry = AcceptRetry::new("Local proxy");
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(accepted) => {
                retry.record_success();
                accepted
            }
            Err(e) => {
                match retry.record_error(&e) {
                    AcceptOutcome::Rebind => {
                        log::warn!("Local proxy listener on {addr} is dead ({e}); rebinding");
                        // The dead socket still owns the port; release it first.
                        drop(listener);
                        listener = rebind_listener(addr).await?;
                        log::info!("Local proxy listener rebound on {addr}");
                        retry.record_rebind();
                    }
                    AcceptOutcome::Retry => retry.wait_retry(&e).await,
                }
                continue;
            }
        };
        log::debug!("proxy connection from {peer}");
        let current = current.clone();
        let routed_set_shared = routed_set_shared.clone();
        let proto = proto.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_local_conn(proto, tcp, current, routed_set_shared).await {
                log::debug!("proxy connection from {peer} ended: {e}");
            }
        });
    }
}

/// Accept loop for the optional Unix-domain SOCKS5 front-end. Mirrors
/// [`accept_loop`] but for a [`UnixListener`]; the per-connection handling is
/// shared (generic over the stream type). Kept separate from the TCP loop
/// because rebinding a socket file means unlinking + re-binding a path rather
/// than a `SocketAddr`. iOS defuncts every socket of a suspended process, so the
/// same "rebind a listener the OS invalidated underneath us" policy applies.
#[cfg(unix)]
async fn accept_loop_unix(
    mut listener: UnixListener,
    current: &SharedConn,
    routed_set_shared: &SharedRoutedSet,
) -> ProxyResult<()> {
    let path = listener
        .local_addr()
        .ok()
        .and_then(|a| a.as_pathname().map(|p| p.to_path_buf()));
    let mut retry = AcceptRetry::new("Unix SOCKS5");
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _addr)) => {
                retry.record_success();
                stream
            }
            Err(e) => {
                match retry.record_error(&e) {
                    AcceptOutcome::Rebind => {
                        let Some(path) = &path else { return Err(e.into()) };
                        log::warn!("Unix SOCKS5 listener at {path:?} is dead ({e}); rebinding");
                        drop(listener);
                        listener = rebind_unix_listener(path).await?;
                        log::info!("Unix SOCKS5 listener rebound at {path:?}");
                        retry.record_rebind();
                    }
                    AcceptOutcome::Retry => retry.wait_retry(&e).await,
                }
                continue;
            }
        };
        log::debug!("unix proxy connection accepted");
        let current = current.clone();
        let routed_set_shared = routed_set_shared.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_local_conn(Socks5Proto, stream, current, routed_set_shared).await
            {
                log::debug!("unix proxy connection ended: {e}");
            }
        });
    }
}

/// Rebind a Unix-domain listener: remove the stale socket file (a defunct socket
/// still owns the path) then bind it again, with one retry after
/// [`ACCEPT_RETRY_DELAY`] to absorb a lingering-file race.
#[cfg(unix)]
async fn rebind_unix_listener(path: &std::path::Path) -> ProxyResult<UnixListener> {
    let _ = std::fs::remove_file(path);
    if let Ok(l) = UnixListener::bind(path) {
        return Ok(l);
    }
    tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
    let _ = std::fs::remove_file(path);
    Ok(UnixListener::bind(path)?)
}

/// Handle one local proxy connection: parse the front-end request, then route by
/// the current route policy — refused with a general-failure reply until the
/// policy is known (fail closed), otherwise an on-list target is tunneled to the
/// server (or answered with a network-unreachable reply if the tunnel is down)
/// and an off-list target is dialed directly from this device.
async fn handle_local_conn<P: LocalProto, S: LocalStream>(
    proto: P,
    mut tcp: S,
    current: SharedConn,
    routed_set_shared: SharedRoutedSet,
) -> Result<()> {
    // Bound the local handshake so a peer that connects and sends nothing can't
    // pin this task and its socket indefinitely.
    let LocalRequest {
        target,
        upstream_preamble,
    } = tokio::time::timeout(LOCAL_HANDSHAKE_TIMEOUT, proto.read_request(&mut tcp))
        .await
        .map_err(|_| anyhow::anyhow!("timed out during local proxy handshake"))??;

    // Fail closed until the route policy is known: before the first handshake
    // learns the tunnel set we don't route anything, so no traffic leaks out
    // (directly or tunneled) before we know how it should be routed. Answer with a
    // general-failure reply rather than leaving the app hanging.
    let policy = { routed_set_shared.lock().expect("routed-set lock").clone() };
    let Some(routed_set) = policy else {
        log::debug!("Route policy not yet known; refusing: {target:?}");
        let _ = proto.reply(&mut tcp, signaling::REP_GENERAL_FAILURE).await;
        return Ok(());
    };

    // The reserved `flextunnel.internal` namespace is always tunneled to the
    // server (which serves it itself), regardless of the pushed routed set — a
    // direct connection would just fail on a name that resolves nowhere.
    let reserved_target = matches!(&target, signaling::Target::Domain(host, _)
        if reserved::is_reserved_host(host));

    // Split-tunnel: a target not in the tunnel set is dialed directly from this
    // device's own network (its DNS, its IP) — works even when the tunnel is down.
    if !reserved_target && !routed_set.allows(&target) {
        log::debug!("Direct (off tunnel set): {target:?}");
        return direct_connect(proto, tcp, &target, upstream_preamble).await;
    }

    // On-list: needs a live tunnel. If the connection is down (a drop/backoff),
    // answer with a network-unreachable reply so the app shows a connection error
    // for this routed target instead of hanging on a dead stream.
    let conn = { current.lock().expect("connection lock").clone() };
    let Some(conn) = conn else {
        log::debug!("Tunnel down; on-list target unreachable: {target:?}");
        let _ = proto.reply(&mut tcp, signaling::REP_NET_UNREACHABLE).await;
        return Ok(());
    };
    log::debug!("Tunneling: {target:?}");

    // Open the tunnel stream and read the server's reply. If any step fails the
    // local app hasn't been answered yet, so send a general-failure reply
    // (best effort) instead of dropping the connection with no response.
    let opened = tokio::time::timeout(TUNNEL_OPEN_TIMEOUT, open_tunnel(&conn, &target))
        .await
        .map_err(|_| anyhow::anyhow!("timed out opening tunnel / awaiting server reply"))
        .and_then(|r| r);
    let (mut send, recv, rep) = match opened {
        Ok(v) => v,
        Err(e) => {
            let _ = proto.reply(&mut tcp, signaling::REP_GENERAL_FAILURE).await;
            return Err(e);
        }
    };

    if rep != signaling::REP_SUCCESS {
        proto.reply(&mut tcp, rep).await?;
        return Ok(());
    }

    // Begin the exchange: a tunnel answers the local app with a success reply
    // and splices; a forward instead writes the rewritten request head upstream
    // — the origin's response, relayed by the splice, is the app's reply.
    match &upstream_preamble {
        None => proto.reply(&mut tcp, rep).await?,
        Some(head) => {
            // A forward hasn't answered the local app yet (its reply is the
            // origin's response, relayed by the splice). If writing the head
            // upstream fails, send a best-effort HTTP failure instead of
            // dropping the connection silently.
            if let Err(e) = send.write_all(head).await {
                let _ = proto.reply(&mut tcp, signaling::REP_GENERAL_FAILURE).await;
                return Err(e.into());
            }
        }
    }

    let mut iroh = tokio::io::join(recv, send);
    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut iroh).await;
    Ok(())
}

/// Connect to `target` directly from this device (bypassing the tunnel) and pipe
/// bytes, answering the local app's request with the matching reply code via
/// `proto` (or, for an HTTP forward, writing its rewritten head upstream instead
/// of a success reply). Used for off-routed-set targets in split-tunnel mode.
/// The dial is bounded by the same deadline as opening a tunnel so a slow target
/// can't pin the task.
async fn direct_connect<P: LocalProto, S: LocalStream>(
    proto: P,
    mut tcp: S,
    target: &signaling::Target,
    upstream_preamble: Option<Vec<u8>>,
) -> Result<()> {
    // Split-tunnel direct connections resolve on the device via its own DNS;
    // server-side conditional forwarding does not apply here.
    let dialed = tokio::time::timeout(TUNNEL_OPEN_TIMEOUT, dial::dial_target(target, None)).await;
    let mut upstream = match dialed {
        Ok(Ok(mut s)) => {
            match &upstream_preamble {
                None => proto.reply(&mut tcp, signaling::REP_SUCCESS).await?,
                Some(head) => s.write_all(head).await?,
            }
            s
        }
        Ok(Err(e)) => {
            let _ = proto.reply(&mut tcp, signaling::map_io_err(&e)).await;
            return Ok(());
        }
        Err(_) => {
            let _ = proto.reply(&mut tcp, signaling::REP_HOST_UNREACHABLE).await;
            return Ok(());
        }
    };
    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut upstream).await;
    Ok(())
}

/// Open a bi-stream to the server, send the CONNECT request, and read back the
/// reply code. Returns the stream halves and the reply so the caller can relay
/// the reply to the local app and then pipe bytes.
async fn open_tunnel(
    conn: &Connection,
    target: &signaling::Target,
) -> Result<(SendStream, RecvStream, u8)> {
    let (mut send, mut recv) = conn.open_bi().await?;
    signaling::write_request(&mut send, target).await?;
    send.flush().await?;
    let rep = signaling::read_reply(&mut recv).await?;
    Ok((send, recv, rep))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpStream;
    #[cfg(unix)]
    use tokio::net::UnixStream;

    fn test_client() -> ProxyClient {
        ProxyClient::new(ClientConfig {
            server_node_id: "server".to_string(),
            auth_token: "token".to_string(),
            socks_listen: Some("127.0.0.1:0".parse().unwrap()),
            http_listen: None,
            relay_urls: Vec::new(),
            relay_auth_token: None,
            auto_reconnect: true,
            max_reconnect_attempts: None,
        })
    }

    /// fd exhaustion must be retried without ever rebinding; aborted/reset
    /// races retry and rebind only as a burst; a broken listener (bad fd)
    /// must rebind immediately instead of killing the client.
    #[cfg(unix)]
    #[test]
    fn accept_error_classification() {
        for code in [libc::EMFILE, libc::ENFILE] {
            assert_eq!(
                classify_accept_error(&io::Error::from_raw_os_error(code)),
                AcceptFailure::ResourcePressure,
                "os error {code} should be resource pressure"
            );
        }
        for code in [libc::ECONNABORTED, libc::EINTR] {
            assert_eq!(
                classify_accept_error(&io::Error::from_raw_os_error(code)),
                AcceptFailure::Aborted,
                "os error {code} should be an abort"
            );
        }
        // A kind-only error (no raw OS code) must be classified by the
        // `ErrorKind` branch alone.
        assert_eq!(
            classify_accept_error(&io::Error::new(
                io::ErrorKind::ConnectionReset,
                "peer reset before accept"
            )),
            AcceptFailure::Aborted
        );
        for code in [libc::EBADF, libc::EINVAL] {
            assert_eq!(
                classify_accept_error(&io::Error::from_raw_os_error(code)),
                AcceptFailure::Broken,
                "os error {code} should be broken"
            );
        }
    }

    /// The accept loop must survive its listener dying: a defunct listener
    /// (simulated with an abort burst via `classify_accept_error` is not
    /// injectable on a real socket, so exercise the rebind path directly) is
    /// replaced by a fresh listener on the same address once the old socket is
    /// dropped.
    #[tokio::test]
    async fn rebind_listener_reclaims_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener); // as accept_loop does: the dead socket owns the port
        let rebound = rebind_listener(addr).await.unwrap();
        assert_eq!(rebound.local_addr().unwrap(), addr);
        // And it actually accepts.
        let client = TcpStream::connect(addr);
        let (accepted, _) = tokio::join!(rebound.accept(), client);
        accepted.unwrap();
    }

    /// End-to-end over a real Unix-domain socket: `accept_loop_unix` accepts a
    /// connection, the (generic) `handle_local_conn` speaks SOCKS5, and an
    /// off-list target takes the direct path — proving the UDS front-end serves
    /// SOCKS5 exactly like the TCP one.
    #[cfg(unix)]
    #[tokio::test]
    async fn unix_socks_direct_path_serves_socks5() {
        // A local origin the proxy will dial directly (off-list).
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_port = origin.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = origin.accept().await.unwrap();
            let mut buf = [0u8; 16];
            let n = sock.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"ping");
            sock.write_all(b"pong").await.unwrap();
        });

        // The Unix-domain SOCKS5 front-end.
        let path = std::env::temp_dir().join(format!("ftuds{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        // 127.0.0.1 is off-list, so the CONNECT takes the direct path.
        let routed = RoutedSet::new(&["nothing.internal".to_string()], &["10.0.0.0/8".to_string()])
            .unwrap();
        let current: SharedConn = Arc::new(Mutex::new(None));
        let policy: SharedRoutedSet = Arc::new(Mutex::new(Some(Arc::new(routed))));
        tokio::spawn(async move {
            accept_loop_unix(listener, &current, &policy).await.ok();
        });

        // SOCKS5 client over the unix socket: greet, CONNECT 127.0.0.1:origin.
        let mut app = UnixStream::connect(&path).await.unwrap();
        app.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0u8; 2];
        app.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00], "no-auth method selected");
        let p = origin_port.to_be_bytes();
        app.write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, p[0], p[1]])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        app.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], signaling::REP_SUCCESS, "SOCKS5 CONNECT succeeded");

        // The tunnel/direct byte-splice is live: round-trip through it.
        app.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        app.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"pong");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn restart_sequence_not_flagged_as_duplicate() {
        let c = test_client();
        // A steady server, then a restart to fresh nonces (never reappearing).
        // No observation should ever newly-flag a duplicate.
        for n in [10u128, 10, 20, 30, 40] {
            assert!(!c.observe_server_nonce(n));
        }
        assert!(!c.duplicate_server.load(Ordering::Relaxed));
    }

    #[test]
    fn reappearing_nonce_flags_duplicate() {
        let c = test_client();
        // A, B, then A again (flip-flop) → two concurrent servers share the id.
        assert!(!c.observe_server_nonce(1));
        assert!(!c.observe_server_nonce(2));
        assert!(!c.duplicate_server.load(Ordering::Relaxed));
        // The reappearance newly latches the flag → caller must reconnect.
        assert!(c.observe_server_nonce(1));
        assert!(c.duplicate_server.load(Ordering::Relaxed));
        // Already latched: a further reappearance is not a *new* flag, so it must
        // not force another reconnect abort.
        assert!(!c.observe_server_nonce(2));
    }

    /// `agent_states` reflects the last-known flag while fresh, but degrades to
    /// `Unknown` when the tunnel is down, the view was never updated, or the last
    /// update is older than `AGENT_STATUS_STALE_AFTER`.
    #[test]
    fn agent_states_degrade_to_unknown_when_stale() {
        let now = Instant::now();
        let mut routes = TunnelRoutes {
            connected: true,
            agent_aliases: vec![
                AgentAlias { name: "up.internal".into(), connected: true },
                AgentAlias { name: "down.internal".into(), connected: false },
            ],
            agent_status_updated: Some(now),
            ..TunnelRoutes::default()
        };

        // Fresh view: flags map straight through.
        let states = routes.agent_states(now);
        assert_eq!(states[0], ("up.internal".into(), AgentConnState::Connected));
        assert_eq!(states[1], ("down.internal".into(), AgentConnState::Disconnected));

        // Just past the staleness window: every route reads Unknown.
        let later = now + AGENT_STATUS_STALE_AFTER + Duration::from_secs(1);
        for (_, state) in routes.agent_states(later) {
            assert_eq!(state, AgentConnState::Unknown);
        }

        // Tunnel down: Unknown regardless of a recent update.
        routes.connected = false;
        for (_, state) in routes.agent_states(now) {
            assert_eq!(state, AgentConnState::Unknown);
        }

        // Never updated: Unknown even while connected.
        routes.connected = true;
        routes.agent_status_updated = None;
        for (_, state) in routes.agent_states(now) {
            assert_eq!(state, AgentConnState::Unknown);
        }
    }

    /// End-to-end plain-HTTP forwarding through the split-tunnel *direct* path:
    /// the HTTP front-end rewrites the absolute-URI request to origin-form, the
    /// off-list target is dialed directly, the rewritten head is written
    /// upstream (no local success reply), and the origin's response streams
    /// back verbatim.
    #[tokio::test]
    async fn http_forward_direct_path_relays_origin_response() {
        // The origin: assert the head arrived rewritten, answer, and close —
        // the close is what ends the exchange (Connection: close semantics).
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_port = origin.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut sock, _) = origin.accept().await.unwrap();
            let mut head = Vec::new();
            let mut buf = [0u8; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = sock.read(&mut buf).await.unwrap();
                assert!(n > 0, "EOF before a complete request head");
                head.extend_from_slice(&buf[..n]);
            }
            let head = String::from_utf8(head).unwrap();
            assert!(
                head.starts_with("GET /hello HTTP/1.1\r\n"),
                "origin-form request line expected, got: {head:?}"
            );
            assert!(head.contains(&format!("Host: 127.0.0.1:{origin_port}\r\n")));
            assert!(head.contains("Connection: close\r\n"));
            assert!(!head.contains("Proxy-Connection"));
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi")
                .await
                .unwrap();
        });

        // The proxy: one accepted socket handled with a policy that leaves
        // 127.0.0.1 off-list, so the request takes the direct path.
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let routed = RoutedSet::new(
            &["nothing.internal".to_string()],
            &["10.0.0.0/8".to_string()],
        )
        .unwrap();
        let current: SharedConn = Arc::new(Mutex::new(None));
        let policy: SharedRoutedSet = Arc::new(Mutex::new(Some(Arc::new(routed))));
        tokio::spawn(async move {
            let (tcp, _) = proxy.accept().await.unwrap();
            handle_local_conn(HttpProto, tcp, current, policy).await.unwrap();
        });

        let mut app = TcpStream::connect(proxy_addr).await.unwrap();
        app.write_all(
            format!(
                "GET http://127.0.0.1:{origin_port}/hello HTTP/1.1\r\n\
                 Host: 127.0.0.1:{origin_port}\r\n\
                 Proxy-Connection: keep-alive\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut resp = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), app.read_to_end(&mut resp))
            .await
            .expect("proxied response timed out")
            .unwrap();
        let resp = String::from_utf8(resp).unwrap();
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "got: {resp:?}");
        assert!(resp.ends_with("hi"), "got: {resp:?}");
    }
}
