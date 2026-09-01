//! flextunnel client: local SOCKS5 and optional HTTP proxy listeners whose
//! routed requests are tunneled over a single iroh QUIC connection to the
//! server, one bi-stream per proxied connection.

use crate::error::{ProxyError, ProxyResult};
use crate::proxy::signaling::{self, ControlMsg, Hello, Target};
use crate::proxy::{dial, http, reserved, socks5, RoutedSet};
use crate::transport::endpoint::RelayConfig;
use crate::transport::paths::{connection_paths, ConnPath, ConnectionSnapshot};
use crate::transport::{HEARTBEAT_INTERVAL, HEARTBEAT_INTERVAL_IDLE, liveness_window};
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
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::sync::{Semaphore, watch};

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

/// Connect to `addr` with `alpn` bounded by [`CONNECT_TIMEOUT`], mapping both
/// the timeout and the underlying connect error to a signaling error. Shared by
/// the client (`ALPN`) and bridge (`BRIDGE_ALPN`) `establish()` flows.
pub(crate) async fn connect_with_timeout(
    endpoint: &Endpoint,
    addr: EndpointAddr,
    alpn: &[u8],
) -> ProxyResult<Connection> {
    tokio::time::timeout(CONNECT_TIMEOUT, endpoint.connect(addr, alpn))
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
/// How long an on-list request arriving while the tunnel link is down is held
/// waiting for the core's own reconnect before being refused with a
/// network-unreachable reply — connection holding in the style of a deploy
/// router: a routed page load racing a transient drop waits out the reconnect
/// and then proceeds as if nothing happened, instead of surfacing an error the
/// user must retry by hand. Sized to cover a silent drop end-to-end in the
/// foreground: detection takes up to [`liveness_window`] of
/// [`HEARTBEAT_INTERVAL`] (33s), then the early backoff steps plus the
/// connect+handshake; a reconnect that hasn't landed by then is genuinely
/// stuck, and the bound keeps the failure inside a browser's own patience.
const TUNNEL_RECOVERY_HOLD: Duration = Duration::from_secs(45);
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
/// Cap on concurrent proxied connections per local front-end listener. At the
/// cap the loop pauses accepting — further connections wait in the kernel
/// backlog — until one closes, so a runaway local app degrades into queueing
/// instead of exhausting the process's file descriptors (each proxied
/// connection holds a socket plus a QUIC stream). Generous for the real
/// client: a browser's worst case is a few dozen parallel fetches.
const MAX_ACTIVE_LOCAL_CONNS: usize = 256;
/// Cap on requests concurrently *held* for a tunnel reconnect per local
/// front-end listener (see [`wait_for_tunnel`]). A held request parks with its
/// [`MAX_ACTIVE_LOCAL_CONNS`] permit for up to [`TUNNEL_RECOVERY_HOLD`], so
/// without a separate bound a burst of on-list retries during an outage could
/// pin every permit and starve the off-list/direct traffic a drop is supposed
/// to leave working. At this cap further on-list requests fall back to the
/// pre-hold behavior: an immediate network-unreachable reply.
const MAX_HELD_CONNS: usize = 64;

/// The live QUIC connection shared with the always-on accept loop; `None` while
/// disconnected (during a drop/backoff), so off-list targets still connect
/// directly. Published over a watch channel so on-list requests arriving during
/// the gap can subscribe and hold for the reconnect (see [`wait_for_tunnel`]).
type SharedConn = Arc<watch::Sender<Option<Connection>>>;
/// The route policy (tunnel set) shared with the accept loop. `None` until the
/// first handshake learns it, then `Some` for the rest of the process — retained
/// across drops so split-tunnel routing keeps working while the connection is
/// down. While it is `None` the client **fails closed**: no connection is routed
/// (directly or tunneled) before the policy is known, so nothing leaks out.
type SharedRoutedSet = Arc<Mutex<Option<Arc<RoutedSet>>>>;

/// How the client authenticates to the server.
pub enum ClientAuth {
    /// Regular client: dial the client [`ALPN`](crate::transport::ALPN) and
    /// present this keypair's public key plus a signature over the client's
    /// own (ephemeral) endpoint id in the `Hello` (see [`crate::auth`]).
    /// Boxed to keep the variants close in size (clippy: large_enum_variant).
    Key(Box<crate::auth::ClientKey>),
    /// Quick-mode client: dial [`QUICK_ALPN`](crate::transport::QUICK_ALPN)
    /// with no keypair. The sole credential is this endpoint's
    /// TLS-authenticated id, which the quick server has allowlisted — the
    /// endpoint must be bound to the session's fixed secret (see
    /// `create_quick_client_endpoint`).
    QuickAllowlisted,
}

/// Configuration for the proxy client.
pub struct ClientConfig {
    /// Server's iroh EndpointId (as a string).
    pub server_node_id: String,
    /// How to authenticate: signed keypair credential, or quick-mode endpoint-id allowlist.
    pub auth: ClientAuth,
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
            .borrow()
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
            current: Arc::new(watch::Sender::new(Some(connection))),
        }
    }
}

/// Exponential backoff with jitter for the Nth (1-based) reconnect attempt.
///
/// Shared with [`crate::proxy::bridge`], whose reconnect policy mirrors the
/// client's.
pub(crate) fn calculate_backoff(attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(6); // cap the doubling at 2^6 = 64
    let secs = (1u64 << shift).min(RECONNECT_BACKOFF_MAX);
    let jitter = rand::rng().random_range(0..=RECONNECT_JITTER_MAX_MS);
    Duration::from_secs(secs) + Duration::from_millis(jitter)
}

/// Snapshot of what the tunnel currently forwards: the split-tunnel set the
/// server pushed on the last successful handshake, plus whether a connection is
/// live right now. Shared with the FFI so the app can display the routed
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
    /// One-way close signal for the local front-end listeners, latched by
    /// [`Self::close_local_listeners`]. The accept loops watch the receiving
    /// side and drop their listener when it flips.
    local_close: watch::Sender<bool>,
    /// Whether the embedding app is backgrounded (mobile embedders flip this
    /// from their scene lifecycle via [`Self::set_background`]). Drives the
    /// heartbeat cadence: [`HEARTBEAT_INTERVAL`] in the foreground,
    /// [`HEARTBEAT_INTERVAL_IDLE`] in the background, switching mid-wait.
    background: watch::Sender<bool>,
    /// Whether the device reports a usable network path
    /// ([`Self::set_network_available`]; defaults to available for embedders
    /// that never report). While unavailable the reconnect loop parks with no
    /// timers at all — retrying into a dead path is pure battery burn — and a
    /// flip back to available reconnects immediately with a fresh backoff.
    network_available: watch::Sender<bool>,
}

impl ProxyClient {
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config,
            routes: Arc::new(Mutex::new(TunnelRoutes::default())),
            current: Arc::new(watch::Sender::new(None)),
            instance_nonce: rand::rng().random(),
            nonce_tracker: Mutex::new(ServerNonceTracker::default()),
            duplicate_server: AtomicBool::new(false),
            local_close: watch::Sender::new(false),
            background: watch::Sender::new(false),
            network_available: watch::Sender::new(true),
        }
    }

    /// Report the embedding app's scene state. Backgrounded, the heartbeat
    /// slows to [`HEARTBEAT_INTERVAL_IDLE`] (one radio wake a minute instead of
    /// six); foregrounded, it snaps back to [`HEARTBEAT_INTERVAL`] — a beat
    /// already overdue at the faster cadence is sent immediately. Safe to call
    /// repeatedly with the same value.
    pub fn set_background(&self, background: bool) {
        self.background.send_replace(background);
    }

    /// Report whether the device has a usable network path (e.g. from
    /// `NWPathMonitor`). While unavailable the reconnect loop parks instead of
    /// burning backoff retries into a dead path; the flip back to available
    /// triggers an immediate reconnect with a fresh backoff series.
    pub fn set_network_available(&self, available: bool) {
        self.network_available.send_replace(available);
    }

    /// Close the local proxy front-end listeners (SOCKS5/HTTP/Unix) while
    /// leaving the session — the connection manager and established relays —
    /// running. One-way: there is no reopen for this client; the embedder
    /// relaunches the session when it wants listeners back.
    ///
    /// For embedders whose process is about to be suspended (iOS): the kernel
    /// keeps accepting into a frozen process's listen backlog, so a suspended
    /// listener is a black hole — local clients connect and then hang. Closing
    /// the listeners first turns that into an immediate connection-refused.
    pub fn close_local_listeners(&self) {
        self.local_close.send_replace(true);
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

    /// Shared handle to the live tunnel set, for callers (the FFI) that want to
    /// display what is routed. Refreshed on every (re)connect.
    pub fn routes(&self) -> Arc<Mutex<TunnelRoutes>> {
        self.routes.clone()
    }

    /// Snapshot the current connection's iroh paths (relay/direct) for a status
    /// UI. Empty while disconnected (during a drop/backoff or before the first
    /// connect). Cheap and synchronous — [`connection_paths`] reads a
    /// point-in-time snapshot, so no background watcher is involved.
    pub fn conn_paths(&self) -> Vec<ConnPath> {
        match self.current.borrow().as_ref() {
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
    /// tunnel is up, matching the paths list). The connection is cloned out of the
    /// watch borrow before the `.await`, so the borrow is never held across it.
    pub async fn connection_snapshot(&self) -> ConnectionSnapshot {
        let conn = self.current.borrow().clone();
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
    /// off-list targets keep connecting directly, while on-list requests are held
    /// for the reconnect (failing with network-unreachable only after
    /// [`TUNNEL_RECOVERY_HOLD`]).
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
    /// reconnect policy). Callers that need the actual bound address — e.g. the
    /// FFI binding to an ephemeral `127.0.0.1:0` and reporting the chosen port —
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
    /// SOCKS5 front-end on an optional **Unix domain socket** listener. The iOS
    /// embedder uses this to expose the proxy over a socket file inside the app's
    /// sandbox container (reachable only by this app) instead of a loopback TCP
    /// port (reachable by any process on the device). Both front-ends speak the
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
                Some(l) => {
                    accept_loop(l, &current, &routed_set, HttpProto, self.local_close.subscribe())
                        .await
                }
                None => std::future::pending::<ProxyResult<()>>().await,
            }
        };

        let socks_accept = async {
            match socks_listener {
                Some(l) => {
                    accept_loop(l, &current, &routed_set, Socks5Proto, self.local_close.subscribe())
                        .await
                }
                None => std::future::pending::<ProxyResult<()>>().await,
            }
        };

        // Same for the optional Unix-domain SOCKS5 front-end. Unix only: on other
        // platforms this branch is inert (there is no Unix-domain listener), so
        // the `select!` shape stays identical.
        let unix_accept = async {
            #[cfg(unix)]
            if let Some(l) = unix_listener {
                return accept_loop_unix(l, &current, &routed_set, self.local_close.subscribe())
                    .await;
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
        // Set when the last backoff resumed from a parked (path-lost) state:
        // the backoff series was reset, but the endpoint still needs the rebind
        // nudge below — the network genuinely changed underneath it. Every
        // retry passes through `wait_backoff`, which reassigns it.
        let mut path_returned = false;
        loop {
            // Until (re)authenticated, nothing is being forwarded.
            self.set_connected(false);
            current.send_replace(None);

            // Retrying after a failure: the endpoint's UDP sockets may be dead
            // underneath it (iOS defuncts them while the process is suspended;
            // a sleeping laptop can do the same) and iroh cannot always detect
            // that by itself, leaving reconnects wedged forever. Nudging it
            // re-checks and rebinds the transports — harmless when nothing
            // actually changed.
            if attempt > 0 || path_returned {
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
                        path_returned = self.wait_backoff(backoff, &mut attempt).await;
                        continue;
                    }
                    Err(fatal) => return Err(fatal),
                },
            };

            // Publish the live connection + route policy so the accept loop routes
            // against them; the policy is retained on the next drop (never reset to
            // None once known, so we only fail closed before the *first* connect).
            *routed_set_shared.lock().expect("routed-set lock") = Some(routed_set);
            // Publishing the reconnected handle wakes every request held in
            // [`wait_for_tunnel`], which then proceeds on the fresh connection.
            current.send_replace(Some(connection.clone()));

            // Keep the connection alive until it drops, then reconnect (or exit).
            let maintained = self.maintain(&connection, ctrl_send, ctrl_recv).await;
            // The connection is no longer live; clear the FFI-visible flag and the
            // shared handle so on-list targets hold for the reconnect (and fail
            // cleanly if it doesn't land) during the gap.
            self.set_connected(false);
            current.send_replace(None);
            if let Err(e) = maintained {
                match self.handle_failure(e, ever_connected, &mut attempt) {
                    Ok(backoff) => {
                        path_returned = self.wait_backoff(backoff, &mut attempt).await;
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

    /// Sit out a reconnect backoff, gated on network availability: while the
    /// device reports no usable path, park with **no timers at all** (retrying
    /// into a dead path detects nothing and, on cellular, wakes the radio for
    /// nothing) and return as soon as the path comes back — resetting the
    /// backoff series so the restored network gets an immediate, fresh
    /// reconnect. While the path is up this is a plain backoff sleep, except
    /// that a mid-sleep loss switches to parking.
    ///
    /// Returns whether the wait resumed from a parked state — i.e. the network
    /// went away and came back — so the caller can nudge
    /// `Endpoint::network_change()` even though the attempt counter was reset.
    async fn wait_backoff(&self, backoff: Duration, attempt: &mut u32) -> bool {
        let mut available = self.network_available.subscribe();
        if !*available.borrow() {
            log::info!("Network unavailable; pausing reconnects until a path returns");
            // The sender lives in self, so this cannot error while we run.
            let _ = available.wait_for(|a| *a).await;
            log::info!("Network available again; reconnecting now");
            *attempt = 0;
            return true;
        }
        let lost_mid_sleep = tokio::select! {
            _ = tokio::time::sleep(backoff) => false,
            r = available.wait_for(|a| !*a) => r.is_ok(),
        };
        if lost_mid_sleep {
            log::info!("Network unavailable; pausing reconnects until a path returns");
            let _ = available.wait_for(|a| *a).await;
            log::info!("Network available again; reconnecting now");
            *attempt = 0;
            return true;
        }
        false
    }

    /// Connect to the server and complete the auth handshake, returning the
    /// connection, the routed set the server pushed, and the control-stream halves
    /// (kept open for heartbeats).
    async fn establish(
        &self,
        endpoint: &Endpoint,
    ) -> ProxyResult<(Connection, Arc<RoutedSet>, SendStream, RecvStream)> {
        let endpoint_addr = self.resolve_server_addr()?;
        let alpn = match &self.config.auth {
            ClientAuth::Key(_) => crate::transport::ALPN,
            ClientAuth::QuickAllowlisted => crate::transport::QUICK_ALPN,
        };
        let connection = connect_with_timeout(endpoint, endpoint_addr, alpn).await?;
        log::info!("Connected to server, authenticating...");
        let (routed_set, send, recv) = self.handshake(&connection, endpoint.id()).await?;
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
            r = client_heartbeat_loop(ctrl_send, ctrl_recv, self.background.subscribe()) => r,
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
    ///
    /// `own_id` is this client's (ephemeral) endpoint id, which a keypair
    /// client signs into its credential so the server can bind the signature
    /// to this very connection.
    async fn handshake(
        &self,
        connection: &Connection,
        own_id: EndpointId,
    ) -> ProxyResult<(RoutedSet, SendStream, RecvStream)> {
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|e| ProxyError::Signaling(format!("Failed to open handshake stream: {e}")))?;

        let auth = match &self.config.auth {
            ClientAuth::Key(key) => Some(signaling::ClientAuthPayload {
                public_key: key.public_str(),
                endpoint_id: own_id.to_string(),
                signature: key.sign_endpoint_id(&own_id),
            }),
            // Quick mode: the endpoint id is the credential; the server's
            // allowlist hook already authenticated it at the TLS handshake.
            ClientAuth::QuickAllowlisted => None,
        };
        let mut hello = Hello::new(auth, self.instance_nonce);
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

        // Publish the live tunnel set so the FFI/app can show what's forwarded.
        if let Ok(mut routes) = self.routes.lock() {
            routes.connected = true;
            routes.domains = response.routed_domains.clone();
            routes.cidrs = response.routed_cidrs.clone();
            routes.host_aliases = response.host_aliases.clone();
            routes.dns_forwards = response.dns_forwards.clone();
            routes.bridges = response.bridges.clone();
        }
        Ok((routed_set, send, recv))
    }
}

/// Client-side heartbeat loop over the retained control stream: send a
/// `Heartbeat` at the current cadence — [`HEARTBEAT_INTERVAL`] while
/// foregrounded, [`HEARTBEAT_INTERVAL_IDLE`] while `background` reads true —
/// and await its `HeartbeatAck` within [`liveness_window`] of that cadence. A
/// missing ack (or stream error) returns [`ProxyError::ConnectionLost`]
/// (recoverable), which drives the reconnect loop.
///
/// A cadence flip takes effect on the *current* wait: the deadline is
/// recomputed from the last heartbeat, so a foreground flip 50s into an idle
/// minute sends the overdue beat immediately, and a background flip stretches
/// the pending wait instead of firing one more fast beat.
///
/// Shared with [`crate::proxy::bridge`]: a bridge also sends heartbeats over its
/// retained control stream, so it reuses this loop (with a receiver that is
/// permanently foreground — servers have no battery to protect).
pub(crate) async fn client_heartbeat_loop(
    mut send: SendStream,
    mut recv: RecvStream,
    mut background: watch::Receiver<bool>,
) -> ProxyResult<()> {
    let mut seq: u64 = 0;
    loop {
        let last_beat = tokio::time::Instant::now();
        let interval = loop {
            let interval = if *background.borrow() {
                HEARTBEAT_INTERVAL_IDLE
            } else {
                HEARTBEAT_INTERVAL
            };
            tokio::select! {
                _ = tokio::time::sleep_until(last_beat + interval) => break interval,
                changed = background.changed() => {
                    // A dropped sender can't change the cadence any more; sleep
                    // out the current interval plainly instead of spinning.
                    if changed.is_err() {
                        tokio::time::sleep_until(last_beat + interval).await;
                        break interval;
                    }
                }
            }
        };
        seq = seq.wrapping_add(1);
        signaling::write_message(
            &mut send,
            &signaling::encode_control(&ControlMsg::Heartbeat { seq })?,
        )
        .await?;
        send.flush().await?;

        let data = tokio::time::timeout(
            liveness_window(interval),
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
            ControlMsg::HeartbeatAck { seq: ack } if ack == seq => {}
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

/// Acquire a permit against the per-listener connection cap, warning once per
/// saturation episode. At the cap this pauses the accept loop — further
/// connections queue in the kernel backlog — until a connection closes.
async fn acquire_conn_permit(
    limiter: &Arc<Semaphore>,
    warned_saturated: &mut bool,
    label: &str,
) -> tokio::sync::OwnedSemaphorePermit {
    if limiter.available_permits() == 0 {
        if !*warned_saturated {
            *warned_saturated = true;
            log::warn!(
                "{label} reached {MAX_ACTIVE_LOCAL_CONNS} concurrent connections; \
                 pausing accepts until one closes"
            );
        }
    } else {
        *warned_saturated = false;
    }
    limiter
        .clone()
        .acquire_owned()
        .await
        .expect("connection limiter is never closed")
}

/// Resolve once the local-listener close signal latches. Pends forever if the
/// signal's sender is gone — no close can arrive anymore — so a `select!` arm
/// built on this never fires spuriously. Cancel-safe (`watch::Receiver::wait_for`
/// is).
async fn listener_closed(close: &mut watch::Receiver<bool>) {
    if close.wait_for(|closed| *closed).await.is_err() {
        std::future::pending::<()>().await;
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
/// **rebound** in place on the same address. Concurrency is bounded by
/// [`MAX_ACTIVE_LOCAL_CONNS`]. Returns only when a rebind fails; on the
/// [`ProxyClient::close_local_listeners`] signal the listener is dropped and
/// the loop parks forever so the enclosing `select!` keeps the session alive.
async fn accept_loop<P: LocalProto>(
    mut listener: TcpListener,
    current: &SharedConn,
    routed_set_shared: &SharedRoutedSet,
    proto: P,
    mut close: watch::Receiver<bool>,
) -> ProxyResult<()> {
    let addr = listener.local_addr()?;
    let mut retry = AcceptRetry::new("Local proxy");
    let limiter = Arc::new(Semaphore::new(MAX_ACTIVE_LOCAL_CONNS));
    let hold_limiter = Arc::new(Semaphore::new(MAX_HELD_CONNS));
    let mut warned_saturated = false;
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            _ = listener_closed(&mut close) => {
                log::info!("Local proxy listener on {addr} closed on request");
                break;
            }
        };
        let (tcp, peer) = match accepted {
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
        // A saturated listener parks here, not in accept, so the close signal
        // must preempt this wait too (dropping the just-accepted socket).
        let permit = tokio::select! {
            permit = acquire_conn_permit(&limiter, &mut warned_saturated, "Local proxy") => permit,
            _ = listener_closed(&mut close) => {
                log::info!("Local proxy listener on {addr} closed on request");
                break;
            }
        };
        let current = current.clone();
        let routed_set_shared = routed_set_shared.clone();
        let proto = proto.clone();
        let hold_limiter = hold_limiter.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) =
                handle_local_conn(proto, tcp, current, routed_set_shared, hold_limiter).await
            {
                log::debug!("proxy connection from {peer} ended: {e}");
            }
        });
    }
    // Closed on request. Release the socket so new local connections get an
    // immediate refusal, then park: returning would resolve the session's
    // `select!` and tear down the tunnel, which must outlive its front-ends.
    drop(listener);
    std::future::pending().await
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
    mut close: watch::Receiver<bool>,
) -> ProxyResult<()> {
    let path = listener
        .local_addr()
        .ok()
        .and_then(|a| a.as_pathname().map(|p| p.to_path_buf()));
    let mut retry = AcceptRetry::new("Unix SOCKS5");
    let limiter = Arc::new(Semaphore::new(MAX_ACTIVE_LOCAL_CONNS));
    let hold_limiter = Arc::new(Semaphore::new(MAX_HELD_CONNS));
    let mut warned_saturated = false;
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            _ = listener_closed(&mut close) => {
                log::info!("Unix SOCKS5 listener at {path:?} closed on request");
                break;
            }
        };
        let stream = match accepted {
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
        // As in `accept_loop`: the close signal must preempt a saturated wait.
        let permit = tokio::select! {
            permit = acquire_conn_permit(&limiter, &mut warned_saturated, "Unix SOCKS5") => permit,
            _ = listener_closed(&mut close) => {
                log::info!("Unix SOCKS5 listener at {path:?} closed on request");
                break;
            }
        };
        let current = current.clone();
        let routed_set_shared = routed_set_shared.clone();
        let hold_limiter = hold_limiter.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) =
                handle_local_conn(Socks5Proto, stream, current, routed_set_shared, hold_limiter)
                    .await
            {
                log::debug!("unix proxy connection ended: {e}");
            }
        });
    }
    // Closed on request: as in `accept_loop`, release the socket and park so
    // the session outlives its front-ends. The socket file is left behind;
    // connecting to it now fails with ECONNREFUSED.
    drop(listener);
    std::future::pending().await
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
/// server (held up to [`TUNNEL_RECOVERY_HOLD`] for the reconnect if the tunnel
/// is down — concurrent holds capped by `hold_limiter` — then answered with a
/// network-unreachable reply) and an off-list target is dialed directly from
/// this device.
async fn handle_local_conn<P: LocalProto, S: LocalStream>(
    proto: P,
    mut tcp: S,
    current: SharedConn,
    routed_set_shared: SharedRoutedSet,
    hold_limiter: Arc<Semaphore>,
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
    // hold the request for the core's own reconnect — up to
    // [`TUNNEL_RECOVERY_HOLD`] — so a routed page load racing a transient drop
    // proceeds transparently once the link is back. Only a reconnect that never
    // lands answers with a network-unreachable reply, so the app shows a
    // connection error for this routed target instead of hanging forever.
    let Some(conn) = wait_for_tunnel(&current, &hold_limiter).await else {
        log::debug!("Tunnel still down after hold; on-list target unreachable: {target:?}");
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

/// The live tunnel connection, immediately when one is up, otherwise a bounded
/// wait for the reconnect loop to publish a replacement. `None` once
/// [`TUNNEL_RECOVERY_HOLD`] elapses — or the session is tearing down (sender
/// gone) — without a connection. Concurrent holds are capped by `holds`
/// ([`MAX_HELD_CONNS`] per listener): at the cap the wait is skipped entirely,
/// so parked on-list requests can never pin the whole
/// [`MAX_ACTIVE_LOCAL_CONNS`] budget that off-list/direct traffic shares.
async fn wait_for_tunnel(current: &SharedConn, holds: &Semaphore) -> Option<Connection> {
    let mut live = current.subscribe();
    if let Some(conn) = live.borrow().clone() {
        return Some(conn);
    }
    let Ok(_hold) = holds.try_acquire() else {
        // Re-check before giving up: a reconnect landing between the borrow
        // above and the failed acquire should still be served.
        log::debug!("Hold capacity exhausted; not holding on-list request");
        return live.borrow().clone();
    };
    log::debug!(
        "Tunnel down; holding on-list request up to {}s for the reconnect",
        TUNNEL_RECOVERY_HOLD.as_secs()
    );
    // `wait_for` re-inspects the current value first, so a publish racing the
    // borrow above is never missed.
    match tokio::time::timeout(TUNNEL_RECOVERY_HOLD, live.wait_for(|conn| conn.is_some())).await {
        Ok(Ok(conn)) => conn.clone(),
        _ => None,
    }
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
            auth: ClientAuth::Key(Box::new(crate::auth::ClientKey::generate())),
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

    /// `close_local_listeners` must drop the front-end listener — local
    /// connects turn into refusals — while the accept future stays pending, so
    /// the session `select!` it lives in keeps the tunnel running.
    #[tokio::test]
    async fn close_signal_drops_listener_without_ending_loop() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = test_client();
        let close = client.local_close.subscribe();
        let current: SharedConn = Arc::new(watch::Sender::new(None));
        let routed: SharedRoutedSet = Arc::new(Mutex::new(None));
        let task = {
            let (current, routed) = (current.clone(), routed.clone());
            tokio::spawn(async move {
                accept_loop(listener, &current, &routed, Socks5Proto, close).await
            })
        };
        // Live: a local connect lands.
        TcpStream::connect(addr).await.unwrap();

        client.close_local_listeners();
        // Closed: once the loop observes the signal and drops the listener,
        // connects are refused. Poll — the drop happens on the spawned task.
        let refused = async {
            loop {
                if TcpStream::connect(addr).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(5), refused)
            .await
            .expect("listener still accepting after close signal");
        // ...but the loop itself parks instead of resolving the session.
        assert!(!task.is_finished());
    }

    /// At the connection cap the loop parks awaiting a permit, not in accept;
    /// the close signal must preempt that wait too and still drop the listener.
    #[tokio::test]
    async fn close_signal_preempts_saturated_listener() {
        // ~2×(cap+1) sockets live at once; don't let the soft fd limit flake it.
        crate::app::raise_fd_limit();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = test_client();
        let close = client.local_close.subscribe();
        let current: SharedConn = Arc::new(watch::Sender::new(None));
        let routed: SharedRoutedSet = Arc::new(Mutex::new(None));
        let task = {
            let (current, routed) = (current.clone(), routed.clone());
            tokio::spawn(async move {
                accept_loop(listener, &current, &routed, Socks5Proto, close).await
            })
        };
        // Saturate every permit with idle connections (each accepted handler
        // sits in the SOCKS handshake read for LOCAL_HANDSHAKE_TIMEOUT, holding
        // its permit), plus one more so the loop parks in permit acquisition.
        let mut held = Vec::new();
        for _ in 0..=MAX_ACTIVE_LOCAL_CONNS {
            held.push(TcpStream::connect(addr).await.unwrap());
        }

        client.close_local_listeners();
        let refused = async {
            loop {
                if TcpStream::connect(addr).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(5), refused)
            .await
            .expect("saturated listener still accepting after close signal");
        assert!(!task.is_finished());
        drop(held);
    }

    /// Unix-domain twin of `close_signal_preempts_saturated_listener`: the
    /// close-vs-permit race is duplicated in `accept_loop_unix`, so cover it
    /// there as well (a closed Unix listener refuses instead of accepting).
    #[cfg(unix)]
    #[tokio::test]
    async fn close_signal_preempts_saturated_unix_listener() {
        crate::app::raise_fd_limit();
        let path = std::env::temp_dir().join(format!("ftsat{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let client = test_client();
        let close = client.local_close.subscribe();
        let current: SharedConn = Arc::new(watch::Sender::new(None));
        let routed: SharedRoutedSet = Arc::new(Mutex::new(None));
        let task = {
            let (current, routed) = (current.clone(), routed.clone());
            tokio::spawn(async move {
                accept_loop_unix(listener, &current, &routed, close).await
            })
        };
        let mut held = Vec::new();
        for _ in 0..=MAX_ACTIVE_LOCAL_CONNS {
            held.push(UnixStream::connect(&path).await.unwrap());
        }

        client.close_local_listeners();
        let refused = async {
            loop {
                if UnixStream::connect(&path).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(5), refused)
            .await
            .expect("saturated unix listener still accepting after close signal");
        assert!(!task.is_finished());
        drop(held);
        let _ = std::fs::remove_file(&path);
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
        let current: SharedConn = Arc::new(watch::Sender::new(None));
        let policy: SharedRoutedSet = Arc::new(Mutex::new(Some(Arc::new(routed))));
        let (_close_tx, close_rx) = watch::channel(false);
        tokio::spawn(async move {
            accept_loop_unix(listener, &current, &policy, close_rx).await.ok();
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

    /// With the network reported unavailable, a reconnect backoff must park
    /// (not sleep out its delay), then return promptly — with the backoff
    /// series reset — the moment the path comes back.
    #[tokio::test]
    async fn backoff_parks_offline_and_resumes_on_path_return() {
        let client = Arc::new(test_client());
        client.set_network_available(false);
        let c = client.clone();
        let task = tokio::spawn(async move {
            let mut attempt = 5;
            // Far longer than the test timeout: only the path-return signal can
            // end the wait in time.
            let resumed = c.wait_backoff(Duration::from_secs(300), &mut attempt).await;
            (attempt, resumed)
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!task.is_finished(), "backoff ended while offline");
        client.set_network_available(true);
        let (attempt, resumed) = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("backoff did not resume on path return")
            .unwrap();
        assert_eq!(attempt, 0, "restored path should reset the backoff series");
        assert!(resumed, "a parked backoff must report the path return");
    }

    /// A path lost *during* the backoff sleep switches it to parking: the wait
    /// outlives its original delay, then resumes — backoff series reset, path
    /// return reported — once the path comes back.
    #[tokio::test(start_paused = true)]
    async fn backoff_parks_when_path_lost_mid_sleep() {
        let client = Arc::new(test_client());
        let c = client.clone();
        let task = tokio::spawn(async move {
            let mut attempt = 5;
            let resumed = c.wait_backoff(Duration::from_millis(100), &mut attempt).await;
            (attempt, resumed)
        });
        // Part-way into the 100ms sleep, drop the path (paused time only
        // advances while every task is idle, so this lands mid-sleep).
        tokio::time::sleep(Duration::from_millis(30)).await;
        client.set_network_available(false);
        // Well past the original delay: the wait must be parked, not timing out.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!task.is_finished(), "backoff ended while offline");
        client.set_network_available(true);
        let (attempt, resumed) = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("backoff did not resume on path return")
            .unwrap();
        assert_eq!(attempt, 0, "restored path should reset the backoff series");
        assert!(resumed, "a mid-sleep loss must report the path return");
    }

    /// While the network is available a backoff is a plain sleep: it must run
    /// its full delay and leave the attempt counter alone.
    #[tokio::test]
    async fn backoff_sleeps_normally_while_online() {
        let client = test_client();
        let mut attempt = 3;
        let started = std::time::Instant::now();
        let resumed = client
            .wait_backoff(Duration::from_millis(200), &mut attempt)
            .await;
        assert!(started.elapsed() >= Duration::from_millis(200));
        assert_eq!(attempt, 3);
        assert!(!resumed, "an uninterrupted sleep saw no path return");
    }

    /// While the tunnel stays down a held request must wait out the full
    /// recovery window before giving up — the hold is a real wait, not a
    /// fail-fast with extra steps.
    #[tokio::test(start_paused = true)]
    async fn tunnel_hold_times_out_after_recovery_window() {
        let current: SharedConn = Arc::new(watch::Sender::new(None));
        let holds = Semaphore::new(MAX_HELD_CONNS);
        let started = tokio::time::Instant::now();
        assert!(wait_for_tunnel(&current, &holds).await.is_none());
        assert!(started.elapsed() >= TUNNEL_RECOVERY_HOLD);
        // The hold permit is released once the wait gives up.
        assert_eq!(holds.available_permits(), MAX_HELD_CONNS);
    }

    /// At the hold cap the wait is skipped: with no permits left a hold must
    /// give up immediately (the pre-hold fail-fast) instead of parking.
    #[tokio::test]
    async fn tunnel_hold_fails_fast_at_hold_cap() {
        let current: SharedConn = Arc::new(watch::Sender::new(None));
        let exhausted = Semaphore::new(0);
        let started = std::time::Instant::now();
        assert!(wait_for_tunnel(&current, &exhausted).await.is_none());
        assert!(
            started.elapsed() < TUNNEL_RECOVERY_HOLD,
            "an at-cap request must not wait out the recovery hold"
        );
    }

    /// An on-list request arriving while the tunnel is down is *held* for the
    /// reconnect — the SOCKS reply must not arrive in the window where the old
    /// fail-fast behavior answered network-unreachable immediately. (The
    /// held-then-proceeds path needs a real reconnect; see the e2e test
    /// `on_list_request_is_held_across_reconnect`.)
    #[tokio::test]
    async fn on_list_request_holds_while_tunnel_down() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Loopback is on-list; no connection is published (drop/backoff).
        let routed = RoutedSet::new(&[], &["127.0.0.0/8".to_string()]).unwrap();
        let current: SharedConn = Arc::new(watch::Sender::new(None));
        let policy: SharedRoutedSet = Arc::new(Mutex::new(Some(Arc::new(routed))));
        tokio::spawn(async move {
            let holds = Arc::new(Semaphore::new(MAX_HELD_CONNS));
            let (tcp, _) = listener.accept().await.unwrap();
            let _ = handle_local_conn(Socks5Proto, tcp, current, policy, holds).await;
        });

        let mut app = TcpStream::connect(addr).await.unwrap();
        app.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut method = [0u8; 2];
        app.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x00], "no-auth method selected");
        app.write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        let held =
            tokio::time::timeout(Duration::from_millis(750), app.read_exact(&mut reply)).await;
        assert!(held.is_err(), "on-list request was answered instead of held");
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
        let current: SharedConn = Arc::new(watch::Sender::new(None));
        let policy: SharedRoutedSet = Arc::new(Mutex::new(Some(Arc::new(routed))));
        tokio::spawn(async move {
            let holds = Arc::new(Semaphore::new(MAX_HELD_CONNS));
            let (tcp, _) = proxy.accept().await.unwrap();
            handle_local_conn(HttpProto, tcp, current, policy, holds)
                .await
                .unwrap();
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
