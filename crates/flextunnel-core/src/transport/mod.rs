//! QUIC transport configuration shared by client and server endpoint setup.
//!
//! Unlike the ezvpn VPN this is derived from, the data path here is reliable
//! QUIC bi-streams (not unreliable datagrams), so there is no datagram-buffer,
//! congestion-controller, or flow-control-window tuning — just keep-alive,
//! idle timeout, and a larger initial MTU.

pub mod endpoint;
pub mod paths;

use anyhow::{Context, Result};
use iroh::endpoint::QuicTransportConfig;
use std::time::Duration;

/// QUIC idle timeout. A connection with no activity for this long is considered
/// dead and closed, resolving `Connection::closed()`.
///
/// There is deliberately **no QUIC-level keep-alive**: the app-level heartbeat
/// below is the sole periodic sender, so an idle connection costs exactly one
/// radio wake per heartbeat instead of two overlapping ping schedules. On
/// cellular every transmission buys ~10s of high-power radio tail, so the
/// heartbeat cadence — not payload size — is the battery cost. The timeout must
/// comfortably exceed the widest heartbeat cadence
/// ([`HEARTBEAT_INTERVAL_IDLE`], 60s) so a healthy-but-quiet connection never
/// idles out; a genuinely dead one is detected sooner by the heartbeat's own
/// liveness window while active, with this as the backstop while idle.
pub const QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(180);

/// Initial QUIC path MTU (UDP payload bytes) before MTU discovery completes.
/// 1452 is the IPv6-safe maximum for a standard 1500-byte Ethernet path
/// (`1500 − 40 IPv6 − 8 UDP`) and matches quinn's DPLPMTUD upper-bound default.
pub const QUIC_INITIAL_MTU: u16 = 1452;

/// App-level heartbeat interval while the client is **active** (foregrounded,
/// or a non-mobile embedder). After the auth handshake the control stream is
/// kept open and the client sends a `Heartbeat` this often; the server replies
/// with a `HeartbeatAck`. The heartbeat is both the liveness probe (a missing
/// ack within [`liveness_window`] means a dead link) and, with no QUIC
/// keep-alive configured, the traffic that keeps NAT mappings and the idle
/// timeout refreshed.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

/// App-level heartbeat interval while the client is **idle in the background**
/// (a mobile embedder reported the app backgrounded — see
/// `ProxyClient::set_background`). One send per minute keeps the cellular radio
/// in its low-power state almost the whole time (anything periodic under
/// ~15–20s keeps it high continuously), matching where battery-conscious peers
/// converged: Tailscale stops idle-session heartbeats entirely, DERP relays
/// keepalive at 60s, and Apple's historical background-heartbeat floor was 10
/// minutes. Liveness detection widens to [`liveness_window`] of this — a dead
/// link found within ~3 minutes is fine for a backgrounded session, and the
/// foreground flip snaps the cadence (and detection) back immediately.
pub const HEARTBEAT_INTERVAL_IDLE: Duration = Duration::from_secs(60);

/// Grace added to the heartbeat liveness window so a heartbeat delayed by
/// scheduler/network jitter isn't misread as a dead connection right at the
/// 3×-interval boundary.
const LIVENESS_GRACE: Duration = Duration::from_secs(3);

/// Liveness window for an app-level heartbeat cadence: 3× the interval
/// (tolerating a couple of dropped heartbeats) plus [`LIVENESS_GRACE`], so a
/// late-but-valid heartbeat doesn't race the timeout at exactly 3× the
/// interval. The client sizes the window from the cadence it is actually using.
pub const fn liveness_window(interval: Duration) -> Duration {
    Duration::from_secs(interval.as_secs() * 3 + LIVENESS_GRACE.as_secs())
}

/// The server's liveness window for client heartbeats. A connection whose
/// control stream produces no heartbeat for this long is treated as dead. Sized
/// for the **widest** client cadence ([`HEARTBEAT_INTERVAL_IDLE`]) because the
/// server cannot know which cadence a client is on; an active client going
/// silent is still closed by the QUIC idle timeout, just later than its own
/// 3×10s window would have been. Slower server-side reaping only delays
/// duplicate-id detection and registry cleanup for genuinely dead clients.
pub const LIVENESS_WINDOW: Duration = liveness_window(HEARTBEAT_INTERVAL_IDLE);

/// QUIC ALPN protocol identifier for flextunnel.
///
/// A plain protocol-negotiation label, sent unencrypted in the TLS/QUIC
/// handshake — it is not a secret and provides no access control. Both peers
/// must offer the same ALPN or negotiation fails; access control is enforced by
/// the keypair auth handshake, not by this value.
pub const ALPN: &[u8] = b"flextunnel/1";

/// QUIC ALPN protocol identifier for server-to-server **bridge** connections.
///
/// The ALPN carries the peer's *role* (bridge vs client) so the two paths can
/// be told apart at the transport layer; like [`ALPN`] it is not a credential.
/// Bridge access control is the receiving server's endpoint-id allowlist,
/// enforced natively at the TLS handshake (see
/// [`endpoint::AllowlistHook`]) — the id needs no further proof because
/// iroh's handshake authenticates it.
pub const BRIDGE_ALPN: &[u8] = b"flextunnel-bridge/1";

/// QUIC ALPN protocol identifier for **quick-mode** client connections
/// (`client start --quick` ↔ `server start --quick`).
///
/// Same trust model as [`BRIDGE_ALPN`]: the ALPN only carries the peer's role;
/// the credential is the server's endpoint-id allowlist (the single client id
/// entered on the quick server), enforced natively at the TLS handshake by
/// [`endpoint::AllowlistHook`]. No auth keypair is involved — the
/// TLS-authenticated endpoint id needs no further proof. After the handshake a
/// quick client is served exactly like a keypair client.
pub const QUICK_ALPN: &[u8] = b"flextunnel-quick/1";

/// Build a QUIC transport config with the idle timeout and a larger initial
/// MTU — and **no transport keep-alive** (see [`QUIC_IDLE_TIMEOUT`]; the
/// app-level heartbeat is the sole periodic sender). Shared by client and
/// server endpoint creation so both sides apply identical settings.
pub fn build_quic_transport_config() -> Result<QuicTransportConfig> {
    let mut transport_config = QuicTransportConfig::builder();
    let idle_timeout = QUIC_IDLE_TIMEOUT
        .try_into()
        .context("converting QUIC_IDLE_TIMEOUT to IdleTimeout")?;
    transport_config = transport_config.max_idle_timeout(Some(idle_timeout));
    transport_config = transport_config.initial_mtu(QUIC_INITIAL_MTU);
    Ok(transport_config.build())
}
