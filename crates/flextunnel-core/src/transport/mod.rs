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

/// QUIC keep-alive interval. Active connections send pings at this interval to
/// keep NAT mappings alive and detect dead peers promptly. Matches iroh's relay
/// ping interval (15s), comfortably under the 30s idle timeout.
pub const QUIC_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// QUIC idle timeout. A connection with no activity (data or keep-alive) for
/// this long is considered dead and closed, resolving `Connection::closed()`.
pub const QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Initial QUIC path MTU (UDP payload bytes) before MTU discovery completes.
/// 1452 is the IPv6-safe maximum for a standard 1500-byte Ethernet path
/// (`1500 − 40 IPv6 − 8 UDP`) and matches quinn's DPLPMTUD upper-bound default.
pub const QUIC_INITIAL_MTU: u16 = 1452;

/// App-level heartbeat interval. After the auth handshake the control stream is
/// kept open and the client sends a `Heartbeat` this often; the server replies
/// with a `HeartbeatAck`. This is a semantic liveness signal on top of QUIC's
/// keep-alive: it refreshes the server's per-client connection registry (used
/// for duplicate-id detection) faster than the 30s QUIC idle timeout would.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

/// Grace added to the heartbeat liveness window so a heartbeat delayed by
/// scheduler/network jitter isn't misread as a dead connection right at the
/// 3×-interval boundary.
const LIVENESS_GRACE: Duration = Duration::from_secs(3);

/// Liveness window for the app-level heartbeat. A connection whose control
/// stream produces no heartbeat traffic for this long is treated as dead (on the
/// server) or as a lost connection (on the client). Derived as 3× the interval
/// (tolerating a couple of dropped heartbeats) plus [`LIVENESS_GRACE`], so a
/// late-but-valid heartbeat doesn't race the timeout at exactly 3× the interval.
/// For a genuinely dead peer the QUIC idle timeout (30s) is the backstop that
/// closes the connection first.
pub const LIVENESS_WINDOW: Duration =
    Duration::from_secs(HEARTBEAT_INTERVAL.as_secs() * 3 + LIVENESS_GRACE.as_secs());

/// QUIC ALPN protocol identifier for flextunnel.
///
/// A plain protocol-negotiation label, sent unencrypted in the TLS/QUIC
/// handshake — it is not a secret and provides no access control. Both peers
/// must offer the same ALPN or negotiation fails; access control is enforced by
/// the auth-token handshake, not by this value.
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
/// [`endpoint::AllowlistHook`]. No auth token is involved — the
/// TLS-authenticated endpoint id needs no further proof. After the handshake a
/// quick client is served exactly like a token client.
pub const QUICK_ALPN: &[u8] = b"flextunnel-quick/1";

/// Build a QUIC transport config with keep-alive, idle timeout, and a larger
/// initial MTU. Shared by client and server endpoint creation so both sides
/// apply identical settings.
pub fn build_quic_transport_config() -> Result<QuicTransportConfig> {
    let mut transport_config = QuicTransportConfig::builder();
    let idle_timeout = QUIC_IDLE_TIMEOUT
        .try_into()
        .context("converting QUIC_IDLE_TIMEOUT to IdleTimeout")?;
    transport_config = transport_config.max_idle_timeout(Some(idle_timeout));
    transport_config = transport_config.keep_alive_interval(QUIC_KEEP_ALIVE_INTERVAL);
    transport_config = transport_config.initial_mtu(QUIC_INITIAL_MTU);
    Ok(transport_config.build())
}
