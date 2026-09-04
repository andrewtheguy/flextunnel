//! Outbound bridge: a persistent connection from this server to **another
//! flextunnel server**, used to forward tunnel streams whose target matches the
//! bridge's rules (split-tunnel across servers). The bridging server dials out
//! on its own server endpoint with the [`BRIDGE_ALPN`], so the TLS identity it
//! presents is its persistent server id — the target server's
//! `allowed_bridge_servers` allowlist matches exactly that id, natively at the
//! TLS handshake, and it is the sole bridge credential.
//!
//! [`BRIDGE_ALPN`]: crate::transport::BRIDGE_ALPN
//!
//! The connect/auth/heartbeat machinery mirrors [`super::client`], with two
//! deliberate differences in reconnect policy: a bridge retries **forever** (no
//! fail-fast first connect, no attempt cap). The peer server may simply not be
//! up yet, and a server daemon must not exit — or stop serving its other
//! routes — because a peer is down. While the upstream is down, matching
//! streams fail with host-unreachable (see `route_to_bridge` in
//! [`super::server`]). And a bridge never escalates to the client's endpoint
//! rebuild: it dials on the **server's own endpoint**, which is also accepting
//! inbound clients on its persistent identity — rebuilding it to unwedge one
//! upstream would sever every connected client.

use crate::error::{ProxyError, ProxyResult};
use crate::proxy::client::{calculate_backoff, client_heartbeat_loop, connect_with_timeout};
use crate::proxy::signaling::{self, BridgeHello};
use crate::proxy::RoutedSet;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

/// Deadline for the target server's handshake response (mirrors the client's).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Resolved config for one outbound bridge (from a `[bridges.<name>]` entry),
/// validated at startup: the endpoint id parsed and the rules parsed into a
/// [`RoutedSet`] whose coverage by the server's own routed set has been
/// checked. No credential is carried — this server's persistent endpoint id,
/// authenticated by the TLS handshake, is what the target server allowlists.
pub struct BridgeUpstreamConfig {
    /// The friendly `[bridges.<name>]` config key, for logs and status.
    pub name: String,
    /// The target server's endpoint id.
    pub endpoint_id: EndpointId,
    /// Relay hints for reaching the target server. These are the same custom
    /// relay URLs installed on this server's endpoint; the relay PSK itself is
    /// endpoint-level state and must not be copied into the peer address.
    pub relay_urls: Vec<RelayUrl>,
    /// The bridge's rules parsed into a matcher: a target this set allows is
    /// forwarded over this bridge instead of dialed locally.
    pub routed_set: RoutedSet,
    /// Raw domain rules, kept for status/GUI display.
    pub domains: Vec<String>,
    /// Raw CIDR rules, kept for status/GUI display.
    pub cidrs: Vec<String>,
}

/// One persistent upstream connection to another server, maintained by
/// [`Self::run`] with reconnect/backoff + heartbeat. `conn` is `Some` while the
/// upstream is authenticated and live, `None` during (re)connect/backoff —
/// stream routing reads it via [`Self::active_conn`] and fails fast when down.
pub struct BridgeUpstream {
    pub config: BridgeUpstreamConfig,
    conn: Mutex<Option<Connection>>,
}

impl BridgeUpstream {
    pub fn new(config: BridgeUpstreamConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            conn: Mutex::new(None),
        })
    }

    /// The live upstream connection, if authenticated right now.
    pub fn active_conn(&self) -> Option<Connection> {
        self.conn.lock().expect("bridge conn lock").clone()
    }

    /// Whether the upstream is authenticated and live right now.
    pub fn is_connected(&self) -> bool {
        self.conn.lock().expect("bridge conn lock").is_some()
    }

    /// Build the target address with the configured custom relays as hints.
    /// Custom relay mode disables n0 internet discovery, so an endpoint id by
    /// itself is not enough when the target is outside mDNS/direct reach.
    fn target_addr(&self) -> EndpointAddr {
        let mut addr = EndpointAddr::new(self.config.endpoint_id);
        for relay_url in &self.config.relay_urls {
            addr = addr.with_relay_url(relay_url.clone());
        }
        if !self.config.relay_urls.is_empty() {
            log::info!(
                "Bridge '{}': using {} relay hint(s)",
                self.config.name,
                self.config.relay_urls.len()
            );
        }
        addr
    }

    /// Maintain the upstream forever: connect + authenticate, publish the
    /// connection, heartbeat until it drops, then back off and retry. Runs for
    /// the life of the server process (spawned from `ProxyServer::run`); ends
    /// only when `endpoint` closes underneath it, failing each retry.
    pub async fn run(self: Arc<Self>, endpoint: Endpoint) {
        let name = &self.config.name;
        let mut attempt: u32 = 0;
        loop {
            if attempt > 0 {
                let backoff = calculate_backoff(attempt);
                log::debug!(
                    "Bridge '{name}': retrying in {:.1}s (attempt {attempt})",
                    backoff.as_secs_f64()
                );
                tokio::time::sleep(backoff).await;
                // Nudge the endpoint to re-check/rebind its transports before
                // retrying, in case the OS invalidated its UDP sockets (see
                // `ProxyClient::manage_connection`); harmless when nothing
                // changed.
                endpoint.network_change().await;
            }

            let (connection, ctrl_send, ctrl_recv) = match self.establish(&endpoint).await {
                Ok(established) => established,
                Err(e) => {
                    // An allowlist rejection surfaces here as the target
                    // closing the connection at the handshake with its reason
                    // ("not on this server's bridge allowlist"), carried in the
                    // error text. Retry at capped backoff regardless: the
                    // operator may fix the *target's* config without
                    // restarting this server.
                    log::warn!("Bridge '{name}': connect failed: {e}");
                    attempt = attempt.saturating_add(1);
                    continue;
                }
            };

            log::info!("Bridge '{name}': connected to {}", self.config.endpoint_id);
            *self.conn.lock().expect("bridge conn lock") = Some(connection.clone());

            // Log the selected path (relay/direct) and any later switch for the
            // lifetime of this connection.
            let _path_watcher = crate::transport::paths::watch_connection_paths(&connection);
            // A bridge runs server-to-server with no battery to protect, so its
            // heartbeat stays at the foreground cadence permanently (the sender
            // is held here so the receiver never reads as disconnected).
            let (_always_foreground, foreground_rx) = tokio::sync::watch::channel(false);
            let heartbeat = client_heartbeat_loop(ctrl_send, ctrl_recv, foreground_rx);
            let ended: ProxyResult<()> = tokio::select! {
                r = heartbeat => r,
                reason = connection.closed() => {
                    Err(ProxyError::ConnectionLost(reason.to_string()))
                }
            };
            *self.conn.lock().expect("bridge conn lock") = None;

            match ended {
                Ok(()) => log::warn!("Bridge '{name}': connection ended; reconnecting"),
                Err(e) => log::warn!("Bridge '{name}': connection lost ({e}); reconnecting"),
            }
            // A successful connection resets the backoff series: the next
            // reconnect after a drop starts at the base delay again.
            attempt = 1;
        }
    }

    /// Connect + handshake as a bridge, returning the connection and the
    /// control-stream halves (kept open for heartbeats). Authentication is the
    /// TLS handshake itself: a non-allowlisted id is rejected natively by the
    /// target's endpoint hook, surfacing here as a connect/handshake error
    /// carrying the target's close reason.
    async fn establish(
        &self,
        endpoint: &Endpoint,
    ) -> ProxyResult<(Connection, SendStream, RecvStream)> {
        let addr = self.target_addr();
        let connection = connect_with_timeout(endpoint, addr, crate::transport::BRIDGE_ALPN).await?;
        log::debug!(
            "Bridge '{}': connected to target server, handshaking...",
            self.config.name
        );
        let (send, recv) = self.handshake(&connection).await?;
        Ok((connection, send, recv))
    }

    /// Perform the bridge handshake on the first bi-stream, returning the
    /// control-stream halves. The stream stays open as the heartbeat channel.
    async fn handshake(&self, connection: &Connection) -> ProxyResult<(SendStream, RecvStream)> {
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|e| ProxyError::Signaling(format!("Failed to open handshake stream: {e}")))?;

        signaling::write_message(&mut send, &signaling::encode_bridge_hello(&BridgeHello::new())?)
            .await?;
        send.flush().await?;

        let data = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            signaling::read_message(&mut recv, signaling::MAX_HANDSHAKE_SIZE),
        )
        .await
        .map_err(|_| {
            ProxyError::Signaling("timed out waiting for target-server handshake response".into())
        })??;
        let response = signaling::decode_hello_response(&data)?;

        if !response.accepted {
            let reason = response.reject_reason.unwrap_or_else(|| "unknown".to_string());
            return Err(ProxyError::AuthenticationFailed(reason));
        }
        // The target server pushes no routed set to a bridge (it re-enforces its
        // own set per stream); ignore any list fields.
        Ok((send, recv))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    fn bridge_with_relays(relay_urls: Vec<RelayUrl>) -> Arc<BridgeUpstream> {
        BridgeUpstream::new(BridgeUpstreamConfig {
            name: "test".to_string(),
            endpoint_id: SecretKey::generate().public(),
            relay_urls,
            routed_set: RoutedSet::default(),
            domains: Vec::new(),
            cidrs: Vec::new(),
        })
    }

    #[test]
    fn target_addr_without_custom_relays_has_no_addressing_hints() {
        let bridge = bridge_with_relays(Vec::new());

        let addr = bridge.target_addr();

        assert_eq!(addr.id, bridge.config.endpoint_id);
        assert!(addr.is_empty());
    }

    #[test]
    fn target_addr_includes_every_custom_relay() {
        let mut expected = vec![
            "https://relay-b.example".parse::<RelayUrl>().unwrap(),
            "https://relay-a.example".parse::<RelayUrl>().unwrap(),
        ];
        let bridge = bridge_with_relays(expected.clone());

        let addr = bridge.target_addr();

        expected.sort();
        assert_eq!(addr.relay_urls().cloned().collect::<Vec<_>>(), expected);
    }
}
