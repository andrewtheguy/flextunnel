//! flextunnel's endpoints: what this program layers onto the shared
//! [`flexaccess_iroh::endpoint`] builder — its three ALPNs, the native
//! per-ALPN allowlist hook, and the client/server identity rules. Relay
//! configuration, the per-relay startup probe, the creation-vs-rebuild
//! policy, and the rebuildable endpoint handle all come from the shared crate.

use crate::transport::{ALPN, BRIDGE_ALPN, QUICK_ALPN, build_quic_transport_config};
use anyhow::Result;
use flexaccess_iroh::endpoint::{
    EndpointOptions, create_endpoint, endpoint_builder, rebuild_endpoint,
};
use iroh::{
    Endpoint, EndpointId, SecretKey,
    endpoint::{
        AfterHandshakeOutcome, Builder as EndpointBuilder, Connection, EndpointHooks, Side,
        VarInt,
    },
};
use std::collections::HashSet;
use std::sync::Arc;

pub use flexaccess_iroh::endpoint::{
    EndpointFactory, RebuildableEndpoint as ClientEndpoint, load_secret, load_secret_from_string,
    secret_to_endpoint_id,
};
pub use flexaccess_iroh::relay::{RELAY_CONNECT_TIMEOUT, RelayConfig};

/// QUIC application close code sent when a connection is rejected by an
/// endpoint-id allowlist — a non-allowlisted bridge on [`BRIDGE_ALPN`] or a
/// non-allowlisted quick client on [`QUICK_ALPN`] (distinct from the in-band
/// auth-failure code `1` and the duplicate-id code `2` used on the keypair
/// client path).
pub const CLOSE_NOT_ALLOWLISTED: u32 = 3;

/// The server's per-ALPN endpoint-id allowlists, enforced natively at the TLS
/// handshake by [`AllowlistHook`]. An empty set disables its ALPN entirely —
/// the allowlist is the sole and mandatory credential on both.
#[derive(Debug, Default, Clone)]
pub struct EndpointAllowlists {
    /// Servers allowed to bridge into this server over [`BRIDGE_ALPN`].
    pub bridge_servers: HashSet<EndpointId>,
    /// Clients allowed to connect over [`QUICK_ALPN`] (quick mode — normally a
    /// single id, entered on the quick server).
    pub quick_clients: HashSet<EndpointId>,
}

/// Native allowlist access control: an [`EndpointHooks`] that rejects inbound
/// [`BRIDGE_ALPN`] / [`QUICK_ALPN`] connections whose TLS-authenticated
/// endpoint id is not on the matching [`EndpointAllowlists`] set. Runs the
/// moment the handshake completes, so a rejected peer never reaches the accept
/// loop; the dialer sees the connection close with [`CLOSE_NOT_ALLOWLISTED`]
/// and the reason text.
///
/// Only the accepting side is gated: outbound dials (this server bridging
/// *out*) pass through, as do inbound [`ALPN`] client connections (gated by
/// their keypair handshake).
#[derive(Debug)]
pub struct AllowlistHook {
    allowlists: EndpointAllowlists,
}

impl AllowlistHook {
    pub fn new(allowlists: EndpointAllowlists) -> Self {
        Self { allowlists }
    }
}

impl EndpointHooks for AllowlistHook {
    async fn after_handshake(&self, conn: &Connection) -> AfterHandshakeOutcome {
        if conn.side() != Side::Server {
            return AfterHandshakeOutcome::Accept;
        }
        let alpn = conn.alpn();
        let (allowed, kind, disabled_reason, rejected_reason) = if alpn == BRIDGE_ALPN {
            (
                &self.allowlists.bridge_servers,
                "bridge",
                "bridging is not enabled on this server",
                "server id is not on this server's bridge allowlist",
            )
        } else if alpn == QUICK_ALPN {
            (
                &self.allowlists.quick_clients,
                "quick client",
                "quick mode is not enabled on this server",
                "client id is not on this server's quick-client allowlist",
            )
        } else {
            return AfterHandshakeOutcome::Accept;
        };
        let remote_id = conn.remote_id();
        if allowed.contains(&remote_id) {
            return AfterHandshakeOutcome::Accept;
        }
        let reason = if allowed.is_empty() {
            disabled_reason
        } else {
            rejected_reason
        };
        log::warn!("Rejecting {kind} {remote_id}: {reason}");
        AfterHandshakeOutcome::Reject {
            error_code: VarInt::from_u32(CLOSE_NOT_ALLOWLISTED),
            reason: reason.as_bytes().to_vec(),
        }
    }
}

/// The shared base builder with flextunnel's QUIC transport tuning. mDNS
/// local-network discovery is on (the shared crate's `mdns` feature; compiled
/// out on iOS by the crate itself).
fn base_builder(relay_config: &RelayConfig, publish_address: bool) -> Result<EndpointBuilder> {
    Ok(endpoint_builder(
        relay_config,
        EndpointOptions {
            transport_config: build_quic_transport_config()?,
            publish_address,
        },
    ))
}

/// A server endpoint builder: persistent identity (published on the default
/// relays), all three server ALPNs, the allowlist hook. Binding policy is the
/// caller's — [`create_server_endpoint`] and [`server_rebuild_factory`] each
/// layer their own.
fn server_builder(
    relay_config: &RelayConfig,
    secret: SecretKey,
    allowlists: EndpointAllowlists,
) -> Result<EndpointBuilder> {
    Ok(base_builder(relay_config, true)?
        .alpns(vec![ALPN.to_vec(), BRIDGE_ALPN.to_vec(), QUICK_ALPN.to_vec()])
        .hooks(AllowlistHook::new(allowlists))
        .secret_key(secret))
}

/// Create a server endpoint with a persistent identity, accepting the client
/// [`ALPN`], the bridge [`BRIDGE_ALPN`], and the quick-client [`QUICK_ALPN`].
/// Inbound bridge and quick-client connections are gated natively by an
/// [`AllowlistHook`] over `allowlists` (an empty set = that path disabled).
///
/// A single endpoint serves both relay modes. With the default relays internet
/// discovery is on, so the server publishes its current home relay and clients
/// resolve it by endpoint ID. With custom relays discovery is off, so clients
/// reach the server through relay hints, while outbound bridges attach those
/// same hints to their target `EndpointAddr`. Strict first-creation policy:
/// every custom relay is probed and the endpoint must come online.
pub async fn create_server_endpoint(
    relay_config: &RelayConfig,
    secret: SecretKey,
    allowlists: EndpointAllowlists,
) -> Result<Endpoint> {
    create_endpoint(relay_config, server_builder(relay_config, secret, allowlists)?).await
}

/// The rebuild recipe for the server endpoint, used when the relay watchdog
/// gives up on the current one. Same identity and allowlists as the original,
/// so the server's id — what clients dial — never changes. Tolerant rebuild
/// policy (see [`rebuild_endpoint`]): no relay probe, and the online wait may
/// fail — the watchdog trips again if the relays stay unreachable, with a
/// lengthening deadline so a dead relay does not churn the endpoint every few
/// minutes (see the CLI's serve loop).
pub fn server_rebuild_factory(
    relay_config: RelayConfig,
    secret: SecretKey,
    allowlists: EndpointAllowlists,
) -> EndpointFactory {
    Arc::new(move || {
        let relay_config = relay_config.clone();
        let secret = secret.clone();
        let allowlists = allowlists.clone();
        Box::pin(async move {
            rebuild_endpoint(server_builder(&relay_config, secret, allowlists)?).await
        })
    })
}

/// A client endpoint builder. A client never publishes its address (it only
/// dials out), even with a quick-mode secret bound as its identity.
fn client_builder(relay_config: &RelayConfig, secret: Option<SecretKey>) -> Result<EndpointBuilder> {
    let mut builder = base_builder(relay_config, false)?;
    if let Some(secret) = secret {
        builder = builder.secret_key(secret);
    }
    Ok(builder)
}

/// Create a client endpoint (ephemeral identity) that can rebuild itself
/// mid-session. Strict first-creation policy, tolerant rebuilds.
pub async fn create_client_endpoint(relay_config: &RelayConfig) -> Result<ClientEndpoint> {
    create_client(relay_config, None).await
}

/// Create a **quick-mode** client endpoint: same as [`create_client_endpoint`]
/// but bound to the given (session-ephemeral) `secret`, so the endpoint id the
/// user entered on the quick server is the id this endpoint presents in the
/// TLS handshake — that id is the quick client's sole credential. The
/// identity is still never published (the client only dials), so pkarr
/// publishing stays off exactly as for an anonymous client, and a rebuild
/// keeps the same id.
pub async fn create_quick_client_endpoint(
    relay_config: &RelayConfig,
    secret: SecretKey,
) -> Result<ClientEndpoint> {
    create_client(relay_config, Some(secret)).await
}

async fn create_client(relay_config: &RelayConfig, secret: Option<SecretKey>) -> Result<ClientEndpoint> {
    let endpoint = create_endpoint(relay_config, client_builder(relay_config, secret.clone())?).await?;
    let factory: EndpointFactory = {
        let relay_config = relay_config.clone();
        Arc::new(move || {
            let relay_config = relay_config.clone();
            let secret = secret.clone();
            Box::pin(async move { rebuild_endpoint(client_builder(&relay_config, secret)?).await })
        })
    };
    Ok(ClientEndpoint::from_parts(endpoint, factory))
}
