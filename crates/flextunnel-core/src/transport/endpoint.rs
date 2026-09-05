//! flextunnel's endpoints: what this program layers onto the shared
//! [`flexaccess_iroh::endpoint`] builder — its three ALPNs, the native
//! per-ALPN allowlist hook, the client/server identity rules, and the
//! client's rebuildable endpoint handle ([`ClientEndpoint`], the reconnect
//! loop's escalation for a wedged endpoint). Relay configuration, the
//! per-relay startup probe, the bind-and-come-online policy, and the server's
//! in-place home-relay failover come from the shared crate; the server's
//! secret-key file is [`crate::secret`]'s.

use crate::transport::{ALPN, BRIDGE_ALPN, QUICK_ALPN, build_quic_transport_config};
use anyhow::{Context, Result};
use flexaccess_iroh::endpoint::{
    CreatedEndpoint, EndpointOptions, create_endpoint, endpoint_builder,
};
use futures::future::BoxFuture;
use iroh::{
    Endpoint, EndpointId, SecretKey,
    endpoint::{
        AfterHandshakeOutcome, Builder as EndpointBuilder, Connection, EndpointHooks, Side,
        VarInt,
    },
};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

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
            relay_only: false,
        },
    ))
}

/// A server endpoint builder: persistent identity (published on the default
/// relays), all three server ALPNs, the allowlist hook.
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
/// same hints to their target `EndpointAddr`. Every custom relay is probed
/// (startup fails only if none answers), the endpoint is bound without the
/// relays that failed and must come online. The relays left out come back in
/// [`CreatedEndpoint::relays_left_out`] for the home-relay failover (run by
/// the CLI's serve loop) to restore once they are connectable.
pub async fn create_server_endpoint(
    relay_config: &RelayConfig,
    secret: SecretKey,
    allowlists: EndpointAllowlists,
) -> Result<CreatedEndpoint> {
    create_endpoint(relay_config, server_builder(relay_config, secret, allowlists)?).await
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
/// mid-session. The first creation probes every custom relay and must come
/// online (see [`create_endpoint`]); rebuilds are tolerant (see
/// [`rebuild_client_endpoint`]).
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
    // A relay that failed the startup probe stays out of this endpoint's relay
    // map for its lifetime: a client only dials, runs no failover, and
    // reaches the server through the relay hints it attaches, so a rebuilt
    // endpoint (below) goes back to the full configured set instead.
    let CreatedEndpoint { endpoint, .. } =
        create_endpoint(relay_config, client_builder(relay_config, secret.clone())?).await?;
    let factory: EndpointFactory = {
        let relay_config = relay_config.clone();
        Arc::new(move || {
            let relay_config = relay_config.clone();
            let secret = secret.clone();
            Box::pin(async move {
                rebuild_client_endpoint(client_builder(&relay_config, secret)?).await
            })
        })
    };
    Ok(ClientEndpoint::from_parts(endpoint, factory))
}

/// Mid-session replacement of a client endpoint, the recipe behind an
/// [`EndpointFactory`]. Differs from [`create_endpoint`] deliberately:
///
/// - **No per-relay probe.** At creation the probe validates the
///   configuration; during an outage it would only delay the reconnect it is
///   part of.
/// - **The online wait is tolerated failing.** A fresh endpoint is no worse
///   than the wedged one it replaces — a client only dials, so its relay
///   hints and mDNS can still reach the server without a home relay — and the
///   reconnect loop that asked for the rebuild escalates again if the relays
///   stay unreachable.
async fn rebuild_client_endpoint(builder: EndpointBuilder) -> Result<Endpoint> {
    let endpoint = builder.bind().await.context("Failed to create iroh endpoint")?;
    if tokio::time::timeout(RELAY_CONNECT_TIMEOUT, endpoint.online())
        .await
        .is_err()
    {
        log::warn!(
            "Rebuilt endpoint has no connected home relay after {}s; continuing (relay hints \
             and local discovery may still reach the server)",
            RELAY_CONNECT_TIMEOUT.as_secs()
        );
    }
    Ok(endpoint)
}

/// Recipe producing a fresh, fully bound endpoint — how a [`ClientEndpoint`]
/// replaces itself mid-session.
pub type EndpointFactory = Arc<dyn Fn() -> BoxFuture<'static, Result<Endpoint>> + Send + Sync>;

/// Bound wait on the old endpoint's graceful close during a rebuild. The close
/// runs as its own task and is never cancelled (dropping a bound endpoint
/// without `close()` is fatal under panic=abort); the bound only keeps the
/// reconnect loop from stalling behind it, letting a slow close finish in the
/// background.
const REBUILD_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// A client endpoint handle that can be **rebuilt** from scratch mid-session.
///
/// `Endpoint::network_change()` re-binds dead UDP transports, but a wedged
/// endpoint can be broken beyond what a rebind repairs: a relay link lost to a
/// ping timeout that never re-establishes, stale cached paths for the server,
/// dead discovery state. A process restart always recovers because it builds a
/// brand-new endpoint; [`Self::rebuild`] gives the reconnect loop that same
/// remedy in-process — fresh sockets, fresh relay connections, fresh discovery
/// — without dropping anything else the process holds (the bound proxy
/// listeners, port forwards, the status socket).
///
/// The handle is `Clone` and shared: the reconnect loop escalates to
/// [`Self::rebuild`] after repeated failures, while the embedder logs
/// [`Self::id`] and [`Self::close`]s whatever endpoint is current at teardown.
/// Client-only: the server's endpoint is bound once and kept, its home relay
/// moved in place by the shared failover.
#[derive(Clone)]
pub struct ClientEndpoint {
    /// The live endpoint, swapped by [`Self::rebuild`]. Std lock: accessors
    /// clone the handle out synchronously and never hold it across an await.
    current: Arc<std::sync::RwLock<Current>>,
    factory: EndpointFactory,
    /// Serializes [`Self::rebuild`]'s build-and-swap: the handle is shared,
    /// and two callers noticing the same outage must not each build an
    /// endpoint and have the second discard (and close) the first's good one.
    rebuilding: Arc<tokio::sync::Mutex<()>>,
}

/// The installed endpoint plus how many rebuilds produced it, so a rebuild
/// caller can tell whether one already happened while it waited its turn.
struct Current {
    generation: u64,
    endpoint: Endpoint,
}

impl ClientEndpoint {
    /// Wrap a bound endpoint with the recipe that rebuilds it.
    pub fn from_parts(endpoint: Endpoint, factory: EndpointFactory) -> Self {
        Self {
            current: Arc::new(std::sync::RwLock::new(Current {
                generation: 0,
                endpoint,
            })),
            factory,
            rebuilding: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    /// A clone of the current endpoint handle. Take it fresh per use: a handle
    /// held across a [`Self::rebuild`] keeps pointing at the old, closed
    /// endpoint.
    pub fn endpoint(&self) -> Endpoint {
        self.current.read().expect("endpoint lock").endpoint.clone()
    }

    /// The current endpoint id. Changes on rebuild for an ephemeral identity;
    /// stable when the factory binds a fixed secret (quick mode).
    pub fn id(&self) -> EndpointId {
        self.endpoint().id()
    }

    fn generation(&self) -> u64 {
        self.current.read().expect("endpoint lock").generation
    }

    /// Swap in a freshly built endpoint and close the old one. On error the
    /// current endpoint stays in place, so the caller can simply retry with it.
    ///
    /// Concurrent calls coalesce: a caller that arrives while another rebuild
    /// is in flight waits for it and, if it installed a fresh endpoint,
    /// returns `Ok` without building another — its trigger was the same dead
    /// endpoint, and [`Self::endpoint`] now yields the replacement. Only if
    /// the in-flight rebuild failed does the waiter build one itself.
    pub async fn rebuild(&self) -> Result<()> {
        let seen = self.generation();
        let old = {
            let _serialized = self.rebuilding.lock().await;
            if self.generation() != seen {
                log::info!(
                    "Endpoint already rebuilt by a concurrent caller; endpoint id: {}",
                    self.id()
                );
                return Ok(());
            }
            let fresh = (self.factory)().await?;
            let mut current = self.current.write().expect("endpoint lock");
            current.generation += 1;
            std::mem::replace(&mut current.endpoint, fresh)
        };
        // Graceful close on its own task: bounded wait here, but the task is
        // never cancelled (see [`REBUILD_CLOSE_TIMEOUT`]).
        let mut close = tokio::task::spawn(async move { old.close().await });
        if tokio::time::timeout(REBUILD_CLOSE_TIMEOUT, &mut close)
            .await
            .is_err()
        {
            log::warn!("Old endpoint's close is slow; leaving it to finish in the background");
        }
        log::info!("Endpoint rebuilt; endpoint id: {}", self.id());
        Ok(())
    }

    /// Close the current endpoint gracefully (session teardown).
    pub async fn close(&self) {
        self.endpoint().close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::{RelayMode, endpoint::presets};

    // Hermetic: loopback-only endpoints, no relays, no discovery.
    fn loopback() -> EndpointBuilder {
        Endpoint::builder(presets::Empty)
            .relay_mode(RelayMode::Disabled)
            .crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
    }

    #[tokio::test]
    async fn client_endpoint_swaps_and_closes_the_old_one() {
        let first = loopback().bind().await.unwrap();
        let first_id = first.id();
        let handle = ClientEndpoint::from_parts(
            first.clone(),
            Arc::new(|| Box::pin(async { loopback().bind().await.map_err(Into::into) })),
        );
        assert_eq!(handle.id(), first_id);

        handle.rebuild().await.unwrap();
        assert_ne!(handle.id(), first_id, "an ephemeral rebuild gets a new id");
        assert!(first.is_closed(), "the replaced endpoint is closed");
        handle.close().await;
        assert!(handle.endpoint().is_closed());
    }

    #[tokio::test]
    async fn concurrent_rebuilds_coalesce_into_one() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let builds = Arc::new(AtomicUsize::new(0));
        let first = loopback().bind().await.unwrap();
        let handle = ClientEndpoint::from_parts(first.clone(), {
            let builds = builds.clone();
            Arc::new(move || {
                builds.fetch_add(1, Ordering::SeqCst);
                Box::pin(async {
                    // Hold the build long enough for the second caller to
                    // queue behind it.
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    loopback().bind().await.map_err(Into::into)
                })
            })
        });

        let a = handle.clone();
        let b = handle.clone();
        let (ra, rb) = tokio::join!(a.rebuild(), async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            b.rebuild().await
        });
        ra.unwrap();
        rb.unwrap();
        assert_eq!(builds.load(Ordering::SeqCst), 1, "the second caller joined the first");
        assert!(first.is_closed());
        assert!(!handle.endpoint().is_closed(), "the one fresh endpoint is live");

        // A rebuild after the coalesced one is a new outage: it builds again.
        handle.rebuild().await.unwrap();
        assert_eq!(builds.load(Ordering::SeqCst), 2);
        handle.close().await;
    }
}
