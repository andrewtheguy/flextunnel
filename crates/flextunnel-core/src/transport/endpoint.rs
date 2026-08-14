//! Common endpoint helpers for iroh proxy connections.

use crate::transport::{ALPN, BRIDGE_ALPN, QUICK_ALPN, build_quic_transport_config};
use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use futures::future::join_all;
use iroh::{
    Endpoint, EndpointId, RelayMap, RelayMode, RelayUrl, SecretKey,
    endpoint::{
        AfterHandshakeOutcome, Builder as EndpointBuilder, Connection, EndpointHooks, Side,
        VarInt, presets,
    },
    address_lookup::{DnsAddressLookup, PkarrPublisher},
};
#[cfg(not(target_os = "ios"))]
use iroh_mdns_address_lookup::MdnsAddressLookup;
use log::info;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// QUIC application close code sent when a connection is rejected by an
/// endpoint-id allowlist — a non-allowlisted bridge on [`BRIDGE_ALPN`] or a
/// non-allowlisted quick client on [`QUICK_ALPN`] (distinct from the in-band
/// auth-failure code `1` and the duplicate-id code `2` used on the keypair
/// client path).
pub const CLOSE_NOT_ALLOWLISTED: u32 = 3;

/// The server's per-ALPN endpoint-id allowlists, enforced natively at the TLS
/// handshake by [`AllowlistHook`]. An empty set disables its ALPN entirely —
/// the allowlist is the sole and mandatory credential on both.
#[derive(Debug, Default)]
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

pub const RELAY_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Relay configuration, resolved once from the raw config strings.
///
/// This is the single source of the default-vs-custom distinction. It selects
/// both which relay map iroh uses **and** whether iroh *internet* discovery is
/// enabled: [`Default`](Self::Default) uses the n0 relays with the n0 lookup
/// stack (pkarr publishing + DNS resolution of the peer's home relay — see
/// <https://docs.iroh.computer/concepts/address-lookup>), while
/// [`Custom`](Self::Custom) uses the configured relays with n0 internet discovery
/// disabled (clients and outbound bridges use relay hints instead). mDNS
/// local-network discovery is independent of this and stays on in both modes,
/// except on iOS where it is compiled out (raw multicast needs a special
/// entitlement there).
/// The full design — shared with tunnel-rs and ezvpn — is documented in
/// <https://github.com/flexaccessdev/iroh-common-architecture> (see
/// `relays-and-address-lookup.md`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum RelayConfig {
    /// iroh's default relay map, with n0 address lookup.
    #[default]
    Default,
    /// Custom relay set (parsed, sorted, deduped). Never empty.
    ///
    /// `auth_token`, when set, is sent to every custom relay as an
    /// `Authorization: Bearer <token>` header on the WebSocket upgrade (see
    /// [`Self::relay_mode`]). It is only ever carried by custom relays — the
    /// default relays never receive a token (see [`Self::from_urls_with_token`]).
    Custom {
        urls: Vec<RelayUrl>,
        auth_token: Option<String>,
    },
}

impl RelayConfig {
    /// Parse raw config strings with no relay auth token.
    ///
    /// Thin wrapper over [`Self::from_urls_with_token`]; see there for behavior.
    pub fn from_urls(urls: &[String]) -> Result<Self> {
        Self::from_urls_with_token(urls, None)
    }

    /// Parse raw config strings and attach an optional shared relay auth token.
    ///
    /// Empty input selects the default relays. Parsing fails on the first
    /// malformed URL, so config typos surface at resolve time instead of at each
    /// use site.
    ///
    /// The token is normalized (blank/whitespace-only becomes `None`) and is
    /// **strictly gated to custom relays**: a non-empty token with no custom
    /// relay URLs is a hard error, since the default iroh relays never take a
    /// token. This surfaces the misconfiguration before the endpoint starts.
    pub fn from_urls_with_token(urls: &[String], auth_token: Option<String>) -> Result<Self> {
        let auth_token = auth_token.and_then(|token| {
            let token = token.trim();
            (!token.is_empty()).then(|| token.to_string())
        });
        if urls.is_empty() {
            if auth_token.is_some() {
                anyhow::bail!(
                    "relay_auth_token requires custom relay_urls; it is not used with the default iroh relays"
                );
            }
            return Ok(Self::Default);
        }
        let mut parsed = urls
            .iter()
            .map(|url| {
                url.parse::<RelayUrl>()
                    .with_context(|| format!("Invalid relay URL: {url}"))
            })
            .collect::<Result<Vec<_>>>()?;
        parsed.sort();
        parsed.dedup();
        Ok(Self::Custom {
            urls: parsed,
            auth_token,
        })
    }

    /// The custom relay URLs; empty for [`RelayConfig::Default`].
    pub fn custom_urls(&self) -> &[RelayUrl] {
        match self {
            Self::Default => &[],
            Self::Custom { urls, .. } => urls,
        }
    }

    /// The shared relay auth token, if configured (custom relays only).
    pub fn relay_auth_token(&self) -> Option<&str> {
        match self {
            Self::Default => None,
            Self::Custom { auth_token, .. } => auth_token.as_deref(),
        }
    }

    pub fn is_custom(&self) -> bool {
        matches!(self, Self::Custom { .. })
    }

    /// The corresponding iroh [`RelayMode`].
    ///
    /// For custom relays, an `auth_token` (when set) is applied to every relay in
    /// the map via [`RelayMap::with_auth_token`], which iroh sends as an
    /// `Authorization: Bearer <token>` header on the relay WebSocket upgrade.
    pub fn relay_mode(&self) -> RelayMode {
        match self {
            Self::Default => RelayMode::Default,
            Self::Custom { urls, auth_token } => {
                let map = RelayMap::from_iter(urls.iter().cloned());
                let map = match auth_token {
                    Some(token) => map.with_auth_token(token.clone()),
                    None => map,
                };
                RelayMode::Custom(map)
            }
        }
    }
}

/// Load secret key from file (base64 encoded).
pub fn load_secret(path: &Path) -> Result<SecretKey> {
    if !path.exists() {
        anyhow::bail!(
            "Secret key file not found: {}\nGenerate one with: flextunnel generate-iroh-key --output {}",
            path.display(),
            path.display()
        );
    }

    let content = std::fs::read_to_string(path).context("Failed to read secret key file")?;
    // Key files carry `# created:` / `# public key:` comments above the secret;
    // the first meaningful line is the base64 secret itself.
    let Some((_, line)) = crate::auth::meaningful_lines(&content).next() else {
        anyhow::bail!("Secret key file is empty: {}", path.display());
    };
    load_secret_from_string(line)
}

/// Load secret key from a base64-encoded string.
pub fn load_secret_from_string(base64_key: &str) -> Result<SecretKey> {
    let bytes = BASE64
        .decode(base64_key)
        .context("Invalid base64 in secret key")?;

    SecretKey::try_from(&bytes[..]).context("Invalid secret key (must be 32 bytes)")
}

/// Get public key (EndpointId) from secret key.
pub fn secret_to_endpoint_id(secret: &SecretKey) -> EndpointId {
    secret.public()
}

/// Print relay configuration status messages.
fn print_relay_status(relay_config: &RelayConfig) {
    match relay_config.custom_urls().len() {
        0 => {}
        1 => info!("Using custom relay server"),
        n => info!("Using {n} custom relay servers (with failover)"),
    }
}

/// Create a base endpoint builder with common configuration.
///
/// iroh *internet* discovery (n0 pkarr publishing + DNS-based lookup of
/// `_iroh.<endpoint-id>.dns.iroh.link`, see
/// <https://docs.iroh.computer/concepts/address-lookup>) follows the relay mode:
///
/// - [`RelayConfig::Default`]: the n0 lookup stack is enabled — DNS resolution is
///   always on, and pkarr publishing is added only when a persistent identity
///   (`secret_key`) is present, so an ephemeral client resolves peers but never
///   advertises itself.
/// - [`RelayConfig::Custom`]: n0 internet discovery is disabled — nothing is
///   published to or resolved from n0's public infrastructure. Dialers reach
///   peer servers through configured relay hints attached to the peer's
///   `EndpointAddr` (clients and outbound bridges both do this): iroh sends QUIC
///   Initials to every configured relay, so the handshake succeeds via whichever
///   relay the server is homed on.
///
/// mDNS local-network discovery is independent of the relay mode and always on,
/// except on iOS where it is compiled out (raw multicast needs the
/// `com.apple.developer.networking.multicast` entitlement).
fn create_endpoint_builder(
    relay_config: &RelayConfig,
    secret_key: Option<&SecretKey>,
) -> Result<EndpointBuilder> {
    let transport_config = build_quic_transport_config()?;
    // iroh 1.0 requires the crypto provider to be set explicitly on the
    // builder when starting from the `Empty` preset — the `tls-ring` feature
    // only makes the ring backend available, it does not wire it in.
    let mut builder = Endpoint::builder(presets::Empty)
        .relay_mode(relay_config.relay_mode())
        .transport_config(transport_config)
        .crypto_provider(Arc::new(rustls::crypto::ring::default_provider()));

    if relay_config.is_custom() {
        info!("Internet discovery disabled (custom relays configured)");
    } else {
        // Default n0 relays: always resolve through n0 DNS, but only publish
        // (pkarr) when we have a persistent identity. An ephemeral endpoint (no
        // secret) shouldn't advertise itself.
        if secret_key.is_some() {
            builder = builder.address_lookup(PkarrPublisher::n0_dns());
        }
        builder = builder.address_lookup(DnsAddressLookup::n0_dns());
    }
    // mDNS local network discovery — unsupported on iOS (raw multicast needs
    // the multicast entitlement), so it is compiled out there.
    #[cfg(not(target_os = "ios"))]
    {
        builder = builder.address_lookup(MdnsAddressLookup::builder());
    }

    Ok(builder)
}

/// Build a minimal, relay-only endpoint for probing a single relay.
///
/// It uses an ephemeral identity (no persistent secret, no address publishing)
/// and clears IP transports so [`Endpoint::online`] reflects *pure relay*
/// connectivity — a holepunched direct path can never mask a dead or
/// auth-rejecting relay. The auth token, when set, rides the WebSocket upgrade
/// exactly as it does for the real endpoint, so the probe validates the token too.
fn probe_endpoint_builder(relay_url: &RelayUrl, auth_token: Option<&str>) -> Result<EndpointBuilder> {
    let transport_config = build_quic_transport_config()?;
    let map = RelayMap::from_iter([relay_url.clone()]);
    let map = match auth_token {
        Some(token) => map.with_auth_token(token.to_string()),
        None => map,
    };
    let builder = Endpoint::builder(presets::Empty)
        .relay_mode(RelayMode::Custom(map))
        .transport_config(transport_config)
        .crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
        // Relay-only: drop direct IP transports so `online()` is a pure relay
        // reachability signal, independent of holepunching.
        .clear_ip_transports();
    Ok(builder)
}

/// Probe a single custom relay by binding a relay-only endpoint and waiting for
/// it to come online, bounded by [`RELAY_CONNECT_TIMEOUT`]. `Ok(())` means the
/// relay connected (and accepted the auth token, if any); otherwise the error
/// describes the failure. The probe endpoint is always closed before returning.
async fn probe_relay(relay_url: &RelayUrl, auth_token: Option<&str>) -> Result<()> {
    let endpoint = probe_endpoint_builder(relay_url, auth_token)?
        .bind()
        .await
        .with_context(|| format!("Failed to bind probe endpoint for relay {relay_url}"))?;
    let outcome = tokio::time::timeout(RELAY_CONNECT_TIMEOUT, endpoint.online()).await;
    endpoint.close().await;
    outcome.map_err(|_| {
        anyhow::anyhow!(
            "did not come online within {}s (unreachable or rejected the auth token)",
            RELAY_CONNECT_TIMEOUT.as_secs()
        )
    })
}

/// Probe every configured custom relay individually (in parallel) and fail if
/// **any** relay is unreachable.
///
/// This is stricter than a single endpoint-wide `online()` wait, which only
/// proved that *one* relay in the set (the home relay) connected and so reported
/// a misleading all-clear when a backup relay was down. Default relays are not
/// probed (returns `Ok(())` immediately).
async fn probe_custom_relays(relay_config: &RelayConfig) -> Result<()> {
    let RelayConfig::Custom { urls, auth_token } = relay_config else {
        return Ok(());
    };
    let token = auth_token.as_deref();
    info!("Probing {} custom relay(s) for reachability...", urls.len());
    let results = join_all(
        urls.iter()
            .map(|url| async move { (url, probe_relay(url, token).await) }),
    )
    .await;
    let failures: Vec<String> = results
        .into_iter()
        .filter_map(|(url, res)| res.err().map(|e| format!("{url}: {e}")))
        .collect();
    if !failures.is_empty() {
        anyhow::bail!(
            "{} of {} custom relay(s) failed to come online:\n  {}",
            failures.len(),
            urls.len(),
            failures.join("\n  ")
        );
    }
    Ok(())
}

/// Wait for the endpoint to come online (relay/discovery ready) with a timeout.
async fn wait_online(endpoint: &Endpoint) -> Result<()> {
    info!(
        "Waiting for endpoint to come online (timeout: {}s)...",
        RELAY_CONNECT_TIMEOUT.as_secs()
    );
    match tokio::time::timeout(RELAY_CONNECT_TIMEOUT, endpoint.online()).await {
        Ok(()) => Ok(()),
        Err(_) => anyhow::bail!(
            "Endpoint failed to come online after {}s - check relay server connectivity",
            RELAY_CONNECT_TIMEOUT.as_secs()
        ),
    }
}

/// Create a server endpoint with a persistent identity, accepting the client
/// [`ALPN`], the bridge [`BRIDGE_ALPN`], and the quick-client [`QUICK_ALPN`].
/// Inbound bridge and quick-client connections are gated natively by an
/// [`AllowlistHook`] over `allowlists` (an empty set = that path disabled).
///
/// A single endpoint serves both relay modes. With the default relays internet
/// discovery is on, so the server publishes its current home relay and clients
/// resolve it by endpoint ID. With custom relays discovery is off, so clients
/// reach the server through relay hints, while outbound bridges attach
/// those same hints to their target `EndpointAddr`
/// (see [`create_endpoint_builder`]).
pub async fn create_server_endpoint(
    relay_config: &RelayConfig,
    secret: SecretKey,
    allowlists: EndpointAllowlists,
) -> Result<Endpoint> {
    print_relay_status(relay_config);

    // Validate each custom relay individually (fail if any is unreachable); a
    // no-op for the default relays.
    probe_custom_relays(relay_config).await?;

    let builder = create_endpoint_builder(relay_config, Some(&secret))?
        .alpns(vec![ALPN.to_vec(), BRIDGE_ALPN.to_vec(), QUICK_ALPN.to_vec()])
        .hooks(AllowlistHook::new(allowlists))
        .secret_key(secret);

    let endpoint = builder
        .bind()
        .await
        .context("Failed to create iroh endpoint")?;

    wait_online(&endpoint).await?;
    Ok(endpoint)
}

/// Create a client endpoint (ephemeral identity).
pub async fn create_client_endpoint(relay_config: &RelayConfig) -> Result<Endpoint> {
    create_client_endpoint_inner(relay_config, None).await
}

/// Create a **quick-mode** client endpoint: same as [`create_client_endpoint`]
/// but bound to the given (session-ephemeral) `secret`, so the endpoint id the
/// user entered on the quick server is the id this endpoint presents in the
/// TLS handshake — that id is the quick client's sole credential. The identity
/// is still never published (the client only dials), so pkarr publishing stays
/// off exactly as for an anonymous client.
pub async fn create_quick_client_endpoint(
    relay_config: &RelayConfig,
    secret: SecretKey,
) -> Result<Endpoint> {
    create_client_endpoint_inner(relay_config, Some(secret)).await
}

async fn create_client_endpoint_inner(
    relay_config: &RelayConfig,
    secret: Option<SecretKey>,
) -> Result<Endpoint> {
    print_relay_status(relay_config);

    // Validate each custom relay individually (fail if any is unreachable); a
    // no-op for the default relays.
    probe_custom_relays(relay_config).await?;

    // `None` for the builder's lookup decision even with a quick secret: a
    // client never publishes its address (it only dials out).
    let mut builder = create_endpoint_builder(relay_config, None)?;
    if let Some(secret) = secret {
        builder = builder.secret_key(secret);
    }

    let endpoint = builder
        .bind()
        .await
        .context("Failed to create iroh endpoint")?;

    wait_online(&endpoint).await?;
    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const RELAY: &str = "https://relay.example.com./";

    #[test]
    fn load_secret_skips_comment_header() {
        // Generated iroh key files carry `# created:` / `# public key:`
        // comments above the base64 secret; the loader must skip them (and
        // blank lines) and read the secret line.
        let secret = SecretKey::generate();
        let encoded = BASE64.encode(secret.to_bytes());
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            file,
            "# created: 2026-08-13T01:02:03Z\n# public key: {}\n\n{}",
            secret.public(),
            encoded
        )
        .unwrap();
        let loaded = load_secret(file.path()).unwrap();
        assert_eq!(loaded.public(), secret.public());

        // A bare secret with no comments still loads.
        let mut bare = tempfile::NamedTempFile::new().unwrap();
        writeln!(bare, "{encoded}").unwrap();
        assert_eq!(load_secret(bare.path()).unwrap().public(), secret.public());

        // Comments only — no secret line — is a hard error.
        let mut empty = tempfile::NamedTempFile::new().unwrap();
        writeln!(empty, "# created: 2026-08-13T01:02:03Z").unwrap();
        let err = load_secret(empty.path()).unwrap_err();
        assert!(err.to_string().contains("empty"), "{err}");
    }

    #[test]
    fn empty_urls_no_token_is_default() {
        let cfg = RelayConfig::from_urls_with_token(&[], None).unwrap();
        assert_eq!(cfg, RelayConfig::Default);
        assert!(!cfg.is_custom());
        assert_eq!(cfg.relay_auth_token(), None);
    }

    #[test]
    fn blank_token_without_urls_is_default() {
        // A whitespace-only token normalizes to None, so it is not an error.
        let cfg = RelayConfig::from_urls_with_token(&[], Some("   ".to_string())).unwrap();
        assert_eq!(cfg, RelayConfig::Default);
    }

    #[test]
    fn token_without_custom_urls_is_error() {
        let err = RelayConfig::from_urls_with_token(&[], Some("secret".to_string()))
            .expect_err("token without custom relays must be rejected");
        assert!(
            err.to_string()
                .contains("relay_auth_token requires custom relay_urls"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn malformed_custom_url_is_rejected_without_token() {
        // Custom relays are always parse-validated, independent of any token.
        let err = RelayConfig::from_urls_with_token(&["not a url".to_string()], None)
            .expect_err("malformed relay URL must be rejected");
        assert!(
            err.to_string().contains("Invalid relay URL"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn custom_urls_without_token() {
        let cfg = RelayConfig::from_urls_with_token(&[RELAY.to_string()], None).unwrap();
        assert!(cfg.is_custom());
        assert_eq!(cfg.custom_urls().len(), 1);
        assert_eq!(cfg.relay_auth_token(), None);
        assert!(matches!(cfg.relay_mode(), RelayMode::Custom(_)));
    }

    #[test]
    fn custom_urls_with_token_trimmed() {
        let cfg =
            RelayConfig::from_urls_with_token(&[RELAY.to_string()], Some("  secret\n".to_string()))
                .unwrap();
        assert!(cfg.is_custom());
        assert_eq!(cfg.relay_auth_token(), Some("secret"));
        assert!(matches!(cfg.relay_mode(), RelayMode::Custom(_)));
    }

    #[test]
    fn token_is_trimmed_to_none_with_custom_urls() {
        // A blank token alongside custom relays is simply no token, not an error.
        let cfg =
            RelayConfig::from_urls_with_token(&[RELAY.to_string()], Some("  ".to_string())).unwrap();
        assert!(cfg.is_custom());
        assert_eq!(cfg.relay_auth_token(), None);
    }

    #[test]
    fn from_urls_carries_no_token() {
        let cfg = RelayConfig::from_urls(&[RELAY.to_string()]).unwrap();
        assert_eq!(cfg.relay_auth_token(), None);
    }
}
