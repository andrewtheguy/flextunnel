//! Server-side conditional DNS forwarding (split-DNS).
//!
//! By default the server resolves every tunneled hostname through its own
//! system resolver (see [`crate::proxy::dial`]). A `DnsForwarder` overrides that
//! for configured domain suffixes: a hostname that equals or is a subdomain of a
//! configured suffix is resolved via that suffix's dedicated upstream DNS
//! server(s) instead. Anything not matching a suffix still uses the system
//! resolver.
//!
//! Resolution itself is purely server-side — it changes only which nameserver
//! answers a name, not the wire protocol. The configured suffix→servers table is
//! additionally pushed to clients (informationally) in the handshake so their
//! status UIs can show it, exactly like host aliases; see
//! [`DnsForwarder::forwards`].
//!
//! Config shape (`[dns_forwards]` in the server file): each key is a bare domain
//! suffix and each value is a list of DNS servers (`IP` or `IP:port`, default
//! port 53) to forward names under that suffix to:
//!
//! ```toml
//! [dns_forwards]
//! "local.168234.xyz" = ["10.0.0.53"]
//! "corp.example.com" = ["10.1.0.10:5353", "10.1.0.11"]
//! ```
//!
//! `local.168234.xyz` and any subdomain (`db.local.168234.xyz`) then resolve via
//! `10.0.0.53:53`. Matching is case-insensitive and most-specific-first: with
//! both `example.com` and `corp.example.com` configured, `a.corp.example.com`
//! uses the `corp.example.com` upstream.

use anyhow::{Context, Result, bail};
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};

/// The standard DNS port, used when a server spec omits an explicit port.
const DEFAULT_DNS_PORT: u16 = 53;

/// One configured suffix and the resolver that forwards names under it.
struct Forward {
    /// Lowercased, dot-trimmed suffix (e.g. `local.168234.xyz`).
    suffix: String,
    /// The configured upstream server specs (trimmed, as written in config),
    /// retained only for display — the live [`Self::resolver`] is what actually
    /// resolves. Pushed to clients and shown on the status page.
    servers: Vec<String>,
    /// Resolver pointed at this suffix's configured upstream server(s).
    resolver: TokioResolver,
}

/// Conditional-forwarding table: maps a hostname to a dedicated upstream
/// resolver when it falls under a configured suffix. Built once at server
/// startup and shared read-only across connections.
pub struct DnsForwarder {
    /// Entries sorted most-specific-first (longest suffix wins), so the first
    /// match in iteration order is the correct one.
    forwards: Vec<Forward>,
}

impl DnsForwarder {
    /// Build a forwarder from the raw `[dns_forwards]` config, or `None` when no
    /// forwards are configured. Suffix keys are expected already lowercased (the
    /// config layer does this); server specs are parsed and validated here so
    /// bad config fails loudly at startup.
    pub fn new(forwards: &HashMap<String, Vec<String>>) -> Result<Option<Self>> {
        if forwards.is_empty() {
            return Ok(None);
        }
        let mut entries = Vec::with_capacity(forwards.len());
        for (suffix, servers) in forwards {
            let suffix = suffix.trim().trim_matches('.').to_ascii_lowercase();
            if suffix.is_empty() || suffix.contains('*') || suffix.split('.').any(str::is_empty) {
                bail!("invalid [dns_forwards] domain suffix: {suffix:?}");
            }
            if servers.is_empty() {
                bail!("[dns_forwards] entry {suffix:?} lists no DNS servers");
            }
            let mut name_servers = Vec::with_capacity(servers.len());
            let mut server_specs = Vec::with_capacity(servers.len());
            for spec in servers {
                let (ip, port) = parse_server(spec).with_context(|| {
                    format!("invalid [dns_forwards] server {spec:?} for suffix {suffix:?}")
                })?;
                server_specs.push(spec.trim().to_string());
                // UDP with a TCP fallback (for truncated answers), both on the
                // configured port — the `udp_and_tcp` helper is hardwired to 53.
                let mut udp = ConnectionConfig::udp();
                udp.port = port;
                let mut tcp = ConnectionConfig::tcp();
                tcp.port = port;
                name_servers.push(NameServerConfig::new(ip, true, vec![udp, tcp]));
            }
            let config = ResolverConfig::from_parts(None, vec![], name_servers);
            let resolver =
                TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
                    .build()
                    .with_context(|| format!("building resolver for [dns_forwards] {suffix:?}"))?;
            entries.push(Forward {
                suffix,
                servers: server_specs,
                resolver,
            });
        }
        // Longest suffix first so a subdomain matches its most specific zone;
        // suffix as tiebreaker keeps ordering deterministic.
        entries.sort_by(|a, b| {
            b.suffix
                .len()
                .cmp(&a.suffix.len())
                .then_with(|| a.suffix.cmp(&b.suffix))
        });
        Ok(Some(Self { forwards: entries }))
    }

    /// The configured suffixes, normalized (lowercased, dot-trimmed) exactly as
    /// they are matched at runtime. Used to cross-check that each is reachable
    /// through the routed set (an unreachable forward is a no-op).
    pub fn suffixes(&self) -> impl Iterator<Item = &str> {
        self.forwards.iter().map(|f| f.suffix.as_str())
    }

    /// The configured forwards as `(suffix, upstream servers)` pairs, sorted by
    /// suffix for stable output. Purely informational: pushed to clients in the
    /// handshake and rendered on the server status page. The servers are the
    /// specs as configured (trimmed), not the resolved socket addresses.
    pub fn forwards(&self) -> Vec<(String, Vec<String>)> {
        let mut out: Vec<(String, Vec<String>)> = self
            .forwards
            .iter()
            .map(|f| (f.suffix.clone(), f.servers.clone()))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// The upstream resolver for `host`, if it equals or is a subdomain of a
    /// configured suffix; `None` means "not forwarded — use the system
    /// resolver". A subdomain match requires a label boundary, so
    /// `notlocal.168234.xyz` does **not** match a `local.168234.xyz` suffix.
    fn resolver_for(&self, host: &str) -> Option<&TokioResolver> {
        let host = host.to_ascii_lowercase();
        self.forwards
            .iter()
            .find(|f| suffix_matches(&host, &f.suffix))
            .map(|f| &f.resolver)
    }

    /// Resolve `host:port` if it matches a configured suffix, returning the
    /// resolved socket addresses. `None` means the host is not forwarded and the
    /// caller should fall back to the system resolver.
    pub async fn resolve(&self, host: &str, port: u16) -> Option<io::Result<Vec<SocketAddr>>> {
        let resolver = self.resolver_for(host)?;
        Some(lookup(resolver, host, port).await)
    }
}

/// Whether `host` equals `suffix` or is a subdomain of it (with a label
/// boundary). Both arguments must already be lowercased.
fn suffix_matches(host: &str, suffix: &str) -> bool {
    if host == suffix {
        return true;
    }
    host.strip_suffix(suffix)
        .is_some_and(|prefix| prefix.ends_with('.'))
}

/// Query `resolver` for `host` and pair each resolved IP with `port`. A DNS
/// error maps to an `io::Error` so it flows through the existing dial path.
async fn lookup(resolver: &TokioResolver, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let lookup = resolver.lookup_ip(host).await.map_err(io::Error::other)?;
    Ok(lookup.iter().map(|ip| SocketAddr::new(ip, port)).collect())
}

/// Parse a DNS-server spec (`IP` or `IP:port`, plus bracketed IPv6
/// `[::1]:5353`) into an address and port, defaulting the port to 53.
fn parse_server(spec: &str) -> Result<(IpAddr, u16)> {
    let spec = spec.trim();
    // A bare IP (v4 or v6) with no port.
    if let Ok(ip) = spec.parse::<IpAddr>() {
        return Ok((ip, DEFAULT_DNS_PORT));
    }
    // Otherwise it must carry a port: `SocketAddr` handles `1.2.3.4:53` and the
    // bracketed IPv6 form `[::1]:53`.
    let sa: SocketAddr = spec
        .parse()
        .with_context(|| format!("expected an IP or IP:port, got {spec:?}"))?;
    Ok((sa.ip(), sa.port()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn forwarder(pairs: &[(&str, &[&str])]) -> DnsForwarder {
        let map: HashMap<String, Vec<String>> = pairs
            .iter()
            .map(|(k, v)| {
                (
                    k.to_ascii_lowercase(),
                    v.iter().map(|s| s.to_string()).collect(),
                )
            })
            .collect();
        DnsForwarder::new(&map).expect("valid config").expect("some forwards")
    }

    #[test]
    fn empty_config_yields_none() {
        assert!(DnsForwarder::new(&HashMap::new()).unwrap().is_none());
    }

    #[test]
    fn suffix_matches_apex_and_subdomains_only() {
        assert!(suffix_matches("local.168234.xyz", "local.168234.xyz"));
        assert!(suffix_matches("db.local.168234.xyz", "local.168234.xyz"));
        assert!(suffix_matches("a.b.local.168234.xyz", "local.168234.xyz"));
        // A label boundary is required: no partial-label matches.
        assert!(!suffix_matches("notlocal.168234.xyz", "local.168234.xyz"));
        assert!(!suffix_matches("local.168234.xyz.evil.com", "local.168234.xyz"));
        assert!(!suffix_matches("other.xyz", "local.168234.xyz"));
    }

    #[test]
    fn most_specific_suffix_wins() {
        let f = forwarder(&[
            ("example.com", &["10.0.0.1"]),
            ("corp.example.com", &["10.0.0.2"]),
        ]);
        // Sorted longest-first, so the corp resolver is found before the apex one.
        assert_eq!(f.forwards[0].suffix, "corp.example.com");
        assert!(f.resolver_for("db.corp.example.com").is_some());
        assert!(f.resolver_for("www.example.com").is_some());
        assert!(f.resolver_for("elsewhere.net").is_none());
    }

    #[test]
    fn forwards_lists_suffixes_and_servers_sorted() {
        let f = forwarder(&[
            ("corp.example.com", &["10.1.0.10:5353", "10.1.0.11"]),
            ("local.168234.xyz", &["10.0.0.53"]),
        ]);
        assert_eq!(
            f.forwards(),
            vec![
                (
                    "corp.example.com".to_string(),
                    vec!["10.1.0.10:5353".to_string(), "10.1.0.11".to_string()]
                ),
                ("local.168234.xyz".to_string(), vec!["10.0.0.53".to_string()]),
            ]
        );
    }

    #[test]
    fn parses_server_specs() {
        assert_eq!(parse_server("10.0.0.53").unwrap(), ("10.0.0.53".parse().unwrap(), 53));
        assert_eq!(parse_server("10.0.0.53:5353").unwrap(), ("10.0.0.53".parse().unwrap(), 5353));
        assert_eq!(parse_server("::1").unwrap(), ("::1".parse().unwrap(), 53));
        assert_eq!(parse_server("[::1]:5353").unwrap(), ("::1".parse().unwrap(), 5353));
        assert!(parse_server("not-an-ip").is_err());
        assert!(parse_server("10.0.0.53:notaport").is_err());
    }

    #[test]
    fn rejects_bad_suffix_and_empty_servers() {
        let mut m = HashMap::new();
        m.insert("*.example.com".to_string(), vec!["10.0.0.1".to_string()]);
        assert!(DnsForwarder::new(&m).is_err());

        let mut m = HashMap::new();
        m.insert("example.com".to_string(), Vec::new());
        assert!(DnsForwarder::new(&m).is_err());

        let mut m = HashMap::new();
        m.insert("example.com".to_string(), vec!["nope".to_string()]);
        assert!(DnsForwarder::new(&m).is_err());
    }
}
