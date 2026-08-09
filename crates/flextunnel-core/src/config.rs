//! TOML configuration files for the server and client.
//!
//! Both roles can be configured from a TOML file (`-c <FILE>` or
//! `--default-config` → `~/.config/flextunnel/{server,client}.toml`). CLI flags
//! always override file values; the file overrides built-in defaults. Unknown
//! keys are rejected (`deny_unknown_fields`) so typos fail loudly.
//!
//! The schema is flat: flextunnel has a single transport and the `server`/
//! `client` subcommands already determine the role, so there is no `[iroh]`
//! table or `role`/`mode` key.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

/// One `[bridges.<name>]` entry: a split-tunnel route forwarding matching
/// targets to **another flextunnel server** over a persistent server-to-server
/// connection. The map key is a friendly label used in logs and status
/// displays. Matched targets are forwarded verbatim — the target server
/// applies its own routed set, host aliases, and DNS forwards, and resolves
/// domain targets on its side. Bridge rules must be covered by this server's
/// routed set (validated at startup), since off-list targets are rejected
/// before routing. Single hop: a stream that arrived over a bridge is never
/// bridged again.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeConfig {
    /// The target server's iroh endpoint id.
    pub endpoint_id: String,
    /// Bridge auth token (an `ftb` token accepted by the target server's
    /// `bridge_auth_tokens`). Exactly one of `auth_token`/`auth_token_file`.
    pub auth_token: Option<String>,
    /// File containing the bridge auth token.
    pub auth_token_file: Option<PathBuf>,
    /// Domain rules forwarded to the target server (routed-set syntax: exact,
    /// `*.x`, or `*`).
    #[serde(default)]
    pub domains: Vec<String>,
    /// CIDR / bare-IP rules forwarded to the target server.
    #[serde(default)]
    pub cidrs: Vec<String>,
}

/// Server config file schema. Every field is optional; CLI flags override these.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Path to the server's secret-key file (persistent identity).
    pub secret_file: Option<PathBuf>,
    /// Inline base64 secret key (alternative to `secret_file`).
    pub secret: Option<String>,
    /// Accepted client auth tokens (inline list).
    pub auth_tokens: Option<Vec<String>>,
    /// File of accepted client auth tokens (one per line).
    pub auth_tokens_file: Option<PathBuf>,
    /// Custom relay URL(s) for failover.
    pub relay_urls: Option<Vec<String>>,
    /// Shared bearer token sent to every custom relay's WebSocket upgrade. Only
    /// valid with custom `relay_urls`; rejected with the default iroh relays.
    pub relay_auth_token: Option<String>,
    /// Hostname aliases resolved on the server side: a requested host that
    /// matches a key is rewritten to its value (an IP or another hostname on the
    /// server's network) before connecting. Keeps the requested port. Lets a
    /// client reach the server's loopback or internal hosts via a real name
    /// (e.g. `server.internal` → `127.0.0.1`), which also dodges Firefox's refusal
    /// to proxy literal `localhost`/`127.0.0.1`. A key is an exact host or a
    /// `*.suffix` wildcard (subdomains only), the same syntax as `routed_domains`;
    /// an exact key beats a wildcard and the most specific wildcard wins.
    pub host_aliases: Option<HashMap<String, String>>,
    /// Domains routed through the tunnel (the tunnel set). Exact (`example.com`),
    /// wildcard (`*.example.com`, subdomains only), or `*` to match every host
    /// (full tunnel). The tunnel set is required — a server with an empty set
    /// refuses to start. Off-list targets are rejected server-side and
    /// direct-connected client-side. Keep in sync with `routed_cidrs`.
    pub routed_domains: Option<Vec<String>>,
    /// CIDRs / bare IPs routed through the tunnel (matched against IP targets).
    /// A default route (`0.0.0.0/0` / `::/0`) matches every IP. See
    /// `routed_domains`.
    pub routed_cidrs: Option<Vec<String>>,
    /// Conditional DNS forwarding (split-DNS), server-side. Each key is a bare
    /// domain suffix and each value a list of DNS servers (`IP` or `IP:port`,
    /// default port 53). A tunneled hostname that equals or is a subdomain of a
    /// key is resolved via that key's upstream server(s) instead of the server's
    /// system resolver; everything else uses the system resolver. Keys are
    /// matched most-specific-first. See [`crate::proxy::DnsForwarder`].
    pub dns_forwards: Option<HashMap<String, Vec<String>>>,
    /// Outbound bridge routes: targets matching a bridge's rules are forwarded
    /// to that bridge's server instead of dialed locally. See [`BridgeConfig`].
    pub bridges: Option<HashMap<String, BridgeConfig>>,
    /// Endpoint ids of servers allowed to connect **to this server** as
    /// bridges. Empty/absent = inbound bridging disabled. A connecting bridge
    /// must present both an allowlisted (TLS-authenticated) endpoint id and a
    /// valid `ftb` token from `bridge_auth_tokens`.
    pub allowed_bridge_servers: Option<Vec<String>>,
    /// Accepted bridge auth tokens (inline list) — a separate pool from client
    /// tokens, using the `ftb` prefix.
    pub bridge_auth_tokens: Option<Vec<String>>,
    /// File of accepted bridge auth tokens (one per line).
    pub bridge_auth_tokens_file: Option<PathBuf>,
}

/// Client config file schema. Every field is optional; CLI flags override these.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// EndpointId of the server to connect to.
    pub server_node_id: Option<String>,
    /// Friendly display name for this profile (e.g. "aws", "home network"),
    /// shown in status UIs. Purely cosmetic — the client's on-disk identity
    /// (lock, control socket, forwards file) is keyed by `server_node_id`.
    pub name: Option<String>,
    /// Loopback port for the optional SOCKS5 listener (binds `127.0.0.1`
    /// only, like the desktop client — the front-ends are unauthenticated and
    /// never exposed beyond the local machine). Unset = SOCKS front-end
    /// disabled; with neither `socks_port` nor `http_port` the client runs in
    /// port-forward/control-panel-only mode.
    pub socks_port: Option<u16>,
    /// Loopback port for the optional HTTP proxy listener (CONNECT tunneling +
    /// absolute-URI plain-HTTP forwarding; binds `127.0.0.1` only). Unset =
    /// HTTP front-end disabled.
    pub http_port: Option<u16>,
    /// Auth token to send to the server.
    pub auth_token: Option<String>,
    /// File containing the auth token.
    pub auth_token_file: Option<PathBuf>,
    /// Custom relay URL(s) for failover.
    pub relay_urls: Option<Vec<String>>,
    /// Shared bearer token sent to every custom relay's WebSocket upgrade. Only
    /// valid with custom `relay_urls`; rejected with the default iroh relays.
    pub relay_auth_token: Option<String>,
    /// Reconnect with backoff on a transient drop (default true).
    pub auto_reconnect: Option<bool>,
    /// Cap on reconnect attempts between successful connections.
    pub max_reconnect_attempts: Option<NonZeroU32>,
}

/// Fully-resolved server settings (CLI > file > default), paths tilde-expanded.
#[derive(Debug)]
pub struct ResolvedServer {
    pub secret_file: Option<PathBuf>,
    pub secret: Option<String>,
    pub auth_tokens: Vec<String>,
    pub auth_tokens_file: Option<PathBuf>,
    pub relay_urls: Vec<String>,
    /// Shared bearer token for custom relays (custom relays only).
    pub relay_auth_token: Option<String>,
    /// Server-side host aliases, keys lowercased for case-insensitive matching.
    pub host_aliases: HashMap<String, String>,
    /// Raw routed-set entries (parsed into a `RoutedSet` at startup).
    pub routed_domains: Vec<String>,
    pub routed_cidrs: Vec<String>,
    /// Conditional DNS-forwarding rules, suffix keys lowercased for
    /// case-insensitive matching (parsed into a `DnsForwarder` at startup).
    pub dns_forwards: HashMap<String, Vec<String>>,
    /// Outbound bridge routes keyed by their friendly label, shape-validated
    /// (token source, non-empty rules, unique endpoint ids) with token-file
    /// paths tilde-expanded. See [`BridgeConfig`].
    pub bridges: HashMap<String, BridgeConfig>,
    /// Endpoint ids of servers allowed to bridge into this server (parsed and
    /// checked against `own_id` at startup).
    pub allowed_bridge_servers: Vec<String>,
    pub bridge_auth_tokens: Vec<String>,
    pub bridge_auth_tokens_file: Option<PathBuf>,
    /// Path to the duplicate-id blocklist file. Always the fixed default
    /// (`~/.config/flextunnel/blocklist.json`); it is deliberately **not**
    /// configurable, since relocating this security guard rail would let it be
    /// bypassed. See [`crate::blocklist`].
    pub blocklist_file: PathBuf,
}

/// Fully-resolved client settings (CLI > file > default), paths tilde-expanded.
pub struct ResolvedClient {
    pub server_node_id: Option<String>,
    pub name: Option<String>,
    pub socks_port: Option<u16>,
    pub http_port: Option<u16>,
    pub auth_token: Option<String>,
    pub auth_token_file: Option<PathBuf>,
    pub relay_urls: Vec<String>,
    /// Shared bearer token for custom relays (custom relays only).
    pub relay_auth_token: Option<String>,
    pub auto_reconnect: bool,
    pub max_reconnect_attempts: Option<NonZeroU32>,
}

/// Expand a leading `~` / `~/…` to the user's home directory.
pub fn expand_tilde(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    } else if s == "~"
        && let Some(home) = dirs::home_dir()
    {
        return home;
    }
    path.to_path_buf()
}

/// Default config path for a role file (e.g. `~/.config/flextunnel/server.toml`).
///
/// Always uses `~/.config` (not the platform config dir) to match tunnel-rs,
/// so the same location works across Linux and macOS.
fn default_config_path(file_name: &str) -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".config").join("flextunnel").join(file_name))
}

/// Read and parse a TOML config file, with the path in any error.
fn load_config<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path.display()))?;
    toml::from_str(&content)
        .with_context(|| format!("Failed to parse config file: {}", path.display()))
}

/// Resolve the config file to load, if any: an explicit `path`, else the default
/// location when `default_config` is set, else `None`.
fn resolve_config_path(
    path: Option<&Path>,
    default_config: bool,
    default_name: &str,
) -> Result<Option<PathBuf>> {
    if let Some(p) = path {
        Ok(Some(expand_tilde(p)))
    } else if default_config {
        Ok(Some(default_config_path(default_name).context(
            "Could not determine the default config directory; pass -c <FILE> instead",
        )?))
    } else {
        Ok(None)
    }
}

/// Load the server config file (explicit path or `--default-config`), or `None`.
pub fn load_server_config(path: Option<&Path>, default_config: bool) -> Result<Option<ServerConfig>> {
    match resolve_config_path(path, default_config, "server.toml")? {
        Some(p) => Ok(Some(load_config(&p)?)),
        None => Ok(None),
    }
}

/// Load the client config: an explicit path (error if missing), else the
/// default `~/.config/flextunnel/client.toml` when it exists, else `None`
/// (the caller then falls back to CLI flags / the interactive prompt).
pub fn load_client_config(path: Option<&Path>) -> Result<Option<ClientConfig>> {
    match path {
        Some(p) => Ok(Some(load_config(&expand_tilde(p))?)),
        None => match default_config_path("client.toml") {
            Some(p) if p.exists() => Ok(Some(load_config(&p)?)),
            _ => Ok(None),
        },
    }
}

/// Merge CLI-provided values over file values over defaults for the server.
///
/// `cli` carries the CLI flags as a `ServerConfig` (a field is `Some`/non-empty
/// only when the user passed it). For each field CLI wins, then the file; list
/// fields are replaced wholesale (not appended), matching tunnel-rs.
pub fn resolve_server(cli: ServerConfig, file: Option<ServerConfig>) -> Result<ResolvedServer> {
    let file = file.unwrap_or_default();

    // Credential groups are merged as a *unit* per source: if the CLI set any
    // part of a group, the CLI's group wins wholesale; otherwise the file's does.
    // This avoids a false "both set" conflict when e.g. the CLI gives a token and
    // the file gives a token-file.
    let (secret, secret_file) = if cli.secret.is_some() || cli.secret_file.is_some() {
        (cli.secret, cli.secret_file)
    } else {
        (file.secret, file.secret_file)
    };
    let (auth_tokens, auth_tokens_file) = if cli.auth_tokens.is_some() || cli.auth_tokens_file.is_some()
    {
        (cli.auth_tokens, cli.auth_tokens_file)
    } else {
        (file.auth_tokens, file.auth_tokens_file)
    };
    let (bridge_auth_tokens, bridge_auth_tokens_file) =
        if cli.bridge_auth_tokens.is_some() || cli.bridge_auth_tokens_file.is_some() {
            (cli.bridge_auth_tokens, cli.bridge_auth_tokens_file)
        } else {
            (file.bridge_auth_tokens, file.bridge_auth_tokens_file)
        };

    // Host aliases are file-only (no CLI flag). Lowercase keys so matching is
    // case-insensitive against a lowercased requested host (DNS hostnames are
    // case-insensitive). Reject entries that collide only by case — silently
    // dropping one would shadow a distinct alias.
    let host_aliases = collect_lowercased(
        cli.host_aliases.or(file.host_aliases).unwrap_or_default(),
        "host_aliases",
    )?;
    // DNS-forward suffixes are matched case-insensitively too; lowercase the keys
    // and reject case-only duplicates for the same reason.
    let dns_forwards = collect_lowercased(
        cli.dns_forwards.or(file.dns_forwards).unwrap_or_default(),
        "dns_forwards",
    )?;
    // Alias keys are either an exact host or a `*.suffix` wildcard (same syntax
    // as the routed set); reject malformed patterns loudly at startup.
    for key in host_aliases.keys() {
        validate_alias_key(key, "host_aliases")?;
    }
    // The `flextunnel.internal` namespace is reserved by flextunnel itself (the
    // server serves a status page there); it can't be used as an alias name.
    for key in host_aliases.keys() {
        if crate::proxy::reserved::is_reserved_host(key) {
            anyhow::bail!(
                "alias '{key}' uses the reserved flextunnel.internal namespace and \
                 cannot be used as a [host_aliases] name"
            );
        }
    }

    // Bridges are file-only (no CLI flag). Shape-validate each entry here so
    // bad bridge config fails at startup with the offending name; I/O-dependent
    // validation (endpoint-id parsing, token loading, routed-set coverage)
    // happens at server startup.
    let mut bridges = cli.bridges.or(file.bridges).unwrap_or_default();
    let mut seen_endpoint_ids: HashMap<&str, &str> = HashMap::new();
    let mut names: Vec<&String> = bridges.keys().collect();
    names.sort();
    for name in names {
        let b = &bridges[name];
        if b.auth_token.is_some() == b.auth_token_file.is_some() {
            anyhow::bail!(
                "bridge '{name}' must set exactly one of auth_token / auth_token_file"
            );
        }
        if b.domains.is_empty() && b.cidrs.is_empty() {
            anyhow::bail!("bridge '{name}' has no domains and no cidrs; it would never match");
        }
        if let Some(other) = seen_endpoint_ids.insert(b.endpoint_id.as_str(), name) {
            anyhow::bail!(
                "bridges '{other}' and '{name}' target the same endpoint_id; \
                 merge their domains/cidrs into one entry"
            );
        }
    }
    for b in bridges.values_mut() {
        b.auth_token_file = b.auth_token_file.take().map(|p| expand_tilde(&p));
    }

    // Fixed at the default (~/.config/flextunnel/blocklist.json) and NOT
    // overridable via CLI or config: the blocklist is a security guard rail, and
    // letting it be pointed elsewhere would let it be bypassed. Fail fast if the
    // home dir can't be determined rather than silently falling back to a
    // cwd-relative path a later run from another directory wouldn't share.
    let blocklist_file = crate::blocklist::default_blocklist_path().context(
        "Could not determine the home directory for the duplicate-id blocklist \
         (~/.config/flextunnel/blocklist.json); set HOME",
    )?;

    Ok(ResolvedServer {
        secret_file: secret_file.map(|p| expand_tilde(&p)),
        secret,
        auth_tokens: auth_tokens.unwrap_or_default(),
        auth_tokens_file: auth_tokens_file.map(|p| expand_tilde(&p)),
        relay_urls: cli.relay_urls.or(file.relay_urls).unwrap_or_default(),
        relay_auth_token: cli.relay_auth_token.or(file.relay_auth_token),
        host_aliases,
        routed_domains: cli
            .routed_domains
            .or(file.routed_domains)
            .unwrap_or_default(),
        routed_cidrs: cli.routed_cidrs.or(file.routed_cidrs).unwrap_or_default(),
        dns_forwards,
        bridges,
        allowed_bridge_servers: cli
            .allowed_bridge_servers
            .or(file.allowed_bridge_servers)
            .unwrap_or_default(),
        bridge_auth_tokens: bridge_auth_tokens.unwrap_or_default(),
        bridge_auth_tokens_file: bridge_auth_tokens_file.map(|p| expand_tilde(&p)),
        blocklist_file,
    })
}

/// Lowercase each source key and collect into a map, failing if two source keys
/// normalize (ASCII-lowercase) to the same key. Aliases are matched
/// case-insensitively, so a case-only duplicate would otherwise let one entry
/// silently shadow the other.
/// Validate one `[host_aliases]` key. A key is either an exact hostname or a
/// `*.suffix` wildcard matching subdomains of `suffix` (the same syntax as
/// `routed_domains`; resolved by `proxy::server::resolve_alias`). A bare `*` is
/// rejected — an alias catch-all mapping every host to one target is almost
/// certainly a misconfiguration — as are malformed patterns like `*.*.x`,
/// `*..x`, or a `*` anywhere but a leading `*.`. Keys are already lowercased by
/// [`collect_lowercased`].
fn validate_alias_key(key: &str, what: &str) -> Result<()> {
    if let Some(suffix) = key.strip_prefix("*.") {
        if suffix.contains('*') || suffix.split('.').any(str::is_empty) {
            anyhow::bail!("invalid [{what}] wildcard pattern '{key}'");
        }
    } else if key.is_empty() || key.contains('*') {
        anyhow::bail!(
            "invalid [{what}] name '{key}': use an exact hostname or a '*.suffix' wildcard"
        );
    }
    Ok(())
}

fn collect_lowercased<V>(
    entries: impl IntoIterator<Item = (String, V)>,
    what: &str,
) -> Result<HashMap<String, V>> {
    let mut out = HashMap::new();
    for (k, v) in entries {
        let key = k.to_ascii_lowercase();
        if out.contains_key(&key) {
            anyhow::bail!(
                "duplicate [{what}] alias '{key}': aliases are matched case-insensitively, \
                 so entries differing only by case collide"
            );
        }
        out.insert(key, v);
    }
    Ok(out)
}

/// Merge CLI-provided values over file values over defaults for the client.
pub fn resolve_client(cli: ClientConfig, file: Option<ClientConfig>) -> ResolvedClient {
    let file = file.unwrap_or_default();

    // Token group merged as a unit per source (see `resolve_server`).
    let (auth_token, auth_token_file) = if cli.auth_token.is_some() || cli.auth_token_file.is_some() {
        (cli.auth_token, cli.auth_token_file)
    } else {
        (file.auth_token, file.auth_token_file)
    };

    ResolvedClient {
        server_node_id: cli.server_node_id.or(file.server_node_id),
        name: cli.name.or(file.name),
        // No defaults: each proxy front-end is off unless explicitly configured.
        socks_port: cli.socks_port.or(file.socks_port),
        http_port: cli.http_port.or(file.http_port),
        auth_token,
        auth_token_file: auth_token_file.map(|p| expand_tilde(&p)),
        relay_urls: cli.relay_urls.or(file.relay_urls).unwrap_or_default(),
        relay_auth_token: cli.relay_auth_token.or(file.relay_auth_token),
        auto_reconnect: cli.auto_reconnect.or(file.auto_reconnect).unwrap_or(true),
        max_reconnect_attempts: cli.max_reconnect_attempts.or(file.max_reconnect_attempts),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_server_config() {
        let toml = r#"
            secret_file = "./server.key"
            auth_tokens = ["ftcAAA", "ftcBBB"]
            relay_urls = ["https://relay.example"]
        "#;
        let cfg: ServerConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.secret_file, Some(PathBuf::from("./server.key")));
        assert_eq!(cfg.auth_tokens.as_deref().map(<[_]>::len), Some(2));
        assert_eq!(cfg.relay_urls.as_deref().map(<[_]>::len), Some(1));
        assert!(cfg.secret.is_none());
    }

    #[test]
    fn parse_client_config() {
        let toml = r#"
            server_node_id = "abc123"
            socks_port = 1085
            auth_token = "ftcTOKEN"
            auto_reconnect = false
            max_reconnect_attempts = 5
        "#;
        let cfg: ClientConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.server_node_id.as_deref(), Some("abc123"));
        assert_eq!(cfg.socks_port, Some(1085));
        assert_eq!(cfg.auto_reconnect, Some(false));
        assert_eq!(cfg.max_reconnect_attempts, NonZeroU32::new(5));
    }

    #[test]
    fn unknown_key_is_rejected() {
        // A misspelled key must be a hard error, not silently ignored.
        let err = toml::from_str::<ServerConfig>("auth_tokenz = []").unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{err}");
    }

    #[test]
    fn cli_overrides_file() {
        let file = ServerConfig {
            secret_file: Some(PathBuf::from("/file/server.key")),
            relay_urls: Some(vec!["https://file-relay".into()]),
            ..Default::default()
        };
        let cli = ServerConfig {
            secret_file: Some(PathBuf::from("/cli/server.key")),
            ..Default::default()
        };
        let r = resolve_server(cli, Some(file)).unwrap();
        // CLI wins where set; file fills the rest.
        assert_eq!(r.secret_file, Some(PathBuf::from("/cli/server.key")));
        assert_eq!(r.relay_urls, vec!["https://file-relay".to_string()]);
    }

    #[test]
    fn host_aliases_parsed_and_lowercased() {
        let toml = r#"
            [host_aliases]
            "Server.Internal" = "127.0.0.1"
            "node2.internal" = "192.168.1.50"
        "#;
        let file: ServerConfig = toml::from_str(toml).unwrap();
        let r = resolve_server(ServerConfig::default(), Some(file)).unwrap();
        // Keys are lowercased so matching against a lowercased host works.
        assert_eq!(r.host_aliases.get("server.internal").map(String::as_str), Some("127.0.0.1"));
        assert_eq!(r.host_aliases.get("node2.internal").map(String::as_str), Some("192.168.1.50"));
        assert!(!r.host_aliases.contains_key("Server.Internal"));
    }

    #[test]
    fn host_aliases_case_only_duplicate_is_rejected() {
        let toml = r#"
            [host_aliases]
            "Server.Internal" = "127.0.0.1"
            "server.internal" = "192.168.1.50"
        "#;
        let file: ServerConfig = toml::from_str(toml).unwrap();
        let err = resolve_server(ServerConfig::default(), Some(file)).unwrap_err();
        assert!(err.to_string().contains("host_aliases"), "{err}");
    }

    #[test]
    fn reserved_namespace_alias_is_rejected() {
        // The exact reserved host and any subdomain are refused as alias names.
        for name in ["flextunnel.internal", "status.flextunnel.internal"] {
            let toml = format!("[host_aliases]\n\"{name}\" = \"127.0.0.1\"\n");
            let file: ServerConfig = toml::from_str(&toml).unwrap();
            let err = resolve_server(ServerConfig::default(), Some(file)).unwrap_err();
            assert!(err.to_string().contains("reserved"), "{err}");
        }
    }

    #[test]
    fn wildcard_alias_keys_parsed_and_lowercased() {
        let toml = r#"
            [host_aliases]
            "*.Web.Internal" = "10.0.0.1"
        "#;
        let file: ServerConfig = toml::from_str(toml).unwrap();
        let r = resolve_server(ServerConfig::default(), Some(file)).unwrap();
        // The `*.` prefix survives lowercasing of the rest of the key.
        assert_eq!(r.host_aliases.get("*.web.internal").map(String::as_str), Some("10.0.0.1"));
    }

    #[test]
    fn malformed_wildcard_alias_is_rejected() {
        // A bare `*` catch-all, a doubled wildcard, an empty label, and a stray
        // `*` outside a leading `*.` are all rejected at config resolution.
        for (table, key) in [
            ("host_aliases", "*"),
            ("host_aliases", "*.*.internal"),
            ("host_aliases", "*..internal"),
            ("host_aliases", "web*.internal"),
        ] {
            let toml = format!("[{table}]\n\"{key}\" = \"10.0.0.1\"\n");
            let file: ServerConfig = toml::from_str(&toml).unwrap();
            let err = resolve_server(ServerConfig::default(), Some(file)).unwrap_err();
            assert!(err.to_string().contains(table), "key {key:?}: {err}");
        }
    }

    #[test]
    fn reserved_namespace_wildcard_alias_is_rejected() {
        // A `*.flextunnel.internal` wildcard collides with the reserved namespace.
        let toml = "[host_aliases]\n\"*.flextunnel.internal\" = \"127.0.0.1\"\n";
        let file: ServerConfig = toml::from_str(toml).unwrap();
        let err = resolve_server(ServerConfig::default(), Some(file)).unwrap_err();
        assert!(err.to_string().contains("reserved"), "{err}");
    }

    #[test]
    fn routed_keys_parsed_and_resolved() {
        let toml = r#"
            routed_domains = ["*.example.com", "httpbin.org"]
            routed_cidrs = ["10.0.0.0/8"]
        "#;
        let file: ServerConfig = toml::from_str(toml).unwrap();
        let r = resolve_server(ServerConfig::default(), Some(file)).unwrap();
        assert_eq!(r.routed_domains, vec!["*.example.com", "httpbin.org"]);
        assert_eq!(r.routed_cidrs, vec!["10.0.0.0/8"]);
        // Defaults to empty (inactive) when unset.
        let empty = resolve_server(ServerConfig::default(), None).unwrap();
        assert!(empty.routed_domains.is_empty());
        assert!(empty.routed_cidrs.is_empty());
    }

    #[test]
    fn dns_forwards_parsed_and_lowercased() {
        let toml = r#"
            [dns_forwards]
            "Local.168234.XYZ" = ["10.0.0.53"]
            "corp.example.com" = ["10.1.0.10:5353", "10.1.0.11"]
        "#;
        let file: ServerConfig = toml::from_str(toml).unwrap();
        let r = resolve_server(ServerConfig::default(), Some(file)).unwrap();
        // Keys lowercased for case-insensitive matching; values kept verbatim.
        assert_eq!(
            r.dns_forwards.get("local.168234.xyz").map(Vec::as_slice),
            Some(["10.0.0.53".to_string()].as_slice())
        );
        assert_eq!(r.dns_forwards.get("corp.example.com").map(Vec::len), Some(2));
        assert!(!r.dns_forwards.contains_key("Local.168234.XYZ"));
        // Defaults to empty (forwarding inactive) when unset.
        assert!(resolve_server(ServerConfig::default(), None).unwrap().dns_forwards.is_empty());
    }

    #[test]
    fn dns_forwards_case_only_duplicate_is_rejected() {
        let toml = r#"
            [dns_forwards]
            "Corp.Example.com" = ["10.0.0.1"]
            "corp.example.com" = ["10.0.0.2"]
        "#;
        let file: ServerConfig = toml::from_str(toml).unwrap();
        let err = resolve_server(ServerConfig::default(), Some(file)).unwrap_err();
        assert!(err.to_string().contains("dns_forwards"), "{err}");
    }

    #[test]
    fn bridges_parsed_and_validated() {
        let toml = r#"
            allowed_bridge_servers = ["endpointid_a"]
            bridge_auth_tokens = ["ftbAAA"]

            [bridges.lab]
            endpoint_id = "endpointid_b"
            auth_token = "ftbBBB"
            domains = ["*.svc"]
            cidrs = ["fd34::/64"]

            [bridges.other]
            endpoint_id = "endpointid_c"
            auth_token_file = "~/bridge.token"
            cidrs = ["10.9.0.0/16"]
        "#;
        let file: ServerConfig = toml::from_str(toml).unwrap();
        let r = resolve_server(ServerConfig::default(), Some(file)).unwrap();
        let lab = &r.bridges["lab"];
        assert_eq!(lab.endpoint_id, "endpointid_b");
        assert_eq!(lab.auth_token.as_deref(), Some("ftbBBB"));
        assert_eq!(lab.domains, vec!["*.svc"]);
        assert_eq!(lab.cidrs, vec!["fd34::/64"]);
        // Token-file paths are tilde-expanded.
        let other = &r.bridges["other"];
        assert_eq!(other.auth_token_file, Some(expand_tilde(Path::new("~/bridge.token"))));
        assert_eq!(r.allowed_bridge_servers, vec!["endpointid_a".to_string()]);
        assert_eq!(r.bridge_auth_tokens, vec!["ftbAAA".to_string()]);
        // Defaults to empty when unset.
        let empty = resolve_server(ServerConfig::default(), None).unwrap();
        assert!(empty.bridges.is_empty());
        assert!(empty.allowed_bridge_servers.is_empty());
        assert!(empty.bridge_auth_tokens.is_empty());
    }

    #[test]
    fn bridge_requires_exactly_one_token_source() {
        for body in [
            // Neither source.
            "endpoint_id = \"e\"\ndomains = [\"*.svc\"]",
            // Both sources.
            "endpoint_id = \"e\"\nauth_token = \"ftbAAA\"\nauth_token_file = \"t\"\ndomains = [\"*.svc\"]",
        ] {
            let toml = format!("[bridges.lab]\n{body}\n");
            let file: ServerConfig = toml::from_str(&toml).unwrap();
            let err = resolve_server(ServerConfig::default(), Some(file)).unwrap_err();
            assert!(err.to_string().contains("exactly one of auth_token"), "{err}");
        }
    }

    #[test]
    fn bridge_with_no_rules_is_rejected() {
        let toml = r#"
            [bridges.lab]
            endpoint_id = "e"
            auth_token = "ftbAAA"
        "#;
        let file: ServerConfig = toml::from_str(toml).unwrap();
        let err = resolve_server(ServerConfig::default(), Some(file)).unwrap_err();
        assert!(err.to_string().contains("never match"), "{err}");
    }

    #[test]
    fn bridges_with_duplicate_endpoint_id_are_rejected() {
        let toml = r#"
            [bridges.a]
            endpoint_id = "same"
            auth_token = "ftbAAA"
            domains = ["*.svc"]

            [bridges.b]
            endpoint_id = "same"
            auth_token = "ftbBBB"
            cidrs = ["10.0.0.0/8"]
        "#;
        let file: ServerConfig = toml::from_str(toml).unwrap();
        let err = resolve_server(ServerConfig::default(), Some(file)).unwrap_err();
        assert!(err.to_string().contains("same endpoint_id"), "{err}");
    }

    #[test]
    fn client_defaults_applied() {
        let r = resolve_client(ClientConfig::default(), None);
        assert_eq!(r.socks_port, None);
        assert!(r.auto_reconnect);
    }

    #[test]
    fn expand_tilde_handles_home() {
        if let Some(home) = dirs::home_dir() {
            assert_eq!(expand_tilde(Path::new("~/x")), home.join("x"));
            assert_eq!(expand_tilde(Path::new("~")), home);
        }
        // Non-tilde paths are unchanged.
        assert_eq!(expand_tilde(Path::new("/etc/x")), PathBuf::from("/etc/x"));
    }

    #[test]
    fn shipped_example_files_parse() {
        // The committed examples must always deserialize against the current
        // schema, so the docs can't drift from the structs (`deny_unknown_fields`
        // would reject a stale/renamed key).
        toml::from_str::<ServerConfig>(include_str!("../../../server.toml.example"))
            .expect("server.toml.example must parse");
        toml::from_str::<ClientConfig>(include_str!("../../../client.toml.example"))
            .expect("client.toml.example must parse");
    }

    #[test]
    fn examples_document_every_config_field() {
        // A maximal config exercising every documented key must parse with
        // deny_unknown_fields — catches a field renamed/removed in the struct but
        // left in the examples (or a new struct field the examples never mention).
        let server = r#"
            secret_file = "./server.key"
            secret = "<base64 key>"
            auth_tokens = ["ftcAAA"]
            auth_tokens_file = "/etc/flextunnel/auth_tokens.txt"
            relay_urls = ["https://relay.example"]
            allowed_bridge_servers = ["<endpoint id>"]
            bridge_auth_tokens = ["ftbAAA"]
            bridge_auth_tokens_file = "/etc/flextunnel/bridge_auth_tokens.txt"
            routed_domains = ["*.example.com"]
            routed_cidrs = ["10.0.0.0/8"]

            [host_aliases]
            "server.internal" = "127.0.0.1"

            [dns_forwards]
            "corp.example.com" = ["10.1.0.10:5353"]

            [bridges.lab]
            endpoint_id = "<endpoint id>"
            auth_token = "ftbBBB"
            domains = ["*.svc"]
            cidrs = ["fd34::/64"]
        "#;
        let s: ServerConfig = toml::from_str(server).expect("maximal server config parses");
        assert!(s.secret_file.is_some() && s.dns_forwards.is_some() && s.bridges.is_some());

        let client = r#"
            server_node_id = "<server endpoint id>"
            name = "aws"
            socks_port = 1080
            http_port = 8081
            auth_token = "ftcAAA"
            auth_token_file = "~/.config/flextunnel/token.txt"
            relay_urls = ["https://relay.example"]
            auto_reconnect = true
            max_reconnect_attempts = 10
        "#;
        let c: ClientConfig = toml::from_str(client).expect("maximal client config parses");
        assert!(c.server_node_id.is_some() && c.max_reconnect_attempts.is_some());
    }
}
