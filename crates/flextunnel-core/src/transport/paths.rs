//! Connection-path reporting (direct vs relay) and custom-relay health.
//!
//! A point-in-time [`connection_snapshot`] backs the on-demand status UIs (the
//! desktop "connection path" CTA and the CLI status TUI).
//! [`watch_connection_paths`] logs the selected
//! path and re-logs whenever it changes (e.g. relay -> direct).

use crate::transport::endpoint::RelayConfig;
use iroh::TransportAddr;
use iroh::endpoint::{Connection, PathList};
use n0_future::StreamExt;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::task::JoinHandle;

/// Per-request timeout for the custom-relay `/healthz` check. Kept short so the
/// on-demand status call stays responsive even when a relay is unreachable.
const HEALTHZ_TIMEOUT: Duration = Duration::from_secs(3);

/// Which kind of transport a connection path uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnPathKind {
    /// A direct peer-to-peer path (holepunched UDP).
    Direct,
    /// A path relayed through an iroh relay server.
    Relay,
    /// Any other transport iroh reports (forward-compatible catch-all).
    Other,
}

/// A single connection path snapshot for status display, decoupled from iroh's
/// borrowed [`PathList`] so it can be stored and shown on demand (the desktop's
/// "connection path" CTA and the CLI status TUI).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnPath {
    pub kind: ConnPathKind,
    /// Human line like `Direct 1.2.3.4:52186 (rtt 1ms)` or
    /// `Relay https://… (rtt 42ms)`.
    pub display: String,
    /// Whether iroh currently routes traffic over this path.
    pub selected: bool,
}

/// Health of one configured custom relay, from an on-demand `/healthz` probe.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustomRelayStatus {
    pub url: String,
    /// `Some(true)` when the relay's `/healthz` returned a 2xx, `Some(false)`
    /// when it failed (unreachable, timed out, or a non-2xx response), or `None`
    /// if the check could not be run at all (e.g. the HTTP client failed to
    /// build). Note this probes the relay's plain HTTP health endpoint, which is
    /// unauthenticated — it confirms the relay is up, not that the auth token is
    /// accepted (the startup per-relay `online()` probe validates the token).
    pub working: Option<bool>,
    pub error: Option<String>,
}

/// One on-demand snapshot for connection-status UIs. Both path discovery and
/// relay health are sampled only when this is requested; no watcher is retained.
#[derive(Clone, Debug, Default)]
pub struct ConnectionSnapshot {
    pub paths: Vec<ConnPath>,
    pub custom_relays: Vec<CustomRelayStatus>,
}

/// Snapshot the current path(s) of a live connection for a status UI, showing
/// *all* paths (not just the selected one) so a direct path iroh has discovered
/// but not selected is still visible. [`Connection::paths`] is itself a
/// point-in-time snapshot, so this needs no background watcher. Empty while the
/// connection is down.
pub fn connection_paths(conn: &Connection) -> Vec<ConnPath> {
    connection_paths_from(&conn.paths())
}

fn connection_paths_from(paths: &PathList<'_>) -> Vec<ConnPath> {
    paths
        .iter()
        .map(|path| {
            let rtt = path.rtt();
            let selected = path.is_selected();
            let (kind, display) = match path.remote_addr() {
                TransportAddr::Ip(addr) => {
                    (ConnPathKind::Direct, format!("Direct {addr} (rtt {rtt:.0?})"))
                }
                TransportAddr::Relay(url) => {
                    (ConnPathKind::Relay, format!("Relay {url} (rtt {rtt:.0?})"))
                }
                other => (ConnPathKind::Other, format!("{other:?} (rtt {rtt:.0?})")),
            };
            ConnPath {
                kind,
                display,
                selected,
            }
        })
        .collect()
}

/// Snapshot the connection paths and probe configured custom-relay health.
///
/// The path snapshot is synchronous; the relay health is an on-demand `/healthz`
/// probe (async, all relays in parallel). This is only invoked when a status UI
/// asks for it (the desktop connection-path sheet, the CLI status TUI), so
/// the HTTP checks never run on the tunnel's hot path.
pub async fn connection_snapshot(
    conn: &Connection,
    relay_config: &RelayConfig,
) -> ConnectionSnapshot {
    let paths = connection_paths_from(&conn.paths());
    let custom_relays = probe_custom_relay_health(relay_config).await;
    ConnectionSnapshot {
        paths,
        custom_relays,
    }
}

/// Install a process-wide ring crypto provider for `reqwest` (built with
/// `rustls-no-provider`, which resolves the provider via
/// [`rustls::crypto::CryptoProvider::get_default`]). Idempotent and safe to call
/// from any thread; a competing install by another component is fine.
fn ensure_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Probe the `/healthz` endpoint of every configured custom relay in parallel.
/// Empty for the default relays (nothing custom to check).
pub async fn probe_custom_relay_health(relay_config: &RelayConfig) -> Vec<CustomRelayStatus> {
    let urls = relay_config.custom_urls();
    if urls.is_empty() {
        return Vec::new();
    }
    ensure_crypto_provider();
    let client = match reqwest::Client::builder().timeout(HEALTHZ_TIMEOUT).build() {
        Ok(client) => client,
        Err(e) => {
            let err = format!("failed to build health-check client: {e}");
            return urls
                .iter()
                .map(|url| CustomRelayStatus {
                    url: url.to_string(),
                    working: None,
                    error: Some(err.clone()),
                })
                .collect();
        }
    };
    futures::future::join_all(urls.iter().map(|url| probe_relay_healthz(&client, url))).await
}

/// Probe one relay's `/healthz`. `working` is `Some(true)` on a 2xx response,
/// `Some(false)` otherwise (unreachable, timeout, or non-2xx).
async fn probe_relay_healthz(client: &reqwest::Client, url: &iroh::RelayUrl) -> CustomRelayStatus {
    // `RelayUrl` derefs to `url::Url`; join an absolute path so a missing/extra
    // trailing slash on the configured URL does not matter.
    let healthz = match url.join("/healthz") {
        Ok(healthz) => healthz,
        Err(e) => {
            return CustomRelayStatus {
                url: url.to_string(),
                working: Some(false),
                error: Some(format!("invalid relay URL: {e}")),
            };
        }
    };
    match client.get(healthz).send().await {
        Ok(resp) if resp.status().is_success() => CustomRelayStatus {
            url: url.to_string(),
            working: Some(true),
            error: None,
        },
        Ok(resp) => CustomRelayStatus {
            url: url.to_string(),
            working: Some(false),
            error: Some(format!("/healthz returned HTTP {}", resp.status())),
        },
        Err(e) => CustomRelayStatus {
            url: url.to_string(),
            working: Some(false),
            error: Some(e.to_string()),
        },
    }
}

/// Format the currently-selected path(s) of a connection for logging, e.g.
/// `Direct [2607:…]:52186 (rtt 1ms)` or `Relay https://… (rtt 42ms)`.
fn format_paths(paths: &PathList<'_>) -> String {
    if paths.is_empty() {
        return "establishing...".to_string();
    }
    let parts: Vec<String> = paths
        .iter()
        .filter(|p| p.is_selected())
        .map(|path| {
            let rtt = path.rtt();
            match path.remote_addr() {
                TransportAddr::Ip(addr) => format!("Direct {addr} (rtt {rtt:.0?})"),
                TransportAddr::Relay(url) => format!("Relay {url} (rtt {rtt:.0?})"),
                other => format!("{other:?} (rtt {rtt:.0?})"),
            }
        })
        .collect();
    if parts.is_empty() {
        "no selected path".to_string()
    } else {
        parts.join(", ")
    }
}

/// Key identifying the selected-path topology, excluding the volatile RTT, so
/// we only log when the path actually changes (not on every RTT update).
fn paths_key(paths: &PathList<'_>) -> (bool, Vec<String>) {
    let selected = paths
        .iter()
        .filter(|p| p.is_selected())
        .map(|p| format!("{:?}", p.remote_addr()))
        .collect();
    (paths.is_empty(), selected)
}

/// RAII guard that aborts the background path-watcher task on drop.
pub struct PathWatcherGuard(Option<JoinHandle<()>>);

impl Drop for PathWatcherGuard {
    fn drop(&mut self) {
        if let Some(handle) = &self.0 {
            handle.abort();
        }
    }
}

/// Log the connection's selected path and spawn a background task that logs
/// updates whenever the active path changes (e.g. relay -> direct).
///
/// Logging is the task's sole purpose, so when debug logging is disabled the
/// task is not spawned at all and the returned guard is inert.
///
/// The returned [`PathWatcherGuard`] aborts the background task when dropped;
/// callers must keep it alive for the duration of the connection.
pub fn watch_connection_paths(conn: &Connection) -> PathWatcherGuard {
    if !log::log_enabled!(log::Level::Debug) {
        return PathWatcherGuard(None);
    }
    let conn = conn.clone();
    PathWatcherGuard(Some(tokio::spawn(async move {
        // The stream yields the current snapshot on the first poll, then a
        // fresh snapshot whenever the open or selected paths change; it ends
        // when the connection closes.
        let mut stream = conn.paths_stream();
        let mut last_key = None;
        while let Some(paths) = stream.next().await {
            let key = paths_key(&paths);
            if last_key.as_ref() != Some(&key) {
                log::debug!("Connection: {}", format_paths(&paths));
                last_key = Some(key);
            }
        }
    })))
}
