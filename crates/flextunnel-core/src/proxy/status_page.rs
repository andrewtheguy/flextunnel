//! The `flextunnel.internal` server status page and the reserved-subdomain 404,
//! served as HTTP responses over the tunnel stream.
//!
//! The status page reflects the **server's** live routing config, so it is
//! rendered server-side (with askama) and written back to the client as opaque
//! HTTP bytes over the same QUIC stream a normal tunnel would use. The client
//! splices those bytes verbatim to the local app, so `http://flextunnel.internal`
//! renders in the browser. HTTPS is not terminated — this is HTTP-only.

use askama::Template;
use iroh::endpoint::SendStream;
use serde::Serialize;
use std::io;
use tokio::io::AsyncWriteExt;

use crate::proxy::signaling;

/// Plain-text status endpoint under `flextunnel.internal`.
pub const STATUS_TEXT_PATH: &str = "/status.txt";
/// JSON status endpoint under `flextunnel.internal`.
pub const STATUS_JSON_PATH: &str = "/status.json";

const CONTENT_TYPE_HTML: &str = "text/html; charset=utf-8";
const CONTENT_TYPE_TEXT: &str = "text/plain; charset=utf-8";
const CONTENT_TYPE_JSON: &str = "application/json; charset=utf-8";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatusFormat {
    Html,
    Text,
    Json,
}

/// One configured outbound bridge plus whether its upstream connection to the
/// target server is live right now.
#[derive(Serialize)]
pub struct BridgeUpstreamStatus {
    pub name: String,
    pub endpoint_id: String,
    pub domains: Vec<String>,
    pub cidrs: Vec<String>,
    pub connected: bool,
}

/// One allowlisted inbound bridge server plus whether it is connected right now.
#[derive(Serialize)]
pub struct BridgeInboundStatus {
    pub endpoint_id: String,
    pub connected: bool,
}

/// The server status page. Fields are populated from the live `ProxyServer`
/// state; secrets are never included and the blocklist is shown as counts only.
#[derive(Template)]
#[template(path = "server_status.html")]
pub struct ServerStatusTemplate {
    pub version: &'static str,
    pub node_id: String,
    pub routed_domains: Vec<String>,
    pub routed_cidrs: Vec<String>,
    /// `(alias, target)` pairs, sorted for stable output.
    pub host_aliases: Vec<(String, String)>,
    /// Conditional DNS forwards as `(suffix, upstream servers)` pairs, sorted by
    /// suffix for stable output.
    pub dns_forwards: Vec<(String, Vec<String>)>,
    /// Outbound bridge routes with live connected state, sorted by name.
    pub bridges: Vec<BridgeUpstreamStatus>,
    /// Allowlisted inbound bridge servers with live connected state, sorted by
    /// endpoint id.
    pub inbound_bridges: Vec<BridgeInboundStatus>,
    pub blocklist_path: String,
    pub blocked_client_count: usize,
    pub conflicted_server_count: usize,
}

/// The `*.flextunnel.internal` "reserved for future use" page.
#[derive(Template)]
#[template(path = "reserved_404.html")]
pub struct ReservedNotFoundTemplate;

#[derive(Template)]
#[template(path = "server_status.txt")]
struct ServerStatusTextTemplate<'a> {
    tpl: &'a ServerStatusTemplate,
}

#[derive(Serialize)]
struct ServerStatusJson<'a> {
    version: &'static str,
    server_node_id: &'a str,
    routed_domains: &'a [String],
    routed_cidrs: &'a [String],
    host_aliases: Vec<HostAliasJson<'a>>,
    dns_forwards: Vec<DnsForwardJson<'a>>,
    bridges: &'a [BridgeUpstreamStatus],
    inbound_bridges: &'a [BridgeInboundStatus],
    duplicate_id_blocklist: DuplicateIdBlocklistJson<'a>,
}

#[derive(Serialize)]
struct HostAliasJson<'a> {
    name: &'a str,
    target: &'a str,
}

#[derive(Serialize)]
struct DnsForwardJson<'a> {
    suffix: &'a str,
    servers: &'a [String],
}

#[derive(Serialize)]
struct DuplicateIdBlocklistJson<'a> {
    file: &'a str,
    blocked_clients: usize,
    conflicted_servers: usize,
}

/// Fallback body used if a template fails to render (should not happen with
/// compiled templates, but we never drop the stream uncleanly over it).
const FALLBACK_BODY: &str =
    "<!DOCTYPE html><title>flextunnel</title><p>status page unavailable</p>";
const FALLBACK_TEXT_BODY: &str = "flextunnel server status unavailable\n";
const FALLBACK_JSON_BODY: &str = "{\"error\":\"flextunnel server status unavailable\"}\n";

/// Render the status page, falling back to a 500 on the (unexpected) render
/// error. Returns `(http_status_line, content_type, body)`.
pub fn render_status(
    tpl: &ServerStatusTemplate,
    format: StatusFormat,
) -> (&'static str, &'static str, String) {
    match format {
        StatusFormat::Html => match tpl.render() {
            Ok(body) => ("200 OK", CONTENT_TYPE_HTML, body),
            Err(e) => {
                log::warn!("Failed to render status page: {e}");
                (
                    "500 Internal Server Error",
                    CONTENT_TYPE_HTML,
                    FALLBACK_BODY.to_string(),
                )
            }
        },
        StatusFormat::Text => match render_status_text(tpl) {
            Ok(body) => ("200 OK", CONTENT_TYPE_TEXT, body),
            Err(e) => {
                log::warn!("Failed to render status text page: {e}");
                (
                    "500 Internal Server Error",
                    CONTENT_TYPE_TEXT,
                    FALLBACK_TEXT_BODY.to_string(),
                )
            }
        },
        StatusFormat::Json => match render_status_json(tpl) {
            Ok(body) => ("200 OK", CONTENT_TYPE_JSON, body),
            Err(e) => {
                log::warn!("Failed to render status JSON page: {e}");
                (
                    "500 Internal Server Error",
                    CONTENT_TYPE_JSON,
                    FALLBACK_JSON_BODY.to_string(),
                )
            }
        },
    }
}

fn render_status_text(tpl: &ServerStatusTemplate) -> Result<String, askama::Error> {
    ServerStatusTextTemplate { tpl }.render()
}

fn render_status_json(tpl: &ServerStatusTemplate) -> Result<String, serde_json::Error> {
    let host_aliases = tpl
        .host_aliases
        .iter()
        .map(|(name, target)| HostAliasJson { name, target })
        .collect();
    let dns_forwards = tpl
        .dns_forwards
        .iter()
        .map(|(suffix, servers)| DnsForwardJson { suffix, servers })
        .collect();
    let payload = ServerStatusJson {
        version: tpl.version,
        server_node_id: &tpl.node_id,
        routed_domains: &tpl.routed_domains,
        routed_cidrs: &tpl.routed_cidrs,
        host_aliases,
        dns_forwards,
        bridges: &tpl.bridges,
        inbound_bridges: &tpl.inbound_bridges,
        duplicate_id_blocklist: DuplicateIdBlocklistJson {
            file: &tpl.blocklist_path,
            blocked_clients: tpl.blocked_client_count,
            conflicted_servers: tpl.conflicted_server_count,
        },
    };
    serde_json::to_string_pretty(&payload).map(|mut body| {
        body.push('\n');
        body
    })
}

/// Render the reserved-subdomain 404 page.
pub fn render_reserved_404() -> (&'static str, &'static str, String) {
    let body = ReservedNotFoundTemplate
        .render()
        .unwrap_or_else(|_| FALLBACK_BODY.to_string());
    ("404 Not Found", CONTENT_TYPE_HTML, body)
}

/// Write the per-stream success byte that lets the local client start relaying.
pub async fn write_tunnel_success(send: &mut SendStream) -> io::Result<()> {
    signaling::write_reply(send, signaling::REP_SUCCESS).await?;
    send.flush().await
}

/// Write an HTTP/1.1 response after the per-stream success byte has been sent.
pub async fn write_http_payload(
    send: &mut SendStream,
    status_line: &str,
    content_type: &str,
    body: &str,
) -> io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status_line}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n{body}",
        body.len(),
    );
    send.write_all(response.as_bytes()).await?;
    send.flush().await?;
    let _ = send.finish();
    Ok(())
}

/// Write an HTTP/1.1 response as the tunnel-stream payload.
///
/// The client expects the per-stream success reply byte first (as with any
/// established tunnel), then treats the rest of the stream as opaque bytes to
/// splice to the local app — here, our HTTP response. `Connection: close` and a
/// `Content-Length` let the browser complete the response, and finishing the
/// stream signals EOF.
pub async fn write_http_response(
    send: &mut SendStream,
    status_line: &str,
    content_type: &str,
    body: &str,
) -> io::Result<()> {
    write_tunnel_success(send).await?;
    write_http_payload(send, status_line, content_type, body).await
}
