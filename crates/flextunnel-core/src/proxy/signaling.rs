//! Wire protocol for flextunnel.
//!
//! Two layers ride one iroh QUIC connection:
//!
//! * **Connection auth** — a [`Hello`]/[`HelloResponse`] exchange on the first
//!   bi-stream, framed with the length-prefixed [`write_message`]/[`read_message`]
//!   helpers (adapted from ezvpn's signaling).
//! * **Per-SOCKS5-connection** — each subsequent bi-stream carries a compact
//!   binary request header (reusing SOCKS5 ATYP encoding), a one-byte reply, then
//!   raw bytes in both directions.

use serde::{Deserialize, Serialize};
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// flextunnel protocol version.
pub const PROTOCOL_VERSION: u16 = 12;

/// Maximum auth-handshake message size (64 KiB). The server's routed set rides
/// the `HelloResponse`, so this is generous enough for a large operator list.
pub const MAX_HANDSHAKE_SIZE: usize = 64 * 1024;

/// Maximum size of a control-stream frame ([`ControlMsg`]). Generous for the
/// small heartbeat frames while still bounding a misbehaving peer.
pub const MAX_CONTROL_MSG_SIZE: usize = 16 * 1024;

/// Per-stream request/reply header version byte.
const STREAM_VERSION: u8 = 1;

// SOCKS5 address types (RFC 1928 ATYP), reused on the flextunnel wire.
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

// Reply codes — deliberately equal to RFC 1928 SOCKS5 reply codes so the client
// forwards the server's reply byte straight into its SOCKS5 reply to the app.
pub const REP_SUCCESS: u8 = 0x00;
pub const REP_GENERAL_FAILURE: u8 = 0x01;
/// Connection not allowed by ruleset — used when the server's routed-set
/// whitelist rejects a target.
pub const REP_NOT_ALLOWED: u8 = 0x02;
pub const REP_NET_UNREACHABLE: u8 = 0x03;
pub const REP_HOST_UNREACHABLE: u8 = 0x04;
pub const REP_CONN_REFUSED: u8 = 0x05;
pub const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
pub const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

/// Public-key credential of a regular client's `Hello` (see [`crate::auth`]).
///
/// Nothing in it is secret: the public key is meant to be displayed, the
/// endpoint id is already TLS-visible, and the signature reveals nothing
/// about the secret key — so `Debug` derives plainly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientAuthPayload {
    /// The client's authentication public key (`flextunnelpubv1:...`), which
    /// must be on the server's authorized-keys file.
    pub public_key: String,
    /// The iroh endpoint id this client claims to be connecting from (its
    /// ephemeral endpoint identity). The server checks it against the
    /// connection's TLS-authenticated `remote_id()`.
    pub endpoint_id: String,
    /// base64url ed25519 signature over the domain-separated `endpoint_id`
    /// (see `auth::verify_endpoint_id_signature`), binding the credential to
    /// this connection so a captured `Hello` cannot be replayed elsewhere.
    pub signature: String,
}

/// Client → server auth handshake (first bi-stream of the connection).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub version: u16,
    /// Public-key credential for a regular [`ALPN`] client. `None` for a
    /// quick-mode [`QUICK_ALPN`] client, whose sole credential is its
    /// TLS-authenticated endpoint id — already checked against the server's
    /// allowlist natively before the connection reaches the accept loop.
    ///
    /// [`ALPN`]: crate::transport::ALPN
    /// [`QUICK_ALPN`]: crate::transport::QUICK_ALPN
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<ClientAuthPayload>,
    /// Random per-process identity of the *client process*, distinct from its
    /// (ephemeral) iroh node id. Lets the server tell a benign reconnect of one
    /// client (same nonce) apart from two distinct processes presenting the same
    /// node id (different nonces → a duplicate-client bug). See `proxy::server`.
    pub client_instance_nonce: u128,
    /// Non-privileged advisory: the client has observed a pattern that indicates
    /// a *duplicate server id* (two servers sharing this identity — see the
    /// server-nonce reappearance rule in `proxy::client`). It is an observation,
    /// not a command; the server decides whether to self-block on it.
    #[serde(default)]
    pub duplicate_server_observed: bool,
}

/// Server → client auth handshake response.
///
/// On acceptance the server pushes its resolved routed set (the *tunnel set*) so
/// the client can make the split-tunnel decision without configuring its own
/// list — the server is the single source of truth. Clients reject an empty
/// routed set; bridges receive empty informational route lists because they do
/// not make local split-tunnel decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloResponse {
    pub version: u16,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reject_reason: Option<String>,
    /// Random per-process identity of the *server process*, stable for its
    /// lifetime. A restarting server emits a fresh random nonce each start (never
    /// reappearing); a client bouncing between two servers that share this
    /// identity sees nonces flip-flop. That reappearance is how a client detects
    /// a duplicate server id (see `proxy::client`). Sent on acceptance and
    /// rejection alike so the client can always record it.
    pub server_instance_nonce: u128,
    /// Domain rules the client should tunnel (exact or `*.` wildcard).
    #[serde(default)]
    pub routed_domains: Vec<String>,
    /// CIDR / bare-IP rules the client should tunnel.
    #[serde(default)]
    pub routed_cidrs: Vec<String>,
    /// Server-side host aliases as `(alias, target)` pairs, sorted by alias.
    /// Purely informational for client UIs (the server status page shows the
    /// same list); alias resolution itself stays server-side.
    #[serde(default)]
    pub host_aliases: Vec<(String, String)>,
    /// Server-side conditional DNS forwards as `(suffix, upstream servers)`
    /// pairs, sorted by suffix. Purely informational for client UIs (the server
    /// status page shows the same list); the resolution itself stays
    /// server-side. Empty when no `[dns_forwards]` are configured.
    #[serde(default)]
    pub dns_forwards: Vec<(String, Vec<String>)>,
    /// Outbound bridge routes (targets forwarded to another server), sorted by
    /// name. Purely informational for client UIs — the routing decision stays
    /// server-side and the bridged rules are already part of the routed set.
    #[serde(default)]
    pub bridges: Vec<BridgeSummary>,
}

impl Hello {
    /// A client `Hello`. `auth` is `Some` for a keypair client, `None` for
    /// a quick-mode client (see the field docs).
    pub fn new(auth: Option<ClientAuthPayload>, client_instance_nonce: u128) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            auth,
            client_instance_nonce,
            duplicate_server_observed: false,
        }
    }
}

/// Bridge → server handshake (first bi-stream of a [`BRIDGE_ALPN`] connection).
///
/// Carries only the protocol version: the bridge's role rides the ALPN, and its
/// sole credential is its TLS-authenticated endpoint id, checked natively
/// against the server's allowlist before the connection ever reaches the
/// accept loop (see `transport::endpoint::AllowlistHook`). The server
/// replies with a [`HelloResponse`] and the stream stays open for heartbeats.
///
/// [`BRIDGE_ALPN`]: crate::transport::BRIDGE_ALPN
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeHello {
    pub version: u16,
}

impl BridgeHello {
    pub fn new() -> Self {
        Self {
            version: PROTOCOL_VERSION,
        }
    }
}

impl Default for BridgeHello {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode a `BridgeHello` to JSON bytes.
pub fn encode_bridge_hello(hello: &BridgeHello) -> io::Result<Vec<u8>> {
    serde_json::to_vec(hello).map_err(io::Error::other)
}

/// Decode a `BridgeHello` from JSON bytes, validating the protocol version.
pub fn decode_bridge_hello(data: &[u8]) -> io::Result<BridgeHello> {
    let hello: BridgeHello = serde_json::from_slice(data).map_err(io::Error::other)?;
    if hello.version != PROTOCOL_VERSION {
        return Err(io::Error::other(format!(
            "Unsupported protocol version: {} (expected {})",
            hello.version, PROTOCOL_VERSION
        )));
    }
    Ok(hello)
}

/// One outbound bridge route, pushed to clients on acceptance. Config only —
/// no live connected-state, which would go stale the moment the handshake
/// snapshot is taken (the server status page shows live state instead).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeSummary {
    /// The friendly `[bridges.<name>]` config key.
    pub name: String,
    /// The target server's iroh endpoint id.
    pub endpoint_id: String,
    /// Domain rules forwarded to the target server (routed-set syntax).
    pub domains: Vec<String>,
    /// CIDR / bare-IP rules forwarded to the target server.
    pub cidrs: Vec<String>,
}

/// The routing/status payload the server pushes to a peer on acceptance,
/// grouped so the several same-typed lists can't be swapped positionally. Only
/// the routed set (`routed_domains`/`routed_cidrs`) is enforced client-side; the
/// rest is informational for status UIs. `Default` (all empty) is the bridge
/// case — a bridge gets no routed set.
#[derive(Debug, Clone, Default)]
pub struct AcceptedRoutes {
    /// Domain rules the client should tunnel (exact or `*.` wildcard).
    pub routed_domains: Vec<String>,
    /// CIDR / bare-IP rules the client should tunnel.
    pub routed_cidrs: Vec<String>,
    /// Server-side host aliases as `(alias, target)` pairs, sorted by alias.
    pub host_aliases: Vec<(String, String)>,
    /// Conditional DNS forwards as `(suffix, upstream servers)` pairs.
    pub dns_forwards: Vec<(String, Vec<String>)>,
    /// Outbound bridge routes, sorted by name.
    pub bridges: Vec<BridgeSummary>,
}

impl HelloResponse {
    /// Accept the peer and push its [`AcceptedRoutes`] (the *tunnel set* plus the
    /// informational host-alias and DNS-forward lists).
    pub fn accepted(server_instance_nonce: u128, routes: AcceptedRoutes) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            accepted: true,
            reject_reason: None,
            server_instance_nonce,
            routed_domains: routes.routed_domains,
            routed_cidrs: routes.routed_cidrs,
            host_aliases: routes.host_aliases,
            dns_forwards: routes.dns_forwards,
            bridges: routes.bridges,
        }
    }

    pub fn rejected(server_instance_nonce: u128, reason: impl Into<String>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            accepted: false,
            reject_reason: Some(reason.into()),
            server_instance_nonce,
            routed_domains: Vec::new(),
            routed_cidrs: Vec::new(),
            host_aliases: Vec::new(),
            dns_forwards: Vec::new(),
            bridges: Vec::new(),
        }
    }
}

/// Control-stream frames exchanged after the auth handshake.
///
/// The first bi-stream is not closed after `Hello`/`HelloResponse`; it stays
/// open as a control channel. The client sends [`ControlMsg::Heartbeat`] every
/// [`HEARTBEAT_INTERVAL`](crate::transport::HEARTBEAT_INTERVAL) and the server
/// replies [`ControlMsg::HeartbeatAck`]. This is an app-level liveness signal
/// (on top of QUIC keep-alive) that also drives the server's duplicate-client
/// registry. Framed with [`write_message`]/[`read_message`], capped at
/// [`MAX_CONTROL_MSG_SIZE`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlMsg {
    /// Client → server liveness ping, carrying a monotonically increasing seq.
    Heartbeat { seq: u64 },
    /// Server → client reply echoing the heartbeat's seq.
    HeartbeatAck { seq: u64 },
}

/// Encode a [`ControlMsg`] to JSON bytes.
pub fn encode_control(msg: &ControlMsg) -> io::Result<Vec<u8>> {
    serde_json::to_vec(msg).map_err(io::Error::other)
}

/// Decode a [`ControlMsg`] from JSON bytes.
pub fn decode_control(data: &[u8]) -> io::Result<ControlMsg> {
    serde_json::from_slice(data).map_err(io::Error::other)
}

/// A connection target requested over a per-SOCKS5 stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A resolved socket address (SOCKS5 ATYP IPv4/IPv6).
    Ip(SocketAddr),
    /// A domain name + port; resolved on the server side (SOCKS5 ATYP DOMAIN).
    Domain(String, u16),
}

/// Write a length-prefixed message (4-byte big-endian length + payload).
pub async fn write_message<W: AsyncWriteExt + Unpin>(writer: &mut W, data: &[u8]) -> io::Result<()> {
    let len = u32::try_from(data.len())
        .map_err(|_| io::Error::other(format!("Message too large: {} bytes", data.len())))?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(data).await?;
    Ok(())
}

/// Read a length-prefixed message, rejecting anything larger than `max_size`.
pub async fn read_message<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    max_size: usize,
) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max_size {
        return Err(io::Error::other(format!(
            "Message too large: {len} > {max_size}"
        )));
    }
    let mut data = vec![0u8; len];
    reader.read_exact(&mut data).await?;
    Ok(data)
}

/// Encode a `Hello` to JSON bytes.
pub fn encode_hello(hello: &Hello) -> io::Result<Vec<u8>> {
    serde_json::to_vec(hello).map_err(io::Error::other)
}

/// Decode a `Hello` from JSON bytes, validating the protocol version.
pub fn decode_hello(data: &[u8]) -> io::Result<Hello> {
    let hello: Hello = serde_json::from_slice(data).map_err(io::Error::other)?;
    if hello.version != PROTOCOL_VERSION {
        return Err(io::Error::other(format!(
            "Unsupported protocol version: {} (expected {})",
            hello.version, PROTOCOL_VERSION
        )));
    }
    Ok(hello)
}

/// Encode a `HelloResponse` to JSON bytes.
pub fn encode_hello_response(resp: &HelloResponse) -> io::Result<Vec<u8>> {
    serde_json::to_vec(resp).map_err(io::Error::other)
}

/// Decode a `HelloResponse` from JSON bytes, validating the protocol version.
pub fn decode_hello_response(data: &[u8]) -> io::Result<HelloResponse> {
    let resp: HelloResponse = serde_json::from_slice(data).map_err(io::Error::other)?;
    if resp.version != PROTOCOL_VERSION {
        return Err(io::Error::other(format!(
            "Unsupported protocol version: {} (expected {})",
            resp.version, PROTOCOL_VERSION
        )));
    }
    Ok(resp)
}

/// Write the per-stream request header: `[ver][atyp][addr][port:u16 BE]`.
pub async fn write_request<W: AsyncWriteExt + Unpin>(w: &mut W, t: &Target) -> io::Result<()> {
    let mut buf = vec![STREAM_VERSION];
    match t {
        Target::Ip(SocketAddr::V4(sa)) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&sa.ip().octets());
            buf.extend_from_slice(&sa.port().to_be_bytes());
        }
        Target::Ip(SocketAddr::V6(sa)) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&sa.ip().octets());
            buf.extend_from_slice(&sa.port().to_be_bytes());
        }
        Target::Domain(host, port) => {
            let bytes = host.as_bytes();
            let len = u8::try_from(bytes.len())
                .map_err(|_| io::Error::other("domain name longer than 255 bytes"))?;
            buf.push(ATYP_DOMAIN);
            buf.push(len);
            buf.extend_from_slice(bytes);
            buf.extend_from_slice(&port.to_be_bytes());
        }
    }
    w.write_all(&buf).await
}

/// Read the per-stream request header written by [`write_request`].
pub async fn read_request<R: AsyncReadExt + Unpin>(r: &mut R) -> io::Result<Target> {
    let ver = r.read_u8().await?;
    if ver != STREAM_VERSION {
        return Err(io::Error::other(format!(
            "Unsupported stream version: {ver} (expected {STREAM_VERSION})"
        )));
    }
    let atyp = r.read_u8().await?;
    match atyp {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            r.read_exact(&mut octets).await?;
            let port = r.read_u16().await?;
            Ok(Target::Ip(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(octets),
                port,
            ))))
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            r.read_exact(&mut octets).await?;
            let port = r.read_u16().await?;
            Ok(Target::Ip(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(octets),
                port,
                0,
                0,
            ))))
        }
        ATYP_DOMAIN => {
            let len = r.read_u8().await? as usize;
            let mut host = vec![0u8; len];
            r.read_exact(&mut host).await?;
            let port = r.read_u16().await?;
            let host = String::from_utf8(host)
                .map_err(|_| io::Error::other("domain name is not valid UTF-8"))?;
            Ok(Target::Domain(host, port))
        }
        other => Err(io::Error::other(format!("invalid address type: 0x{other:02x}"))),
    }
}

/// Write the per-stream reply header: `[ver][rep]`.
pub async fn write_reply<W: AsyncWriteExt + Unpin>(w: &mut W, rep: u8) -> io::Result<()> {
    w.write_all(&[STREAM_VERSION, rep]).await
}

/// Read the per-stream reply header, returning the reply code.
pub async fn read_reply<R: AsyncReadExt + Unpin>(r: &mut R) -> io::Result<u8> {
    let ver = r.read_u8().await?;
    if ver != STREAM_VERSION {
        return Err(io::Error::other(format!(
            "Unsupported stream version: {ver} (expected {STREAM_VERSION})"
        )));
    }
    r.read_u8().await
}

/// Map an outbound-connect I/O error to a SOCKS5 reply code.
pub fn map_io_err(e: &io::Error) -> u8 {
    use io::ErrorKind::*;
    match e.kind() {
        ConnectionRefused => REP_CONN_REFUSED,
        NetworkUnreachable => REP_NET_UNREACHABLE,
        HostUnreachable => REP_HOST_UNREACHABLE,
        _ => REP_GENERAL_FAILURE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn request_roundtrip_ipv4() {
        let t = Target::Ip("93.184.216.34:443".parse().unwrap());
        let mut buf = Vec::new();
        write_request(&mut buf, &t).await.unwrap();
        let got = read_request(&mut buf.as_slice()).await.unwrap();
        assert_eq!(got, t);
    }

    #[tokio::test]
    async fn request_roundtrip_ipv6() {
        let t = Target::Ip("[2606:2800:220:1:248:1893:25c8:1946]:80".parse().unwrap());
        let mut buf = Vec::new();
        write_request(&mut buf, &t).await.unwrap();
        let got = read_request(&mut buf.as_slice()).await.unwrap();
        assert_eq!(got, t);
    }

    #[tokio::test]
    async fn request_roundtrip_domain() {
        let t = Target::Domain("example.com".to_string(), 443);
        let mut buf = Vec::new();
        write_request(&mut buf, &t).await.unwrap();
        let got = read_request(&mut buf.as_slice()).await.unwrap();
        assert_eq!(got, t);
    }

    #[tokio::test]
    async fn reply_roundtrip() {
        let mut buf = Vec::new();
        write_reply(&mut buf, REP_HOST_UNREACHABLE).await.unwrap();
        let rep = read_reply(&mut buf.as_slice()).await.unwrap();
        assert_eq!(rep, REP_HOST_UNREACHABLE);
    }

    #[test]
    fn hello_roundtrip() {
        let hello = Hello::new(
            Some(ClientAuthPayload {
                public_key: "flextunnelpubv1:abc".to_string(),
                endpoint_id: "endpointid".to_string(),
                signature: "sig".to_string(),
            }),
            0x1234_5678_9abc_def0_1122_3344_5566_7788,
        );
        let encoded = encode_hello(&hello).unwrap();
        let decoded = decode_hello(&encoded).unwrap();
        let auth = decoded.auth.expect("auth payload present");
        assert_eq!(auth.public_key, "flextunnelpubv1:abc");
        assert_eq!(auth.endpoint_id, "endpointid");
        assert_eq!(auth.signature, "sig");
        assert_eq!(decoded.version, PROTOCOL_VERSION);
        assert_eq!(
            decoded.client_instance_nonce,
            0x1234_5678_9abc_def0_1122_3344_5566_7788
        );
        assert!(!decoded.duplicate_server_observed);

        // A quick-mode hello carries no credential (the endpoint-id allowlist
        // is the credential); the field is omitted on the wire entirely.
        let quick = Hello::new(None, 7);
        let encoded = encode_hello(&quick).unwrap();
        assert!(!String::from_utf8_lossy(&encoded).contains("auth"));
        assert!(decode_hello(&encoded).unwrap().auth.is_none());
    }

    #[test]
    fn hello_response_roundtrip() {
        let resp = HelloResponse::accepted(
            42,
            AcceptedRoutes {
                routed_domains: vec!["*.example.com".to_string(), "httpbin.org".to_string()],
                routed_cidrs: vec!["10.0.0.0/8".to_string()],
                host_aliases: vec![("nas.internal".to_string(), "192.168.1.9".to_string())],
                dns_forwards: vec![(
                    "corp.example.com".to_string(),
                    vec!["10.1.0.10:5353".to_string()],
                )],
                bridges: vec![BridgeSummary {
                    name: "lab".to_string(),
                    endpoint_id: "endpointid".to_string(),
                    domains: vec!["*.svc".to_string()],
                    cidrs: vec!["fd34::/64".to_string()],
                }],
            },
        );
        let decoded = decode_hello_response(&encode_hello_response(&resp).unwrap()).unwrap();
        assert!(decoded.accepted);
        assert_eq!(decoded.version, PROTOCOL_VERSION);
        assert_eq!(decoded.server_instance_nonce, 42);
        assert_eq!(decoded.routed_domains, vec!["*.example.com", "httpbin.org"]);
        assert_eq!(decoded.routed_cidrs, vec!["10.0.0.0/8"]);
        assert_eq!(
            decoded.host_aliases,
            vec![("nas.internal".to_string(), "192.168.1.9".to_string())]
        );
        assert_eq!(
            decoded.dns_forwards,
            vec![("corp.example.com".to_string(), vec!["10.1.0.10:5353".to_string()])]
        );
        assert_eq!(
            decoded.bridges,
            vec![BridgeSummary {
                name: "lab".to_string(),
                endpoint_id: "endpointid".to_string(),
                domains: vec!["*.svc".to_string()],
                cidrs: vec!["fd34::/64".to_string()],
            }]
        );

        // A rejection carries no routed set but still carries the server nonce.
        let rej = HelloResponse::rejected(7, "nope");
        let decoded = decode_hello_response(&encode_hello_response(&rej).unwrap()).unwrap();
        assert!(!decoded.accepted);
        assert_eq!(decoded.reject_reason.as_deref(), Some("nope"));
        assert_eq!(decoded.server_instance_nonce, 7);
        assert!(decoded.routed_domains.is_empty());
        assert!(decoded.routed_cidrs.is_empty());
        assert!(decoded.host_aliases.is_empty());
        assert!(decoded.dns_forwards.is_empty());
        assert!(decoded.bridges.is_empty());
    }

    #[test]
    fn bridge_hello_roundtrip() {
        let hello = BridgeHello::new();
        let decoded = decode_bridge_hello(&encode_bridge_hello(&hello).unwrap()).unwrap();
        assert_eq!(decoded.version, PROTOCOL_VERSION);

        // A version mismatch is rejected at decode.
        let stale = serde_json::to_vec(&BridgeHello { version: 1 }).unwrap();
        assert!(decode_bridge_hello(&stale).is_err());
    }

    #[test]
    fn control_msg_roundtrip() {
        for msg in [
            ControlMsg::Heartbeat { seq: 1 },
            ControlMsg::HeartbeatAck { seq: u64::MAX },
        ] {
            let decoded = decode_control(&encode_control(&msg).unwrap()).unwrap();
            assert_eq!(decoded, msg);
        }
    }
}
