//! End-to-end duplicate-id detection tests over real (loopback) iroh endpoints.
//!
//! These exercise the *actual* [`ProxyServer`] accept/handshake path — not just
//! the codecs — by binding endpoints to `127.0.0.1:0` with relay + discovery
//! disabled and connecting via a direct address, so they are fully hermetic (no
//! network, no relay, deterministic).
//!
//! They cover both misconfiguration guard rails:
//!
//! * **Duplicate server** — a client advisory makes the server self-block (record
//!   its own id + shut down), and a server refuses to start once its id is
//!   recorded (startup guard, tested via [`crate::blocklist`]).
//! * **Duplicate client** — two client processes sharing one key (same node id)
//!   are detected and the id is blocklisted. Client identity is ephemeral in
//!   production, so a fixed key is injected here — the only way to reproduce a
//!   duplicate client id, exactly as the design intends.

use crate::blocklist::BlockList;
use crate::proxy::signaling::{self, Hello, HelloResponse, Target};
use crate::proxy::dns_forward::DnsForwarder;
use crate::proxy::{
    BridgeUpstream, BridgeUpstreamConfig, ForwardManager, ForwardSpec, ProxyServer,
    ProxyServerParams, RoutedSet, ServerForwarder,
};
use crate::transport::{ALPN, build_quic_transport_config};
use iroh::address_lookup::MemoryLookup;
use iroh::endpoint::{presets, Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const TOKEN: &str = "test-token";
/// A distinct bridge-token string (the server checks pool membership, not the
/// prefix, so any string works as long as the pools differ).
const BRIDGE_TOKEN: &str = "test-bridge-token";

/// Bind a hermetic loopback endpoint: relay off, no discovery, `127.0.0.1:0`.
/// Servers get the ALPN so they can accept; clients only dial.
async fn loopback_endpoint(secret: SecretKey, is_server: bool) -> Endpoint {
    loopback_endpoint_seeded(secret, is_server, Vec::new()).await
}

/// Like [`loopback_endpoint`] but pre-seeded with out-of-band addresses for
/// `peers`, so an id-only dial — as a bridge upstream performs — resolves
/// hermetically (no relay, no discovery).
async fn loopback_endpoint_seeded(
    secret: SecretKey,
    is_server: bool,
    peers: Vec<EndpointAddr>,
) -> Endpoint {
    loopback_endpoint_with_lookup(secret, is_server, MemoryLookup::from_endpoint_info(peers)).await
}

/// Like [`loopback_endpoint_seeded`] with an externally-held [`MemoryLookup`]
/// (Arc-backed), so a test can add peer addresses *after* binding — needed when
/// two endpoints must learn each other's ephemeral addresses.
async fn loopback_endpoint_with_lookup(
    secret: SecretKey,
    is_server: bool,
    lookup: MemoryLookup,
) -> Endpoint {
    let builder = Endpoint::builder(presets::Empty)
        .relay_mode(RelayMode::Disabled)
        .transport_config(build_quic_transport_config().unwrap())
        .crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .secret_key(secret)
        .bind_addr("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .unwrap()
        .address_lookup(lookup);
    let builder = if is_server {
        builder.alpns(vec![ALPN.to_vec()])
    } else {
        builder
    };
    builder.bind().await.unwrap()
}

async fn with_timeout<F: std::future::Future>(f: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(10), f)
        .await
        .expect("operation timed out")
}

/// Spawn a `ProxyServer` on `endpoint` with a single client token, an empty
/// routed set, and the given blocklist path. Returns the server's own id.
fn spawn_server(endpoint: Endpoint, blocklist_path: std::path::PathBuf) -> iroh::EndpointId {
    spawn_server_full(endpoint, blocklist_path, HashMap::new(), Vec::new())
}

/// Spawn a `ProxyServer` with configurable host aliases. Client token is always
/// [`TOKEN`]; `routed_domains` seeds the routed set (empty = deny all). Returns
/// the server's own id.
fn spawn_server_full(
    endpoint: Endpoint,
    blocklist_path: std::path::PathBuf,
    host_aliases: HashMap<String, String>,
    routed_domains: Vec<String>,
) -> iroh::EndpointId {
    spawn_server_dns(endpoint, blocklist_path, host_aliases, routed_domains, HashMap::new())
}

/// Like [`spawn_server_full`] but also seeds the conditional DNS-forwarding
/// table (`[dns_forwards]`), exercised by the status-page test.
fn spawn_server_dns(
    endpoint: Endpoint,
    blocklist_path: std::path::PathBuf,
    host_aliases: HashMap<String, String>,
    routed_domains: Vec<String>,
    dns_forwards: HashMap<String, Vec<String>>,
) -> iroh::EndpointId {
    let own_id = endpoint.id();
    let mut tokens = HashSet::new();
    tokens.insert(TOKEN.to_string());
    let no_cidrs: Vec<String> = Vec::new();
    let dns_forwarder = DnsForwarder::new(&dns_forwards).unwrap();
    let server = ProxyServer::new(ProxyServerParams {
        own_id,
        valid_tokens: tokens,
        bridge_valid_tokens: HashSet::new(),
        allowed_bridge_servers: HashSet::new(),
        host_aliases,
        routed_set: RoutedSet::new(&routed_domains, &no_cidrs).unwrap(),
        routed_domains,
        routed_cidrs: no_cidrs,
        dns_forwarder,
        bridges: Vec::new(),
        blocklist: BlockList::load(blocklist_path).unwrap(),
        first_client: None,
    });
    tokio::spawn(async move {
        // Surface why the server task ended — captured by the test harness and
        // shown on failure, aiding diagnosis. This must NOT panic: a
        // duplicate-server self-block legitimately returns `Err` here (it's the
        // expected outcome of one test), so it's informational, not an assertion.
        if let Err(e) = server.run(&endpoint).await {
            eprintln!("e2e test server task ended: {e}");
        }
    });
    own_id
}

/// Baseline [`ProxyServerParams`]: the [`TOKEN`] client pool and everything
/// else empty/off. Bridge tests override the fields they exercise.
fn base_params(own_id: iroh::EndpointId, blocklist_path: std::path::PathBuf) -> ProxyServerParams {
    ProxyServerParams {
        own_id,
        valid_tokens: HashSet::from([TOKEN.to_string()]),
        bridge_valid_tokens: HashSet::new(),
        allowed_bridge_servers: HashSet::new(),
        host_aliases: HashMap::new(),
        routed_set: RoutedSet::default(),
        routed_domains: Vec::new(),
        routed_cidrs: Vec::new(),
        dns_forwarder: None,
        bridges: Vec::new(),
        blocklist: BlockList::load(blocklist_path).unwrap(),
        first_client: None,
    }
}

/// Spawn a `ProxyServer` built from explicit [`ProxyServerParams`] (the bridge
/// tests need knobs the older helpers don't expose).
fn spawn_server_params(endpoint: Endpoint, params: ProxyServerParams) {
    let server = ProxyServer::new(params);
    tokio::spawn(async move {
        if let Err(e) = server.run(&endpoint).await {
            eprintln!("e2e test server task ended: {e}");
        }
    });
}

/// A routed set (and its raw rules) for all of loopback — what the bridge tests
/// tunnel and bridge.
fn loopback_cidr_set() -> (RoutedSet, Vec<String>) {
    let cidrs = vec!["127.0.0.0/8".to_string()];
    (RoutedSet::new(&[], &cidrs).unwrap(), cidrs)
}

/// An outbound bridge upstream forwarding all of loopback to `target`.
fn loopback_bridge(name: &str, target: iroh::EndpointId) -> Arc<BridgeUpstream> {
    let (routed_set, cidrs) = loopback_cidr_set();
    BridgeUpstream::new(BridgeUpstreamConfig {
        name: name.to_string(),
        endpoint_id: target,
        auth_token: BRIDGE_TOKEN.to_string(),
        relay_urls: Vec::new(),
        routed_set,
        domains: Vec::new(),
        cidrs,
    })
}

/// Poll `pred` until it holds, or panic after 10s.
async fn wait_until(what: &str, pred: impl Fn() -> bool) {
    let start = Instant::now();
    while !pred() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// A tiny loopback echo server: greets "HELLO", then echoes. Returns its port.
async fn spawn_echo() -> u16 {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = echo.accept().await {
            tokio::spawn(async move {
                let _ = sock.write_all(b"HELLO").await;
                let mut buf = [0u8; 256];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    port
}

/// Perform the client side of the auth handshake and return the open control
/// stream + the server's response.
async fn client_handshake(
    ep: &Endpoint,
    server_addr: EndpointAddr,
    nonce: u128,
    duplicate_server_observed: bool,
) -> (Connection, SendStream, RecvStream, HelloResponse) {
    let conn = with_timeout(ep.connect(server_addr, ALPN)).await.unwrap();
    let (mut send, mut recv) = with_timeout(conn.open_bi()).await.unwrap();
    let mut hello = Hello::new(TOKEN, nonce);
    hello.duplicate_server_observed = duplicate_server_observed;
    signaling::write_message(&mut send, &signaling::encode_hello(&hello).unwrap())
        .await
        .unwrap();
    send.flush().await.unwrap();
    let data = with_timeout(signaling::read_message(
        &mut recv,
        signaling::MAX_HANDSHAKE_SIZE,
    ))
    .await
    .unwrap();
    let resp = signaling::decode_hello_response(&data).unwrap();
    (conn, send, recv, resp)
}

/// Perform the bridge side of the auth handshake (`role = Bridge`) and return
/// the open control stream + the server's response.
async fn bridge_handshake(
    ep: &Endpoint,
    server_addr: EndpointAddr,
    token: &str,
    nonce: u128,
) -> (Connection, SendStream, RecvStream, HelloResponse) {
    let conn = with_timeout(ep.connect(server_addr, ALPN)).await.unwrap();
    let (mut send, mut recv) = with_timeout(conn.open_bi()).await.unwrap();
    let hello = Hello::new_bridge(token, nonce);
    signaling::write_message(&mut send, &signaling::encode_hello(&hello).unwrap())
        .await
        .unwrap();
    send.flush().await.unwrap();
    let data = with_timeout(signaling::read_message(
        &mut recv,
        signaling::MAX_HANDSHAKE_SIZE,
    ))
    .await
    .unwrap();
    let resp = signaling::decode_hello_response(&data).unwrap();
    (conn, send, recv, resp)
}

/// Open a tunnel stream to `127.0.0.1:port` through `conn` and assert the echo
/// round-trip ("HELLO" greeting + our echoed bytes) completes.
async fn assert_echo_roundtrip(conn: &Connection, port: u16) {
    let (mut send, mut recv) = with_timeout(conn.open_bi()).await.unwrap();
    let target = Target::Ip(format!("127.0.0.1:{port}").parse().unwrap());
    signaling::write_request(&mut send, &target).await.unwrap();
    send.flush().await.unwrap();
    let rep = with_timeout(signaling::read_reply(&mut recv)).await.unwrap();
    assert_eq!(rep, signaling::REP_SUCCESS, "tunnel stream should connect");
    send.write_all(b"ping").await.unwrap();
    send.flush().await.unwrap();
    let mut buf = [0u8; 9]; // "HELLO" + "ping"
    with_timeout(recv.read_exact(&mut buf)).await.unwrap();
    assert_eq!(&buf, b"HELLOping");
}

/// Port forwards bypass the local proxy front-ends: the listener hands an
/// accepted TCP stream straight to a QUIC data stream. The same server rejects
/// a target outside its routed-set whitelist before attempting to dial it.
#[tokio::test]
async fn server_direct_forward_relays_and_server_rejects_off_list_target() {
    let bl_path = temp_blocklist("server-direct-forward");
    let server_ep = loopback_endpoint(SecretKey::generate(), true).await;
    let server_addr = EndpointAddr::new(server_ep.id()).with_ip_addr(server_ep.bound_sockets()[0]);
    let (routed_set, routed_cidrs) = loopback_cidr_set();
    let params = ProxyServerParams {
        routed_set,
        routed_cidrs,
        ..base_params(server_ep.id(), bl_path.clone())
    };
    spawn_server_params(server_ep, params);

    let client_ep = loopback_endpoint(SecretKey::generate(), false).await;
    let (conn, _ctrl_send, _ctrl_recv, response) =
        client_handshake(&client_ep, server_addr, 41, false).await;
    assert!(response.accepted);
    let forwarder = ServerForwarder::connected(conn);

    let rejected = forwarder
        .connect(&Target::Domain("off-list.invalid".into(), 443))
        .await
        .unwrap_err();
    assert!(
        rejected.to_string().contains("not allowed"),
        "unexpected rejection: {rejected:#}"
    );

    let echo_port = spawn_echo().await;
    let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_port = probe.local_addr().unwrap().port();
    drop(probe);
    let manager = ForwardManager::new(
        tokio::runtime::Handle::current(),
        forwarder,
        &[ForwardSpec {
            id: "echo".into(),
            local_port,
            target: Target::Ip(format!("127.0.0.1:{echo_port}").parse().unwrap()),
        }],
    );

    let mut local = None;
    for _ in 0..50 {
        match tokio::net::TcpStream::connect(("127.0.0.1", local_port)).await {
            Ok(stream) => {
                local = Some(stream);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    let mut local = local.expect("direct forward listener reachable");
    let mut greeting = [0u8; 5];
    with_timeout(local.read_exact(&mut greeting)).await.unwrap();
    assert_eq!(&greeting, b"HELLO");
    local.write_all(b"ping").await.unwrap();
    let mut echoed = [0u8; 4];
    with_timeout(local.read_exact(&mut echoed)).await.unwrap();
    assert_eq!(&echoed, b"ping");
    assert_eq!(manager.statuses()[0].active, 1);

    drop(manager);
    let _ = std::fs::remove_file(bl_path);
}

fn temp_blocklist(tag: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "flextunnel-e2e-{tag}-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    path
}

/// Poll the persisted blocklist until `pred` holds, or panic after a timeout.
/// Replaces a fixed sleep so the persistence check waits for the server's write
/// instead of assuming a fixed delay is enough (which flakes under load).
async fn wait_for_blocklist(path: &std::path::Path, pred: impl Fn(&BlockList) -> bool) {
    let start = Instant::now();
    let deadline = Duration::from_secs(5);
    loop {
        if let Ok(bl) = BlockList::load(path.to_path_buf())
            && pred(&bl)
        {
            return;
        }
        assert!(
            start.elapsed() < deadline,
            "blocklist at {} did not reach the expected state within {deadline:?}",
            path.display()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Two clients sharing one key (same node id) with different instance nonces are
/// a confirmed duplicate: the id is blocklisted and the second is rejected.
#[tokio::test]
async fn duplicate_client_is_detected_and_blocklisted() {
    let bl_path = temp_blocklist("dupclient");

    let server_ep = loopback_endpoint(SecretKey::generate(), true).await;
    let server_addr = EndpointAddr::new(server_ep.id()).with_ip_addr(server_ep.bound_sockets()[0]);
    spawn_server(server_ep, bl_path.clone());

    // Two client processes sharing one secret → identical node id.
    let client_secret = SecretKey::generate();
    let ep1 = loopback_endpoint(client_secret.clone(), false).await;
    let ep2 = loopback_endpoint(client_secret, false).await;
    let client_id = ep1.id();

    // First client authenticates and stays live (held in scope).
    let (_conn1, _s1, _r1, resp1) = client_handshake(&ep1, server_addr.clone(), 1, false).await;
    assert!(resp1.accepted, "first client should be accepted");

    // Second client, same node id but a different instance nonce → duplicate.
    let (_conn2, _s2, _r2, resp2) = client_handshake(&ep2, server_addr.clone(), 2, false).await;
    assert!(!resp2.accepted, "duplicate client must be rejected");
    assert!(
        resp2
            .reject_reason
            .as_deref()
            .unwrap_or_default()
            .contains("duplicate"),
        "reject reason should mention duplicate: {:?}",
        resp2.reject_reason
    );

    // The server persisted the offending node id to the blocklist. Poll rather
    // than assume a fixed delay is enough (avoids flaking under load).
    wait_for_blocklist(&bl_path, |bl| bl.is_client_blocked(&client_id.to_string())).await;

    let _ = std::fs::remove_file(&bl_path);
}

/// A client advisory (`duplicate_server_observed`) makes the server self-block:
/// it records its own id in the blocklist and stops.
#[tokio::test]
async fn server_self_blocks_on_duplicate_advisory() {
    let bl_path = temp_blocklist("selfblock");

    let server_ep = loopback_endpoint(SecretKey::generate(), true).await;
    let server_addr = EndpointAddr::new(server_ep.id()).with_ip_addr(server_ep.bound_sockets()[0]);
    let own_id = spawn_server(server_ep, bl_path.clone());

    let client_ep = loopback_endpoint(SecretKey::generate(), false).await;
    let (_conn, _s, _r, resp) = client_handshake(&client_ep, server_addr, 9, true).await;
    assert!(!resp.accepted, "self-blocking server should reject the connection");

    // The server recorded its own id as conflicted. Poll rather than assume a
    // fixed delay is enough (avoids flaking under load).
    wait_for_blocklist(&bl_path, |bl| bl.is_server_conflicted(&own_id.to_string())).await;

    let _ = std::fs::remove_file(&bl_path);
}

/// The routed-set whitelist is enforced on the *requested* hostname before any
/// alias resolution, so a `*.web.internal` host alias whose subdomain was
/// never added to the routed set does NOT smuggle an off-list host past the
/// gate. The same request, once the wildcard is on the routed set, resolves
/// through the alias to the server's loopback and pipes bytes.
#[tokio::test]
async fn wildcard_host_alias_still_requires_routed_set_coverage() {
    // The alias rewrites to loopback; this echo server is the on-list dial target.
    let echo_port = spawn_echo().await;
    let host_aliases = HashMap::from([("*.web.internal".to_string(), "127.0.0.1".to_string())]);

    // --- Off-list: the alias exists, but the routed set does not cover it. ---
    let server_ep = loopback_endpoint(SecretKey::generate(), true).await;
    let server_addr = EndpointAddr::new(server_ep.id()).with_ip_addr(server_ep.bound_sockets()[0]);
    spawn_server_full(
        server_ep,
        temp_blocklist("wildcard-alias-offlist"),
        host_aliases.clone(),
        // Covers a different name — `*.web.internal` is deliberately absent.
        vec!["allowed.example.com".to_string()],
    );

    let client_ep = loopback_endpoint(SecretKey::generate(), false).await;
    let (conn, _cs, _cr, resp) = client_handshake(&client_ep, server_addr, 61, false).await;
    assert!(resp.accepted, "client should be accepted");

    let (mut send, mut recv) = with_timeout(conn.open_bi()).await.unwrap();
    signaling::write_request(&mut send, &Target::Domain("db.web.internal".to_string(), echo_port))
        .await
        .unwrap();
    send.flush().await.unwrap();
    let rep = with_timeout(signaling::read_reply(&mut recv)).await.unwrap();
    assert_eq!(
        rep,
        signaling::REP_NOT_ALLOWED,
        "off-list wildcard-aliased host must be rejected by the whitelist before aliasing"
    );

    // --- On-list: add the wildcard to the routed set; the alias now resolves. ---
    let server_ep2 = loopback_endpoint(SecretKey::generate(), true).await;
    let server_addr2 =
        EndpointAddr::new(server_ep2.id()).with_ip_addr(server_ep2.bound_sockets()[0]);
    spawn_server_full(
        server_ep2,
        temp_blocklist("wildcard-alias-onlist"),
        host_aliases,
        vec!["*.web.internal".to_string()],
    );

    let client_ep2 = loopback_endpoint(SecretKey::generate(), false).await;
    let (conn2, _cs2, _cr2, resp2) = client_handshake(&client_ep2, server_addr2, 62, false).await;
    assert!(resp2.accepted, "client should be accepted");

    let (mut send2, mut recv2) = with_timeout(conn2.open_bi()).await.unwrap();
    signaling::write_request(
        &mut send2,
        &Target::Domain("db.web.internal".to_string(), echo_port),
    )
    .await
    .unwrap();
    send2.flush().await.unwrap();
    let rep2 = with_timeout(signaling::read_reply(&mut recv2)).await.unwrap();
    assert_eq!(
        rep2,
        signaling::REP_SUCCESS,
        "on-list wildcard alias should resolve to the server's loopback"
    );
    // Round-trip through the aliased loopback echo server: greeting + echo.
    send2.write_all(b"ping").await.unwrap();
    send2.flush().await.unwrap();
    let mut buf = [0u8; 9]; // "HELLO" + "ping"
    with_timeout(recv2.read_exact(&mut buf)).await.unwrap();
    assert_eq!(&buf, b"HELLOping");
}

/// End-to-end reserved namespace: a request for `flextunnel.internal` is served
/// by the server itself as an HTTP status page (bypassing the routed-set
/// whitelist — note the routed set here does NOT contain it), and a
/// `*.flextunnel.internal` subdomain returns an HTTP 404.
#[tokio::test]
async fn reserved_internal_serves_status_page_and_subdomain_404() {
    let server_ep = loopback_endpoint(SecretKey::generate(), true).await;
    let server_addr = EndpointAddr::new(server_ep.id()).with_ip_addr(server_ep.bound_sockets()[0]);
    // A distinctive routed domain we expect to see rendered on the status page.
    // `flextunnel.internal` is deliberately NOT on the routed set.
    let host_aliases =
        HashMap::from([("nas.internal".to_string(), "192.168.1.9".to_string())]);
    // Two conditional DNS forwards we expect rendered on the status page and
    // pushed to the client (each suffix must be reachable through the routed
    // set). `corp.example.com` carries two servers in a deliberate, non-sorted
    // order; the server must emit the suffixes sorted (`corp` before `marker`)
    // while preserving each suffix's server order verbatim — exercised through
    // every serialization path below.
    let dns_forwards = HashMap::from([
        (
            "marker.example.com".to_string(),
            vec!["10.9.9.9:5353".to_string()],
        ),
        (
            "corp.example.com".to_string(),
            vec!["10.1.0.11".to_string(), "10.1.0.10:5353".to_string()],
        ),
    ]);
    spawn_server_dns(
        server_ep,
        temp_blocklist("reserved"),
        host_aliases,
        vec!["marker.example.com".to_string(), "corp.example.com".to_string()],
        dns_forwards,
    );

    let client_ep = loopback_endpoint(SecretKey::generate(), false).await;
    let (client_conn, _cs, _cr, cresp) =
        client_handshake(&client_ep, server_addr, 1, false).await;
    assert!(cresp.accepted, "client should be accepted");
    assert_eq!(
        cresp.host_aliases,
        vec![("nas.internal".to_string(), "192.168.1.9".to_string())],
        "handshake should push the configured host aliases for client status UIs"
    );
    assert_eq!(
        cresp.dns_forwards,
        vec![
            (
                "corp.example.com".to_string(),
                vec!["10.1.0.11".to_string(), "10.1.0.10:5353".to_string()]
            ),
            (
                "marker.example.com".to_string(),
                vec!["10.9.9.9:5353".to_string()]
            ),
        ],
        "handshake should push DNS forwards sorted by suffix, each suffix's servers verbatim"
    );

    // The status host: expect an HTTP 200 whose body contains the routed domain.
    let body = fetch_reserved(&client_conn, "flextunnel.internal").await;
    assert!(body.starts_with("HTTP/1.1 200"), "status page should be 200: {body:.40}");
    assert!(
        body.contains("marker.example.com"),
        "status page should list the configured routed domain"
    );
    assert!(
        body.contains("10.9.9.9:5353"),
        "status page should list the configured DNS forward server"
    );
    assert!(
        body.contains("10.1.0.11, 10.1.0.10:5353"),
        "status page should list the multi-server forward with servers in verbatim order"
    );
    assert!(
        body.find("10.1.0.11").unwrap() < body.find("10.9.9.9:5353").unwrap(),
        "status page should render DNS forwards sorted by suffix (corp before marker)"
    );

    let body = fetch_reserved_path(&client_conn, "flextunnel.internal", "/status.txt").await;
    assert!(body.starts_with("HTTP/1.1 200"), "text status should be 200: {body:.40}");
    assert!(
        body.contains("Content-Type: text/plain; charset=utf-8"),
        "text status should use text/plain"
    );
    assert!(
        body.contains("flextunnel server status"),
        "text status should include a plain heading"
    );
    assert!(
        body.contains("  - nas.internal -> 192.168.1.9"),
        "text status should show the configured host alias"
    );
    assert!(
        body.contains("  - marker.example.com (+ subdomains) -> 10.9.9.9:5353"),
        "text status should show the configured DNS forward"
    );
    assert!(
        body.contains("  - corp.example.com (+ subdomains) -> 10.1.0.11, 10.1.0.10:5353"),
        "text status should show the multi-server forward with servers in verbatim order"
    );
    assert!(
        body.find("  - corp.example.com (+ subdomains) -> 10.1.0.11").unwrap()
            < body.find("  - marker.example.com (+ subdomains) -> 10.9.9.9:5353").unwrap(),
        "text status should render DNS forwards sorted by suffix (corp before marker)"
    );

    let body = fetch_reserved_path(&client_conn, "flextunnel.internal", "/status.json").await;
    assert!(body.starts_with("HTTP/1.1 200"), "json status should be 200: {body:.40}");
    assert!(
        body.contains("Content-Type: application/json; charset=utf-8"),
        "json status should use application/json"
    );
    let json_body = body
        .split_once("\r\n\r\n")
        .expect("json status response should include headers")
        .1;
    let status: serde_json::Value =
        serde_json::from_str(json_body).expect("json status body should parse");
    assert_eq!(
        status["routed_domains"],
        serde_json::json!(["marker.example.com", "corp.example.com"]),
        "json status should list the configured routed domains"
    );
    assert_eq!(
        status["host_aliases"],
        serde_json::json!([{"name": "nas.internal", "target": "192.168.1.9"}]),
        "json status should list the configured host alias"
    );
    assert_eq!(
        status["dns_forwards"],
        serde_json::json!([
            {"suffix": "corp.example.com", "servers": ["10.1.0.11", "10.1.0.10:5353"]},
            {"suffix": "marker.example.com", "servers": ["10.9.9.9:5353"]},
        ]),
        "json status should list the DNS forwards sorted by suffix, servers verbatim"
    );

    // Accept-header negotiation: a `/` request with `Accept: text/plain` should
    // also return the plain-text status response (not the HTML page).
    let body = fetch_reserved_accept(&client_conn, "flextunnel.internal", "/", "text/plain").await;
    assert!(body.starts_with("HTTP/1.1 200"), "accept-text status should be 200: {body:.40}");
    assert!(
        body.contains("Content-Type: text/plain; charset=utf-8"),
        "accept-text status should use text/plain"
    );
    assert!(
        body.contains("flextunnel server status"),
        "accept-text status should include a plain heading"
    );

    // A reserved subdomain: expect an HTTP 404 "reserved" page.
    let body = fetch_reserved(&client_conn, "sub.flextunnel.internal").await;
    assert!(body.starts_with("HTTP/1.1 404"), "reserved subdomain should be 404: {body:.40}");

    drop(client_conn);
}

/// Open a tunnel stream for `host:80`, send a minimal HTTP request, and return
/// the full response after consuming the per-stream success reply byte.
async fn fetch_reserved(conn: &Connection, host: &str) -> String {
    fetch_reserved_path(conn, host, "/").await
}

async fn fetch_reserved_path(conn: &Connection, host: &str, path: &str) -> String {
    fetch_reserved_request(conn, host, path, None).await
}

/// Like [`fetch_reserved_path`] but with an optional `Accept` header, so the
/// Accept-based text negotiation path can be exercised (a `/` request with
/// `Accept: text/plain` should return the plain-text status response).
async fn fetch_reserved_accept(conn: &Connection, host: &str, path: &str, accept: &str) -> String {
    fetch_reserved_request(conn, host, path, Some(accept)).await
}

async fn fetch_reserved_request(
    conn: &Connection,
    host: &str,
    path: &str,
    accept: Option<&str>,
) -> String {
    let (mut send, mut recv) = with_timeout(conn.open_bi()).await.unwrap();
    signaling::write_request(&mut send, &Target::Domain(host.to_string(), 80))
        .await
        .unwrap();
    send.flush().await.unwrap();
    let rep = with_timeout(signaling::read_reply(&mut recv)).await.unwrap();
    assert_eq!(rep, signaling::REP_SUCCESS, "reserved host should reply success");
    let accept_header = accept.map(|a| format!("Accept: {a}\r\n")).unwrap_or_default();
    let _ = send
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n{accept_header}\r\n").as_bytes(),
        )
        .await;
    let _ = send.finish();
    let bytes = with_timeout(recv.read_to_end(64 * 1024)).await.unwrap();
    String::from_utf8(bytes).unwrap()
}

/// End-to-end bridge routing: a client stream whose target matches server A's
/// bridge rules is spliced over A's persistent upstream connection to server B,
/// which dials the target from its own network; bytes round-trip. Also asserts
/// the informational surfaces: the handshake's bridge summaries, A's outbound
/// bridge status (connected), and B's inbound allowlist status (connected).
#[tokio::test]
async fn bridge_routes_pipe_through_target_server() {
    let echo_port = spawn_echo().await;
    let (routed_set, cidrs) = loopback_cidr_set();

    // Server B (target): allows bridging from A, dials loopback locally.
    let b_ep = loopback_endpoint(SecretKey::generate(), true).await;
    let b_id = b_ep.id();
    let b_addr = EndpointAddr::new(b_id).with_ip_addr(b_ep.bound_sockets()[0]);

    // Server A (bridging): seeded with B's direct address so its id-only
    // upstream dial resolves hermetically.
    let a_ep = loopback_endpoint_seeded(SecretKey::generate(), true, vec![b_addr.clone()]).await;
    let a_id = a_ep.id();
    let a_addr = EndpointAddr::new(a_id).with_ip_addr(a_ep.bound_sockets()[0]);

    let mut b_params = base_params(b_id, temp_blocklist("bridgetarget"));
    b_params.routed_set = routed_set.clone();
    b_params.routed_cidrs = cidrs.clone();
    b_params.allowed_bridge_servers = HashSet::from([a_id]);
    b_params.bridge_valid_tokens = HashSet::from([BRIDGE_TOKEN.to_string()]);
    spawn_server_params(b_ep, b_params);

    let bridge = loopback_bridge("lab", b_id);
    let mut a_params = base_params(a_id, temp_blocklist("bridgesource"));
    a_params.routed_set = routed_set;
    a_params.routed_cidrs = cidrs;
    a_params.bridges = vec![bridge.clone()];
    spawn_server_params(a_ep, a_params);

    // The upstream is established in the background; wait for it.
    wait_until("bridge upstream to connect", || bridge.is_connected()).await;

    // Client → A: the loopback target matches A's bridge rules → routed via B.
    let client_ep = loopback_endpoint(SecretKey::generate(), false).await;
    let (client_conn, _cs, _cr, cresp) = client_handshake(&client_ep, a_addr, 1, false).await;
    assert!(cresp.accepted, "client should be accepted");
    let summaries = cresp.bridges;
    assert_eq!(summaries.len(), 1, "handshake should push the bridge summary");
    assert_eq!(summaries[0].name, "lab");
    assert_eq!(summaries[0].endpoint_id, b_id.to_string());
    assert_eq!(summaries[0].cidrs, vec!["127.0.0.0/8".to_string()]);

    assert_echo_roundtrip(&client_conn, echo_port).await;

    // A's status page shows the outbound bridge as connected.
    let body = fetch_reserved_path(&client_conn, "flextunnel.internal", "/status.json").await;
    let json_body = body.split_once("\r\n\r\n").expect("headers").1;
    let status: serde_json::Value = serde_json::from_str(json_body).expect("json status parses");
    assert_eq!(
        status["bridges"],
        serde_json::json!([{
            "name": "lab",
            "endpoint_id": b_id.to_string(),
            "domains": [],
            "cidrs": ["127.0.0.0/8"],
            "connected": true,
        }]),
        "A's json status should show the connected outbound bridge"
    );
    let html = fetch_reserved(&client_conn, "flextunnel.internal").await;
    assert!(html.contains("lab"), "A's status page should name the bridge");
    assert!(
        html.contains(&b_id.to_string()),
        "A's status page should show the bridge target's endpoint id"
    );

    // B's status page shows the allowlisted inbound bridge as connected.
    let b_client_ep = loopback_endpoint(SecretKey::generate(), false).await;
    let (b_client_conn, _bs, _br, bresp) = client_handshake(&b_client_ep, b_addr, 2, false).await;
    assert!(bresp.accepted, "client should be accepted by B");
    let body = fetch_reserved_path(&b_client_conn, "flextunnel.internal", "/status.json").await;
    let json_body = body.split_once("\r\n\r\n").expect("headers").1;
    let status: serde_json::Value = serde_json::from_str(json_body).expect("json status parses");
    assert_eq!(
        status["inbound_bridges"],
        serde_json::json!([{ "endpoint_id": a_id.to_string(), "connected": true }]),
        "B's json status should show the allowlisted inbound bridge as connected"
    );

    drop(client_conn);
    drop(b_client_conn);
}

/// Inbound bridge gating: every gate must pass — the endpoint-id allowlist, the
/// `ftb` token pool, and bridging being enabled at all (non-empty allowlist).
#[tokio::test]
async fn bridge_rejected_without_allowlist_or_token() {
    // Case 1: token valid, id not allowlisted (allowlist names someone else).
    let ep1 = loopback_endpoint(SecretKey::generate(), true).await;
    let addr1 = EndpointAddr::new(ep1.id()).with_ip_addr(ep1.bound_sockets()[0]);
    let mut p1 = base_params(ep1.id(), temp_blocklist("bridgerej1"));
    p1.allowed_bridge_servers = HashSet::from([SecretKey::generate().public()]);
    p1.bridge_valid_tokens = HashSet::from([BRIDGE_TOKEN.to_string()]);
    spawn_server_params(ep1, p1);
    let dialer = loopback_endpoint(SecretKey::generate(), false).await;
    let (_c, _s, _r, resp) = bridge_handshake(&dialer, addr1, BRIDGE_TOKEN, 1).await;
    assert!(!resp.accepted, "an unlisted bridge id must be rejected");
    assert!(
        resp.reject_reason.as_deref().unwrap_or_default().contains("allowlist"),
        "reject reason should mention the allowlist: {:?}",
        resp.reject_reason
    );

    // Case 2: id allowlisted, wrong token.
    let dialer2 = loopback_endpoint(SecretKey::generate(), false).await;
    let ep2 = loopback_endpoint(SecretKey::generate(), true).await;
    let addr2 = EndpointAddr::new(ep2.id()).with_ip_addr(ep2.bound_sockets()[0]);
    let mut p2 = base_params(ep2.id(), temp_blocklist("bridgerej2"));
    p2.allowed_bridge_servers = HashSet::from([dialer2.id()]);
    p2.bridge_valid_tokens = HashSet::from([BRIDGE_TOKEN.to_string()]);
    spawn_server_params(ep2, p2);
    let (_c, _s, _r, resp) = bridge_handshake(&dialer2, addr2, "wrong-token", 2).await;
    assert!(!resp.accepted, "a wrong bridge token must be rejected");
    assert!(
        resp.reject_reason.as_deref().unwrap_or_default().contains("token"),
        "reject reason should mention the token: {:?}",
        resp.reject_reason
    );

    // Case 3: bridging not enabled (empty allowlist) — even a token that IS in
    // the pool is rejected up front, proving the enabled-at-all gate runs
    // before token validation. (The CLI refuses tokens-without-allowlist as
    // dead config, but the server layer must still gate on the allowlist.)
    let dialer3 = loopback_endpoint(SecretKey::generate(), false).await;
    let ep3 = loopback_endpoint(SecretKey::generate(), true).await;
    let addr3 = EndpointAddr::new(ep3.id()).with_ip_addr(ep3.bound_sockets()[0]);
    let mut p3 = base_params(ep3.id(), temp_blocklist("bridgerej3"));
    p3.bridge_valid_tokens = HashSet::from([BRIDGE_TOKEN.to_string()]);
    spawn_server_params(ep3, p3);
    let (_c, _s, _r, resp) = bridge_handshake(&dialer3, addr3, BRIDGE_TOKEN, 3).await;
    assert!(!resp.accepted, "bridging must be off with an empty allowlist");
    assert!(
        resp.reject_reason.as_deref().unwrap_or_default().contains("not enabled"),
        "reject reason should say bridging is not enabled: {:?}",
        resp.reject_reason
    );
}

/// Single hop: two servers bridging the same range at each other must not
/// forward in a loop. A stream bridged A→B is flagged `from_bridge` on B, so B
/// dials it locally instead of re-bridging it back to A — without the guard
/// this request would ping-pong forever and time out.
#[tokio::test]
async fn bridged_stream_is_never_rebridged() {
    let echo_port = spawn_echo().await;
    let (routed_set, cidrs) = loopback_cidr_set();

    // Each server must learn the other's ephemeral address, so bind both with
    // shared-handle lookups and seed them after binding.
    let a_lookup = MemoryLookup::new();
    let b_lookup = MemoryLookup::new();
    let a_ep = loopback_endpoint_with_lookup(SecretKey::generate(), true, a_lookup.clone()).await;
    let b_ep = loopback_endpoint_with_lookup(SecretKey::generate(), true, b_lookup.clone()).await;
    let a_id = a_ep.id();
    let b_id = b_ep.id();
    let a_addr = EndpointAddr::new(a_id).with_ip_addr(a_ep.bound_sockets()[0]);
    let b_addr = EndpointAddr::new(b_id).with_ip_addr(b_ep.bound_sockets()[0]);
    a_lookup.add_endpoint_info(b_addr);
    b_lookup.add_endpoint_info(a_addr.clone());

    let bridge_a_to_b = loopback_bridge("to-b", b_id);
    let mut a_params = base_params(a_id, temp_blocklist("rebridge-a"));
    a_params.routed_set = routed_set.clone();
    a_params.routed_cidrs = cidrs.clone();
    a_params.bridges = vec![bridge_a_to_b.clone()];
    a_params.allowed_bridge_servers = HashSet::from([b_id]);
    a_params.bridge_valid_tokens = HashSet::from([BRIDGE_TOKEN.to_string()]);
    spawn_server_params(a_ep, a_params);

    let bridge_b_to_a = loopback_bridge("to-a", a_id);
    let mut b_params = base_params(b_id, temp_blocklist("rebridge-b"));
    b_params.routed_set = routed_set;
    b_params.routed_cidrs = cidrs;
    b_params.bridges = vec![bridge_b_to_a.clone()];
    b_params.allowed_bridge_servers = HashSet::from([a_id]);
    b_params.bridge_valid_tokens = HashSet::from([BRIDGE_TOKEN.to_string()]);
    spawn_server_params(b_ep, b_params);

    // Both upstreams live: the loop is armed if re-bridging were possible.
    wait_until("A→B bridge to connect", || bridge_a_to_b.is_connected()).await;
    wait_until("B→A bridge to connect", || bridge_b_to_a.is_connected()).await;

    // Client → A → (bridge) → B → local dial. Success proves B did not
    // re-bridge the stream back to A.
    let client_ep = loopback_endpoint(SecretKey::generate(), false).await;
    let (client_conn, _cs, _cr, cresp) = client_handshake(&client_ep, a_addr, 1, false).await;
    assert!(cresp.accepted, "client should be accepted");
    assert_echo_roundtrip(&client_conn, echo_port).await;
}

/// A matching request while the bridge upstream is down (target server never
/// existed/bound) fails fast with host-unreachable instead of hanging.
#[tokio::test]
async fn bridge_down_returns_host_unreachable() {
    let (routed_set, cidrs) = loopback_cidr_set();

    let a_ep = loopback_endpoint(SecretKey::generate(), true).await;
    let a_id = a_ep.id();
    let a_addr = EndpointAddr::new(a_id).with_ip_addr(a_ep.bound_sockets()[0]);

    // The bridge target is a generated identity that is never bound anywhere.
    let bridge = loopback_bridge("ghost", SecretKey::generate().public());
    let mut a_params = base_params(a_id, temp_blocklist("bridgedown"));
    a_params.routed_set = routed_set;
    a_params.routed_cidrs = cidrs;
    a_params.bridges = vec![bridge];
    spawn_server_params(a_ep, a_params);

    let client_ep = loopback_endpoint(SecretKey::generate(), false).await;
    let (client_conn, _cs, _cr, cresp) = client_handshake(&client_ep, a_addr, 1, false).await;
    assert!(cresp.accepted, "client should be accepted");

    let (mut send, mut recv) = with_timeout(client_conn.open_bi()).await.unwrap();
    signaling::write_request(&mut send, &Target::Ip("127.0.0.1:9999".parse().unwrap()))
        .await
        .unwrap();
    send.flush().await.unwrap();
    let rep = with_timeout(signaling::read_reply(&mut recv)).await.unwrap();
    assert_eq!(
        rep,
        signaling::REP_HOST_UNREACHABLE,
        "a down bridge should fail fast with host-unreachable"
    );
}

/// The startup guard: a server whose own id is already recorded as conflicted
/// must be refused. (The CLI performs the same check in `run_server`; here we
/// assert the underlying predicate the guard relies on.)
#[tokio::test]
async fn startup_guard_recognizes_conflicted_own_id() {
    let bl_path = temp_blocklist("startupguard");

    let secret = SecretKey::generate();
    let own_id = secret.public();

    let mut bl = BlockList::load(bl_path.clone()).unwrap();
    assert!(!bl.is_server_conflicted(&own_id.to_string()));
    bl.add_conflicted_server(&own_id.to_string(), "test");
    crate::blocklist::write_atomic(bl.path(), &bl.to_json().unwrap()).unwrap();

    // A fresh load (as the CLI does at startup) sees the conflict and would bail.
    let reloaded = BlockList::load(bl_path.clone()).unwrap();
    assert!(reloaded.is_server_conflicted(&own_id.to_string()));

    let _ = std::fs::remove_file(&bl_path);
}
