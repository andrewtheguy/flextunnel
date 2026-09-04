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
use crate::proxy::signaling::{self, BridgeHello, Hello, HelloResponse, Target};
use crate::proxy::dns_forward::DnsForwarder;
use crate::proxy::{
    BridgeUpstream, BridgeUpstreamConfig, ClientAuth, ClientConfig, ForwardManager, ForwardSpec,
    ProxyClient, ProxyServer, ProxyServerParams, RoutedSet, ServerForwarder,
};
use crate::transport::endpoint::{AllowlistHook, ClientEndpoint, EndpointAllowlists};
use crate::transport::{ALPN, BRIDGE_ALPN, QUICK_ALPN, build_quic_transport_config};
use iroh::address_lookup::MemoryLookup;
use iroh::endpoint::{presets, Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The one authorized client keypair shared by the tests: servers authorize
/// its public half, clients sign their handshakes with it.
fn test_client_key() -> &'static crate::auth::ClientKey {
    static KEY: std::sync::OnceLock<crate::auth::ClientKey> = std::sync::OnceLock::new();
    KEY.get_or_init(|| crate::auth::ClientKey::generate().unwrap())
}

/// An authorized-keys set holding only [`test_client_key`]'s public half.
fn test_authorized_keys() -> crate::auth::AuthorizedKeys {
    flexaccess_keys::parse_authorized_key_entries(
        &[test_client_key().public_str()],
        "e2e_tests",
    )
    .unwrap()
}

/// A valid signed auth payload for `ep` (binding its own endpoint id), signed
/// with [`test_client_key`].
fn test_auth_payload(ep: &Endpoint) -> signaling::ClientAuthPayload {
    signaling::ClientAuthPayload {
        public_key: test_client_key().public_str(),
        endpoint_id: ep.id().to_string(),
        signature: crate::auth::sign_endpoint_id(test_client_key(), &ep.id()),
    }
}

/// Bind a hermetic loopback endpoint: relay off, no discovery, `127.0.0.1:0`.
/// Servers get the ALPNs so they can accept (with the allowlisted paths —
/// inbound bridging and quick clients — disabled: the hook gets empty sets);
/// clients only dial.
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
    loopback_endpoint_full(
        secret,
        is_server,
        MemoryLookup::from_endpoint_info(peers),
        EndpointAllowlists::default(),
    )
    .await
}

/// The full-knob loopback endpoint: servers accept all three ALPNs and install
/// the native allowlist hook over `allowlists` (mirroring
/// `create_server_endpoint`); clients only dial. The externally-held
/// [`MemoryLookup`] (Arc-backed) lets a test add peer addresses *after*
/// binding — needed when two endpoints must learn each other's ephemeral
/// addresses.
async fn loopback_endpoint_full(
    secret: SecretKey,
    is_server: bool,
    lookup: MemoryLookup,
    allowlists: EndpointAllowlists,
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
        builder
            .alpns(vec![ALPN.to_vec(), BRIDGE_ALPN.to_vec(), QUICK_ALPN.to_vec()])
            .hooks(AllowlistHook::new(allowlists))
    } else {
        builder
    };
    builder.bind().await.unwrap()
}

/// [`EndpointAllowlists`] with only the bridge set populated.
fn bridge_allowlist(ids: impl IntoIterator<Item = EndpointId>) -> EndpointAllowlists {
    EndpointAllowlists {
        bridge_servers: ids.into_iter().collect(),
        quick_clients: HashSet::new(),
    }
}

async fn with_timeout<F: std::future::Future>(f: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(10), f)
        .await
        .expect("operation timed out")
}

/// Spawn a `ProxyServer` on `endpoint` with a single authorized client key, an empty
/// routed set, and the given blocklist path. Returns the server's own id.
fn spawn_server(endpoint: Endpoint, blocklist_path: std::path::PathBuf) -> iroh::EndpointId {
    spawn_server_full(endpoint, blocklist_path, HashMap::new(), Vec::new())
}

/// Spawn a `ProxyServer` with configurable host aliases. The authorized client
/// key is always [`test_client_key`]; `routed_domains` seeds the routed set
/// (empty = deny all). Returns
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
    let no_cidrs: Vec<String> = Vec::new();
    let dns_forwarder = DnsForwarder::new(&dns_forwards).unwrap();
    let server = ProxyServer::new(ProxyServerParams {
        own_id,
        authorized_keys: test_authorized_keys(),
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

/// Baseline [`ProxyServerParams`]: the [`test_client_key`] authorized and
/// everything else empty/off. Bridge tests override the fields they exercise.
fn base_params(own_id: iroh::EndpointId, blocklist_path: std::path::PathBuf) -> ProxyServerParams {
    ProxyServerParams {
        own_id,
        authorized_keys: test_authorized_keys(),
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
fn loopback_bridge(name: &str, target: EndpointId) -> Arc<BridgeUpstream> {
    let (routed_set, cidrs) = loopback_cidr_set();
    BridgeUpstream::new(BridgeUpstreamConfig {
        name: name.to_string(),
        endpoint_id: target,
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
    handshake_on_alpn(ep, server_addr, ALPN, nonce, duplicate_server_observed).await
}

/// [`client_handshake`] on an explicit ALPN. The `Hello` carries a
/// [`test_client_key`]-signed credential on the client ALPN and no credential
/// on the quick ALPN, matching production.
async fn handshake_on_alpn(
    ep: &Endpoint,
    server_addr: EndpointAddr,
    alpn: &[u8],
    nonce: u128,
    duplicate_server_observed: bool,
) -> (Connection, SendStream, RecvStream, HelloResponse) {
    let auth = (alpn == ALPN).then(|| test_auth_payload(ep));
    let conn = with_timeout(ep.connect(server_addr, alpn)).await.unwrap();
    let (mut send, mut recv) = with_timeout(conn.open_bi()).await.unwrap();
    let mut hello = Hello::new(auth, nonce);
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

/// Dial `server_addr` on the bridge ALPN and assert the native allowlist hook
/// rejects it (see [`assert_rejected_by_allowlist`]).
async fn assert_bridge_rejected(ep: &Endpoint, server_addr: EndpointAddr, reason: &str) {
    let hello = signaling::encode_bridge_hello(&BridgeHello::new()).unwrap();
    assert_rejected_by_allowlist(ep, server_addr, BRIDGE_ALPN, hello, reason).await;
}

/// Dial `server_addr` on the quick ALPN and assert the native allowlist hook
/// rejects it (see [`assert_rejected_by_allowlist`]).
async fn assert_quick_client_rejected(ep: &Endpoint, server_addr: EndpointAddr, reason: &str) {
    let hello = signaling::encode_hello(&Hello::new(None, 1)).unwrap();
    assert_rejected_by_allowlist(ep, server_addr, QUICK_ALPN, hello, reason).await;
}

/// Dial `server_addr` on `alpn` and assert the native allowlist hook rejects
/// it: the server closes the connection at the TLS handshake with `reason`,
/// before any application handshake (`hello`) can be exchanged.
async fn assert_rejected_by_allowlist(
    ep: &Endpoint,
    server_addr: EndpointAddr,
    alpn: &[u8],
    hello: Vec<u8>,
    reason: &str,
) {
    // The QUIC handshake itself completes on the dialer side (the rejection is
    // an application close right after it), so `connect` may return Ok; the
    // rejection then surfaces as the connection closing with the hook's
    // reason. A `connect` error (rejection raced the handshake) is fine too.
    match with_timeout(ep.connect(server_addr, alpn)).await {
        Ok(conn) => {
            // Attempting the application handshake must fail...
            let handshake = async {
                let (mut send, mut recv) = conn.open_bi().await.map_err(std::io::Error::other)?;
                signaling::write_message(&mut send, &hello).await?;
                send.flush().await?;
                signaling::read_message(&mut recv, signaling::MAX_HANDSHAKE_SIZE).await
            };
            assert!(
                with_timeout(handshake).await.is_err(),
                "a rejected peer must not complete a handshake"
            );
            // ...because the server closed the connection with the hook's reason.
            let closed = with_timeout(conn.closed()).await.to_string();
            assert!(
                closed.contains(reason),
                "close reason should say {reason:?}: {closed}"
            );
        }
        Err(e) => {
            // Rejected before `connect` resolved (the close raced the
            // handshake) — equally a refusal, but only if the error carries
            // the hook's reason. Anything else (refused socket, wrong
            // address) is a test failure, not a rejection. Walk the source
            // chain: the close reason may sit below the top-level error.
            let mut chain = e.to_string();
            let mut source = std::error::Error::source(&e);
            while let Some(s) = source {
                chain.push_str(": ");
                chain.push_str(&s.to_string());
                source = s.source();
            }
            assert!(
                chain.contains(reason),
                "connect failed without the hook's reason {reason:?}: {chain}"
            );
        }
    }
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

/// Endpoint-rebuild escalation: when reconnect attempts keep failing on an
/// endpoint that is broken beyond repair (here: closed out from under the
/// session — the loopback stand-in for a wedged endpoint whose relay link or
/// path state never recovers), the reconnect loop must escalate to rebuilding
/// the endpoint via its factory and reconnect on the fresh one. The old
/// endpoint can never connect again, so recovery itself proves the rebuild
/// ran; the changed node id confirms it.
#[tokio::test]
async fn reconnect_rebuilds_a_dead_endpoint() {
    let server_ep = loopback_endpoint(SecretKey::generate(), true).await;
    let server_id = server_ep.id();
    let server_addr = EndpointAddr::new(server_id).with_ip_addr(server_ep.bound_sockets()[0]);
    let bl_path = temp_blocklist("rebuild-endpoint");
    let (routed_set, routed_cidrs) = loopback_cidr_set();
    spawn_server_params(
        server_ep.clone(),
        ProxyServerParams {
            routed_set,
            routed_cidrs,
            ..base_params(server_id, bl_path.clone())
        },
    );

    let lookup = MemoryLookup::from_endpoint_info(vec![server_addr]);
    let first_ep = loopback_endpoint_full(
        SecretKey::generate(),
        false,
        lookup.clone(),
        EndpointAllowlists::default(),
    )
    .await;
    let client_ep = ClientEndpoint::from_parts(first_ep.clone(), {
        let lookup = lookup.clone();
        Arc::new(move || {
            let lookup = lookup.clone();
            Box::pin(async move {
                Ok(loopback_endpoint_full(
                    SecretKey::generate(),
                    false,
                    lookup,
                    EndpointAllowlists::default(),
                )
                .await)
            })
        })
    });
    let first_id = client_ep.id();

    let client = Arc::new(ProxyClient::new(ClientConfig {
        server_node_id: server_id.to_string(),
        auth: ClientAuth::Key(Box::new(test_client_key().clone())),
        socks_listen: None,
        http_listen: None,
        relay_urls: Vec::new(),
        relay_auth_token: None,
        auto_reconnect: true,
        max_reconnect_attempts: None,
    }));
    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    {
        let (client, ep) = (client.clone(), client_ep.clone());
        tokio::spawn(async move {
            if let Err(e) = client.run_with_listener(&ep, socks_listener).await {
                eprintln!("e2e rebuild test client session ended: {e}");
            }
        });
    }
    let connected = || client.routes().lock().unwrap().connected;
    wait_until("client to connect", connected).await;

    // Kill the client's own endpoint. Every reconnect attempt on it fails
    // immediately, so the backoff series reaches the rebuild escalation well
    // inside the wait window.
    first_ep.close().await;
    wait_until("client to notice the drop", || !connected()).await;
    // Own, longer bound: reaching the rebuild takes the full early backoff
    // series (1s + 2s + 4s plus jitter), which crowds `wait_until`'s 10s.
    let start = Instant::now();
    while !connected() {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "timed out waiting for client to reconnect on a rebuilt endpoint"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    assert_ne!(
        client_ep.id(),
        first_id,
        "recovery must have swapped in a freshly built endpoint"
    );

    let _ = std::fs::remove_file(bl_path);
}

/// Deploy-style connection holding: a SOCKS request for an on-list target
/// arriving while the tunnel link is down is *held* for the client's own
/// reconnect and then proceeds transparently on the fresh connection, instead
/// of being refused with network-unreachable. Runs the full [`ProxyClient`]
/// session, kills the server endpoint mid-session, issues the request during
/// the outage, resurrects the server on the same identity, and asserts the
/// held request completes end-to-end.
#[tokio::test]
async fn on_list_request_is_held_across_reconnect() {
    let echo_port = spawn_echo().await;

    // First server incarnation, on a secret the test keeps to resurrect it.
    let server_secret = SecretKey::generate();
    let server_ep = loopback_endpoint(server_secret.clone(), true).await;
    let server_id = server_ep.id();
    let server_addr = EndpointAddr::new(server_id).with_ip_addr(server_ep.bound_sockets()[0]);
    let bl_path = temp_blocklist("hold-reconnect");
    let (routed_set, routed_cidrs) = loopback_cidr_set();
    spawn_server_params(
        server_ep.clone(),
        ProxyServerParams {
            routed_set,
            routed_cidrs,
            ..base_params(server_id, bl_path.clone())
        },
    );

    // The client endpoint's lookup is held externally so the resurrected
    // server's fresh address can be published mid-test.
    let lookup = MemoryLookup::from_endpoint_info(vec![server_addr]);
    let client_ep = loopback_endpoint_full(
        SecretKey::generate(),
        false,
        lookup.clone(),
        EndpointAllowlists::default(),
    )
    .await;
    // Hermetic rebuild recipe: should the session escalate to an endpoint
    // rebuild mid-test, the replacement is another loopback endpoint sharing
    // the same externally-held lookup.
    let client_ep = ClientEndpoint::from_parts(client_ep, {
        let lookup = lookup.clone();
        Arc::new(move || {
            let lookup = lookup.clone();
            Box::pin(async move {
                Ok(loopback_endpoint_full(
                    SecretKey::generate(),
                    false,
                    lookup,
                    EndpointAllowlists::default(),
                )
                .await)
            })
        })
    });

    // The full reconnecting client session with a real SOCKS front-end.
    let client = Arc::new(ProxyClient::new(ClientConfig {
        server_node_id: server_id.to_string(),
        auth: ClientAuth::Key(Box::new(test_client_key().clone())),
        socks_listen: None,
        http_listen: None,
        relay_urls: Vec::new(),
        relay_auth_token: None,
        auto_reconnect: true,
        max_reconnect_attempts: None,
    }));
    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_addr = socks_listener.local_addr().unwrap();
    {
        let (client, ep) = (client.clone(), client_ep.clone());
        tokio::spawn(async move {
            if let Err(e) = client.run_with_listener(&ep, socks_listener).await {
                eprintln!("e2e hold test client session ended: {e}");
            }
        });
    }
    let connected = || client.routes().lock().unwrap().connected;
    wait_until("client to connect", connected).await;

    // Drop the tunnel out from under the session and wait for it to notice.
    server_ep.close().await;
    wait_until("client to notice the drop", || !connected()).await;

    // Issue the on-list request during the outage: handshake completes (the
    // listener is up), but the CONNECT reply is held for the reconnect.
    let mut app = tokio::net::TcpStream::connect(socks_addr).await.unwrap();
    app.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method = [0u8; 2];
    with_timeout(app.read_exact(&mut method)).await.unwrap();
    assert_eq!(method, [0x05, 0x00], "no-auth method selected");
    let p = echo_port.to_be_bytes();
    app.write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, p[0], p[1]])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    let held = tokio::time::timeout(Duration::from_millis(500), app.read_exact(&mut reply)).await;
    assert!(held.is_err(), "on-list request was answered instead of held");

    // Resurrect the server on the same identity (a fresh nonce — a restart,
    // not a duplicate) and publish its new address to the client's lookup.
    let server_ep2 = loopback_endpoint(server_secret, true).await;
    lookup.set_endpoint_info(
        EndpointAddr::new(server_id).with_ip_addr(server_ep2.bound_sockets()[0]),
    );
    let (routed_set, routed_cidrs) = loopback_cidr_set();
    spawn_server_params(
        server_ep2,
        ProxyServerParams {
            routed_set,
            routed_cidrs,
            ..base_params(server_id, bl_path.clone())
        },
    );

    // The reconnect (backoff ~1s) wakes the held request, which then proceeds:
    // the echo greeting arriving through the SOCKS stream proves it.
    with_timeout(app.read_exact(&mut reply)).await.unwrap();
    assert_eq!(
        reply[1],
        signaling::REP_SUCCESS,
        "held request should succeed once the tunnel is back"
    );
    let mut greeting = [0u8; 5];
    with_timeout(app.read_exact(&mut greeting)).await.unwrap();
    assert_eq!(&greeting, b"HELLO");
    app.write_all(b"ping").await.unwrap();
    let mut echoed = [0u8; 4];
    with_timeout(app.read_exact(&mut echoed)).await.unwrap();
    assert_eq!(&echoed, b"ping");

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

    // A's identity is fixed up front so B's endpoint can allowlist it at bind.
    let a_secret = SecretKey::generate();
    let a_id = a_secret.public();

    // Server B (target): natively allows bridging from A, dials loopback locally.
    let b_ep = loopback_endpoint_full(
        SecretKey::generate(),
        true,
        MemoryLookup::new(),
        bridge_allowlist([a_id]),
    )
    .await;
    let b_id = b_ep.id();
    let b_addr = EndpointAddr::new(b_id).with_ip_addr(b_ep.bound_sockets()[0]);

    // Server A (bridging): seeded with B's direct address so its id-only
    // upstream dial resolves hermetically.
    let a_ep = loopback_endpoint_seeded(a_secret, true, vec![b_addr.clone()]).await;
    let a_addr = EndpointAddr::new(a_id).with_ip_addr(a_ep.bound_sockets()[0]);

    let mut b_params = base_params(b_id, temp_blocklist("bridgetarget"));
    b_params.routed_set = routed_set.clone();
    b_params.routed_cidrs = cidrs.clone();
    b_params.allowed_bridge_servers = HashSet::from([a_id]);
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

/// Inbound bridge gating, enforced natively by the endpoint's allowlist hook:
/// a non-allowlisted id is rejected at the TLS handshake (the connection is
/// closed with the reason — no bridge ever reaches the server's accept path),
/// and an empty allowlist means bridging is off entirely.
#[tokio::test]
async fn bridge_rejected_by_native_allowlist() {
    // Case 1: id not allowlisted (allowlist names someone else).
    let ep1 = loopback_endpoint_full(
        SecretKey::generate(),
        true,
        MemoryLookup::new(),
        bridge_allowlist([SecretKey::generate().public()]),
    )
    .await;
    let addr1 = EndpointAddr::new(ep1.id()).with_ip_addr(ep1.bound_sockets()[0]);
    let mut p1 = base_params(ep1.id(), temp_blocklist("bridgerej1"));
    p1.allowed_bridge_servers = HashSet::from([SecretKey::generate().public()]);
    spawn_server_params(ep1, p1);
    let dialer = loopback_endpoint(SecretKey::generate(), false).await;
    assert_bridge_rejected(&dialer, addr1, "allowlist").await;

    // Case 2: bridging not enabled (empty allowlist) — every bridge dial is
    // rejected up front.
    let dialer2 = loopback_endpoint(SecretKey::generate(), false).await;
    let ep2 = loopback_endpoint(SecretKey::generate(), true).await;
    let addr2 = EndpointAddr::new(ep2.id()).with_ip_addr(ep2.bound_sockets()[0]);
    let p2 = base_params(ep2.id(), temp_blocklist("bridgerej2"));
    spawn_server_params(ep2, p2);
    assert_bridge_rejected(&dialer2, addr2, "not enabled").await;
}

/// Quick mode end to end: a client whose endpoint id is on the server's quick
/// allowlist connects over the quick ALPN with **no keypair** (the server runs
/// with an empty authorized-keys set, like a quick server), is served exactly
/// like a keypair client (routed set pushed, tunnel streams pipe), and its heartbeat
/// refreshes liveness through the same accepted path.
#[tokio::test]
async fn quick_client_authenticates_by_endpoint_id() {
    let echo_port = spawn_echo().await;
    let (routed_set, cidrs) = loopback_cidr_set();

    // The client's identity is fixed up front — its id is what the quick
    // server allowlists (the user enters it at the server prompt).
    let client_secret = SecretKey::generate();
    let client_id = client_secret.public();

    let server_ep = loopback_endpoint_full(
        SecretKey::generate(),
        true,
        MemoryLookup::new(),
        EndpointAllowlists {
            bridge_servers: HashSet::new(),
            quick_clients: HashSet::from([client_id]),
        },
    )
    .await;
    let server_addr = EndpointAddr::new(server_ep.id()).with_ip_addr(server_ep.bound_sockets()[0]);
    let mut params = base_params(server_ep.id(), temp_blocklist("quickok"));
    params.authorized_keys = Default::default(); // a quick server has no client keys at all
    params.routed_set = routed_set;
    params.routed_cidrs = cidrs;
    spawn_server_params(server_ep, params);

    let client_ep = loopback_endpoint(client_secret, false).await;
    let (conn, _cs, _cr, resp) =
        handshake_on_alpn(&client_ep, server_addr, QUICK_ALPN, 1, false).await;
    assert!(resp.accepted, "allowlisted quick client must be accepted: {:?}", resp.reject_reason);
    assert_eq!(
        resp.routed_cidrs,
        vec!["127.0.0.0/8".to_string()],
        "a quick client gets the routed set pushed like any client"
    );
    assert_echo_roundtrip(&conn, echo_port).await;
}

/// Quick-mode gating, enforced natively by the endpoint's allowlist hook: a
/// non-allowlisted client id is rejected at the TLS handshake, and an empty
/// quick allowlist (every normal server) rejects the quick ALPN entirely. A
/// keypair credential is no substitute: case 1's dialer presents a validly
/// signed credential the server's authorized-keys set does accept (on the
/// client ALPN), yet is still rejected — the hook closes the connection
/// before the `Hello` is ever read.
#[tokio::test]
async fn quick_client_rejected_by_native_allowlist() {
    // Case 1: quick allowlist names someone else. The server's ProxyServer
    // authorizes [`test_client_key`] (base_params), and the dialer's Hello
    // carries a valid signed credential — proving an authorized keypair cannot
    // bypass the allowlist on the quick ALPN.
    let ep1 = loopback_endpoint_full(
        SecretKey::generate(),
        true,
        MemoryLookup::new(),
        EndpointAllowlists {
            bridge_servers: HashSet::new(),
            quick_clients: HashSet::from([SecretKey::generate().public()]),
        },
    )
    .await;
    let addr1 = EndpointAddr::new(ep1.id()).with_ip_addr(ep1.bound_sockets()[0]);
    let p1 = base_params(ep1.id(), temp_blocklist("quickrej1"));
    spawn_server_params(ep1, p1);
    let dialer = loopback_endpoint(SecretKey::generate(), false).await;
    let hello_with_valid_credential =
        signaling::encode_hello(&Hello::new(Some(test_auth_payload(&dialer)), 1)).unwrap();
    assert_rejected_by_allowlist(&dialer, addr1, QUICK_ALPN, hello_with_valid_credential, "allowlist")
        .await;

    // Case 2: quick mode not enabled (empty allowlist — every normal server).
    let ep2 = loopback_endpoint(SecretKey::generate(), true).await;
    let addr2 = EndpointAddr::new(ep2.id()).with_ip_addr(ep2.bound_sockets()[0]);
    let p2 = base_params(ep2.id(), temp_blocklist("quickrej2"));
    spawn_server_params(ep2, p2);
    let dialer2 = loopback_endpoint(SecretKey::generate(), false).await;
    assert_quick_client_rejected(&dialer2, addr2, "not enabled").await;
}

/// Send `hello` on the client ALPN and return the server's response.
async fn send_hello_expect_response(
    client_ep: &Endpoint,
    server_addr: EndpointAddr,
    hello: Hello,
) -> HelloResponse {
    let conn = with_timeout(client_ep.connect(server_addr, ALPN)).await.unwrap();
    let (mut send, mut recv) = with_timeout(conn.open_bi()).await.unwrap();
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
    signaling::decode_hello_response(&data).unwrap()
}

/// Every broken credential on the regular client ALPN is an auth failure: a
/// missing payload, an unauthorized (though validly signing) key, a claimed
/// endpoint id that differs from the connection's TLS-authenticated one
/// (replaying a captured credential from another endpoint), and a corrupted
/// signature. Only the intact [`test_client_key`] credential is accepted
/// (covered by the other tests via [`client_handshake`]).
#[tokio::test]
async fn broken_credentials_on_client_alpn_are_rejected() {
    let server_ep = loopback_endpoint(SecretKey::generate(), true).await;
    let server_addr = EndpointAddr::new(server_ep.id()).with_ip_addr(server_ep.bound_sockets()[0]);
    spawn_server(server_ep, temp_blocklist("badcreds"));

    let client_ep = loopback_endpoint(SecretKey::generate(), false).await;

    // No credential at all.
    let cases: Vec<(&str, Option<signaling::ClientAuthPayload>)> = vec![
        ("missing credential", None),
        ("unauthorized key", {
            let stranger = crate::auth::ClientKey::generate().unwrap();
            Some(signaling::ClientAuthPayload {
                public_key: stranger.public_str(),
                endpoint_id: client_ep.id().to_string(),
                signature: crate::auth::sign_endpoint_id(&stranger, &client_ep.id()),
            })
        }),
        ("mismatched claimed endpoint id", {
            // Validly signed by the authorized key, but binding a *different*
            // endpoint id — a replay from another endpoint.
            let other_id = SecretKey::generate().public();
            Some(signaling::ClientAuthPayload {
                public_key: test_client_key().public_str(),
                endpoint_id: other_id.to_string(),
                signature: crate::auth::sign_endpoint_id(test_client_key(), &other_id),
            })
        }),
        ("bad signature", {
            let mut auth = test_auth_payload(&client_ep);
            auth.signature = crate::auth::sign_endpoint_id(
                &crate::auth::ClientKey::generate().unwrap(),
                &client_ep.id(),
            );
            Some(auth)
        }),
    ];
    for (what, auth) in cases {
        let resp =
            send_hello_expect_response(&client_ep, server_addr.clone(), Hello::new(auth, 5)).await;
        assert!(!resp.accepted, "{what} must be rejected");
        assert!(
            resp.reject_reason
                .as_deref()
                .unwrap_or_default()
                .contains("authentication"),
            "{what}: reject reason should mention authentication: {:?}",
            resp.reject_reason
        );
    }
}

/// Single hop: two servers bridging the same range at each other must not
/// forward in a loop. A stream bridged A→B is flagged `from_bridge` on B, so B
/// dials it locally instead of re-bridging it back to A — without the guard
/// this request would ping-pong forever and time out.
#[tokio::test]
async fn bridged_stream_is_never_rebridged() {
    let echo_port = spawn_echo().await;
    let (routed_set, cidrs) = loopback_cidr_set();

    // Both identities are fixed up front so each endpoint can natively
    // allowlist the other at bind. Each server must also learn the other's
    // ephemeral address, so bind both with shared-handle lookups and seed them
    // after binding.
    let a_secret = SecretKey::generate();
    let b_secret = SecretKey::generate();
    let a_id = a_secret.public();
    let b_id = b_secret.public();
    let a_lookup = MemoryLookup::new();
    let b_lookup = MemoryLookup::new();
    let a_ep =
        loopback_endpoint_full(a_secret, true, a_lookup.clone(), bridge_allowlist([b_id])).await;
    let b_ep =
        loopback_endpoint_full(b_secret, true, b_lookup.clone(), bridge_allowlist([a_id])).await;
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
    spawn_server_params(a_ep, a_params);

    let bridge_b_to_a = loopback_bridge("to-a", a_id);
    let mut b_params = base_params(b_id, temp_blocklist("rebridge-b"));
    b_params.routed_set = routed_set;
    b_params.routed_cidrs = cidrs;
    b_params.bridges = vec![bridge_b_to_a.clone()];
    b_params.allowed_bridge_servers = HashSet::from([a_id]);
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
