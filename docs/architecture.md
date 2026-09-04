# Architecture

flextunnel is a **SOCKS5/HTTP-proxy-over-QUIC split tunnel**: local proxy
listeners on the **client** parse each request, match it against the
server-pushed tunnel set, and either direct-connect off-list targets from the
client device or tunnel on-list targets over reliable QUIC bi-streams to the
**server**. Tunneled targets are resolved and connected *from the server's own
network*. Transport, NAT traversal, relay fallback, and TLS 1.3 encryption come
from [iroh](https://www.iroh.computer/). Neither side needs a TUN device or
admin/root — it is ordinary userspace sockets end to end.

## High-level flow

```
local app ──SOCKS5/HTTP──► flextunnel client                    flextunnel server
                      (optional SOCKS5/HTTP listeners)           (no root, no TUN)
                          │                                          │
                          │   one iroh QUIC Connection               │
                          │   (fixed ALPN + TLS 1.3)                 │
                          │                                          │
                          ├── control bi-stream ───────────────────►│  verify client keypair
                          │      Hello / HelloResponse               │
                          │                                          │
   per routed request ────┼── data bi-stream #1 ───────────────────►│  resolve DNS, TcpStream::connect
                          │      [request hdr][reply][raw bytes]     │      ───► target host:port
                          ├── data bi-stream #2 ───────────────────►│           (server's network)
                          └── data bi-stream #N ───────────────────►│
                          └── off-list targets: direct connect from client
```

All streams from one client multiplex over a **single** QUIC `Connection`. The
control stream authenticates once; each subsequent data bi-stream carries one
tunneled proxied TCP connection. Direct off-list connections never touch the
server.

## Module map (`src/`)

| Module | Responsibility |
|---|---|
| `main.rs` | clap CLI, command dispatch, logger/runtime, graceful `endpoint.close()`, shutdown signal |
| `config.rs` | TOML config files (`-c`/`--default-config`), `deny_unknown_fields`, CLI>file>default merge, `~` expansion |
| `auth.rs` | client keypair auth (ed25519): endpoint-id-bound sign/verify over flextunnel's domain-separated transcript; key format, key files, and authorized-keys parsing (`ed25519-pub:`/`ed25519-sec:`) are delegated to the shared [flexaccess-keys](https://github.com/flexaccessdev/flexaccess-keys) crate |
| `blocklist.rs` | persisted duplicate-id blocklist (JSON): confirmed duplicate client ids + the server's own conflicted id |
| `secret.rs` | iroh identity key commands (`generate-iroh-key`/`show-iroh-id`); client auth keypairs are generated with the standalone `flexaccess-keys` CLI |
| `error.rs` | `ProxyError` (`Network`/`Config`/`Signaling`/`AuthenticationFailed`/`ConnectionLost`) + `is_recoverable()` |
| `transport/mod.rs` | QUIC transport config, ALPN, heartbeat/liveness timing |
| `transport/endpoint.rs` | iroh `Endpoint` creation (`RelayConfig`, relay mode + relay-mode-dependent n0 discovery, per-relay startup probe), secret/relay helpers, native per-ALPN allowlist hook (`AllowlistHook` over `EndpointAllowlists`: bridges + quick clients) |
| `transport/paths.rs` | connection-path snapshot (direct/relay) + on-demand custom-relay `/healthz` health |
| `proxy/signaling.rs` | length-prefixed `Hello`/`HelloResponse`, control frames, per-stream `Target` codec, `REP_*` codes |
| `proxy/socks5.rs` | client-side RFC 1928: method negotiation + `CONNECT` parsing + replies |
| `proxy/client.rs` | connect + auth + SOCKS5/HTTP listeners + split-tunnel routing + reconnect loop |
| `proxy/http.rs` | client-side HTTP proxy front-end: `CONNECT` tunneling + absolute-URI plain-HTTP forwarding |
| `proxy/routed_set.rs` | parsed tunnel set: client split-tunnel decision + server whitelist enforcement |
| `proxy/server.rs` | accept + auth + routed-set whitelist + per-stream DNS/connect/pipe; status page |
| `proxy/bridge.rs` | outbound server-to-server bridge: persistent upstream connection (`BRIDGE_ALPN`, id-allowlist-authenticated) with retry-forever reconnect; matching streams splice over it |
| `proxy/dial.rs` | `Target` → TCP dial + `connect_and_pipe` (the server's exit-point body) |

**Bridges** split-tunnel *across servers*: a `[bridges.<name>]` entry on server A
forwards targets matching its domain/CIDR rules verbatim over a persistent
connection to server B, which re-enforces its own routed set, applies its own
aliases/DNS forwards, and dials from its network. A dials out on its
own server endpoint with the bridge ALPN, so the TLS-authenticated id it
presents is its persistent server id — which B must list in
`allowed_bridge_servers`, the sole bridge credential, enforced natively at the
TLS handshake by B's endpoint hook (empty allowlist = inbound bridging
disabled). Bridged-in streams are served like client streams but are
never re-bridged (single hop, so mutual bridges cannot loop). Bridge rules must
be reachable through A's routed set (validated at startup, like `dns_forwards`
coverage).

## Connection lifecycle

### 1. ALPN
Clients connect with the fixed constant `flextunnel/1` (`transport::ALPN`);
bridging servers connect with `flextunnel-bridge/1` (`transport::BRIDGE_ALPN`);
quick-mode clients connect with `flextunnel-quick/1` (`transport::QUICK_ALPN`).
The ALPN is a protocol-negotiation label sent **unencrypted** in the TLS/QUIC
handshake, not a secret: it carries the peer's *role*, never a credential.
Keypair-client access control is the auth handshake below; bridge and quick-client
access control is an endpoint-id allowlist (`allowed_bridge_servers`, or the
single client id entered on a quick server), enforced **natively at the TLS
handshake** by an iroh `EndpointHooks::after_handshake` hook
(`transport::endpoint::AllowlistHook` over `EndpointAllowlists`) — a
non-allowlisted peer's connection is closed with the reason before it ever
reaches the accept loop, and the id needs no further proof because iroh's
handshake authenticates it. An empty set disables its ALPN entirely (a normal
server rejects every quick dial; a no-bridging server rejects every bridge).

### 2. Auth handshake (control stream)
The protocol version is `PROTOCOL_VERSION = 13`. On the first bi-stream a
client sends
`Hello { version, auth?, client_instance_nonce, duplicate_server_observed }`
where `auth` is `ClientAuthPayload { public_key, endpoint_id, signature }`
(a bridge sends the minimal `BridgeHello { version }` — its authentication
already happened at the TLS handshake) and the server replies
`HelloResponse { version, accepted, reject_reason, server_instance_nonce, routed_*, host_aliases, dns_forwards, bridges }`,
both length-prefixed JSON via `signaling::write_message` / `read_message` (4-byte
big-endian length + payload, capped at `MAX_HANDSHAKE_SIZE` = 64 KiB). On the
client ALPN `auth` is required: the server checks that the claimed
`endpoint_id` equals the connection's TLS-authenticated `remote_id()`, that the
ed25519 `signature` (over a domain-separated hash of that id) verifies under
`public_key`, and that `public_key` is on the server's authorized-keys file —
binding the credential to this connection so a captured `Hello` cannot be
replayed from another endpoint. On the quick ALPN `auth` is absent — the
allowlist hook already authenticated the endpoint id, and everything after the
handshake (routed set, duplicate detection, heartbeats, data streams) is
identical for both. On rejection the server closes the connection gracefully
(with a short drain) carrying the reason. Nothing in the payload is secret, so
`Hello` derives `Debug` plainly.

The `*_instance_nonce` fields are random per-process ids (distinct from the iroh
node id) that drive duplicate-id detection (see below); `duplicate_server_observed`
is a client advisory. Unlike earlier versions the handshake bi-stream is **not
closed** after the exchange — it stays open as the control stream carrying
heartbeats (§6).

The server bounds accepting/reading the client `Hello` with a 10s timeout, and
the client bounds waiting for the server `HelloResponse` with the same timeout
(`HANDSHAKE_TIMEOUT` in `client.rs` / `server.rs`), because QUIC keep-alive
otherwise prevents the idle timeout from firing on a peer that connects but
never speaks.

### 3. Per-request data streams
For each on-list local request that needs the tunnel, the client opens a new
bi-stream and writes a compact request header, then reads a one-byte reply, then
pipes raw bytes:

```
Request (client→server):  [ver=1][atyp][addr][port:u16 BE]
    atyp 0x01 IPv4 → 4 bytes   0x03 DOMAIN → [len:u8][host]   0x04 IPv6 → 16 bytes
Reply   (server→client):  [ver=1][rep]      then raw bytes both ways
```

`rep` values are deliberately equal to RFC 1928 SOCKS5 reply codes
(`REP_SUCCESS=0x00`, `REP_HOST_UNREACHABLE=0x04`, …), so the client forwards the
server's reply byte straight into its SOCKS5 reply to the local app with no
translation table. The header is parsed with `read_exact` (ATYP fixes the
length; domains ≤ 255 bytes).

### 4. Server-side resolve + connect
The server reads the requested `Target`, enforces the routed-set whitelist on
that requested target, handles reserved `flextunnel.internal` status routes,
then (bounded by `CONNECT_TIMEOUT` = 10s in `proxy/dial.rs`) either
`TcpStream::connect`s a literal address or, for a domain, calls
`tokio::net::lookup_host` and connects to the first address that accepts.
**DNS happens on the server** for tunneled domain targets, which is what lets
clients reach names/IPs that only resolve or route from the server's network.
Connect failures map to SOCKS5 reply codes via `signaling::map_io_err`.

### 5. Byte piping
Both ends join the iroh `(SendStream, RecvStream)` halves with
`tokio::io::join` and run `tokio::io::copy_bidirectional` against the `TcpStream`.
This propagates half-close correctly (EOF on one side → `shutdown`, which quinn
maps to a stream FIN). Per-stream errors stay per-stream — the shared QUIC
`Connection` is never closed for a single failed proxied connection.

### 6. Heartbeat & liveness (control stream)
After the handshake the control bi-stream stays open. The client sends a
`ControlMsg::Heartbeat { seq }` every `HEARTBEAT_INTERVAL` (10s) and the server
replies `HeartbeatAck { seq }`, framed with the same length-prefixed helpers
(capped at `MAX_CONTROL_MSG_SIZE` = 16 KiB). This is an app-level liveness signal *on top
of* QUIC keep-alive: it catches an *application-level* stall — a peer still
answering QUIC keep-alive at the transport level but no longer sending
heartbeats — within `LIVENESS_WINDOW` (33s: three heartbeat intervals plus 3s
grace). A fully silent peer is caught sooner by the 30s QUIC idle timeout, which
fires first. On the server,
heartbeats also refresh the per-client connection registry used for duplicate
detection (below). A missing heartbeat surfaces as a recoverable
`ConnectionLost`, so the client's normal reconnect path applies. The heartbeat
runs concurrently with the SOCKS5 stream loop via `tokio::select!` on both sides.

## Duplicate-id detection

A guard rail against *accidental misconfiguration* (not an adversary defense —
see the security model). Both roles carry a random per-process **instance nonce**
that is distinct from the iroh node id, exchanged in the handshake.

**Duplicate client (server-side).** Client identity is ephemeral (a fresh key per
process), so two *different* client processes never share a node id; a node id
seen on two concurrently-live connections is a rare bug. The server keeps a
registry keyed by client node id, and within it by connection, refreshed by the
heartbeat. Two live connections for one node id with **different** instance nonces
are a confirmed duplicate (a benign same-process reconnect reuses the *same*
nonce and is ignored). On confirmation the server tears down the offending
connections and records the node id in the persisted blocklist (`blocklist.rs`);
a blocklisted node id is rejected up-front. Because ephemeral ids never recur,
the persisted client entry is largely an audit record.

**Duplicate server (self-block).** Server identity is persistent, so two servers
sharing one secret key is a plausible misconfiguration — but only observable when
both are reachable by the *same client over a shared discovery/relay path*
(same-id servers on isolated networks that no client can reach both of are not a
conflict). Each server emits a stable `server_instance_nonce`; a restart yields a
fresh nonce that never reappears, whereas a client bouncing between two concurrent
same-id servers sees a previously-seen nonce **reappear** after a different one.
On that reappearance the client latches an advisory (`duplicate_server_observed`)
into its next `Hello` — a non-privileged observation, not a command. The server,
on receiving it from any active client, records its **own** `EndpointId` in the
blocklist and shuts down; on the next start it refuses to run while its id is
listed. Detection is best-effort and delayed (it needs client churn to observe
both instances); prompt, robust detection would require a signaling server. See
[`duplicate-detection-roadmap.md`](./duplicate-detection-roadmap.md).

The blocklist is a JSON file at the fixed path
`~/.config/flextunnel/blocklist.json` — deliberately **not** configurable, since
relocating this security guard rail would let it be bypassed. It is written
atomically (temp + rename) and loaded at startup.

## Concurrency model

- **Server:** one tokio task per accepted iroh connection (`handle_connection`,
  capped at `MAX_CONCURRENT_CONNECTIONS`), and within it one task per accepted
  data bi-stream (`handle_socks_stream`). No shared mutable state on the data
  path; the authorized-keys set is read-only (loaded at startup).
- **Client:** one task per accepted local TCP connection (`handle_local_conn`),
  from the SOCKS5 listener and optional HTTP listener. All tunneled requests
  share the single `Connection` clone; off-list requests direct-connect locally.
  The local listeners and the QUIC connection liveness are raced with
  `tokio::select!` so a dropped connection breaks into the reconnect path.

## Reconnect policy (client)

Implemented in `ProxyClient::run` / `handle_failure`:

- The **first** connection must succeed; if it fails (even a transient error),
  the client exits — a bad node id, wrong relay, or down server is not worth
  retrying blindly.
- After at least one success, transient drops (`ConnectionLost` / `Network` /
  `Signaling` — see `ProxyError::is_recoverable`) are retried with **exponential
  backoff + jitter** (1s → 60s), indefinitely, unless `--max-reconnect-attempts`
  caps it or `--no-auto-reconnect` disables it.
- Permanent errors (`AuthenticationFailed` / `Config`) never retry.
- Every **third** consecutive failure escalates to a **full endpoint rebuild**
  (`ClientEndpoint::rebuild`); the other retries nudge
  `Endpoint::network_change()` (rebinds dead UDP sockets) instead. The rebuild
  swaps in a freshly bound endpoint — new sockets, new
  relay connections, fresh discovery — and closes the wedged one in the
  background. This is the in-process equivalent of restarting the
  client, for wedges a rebind can't fix (a relay link lost to a ping timeout
  and never re-established, stale cached paths for the server). The rebuild
  skips the startup per-relay probe and tolerates the online-wait failing, so
  a partial outage never blocks recovery.
- The local proxy listeners stay bound across reconnects. Off-list targets keep
  connecting directly; on-list requests are held for the reconnect — up to 45s
  (`TUNNEL_RECOVERY_HOLD`), deploy-style connection holding — and only then fail
  with a network-unreachable reply.

## Relay watchdog (server, custom relays)

Implemented in `transport/relay_watchdog.rs`, driven by the serve loop in the
CLI's `run_server`. A custom-relay server is dialable from off the LAN only
while it is **registered on its home relay** (n0 discovery is off; clients dial
by relay hint, and a relay forwards Initials only to endpoints connected to it).
iroh (v1.0.3) has been observed to silently lose its home relay for good after
a routine relay reconnect: no dial retries, no warnings, no registration on
any relay — the server stops being reachable through the relays until the
process restarts, while LAN clients that find it over mDNS keep working and
hide the outage (the mac desktop reconnects, the iOS app times out).

The watchdog observes `Endpoint::home_relay_status()` and escalates like the
client's reconnect loop:

1. no connected home relay for `RELAY_OUTAGE_NUDGE` (60s) → log a warning and
   call `Endpoint::network_change()` (forces a fresh net report and relay
   re-selection — enough when only the bookkeeping went stale);
2. still none at `RELAY_OUTAGE_REBUILD` (180s from the outage start) → the
   serve loop closes the endpoint, binds a fresh one with the **same identity
   and allowlists** (`server_rebuild_factory`: no per-relay probe, online-wait
   tolerated failing), and calls `ProxyServer::run` again on it. The
   `ProxyServer` — registries, blocklist, status state — carries over; the old
   endpoint's connections end with it, and its bridge tasks are aborted with
   the previous `run` future (they are owned by a `JoinSet` per run). A failed
   rebuild is retried every `REBUILD_RETRY` (30s).

A reconnect at any point resets the outage clock. Non-home relays are
connected on demand and dropped after a minute idle, which is normal and never
counts as an outage. With the default relays the watchdog is not armed:
reachability there rests on n0 publishing/resolution, not on one relay
registration.

On every exit path both `run_server` and `run_client` call
`endpoint.close().await` before the `Endpoint` drops; skipping it makes iroh tear
down its relay tasks ungracefully (a `JoinSet` panic that is fatal under the
release profile's `panic = "abort"`).

## Security model & trust boundaries

**Purpose & threat model.** flextunnel exists to let a set of **trusted clients**
reach resources on the **server's** side of the network — names and addresses that
only resolve or route from where the server sits. Both ends of the deployment are
operated by the same trusted party: whoever runs the server also decides which
clients' keys get authorized. flextunnel is *not* a multi-tenant service and does not defend
the server against the clients it admits — a client with an authorized key is, by
design, allowed to reach whatever the server's network can reach. The threats it
does address are **on-path attackers** (defeated by QUIC/TLS 1.3 encryption and
per-client keypairs) and **accidental misconfiguration** — the duplicate-id
detection (see "Duplicate-id detection" above) catches, e.g., two clients or two
servers started with the same identity, blocking the conflicted id and refusing a
self-blocked server's restart. These are guard rails for operators, not adversary
defenses.

- **Credentials:** client keypairs are ed25519 in the shared
  [flexaccess-keys](https://github.com/flexaccessdev/flexaccess-keys) format —
  the public key travels as `ed25519-pub:` + base64url, the secret as
  `ed25519-sec:` + base64url — verified in the handshake via a signature bound
  to the connection's endpoint id under a flextunnel-specific
  domain-separation context. That context is what rejects a signature produced
  for another FlexAccess app — cross-app isolation holds because each app signs
  under its own distinct context, not because the shared library enforces
  anything about how applications use the keys. Bridges and quick-mode clients
  carry no keypair: their credential is their TLS-authenticated endpoint id,
  checked natively against the matching allowlist — `allowed_bridge_servers`,
  or the single client id entered on a quick server (the `authorized_keys`
  model). The QUIC ALPNs (`flextunnel/1`, `flextunnel-bridge/1`,
  `flextunnel-quick/1`) are fixed protocol/role identifiers, not credentials.
  All payload is encrypted by QUIC/TLS 1.3.
- **The server is the exit point.** Anyone with an authorized key can reach whatever
  the server's network can reach (including its `localhost`). Authorize keys
  accordingly; scope server network access if needed.
- **The local SOCKS5/HTTP proxy listeners are unauthenticated** and bind to
  loopback by default — access control lives at the QUIC layer, not in the local
  proxy front-ends. Binding them off-loopback exposes an open proxy on the LAN;
  don't, unless you add auth.
- iroh's relay/discovery operators can see connection *metadata* (which endpoints
  talk), never the encrypted payload.

## Reference constants

| Constant | Value | Where |
|---|---|---|
| `QUIC_KEEP_ALIVE_INTERVAL` | 15s | `transport/mod.rs` |
| `QUIC_IDLE_TIMEOUT` | 30s | `transport/mod.rs` |
| `QUIC_INITIAL_MTU` | 1452 | `transport/mod.rs` |
| `HEARTBEAT_INTERVAL` | 10s | `transport/mod.rs` |
| `LIVENESS_WINDOW` | 33s | `transport/mod.rs` |
| `RELAY_CONNECT_TIMEOUT` (`endpoint.online()`) | 10s | `transport/endpoint.rs` |
| `RELAY_OUTAGE_NUDGE` (server relay watchdog) | 60s | `transport/relay_watchdog.rs` |
| `RELAY_OUTAGE_REBUILD` (server relay watchdog) | 180s | `transport/relay_watchdog.rs` |
| `REBUILD_RETRY` (server endpoint rebuild) | 30s | `flextunnel-cli/src/main.rs` |
| `CONNECT_TIMEOUT` (client server connect) | 30s | `proxy/client.rs` |
| `HANDSHAKE_TIMEOUT` | 10s | `proxy/client.rs`, `proxy/server.rs`, `proxy/bridge.rs` |
| `LOCAL_HANDSHAKE_TIMEOUT` | 10s | `proxy/client.rs` |
| `TUNNEL_OPEN_TIMEOUT` | 30s | `proxy/client.rs` |
| `CONNECT_TIMEOUT` (server dial) | 10s | `proxy/dial.rs` |
| `MAX_CONCURRENT_CONNECTIONS` | 1024 | `proxy/server.rs` |
| reconnect backoff | 1s → 60s + ≤500ms jitter | `proxy/client.rs` |
| `MAX_HANDSHAKE_SIZE` | 64 KiB | `proxy/signaling.rs` |
| `MAX_CONTROL_MSG_SIZE` | 16 KiB | `proxy/signaling.rs` |
| `MAX_HTTP_HEADER` | 64 KiB | `proxy/http.rs` |
| `PROTOCOL_VERSION` | 13 | `proxy/signaling.rs` |
| client key encoding | ed25519, base64url (32-byte keys, 64-byte sigs) | `auth.rs` |
| `ALPN` | `flextunnel/1` | `transport/mod.rs` |
| `BRIDGE_ALPN` | `flextunnel-bridge/1` | `transport/mod.rs` |
| `QUICK_ALPN` | `flextunnel-quick/1` | `transport/mod.rs` |

## Relation to ezvpn

flextunnel reuses ezvpn's iroh transport and
secret-key identity, but replaces the IP-over-QUIC-datagrams + TUN data path
(which needs root) with SOCKS5/HTTP proxy front-ends over reliable QUIC streams
(which don't). See the project `README.md` for the user-facing comparison.

## Roadmap

HTTP proxy support is implemented on the client side; the wire protocol and
server remain front-end-agnostic. See
[`http-proxy-roadmap.md`](./http-proxy-roadmap.md).

Future work on duplicate-id detection — non-ephemeral client ids and their
pitfalls, the signaling-server path for prompt server-dup detection, and
client-side dup acknowledgement/flagging — is in
[`duplicate-detection-roadmap.md`](./duplicate-detection-roadmap.md).
