# flextunnel

A SOCKS5/HTTP-proxy-over-QUIC split tunnel. The **client** runs optional local
SOCKS5 and HTTP proxy listeners. Each request is matched
against the server-pushed tunnel set: routed targets are tunneled as reliable
QUIC bi-streams to the **server**, which performs **DNS resolution and the
outbound TCP connection from its own network**, then pipes bytes back; off-list
targets are connected directly from the client device.

This lets you reach hosts that are only reachable from the server side — a
private network, the server's own `localhost`, or names that only resolve via
the server's DNS — without a VPN. Because it uses ordinary userspace sockets
(no TUN device), **neither the client nor the server needs admin/root**.

Transport, NAT traversal, relay fallback, and TLS 1.3 encryption are provided by
[iroh](https://www.iroh.computer/): the client dials the server by its
`EndpointId`, so the server needs no public inbound port or port forwarding.

```
local app ──SOCKS5/HTTP──► flextunnel client (optional listeners, e.g. 127.0.0.1:1080 / :8081)
                          │  one iroh QUIC connection (fixed ALPN + auth handshake)
                          │  ├─ control stream:  Hello / HelloResponse
                          │  └─ N data streams:  [target header][reply][raw bytes]
                          ▼
                      flextunnel server  (no root, no TUN)
                          │  per stream: resolve DNS ─► TcpStream::connect
                          ▼
                      target host:port  (reachable from the SERVER's network)
```

## Scope

- **SOCKS5 `CONNECT` only.** No UDP `ASSOCIATE`, no `BIND`. The optional HTTP
  proxy supports HTTP `CONNECT` plus absolute-URI plain-HTTP forwarding.
- The local SOCKS5 and HTTP proxy listeners are **unauthenticated**, and each is
  disabled unless explicitly configured. Any local user or process that can reach
  them can use the tunnel, so they **bind `127.0.0.1` only** (you configure just
  the port, like the desktop client) and flextunnel assumes a **trusted,
  single-user host**. The QUIC auth token authenticates the client *process* to
  the server; it does **not** authenticate local callers of the proxy
  front-ends, and is no substitute for OS-level access control on a shared
  machine.

## Security model

flextunnel lets a set of **trusted clients** reach resources on the **server's**
side of the network. Both ends are run by the same trusted party: whoever runs
the server decides which clients get tokens. It is **not** a multi-tenant service
and does not defend the server against the clients it admits — a client with a
valid token can, by design, reach whatever the server's network can reach
(including the server's own `localhost`). Distribute tokens accordingly, and
scope the server's network access if that reach is too broad. The threats it does
address are on-path attackers (encryption + per-client tokens) and accidental
misconfiguration (e.g. duplicate-id detection catching two clients or servers
started with the same identity — an operator guard rail, not an adversary
defense).

A per-client auth token gates every connection:

- **Auth token** — sent in the connection handshake and checked against the
  server's accepted set. Per-client, like an API key.

The QUIC ALPN is a fixed protocol identifier (`flextunnel/1`), not a secret: it
ensures both peers speak the flextunnel protocol but provides no access control
on its own.

All payload is end-to-end encrypted by QUIC/TLS 1.3.

## Install

Prebuilt release assets are published on the
[GitHub Releases](https://github.com/flexaccessdev/flextunnel/releases) page.
Stable releases include `flextunnel` for Linux
amd64/arm64, macOS arm64, and Windows amd64, plus the iOS xcframework asset.
Automated prereleases currently include Linux amd64/arm64, macOS arm64, and the
iOS xcframework, but skip Windows. The install scripts download the latest
binary and verify its SHA-256 checksum. On Linux/macOS this installs to a
per-user location (`~/.local/bin`, no root required). On Windows this installs
system-wide to `C:\Program Files\flextunnel` and updates the machine PATH,
which **requires an elevated (Administrator) PowerShell session** — running
the installed binary afterward does not.

**`flextunnel` (server / client) — Linux / macOS:**

```sh
curl -sSL https://flexaccessdev.github.io/flextunnel/install.sh | bash
```

**`flextunnel` (server / client) — Windows (PowerShell):**

```powershell
irm https://flexaccessdev.github.io/flextunnel/install.ps1 | iex
```

Options: append `-s -- --prerelease` (bash) for the latest prerelease, a release
tag to pin a version, or `--download-only` / `-DownloadOnly` to fetch the binary
without installing. `-PreRelease` is also accepted by the Windows installer when
the selected prerelease includes a Windows asset. A container image is also
published to `ghcr.io/flexaccessdev/flextunnel`.

### Desktop app (tray GUI, client mode)

Stable releases also include the desktop client
(`flextunnel-desktop-macos-arm64.dmg` and
`flextunnel-desktop-windows-amd64.msi`). The installers are **unsigned** — if
you'd rather not apply the workarounds below, build it yourself instead:

```sh
cargo build --release -p flextunnel-desktop
# binary: target/release/flextunnel-desktop — locally built binaries are not
# quarantined, so no workaround is needed
```

That produces the bare executable, **not** a `.app` bundle — so on macOS it has
no `Info.plist` and will show a Dock icon instead of running as a pure menu-bar
app. For the proper bundle, build it the way CI does with `cargo-packager`
(macOS only; `app` gives `flextunnel.app`, `dmg` gives the drag-to-Applications
disk image):

```sh
cargo install cargo-packager   # or: cargo binstall cargo-packager
cargo packager --release -p flextunnel-desktop --formats app
# bundle: target/release/flextunnel.app  (locally built → not quarantined,
# so no Gatekeeper workaround needed; use --formats dmg for a .dmg instead)
```

Otherwise:

**macOS:** because the app is not notarized, Gatekeeper quarantines the
download and shows *"flextunnel" is damaged and can't be opened*.

The cleanest fix is to avoid the quarantine flag in the first place: browsers
set `com.apple.quarantine` on downloads, but command-line tools like `curl` and
`wget` do not. Download the disk image from the terminal instead:

```sh
# Replace vX.Y.Z with the release tag from the Releases page.
curl -fL -o flextunnel-desktop.dmg \
  https://github.com/flexaccessdev/flextunnel/releases/download/vX.Y.Z/flextunnel-desktop-macos-arm64.dmg
```

Then in Finder: double-click the `.dmg` to open it, drag `flextunnel.app` onto
the **Applications** shortcut in the window (choose **Replace** if an older copy
is already there), then eject the mounted image.

> **macOS zsh note:** the shell snippets in this README include `#` comment
> lines. zsh (the macOS default shell) treats `#` as a comment on an
> interactive prompt only after `setopt interactivecomments`; without it,
> pasting a `#` line reports `command not found`. Run `setopt interactivecomments`
> once per session, or just omit the comment lines when pasting.

If you already downloaded the `.dmg` via a browser, the quarantine flag
propagates to the app you copy out of it; remove it after installing (into
`/Applications`) instead:

```sh
xattr -cr /Applications/flextunnel.app
```

Alternatively, right-click the app and choose **Open** the first time.

**Windows:** SmartScreen's *"Windows protected your PC"* warning is triggered by
the Mark of the Web (the `Zone.Identifier` stream), which — like macOS
quarantine — is set by browsers but not by command-line tools. Avoid it the same
way: download with `curl.exe` (bundled in Windows 10+) or PowerShell instead of a
browser. Replace `vX.Y.Z` with the release tag from the Releases page:

```powershell
curl.exe -fL -o flextunnel-desktop.msi `
  https://github.com/flexaccessdev/flextunnel/releases/download/vX.Y.Z/flextunnel-desktop-windows-amd64.msi
# or: Invoke-WebRequest -OutFile flextunnel-desktop.msi `
#   https://github.com/flexaccessdev/flextunnel/releases/download/vX.Y.Z/flextunnel-desktop-windows-amd64.msi
```

If you already downloaded via a browser, strip the mark instead:
`Unblock-File .\flextunnel-desktop-windows-amd64.msi` (or right-click →
Properties → **Unblock**). Otherwise click **More info → Run anyway**.

## Build from source

```sh
cargo build --release
# binary: target/release/flextunnel
```

Requires a recent Rust toolchain (edition 2024). A bare `cargo build --release`
uses the workspace's default members and builds the CLI, but not
the iOS static library. To cross-build the CLI for Linux amd64 + arm64 via
Docker, use `./build-linux.sh`.

## Quick start

### 1. Generate credentials (once)

```sh
flextunnel generate-server-key -o server.key   # prints the server's EndpointId
flextunnel show-server-id --secret-file server.key   # re-print the EndpointId
flextunnel generate-auth-token                  # a client auth token
```

Keep `server.key` private (written `0600` on Unix). Share the **EndpointId**
and the **auth token** with clients.

### 2. Configure and run the server (no root needed)

The routed set is required and is configured in `server.toml`. This example is a
full tunnel; narrow it later with specific domains/CIDRs if you want split
tunneling.

```toml
secret_file = "./server.key"

# Accepted client auth tokens (prefix `ftc`, from `flextunnel generate-auth-token`).
# Within this config file, inline tokens and a token file combine.
auth_tokens = ["ftcXXXXXXX"]
# auth_tokens_file = "/etc/flextunnel/auth_tokens.txt"

routed_domains = ["*"]
routed_cidrs = ["0.0.0.0/0", "::/0"]

[host_aliases]
"server.internal" = "127.0.0.1"
```

```sh
flextunnel server start -c server.toml
```

It prints `flextunnel server Node ID: <ENDPOINT_ID>` — give that to clients.

### 3. Run the client (no root needed)

```sh
flextunnel client start \
    --server-node-id <ENDPOINT_ID> \
    --auth-token     <AUTH_TOKEN> \
    --socks-port     1080            # SOCKS5 on 127.0.0.1:1080 (loopback only)
```

### 4. Use it

Point any SOCKS5 client at `127.0.0.1:1080`. Use `socks5h://` so routed
hostnames reach flextunnel as names and are resolved on the server side:

```sh
# With the full-tunnel routed set above, DNS + connect happen server-side.
curl -x socks5h://127.0.0.1:1080 https://example.com

# a server-side host alias, for example server.internal -> 127.0.0.1
curl -x socks5h://127.0.0.1:1080 http://server.internal:8000/

# SSH through the proxy
ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:1080 %h %p' user@internal-host
```

#### Quick ephemeral tunnel (no setup)

For a throwaway "route everything through this box for a few minutes" session,
`--quick` skips all of the above — no key file, no token, no config:

```sh
# On the server host: mints an in-memory identity + client token, full-tunnels
# all traffic, and prints the two values to paste. Exits on its own if no client
# connects within 5 minutes. Nothing is persisted.
flextunnel server start --quick

# On the client host: ignores any saved config and prompts for the server
# EndpointId and auth token printed above (token entry is masked), then shows a
# live control panel in this terminal. Needs an interactive terminal.
flextunnel client start --quick
```

The quick server runs a full tunnel (`routed_domains = ["*"]`,
`routed_cidrs = ["0.0.0.0/0", "::/0"]`); enter a SOCKS5/HTTP port at the client
prompt to open a local proxy listener. Both sides are fully ephemeral: neither
takes the single-instance lock (so a quick session can run alongside a real one,
or another quick one), and both forget everything on exit.

The quick client is **self-contained**: after the prompt it runs the same live
panel as [`client control`](#client-control) right in that terminal — but it
opens **no control socket** (nothing else can attach to it), and quitting the
panel (`q`) **disconnects** the tunnel and exits, rather than detaching. Port
forwards added in the panel live in memory only and are never written to disk.

#### Server status page

From a connected client, `flextunnel.internal` is reserved by flextunnel and is
always tunneled to the server, regardless of the routed set. The browser view is
HTML; `/status.txt` is plain text and `/status.json` is structured JSON for
scripts:

```sh
# plain-text status through the default SOCKS5 listener
curl -sS -x socks5h://127.0.0.1:1080 http://flextunnel.internal/status.txt

# JSON status through the default SOCKS5 listener
curl -sS -x socks5h://127.0.0.1:1080 http://flextunnel.internal/status.json

# same endpoint through the optional HTTP proxy listener
curl -sS -x http://127.0.0.1:8081 http://flextunnel.internal/status.txt
curl -sS -x http://127.0.0.1:8081 http://flextunnel.internal/status.json
```

The JSON response includes `version`, `server_node_id`, `routed_domains`,
`routed_cidrs`, `host_aliases`, `dns_forwards`, `bridges`,
`inbound_bridges`, and duplicate-id blocklist counts under
`duplicate_id_blocklist`.

For more ways to use the proxy — `curl`/`git`/browser recipes, `ssh` through the
tunnel, and putting a plain local TCP port in front of it for apps that can't
speak SOCKS5 (databases, RDP, most GUIs) — see
[`docs/proxy-usage.md`](docs/proxy-usage.md).

#### HTTP proxy front-end (optional)

Add `--http-port <PORT>` to also run an HTTP proxy alongside SOCKS5 — useful
for the many tools that only speak an HTTP proxy or whose SOCKS5 support
resolves DNS client-side (`wget`, Docker pulls, npm/yarn, JVM/JDBC). It
handles HTTPS (and any TCP) via `CONNECT` tunneling and plain-HTTP via
absolute-URI forwarding; either way the hostname goes to the proxy, so DNS
still happens on the server.

```sh
flextunnel client start \
    --server-node-id <ENDPOINT_ID> \
    --auth-token     <AUTH_TOKEN> \
    --socks-port     1080 \
    --http-port      8081

# HTTPS tunnels via CONNECT; plain HTTP is forwarded
https_proxy=http://127.0.0.1:8081 curl https://example.com
http_proxy=http://127.0.0.1:8081  curl http://example.com
```

See [`docs/http-proxy-roadmap.md`](docs/http-proxy-roadmap.md) for the gap
analysis and what it doesn't cover (raw-TCP apps still need SOCKS5 or `socat`).

## Commands

| Command | Description |
|---|---|
| `server start` | Run the proxy server. |
| `client start` | Run the proxy client (optional SOCKS5 and HTTP proxy listeners, port forwards). |
| `client control` | Attach the terminal control panel to a running client. |
| `client help` | Show the client subcommands and their help. |
| `generate-server-key -o <FILE> [--force]` | Generate the server identity key. |
| `show-server-id --secret-file <FILE>` | Print the EndpointId for a key. |
| `generate-auth-token [-c N]` | Generate N client auth tokens (prefix `ftc`). |
| `generate-bridge-token [-c N]` | Generate N bridge auth tokens (prefix `ftb`). |

### `server start`

| Flag | Description |
|---|---|
| `-c, --config <FILE>` | Load options from a TOML file (CLI flags override it). |
| `--default-config` | Load `~/.config/flextunnel/server.toml`. |
| `--secret-file <FILE>` | Server identity key. |
| `--auth-token <TOKEN>` | Accepted client token (repeatable). |
| `--auth-tokens-file <FILE>` | File of accepted client tokens, one per line. |
| `--relay-url <URL>` | Custom relay URL(s) for failover (repeatable). Configuring custom relays disables n0 internet discovery: clients reach this server via relay hints, and outbound bridges attach the same hints when dialing peer servers. mDNS local discovery stays on. |
| `--relay-auth-token <TOKEN>` | Shared bearer token sent to every custom relay's WebSocket upgrade. Only valid with `--relay-url` (rejected with the default relays). |
| `--quick` | Ephemeral one-off server: mint an in-memory identity + client token, full-tunnel all traffic, print the EndpointId/token, and exit if no client connects within 5 minutes. Takes no single-instance lock; nothing is persisted. Conflicts with `-c`/`--secret-file`/`--auth-token(s)`. |

### `client start`

| Flag | Description |
|---|---|
| `-c, --config <FILE>` | Load options from a TOML file (CLI flags override it). Without it, `~/.config/flextunnel/client.toml` is used if present. |
| `-n, --server-node-id <ID>` | Server EndpointId. |
| `--socks-port <PORT>` | Optional SOCKS5 listener port, e.g. `1080`. Binds `127.0.0.1` only. Disabled unless set. |
| `--http-port <PORT>` | Optional HTTP proxy listener port (CONNECT + plain-HTTP forwarding). Binds `127.0.0.1` only. |
| `--auth-token <TOKEN>` / `--auth-token-file <FILE>` | Client auth token (one required). |
| `--relay-url <URL>` | Custom relay URL(s) for failover (repeatable). Configuring custom relays disables n0 internet discovery (the server is reached via relay hints); mDNS local discovery stays on. |
| `--relay-auth-token <TOKEN>` | Shared bearer token sent to every custom relay's WebSocket upgrade. Only valid with `--relay-url` (rejected with the default relays). |
| `--auto-reconnect` | Force auto-reconnect on (overrides `auto_reconnect = false` in the config). |
| `--no-auto-reconnect` | Exit on the first disconnection instead of reconnecting. |
| `--max-reconnect-attempts <N>` | Cap reconnect attempts between successful connections (unlimited if unset). |
| `--quick` | Self-contained ephemeral session (pairs with `server start --quick`): ignore any saved config, prompt for the server EndpointId + auth token, then run the live control panel in this terminal. Needs an interactive terminal. Takes no lock and opens no control socket; quitting the panel disconnects. Nothing is persisted. Conflicts with `-c`. |

`flextunnel client start` needs at least one flag — run with no arguments and it
prints help. With a flag but no `-c`, it loads `~/.config/flextunnel/client.toml`
if it exists (so `flextunnel client start --socks-port 1080` runs off the default
config). `--quick` ignores any saved config and prompts (on an interactive
terminal) for the server EndpointId, auth token, and optional proxy ports, then
runs the self-contained control panel described under [`client control`](#client-control)
right in that terminal — but with no control socket exposed, and quitting the
panel disconnects instead of detaching. Nothing is saved.

With neither `--socks-port` nor `--http-port` (nor the config keys) the
client runs in **port-forward-only mode**: it holds the tunnel and serves only
the control panel and any enabled port forwards.

A client's on-disk identity — the single-instance lock, the control socket,
and the persisted port forwards — is keyed by the prefix of its
`server_node_id` (which never changes for a profile). So one client runs per
server per user, and clients for different servers coexist without any extra
configuration. The optional `name` key in the config ("aws", "home network")
is a display-only label shown in the control panel. (A `--quick` client is
exempt: it takes none of these — no lock, no socket, no forwards file.)

### `client control`

```sh
flextunnel client control                # profile from ~/.config/flextunnel/client.toml
flextunnel client control -c aws.toml    # profile from a specific config
flextunnel client control -n <ENDPOINT_ID>   # or by server id directly
```

Attaches a terminal control panel to the **running** client for a profile,
over its control socket (`~/.config/flextunnel/client-<server id prefix>.sock`;
a named pipe on Windows). It shows live status — connection phase and uptime,
server/client node ids, connection paths (direct/relay), and the server-pushed
routing breakdown (split-tunnel rules, host aliases, DNS forwards, and bridge
routes) — plus an editable **port forwards** table: add/edit/delete
forwards and toggle them on/off (`space`), live.

Forwards open server-direct streams on the authenticated connection (the
server enforces its routed set) and listen on localhost. They persist in
`~/.config/flextunnel/forwards-<server id prefix>.json` — written only by the
running client — and always load **disabled**; enabling is a per-session
action, like the desktop app. A forward whose local port can't bind flips back
off with the reason shown next to its row.

Detaching (`q`) never affects the tunnel; several panels can attach at once.

## Configuration files

Instead of passing everything on the command line, `server start` and
`client start` can read a TOML file:

```sh
flextunnel server start -c server.toml
flextunnel client start -c client.toml
flextunnel client start --socks-port 1080  # loads ~/.config/flextunnel/client.toml
```

Precedence is **CLI flag > config file > built-in default**, so you can keep a
file and override settings on the command line. Credential groups are replaced
as a unit: for example, if the CLI supplies either `--auth-token` or
`--auth-token-file`, the config file's client token fields are ignored. Unknown
or misspelled keys are rejected (`deny_unknown_fields`) rather than silently
ignored. Paths support `~` expansion.

See [`server.toml.example`](server.toml.example) and
[`client.toml.example`](client.toml.example) for the full set of keys. A minimal
client file:

```toml
server_node_id = "<server endpoint id>"
socks_port     = 1080          # SOCKS5 on 127.0.0.1:1080 (loopback only)
auth_token     = "ftc…"        # or: auth_token_file = "~/.config/flextunnel/token.txt"
```

Secrets may be inline (as above) or kept in separate files via the `*_file`
keys. CLI flags still work and override any of these.

Server-only routing keys include `host_aliases`,
`dns_forwards`, outbound `[bridges.<name>]`, inbound `allowed_bridge_servers`,
and `bridge_auth_tokens` / `bridge_auth_tokens_file`; these are config-file only
because they describe the server's routing policy.

## Host aliases (server-side)

The server config can map hostnames to addresses on its own network, so a client
can reach the server's loopback or internal hosts by a real name. Add a
`[host_aliases]` table to `server.toml` (config-file only — there is no CLI flag):

```toml
[host_aliases]
"server.internal" = "127.0.0.1"      # the server's own loopback
"node2.internal"  = "192.168.1.50"   # another host on the server's network
```

When a requested hostname matches a key (case-insensitive), the server rewrites
it to the value — an IP or another hostname — keeping the requested port, then
resolves and connects like any other target. Only domain targets are aliased;
literal IPs pass through unchanged.

This is also the clean way around Firefox refusing to proxy literal
`localhost` / `127.0.0.1`: alias `server.internal` → `127.0.0.1` on the server and
browse to `http://server.internal:8000/`. Use `socks5h://` (or set Firefox's
`network.proxy.socks_remote_dns = true`) so the name is resolved by the server,
not locally.

## Routed-set split-tunneling

The routed set (the **tunnel set**) is a VPN-style split-tunnel "included routes"
list that decides which destinations traverse the tunnel. Targets not on it are
**not** rejected — the client falls back to a direct connection for them. It is
useful when a client must send *all* its traffic to the local SOCKS5 proxy (e.g.
an iOS WebView, whose proxy config is global) but only some hosts should actually
be tunneled. It is **required** and configured on the **server only** (config-file
only — there is no CLI flag); the client configures nothing:

```toml
# server.toml
routed_domains = ["*.example.com", "httpbin.org"]
routed_cidrs   = ["10.0.0.0/8", "192.168.1.5"]
```

The tunnel set is required: a server started with an empty set **refuses to
start**, and a client that receives an empty set from a (misconfigured or old)
server **aborts the handshake** rather than silently direct-connecting
everything. To route **all** traffic through the tunnel (full tunnel), use the
catch-alls:

```toml
routed_domains = ["*"]
routed_cidrs   = ["0.0.0.0/0", "::/0"]
```

The server is the single source of truth. It **pushes** the list to every client
in the handshake response, so there is no client list to keep in sync:

- **Client** — on connect it learns the server's list. It tunnels only matching
  targets and connects everything else **directly** from its own network
  (split-tunneling). The direct path is independent of the tunnel, so off-list
  targets keep connecting even while the tunnel is down; an on-list target during
  a drop/backoff gets a SOCKS5 network-unreachable reply (`0x03`) rather than
  hanging.
- **Server** — it also enforces the same list independently as a **whitelist**,
  **rejecting** any tunnel request for a target not on it (SOCKS5 reply `0x02`).
  This is a defense-in-depth boundary against a misconfigured or untrusted
  client. (Note the asymmetry: the client falls back to a direct connection for
  off-list targets, whereas the server rejects them outright.)

Matching: domain entries are exact (`example.com`), wildcard (`*.example.com`,
which matches subdomains only — not the bare apex), or `*` (matches every
hostname), case-insensitive; CIDR entries match IP targets, accept a bare IP as a
single host, and a default route (`0.0.0.0/0` / `::/0`) matches every IP.
Hostnames are matched only against `routed_domains` and IPs only against
`routed_cidrs`. A numeric IP literal is always gated by `routed_cidrs` even
when a client sends it in hostname form (SOCKS5 `ATYP_DOMAIN`), so `*` never lets
a raw IP through — it can only route real hostnames.

Only the **combined** set must be non-empty — setting just one list is fine. The
two never cross: an omitted/empty list means that whole category is off-list and
always direct-connected. So `routed_domains` alone (no `routed_cidrs`)
tunnels those hostnames but direct-connects every bare-IP target, and
`routed_cidrs` alone tunnels those IPs but direct-connects every hostname.

### Roadmap

- **Client blocking mode.** Today the client **always direct-connects** every
  off-list target (split-tunneling), and this is
  the same for the desktop and iOS clients (they share the same core). A future
  client option — likely `routed_mode = "block" | "direct"` (default
  `"direct"`) — will let a client instead **refuse** an off-list connection,
  returning a SOCKS5 error to the local app rather than falling back to a direct
  connection. This is aimed mainly at the desktop client, where blocking off-list
  traffic can be preferable to letting it leak out directly; the iOS client keeps
  defaulting to direct-connect. (The server's `0x02` rejection above is a
  separate, server-side control and is unaffected.)

## Reconnect behavior

Auto-reconnect is **enabled by default** (`auto_reconnect = true`); pass
`--no-auto-reconnect` (or set `auto_reconnect = false`) to disable it, and
`--auto-reconnect` to force it on over a config that disabled it.

- The **first** connection must succeed. If it fails — bad node id, wrong
  relay, server down, or a rejected token — the client **exits immediately**
  rather than retrying blindly.
- Once connected at least once, a transient drop triggers reconnection with
  **exponential backoff + jitter** (1s → 60s), indefinitely, unless
  `--max-reconnect-attempts` caps it or auto-reconnect is disabled.
- A permanent error (auth/config) never retries.
- The local proxy listeners stay bound across reconnects. Off-list targets keep
  connecting directly; on-list requests fail immediately with a network-unreachable
  reply until the tunnel recovers.

## Logging

Logging uses `env_logger`. The default is `info` with iroh/tracing quieted to
`warn`. Override with `RUST_LOG`, e.g. `RUST_LOG=flextunnel=debug`.

## Documentation

- [iroh-common-architecture](https://github.com/flexaccessdev/iroh-common-architecture) —
  the iroh transport layer shared with [tunnel-rs](https://github.com/andrewtheguy/tunnel-rs)
  and [ezvpn](https://github.com/flexaccessdev/ezvpn):
  [relays and address lookup](https://github.com/flexaccessdev/iroh-common-architecture/blob/main/relays-and-address-lookup.md)
  (default vs custom relays, relay hints, the per-relay startup probe, relay auth
  tokens) and
  [self-hosting](https://github.com/flexaccessdev/iroh-common-architecture/blob/main/self-hosting.md)
  (running your own iroh relay).
- [`docs/architecture.md`](docs/architecture.md) — how it works: connection
  lifecycle (fixed ALPN, auth handshake, per-stream protocol), module map,
  concurrency model, reconnect policy, security boundaries, and reference
  constants.
- [`docs/http-proxy-roadmap.md`](docs/http-proxy-roadmap.md) — the HTTP proxy
  front-end (CONNECT tunneling + absolute-URI forwarding): motivation, design,
  and remaining hardening work.
- [`docs/proxy-usage.md`](docs/proxy-usage.md) — using the SOCKS5 and HTTP
  proxies: which listener a tool needs, native SOCKS5 clients (`curl`, `git`,
  browsers), HTTP-proxy-only tools (`wget`, Docker, JVM/JDBC), `ssh`
  through the tunnel, and `socat`/`ssh -L`/`-D` forwards for apps that speak
  neither.

## How it relates to ezvpn

flextunnel is modeled on the sibling project **ezvpn** (an IP-over-QUIC VPN),
reusing its iroh transport, auth-token scheme, and secret-key
identity. The difference: ezvpn creates a TUN device and ships IP packets over
unreliable QUIC datagrams (and needs root); flextunnel exposes SOCKS5/HTTP proxy
listeners and tunnels TCP over reliable QUIC streams (and needs no root).
