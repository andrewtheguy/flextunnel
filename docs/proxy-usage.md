# Using the flextunnel proxies

The flextunnel client exposes up to two local proxy listeners, both sharing the
same routing core:

- an optional **SOCKS5** listener (`--socks-port 1080`); and
- an optional **HTTP proxy** listener (`--http-port 8081`).

Each is off unless you enable it, and each binds `127.0.0.1` only — the
listeners are unauthenticated, so they are never exposed beyond the local
machine (this guide's examples assume SOCKS5 on `127.0.0.1:1080`). With
neither enabled the client runs in port-forward-only mode.

Which one you point a tool at depends only on what that tool can speak — the
client applies the server-pushed tunnel set after parsing the request. On-list
targets are tunneled over the QUIC connection; off-list targets are connected
directly from the client device. For on-list targets, the server sees the same
wire `Target` either way and does not care which local front-end you used. This
guide covers, in order:

1. **The one rule** — always let the *server* resolve names.
2. **Which listener to use** — SOCKS5 vs HTTP proxy, and when only one works.
3. **Programs that speak SOCKS5 natively** — `curl`, `git`, `kubectl`, `ssh`,
   browsers, and other common tools.
4. **Programs that need the HTTP proxy** — tools that can't speak SOCKS5 at
   all, or whose SOCKS5 support resolves DNS client-side (which breaks routed
   internal names): `wget`, Docker, JVM/JDBC, and the generic
   `https_proxy=` path.
5. **`ssh` through the proxy** — reach an internal SSH host, then use SSH's own
   `-L` / `-D` forwards for a second hop.
6. **Adapters for programs that don't speak either proxy** — put a plain local
   TCP port in front of the proxy with `socat` (databases, RDP, JDBC natives).

## The one rule: let the server resolve names

flextunnel's whole point is that DNS and the outbound connection for **routed**
targets happen on the **server's** network. The server only accepts targets in
its `routed_domains` / `routed_cidrs` tunnel set and maps some names via
`[host_aliases]` (e.g. `networking.internal` -> `127.0.0.1` on the server).
Those names usually **do not resolve on the client at all**.

The tunnel set is pushed to the client during the handshake. Anything outside
that set is direct-connected from the client, so add every internal hostname or
alias you intend to route to `routed_domains`; add literal IP destinations to
`routed_cidrs` only when you really want those IPs tunneled.

By default the server resolves those names through its own system resolver. If
some internal names are only known to a specific (e.g. internal) DNS server, add
a `[dns_forwards]` entry: names under a configured suffix are then resolved via
that suffix's upstream DNS server instead of the system resolver, with everything
else unchanged. For example, `"local.168234.xyz" = ["10.0.0.53"]` sends
`local.168234.xyz` and its subdomains to `10.0.0.53:53`. This is server-side
only — the client still just sends the hostname (`socks5h` / HTTP proxy). The
suffix must be on the tunnel set (`routed_domains`), since the whitelist is
enforced on the requested hostname before resolution — the server refuses to
start if a forward suffix is not covered (it would be a no-op). See
`server.toml.example`.

So whatever you use must send the target **hostname** to the proxy and let
flextunnel resolve it. The two front-ends reach this differently:

- **HTTP proxy** — sends the hostname to flextunnel (`CONNECT host:port` or an
  absolute-URI `GET http://host/...`), so DNS happens server-side for on-list
  targets with no extra configuration. There is no SOCKS-style client-DNS
  footgun here.
- **SOCKS5** — *can* resolve either at the client or at the proxy, and the
  default in many tools is the wrong one. You want the `socks5h` behavior (the
  `h` means "resolve host at the proxy"). Never pre-resolve the name to an IP on
  the client, and don't attach a client-side resolver.

The single most common mistake is using `socks5://` (client-side DNS) where you
want `socks5h://` (proxy-side DNS). With flextunnel, **you almost always want
the `h`.** This mistake is impossible with the HTTP proxy, which is one reason
to prefer it for tools whose SOCKS5 support is client-DNS-only (see below).

## Which listener to use

| Your tool… | Use |
|---|---|
| speaks SOCKS5 with remote DNS (`socks5h`) — curl, ssh, browsers, apt | **SOCKS5** `127.0.0.1:1080` |
| needs raw TCP — databases, RDP, native JDBC | **SOCKS5** (or a `socat` forward; see "Adapters for programs that don't speak either proxy") |
| only speaks an HTTP proxy — `wget`, Docker pulls | **HTTP proxy** `127.0.0.1:8081` |
| speaks SOCKS5 but only with **client-side** DNS — JVM `socksProxyHost` | **HTTP proxy** (client DNS can't resolve routed names) |

The HTTP proxy handles **HTTPS and any TCP** via `CONNECT` tunneling and
**plain HTTP** via absolute-URI forwarding. What it *cannot* do is carry a
protocol that isn't HTTP: a database wire protocol, RDP, or SSH does not speak
HTTP `CONNECT`, so those still go through SOCKS5 or a `socat` forward. The HTTP
proxy *complements* SOCKS5; it doesn't replace it.

Enable the HTTP proxy by adding `--http-port` when you start the client.
SOCKS5 is not on by default — keep `--socks-port` too if you also want it:

```sh
flextunnel client start \
    --server-node-id <ENDPOINT_ID> \
    --auth-key-file  client.key \
    --socks-port     1080 \
    --http-port      8081
```

## Programs that speak SOCKS5 natively

### `curl`

```sh
# For an on-list target, DNS + connection happen server-side (note socks5h)
curl -x socks5h://127.0.0.1:1080 https://example.com

# a host alias defined on the server, for example networking.internal -> 127.0.0.1
curl -x socks5h://127.0.0.1:1080 http://networking.internal/

# flextunnel server status, as plain text
curl -sS -x socks5h://127.0.0.1:1080 http://flextunnel.internal/status.txt

# flextunnel server status, as JSON
curl -sS -x socks5h://127.0.0.1:1080 http://flextunnel.internal/status.json
```

You can also set it for a whole shell session via the standard proxy env vars
(most tools built on libcurl honor these):

```sh
export ALL_PROXY=socks5h://127.0.0.1:1080
curl https://example.com
```

`http://flextunnel.internal/` is the HTML status page; `/status.txt` is the
script-friendly text form; `/status.json` is the structured JSON form. The JSON
response includes `version`, `server_node_id`, `routed_domains`,
`routed_cidrs`, `host_aliases`, `dns_forwards`, `bridges`,
`inbound_bridges`, and duplicate-id blocklist counts under
`duplicate_id_blocklist`. These names are reserved by flextunnel and are always
tunneled, even when they are not in the server's routed set. If the client is
also running the HTTP proxy front-end, query the same endpoints through it
instead:

```sh
curl -sS -x http://127.0.0.1:8081 http://flextunnel.internal/status.txt
curl -sS -x http://127.0.0.1:8081 http://flextunnel.internal/status.json
```

### `git`

Git routes differently depending on the remote's transport — this catches
people out:

| Remote type | How to route through flextunnel |
|---|---|
| `http://` / `https://` | `ALL_PROXY` (git's libcurl transport honors it) |
| `ssh://` / `git@host:…` | SSH `ProxyCommand` — **`ALL_PROXY` is ignored** |

**HTTP(S) remotes** — `ALL_PROXY` works:

```sh
ALL_PROXY=socks5h://127.0.0.1:1080 git clone https://networking.internal/repo.git
```

Make it permanent for a host:

```sh
git config --global http.https://networking.internal/.proxy socks5h://127.0.0.1:1080
```

**SSH remotes** — `ALL_PROXY` does *nothing* here; git shells out to `ssh`,
which does its own DNS and would fail with `Could not resolve hostname`. Route
through SSH's `ProxyCommand` instead:

```sh
GIT_SSH_COMMAND='ssh -o "ProxyCommand=nc -X 5 -x 127.0.0.1:1080 %h %p"' \
  git clone ssh://networking.internal/repo.git
```

Or make it permanent in `~/.ssh/config` (see "`ssh` through the proxy") so plain
`git clone ssh://networking.internal/repo.git` just works:

```
Host networking.internal
    ProxyCommand nc -X 5 -x 127.0.0.1:1080 %h %p
```

### `kubectl` (inline `proxy-url` in kubeconfig)

`kubectl` (and any client-go–based tool) can route a **single cluster's** API
traffic through a proxy declared inline in the kubeconfig, via the
`proxy-url` field under `clusters[].cluster`. SOCKS5 support for this field is
**stable since Kubernetes 1.24** — that release also fixed `kubectl exec`,
which was the one subcommand that didn't work through a SOCKS proxy before. This
is the preferred pattern: it scopes the proxy to just the one cluster context,
and a kubeconfig `proxy-url` takes precedence over the global `HTTPS_PROXY`
environment variable (which would otherwise proxy *every* context).

Use the `socks5h://` scheme so flextunnel resolves the API server's hostname
server-side — the same "let the server resolve names" rule as everywhere else.
The `server:` host must be a name the flextunnel **server** can resolve and
reach, and it must be on the tunnel set (a `routed_domains` entry or a
`[host_aliases]` name that is also listed in `routed_domains`):

```yaml
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://k8s.internal:6443
    proxy-url: socks5h://127.0.0.1:1080   # flextunnel resolves k8s.internal
    certificate-authority-data: LS0tLS1C…  # shortened
  name: internal
contexts:
- context:
    cluster: internal
    user: internal
  name: internal
current-context: internal
users:
- name: internal
  user:
    client-certificate-data: LS0tLS1C…    # shortened
    client-key-data: LS0tLS1C…            # shortened
```

`proxy-url` also accepts `http://` — point it at the HTTP proxy front-end
(`proxy-url: http://127.0.0.1:8081`) if that fits your tooling better; kubectl
sends the API server hostname to an HTTP proxy, so DNS still happens
server-side for on-list targets there too. Plain `socks5://` (no `h`) would
resolve `k8s.internal` on the client and fail — use `socks5h://`.

> Note the DNS semantics: with `socks5h://`, a `server:` of
> `https://localhost:6443` means *the flextunnel server's* localhost, not your
> laptop's — the whole point when the API server sits on the server's network.

### Web browsers

Point the browser's SOCKS proxy at `127.0.0.1:1080` **with remote DNS enabled**
so on-list hostnames resolve on the server:

- **Firefox** — set a manual SOCKS v5 proxy of `127.0.0.1:1080` in its network
  settings, and enable the option to proxy DNS through SOCKS v5 so hostnames
  for tunneled targets resolve on the server rather than locally.
- **Chrome / Chromium** — configure a SOCKS5 proxy of `127.0.0.1:1080` (Chrome
  sends the hostname to the proxy, so DNS happens server-side for on-list
  targets).

A browser can also use the HTTP proxy on `127.0.0.1:8081` instead — it sends the
hostname either way, so DNS still happens server-side for on-list targets. For
per-site control instead of a system-wide switch, a browser extension like
FoxyProxy lets you route only the internal domains through the proxy.

#### FoxyProxy (per-site routing)

FoxyProxy (Firefox / Chrome extension) routes only the domains you list through
flextunnel and leaves everything else on your normal connection. Add a proxy
entry:

- **Type**: `SOCKS5`
- **Hostname / Port**: `127.0.0.1` / `1080` (or whatever `--socks-port` you run
  the client with)
- **Proxy DNS**: **on** — this is the `socks5h` equivalent; without it the
  browser resolves the routed names locally and fails. Per-proxy and
  per-request: it only applies to requests matched to this proxy entry —
  DNS for everything else is untouched. Firefox-only; in Chrome the toggle is
  grayed out because Chrome always sends the hostname to a SOCKS5 proxy
  (i.e. it's permanently "on")
- **Username / Password**: leave empty (the listener is unauthenticated)

Then add one **Include** pattern per routed name, e.g.:

| Include | Type | Pattern |
|---|---|---|
| Include | Wildcard | `*.proxkube.internal` |
| Include | Wildcard | `flextunnel.internal` |

Finally, **enable pattern mode**: click the FoxyProxy toolbar icon and select
**Proxy by Patterns**. The extension starts out disabled — with it set to
Disable (or pinned to a single proxy), the patterns you just saved are not
consulted at all.

`*.example.internal` matches the subdomains; add a second bare
`example.internal` pattern if you also browse the apex name. A
`flextunnel.internal` pattern is handy to keep the server status page
(`http://flextunnel.internal/`) reachable. Requests that match no pattern
bypass the proxy entirely, so off-list browsing is untouched even before
flextunnel's own routing decision.

An HTTP-proxy entry (`Type: HTTP`, `127.0.0.1:8081`) works with the same
patterns too — no Proxy DNS toggle needed there, since an HTTP proxy always
receives the hostname.

> Firefox with DNS-over-HTTPS enabled may resolve names via DoH even when
> Proxy DNS is on; routed internal names then fail to resolve (they don't
> exist in public DNS). If that bites, exempt the internal suffixes from DoH
> or lower the DoH protection level.

> These browser paths were not tested here; verify the exact settings in your
> browser version.

### Other tools worth knowing

- **`nc` (OpenBSD netcat)** — `nc -X 5 -x 127.0.0.1:1080 host port` dials
  through SOCKS5 (used as the SSH `ProxyCommand` below).
- **`proxychains-ng`** — wraps programs that have no proxy option of their own
  by hooking libc. Point it at `127.0.0.1:1080`. It can miss statically linked
  or Go binaries, where a `socat` port forward is more reliable. (Not tested
  here.)
- **Package managers / language toolchains** (`pip`, `npm`, `cargo`, `apt`)
  generally honor the `ALL_PROXY` / `https_proxy` environment variables. `apt`
  understands `socks5h://` directly; for the others, if the SOCKS path needs an
  extra plugin (see the `pip` note below), the HTTP proxy is the simpler route.
  (Not tested here — consult each tool's proxy docs.)

## Programs that need the HTTP proxy

These are the cases the SOCKS5 listener alone cannot serve — either the tool has
no SOCKS5 support, or its SOCKS5 support resolves DNS on the client, which can't
resolve flextunnel's routed names. Start the client with `--http-port`
(section "Which listener to use") and point the tool at
`http://127.0.0.1:8081`. The HTTP proxy sends the hostname to the proxy, so the
server still resolves it.

The generic pattern — the standard proxy env vars, which a large number of tools
honor:

```sh
export https_proxy=http://127.0.0.1:8081
export http_proxy=http://127.0.0.1:8081
curl https://example.com          # HTTPS → CONNECT tunnel
curl http://networking.internal/  # plain HTTP → absolute-URI forwarding
```

### `wget` — no SOCKS support, but HTTP proxy works

GNU `wget` (tested with 1.25.0) **cannot use a SOCKS5 proxy** — its `*_proxy`
variables only accept HTTP/HTTPS proxies, so pointing them at the SOCKS listener
fails immediately:

```sh
$ https_proxy=socks5h://127.0.0.1:1080 wget http://networking.internal/
Error parsing proxy URL socks5h://127.0.0.1:1080: Unsupported scheme.
```

With the HTTP proxy front-end this is exactly what `wget` wants — no `socat`
workaround needed:

```sh
https_proxy=http://127.0.0.1:8081 http_proxy=http://127.0.0.1:8081 \
  wget http://networking.internal/file
```

### JVM tools (Gradle, JDBC over HTTP, anything using `socksProxyHost`)

The JVM *does* support SOCKS5, but it resolves the hostname on the **client**
(`-DsocksProxyHost`), so a routed name like `networking.internal` fails to
resolve even though "SOCKS is supported." Use the JVM's HTTP proxy properties
against the HTTP listener instead, which sends the hostname to the proxy:

```sh
java -Dhttp.proxyHost=127.0.0.1  -Dhttp.proxyPort=8081 \
     -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=8081 \
     -jar app.jar
```

(A JDBC *native* wire protocol is not HTTP and cannot use either the JVM HTTP
proxy or CONNECT — route those through `socat`; see "Adapters for programs that
don't speak either proxy.")

### Docker, npm/yarn, and other HTTP-only clients

- **Docker** daemon and `docker build` base-image pulls speak HTTP/HTTPS proxies
  only. Configure the daemon with `HTTPS_PROXY=http://127.0.0.1:8081` in its
  environment or daemon configuration. `~/.docker/config.json` instead injects
  proxy environment variables and build arguments into new containers and build
  steps; it does not configure daemon image pulls.
- **npm / yarn** — `npm config set proxy http://127.0.0.1:8081` and
  `https-proxy` likewise, or the `https_proxy` env var.
- **Python `requests` / `pip`** — the HTTP proxy works out of the box
  (`https_proxy=http://127.0.0.1:8081`). SOCKS5 support requires the extra
  `requests[socks]` / PySocks install, so the HTTP proxy is the lower-friction
  path.

### Caveat: one request per upstream connection

The plain-HTTP forwarding path opens a fresh tunnel per request and forces
`Connection: close`, so keep-alive reuse across requests doesn't happen — a
client that tries to reuse the socket sees a clean close and retries on a new
connection. This is transparent to well-behaved clients but shows up as extra
connection churn under high plain-HTTP request rates. HTTPS (`CONNECT`) tunnels
are unaffected — they carry a single long-lived stream. `https://` URLs always
go over `CONNECT` automatically; you never send them as absolute-URI forwards.

## `ssh` through the proxy

SSH is a raw-TCP protocol — it does not speak HTTP `CONNECT`, so route it
through **SOCKS5**, not the HTTP proxy. To reach an SSH server that only listens
on the flextunnel server's network, run SSH's connection *through* the proxy
with a `ProxyCommand`. OpenBSD `nc` (`netcat`) speaks SOCKS5 with `-X 5 -x`:

```sh
ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:1080 %h %p' user@workstation.internal
```

`%h`/`%p` expand to the target host/port; `nc` sends `%h` as a hostname to the
proxy, so flextunnel resolves `workstation.internal` server-side.

Make it permanent in `~/.ssh/config` so plain `ssh workstation` just works (and
so `git@workstation:…` remotes route through the tunnel too):

```
Host workstation
    HostName workstation.internal
    User user
    ProxyCommand nc -X 5 -x 127.0.0.1:1080 %h %p
```

### Combine with SSH's own forwards

Once the SSH session rides the tunnel, you get SSH's forwarding for free — a
second hop *from the SSH host's* network:

```sh
# Local forward: localhost:5432 -> db.internal:5432, as seen from workstation.internal
ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:1080 %h %p' \
    -L 127.0.0.1:5432:db.internal:5432 user@workstation.internal

# Dynamic (SOCKS) forward: a second SOCKS5 proxy scoped to the SSH host's network
ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:1080 %h %p' \
    -D 127.0.0.1:1081 user@workstation.internal
```

Here `db.internal` is resolved by `workstation.internal`, not by flextunnel —
useful for reaching hosts that the flextunnel server itself can't see but the
SSH box can.

## Adapters for programs that don't speak either proxy

Database clients, RDP, JDBC native drivers, `psql`, and many GUI apps have no
SOCKS5 option and don't speak HTTP `CONNECT` either. Put `socat` in front of the
proxy to present a **plain local TCP port** that forwards through it.

`socat`'s `SOCKS5-CONNECT` address dials a target *through* the SOCKS5 proxy and
sends the target as a **domain name** (it emits SOCKS5 `ATYP=DOMAIN`, so
flextunnel resolves it server-side).

Address form:

```
SOCKS5-CONNECT:<socks-host>:<socks-port>:<target-host>:<target-port>
```

Example — expose the server-side `networking.internal:80` as a local
`http://localhost:8080/`:

```sh
socat TCP-LISTEN:8080,bind=127.0.0.1,reuseaddr,fork \
      SOCKS5-CONNECT:127.0.0.1:1080:networking.internal:80
```

Then, with the flextunnel client running:

```sh
curl http://localhost:8080/
# or open http://localhost:8080/ in a browser
```

Example — expose a server-side Postgres as a local port:

```sh
socat TCP-LISTEN:5432,bind=127.0.0.1,reuseaddr,fork \
      SOCKS5-CONNECT:127.0.0.1:1080:nas.internal:5432
# then: psql -h 127.0.0.1 -p 5432 …
```

Options that matter:

- **`fork`** — serve each incoming connection in its own child. Without it
  `socat` handles one connection and exits; browsers and most clients open
  several in parallel, so `fork` is effectively required.
- **`reuseaddr`** — lets you restart immediately without "address already in
  use".
- **`bind=127.0.0.1`** — keep the forward loopback-only. Drop it
  (`TCP-LISTEN:5432,reuseaddr,fork`) only if you deliberately want other
  machines on your LAN to reach it.
- **`SOCKS5`** is just an alias for `SOCKS5-CONNECT`.
- Add `-d -d` for verbose logs when debugging; `-T5` sets an idle timeout so
  stuck streams drop.

### Caveat: HTTP `Host` header

When you browse to `http://localhost:8080/`, the browser sends
`Host: localhost:8080`. A server that vhosts on `networking.internal` may not
match. Either send the header explicitly:

```sh
curl -H 'Host: networking.internal' http://localhost:8080/
```

…or skip the port forward entirely and use a proxy path that preserves the real
hostname — SOCKS5:

```sh
curl -x socks5h://127.0.0.1:1080 http://networking.internal:8080/
```

…or the HTTP proxy (which regenerates `Host` from the request URI):

```sh
curl -x http://127.0.0.1:8081 http://networking.internal:8080/
```

(or point the browser's SOCKS proxy at `127.0.0.1:1080` with remote DNS
enabled).

### `socat` vs `ssh`

- **`socat`** needs no account on the target — just the flextunnel proxy. Best
  for exposing a single service port (DB, web, RDP) to a local app.
- **`ssh`** needs an SSH account on a reachable host, but then gives you a
  shell plus arbitrary `-L`/`-D` forwards and an extra network hop.
