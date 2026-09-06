# Running the CLI client under systemd

The CLI client is strictly **one process per server**: a `client.toml` holds a
single `server_node_id`, and that id's prefix keys the client's on-disk
identity — the single-instance lock, the control socket, and the persisted
port forwards — so clients for different servers coexist with no extra
configuration. The natural systemd shape for that is a **template unit**: one
`flextunnel-client@<name>` instance per server, each reading its own config
file. (This mirrors what the desktop app does inside one process — one
independent session per connected profile — the CLI just packages each session
as its own process.)

Everything here is a **user** unit; the client needs no root.

## Setup

One config file per server, named after the instance:

```
~/.config/flextunnel/aws.toml
~/.config/flextunnel/home.toml
```

Each is an ordinary client config (see
[`client.toml.example`](../client.toml.example)); the optional `name` key is a
good place to repeat the instance name so control panels and statuses label
themselves. Profiles can share one `auth_key_file` — the server side
authorizes the key, not the profile.

The template unit, at `~/.config/systemd/user/flextunnel-client@.service`:

```ini
[Unit]
Description=flextunnel client (%i)

[Service]
ExecStart=%h/.local/bin/flextunnel client start -c %h/.config/flextunnel/%i.toml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
```

Then:

```sh
systemctl --user daemon-reload
systemctl --user enable --now flextunnel-client@aws flextunnel-client@home

# Start at boot instead of at first login, and survive logout:
loginctl enable-linger "$USER"
```

## Why `Restart=on-failure` is the whole restart policy

The client already supervises itself where it matters:

- After the **first** successful connection, auto-reconnect (on by default)
  retries transient drops internally with exponential backoff, indefinitely.
  Reconnects that keep failing escalate every third attempt to rebuilding the
  iroh endpoint from scratch — the in-process equivalent of a unit restart,
  covering wedges (a dead relay link, stale path state) that only a fresh
  endpoint repairs. The process does not exit, so systemd never gets involved.
  Don't disable `auto_reconnect` or set `max_reconnect_attempts` under
  systemd — that just replaces the client's backoff with unit restarts, which
  re-bind listeners and drop held proxy requests.
- The client **exits nonzero** when the *first* connection fails (server down,
  network not up yet at boot) and on permanent auth/config errors.
  `Restart=on-failure` + `RestartSec` covers the boot-time window where the
  network isn't ready — there's no user-manager `network-online.target` to
  order against, and none is needed.

The one wrinkle: a **permanent** error (bad node id, rejected key, malformed
config) also exits nonzero, so systemd will keep retrying it every
`RestartSec`. That's harmless but noisy — if an instance is flapping, read the
reason with `journalctl --user -u flextunnel-client@<name>`.

## Interacting with a running instance

The control panel attaches over the client's control socket, which is keyed by
the server id — systemd isn't involved:

```sh
flextunnel client control -c ~/.config/flextunnel/aws.toml
```

The `-c` is not optional here: a bare `flextunnel client control` reads only
`~/.config/flextunnel/client.toml`, which this layout deliberately does not
have — each instance's profile is `<instance>.toml`. (Running it bare says so,
and lists the profile files it found.) `-n <server EndpointId>` attaches
without any config file.

Detaching (`q`) never affects the tunnel. Port forwards edited there persist
per server (`~/.config/flextunnel/forwards-<server id prefix>.json`) but
always load **disabled**; enabling is a per-session action, so a unit restart
comes up with all forwards off.

## Duplicate configs

Pointing two instance configs at the same `server_node_id` is the
misconfiguration the single-instance lock exists to catch: the second instance
fails to start (and, under `Restart=on-failure`, keeps retrying until the
first stops). Fix the config rather than relying on that takeover behavior.

## Logging

Logging goes to stderr and lands in the journal:

```sh
journalctl --user -u flextunnel-client@aws -f
```

Raise verbosity per instance with a drop-in
(`systemctl --user edit flextunnel-client@aws`):

```ini
[Service]
Environment=RUST_LOG=flextunnel=debug
```
