# flextunnel-desktop

The native desktop GUI for the [flextunnel](../..) client — a system-tray app
for **macOS and Windows** that manages connection profiles and runs one tunnel
session per profile without ever opening a terminal.

It embeds [`flextunnel-core`](../flextunnel-core) directly and is
built on [iced](https://iced.rs/)'s daemon runtime: the process lives in the
menu bar / system tray and keeps running with no window open, so closing the
window loses nothing — the tray owns the lifecycle and re-opens it on demand.

```
┌── tray / menu bar ──┐        ┌──────────── window ────────────┐
│ flextunnel          │        │  Profiles          Detail pane │
│  ● home-lab   ▸     │        │  ● home-lab        SOCKS 1080   │
│  ○ staging    ▸     │  ⇄     │  ○ staging         HTTP  18080  │
│  Connect / Disconnect│        │  Logs              forwards…   │
│  Copy SOCKS5 Address │        │  Export / Import   Conn. path  │
└──────────────────────┘        └────────────────────────────────┘
```

## What it does

Each **profile** is the desktop equivalent of a `client.toml` — a server
`EndpointId`, an auth token, and the local front-ends you want. Profiles are
independent: any number can be connected at once, and each runs its own tunnel
session with its own optional local **SOCKS5** and **HTTP** proxy listeners plus
its own **server-direct port forwards**. Connecting is always manual.

- **Multiple concurrent profiles** — a sidebar of connections, each with its own
  session, ports, and forwards. Add, edit, and delete them from the window.
- **Local SOCKS5 / HTTP proxies** — enable either or both per profile; point any
  proxy-aware app at `127.0.0.1:<port>` and its traffic to routed targets rides
  the tunnel.
- **Port forwards** — bind a local port to any `host:port` on the server's
  network so tools that can't use a proxy reach private services as if local.
- **System tray control** — per-profile submenus for status, Connect,
  Disconnect, and Copy SOCKS5 Address; the tray icon reflects the worst/most-
  notable state across all profiles.
- **Connection path** — a modal that reports whether a connected profile is
  reaching the server directly (hole-punched) or via relay.
- **Live logs** — an in-app Logs pane; every session's log lines (core internals
  included) are attributed to their profile.
- **Export / import** — move profiles between machines via native save/open
  dialogs. (Secrets are re-entered on import: neither the auth token nor the
  custom-relay auth token is written to the export file. Importing over an
  existing profile — matched by server id — keeps that profile's secrets.)
- **Auto-reconnect** — sessions re-establish the tunnel when the path drops.

## Where settings live

Non-secret profile data (name, server id, ports, forwards) is stored as a
plaintext `profiles.json` in the platform's local data directory. The **auth
token is the only secret** and is kept in the system keychain — **macOS
Keychain** or the **Windows Credential Manager** — one entry per profile.

> **Development escape hatch:** setting `FLEXTUNNEL_DEV_CONFIG` (to `1` or to an
> explicit file path) stores everything, tokens included, in a single plaintext
> JSON file, so an unsigned rebuild loop doesn't trigger the keychain access
> prompt on every launch. **Never set it for a real install** — the tokens are
> stored unencrypted.

## Install

Prebuilt, **unsigned** installers ship with each stable flextunnel release —
`flextunnel-desktop-macos-arm64.dmg` and `flextunnel-desktop-windows-amd64.msi`
on the [Releases page](https://github.com/flexaccessdev/flextunnel/releases).
Because they're unsigned you'll need to work around Gatekeeper (macOS) or
SmartScreen (Windows); the [main README](../../README.md#desktop-app-tray-gui-client-mode)
covers the exact steps (the short version: download with `curl` rather than a
browser to avoid the quarantine / mark-of-the-web flag).

## Build from source

macOS and Windows only — the crate depends on platform keychain and tray
backends, and it is deliberately kept out of the workspace default members so a
server-side `cargo build` on Linux is unaffected. Build it explicitly:

```sh
cargo build --release -p flextunnel-desktop
# binary: target/release/flextunnel-desktop
# locally built binaries aren't quarantined — no Gatekeeper/SmartScreen workaround needed
```

That produces the bare executable, **not** an app bundle — on macOS it will show
a Dock icon instead of running as a pure menu-bar app because it has no
`Info.plist`. For the proper bundle, build it the way CI does with
[`cargo-packager`](https://github.com/crabnebula-dev/cargo-packager) (macOS
`.app`/`.dmg`, Windows `.msi`):

```sh
cargo install cargo-packager        # or: cargo binstall cargo-packager
cargo packager --release -p flextunnel-desktop --formats app   # or dmg / wix
# bundle: target/release/flextunnel.app
```

Requires a recent Rust toolchain (edition 2024).

## How it fits together

```
src/main.rs     entry point; boots the iced daemon and the tray
   app.rs       the daemon state machine (sidebar + detail pane + tray glue)
   view.rs      the window UI (profile list, detail pane, modals)
   tray.rs      system-tray icon + per-profile menus
   tunnel.rs    background controller: one session per connected profile
   config.rs    profile persistence (profiles.json + keychain tokens)
   icon.rs      tray glyph rendered at runtime
   style.rs     iced theme
   logging.rs   per-profile log attribution
```

For the tunnel protocol, transport, and security model, see the
[flextunnel README](../../README.md).
