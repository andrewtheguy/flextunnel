//! flextunnel
//!
//! A SOCKS5/HTTP-proxy-over-QUIC split tunnel via iroh P2P connections. The
//! clients may run local SOCKS5/HTTP proxy listeners or server-direct loopback
//! forwards; routed targets are reliable QUIC bi-streams to the server, which
//! resolves DNS and connects from its own network. Uses a fixed ALPN for
//! protocol selection, client keypairs (ed25519) for access control, and TLS 1.3/QUIC for
//! encryption. Neither side needs admin/root (no TUN device).
//!
//! This is the reusable core library, consumed by the `flextunnel` CLI binary
//! (`flextunnel-cli`), the desktop app (`flextunnel-desktop`), and the iOS C FFI
//! staticlib (`flextunnel-ffi`).

// Re-exported so downstream crates (CLI, desktop) can name iroh types (e.g.
// `EndpointId`) without declaring their own iroh dependency, which would risk
// a version skew against the one the core is built with.
pub use iroh;

// Same for the shared FlexAccess key crate (`ed25519-sec:` / `ed25519-pub:`
// tokens, key files, authorized-keys parsing) that `auth` builds on, and the
// shared iroh transport crate (relay config, endpoint rebuild, relay
// watchdog) that `transport` builds on.
pub use flexaccess_iroh;
pub use flexaccess_keys;

pub mod app;
pub mod auth;
pub mod blocklist;
pub mod config;
pub mod error;
pub mod forwards;
pub mod lock;
pub mod proxy;
pub mod secret;
pub mod transport;
