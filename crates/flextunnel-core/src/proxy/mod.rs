//! The proxy over QUIC: signaling, SOCKS5 and HTTP front-ends, client, and
//! server.

pub mod bridge;
pub mod client;
pub mod dial;
pub mod dns_forward;
pub mod forward;
pub mod http;
pub mod reserved;
pub mod server;
pub mod routed_set;
pub mod signaling;
pub mod socks5;
pub mod status_page;

#[cfg(test)]
mod e2e_tests;

pub use bridge::{BridgeUpstream, BridgeUpstreamConfig};
pub use client::{ClientConfig, ProxyClient, ServerForwarder, TunnelRoutes};
pub use dns_forward::DnsForwarder;
pub use forward::{ForwardManager, ForwardSpec, ForwardState, ForwardStatus};
pub use routed_set::RoutedSet;
pub use server::{ProxyServer, ProxyServerParams};
