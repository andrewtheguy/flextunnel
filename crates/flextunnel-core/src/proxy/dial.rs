//! Dialing a [`Target`] to an outbound TCP connection.
//!
//! Shared by the server (which dials every tunneled target from its own
//! network) and the client's split-tunnel path (which dials non-routed
//! targets directly from the device). Callers wrap these in their own timeouts.

use crate::proxy::dns_forward::DnsForwarder;
use crate::proxy::signaling::{self, Target};
use iroh::endpoint::{RecvStream, SendStream};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// Deadline for dialing a target (DNS resolution + TCP connect), so a slow or
/// black-holed target can't tie up a task and its sockets indefinitely. Used by
/// the server's exit path.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Connect to `target`: a loopback target tries both loopback families (see
/// [`loopback_addrs`]), any other literal IP connects directly, and a domain is
/// resolved (via `forwarder` when its name matches a configured suffix, else the
/// caller's system DNS) and tried address-by-address (see [`connect_resolved`]).
///
/// `forwarder` is the server's conditional-DNS-forwarding table; the client's
/// split-tunnel path passes `None`.
pub async fn dial_target(target: &Target, forwarder: Option<&DnsForwarder>) -> io::Result<TcpStream> {
    if let Some(port) = loopback_port(target) {
        return connect_any(&loopback_addrs(port)).await;
    }
    match target {
        Target::Ip(sa) => TcpStream::connect(*sa).await,
        Target::Domain(host, port) => connect_resolved(host, *port, forwarder).await,
    }
}

/// The port of a loopback target (a loopback literal IP, or the literal
/// `localhost` host), or `None` for anything that must be resolved/dialed as
/// given. Both loopback families are distinct sockets, so a loopback target is
/// dialed on both — a service told `localhost` may bind only `::1`, and an alias
/// pointing at `127.0.0.1` may front a service that only listens on `::1`.
fn loopback_port(target: &Target) -> Option<u16> {
    match target {
        Target::Ip(sa) if sa.ip().is_loopback() => Some(sa.port()),
        Target::Ip(_) => None,
        Target::Domain(host, port) => {
            if host.eq_ignore_ascii_case("localhost") {
                return Some(*port);
            }
            host.parse::<IpAddr>()
                .ok()
                .filter(IpAddr::is_loopback)
                .map(|_| *port)
        }
    }
}

/// Both loopback socket addresses for `port`, IPv4 first. Most local services
/// bind `127.0.0.1`, and trying IPv4 first also dodges the macOS ::1-first stall.
fn loopback_addrs(port: u16) -> [SocketAddr; 2] {
    [
        SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
    ]
}

/// Try each address in order, returning the first successful connection or the
/// last error. An empty list yields a host-unreachable error.
async fn connect_any(addrs: &[SocketAddr]) -> io::Result<TcpStream> {
    let mut last_err: Option<io::Error> = None;
    for addr in addrs {
        match TcpStream::connect(*addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::HostUnreachable, "no addresses to connect to")
    }))
}

/// Resolve a host:port and connect to the first address that accepts. When a
/// `forwarder` is given and `host` matches a configured suffix, resolution goes
/// through that suffix's upstream DNS server; otherwise the local system DNS is
/// used. When every resolved address is loopback, IPv4 is tried first (most
/// local services bind `127.0.0.1`; this also dodges the macOS ::1-first stall).
/// Returns the last connect error, or a host-unreachable error if resolution
/// yielded no addresses.
pub async fn connect_resolved(
    host: &str,
    port: u16,
    forwarder: Option<&DnsForwarder>,
) -> io::Result<TcpStream> {
    // Forwarded resolution when a matching suffix is configured; otherwise (no
    // forwarder, or the host matches no suffix) fall back to the system DNS.
    let forwarded = match forwarder {
        Some(f) => f.resolve(host, port).await,
        None => None,
    };
    let mut addrs: Vec<SocketAddr> = match forwarded {
        Some(res) => res?,
        None => tokio::net::lookup_host((host, port)).await?.collect(),
    };
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::HostUnreachable,
            format!("no addresses resolved for {host}:{port}"),
        ));
    }
    if addrs.iter().all(|a| a.ip().is_loopback()) {
        addrs.sort_by_key(|a| if a.is_ipv4() { 0 } else { 1 });
    }
    connect_any(&addrs).await
}

/// Terminate a tunnel stream against a `target`: dial it (bounded by
/// [`CONNECT_TIMEOUT`]), write the SOCKS5-shaped reply byte, and — on success —
/// pipe bytes bidirectionally until either side closes.
///
/// This is the server's exit-point body, run for a normal tunneled target
/// (dialing from its own network, optionally with a `forwarder` for
/// conditional DNS). Per-stream errors stay per-stream; the shared QUIC
/// connection is never torn down here.
pub async fn connect_and_pipe(
    mut send: SendStream,
    recv: RecvStream,
    target: &Target,
    forwarder: Option<&DnsForwarder>,
) -> io::Result<()> {
    let connected = match tokio::time::timeout(CONNECT_TIMEOUT, dial_target(target, forwarder)).await
    {
        Ok(res) => res,
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out")),
    };

    let mut tcp = match connected {
        Ok(s) => {
            signaling::write_reply(&mut send, signaling::REP_SUCCESS).await?;
            s
        }
        Err(e) => {
            // Keep the failure visible at warn without exposing the target there;
            // log the target-specific detail at debug instead.
            log::warn!("Connect to target failed: {e}");
            log::debug!("Connect to {target:?} failed: {e}");
            signaling::write_reply(&mut send, signaling::map_io_err(&e)).await?;
            send.flush().await?;
            return Ok(());
        }
    };
    send.flush().await?;

    let mut iroh = tokio::io::join(recv, send);
    let _ = tokio::io::copy_bidirectional(&mut iroh, &mut tcp).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn loopback_port_detection() {
        // Loopback literals and `localhost` (any case) resolve to dual-stack.
        assert_eq!(
            loopback_port(&Target::Ip("127.0.0.1:80".parse().unwrap())),
            Some(80)
        );
        assert_eq!(
            loopback_port(&Target::Ip("[::1]:81".parse().unwrap())),
            Some(81)
        );
        assert_eq!(
            loopback_port(&Target::Domain("localhost".into(), 82)),
            Some(82)
        );
        assert_eq!(
            loopback_port(&Target::Domain("LocalHost".into(), 83)),
            Some(83)
        );
        assert_eq!(
            loopback_port(&Target::Domain("127.0.0.1".into(), 84)),
            Some(84)
        );
        assert_eq!(loopback_port(&Target::Domain("::1".into(), 85)), Some(85));

        // Non-loopback targets are dialed as given.
        assert_eq!(
            loopback_port(&Target::Ip("93.184.216.34:443".parse().unwrap())),
            None
        );
        assert_eq!(loopback_port(&Target::Domain("example.com".into(), 443)), None);
    }

    /// A service bound only on `::1` must still be reachable when the target is a
    /// `127.0.0.1` literal (e.g. an alias) or the `localhost` name — the very
    /// case where a non-dual-stack dial would hard-fail.
    #[tokio::test]
    async fn dials_ipv6_loopback_service_via_ipv4_and_name_targets() {
        let listener = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });

        for target in [
            Target::Ip(SocketAddr::from((Ipv4Addr::LOCALHOST, port))),
            Target::Domain("127.0.0.1".into(), port),
            Target::Domain("localhost".into(), port),
        ] {
            dial_target(&target, None)
                .await
                .unwrap_or_else(|e| panic!("dial {target:?} to ::1 service failed: {e}"));
        }
    }
}
