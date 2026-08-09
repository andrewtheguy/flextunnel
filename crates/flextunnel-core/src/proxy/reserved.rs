//! The reserved `flextunnel.internal` namespace.
//!
//! `flextunnel.internal` and every `*.flextunnel.internal` subdomain are
//! reserved by flextunnel itself: the operator may not use them as
//! `[host_aliases]` names (rejected at config resolution), the
//! client always tunnels them to the server rather than split-tunneling, and the
//! server intercepts them before the routed-set whitelist. `flextunnel.internal`
//! serves a read-only server status page (see [`super::status_page`]); other
//! subdomains are reserved for future use and answer with an HTTP 404.

/// The status-page host. `http://flextunnel.internal` through the tunnel returns
/// the server status page.
pub const STATUS_HOST: &str = "flextunnel.internal";

/// The reserved subdomain suffix (matches `*.flextunnel.internal`).
const RESERVED_SUFFIX: &str = ".flextunnel.internal";

/// True for `flextunnel.internal` and any `*.flextunnel.internal` subdomain
/// (case-insensitive). A bare `.flextunnel.internal` (empty label) does not
/// match, and `flextunnel.internal.evil.com` does not match.
pub fn is_reserved_host(host: &str) -> bool {
    if is_status_host(host) {
        return true;
    }
    let lower = host.to_ascii_lowercase();
    // A non-empty subdomain label: strip the suffix and require something left.
    lower
        .strip_suffix(RESERVED_SUFFIX)
        .is_some_and(|label| !label.is_empty())
}

/// True only for the exact status host `flextunnel.internal` (case-insensitive).
pub fn is_status_host(host: &str) -> bool {
    host.eq_ignore_ascii_case(STATUS_HOST)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_host_matches_exact_case_insensitive() {
        assert!(is_status_host("flextunnel.internal"));
        assert!(is_status_host("FlexTunnel.Internal"));
        assert!(is_reserved_host("flextunnel.internal"));
        assert!(is_reserved_host("FLEXTUNNEL.INTERNAL"));
    }

    #[test]
    fn subdomains_are_reserved_but_not_status() {
        assert!(is_reserved_host("status.flextunnel.internal"));
        assert!(is_reserved_host("a.b.flextunnel.internal"));
        assert!(is_reserved_host("Foo.FlexTunnel.Internal"));
        assert!(!is_status_host("status.flextunnel.internal"));
    }

    #[test]
    fn non_reserved_hosts_do_not_match() {
        assert!(!is_reserved_host("flextunnel.internal.evil.com"));
        assert!(!is_reserved_host("internal"));
        assert!(!is_reserved_host("example.com"));
        // A bare suffix with no subdomain label must not match.
        assert!(!is_reserved_host(".flextunnel.internal"));
        // Not a subdomain boundary.
        assert!(!is_reserved_host("myflextunnel.internal"));
    }
}
