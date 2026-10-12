//! Request guards: only loopback peers and `Host` names (DNS rebinding)
//! and no browser `Origin` unless allow-listed (CSRF from web pages).

use std::net::{IpAddr, SocketAddr};

use http::header::{HOST, ORIGIN};
use http::{HeaderMap, Uri};
use parda_core::ProxyConfig;

/// `peer` is the TCP peer, when known (always, when served by [`crate::serve`]).
pub(crate) fn check(
    headers: &HeaderMap,
    uri: &Uri,
    peer: Option<SocketAddr>,
    cfg: &ProxyConfig,
) -> Result<(), &'static str> {
    if !cfg.allow_non_loopback {
        // The peer address cannot be forged the way a Host header can.
        if peer.is_some_and(|p| !p.ip().is_loopback()) {
            return Err("only this machine may use the proxy (proxy.allow_non_loopback = false)");
        }
        // HTTP/2 carries the host as :authority (in the URI), HTTP/1.0 may
        // carry none at all: refuse rather than skip the check.
        let host = match headers.get(HOST) {
            Some(h) => h.to_str().map_err(|_| "invalid Host header")?,
            None => uri
                .authority()
                .map(|a| a.as_str())
                .ok_or("a Host header is required")?,
        };
        if !is_loopback_host(host) {
            return Err("Host must be localhost or a loopback address (DNS-rebinding guard)");
        }
    }
    if let Some(origin) = headers.get(ORIGIN) {
        let origin = origin.to_str().unwrap_or("");
        if !cfg.allowed_origins.iter().any(|a| a == origin) {
            return Err("requests from web pages (Origin header) are refused (CSRF guard)");
        }
    }
    Ok(())
}

fn is_loopback_host(h: &str) -> bool {
    if let Ok(ip) = h.parse::<IpAddr>() {
        return ip.is_loopback();
    }
    let host = if let Some(rest) = h.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        match h.rsplit_once(':') {
            Some((name, port)) if port.chars().all(|c| c.is_ascii_digit()) => name,
            _ => h,
        }
    };
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_hosts() {
        for ok in [
            "localhost",
            "localhost:8787",
            "127.0.0.1:8787",
            "127.0.0.2",
            "[::1]:8787",
            "::1",
            "LOCALHOST",
        ] {
            assert!(is_loopback_host(ok), "{ok}");
        }
        for bad in [
            "attacker.example:8787",
            "10.0.0.1",
            "localhost.evil.com",
            "[2001:db8::1]:80",
            "",
        ] {
            assert!(!is_loopback_host(bad), "{bad}");
        }
    }

    fn uri() -> Uri {
        Uri::from_static("/v1/messages")
    }

    #[test]
    fn origin_needs_allow_list() {
        let mut cfg = ProxyConfig::default();
        let mut h = HeaderMap::new();
        h.insert(HOST, "127.0.0.1:8787".parse().unwrap());
        assert!(check(&h, &uri(), None, &cfg).is_ok());
        h.insert(ORIGIN, "https://evil.example".parse().unwrap());
        assert!(check(&h, &uri(), None, &cfg).is_err());
        cfg.allowed_origins.push("https://evil.example".into());
        assert!(check(&h, &uri(), None, &cfg).is_ok());
    }

    #[test]
    fn non_loopback_peer_refused_even_with_a_loopback_host() {
        let mut cfg = ProxyConfig::default();
        let mut h = HeaderMap::new();
        h.insert(HOST, "127.0.0.1:8787".parse().unwrap());
        let lan: SocketAddr = "192.168.1.20:5555".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:5555".parse().unwrap();
        assert!(check(&h, &uri(), Some(lan), &cfg).is_err());
        assert!(check(&h, &uri(), Some(local), &cfg).is_ok());
        cfg.allow_non_loopback = true;
        assert!(check(&h, &uri(), Some(lan), &cfg).is_ok());
    }

    #[test]
    fn missing_host_falls_back_to_the_authority_or_is_refused() {
        let cfg = ProxyConfig::default();
        let h = HeaderMap::new();
        assert!(check(&h, &uri(), None, &cfg).is_err());
        let local = Uri::from_static("http://127.0.0.1:8787/v1/messages");
        assert!(check(&h, &local, None, &cfg).is_ok());
        let evil = Uri::from_static("http://attacker.example/v1/messages");
        assert!(check(&h, &evil, None, &cfg).is_err());
    }
}
