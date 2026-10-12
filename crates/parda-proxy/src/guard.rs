//! Request guards: only loopback `Host` names (DNS rebinding) and no browser
//! `Origin` unless allow-listed (CSRF from web pages).

use std::net::IpAddr;

use http::HeaderMap;
use http::header::{HOST, ORIGIN};
use parda_core::ProxyConfig;

pub(crate) fn check(headers: &HeaderMap, cfg: &ProxyConfig) -> Result<(), &'static str> {
    if !cfg.allow_non_loopback
        && let Some(host) = headers.get(HOST)
    {
        let host = host.to_str().map_err(|_| "invalid Host header")?;
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

    #[test]
    fn origin_needs_allow_list() {
        let mut cfg = ProxyConfig::default();
        let mut h = HeaderMap::new();
        h.insert(HOST, "127.0.0.1:8787".parse().unwrap());
        assert!(check(&h, &cfg).is_ok());
        h.insert(ORIGIN, "https://evil.example".parse().unwrap());
        assert!(check(&h, &cfg).is_err());
        cfg.allowed_origins.push("https://evil.example".into());
        assert!(check(&h, &cfg).is_ok());
    }
}
