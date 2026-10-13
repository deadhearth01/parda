//! Which hosts parda decrypts: the listed AI hosts and their subdomains.

/// The hosts parda intercepts. An entry matches itself and every subdomain,
/// case-insensitively. Entries are host names without a port.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostList {
    entries: Vec<String>,
}

impl HostList {
    /// Normalizes entries (trim, lowercase, strip a leading `*.` or `.` and a
    /// trailing dot) and drops any that are not plain host names
    /// (`[a-z0-9.-]` only), so an entry can never inject into the PAC script.
    pub fn new(hosts: &[String]) -> HostList {
        let mut entries: Vec<String> = Vec::new();
        for h in hosts {
            let h = h.trim().to_ascii_lowercase();
            let h = h.strip_prefix("*.").unwrap_or(&h);
            let h = h.trim_start_matches('.').trim_end_matches('.');
            let valid = !h.is_empty()
                && h.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-'
                });
            if valid && !entries.iter().any(|e| e == h) {
                entries.push(h.to_string());
            }
        }
        HostList { entries }
    }

    /// Exact or subdomain match against an entry; `host` has no port.
    pub fn matches(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.entries.iter().any(|e| {
            host == *e
                || (host.len() > e.len()
                    && host.ends_with(e.as_str())
                    && host.as_bytes()[host.len() - e.len() - 1] == b'.')
        })
    }

    /// The normalized entries (lowercase, no leading `*.`/`.`, no trailing dot).
    pub fn entries(&self) -> &[String] {
        &self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(v: &[&str]) -> HostList {
        HostList::new(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn exact_and_subdomains_match_case_insensitively() {
        let l = list(&["chat.test", "Claude.AI"]);
        assert!(l.matches("chat.test"));
        assert!(l.matches("x.chat.test"));
        assert!(l.matches("a.b.CHAT.test"));
        assert!(l.matches("claude.ai"));
        assert!(l.matches("api.claude.ai"));
        assert!(l.matches("chat.test."));
    }

    #[test]
    fn lookalikes_do_not_match() {
        let l = list(&["chat.test"]);
        assert!(!l.matches("evilchat.test"));
        assert!(!l.matches("chat.test.evil.com"));
        assert!(!l.matches("test"));
        assert!(!l.matches(""));
        assert!(!l.matches("example.com"));
    }

    #[test]
    fn entries_are_normalized_and_junk_dropped() {
        let l = list(&[
            " *.Chat.Test ",
            ".claude.ai.",
            "",
            "bad host",
            "x\";alert(1)//",
            "a:443",
        ]);
        assert_eq!(l.entries(), ["chat.test", "claude.ai"]);
        assert!(l.matches("chat.test"));
        assert!(!list(&[]).matches("chat.test"));
    }
}
