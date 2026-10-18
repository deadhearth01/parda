//! Which hosts parda decrypts: the listed AI hosts and their subdomains.
//! Decrypted requests are filtered; answers are restored only on the exact
//! hosts a known site names (`sites::restore_rule`).

/// The hosts parda intercepts. An entry matches itself and every subdomain,
/// case-insensitively. Entries are host names without a port.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostList {
    entries: Vec<String>,
}

impl HostList {
    /// Normalizes entries (trim, lowercase, strip a leading `*.` or `.` and a
    /// trailing dot) and drops any that are not plain DNS names: only
    /// `[a-z0-9.-]` (so an entry can never inject into the PAC script), at
    /// least one dot, no empty label, not an IP literal.
    pub fn new(hosts: &[String]) -> HostList {
        let mut entries: Vec<String> = Vec::new();
        for h in hosts {
            let h = h.trim().to_ascii_lowercase();
            let h = h.strip_prefix("*.").unwrap_or(&h);
            let h = h.trim_start_matches('.').trim_end_matches('.');
            let valid = h
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
                && h.contains('.')
                && h.split('.').all(|label| !label.is_empty())
                && h.parse::<std::net::IpAddr>().is_err();
            if valid && !entries.iter().any(|e| e == h) {
                entries.push(h.to_string());
            }
        }
        HostList { entries }
    }

    /// Exact or subdomain match against an entry; `host` has no port.
    pub fn matches(&self, host: &str) -> bool {
        self.entry_for(host).is_some()
    }

    /// The entry `host` falls under (the most specific one when entries
    /// nest); `host` has no port.
    pub fn entry_for(&self, host: &str) -> Option<&str> {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.entries
            .iter()
            .filter(|e| {
                host == **e
                    || (host.len() > e.len()
                        && host.ends_with(e.as_str())
                        && host.as_bytes()[host.len() - e.len() - 1] == b'.')
            })
            .max_by_key(|e| e.len())
            .map(String::as_str)
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
    fn entry_for_names_the_most_specific_entry() {
        let l = list(&["google.com", "gemini.google.com", "claude.ai"]);
        assert_eq!(l.entry_for("Gemini.Google.com."), Some("gemini.google.com"));
        assert_eq!(
            l.entry_for("x.gemini.google.com"),
            Some("gemini.google.com")
        );
        assert_eq!(l.entry_for("mail.google.com"), Some("google.com"));
        assert_eq!(l.entry_for("api.claude.ai"), Some("claude.ai"));
        assert_eq!(l.entry_for("claude.ai.evil"), None);
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
            // No dot, IP literals, empty labels.
            "localhost",
            "127.0.0.1",
            "10.1.2.3",
            "a..b",
        ]);
        assert_eq!(l.entries(), ["chat.test", "claude.ai"]);
        assert!(!l.matches("127.0.0.1"));
        assert!(l.matches("chat.test"));
        assert!(!list(&[]).matches("chat.test"));
    }
}
