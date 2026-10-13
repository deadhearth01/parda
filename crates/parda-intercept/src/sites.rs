//! Per-site knowledge: keys of the AI sites' private web APIs whose values
//! must reach the server verbatim (enums, flags, tokens, opaque ids) on top
//! of the generic identifier rules in [`crate::walk`].
//!
//! The generic rules carry most of the load; these lists only name what
//! they would miss. A key listed here is never redacted, so a list must
//! never name a field that can hold what the user typed.

/// One site: its hosts (subdomains included) and extra keys to skip.
#[derive(Debug)]
pub(crate) struct Site {
    pub(crate) hosts: &'static [&'static str],
    /// Key patterns (`*` matches any run of characters), case-insensitive.
    pub(crate) skip_keys: &'static [&'static str],
}

pub(crate) static SITES: &[Site] = &[
    Site {
        hosts: &["chatgpt.com", "chat.openai.com"],
        skip_keys: &[
            "content_type",
            "recipient",
            "channel",
            "conversation_mode",
            "conversation_origin",
            "system_hints",
            "supported_encodings",
            "variant_purpose",
            "paragen_*",
            "force_*",
            "websocket_*",
            "*_proof*",
        ],
    },
    Site {
        hosts: &["claude.ai"],
        skip_keys: &["rendering_mode", "sync_sources", "files"],
    },
    Site {
        // Form fields and query parameters of the batchexecute endpoints;
        // the prompt travels in `f.req` (JSON inside a string).
        hosts: &["gemini.google.com"],
        skip_keys: &[
            "at",
            "bl",
            "f.sid",
            "_reqid",
            "rt",
            "hl",
            "soc-*",
            "source-path",
        ],
    },
    Site {
        hosts: &["copilot.microsoft.com"],
        skip_keys: &["mode", "channel", "api-version"],
    },
    Site {
        hosts: &["perplexity.ai"],
        skip_keys: &[
            "frontend_*",
            "version",
            "source",
            "mode",
            "search_focus",
            "sources",
            "language",
            "attachments",
        ],
    },
    Site {
        hosts: &["chat.deepseek.com"],
        skip_keys: &["challenge*", "thinking_enabled", "search_enabled"],
    },
    Site {
        hosts: &["chat.mistral.ai"],
        skip_keys: &["mode", "features"],
    },
    Site {
        hosts: &["grok.com"],
        skip_keys: &["*Attachments", "deviceEnvInfo", "toolOverrides"],
    },
    Site {
        // GraphQL over form posts: the prompt is inside `variables` (JSON
        // in a string); the rest is request plumbing.
        hosts: &["meta.ai"],
        skip_keys: &[
            "fb_*",
            "__*",
            "lsd",
            "jazoest",
            "av",
            "dpr",
            "server_timestamps",
            "doc_id",
        ],
    },
    Site {
        hosts: &["poe.com"],
        skip_keys: &["queryName", "hash", "bot", "sdid", "extensions"],
    },
];

/// The site entry for `host` (exact or a subdomain), if parda knows it.
pub(crate) fn for_host(host: &str) -> Option<&'static Site> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    SITES.iter().find(|s| {
        s.hosts
            .iter()
            .any(|h| host == *h || host.strip_suffix(h).is_some_and(|rest| rest.ends_with('.')))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_default_host_has_a_site_entry() {
        for host in parda_core::DEFAULT_INTERCEPT_HOSTS {
            assert!(for_host(host).is_some(), "{host}");
        }
        assert!(for_host("www.perplexity.ai").is_some());
        assert!(for_host("CLAUDE.AI.").is_some());
        assert!(for_host("example.com").is_none());
        assert!(for_host("notclaude.ai").is_none());
    }

    #[test]
    fn site_lists_never_name_text_fields() {
        let text_keys = [
            "prompt",
            "parts",
            "text",
            "content",
            "message",
            "query",
            "query_str",
            "q",
            "input",
            "variables",
            "f.req",
        ];
        for site in SITES {
            for key in text_keys {
                assert!(
                    !site.skip_keys.iter().any(|p| crate::walk::glob(p, key)),
                    "{:?} skips {key}",
                    site.hosts
                );
            }
        }
    }
}
