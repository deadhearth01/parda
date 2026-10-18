//! Per-site knowledge: keys of the AI sites' private web APIs whose values
//! must reach the server verbatim (enums, flags, tokens, opaque ids) on top
//! of the generic identifier rules in [`crate::walk`], and which answers get
//! real values back.
//!
//! The generic rules carry most of the load; these lists only name what
//! they would miss. A key listed here is never redacted, so a list must
//! never name a field that can hold what the user typed.

/// One site: its hosts, extra keys to skip, and the answers parda restores.
#[derive(Debug)]
pub(crate) struct Site {
    /// Exact host names. Requests to their subdomains use this site's keys
    /// too, but answers are restored only on the hosts named here: a
    /// subdomain is part of the site for that only when it is listed.
    pub(crate) hosts: &'static [&'static str],
    /// Key patterns (`*` matches any run of characters), case-insensitive.
    pub(crate) skip_keys: &'static [&'static str],
    /// Which answers get real values back (see [`restore_rule`]).
    pub(crate) answers: Answers,
}

/// The answers of a site that parda restores. Everything else passes
/// through with its tags, so a page someone else wrote (a shared
/// conversation, a GPT or bot description, a public thread) never gets the
/// viewer's real values.
#[derive(Debug)]
pub(crate) enum Answers {
    /// Only these endpoints, in any format parda reads: the user's own
    /// sends (answers to POST) and own history (answers to GET). In a
    /// pattern `*` matches one path segment; literals match ASCII
    /// case-insensitively.
    Listed {
        send: &'static [&'static str],
        history: &'static [&'static str],
    },
    /// Only streamed answers to POST requests ([`Restore::Streamed`]).
    StreamedSends,
}

/// What parda restores in one answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Restore {
    /// Nothing: the answer passes through with its tags.
    Never,
    /// Every format parda reads.
    Answer,
    /// Only a stream by its content type (`text/event-stream` or an NDJSON
    /// type). Any JSON-typed body (one document, or one followed by more
    /// lines, as a GraphQL answer ends in `{"extensions":…}`) or text body
    /// passes through: an AI answer to a send streams, while a document may
    /// be anybody's content (a GraphQL query for a public page, a bot card).
    Streamed,
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
        answers: Answers::Listed {
            send: &["/backend-api/conversation", "/backend-api/f/conversation"],
            history: &["/backend-api/conversation/*", "/backend-api/conversations"],
        },
    },
    Site {
        hosts: &["claude.ai"],
        skip_keys: &["rendering_mode", "sync_sources", "files"],
        answers: Answers::Listed {
            send: &[
                "/api/organizations/*/chat_conversations/*/completion",
                "/api/organizations/*/chat_conversations/*/retry_completion",
            ],
            history: &[
                "/api/organizations/*/chat_conversations",
                "/api/organizations/*/chat_conversations/*",
            ],
        },
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
        // Answers to sends only: the history comes from batchexecute, which
        // also serves shared chats, so it keeps its tags.
        answers: Answers::Listed {
            send: &[
                "/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate",
                "/u/*/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate",
            ],
            history: &[],
        },
    },
    Site {
        hosts: &["copilot.microsoft.com"],
        skip_keys: &["mode", "channel", "api-version"],
        answers: Answers::StreamedSends,
    },
    Site {
        hosts: &["perplexity.ai", "www.perplexity.ai"],
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
        answers: Answers::StreamedSends,
    },
    Site {
        hosts: &["chat.deepseek.com"],
        skip_keys: &["challenge*", "thinking_enabled", "search_enabled"],
        answers: Answers::StreamedSends,
    },
    Site {
        hosts: &["chat.mistral.ai"],
        skip_keys: &["mode", "features"],
        answers: Answers::StreamedSends,
    },
    Site {
        hosts: &["grok.com"],
        skip_keys: &["*Attachments", "deviceEnvInfo", "toolOverrides"],
        answers: Answers::StreamedSends,
    },
    Site {
        // GraphQL over form posts: the prompt is inside `variables` (JSON
        // in a string); the rest is request plumbing.
        hosts: &["meta.ai", "www.meta.ai"],
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
        answers: Answers::StreamedSends,
    },
    Site {
        hosts: &["poe.com"],
        skip_keys: &["queryName", "hash", "bot", "sdid", "extensions"],
        answers: Answers::StreamedSends,
    },
];

/// What to restore in the answer to `method path` on `host`. Only a host a
/// site names exactly gets anything back (a subdomain it does not name, or
/// a host no site names, keeps its tags): a site parda knows by its
/// endpoints restores only those; the other sites only streamed answers to
/// POST requests.
pub(crate) fn restore_rule(host: &str, method: &http::Method, path: &str) -> Restore {
    let Some(site) = exact_site(host) else {
        return Restore::Never;
    };
    match &site.answers {
        Answers::StreamedSends if *method == http::Method::POST => Restore::Streamed,
        Answers::StreamedSends => Restore::Never,
        Answers::Listed { send, history } => {
            let patterns = if *method == http::Method::POST {
                send
            } else if *method == http::Method::GET {
                history
            } else {
                return Restore::Never;
            };
            match segments(path) {
                Some(segs) if patterns.iter().any(|p| matches(p, &segs)) => Restore::Answer,
                _ => Restore::Never,
            }
        }
    }
}

/// The segments of a request path, for endpoint matching: the query and
/// fragment dropped, each segment percent-decoded once. `None` (matches
/// nothing) for a path a server might read differently from parda:
/// relative, not UTF-8, an empty, `.` or `..` segment, or a `/`, `%`, `\`,
/// `;` or control character left after decoding.
fn segments(path: &str) -> Option<Vec<String>> {
    let path = path.split(['?', '#']).next().unwrap_or("");
    path.strip_prefix('/')?
        .split('/')
        .map(|raw| {
            let seg = percent_encoding::percent_decode_str(raw)
                .decode_utf8()
                .ok()?;
            let odd = |c: char| matches!(c, '/' | '%' | '\\' | ';') || c.is_control();
            (!matches!(&*seg, "" | "." | "..") && !seg.contains(odd)).then(|| seg.into_owned())
        })
        .collect()
}

/// Does `pattern` (`*` = one segment) match the path `segs`?
fn matches(pattern: &str, segs: &[String]) -> bool {
    let pat: Vec<&str> = pattern.trim_start_matches('/').split('/').collect();
    pat.len() == segs.len()
        && pat
            .iter()
            .zip(segs)
            .all(|(p, s)| *p == "*" || p.eq_ignore_ascii_case(s))
}

/// The site that names `host` exactly (ASCII case and a trailing dot
/// aside), if any.
fn exact_site(host: &str) -> Option<&'static Site> {
    let host = normalize(host);
    SITES.iter().find(|s| s.hosts.contains(&host.as_str()))
}

/// `host` lowercased, without a trailing dot: the form a vault scope and
/// the site lists use.
pub(crate) fn normalize(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// The site entry for `host` (exact or a subdomain), if parda knows it:
/// the keys its requests skip. Restoring needs the exact host
/// ([`restore_rule`]).
pub(crate) fn for_host(host: &str) -> Option<&'static Site> {
    let host = normalize(host);
    SITES.iter().find(|s| {
        s.hosts
            .iter()
            .any(|h| host == *h || host.strip_suffix(h).is_some_and(|rest| rest.ends_with('.')))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Method;

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
    fn paths_are_decoded_once_and_dot_segments_refused() {
        let segs = |p: &str| segments(p).map(|v| v.join("|"));
        assert_eq!(segs("/a/b?x=/c#d").as_deref(), Some("a|b"));
        assert_eq!(segs("/a#/../b").as_deref(), Some("a"));
        assert_eq!(segs("/a/%62c").as_deref(), Some("a|bc"));
        assert_eq!(segs("/a%20b").as_deref(), Some("a b"));
        for bad in [
            "",
            "a/b",
            "/",
            "//a",
            "/a//b",
            "/a/",
            "/.",
            "/a/..",
            "/a/%2e%2e",
            "/a/%2E",
            "/a/%252e",
            "/a/%zz",
            "/a/%ff",
            "/a\\b",
            "/a/%5c",
            "/a;b",
            "/a/%00",
            "/a/%0a",
            "/a/%2F/b",
            "/a/b%2fc",
            "/a/%2e%2e%2fb",
        ] {
            assert_eq!(segs(bad), None, "{bad:?}");
        }
        let path = |p: &str| segments(p).unwrap();
        assert!(matches(
            "/backend-api/conversation/*",
            &path("/Backend-API/CONVERSATION/x")
        ));
        assert!(!matches(
            "/backend-api/conversation/*",
            &path("/backend-api/conversation")
        ));
        assert!(!matches(
            "/backend-api/conversation",
            &path("/backend-api/conversation/x")
        ));
    }

    #[test]
    fn known_and_unknown_sites_have_their_rules() {
        let rule = |host: &str, m: Method, path: &str| restore_rule(host, &m, path);
        assert_eq!(rule("example.com", Method::POST, "/x"), Restore::Never);
        assert_eq!(rule("example.com", Method::GET, "/x"), Restore::Never);
        assert_eq!(rule("example.com", Method::PUT, "/x"), Restore::Never);
        assert_eq!(
            rule("meta.ai", Method::POST, "/api/graphql/"),
            Restore::Streamed
        );
        assert_eq!(
            rule("meta.ai", Method::GET, "/api/graphql/"),
            Restore::Never
        );
        assert_eq!(
            rule("chatgpt.com", Method::POST, "/backend-api/conversation"),
            Restore::Answer
        );
        assert_eq!(
            rule("chatgpt.com", Method::POST, "/backend-api/gizmos/x"),
            Restore::Never
        );
        assert_eq!(
            rule("chatgpt.com", Method::GET, "/backend-api/share/x"),
            Restore::Never
        );
        assert_eq!(
            rule(
                "gemini.google.com",
                Method::POST,
                "/u/1/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate"
            ),
            Restore::Answer
        );
        assert_eq!(
            rule(
                "gemini.google.com",
                Method::POST,
                "/_/BardChatUi/data/batchexecute"
            ),
            Restore::Never
        );
        assert_eq!(
            rule(
                "gemini.google.com",
                Method::GET,
                "/_/BardChatUi/data/batchexecute"
            ),
            Restore::Never
        );
    }

    /// Review F3: a subdomain of a listed site is decrypted and filtered,
    /// but only the exact hosts a site names get answers restored.
    #[test]
    fn only_exact_site_hosts_restore() {
        let send = |host: &str| restore_rule(host, &Method::POST, "/backend-api/conversation");
        assert_eq!(send("chatgpt.com"), Restore::Answer);
        assert_eq!(send("CHATGPT.COM."), Restore::Answer);
        assert_eq!(send("chat.openai.com"), Restore::Answer);
        for host in [
            "x.chatgpt.com",
            "a.b.chatgpt.com",
            "X.ChatGPT.com.",
            "x.chat.openai.com",
            "openai.com",
            "evilchatgpt.com",
            "chatgpt.com.evil.test",
        ] {
            assert_eq!(send(host), Restore::Never, "{host}");
        }
        let post = |host: &str| restore_rule(host, &Method::POST, "/api/graphql/");
        // Subdomains a site names explicitly are that site.
        assert_eq!(post("meta.ai"), Restore::Streamed);
        assert_eq!(post("www.meta.ai"), Restore::Streamed);
        assert_eq!(post("www.perplexity.ai"), Restore::Streamed);
        for host in [
            "x.meta.ai",
            "x.www.meta.ai",
            "api.perplexity.ai",
            "x.chat.deepseek.com",
            "deepseek.com",
            "x.claude.ai",
            "x.gemini.google.com",
            "google.com",
            // A host no site names (added to `hosts` by the user).
            "example.com",
            "chat.test",
        ] {
            assert_eq!(post(host), Restore::Never, "{host}");
        }
        // Requests to subdomains still use the site's keys.
        assert!(for_host("x.chatgpt.com").is_some());
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
