use super::Rule;
use parda_core::{EntityKind as K, validators::shannon_entropy};

pub(super) fn rules() -> Vec<Rule> {
    vec![
        Rule::new(K::Secret, r"AKIA[0-9A-Z]{16}", None, &["aws", "key"], 0.8),
        Rule::new(
            K::Secret,
            r"gh[pousr]_[A-Za-z0-9]{20,}",
            None,
            &["github", "token"],
            0.8,
        ),
        Rule::new(
            K::Secret,
            r"sk-(?:ant-(?:api[0-9]{2}-)?)?[A-Za-z0-9_-]{20,}",
            None,
            &["key", "api_key"],
            0.8,
        ),
        Rule::new(
            K::Secret,
            r"xox[abpr]-[A-Za-z0-9-]{20,}",
            None,
            &["slack", "token"],
            0.8,
        ),
        Rule::new(
            K::Secret,
            r"AIza[0-9A-Za-z_-]{35}",
            None,
            &["google", "key"],
            0.8,
        ),
        Rule::new(
            K::Secret,
            r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            None,
            &["jwt", "bearer", "token"],
            0.8,
        ),
        Rule::new(
            K::Secret,
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----(?:[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----)?",
            None,
            &[],
            0.9,
        ),
        Rule::new(
            K::Secret,
            r#"(?i)\b(?:password|secret|token|api_key)\b["']?\s*[:=]\s*["']?(?P<value>[^\s"',;]+)"#,
            None,
            &["password", "secret", "token", "api_key"],
            0.7,
        ),
        Rule::new(
            K::Secret,
            r"[A-Za-z0-9_+/=-]{24,}",
            Some(entropic),
            &[
                "key",
                "credential",
                "credentials",
                "auth",
                "authorization",
                "password",
                "secret",
                "token",
                "api_key",
            ],
            0.7,
        ),
    ]
}
fn entropic(s: &str) -> bool {
    shannon_entropy(s) >= 4.0
}
