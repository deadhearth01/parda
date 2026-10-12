//! Golden corpus files (`bench/golden/*.jsonl`).

use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Gold {
    pub start: usize,
    pub end: usize,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Case {
    #[serde(default)]
    pub region: Option<String>,
    pub text: String,
    #[serde(default)]
    pub entities: Vec<Gold>,
}

impl Case {
    /// `IN`, `GL` (global) or `NEG`; files without regions count as `GL`.
    pub fn region(&self) -> &str {
        self.region.as_deref().unwrap_or("GL")
    }
}

pub fn load(path: &Path) -> anyhow::Result<Vec<Case>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
    text.lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
        .map(|(i, l)| {
            let c: Case = serde_json::from_str(l)
                .map_err(|e| anyhow::anyhow!("{}:{}: {e}", path.display(), i + 1))?;
            for g in &c.entities {
                if g.end > c.text.len()
                    || g.start >= g.end
                    || !c.text.is_char_boundary(g.start)
                    || !c.text.is_char_boundary(g.end)
                {
                    anyhow::bail!(
                        "{}:{}: bad span {}..{}",
                        path.display(),
                        i + 1,
                        g.start,
                        g.end
                    );
                }
            }
            Ok(c)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_repo_corpus() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bench/golden");
        let names = load(&dir.join("names.jsonl")).unwrap();
        assert!(names.len() >= 120);
        assert!(names.iter().any(|c| c.region() == "IN"));
        assert!(
            names
                .iter()
                .any(|c| c.region() == "NEG" && c.entities.is_empty())
        );
        let rules = load(&dir.join("rules.jsonl")).unwrap();
        assert!(rules.len() >= 60);
        assert_eq!(rules[0].region(), "GL");
    }

    #[test]
    fn rejects_bad_spans() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.jsonl");
        std::fs::write(
            &p,
            r#"{"text":"héllo","entities":[{"start":0,"end":2,"kind":"Person"}]}"#,
        )
        .unwrap();
        assert!(load(&p).is_err());
    }
}
