//! Timing helpers.

use std::time::Instant;

use serde::Serialize;

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Timing {
    pub label: String,
    pub runs: usize,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub max_ms: f64,
}

pub fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let i = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[i.min(sorted.len() - 1)]
}

/// Run `f` `warmup + runs` times and summarise the last `runs`.
pub fn time(label: &str, warmup: usize, runs: usize, mut f: impl FnMut()) -> Timing {
    for _ in 0..warmup {
        f();
    }
    let mut ms: Vec<f64> = (0..runs)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed().as_secs_f64() * 1000.0
        })
        .collect();
    ms.sort_by(f64::total_cmp);
    Timing {
        label: label.to_string(),
        runs,
        p50_ms: percentile(&ms, 0.5),
        p95_ms: percentile(&ms, 0.95),
        max_ms: ms.last().copied().unwrap_or(0.0),
    }
}

/// A fragment of roughly `words` words of chat-style text with a few names.
pub fn fragment(words: usize) -> String {
    const BASE: &[&str] = &[
        "Please",
        "ask",
        "Venkatesh",
        "Iyer",
        "to",
        "send",
        "the",
        "revised",
        "invoice",
        "to",
        "the",
        "Pune",
        "office",
        "before",
        "Friday,",
        "and",
        "copy",
        "Siobhan",
        "O'Brien",
        "on",
        "the",
        "thread",
        "so",
        "that",
        "the",
        "auditors",
        "can",
        "close",
        "the",
        "quarter.",
    ];
    BASE.iter()
        .cycle()
        .take(words)
        .copied()
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_and_fragment() {
        let v = [1.0, 2.0, 3.0, 4.0, 100.0];
        assert_eq!(percentile(&v, 0.5), 3.0);
        assert_eq!(percentile(&v, 0.95), 100.0);
        assert_eq!(fragment(64).split(' ').count(), 64);
        let t = time("noop", 1, 5, || {});
        assert_eq!(t.runs, 5);
    }
}
