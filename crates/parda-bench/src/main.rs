//! `parda-bench`: evaluate detection on the golden corpus, time the tiers,
//! and run a mock LLM upstream for end-to-end checks.

mod eval;
mod golden;
mod latency;
mod mock;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use clap::{Parser, Subcommand};
use parda_core::{Config, MlDetector};
use parda_detect::RulesFile;
use parda_engine::{Engine, EngineOptions};
use parda_ml::ExecutionProvider;

#[derive(Parser)]
#[command(name = "parda-bench", about = "parda evaluation and latency harness")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Precision / recall / zero-leak / round-trip on the golden corpus.
    Eval {
        /// Model id (from the models dir) or `none` for rules only.
        #[arg(long, default_value = "none")]
        model: String,
        #[arg(long, default_value = "bench/golden")]
        golden: PathBuf,
        /// Models directory (default: $PARDA_HOME/data/models).
        #[arg(long)]
        models: Option<PathBuf>,
        #[arg(long, default_value = "auto")]
        ep: String,
        #[arg(long, default_value_t = 0.4)]
        threshold: f32,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// p50/p95 latency of the rules tier and of the model.
    Latency {
        #[arg(long, default_value = "none")]
        model: String,
        #[arg(long)]
        models: Option<PathBuf>,
        #[arg(long, default_value = "auto")]
        ep: String,
        #[arg(long, default_value_t = 30)]
        runs: usize,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Echo-style Anthropic/OpenAI upstream (JSON and SSE) for E2E tests.
    MockUpstream {
        #[arg(long, default_value_t = 9901)]
        port: u16,
        /// Append every received request body to this file.
        #[arg(long)]
        log: Option<PathBuf>,
    },
}

fn models_dir(arg: Option<PathBuf>) -> PathBuf {
    arg.unwrap_or_else(|| {
        std::env::var_os("PARDA_HOME")
            .map(|h| PathBuf::from(h).join("data/models"))
            .unwrap_or_else(|| PathBuf::from(".parda-dev/data/models"))
    })
}

fn load_ml(
    model: &str,
    models: &Path,
    ep: &str,
    threshold: f32,
) -> anyhow::Result<Option<Arc<dyn MlDetector>>> {
    if model == "none" {
        return Ok(None);
    }
    let ep: ExecutionProvider = ep.parse()?;
    let t = Instant::now();
    let det = parda_ml::load_detector(models, model, ep, threshold)
        .with_context(|| format!("loading {model} from {}", models.display()))?;
    eprintln!("loaded {model} in {} ms", t.elapsed().as_millis());
    Ok(Some(det))
}

fn engine(
    model: &str,
    ml: Option<Arc<dyn MlDetector>>,
) -> anyhow::Result<(tempfile::TempDir, Engine)> {
    let dir = tempfile::tempdir()?;
    let mut config = Config::default();
    config.detect.model = model.to_string();
    config.detect.ml_timeout_ms = 30_000;
    let e = Engine::open(
        EngineOptions {
            config,
            rules: RulesFile::default(),
            data_dir: dir.path().to_path_buf(),
            use_keyring: false,
        },
        ml,
    )?;
    Ok((dir, e))
}

fn write_json(out: Option<PathBuf>, v: &impl serde::Serialize) -> anyhow::Result<()> {
    let s = serde_json::to_string_pretty(v)?;
    match out {
        Some(p) => {
            if let Some(d) = p.parent() {
                std::fs::create_dir_all(d)?;
            }
            std::fs::write(&p, &s)?;
            eprintln!("wrote {}", p.display());
        }
        None => println!("{s}"),
    }
    Ok(())
}

fn run_eval(
    model: &str,
    golden: &Path,
    models: PathBuf,
    ep: &str,
    threshold: f32,
    out: Option<PathBuf>,
) -> anyhow::Result<()> {
    let mut cases = golden::load(&golden.join("names.jsonl"))?;
    cases.extend(golden::load(&golden.join("rules.jsonl"))?);
    let ml = load_ml(model, &models, ep, threshold)?;
    let (_dir, e) = engine(model, ml)?;
    let mut outcomes = Vec::with_capacity(cases.len());
    for c in &cases {
        let t = Instant::now();
        let detections = e.scan(&c.text)?;
        let ms = t.elapsed().as_secs_f64() * 1000.0;
        let red = e.redact(&c.text, "bench")?;
        let restored = e.restore(&red.text, "bench");
        outcomes.push(eval::Outcome {
            case: c,
            detections,
            redacted: red.text,
            restored,
            ms,
        });
    }
    if std::env::var_os("PARDA_BENCH_MISSES").is_some() {
        // The corpus is synthetic, so printing its values is fine.
        for o in &outcomes {
            for g in &o.case.entities {
                let gs = parda_core::Span::new(g.start, g.end);
                if !o
                    .detections
                    .iter()
                    .any(|d| d.kind.to_string() == g.kind && eval::matches(&d.span, &gs))
                {
                    let near: Vec<String> = o
                        .detections
                        .iter()
                        .filter(|d| d.span.overlaps(&gs))
                        .map(|d| {
                            format!(
                                "{}:{:?}:{:?}",
                                d.kind,
                                d.source,
                                &o.case.text[d.span.start..d.span.end]
                            )
                        })
                        .collect();
                    eprintln!(
                        "MISS {} {:?} in {:?} — overlapping: {}",
                        g.kind,
                        &o.case.text[g.start..g.end],
                        o.case.text,
                        if near.is_empty() {
                            "none".into()
                        } else {
                            near.join(", ")
                        }
                    );
                }
            }
            for d in &o.detections {
                let k = d.kind.to_string();
                if o.case.entities.iter().any(|g| g.kind == k) || o.case.region() == "NEG" {
                    let ok = o.case.entities.iter().any(|g| {
                        g.kind == k
                            && eval::matches(&d.span, &parda_core::Span::new(g.start, g.end))
                    });
                    if !ok {
                        eprintln!(
                            "FALSE {k}:{:?} {:?} in {:?}",
                            d.source,
                            &o.case.text[d.span.start..d.span.end],
                            o.case.text
                        );
                    }
                }
            }
        }
    }
    let report = eval::score(model, &outcomes);
    eprintln!(
        "\nmodel {model}: {} cases, mean {:.1} ms",
        report.cases, report.mean_ms
    );
    eprintln!(
        "{:<18} {:>6} {:>8} {:>10}",
        "kind", "gold", "recall", "precision"
    );
    for (k, s) in &report.per_kind {
        eprintln!(
            "{k:<18} {:>6} {:>8.3} {:>10.3}",
            s.gold, s.recall, s.precision
        );
    }
    for (r, v) in &report.person_recall_by_region {
        eprintln!("Person recall [{r}] = {v:.3}");
    }
    eprintln!(
        "zero-leak {:.3} · round-trip {:.3}",
        report.zero_leak_rate, report.round_trip_rate
    );
    write_json(out, &report)
}

fn run_latency(
    model: &str,
    models: PathBuf,
    ep: &str,
    runs: usize,
    out: Option<PathBuf>,
) -> anyhow::Result<()> {
    let mut timings = Vec::new();
    let (_d, rules_engine) = engine("none", None)?;
    for words in [64usize, 256] {
        let text = latency::fragment(words);
        timings.push(latency::time(
            &format!("rules scan, {words} words"),
            3,
            runs,
            || {
                let _ = rules_engine.scan(&format!("{text} {}", rand_suffix()));
            },
        ));
    }
    let big = "Contact ravi.k@gmail.com or +91 98765 43210 about order 12345.\n".repeat(16_000);
    timings.push(latency::time(
        &format!("rules redact, {} KB, uncached", big.len() / 1024),
        1,
        3,
        || {
            let _ = rules_engine.redact(&format!("{big}{}", rand_suffix()), "bench");
        },
    ));
    timings.push(latency::time(
        "rules redact, same text again (cache)",
        1,
        runs,
        || {
            let _ = rules_engine.redact(&big, "bench");
        },
    ));
    if let Some(ml) = load_ml(model, &models, ep, 0.5)? {
        for words in [64usize, 256] {
            let text = latency::fragment(words);
            timings.push(latency::time(
                &format!("{model} ({ep}), {words} words"),
                3,
                runs,
                || {
                    let _ = ml.detect_batch(&[text.as_str()]);
                },
            ));
        }
    }
    for t in &timings {
        eprintln!(
            "{:<45} p50 {:>8.2} ms  p95 {:>8.2} ms",
            t.label, t.p50_ms, t.p95_ms
        );
    }
    write_json(out, &timings)
}

/// Makes each input unique so the detection cache is bypassed.
fn rand_suffix() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    format!("#{}", N.fetch_add(1, Ordering::Relaxed))
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::Eval {
            model,
            golden,
            models,
            ep,
            threshold,
            out,
        } => run_eval(&model, &golden, models_dir(models), &ep, threshold, out),
        Cmd::Latency {
            model,
            models,
            ep,
            runs,
            out,
        } => run_latency(&model, models_dir(models), &ep, runs, out),
        Cmd::MockUpstream { port, log } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(mock::serve(port, log))
        }
    }
}
