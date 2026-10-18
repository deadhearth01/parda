//! Print raw model detections (no engine filtering) for each argument.
//!
//!     cargo run --release -p parda-ml --example probe -- <model-dir> <threshold> "text" ...
use std::path::Path;

use parda_core::MlDetector;
use parda_ml::{ExecutionProvider, GlinerDetector};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (dir, threshold, texts) = match args.as_slice() {
        [dir, t, texts @ ..] if !texts.is_empty() => (dir, t.parse::<f32>()?, texts),
        _ => anyhow::bail!("usage: probe <model-dir> <threshold> TEXT..."),
    };
    let det = GlinerDetector::load(Path::new(dir), threshold, ExecutionProvider::Cpu)?;
    let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
    for (t, dets) in refs.iter().zip(det.detect_batch(&refs)?) {
        let found: Vec<String> = dets
            .iter()
            .map(|d| {
                format!(
                    "{}={:?}({:.2})",
                    d.kind,
                    &t[d.span.start..d.span.end],
                    d.score
                )
            })
            .collect();
        println!("{t}\n    {}", found.join("  "));
    }
    Ok(())
}
