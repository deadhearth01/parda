//! [`MlDetector`] backed by a token-level GLiNER model (via `gline-rs`).

use std::path::Path;

use anyhow::Context;
use gliner::model::GLiNER;
use gliner::model::input::text::TextInput;
use gliner::model::params::Parameters;
use gliner::model::pipeline::token::TokenMode;
use orp::params::RuntimeParameters;
use parda_core::{Detection, EntityKind, MlDetector, Source, Span};

use crate::catalog::ml_labels;
use crate::ep::ExecutionProvider;

pub struct GlinerDetector {
    model: GLiNER<TokenMode>,
    labels: Vec<String>,
    kinds: Vec<EntityKind>,
    name: String,
}

impl GlinerDetector {
    /// Load `model_quint8.onnx` + `tokenizer.json` from `dir`.
    pub fn load(dir: &Path, threshold: f32, ep: ExecutionProvider) -> anyhow::Result<Self> {
        let threads = std::thread::available_parallelism()
            .map(|n| n.get().min(4))
            .unwrap_or(2);
        let runtime = RuntimeParameters::default()
            .with_threads(threads)
            .with_execution_providers(ep.dispatch());
        let params = Parameters::default().with_threshold(threshold);
        let model = GLiNER::<TokenMode>::new(
            params,
            runtime,
            dir.join("tokenizer.json"),
            dir.join("model_quint8.onnx"),
        )
        .map_err(|e| anyhow::anyhow!("loading GLiNER model from {}: {e}", dir.display()))?;
        let (labels, kinds) = ml_labels()
            .into_iter()
            .map(|(l, k)| (l.to_string(), k))
            .unzip();
        Ok(GlinerDetector {
            model,
            labels,
            kinds,
            name: "gliner".into(),
        })
    }

    pub fn named(mut self, name: &str) -> Self {
        self.name = name.to_string();
        self
    }
}

impl MlDetector for GlinerDetector {
    fn name(&self) -> &str {
        &self.name
    }

    fn detect_batch(&self, texts: &[&str]) -> anyhow::Result<Vec<Vec<Detection>>> {
        let mut out = vec![Vec::new(); texts.len()];
        // gline-rs rejects inputs without any word; skip them.
        let idx: Vec<usize> = (0..texts.len())
            .filter(|&i| texts[i].chars().any(char::is_alphanumeric))
            .collect();
        if idx.is_empty() {
            return Ok(out);
        }
        let input = TextInput::new(
            idx.iter().map(|&i| texts[i].to_string()).collect(),
            self.labels.clone(),
        )
        .map_err(|e| anyhow::anyhow!("building GLiNER input: {e}"))?;
        let output = self
            .model
            .inference(input)
            .map_err(|e| anyhow::anyhow!("GLiNER inference: {e}"))?;
        for (seq, spans) in output.spans.iter().enumerate() {
            let target = idx[seq];
            let text = texts[target];
            for s in spans {
                let (start, end) = s.offsets();
                if end > text.len()
                    || !text.is_char_boundary(start)
                    || !text.is_char_boundary(end)
                    || start >= end
                {
                    continue;
                }
                let kind = self
                    .labels
                    .iter()
                    .position(|l| l == s.class())
                    .map(|i| self.kinds[i].clone())
                    .context("model returned an unknown label")?;
                out[target].push(Detection {
                    span: Span::new(start, end),
                    kind,
                    score: s.probability(),
                    source: Source::Ml,
                });
            }
        }
        Ok(out)
    }
}
