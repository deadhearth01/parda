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
    /// Run one text per inference. Dynamically quantized models scale
    /// activations over the whole padded batch, so batch neighbours would
    /// change each other's results.
    one_at_a_time: bool,
}

impl GlinerDetector {
    /// Load the model's ONNX file (see [`crate::MODEL_FILES`]) and
    /// `tokenizer.json` from `dir`.
    pub fn load(dir: &Path, threshold: f32, ep: ExecutionProvider) -> anyhow::Result<Self> {
        let threads = std::thread::available_parallelism()
            .map(|n| n.get().min(4))
            .unwrap_or(2);
        let runtime = RuntimeParameters::default()
            .with_threads(threads)
            .with_execution_providers(ep.dispatch());
        let params = Parameters::default().with_threshold(threshold);
        let model_path = crate::manager::model_file(dir)
            .with_context(|| format!("no ONNX model in {}", dir.display()))?;
        let one_at_a_time = model_path.file_name() == Some("model_quint8.onnx".as_ref());
        let model =
            GLiNER::<TokenMode>::new(params, runtime, dir.join("tokenizer.json"), model_path)
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
            one_at_a_time,
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
        let groups: Vec<Vec<usize>> = if self.one_at_a_time {
            idx.into_iter().map(|i| vec![i]).collect()
        } else if idx.is_empty() {
            Vec::new()
        } else {
            vec![idx]
        };
        for group in groups {
            self.infer(texts, &group, &mut out)?;
        }
        Ok(out)
    }
}

impl GlinerDetector {
    /// Run one inference over `texts[i]` for each `i` in `group`.
    fn infer(
        &self,
        texts: &[&str],
        group: &[usize],
        out: &mut [Vec<Detection>],
    ) -> anyhow::Result<()> {
        let input = TextInput::new(
            group.iter().map(|&i| texts[i].to_string()).collect(),
            self.labels.clone(),
        )
        .map_err(|e| anyhow::anyhow!("building GLiNER input: {e}"))?;
        let output = self
            .model
            .inference(input)
            .map_err(|e| anyhow::anyhow!("GLiNER inference: {e}"))?;
        for (seq, spans) in output.spans.iter().enumerate() {
            let target = group[seq];
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
        Ok(())
    }
}
