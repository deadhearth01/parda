# Notes: local PII detection models and benchmarks

## openai/privacy-filter (HF model card, fetched 2026-10-11)
- Source: https://huggingface.co/openai/privacy-filter ; repo https://github.com/openai/privacy-filter
- Bidirectional token classifier converted from an autoregressive gpt-oss-style checkpoint. 1.5B total params, ~50M active (sparse MoE, 128 experts, top-4). 8 blocks, d_model 640.
- 8 fixed labels: account_number, private_address, private_email, private_person, private_phone, private_url, private_date, secret. BIOES tags -> 33 classes; constrained Viterbi span decoding.
- Apache 2.0. "Runs in a web browser or on a laptop". 128k context, banded attention (window 257 tokens).
- Runtime precision/recall "operating points" via decoder transition biases.
- Transformers.js usage shown with device "webgpu", dtype "q4" -> can run inside a browser extension.
- Model card limitations: primarily English; under-detects uncommon/regional names, initials, honorifics; over-redacts public entities; label policy NOT configurable at runtime (needs fine-tune).
- ~350k downloads/month.

## heyneo.com eval: GLiNER large-v2.1 vs openai/privacy-filter (ai4privacy/pii-masking-400k, 600 samples)
- Source: https://heyneo.com/blog/pii-filter-model-eval
- Strict F1 misleading: privacy-filter loses ~0.34 F1 to BPE leading-space offset drift. Boundary-match macro F1 EN: privacy-filter 0.498 vs GLiNER 0.416. Multilingual: 0.556 vs 0.451.
- Email boundary F1: privacy-filter 0.987 (EN), 1.0 (ML). PERSON ~0.69 both.
- GLiNER: high recall/low precision (PHONE recall 0.92, precision 0.35). Best threshold 0.7 (default 0.5 is ~8 F1 pts worse).
- CPU throughput: privacy-filter ~2.8 samples/s vs GLiNER-large ~1.1 samples/s.
- Practical lesson: offsets from BPE tokenizers must be trimmed of leading whitespace before replacement.

## albertsikkema.com benchmark (2026-06-01), Apple M1 Pro CPU
- Source: https://albertsikkema.com/python/security/privacy/2026/06/01/benchmarking-open-source-pii-detection.html
- 5 approaches x 4 datasets (AI4Privacy, Gretel finance, Nemotron-PII, CoNLL-2002 NL). Shared labels: PERSON, EMAIL, PHONE, LOCATION, CREDITCARD, IBAN.
- Avg F1: Piiranha (DeBERTa-v3-base 86M) 0.542; GLiNER v1 multi_pii 0.535; Presidio (spaCy lg) 0.481; GLiNER2 base 0.478; regex 0.171.
- Piiranha collapses OOD (0.78 -> 0.17 on finance). GLiNER v1 most stable (0.455–0.607).
- Speed (median per text, M1 Pro CPU): regex 0.1 ms; Presidio 15.1 ms; Piiranha 118.5 ms; GLiNER v1 161 ms; GLiNER v2 198 ms.
- Email: Presidio's pattern recognizer best (0.93–0.996). Names: hardest; regex = 0.
- Reversibility (restore(redact(x))==x): regex/Piiranha/GLiNER 100%, Presidio 64% (offset misalignment, fixable).
- Regex+NER merge added ~0 F1 on their sets (but note: their regex set was small; structured IDs w/ checksums are a different story).
- Cross-domain is unsolved: PIIBench best system F1 0.14; Tonic found OpenAI Privacy Filter drops 0.96 -> 0.18–0.65 OOD.
- Recommendation: Presidio as framework + plug better NER (GLiNER) as custom recognizer.

## Fastino GLiNER2-PII (2026-05-14)
- Source: https://fastino.ai/blog/gliner2-pii-open-source-privacy-filtering-with-pii-detection
- 300M params, multilingual, Apache 2.0, 42 entity types incl. gov IDs, tax IDs, IBAN, card/CVV, username, IP, password/API key/token, DOB. Label-conditioned (custom schema at inference).
- SPY benchmark (legal + medical, OOD): avg F1 0.471 vs NVIDIA GLiNER-PII 0.391, urchade 0.384, OpenAI Privacy Filter 0.373, knowledgator 0.368. Recall 0.72/0.68. (Vendor benchmark.)
- Separate source (shattered.io, 2026-09-26) quotes Fastino p50 167 ms @ batch 1, 64 tokens on CPU for GLiNER2.5 340M.

## knowledgator GLiNER-PII family (HF card)
- Source: https://huggingface.co/knowledgator/gliner-pii-small-v1.0
- edge / small / base / large. F1 on synthetic-multi-pii-ner-v1: edge 75.5, small 76.8, base 81.0, large 83.3 (urchade multi_pii 76.9).
- 60+ predefined PII labels; quantization-aware training; ONNX FP16 330MB / UINT8 197MB (base).
- Ports: gline-rs (Rust, "4x faster than Python on CPU"), GLiNER.cpp, GLiNER.js (onnxruntime-web, WebGPU).
- Recommended threshold 0.3 (vs heyneo found 0.7 better for gliner_large-v2.1 — threshold is model-specific; tune).

## PII Engineer (Rust + GLiNER2) — users.rust-lang.org post (2026-05-05)
- Source: https://users.rust-lang.org/t/building-a-production-multilingual-pii-detection-system-in-rust-with-gliner2/139964
- mDeBERTa-v3-base GLiNER2 (280M) split into 5 ONNX graphs; INT8 encoder, FP32 heads. ort + tokenizers + axum. ~180 ms p50 on CPU, 50+ languages.
- 8-stage post-processing: reclassify, validate, filter, normalize, email/IP regex detect, threshold, dedup, merge.

## Other models to note (not yet verified in detail)
- iiiorg/piiranha-v1 (DeBERTa-v3-base, 17 types).
- ai4privacy models/datasets (pii-masking-300k/400k).
- nvidia/gliner-PII.
- urchade/gliner_multi_pii-v1.

## Corrections / additions (search results 2026-10-11)
- OpenAI Privacy Filter release date: 2026-04-22 (openai.com/index/introducing-openai-privacy-filter). heyneo's "April 2025" is wrong. Claims F1 96% on PII-Masking-300k (P 94.04 / R 98.04).
- Tonic.ai (2026-04-24, tonic.ai/blog/benchmarking-openai-privacy-filter-pii-detection): on real documents OPF dropped to ~18% F1 on web data (per Tonic CEO LinkedIn summary); Tonic Textual emits 26 labels vs OPF 8.
- arXiv 2608.02616 (2026-08): OPF degrades to F1 0.04–0.40 on general NER benchmarks (MultiCoNER).
- GLiNER2-PII HF id: fastino/gliner2-privacy-filter-PII-multi (HF card says 205M params; blog says 300M). Community ONNX exports: jugaadsrl/gliner2-privacy-filter-PII-multi-onnx, yethdev/gliner2-pii-onnx ("2.75x smaller, near performance"). Fastino also ships GLiNER2-Guardrails-PII-Multi (safety + PII in one pass).
