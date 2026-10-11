# Notes: masking strategy, stream handling, packaging, TUI

## Masking strategy (what to replace PII with)
- Pasch & Cha, PrivateNLP @ NAACL 2025 (https://aclanthology.org/2025.privatenlp-main.3/): tested simple masking, masking + context, pseudonymization on intro/cover-letter/email tasks. ~1 point quality loss on 10-pt scale while masking 97–99% of entities. Llama 3.3 70B best with simple masking; GPT-4o benefited from contextual cues. => Best strategy is model-dependent; let user choose; contextual placeholders are a good default.
- token-proxy (zolderio): bracket placeholders like [User_Email_1] caused Claude to hallucinate realistic replacements inside KQL queries; random fakes destroyed semantics (IP geo). Fix: type-consistent, context-preserving surrogates (same ASN/country IP).
- privalyse-mask (MIT, early): semantic placeholders keep coarse attributes: {Date_March_1990}, {Email_at_company.com}, {Name_a8f}. Chat-history-consistent mapping. Streaming "coming soon".
- rdx: format-preserving fake names with case preservation; deterministic SHA-256 tokens; person "blocks" expanding variants.
- TrueFoundry blog (2026-09-28): taxonomy — masking/redaction irreversible; tokenisation/FPE/pseudonymisation reversible via vault/key. Failure modes when masking LLM traffic: (1) quality drops unevenly; (2) tool calls need real value — mask model path but tool args may still leak to MCP; (3) JSON schema / structured output breaks (format: email can't hold [REDACTED]); (4) multi-turn consistency needs stateful deterministic mapping; (5) RAG embedding mismatch. Their own gateway: no unmasking on response path; output guardrails skipped when stream=true; system prompts never masked. GDPR: pseudonymised data is still personal data (Recital 26).
- => Differentiators: stateful, deterministic, reversible, type/format-preserving surrogates; restore inside streamed SSE deltas and tool_use JSON args; mask system prompts and tool results too.

## Streaming restoration
- pii-hole buffers just enough to reassemble a token split across SSE chunks; restores in tool calls too.
- token-proxy: 80-char tail buffer per chunk.
- Design: a streaming Aho-Corasick over all active surrogates; hold back only the longest-possible partial-match suffix (bounded by max surrogate length) instead of a fixed 80 chars => minimal added latency.

## Latency budget (from benchmarks)
- Regex/checksum: ~0.1 ms/text (albertsikkema); Grepture claims <2 ms regex.
- Presidio+spaCy: ~15 ms/text (M1 Pro CPU).
- Transformer NER CPU: Piiranha 119 ms, GLiNER v1 161 ms, GLiNER2 198 ms median (M1 Pro); PII Engineer Rust+INT8 ~180 ms p50; Fastino GLiNER2.5 167 ms p50 @64 tokens.
- HN user: any perceptible delay on paste causes abandonment -> run NER at copy time / while typing (debounced, incremental), and only do cheap work at send time.
- Ideas: two-tier (instant deterministic tier + async NER tier); cache detections per paragraph hash so resent history (agents resend full conversation each turn) costs ~0; CoreML/ANE (macOS), DirectML (Windows), CUDA/ROCm/OpenVINO (Linux) via ort EPs.

## Cross-platform engineering
- ONNX Runtime via Rust `ort` crate (ort.pyke.io, 2026-07-28 docs): EPs via Cargo features — CUDA, TensorRT, DirectML (Windows), CoreML (Apple, ComputeUnits::CPUAndNeuralEngine), WebGPU (experimental; Win/macOS/Linux). Silent CPU fallback unless error_on_failure(). CUDA/TensorRT EPs need dynamic libs.
- GLiNER Rust port `gline-rs` ("4x faster than Python on CPU"), GLiNER.cpp, GLiNER.js. knowledgator ONNX: FP16 330MB, UINT8 197MB (base).
- Clipboard: `arboard` (1Password; 972 stars). Linux default X11/XWayland; Wayland needs `wayland-data-control` feature and compositor support for data-control protocol; Flatpak/Snap need X11 socket. Linux clipboard ownership: data served by owning process (must keep process alive — fine for a daemon).
- Wayland global shortcuts: new protocol under discussion (2026); historically restricted => on Wayland use desktop-portal GlobalShortcuts or DE-specific bindings that call `tool paste-safe` CLI.
- Packaging: `dist` (formerly cargo-dist, v0.33.0 2026-09-11) generates `curl ... | sh` and `powershell -c "irm ... | iex"` installers, Homebrew formulae, MSI, npm packages, GitHub Release CI. Targets: Linux x64/arm64 (gnu+musl), macOS Intel/Apple Silicon, Windows x64.
- TUI: ratatui (Rust, community fork of tui-rs; crossterm backend works on Windows/macOS/Linux).

## India-specific identifiers
- Presidio has IN_PAN, IN_AADHAAR (pattern+context+checksum — Verhoeff), IN_VEHICLE_REGISTRATION, IN_VOTER, IN_PASSPORT, IN_GSTIN (https://presidio.dataprivacystack.org/supported_entities/). Also UK/US/ES/IT/PL/SG/AU/FI/KR/NG/PH/CA/SE/ZA/TH/TR/DE sets — a good spec to port into a Rust recognizer pack.
- openai/privacy-filter card warns about under-detection of regional naming conventions -> Indian names are a known risk; need eval set + user dictionaries.
