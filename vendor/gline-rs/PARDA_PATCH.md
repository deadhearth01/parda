# Vendored gline-rs 1.1.0 (Apache-2.0)

Upstream: https://github.com/fbilhaut/gline-rs — crates.io `gline-rs` 1.1.0, © its authors,
licensed under the Apache License 2.0 (see `LICENSE.txt`).

parda vendors this crate via `[patch.crates-io]` with one modification:

- `src/model/output/decoded/token.rs`: token-mode decoding accepts logits in the
  channels-last layout `(batch, num_words, num_classes, 3)` emitted by current GLiNER
  ONNX exporters (gliner ≥ 0.2.2x, e.g. knowledgator/gliner-pii-*-v1.0), in addition to
  the original `(3, batch, num_words, num_classes)` layout, using a zero-copy axis
  permutation.

Drop this vendored copy once upstream supports both layouts.
- `src/text/tokenizer.rs` + `src/model/input/encoded.rs`: the sequence start/end token ids
  are read from the model's tokenizer (`[CLS]`/`<s>`, `[SEP]`/`</s>`) instead of being
  hard-coded to 1 and 2 (DeBERTa ids). Required for ModernBERT/Ettin-based GLiNER models,
  whose `[CLS]`/`[SEP]` are 50281/50282.

Note: some of the vendored crate's own unit tests (`encoded::tests::*`,
`tensors::span::tests::test`) load `models/gliner_small-v2.1/tokenizer.json`, which is not
part of the published crate, so they fail when run here; they are not part of parda's test
suite (the vendored crate is excluded from the workspace).
- `Cargo.toml` + `src/text/tokenizer.rs`: `tokenizers` is built without default features
  (keeping only `onig`) and `HFTokenizer::from_pretrained` (network download) is removed.
  The default `esaxx_fast` feature compiles C++ with the static CRT, which fails to link with
  ONNX Runtime (dynamic CRT) on Windows/MSVC (LNK2038); parda never downloads tokenizers here.
