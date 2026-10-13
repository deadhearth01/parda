# Model card — `parda-pii-edge`

A small on-device named-entity model that finds personal data in chat prompts, documents,
code and logs, tuned for Indian names and identifiers while keeping global coverage. It is the
ML tier of [parda](README.md); format-checked identifiers (cards, Aadhaar, PAN, IBAN …) are
also caught by parda's rule tier, so the model's main job is names and addresses.

| | |
|---|---|
| Architecture | GLiNER, token-level (Ettin encoder, ~32M parameters + span heads) |
| Base model | [knowledgator/gliner-pii-edge-v1.0](https://huggingface.co/knowledgator/gliner-pii-edge-v1.0) (Apache-2.0) |
| Fine-tuning data | 20,000 synthetic examples from `training/datagen` — see [DATA_CARD.md](DATA_CARD.md) |
| Format | ONNX, fp32, 181 MB (`model.onnx` + `tokenizer.json` + `gliner_config.json`) |
| Runtime | ONNX Runtime via the `ort` crate, CPU (CoreML / DirectML / CUDA optional) |
| Licence | Apache-2.0 |
| Labels | person, email, phone number, address, organization, date of birth, aadhaar number, pan number, upi id, bank account number, ifsc code, passport number, credit card number, ip address, username, password |

## Training

- Recipe: `training/train_gliner.py` — 2,500 optimizer steps, batch 8 × 4 accumulation,
  learning rate 1e-5 (encoder) / 5e-5 (heads), cosine schedule, focal loss (α 0.75, γ 2),
  CPU (Apple M4, 24 min).
- Checkpoint selection: the hand-written golden corpus, not the synthetic dev split (which shares
  templates with training and reaches near-zero loss). Step 2,250 was best and is the release.
- Export: `training/export_onnx.py`. The fp32 export matches PyTorch exactly.

## Evaluation

### Through parda itself (Rust engine, all tiers, threshold 0.4)

`parda-bench eval` on `bench/golden` (213 hand-written cases: Indian and global names, Hinglish,
multi-sentence messages with several names, negatives, identifiers, code and logs; never produced by
the training templates):

| | gliner-pii-edge (base, INT8) | **parda-pii-edge** |
|---|---|---|
| Person recall, Indian names | 0.946 | **0.968** |
| Person recall, global names | 0.964 | **1.000** |
| Person precision | 0.934 | **1.000** |
| Address recall / precision | 0.75 / 0.27 | **1.00 / 1.00** |
| Cases with zero leaked values | 0.986 | **0.991** |
| `restore(redact(x)) == x` | 1.000 | 1.000 |

A second fine-tune with 35% stitched multi-sentence examples was more precise (no false positives)
but missed more Indian names (0.946), so this release keeps the first.

Base-model misses include "Venkatesh Iyer", "Yash", "Siobhan O'Brien", "Nguyễn Văn An" and
two Indian addresses; it also labels many non-addresses as addresses.

### Model alone (Python, held-out synthetic test, 600 examples, threshold 0.4)

The test split uses person names never seen in training, but the same sentence templates, so
these numbers are optimistic; they show what the fine-tune added on Indian identifiers and form
/ code / log layouts.

| Label | Base recall | Base precision | parda recall | parda precision |
|---|---|---|---|---|
| person | 0.68 | 0.88 | 1.00 | 0.93 |
| phone number | 0.99 | 0.67 | 1.00 | 1.00 |
| email | 0.97 | 0.89 | 1.00 | 1.00 |
| address | 1.00 | 0.85 | 1.00 | 1.00 |
| organization | 0.90 | 0.29 | 1.00 | 0.74 |
| aadhaar number | 0.15 | 0.21 | 1.00 | 1.00 |
| pan number | 0.02 | 0.04 | 1.00 | 1.00 |
| upi id | 0.00 | 0.00 | 0.98 | 1.00 |
| ifsc code | 0.97 | 0.49 | 1.00 | 1.00 |
| bank account number | 0.18 | 0.62 | 1.00 | 1.00 |
| password | 0.94 | 0.26 | 1.00 | 1.00 |
| macro F1 (16 labels) | 0.57 | | 0.99 | |

### Speed

`parda-bench latency`, Apple M4, CPU only, measured while other builds were running (expect
lower numbers on an idle machine):

| | 64 words p50 | 256 words p50 / p95 |
|---|---|---|
| gliner-pii-edge (INT8) | 8.9 ms | 36.9 / 41.6 ms |
| parda-pii-edge (fp32) | 43.4 ms | 159.7 / 187.2 ms |

Repeated text (agents resend history every turn) is served from parda's cache, so only new
text pays this cost.

## Why fp32 and not INT8

Per-channel INT8 (57 MB) keeps every label within 1 point of the fp32 model on ONNX Runtime
1.31, but on the ONNX Runtime bundled with parda's current `ort` crate it drops some names
outright, and every other INT8 scheme tried (UInt8, per-tensor, with and without embeddings,
reduced range) loses 3–6 points of person recall. parda therefore ships fp32 until the runtime
is upgraded; `export_onnx.py --int8` builds and gates the INT8 variant.

## Intended use and limits

- Intended for redacting personal data in text sent from a user's machine to cloud AI services.
- English and romanised Hindi / Hinglish. Native scripts (Devanagari, Tamil, Bengali …) are not
  covered by the training data; parda's rule and dictionary tiers still apply to them.
- Synthetic training data does not match every real-world style; the golden corpus is small
  (201 cases). Evaluate on your own data before relying on it for compliance.
- Public figures are redacted like anyone else (a deliberate choice: missing a private name is
  worse than masking a public one).
- No personal data from real people was used in training.

## Reproduce

```bash
cd training
python -m datagen.generate --n 20000 --seed 7 --split train --out data/train.jsonl
python -m datagen.generate --n 2000 --seed 7 --split dev --out data/dev.jsonl
python -m datagen.generate --n 2000 --seed 7 --split test --out data/test.jsonl
python train_gliner.py --cpu --name parda-pii-edge
python export_onnx.py --model runs/parda-pii-edge/final --out out/parda-pii-edge
parda model import out/parda-pii-edge && parda model use parda-pii-edge
```
