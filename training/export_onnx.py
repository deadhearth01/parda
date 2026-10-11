"""Export a fine-tuned GLiNER model to ONNX (fp32 + dynamic INT8), check that
the quantized model agrees with the PyTorch model, and write checksums.

    python export_onnx.py --model runs/parda-pii-edge/final --out out/parda-pii-edge
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from common import LABELS, ROOT, read_jsonl, ssd_env

ssd_env()

from gliner import GLiNER  # noqa: E402


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def spans(model, text):
    return {(p["start"], p["end"], p["label"]) for p in model.predict_entities(text, LABELS, threshold=0.5)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--parity-n", type=int, default=300)
    args = ap.parse_args()

    out = Path(args.out)
    torch_model = GLiNER.from_pretrained(args.model)
    paths = torch_model.export_to_onnx(out, onnx_filename="model.onnx",
                                       quantized_filename="model_quint8.onnx", quantize=True)
    print("exported", paths)

    onnx_q = GLiNER.from_pretrained(str(out), load_onnx_model=True, onnx_model_file="model_quint8.onnx")
    texts = [ex["text"] for ex in read_jsonl(ROOT / "data/test.chars.jsonl")[: args.parity_n]]
    disagree = 0
    total = 0
    for t in texts:
        a, b = spans(torch_model, t), spans(onnx_q, t)
        total += max(1, len(a | b))
        disagree += len(a ^ b)
    rate = disagree / max(1, total)
    print(f"parity: {disagree} disagreeing spans of {total} ({rate:.2%})")

    manifest = {
        "files": {p.name: {"sha256": sha256(p), "size": p.stat().st_size}
                  for p in sorted(out.iterdir()) if p.is_file()},
        "parity_disagreement_rate": rate,
        "labels": LABELS,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(json.dumps(manifest, indent=2))
    if rate > 0.02:
        raise SystemExit(f"quantized model disagrees with torch model on {rate:.2%} of spans (> 2%)")


if __name__ == "__main__":
    main()
