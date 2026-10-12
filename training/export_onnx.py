"""Export a fine-tuned GLiNER model to ONNX and write a manifest with checksums
(consumed by `parda model import`).

The shipped artefact is the full-precision `model.onnx`: the ONNX Runtime
bundled with parda's `ort` crate (1.20) mis-executes the per-channel INT8
variant of this model (it drops names the same file finds on ORT 1.31), and
every other INT8 scheme tried loses recall. `--int8` still builds and gates
`model_quint8.onnx` for when the runtime is upgraded.

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


# Files the Rust runtime needs; everything else stays local.
SUPPORT_FILES = ("tokenizer.json", "gliner_config.json")


def recall_by_label(model, examples):
    hit, total = {}, {}
    for ex in examples:
        preds = {(p["start"], p["end"], p["label"])
                 for p in model.predict_entities(ex["text"], LABELS, threshold=0.4)}
        for e in ex["entities"]:
            g = (e["start"], e["end"], e["label"])
            total[g[2]] = total.get(g[2], 0) + 1
            if any(p[2] == g[2] and p[0] < g[1] and g[0] < p[1] for p in preds):
                hit[g[2]] = hit.get(g[2], 0) + 1
    return {k: hit.get(k, 0) / n for k, n in total.items()}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--gate-n", type=int, default=400)
    ap.add_argument("--max-drop", type=float, default=0.03, help="largest allowed per-label recall drop")
    ap.add_argument("--int8", action="store_true", help="ship a per-channel INT8 model instead of fp32")
    args = ap.parse_args()

    out = Path(args.out)
    torch_model = GLiNER.from_pretrained(args.model)
    torch_model.export_to_onnx(out, onnx_filename="model.onnx", quantize=False)
    manifest = {"labels": LABELS}
    model_name = "model.onnx"
    if args.int8:
        # Dynamic UInt8 quantization (the gliner default) destroys the identifier
        # labels of this model (Aadhaar recall 1.0 -> 0.03). Per-channel Int8
        # weights for MatMul/Gemm/Gather keep quality within ~1 point on ORT 1.31.
        from onnxruntime.quantization import QuantType, quantize_dynamic  # noqa: PLC0415

        quantize_dynamic(str(out / "model.onnx"), str(out / "model_quint8.onnx"),
                         weight_type=QuantType.QInt8, per_channel=True,
                         op_types_to_quantize=["MatMul", "Gemm", "Gather"])
        q = GLiNER.from_pretrained(str(out), load_onnx_model=True, onnx_model_file="model_quint8.onnx")
        examples = read_jsonl(ROOT / "data/test.chars.jsonl")[: args.gate_n]
        base, quant = recall_by_label(torch_model, examples), recall_by_label(q, examples)
        drops = {k: round(base[k] - quant.get(k, 0.0), 4) for k in base}
        print("recall drop torch -> int8 by label:", drops)
        manifest["quantization"] = "dynamic int8, per-channel, MatMul/Gemm/Gather"
        manifest["recall_drop_vs_torch"] = drops
        model_name = "model_quint8.onnx"
        worst = max(drops.values(), default=0.0)
        if worst > args.max_drop:
            raise SystemExit(f"int8 model loses {worst:.1%} recall on a label (> {args.max_drop:.0%})")
        (out / "model.onnx").unlink()  # one model file per directory
    manifest["files"] = {name: {"sha256": sha256(out / name), "size": (out / name).stat().st_size}
                         for name in (model_name, *SUPPORT_FILES)}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(json.dumps(manifest["files"], indent=2))


if __name__ == "__main__":
    main()
