"""Evaluate a GLiNER model on parda's held-out synthetic test split and the
hand-written golden corpus (bench/golden/names.jsonl).

Matching is overlap-based (a prediction counts if it overlaps a gold span with
the same label) because honorifics/titles may or may not be inside a span.

    python eval_gliner.py --model knowledgator/gliner-pii-edge-v1.0 --tag base
    python eval_gliner.py --model runs/parda-pii-edge/final --tag ft
"""

from __future__ import annotations

import argparse
import statistics
import time
from collections import defaultdict

from common import KIND_TO_LABEL, LABELS, REPO, ROOT, read_jsonl, ssd_env, write_json

ssd_env()

from gliner import GLiNER  # noqa: E402


def overlaps(a, b) -> bool:
    return a[0] < b[1] and b[0] < a[1]


HONORIFIC_PREFIXES = ("late shri ", "shri ", "smt. ", "smt ", "mr. ", "mrs. ", "ms. ", "dr. ", "prof. ",
                      "professor ", "baby of ", "sir ", "madam ")
HONORIFIC_SUFFIXES = (" ji", " jr.", " sr.", " bhai", " bhaiya", " uncle", " aunty", " amma", " didi")


def norm_span(text, s, e):
    """Trim honorifics/address words so 'Mr. Prakash Rao' == 'Prakash Rao'."""
    frag = text[s:e]
    low = frag.lower()
    changed = True
    while changed:
        changed = False
        for pre in HONORIFIC_PREFIXES:
            if low.startswith(pre):
                s += len(pre); frag = frag[len(pre):]; low = low[len(pre):]; changed = True
        for suf in HONORIFIC_SUFFIXES:
            if low.endswith(suf):
                e -= len(suf); frag = frag[: -len(suf)]; low = low[: -len(suf)]; changed = True
    return s, e


def score(model, examples, threshold, labels):
    """examples: list of (group, text, [(start_char, end_char, label)])."""
    tp = defaultdict(int)
    fn = defaultdict(int)
    fp = defaultdict(int)
    per_group = defaultdict(lambda: defaultdict(lambda: [0, 0]))  # group -> label -> [hit, total]
    neg_fp = defaultdict(int)
    exact_tp = defaultdict(int)
    fp_examples = []
    latencies = []
    for group, text, gold in examples:
        t = time.perf_counter()
        preds = model.predict_entities(text, labels, threshold=threshold)
        latencies.append((time.perf_counter() - t) * 1000)
        pred_spans = [(p["start"], p["end"], p["label"]) for p in preds]
        normed_preds = {(*norm_span(text, p[0], p[1]), p[2]) for p in pred_spans}
        for g in gold:
            if (*norm_span(text, g[0], g[1]), g[2]) in normed_preds:
                exact_tp[g[2]] += 1
            hit = any(overlaps(g, p) and p[2] == g[2] for p in pred_spans)
            per_group[group][g[2]][1] += 1
            if hit:
                tp[g[2]] += 1
                per_group[group][g[2]][0] += 1
            else:
                fn[g[2]] += 1
        for p in pred_spans:
            if not any(overlaps(g, p) and p[2] == g[2] for g in gold):
                fp[p[2]] += 1
                if len(fp_examples) < 40:
                    fp_examples.append({"group": group, "label": p[2], "span": text[p[0]:p[1]], "text": text[:120]})
                if group == "NEG":
                    neg_fp[p[2]] += 1
    report = {}
    for label in sorted(set(tp) | set(fn) | set(fp)):
        r = tp[label] / max(1, tp[label] + fn[label])
        p = tp[label] / max(1, tp[label] + fp[label])
        f1 = 0 if p + r == 0 else 2 * p * r / (p + r)
        n_gold = tp[label] + fn[label]
        n_pred = tp[label] + fp[label]
        er = exact_tp[label] / max(1, n_gold)
        ep = exact_tp[label] / max(1, n_pred)
        ef1 = 0 if er + ep == 0 else 2 * er * ep / (er + ep)
        report[label] = {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4),
                         "exact_f1": round(ef1, 4), "tp": tp[label], "fn": fn[label], "fp": fp[label]}
    groups = {g: {l: round(h / max(1, n), 4) for l, (h, n) in d.items()} for g, d in per_group.items()}
    return {
        "per_label": report,
        "recall_by_group": groups,
        "negatives_false_positives": dict(neg_fp),
        "false_positive_examples": fp_examples,
        "latency_ms": {"p50": round(statistics.median(latencies), 2),
                       "p95": round(sorted(latencies)[int(0.95 * (len(latencies) - 1))], 2)},
        "n": len(examples),
    }


def golden_examples():
    out = []
    for ex in read_jsonl(REPO / "bench/golden/names.jsonl"):
        b = ex["text"].encode("utf-8")
        gold = []
        for e in ex["entities"]:
            # byte offsets -> char offsets
            s = len(b[: e["start"]].decode("utf-8"))
            t = len(b[: e["end"]].decode("utf-8"))
            label = KIND_TO_LABEL.get(e["kind"])
            if label:
                gold.append((s, t, label))
        out.append((ex["region"], ex["text"], gold))
    return out


def synthetic_examples(path, limit):
    out = []
    for ex in read_jsonl(path)[:limit]:
        gold = [(e["start"], e["end"], e["label"]) for e in ex["entities"]]
        group = "IN" if ex.get("region") == "india" else "GL"
        if not gold:
            group = "NEG"
        out.append((group, ex["text"], gold))
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--tag", required=True)
    ap.add_argument("--test", default=str(ROOT / "data/test.chars.jsonl"))
    ap.add_argument("--limit", type=int, default=2000)
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--onnx", default=None, help="ONNX file name inside --model dir")
    args = ap.parse_args()

    if args.onnx:
        model = GLiNER.from_pretrained(args.model, load_onnx_model=True, onnx_model_file=args.onnx)
    else:
        model = GLiNER.from_pretrained(args.model)
    result = {"model": args.model, "threshold": args.threshold}
    result["golden"] = score(model, golden_examples(), args.threshold,
                             ["person", "email", "phone number", "address"])
    try:
        result["synthetic_test"] = score(model, synthetic_examples(args.test, args.limit), args.threshold, LABELS)
    except FileNotFoundError:
        result["synthetic_test"] = None
    write_json(ROOT / f"out/eval-{args.tag}.json", result)
    g = result["golden"]
    print(f"[{args.tag}] golden person recall: IN={g['recall_by_group'].get('IN', {}).get('person')} "
          f"GL={g['recall_by_group'].get('GL', {}).get('person')} exactF1={g['per_label'].get('person', {}).get('exact_f1')} "
          f"neg_fp={g['negatives_false_positives']} "
          f"latency={g['latency_ms']}")
    if result["synthetic_test"]:
        s = result["synthetic_test"]
        print(f"[{args.tag}] synthetic test: " + ", ".join(
            f"{k}: R={v['recall']} P={v['precision']} xF1={v['exact_f1']}" for k, v in s["per_label"].items()))


if __name__ == "__main__":
    main()
