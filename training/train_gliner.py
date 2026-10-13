"""Fine-tune a GLiNER PII model on parda's synthetic India-first data.

Example (smoke run):
    python train_gliner.py --smoke
Full run:
    python train_gliner.py --max-steps 3000 --name parda-pii-edge-v1
"""

from __future__ import annotations

import argparse
import random
import time
from pathlib import Path

from common import ROOT, read_jsonl, ssd_env

ssd_env()

import torch  # noqa: E402
from gliner import GLiNER  # noqa: E402


def compose(examples, rate, rng, max_tokens=280):
    """Replace a share of examples with 2-4 examples stitched together, so the
    model also sees long, multi-sentence, multi-entity inputs (real prompts),
    not only the single sentences the templates produce."""
    out = []
    for ex in examples:
        if rng.random() >= rate:
            out.append(ex)
            continue
        parts = [ex] + rng.sample(examples, rng.choice([1, 2, 3]))
        tokens, ner = [], []
        for part in parts:
            if tokens and len(tokens) + len(part["tokenized_text"]) > max_tokens:
                break
            offset = len(tokens)
            tokens += part["tokenized_text"]
            ner += [[s + offset, e + offset, label] for s, e, label in part["ner"]]
        out.append({"tokenized_text": tokens, "ner": ner})
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="knowledgator/gliner-pii-edge-v1.0")
    ap.add_argument("--train", default=str(ROOT / "data/train.jsonl"))
    ap.add_argument("--dev", default=str(ROOT / "data/dev.jsonl"))
    ap.add_argument("--name", default="parda-pii-edge")
    ap.add_argument("--max-steps", type=int, default=2500)
    ap.add_argument("--batch", type=int, default=8)
    ap.add_argument("--grad-accum", type=int, default=4)
    ap.add_argument("--lr", type=float, default=1e-5)
    ap.add_argument("--others-lr", type=float, default=5e-5)
    ap.add_argument("--eval-steps", type=int, default=250)
    ap.add_argument("--dev-limit", type=int, default=600)
    ap.add_argument("--cpu", action="store_true")
    ap.add_argument("--smoke", action="store_true", help="short run on a small slice")
    ap.add_argument("--threads", type=int, default=8, help="CPU threads (CPU training)")
    ap.add_argument("--seed", type=int, default=13)
    ap.add_argument("--compose", type=float, default=0.35, help="share of stitched multi-example inputs")
    args = ap.parse_args()

    random.seed(args.seed)
    torch.manual_seed(args.seed)

    train = read_jsonl(args.train)
    dev = read_jsonl(args.dev)[: args.dev_limit]
    if args.smoke:
        train = train[:1600]
        dev = dev[:100]
        args.max_steps = min(args.max_steps, 200)
        args.eval_steps = max(10, args.max_steps // 2)
        args.name += "-smoke"
    rng = random.Random(args.seed)
    train = compose(train, args.compose, rng)
    dev = compose(dev, args.compose, rng)
    random.shuffle(train)

    out_dir = ROOT / "runs" / args.name
    # MPS recompiles a graph for every new sequence shape and caches the graphs on
    # the boot disk; CPU training is slower per FLOP but steady and disk-safe.
    device = "cpu" if args.cpu or not torch.backends.mps.is_available() else "mps"
    if device == "cpu":
        torch.set_num_threads(args.threads)
    print(f"train={len(train)} dev={len(dev)} device={device} out={out_dir}", flush=True)

    model = GLiNER.from_pretrained(args.base)
    training_args = model.create_training_args(
        output_dir=str(out_dir),
        learning_rate=args.lr,
        others_lr=args.others_lr,
        weight_decay=0.01,
        others_weight_decay=0.01,
        focal_loss_alpha=0.75,
        focal_loss_gamma=2.0,
        lr_scheduler_type="cosine",
        warmup_ratio=0.06,
        per_device_train_batch_size=args.batch,
        per_device_eval_batch_size=args.batch,
        gradient_accumulation_steps=args.grad_accum,
        max_steps=args.max_steps,
        save_steps=args.eval_steps,
        eval_strategy="steps",
        eval_steps=args.eval_steps,
        save_total_limit=2,
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        greater_is_better=False,
        logging_steps=25,
        use_cpu=device == "cpu",
        bf16=False,
        dataloader_num_workers=0,
        dataloader_pin_memory=False,
        report_to="none",
        seed=args.seed,
    )
    started = time.time()
    trainer = model.train_model(train_dataset=train, eval_dataset=dev, training_args=training_args)
    elapsed = time.time() - started
    final = out_dir / "final"
    trainer.model.save_pretrained(str(final))
    print(f"done in {elapsed / 60:.1f} min -> {final}", flush=True)


if __name__ == "__main__":
    main()
