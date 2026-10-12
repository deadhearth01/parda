"""Generate GLiNER training data (India-first, global coverage).

    python -m datagen.generate --n 20000 --seed 7 --split train --out data/train.jsonl

writes `train.jsonl` (GLiNER format: tokenized_text + inclusive token spans)
and `train.chars.jsonl` (character offsets, region and style for evaluation).

Generation is a deterministic stream: example *i* depends only on
(seed, split, i) and on the examples before it, so the first k examples of a
longer run equal a run of k examples.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
from pathlib import Path

from .entities import LABELS
from .templates import FAMILIES, NEGATIVES, instantiate

SPLITTER = re.compile(r"\w+(?:[-_]\w+)*|\S")
SPLITS = ("train", "dev", "test")

# Target share of each label among all entity mentions. Person dominates
# (names are what rules cannot catch, and most templates mention someone);
# every other label keeps >= 2.5% so a 20k run holds 1,000+ examples of each.
LABEL_TARGETS = {
    "person": 0.320,
    "phone number": 0.095,
    "email": 0.087,
    "address": 0.075,
    "organization": 0.067,
    "date of birth": 0.038,
    "pan number": 0.037,
    "bank account number": 0.037,
    "aadhaar number": 0.035,
    "upi id": 0.035,
    "username": 0.033,
    "ip address": 0.031,
    "credit card number": 0.030,
    "password": 0.028,
    "ifsc code": 0.026,
    "passport number": 0.026,
}

# Ten-slot schedule: 6 India / 4 global, one negative per region per cycle
# (slot 0 India, slot 1 global). Negatives come first so even a 1-example run
# contains one.
INDIA_SLOTS = {0, 2, 3, 5, 7, 8}
NEGATIVE_SLOTS = {0, 1}
STYLES = list(FAMILIES)


def aligned(chars: dict) -> bool:
    """True when every entity starts and ends on a GLiNER word boundary."""
    starts = set()
    ends = set()
    for m in SPLITTER.finditer(chars["text"]):
        starts.add(m.start())
        ends.add(m.end())
    return all(e["start"] in starts and e["end"] in ends for e in chars["entities"])


def to_gliner(chars: dict) -> dict:
    """Convert a char-offset record to GLiNER's word-level format.
    Raises AssertionError when an entity does not align with word boundaries."""
    tokens = list(SPLITTER.finditer(chars["text"]))
    start_index = {m.start(): i for i, m in enumerate(tokens)}
    end_index = {m.end(): i for i, m in enumerate(tokens)}
    ner = []
    for e in chars["entities"]:
        assert e["start"] in start_index and e["end"] in end_index, (
            f"entity {chars['text'][e['start']:e['end']]!r} does not align with word boundaries")
        ner.append([start_index[e["start"]], end_index[e["end"]], e["label"]])
    return {"tokenized_text": [m.group() for m in tokens], "ner": ner}


def _schedule(i: int) -> tuple[str, bool, str]:
    slot = i % 10
    cycle = i // 10
    region = "india" if slot in INDIA_SLOTS else "global"
    negative = slot in NEGATIVE_SLOTS
    style = STYLES[(cycle + slot * 5) % len(STYLES)]
    return region, negative, style


def _pick_template(candidates, counts, total, rng):
    """Prefer templates whose labels are below their target share."""
    weights = []
    for t in candidates:
        projected = total + len(t.labels)
        deficit = sum(max(0.0, LABEL_TARGETS[label] * projected - counts[label]) for label in t.labels)
        weights.append(0.05 + deficit / max(1, len(t.labels)))
    return rng.choices(candidates, weights=weights, k=1)[0]


def _negative(candidates, style: str, split: str, rng) -> dict:
    """One or two entity-free sentences: prompts are rarely a single line, and
    pairs keep negatives varied (single fillers repeat quickly)."""
    first = rng.choice(candidates)
    chars = instantiate(first, style, split, rng)
    if rng.random() < 0.6:
        second = rng.choice([t for t in candidates if t is not first] or candidates)
        more = instantiate(second, style, split, rng)
        chars = {**chars, "text": chars["text"] + rng.choice([" ", "\n"]) + more["text"]}
    return chars


def generate_examples(n: int, seed: int, split: str = "train"):
    """Yield `(gliner_record, chars_record)` pairs."""
    if not isinstance(n, int) or n < 0:
        raise ValueError(f"n must be a non-negative integer, got {n!r}")
    if split not in SPLITS:
        raise ValueError(f"split must be one of {SPLITS}, got {split!r}")
    counts = {label: 0 for label in LABELS}
    total = 0
    for i in range(n):
        rng = random.Random(f"parda-datagen/{seed}/{split}/{i}")
        region, negative, style = _schedule(i)
        pool = NEGATIVES[style] if negative else FAMILIES[style]
        candidates = [t for t in pool if t.region == region]
        if negative:
            chars = _negative(candidates, style, split, rng)
        else:
            template = _pick_template(candidates, counts, total, rng)
            chars = instantiate(template, style, split, rng)
        for e in chars["entities"]:
            counts[e["label"]] += 1
            total += 1
        yield to_gliner(chars), chars


def write_dataset(n: int, seed: int, split: str, out: str | Path) -> None:
    """Write `<out>` (GLiNER) and `<out stem>.chars.jsonl` (char offsets)."""
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    sidecar = out.with_suffix(".chars.jsonl")
    with open(out, "w", encoding="utf-8") as fg, open(sidecar, "w", encoding="utf-8") as fc:
        for record, chars in generate_examples(n, seed, split):
            fg.write(json.dumps(record, ensure_ascii=False) + "\n")
            fc.write(json.dumps(chars, ensure_ascii=False) + "\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--n", type=int, required=True)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--split", default="train", choices=SPLITS)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    write_dataset(args.n, args.seed, args.split, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
