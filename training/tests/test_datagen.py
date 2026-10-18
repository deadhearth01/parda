"""Contract tests for the synthetic PII training-data generator.

Checksum oracles below are written independently of the generator's own
validators (different formulation) so that a bug in one cannot hide a bug in
the other.
"""
import ast
import json
import random
import re
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

import pytest

from datagen.entities import (
    BRANDS, LABELS, gstin, iban, luhn_valid, make_entity, verhoeff_valid, ORG_REAL,
)
from datagen.generate import LABEL_TARGETS, generate_examples, to_gliner, write_dataset
from datagen.names import inventory, name_pool, sample_name
from datagen.templates import FAMILIES, NEGATIVES, instantiate, render

TRAINING_DIR = Path(__file__).resolve().parent.parent
SPLITTER = re.compile(r"\w+(?:[-_]\w+)*|\S")
INDIA_ONLY = {"aadhaar number", "pan number", "upi id", "ifsc code"}
EXPECTED_LABELS = {
    "person", "email", "phone number", "address", "organization", "date of birth",
    "aadhaar number", "pan number", "upi id", "bank account number", "ifsc code",
    "passport number", "credit card number", "ip address", "username", "password",
}
PASSWORD_CUE = re.compile(r"(?i)(?:password|passwd|pwd|passcode|pass\b|\bpw\b)")


@pytest.fixture(scope="module")
def corpus():
    return list(generate_examples(20000, seed=7, split="train"))


# --------------------------------------------------------------------------
# determinism / structure
# --------------------------------------------------------------------------
def test_determinism_and_split_streams():
    a = list(generate_examples(100, seed=7, split="train"))
    assert a == list(generate_examples(100, seed=7, split="train"))
    assert a != list(generate_examples(100, seed=8, split="train"))
    assert a != list(generate_examples(100, seed=7, split="dev"))
    assert a != list(generate_examples(100, seed=7, split="test"))


def test_prefix_stability(corpus):
    assert list(generate_examples(300, seed=7, split="train")) == corpus[:300]


def test_exact_span_alignment_and_labels(corpus):
    assert set(LABELS) == EXPECTED_LABELS and len(LABELS) == 16
    seen = set()
    for record, chars in corpus:
        assert set(record) == {"tokenized_text", "ner"}
        assert set(chars) == {"text", "entities", "region", "style"}
        tokens = list(SPLITTER.finditer(chars["text"]))
        assert record["tokenized_text"] == [m.group() for m in tokens]
        assert len(record["ner"]) == len(chars["entities"])
        end = 0
        for (start_token, end_token, label), entity in zip(record["ner"], chars["entities"]):
            assert isinstance(record["ner"][0], list)
            start, stop = entity["start"], entity["end"]
            assert end <= start < stop <= len(chars["text"])
            assert tokens[start_token].start() == start
            assert tokens[end_token].end() == stop
            value = chars["text"][start:stop]
            assert value and value == value.strip()
            assert label == entity["label"] and label in EXPECTED_LABELS
            seen.add(label)
            end = stop
    assert seen == EXPECTED_LABELS


def test_fragments_repeats_unicode_and_honorifics():
    chars = render(["Dr. ", ("person", "Élodie O’Neill"), " ji emailed ",
                    ("email", "ravi.k@example.com"), "; ", ("person", "Élodie O’Neill")],
                   "global", "chat_prompt")
    record = to_gliner(chars)
    assert [chars["text"][e["start"]:e["end"]] for e in chars["entities"]] == [
        "Élodie O’Neill", "ravi.k@example.com", "Élodie O’Neill"]
    assert record["tokenized_text"][record["ner"][1][0]:record["ner"][1][1] + 1] == [
        "ravi", ".", "k", "@", "example", ".", "com"]
    assert len(chars["text"].encode()) > len(chars["text"])
    for text, start, end in [("prefixName", 6, 10), ("Name_suffix", 0, 4)]:
        with pytest.raises(AssertionError):
            to_gliner({"text": text, "entities": [{"start": start, "end": end, "label": "person"}]})


def test_mix_negatives_styles_and_label_targets(corpus):
    regions = Counter(c["region"] for _, c in corpus)
    assert regions == {"india": 12000, "global": 8000}
    negatives = [c for _, c in corpus if not c["entities"]]
    assert len(negatives) >= 3000
    counts = Counter(e["label"] for _, c in corpus for e in c["entities"])
    total = sum(counts.values())
    assert abs(sum(LABEL_TARGETS.values()) - 1.0) < 1e-6 and set(LABEL_TARGETS) == EXPECTED_LABELS
    for label, target in LABEL_TARGETS.items():
        assert abs(counts[label] / total - target) <= 0.05
        # rare labels must still be well represented for fine-tuning
        assert counts[label] >= 400, (label, counts[label])
    assert set(c["style"] for _, c in corpus) == set(FAMILIES)
    for region in ("india", "global"):
        subset = [c for _, c in corpus if c["region"] == region]
        assert sum(not c["entities"] for c in subset) / len(subset) >= .15
        assert {c["style"] for c in subset if c["entities"]} == set(FAMILIES)
        assert {c["style"] for c in subset if not c["entities"]} == set(FAMILIES)
    for _, c in corpus:
        if c["region"] == "global":
            assert not INDIA_ONLY.intersection(e["label"] for e in c["entities"])
        if not c["entities"]:
            assert not re.search(r"\b(?:Mr|Ms|Dr|Shri)\.?\s+[A-Z]", c["text"])


def test_template_families_size_and_shape():
    assert len(FAMILIES) >= 12
    assert set(NEGATIVES) == set(FAMILIES)
    for style, templates in FAMILIES.items():
        assert len(templates) >= 6, style
        for region in ("india", "global"):
            assert sum(t.region == region for t in templates) >= 3, (style, region)
            assert sum(t.region == region for t in NEGATIVES[style]) >= 2, (style, region)
        for t in templates:
            assert t.labels, (style, t.text)
        for t in NEGATIVES[style]:
            assert not t.labels, (style, t.text)
    # Hinglish is written the way people type it
    texts = " ".join(t.text for t in FAMILIES["whatsapp"])
    for phrase in ("kal", "hai", "bhai", "karna", "mera"):
        assert phrase in texts


@pytest.mark.parametrize("split", ["train", "test"])
def test_every_template_renders_with_exact_alignment(split):
    """Property test: each template (positive and negative) tokenises exactly."""
    for style in FAMILIES:
        for template in FAMILIES[style] + NEGATIVES[style]:
            for k in range(12):
                rng = random.Random(f"{style}-{split}-{k}-{template.text[:20]}")
                chars = instantiate(template, style, split, rng)
                record = to_gliner(chars)  # raises AssertionError on any misalignment
                assert bool(chars["entities"]) == bool(template.labels), template.text
                assert len(record["ner"]) == len(chars["entities"])


# --------------------------------------------------------------------------
# names
# --------------------------------------------------------------------------
@pytest.mark.parametrize("region,kind,minimum", [
    ("india", "first", 400), ("india", "last", 300),
    ("global", "first", 300), ("global", "last", 300),
])
def test_name_inventory_and_partitions(region, kind, minimum):
    entries = inventory(region, kind)
    assert len(set(entries)) >= minimum
    assert not [n for n in entries if re.fullmatch(r".*(?:name|test|sample)\d+", n.casefold())]
    train, test = set(name_pool(region, kind, "train")), set(name_pool(region, kind, "test"))
    assert train and len(test) >= 30 and train.isdisjoint(test)
    assert train | test == set(entries)
    assert name_pool(region, kind, "train") == name_pool(region, kind, "dev")


def test_name_data_files_are_documented_and_diverse():
    data = TRAINING_DIR / "datagen" / "data"
    files = sorted(data.glob("*.txt"))
    assert len(files) >= 6
    for path in files:
        lines = path.read_text(encoding="utf-8").splitlines()
        assert lines[0].startswith("#"), path.name  # coverage header
    india_first = "\n".join(inventory("india", "first"))
    india_last = "\n".join(inventory("india", "last"))
    glob_first = "\n".join(inventory("global", "first"))
    glob_last = "\n".join(inventory("global", "last"))
    for needle in ("Gurpreet", "Venkatesh", "Sourav", "Prasanna", "Fatima", "Joseph", "Cyrus",
                   "Sneha", "Hardik", "Lakshmi", "Anjana", "Pranjal"):
        assert needle in india_first, needle
    for needle in ("Singh", "Iyer", "Banerjee", "Khan", "D'Souza", "Patel", "Reddy", "Nair",
                   "Wadia", "Deshmukh", "Borah", "Rathore", "Kaur"):
        assert needle in india_last, needle
    for needle in ("Sofía", "Nguyễn", "Müller", "O'Brien", "Yılmaz", "Adeyemi", "Kowalski",
                   "Hosseini", "Tanaka", "Kim", "Wang", "Mwangi"):
        assert needle in glob_first + "\n" + glob_last, needle


def test_heldout_components_absent_from_all_training_text(corpus):
    held = {n.casefold() for r in ("india", "global") for k in ("first", "last")
            for n in name_pool(r, k, "test")}
    train = {n.casefold() for r in ("india", "global") for k in ("first", "last")
             for n in name_pool(r, k, "train")}
    assert held.isdisjoint(train)
    pattern = re.compile(r"(?<!\w)(?:" + "|".join(re.escape(n) for n in sorted(held)) + r")(?!\w)", re.I)
    leaked = {m.group().casefold() for _, c in corpus for m in pattern.finditer(c["text"])}
    assert not leaked, sorted(leaked)[:20]
    dev = list(generate_examples(2000, seed=7, split="dev"))
    assert not any(pattern.search(c["text"]) for _, c in dev)
    train_people = {c["text"][e["start"]:e["end"]].casefold()
                    for _, c in corpus for e in c["entities"] if e["label"] == "person"}
    test_people = 0
    for _, c in generate_examples(2000, seed=7, split="test"):
        for e in c["entities"]:
            if e["label"] == "person":
                value = c["text"][e["start"]:e["end"]]
                test_people += 1
                assert value.casefold() not in train_people
                assert pattern.search(value), value
    assert test_people > 500


def test_name_shapes_and_external_address_words(corpus):
    people = [c["text"][e["start"]:e["end"]] for _, c in corpus
              for e in c["entities"] if e["label"] == "person"]
    assert any(re.match(r"[A-Z]\. [A-Z]\. ", p) for p in people)
    assert any(re.match(r"[A-Z]\. ", p) for p in people)
    assert any(" " not in p for p in people)
    assert any("'" in p or "’" in p for p in people)
    assert any(any(ord(ch) > 127 for ch in p) for p in people)
    assert any(re.search(r"\w+, \w+", p) for p in people)   # surname-first
    assert any(p.isupper() and len(p) > 3 for p in people)  # FORM CAPS
    assert all(not re.search(r"\b(?:bhai|didi|sir|madam|ji|bhaiya|anna|akka|Shri|Smt|Dr|Mr|Ms|Mrs)\b", p)
               for p in people)
    texts = "\n".join(c["text"] for _, c in corpus)
    for word in ("bhai", "didi", "sir", "madam", "ji", "bhaiya", "anna", "akka",
                 "Shri", "Smt.", "Dr.", "Mr.", "Ms."):
        assert word in texts
    # "Sharma ji" style: the person span excludes the -ji suffix
    assert re.search(r"\w+ ji\b", texts)
    ji_hits = 0
    for _, c in corpus:
        for e in c["entities"]:
            if e["label"] == "person" and c["text"][e["end"]:e["end"] + 3] == " ji":
                ji_hits += 1
    assert ji_hits > 20


def test_sample_name_variety_by_region():
    rng = random.Random(3)
    india = {sample_name(rng, "india", "train") for _ in range(400)}
    glob = {sample_name(rng, "global", "train") for _ in range(400)}
    assert len(india) > 300 and len(glob) > 300


# --------------------------------------------------------------------------
# identifiers
# --------------------------------------------------------------------------
def independent_verhoeff(value):
    # Dihedral group multiplication derived directly, separate from table implementation.
    permutations = [tuple(range(10)), (1, 5, 7, 6, 2, 8, 3, 0, 9, 4)]
    for _ in range(6):
        permutations.append(tuple(permutations[-1][permutations[1][i]] for i in range(10)))
    acc = 0
    for i, digit in enumerate(reversed(value)):
        right = permutations[i % 8][int(digit)]
        rotation = (acc % 5 + (1 if acc < 5 else -1) * (right % 5)) % 5
        acc = rotation + 5 * ((acc >= 5) != (right >= 5))
    return acc == 0


def independent_luhn(value):
    digits = [int(d) for d in re.sub(r"\D", "", value)]
    return sum((2 * d - 9 if d >= 5 else 2 * d) if i % 2 else d
               for i, d in enumerate(reversed(digits))) % 10 == 0


def independent_iban(value):
    compact = value.replace(" ", "")
    moved = compact[4:] + compact[:4]
    return int("".join(str(ord(c) - 55) if c.isalpha() else c for c in moved)) % 97 == 1


def test_identifier_checksums_and_shapes(corpus):
    pins = 0
    indian_addresses = 0
    ibans = 0
    for _, c in corpus:
        for e in c["entities"]:
            value = c["text"][e["start"]:e["end"]]
            label = e["label"]
            before = c["text"][:e["start"]]
            if label == "aadhaar number":
                digits = re.sub(r"[ -]", "", value)
                assert re.fullmatch(r"[2-9]\d{11}", digits) and independent_verhoeff(digits)
                assert re.fullmatch(r"\d{4}( \d{4} \d{4}|-\d{4}-\d{4}|\d{8})", value)
            elif label == "pan number":
                assert re.fullmatch(r"[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z]", value)
            elif label == "credit card number":
                assert 13 <= len(re.sub(r"\D", "", value)) <= 19 and independent_luhn(value)
            elif label == "ifsc code":
                assert re.fullmatch(r"[A-Z]{4}0[A-Z0-9]{6}", value)
            elif label == "bank account number":
                if re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9 ]{10,34}", value):
                    ibans += 1
                    assert c["region"] == "global" and independent_iban(value)
                else:
                    assert re.fullmatch(r"\d{9,18}", value)
            elif label == "upi id":
                assert re.fullmatch(r"[a-z0-9._-]+@(okaxis|okicici|oksbi|okhdfcbank|ybl|ibl|axl|paytm|upi)", value)
            elif label == "passport number" and c["region"] == "india":
                assert re.fullmatch(r"[A-Z]\d{7}", value)
            elif label == "password":
                assert PASSWORD_CUE.search(before[-48:]), before[-48:]
                assert " " not in value and len(value) >= 4
            elif label == "ip address":
                assert re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value) or ":" in value
            elif label == "address" and c["region"] == "india":
                indian_addresses += 1
                match = re.search(r"(?<!\d)([1-9]\d{5})(?!\d)", value)
                pins += bool(match)
    assert pins / indian_addresses >= 0.7
    assert ibans > 50


def test_checksum_known_vectors_and_invalid_inputs():
    assert verhoeff_valid("2363") and not verhoeff_valid("2364")
    assert luhn_valid("4111111111111111") and not luhn_valid("4111111111111112")
    for value in ("", "abc", "12x3", "१२३"):
        assert not verhoeff_valid(value) and not luhn_valid(value)


def test_extra_checksum_generators():
    rng = random.Random(123)
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    countries = set()
    for _ in range(300):
        number = iban(rng)
        countries.add(number[:2])
        assert independent_iban(number)
        number = gstin(rng)
        assert re.fullmatch(r"\d{2}[A-Z]{3}[PCHFATBLJG][A-Z]\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]", number)
        total = 0
        for i, ch in enumerate(reversed(number[:-1])):
            product = alphabet.index(ch) * (2 if i % 2 == 0 else 1)
            total += product // 36 + product % 36
        assert (total + alphabet.index(number[-1])) % 36 == 0
    assert len(countries) >= 8


def test_entity_variation_and_addresses():
    rng = random.Random(9)
    for region in ("india", "global"):
        phones = {make_entity("phone number", rng, region, "train") for _ in range(600)}
        addresses = {make_entity("address", rng, region, "train") for _ in range(1500)}
        ips = {make_entity("ip address", rng, region, "train") for _ in range(100)}
        assert any(":" in ip for ip in ips) and any("." in ip for ip in ips)
        dobs = {make_entity("date of birth", rng, region, "train") for _ in range(200)}
        assert len({re.sub(r"\d", "9", d) for d in dobs}) >= 5
        if region == "india":
            assert any(p.startswith("+91") for p in phones)
            assert any(p.startswith("0") for p in phones)
            assert any(re.fullmatch(r"[6-9]\d{9}", p) for p in phones)
            assert any(re.fullmatch(r"[6-9]\d{4} \d{5}", p) for p in phones)
            assert any(re.search(r"\bnear [A-Z]\w+", a) for a in addresses)
            assert any("Hanuman Mandir" in a for a in addresses)
            assert any("\n" in a for a in addresses)
            assert all(not re.search(r"(?<!\d)0\d{5}(?!\d)", a) for a in addresses)
        else:
            for marker in ("USA", "UK", "France", "Germany", "Brasil", "México", "Japan"):
                assert any(marker in a for a in addresses), marker


def test_orgs_and_brands_are_disjoint_vocabularies():
    assert not {o.casefold() for o in ORG_REAL} & {b.casefold() for b in BRANDS}
    assert len(BRANDS) >= 100 and len(ORG_REAL) >= 100


# --------------------------------------------------------------------------
# writer / CLI
# --------------------------------------------------------------------------
def test_writer_cli_and_performance(tmp_path):
    out = tmp_path / "nested" / "train.jsonl"
    started = time.monotonic()
    write_dataset(20000, 7, "train", out)
    assert time.monotonic() - started < 60
    sidecar = out.with_suffix(".chars.jsonl")
    assert len(out.read_text(encoding="utf-8").splitlines()) == \
        len(sidecar.read_text(encoding="utf-8").splitlines()) == 20000
    result = subprocess.run([sys.executable, "-m", "datagen.generate", "--n", "20", "--seed", "7",
                             "--split", "test", "--out", str(out)],
                            capture_output=True, text=True, cwd=TRAINING_DIR)
    assert result.returncode == 0, result.stderr
    assert not result.stderr
    pairs = zip(out.read_text(encoding="utf-8").splitlines(),
                sidecar.read_text(encoding="utf-8").splitlines())
    assert [(json.loads(a), json.loads(b)) for a, b in pairs] == list(generate_examples(20, 7, "test"))


def test_cli_default_split_is_train(tmp_path):
    out = tmp_path / "t.jsonl"
    result = subprocess.run([sys.executable, "-m", "datagen.generate", "--n", "15", "--seed", "3",
                             "--out", str(out)], capture_output=True, text=True, cwd=TRAINING_DIR)
    assert result.returncode == 0, result.stderr
    got = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert got == [r for r, _ in generate_examples(15, 3, "train")]


@pytest.mark.parametrize("n,split", [(-1, "train"), (1, "bad")])
def test_invalid_arguments(n, split):
    with pytest.raises(ValueError):
        list(generate_examples(n, 7, split))


def test_empty_and_small_samples():
    assert list(generate_examples(0, 7, "train")) == []
    for n in (1, 2, 3, 7, 11):
        examples = list(generate_examples(n, 7, "train"))
        assert len(examples) == n
        assert sum(not c["entities"] for _, c in examples) >= n * .15


def test_stdlib_only_and_no_duplicates(corpus):
    stdlib = set(sys.stdlib_module_names) | {"datagen"}
    for path in (TRAINING_DIR / "datagen").glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                mods = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                mods = [node.module.split(".")[0]] if node.module and not node.level else []
            else:
                continue
            assert set(mods) <= stdlib, (path.name, mods)
    texts = [c["text"] for _, c in corpus]
    assert len(set(texts)) >= len(texts) * 0.995
    lengths = sorted(len(r["tokenized_text"]) for r, _ in corpus)
    assert lengths[-1] <= 320 and lengths[len(lengths) // 2] >= 12
