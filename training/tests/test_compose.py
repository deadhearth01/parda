import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from train_gliner import compose  # noqa: E402


def ex(words, ner):
    return {"tokenized_text": words, "ner": ner}


def test_compose_shifts_spans_and_respects_limit():
    data = [ex(["Call", "Ravi", "Kumar", "."], [[1, 2, "person"]]),
            ex(["Mail", "a", "@", "b", ".", "in"], [[1, 5, "email"]]),
            ex(["Hi", "Asha", "!"], [[1, 1, "person"]])]
    out = compose(data, 1.0, random.Random(1), max_tokens=100)
    assert len(out) == len(data)
    for record in out:
        for s, e, label in record["ner"]:
            assert 0 <= s <= e < len(record["tokenized_text"])
            words = record["tokenized_text"][s:e + 1]
            assert words in (["Ravi", "Kumar"], ["a", "@", "b", ".", "in"], ["Asha"]), (words, label)
    assert any(len(r["tokenized_text"]) > 6 for r in out)
    capped = compose(data, 1.0, random.Random(2), max_tokens=5)
    assert all(len(r["tokenized_text"]) <= 6 for r in capped)


def test_compose_rate_zero_is_identity():
    data = [ex(["x"], [])] * 5
    assert compose(data, 0.0, random.Random(0)) == data
