"""Name inventories, the held-out test partition and person-name shapes."""

from __future__ import annotations

import functools
import hashlib
import re
import unicodedata
from pathlib import Path

DATA = Path(__file__).resolve().parent / "data"
FILES = {
    ("india", "first"): "india_first.txt",
    ("india", "last"): "india_last.txt",
    ("global", "first"): "global_first.txt",
    ("global", "last"): "global_last.txt",
}
SPLITS = ("train", "dev", "test")
# Share of eligible names held out for the test split.
TEST_FRACTION = 0.15
WORD = re.compile(r"\w+")


def _check(region: str, kind: str) -> None:
    if (region, kind) not in FILES:
        raise ValueError(f"unknown name list {region}/{kind}")


@functools.lru_cache(maxsize=None)
def _parse(region: str, kind: str) -> tuple[tuple[str, ...], frozenset[str]]:
    _check(region, kind)
    entries: list[str] = []
    pinned: set[str] = set()
    seen: set[str] = set()
    for raw in (DATA / FILES[(region, kind)]).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "@")):
            continue
        pin = line.startswith("!")
        name = line.lstrip("!").strip()
        if name in seen:
            continue
        seen.add(name)
        entries.append(name)
        if pin:
            pinned.add(name)
    return tuple(entries), frozenset(pinned)


def inventory(region: str, kind: str) -> list[str]:
    """Every name of one list, in file order."""
    return list(_parse(region, kind)[0])


def words(text: str) -> set[str]:
    return {w.casefold() for w in WORD.findall(text)}


@functools.lru_cache(maxsize=None)
def _word_owners() -> dict[str, int]:
    """How many names (across all lists) contain each word."""
    owners: dict[str, int] = {}
    for key in FILES:
        for name in _parse(*key)[0]:
            for w in words(name):
                owners[w] = owners.get(w, 0) + 1
    return owners


@functools.lru_cache(maxsize=None)
def _reserved() -> frozenset[str]:
    """Words used anywhere outside person names (templates, places, orgs …).
    A held-out name must never be one of them, or it would leak into train."""
    from . import entities, templates  # late import: they import this module

    vocab: set[str] = set()
    for text in templates.static_texts():
        vocab |= words(text)
    for text in entities.static_vocab():
        vocab |= words(text)
    return frozenset(vocab)


def _held_out(name: str) -> bool:
    digest = hashlib.sha256(("parda-heldout|" + name.casefold()).encode()).digest()
    return digest[0] < 256 * TEST_FRACTION


@functools.lru_cache(maxsize=None)
def _partition(region: str, kind: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    entries, pinned = _parse(region, kind)
    owners = _word_owners()
    reserved = _reserved()
    test = []
    for name in entries:
        ws = words(name)
        if (
            name not in pinned
            and len(name) >= 4
            and all(owners.get(w, 0) == 1 for w in ws)
            and not ws & reserved
            and _held_out(name)
        ):
            test.append(name)
    held = set(test)
    train = tuple(n for n in entries if n not in held)
    return train, tuple(test)


def name_pool(region: str, kind: str, split: str) -> list[str]:
    """Names usable in a split. dev shares train's pool; test is disjoint."""
    if split not in SPLITS:
        raise ValueError(f"unknown split {split!r}")
    train, test = _partition(region, kind)
    return list(test if split == "test" else train)


def ascii_fold(text: str) -> str:
    """'Müller' -> 'muller', "O'Brien" -> 'obrien' (for e-mail local parts)."""
    text = text.replace("ß", "ss").replace("ø", "o").replace("Ø", "O").replace("ı", "i")
    text = text.replace("đ", "d").replace("Đ", "D").replace("ł", "l").replace("Ł", "L")
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(c for c in decomposed if c.isascii() and c.isalnum()).lower()


def _first(rng, region: str, split: str) -> str:
    return rng.choice(name_pool(region, "first", split))


def _last(rng, region: str, split: str) -> str:
    return rng.choice(name_pool(region, "last", split))


def _initial(name: str) -> str:
    folded = ascii_fold(name)
    return (folded[:1] or "a").upper()


def sample_name(rng, region: str, split: str) -> str:
    """A person name in one of the shapes people write: full, three-part,
    initials, first name only, "Last, First", or FORM CAPS."""
    shape = rng.random()
    first, last = _first(rng, region, split), _last(rng, region, split)
    if shape < 0.46:
        return f"{first} {last}"
    if shape < 0.54:
        middle = _first(rng, region, split)
        return f"{first} {middle} {last}"
    if shape < 0.61:
        return f"{_initial(first)}. {last}"
    if shape < 0.66:
        return f"{_initial(first)}. {_initial(_first(rng, region, split))}. {last}"
    if shape < 0.80:
        return first
    if shape < 0.86:
        return f"{last}, {first}"
    if shape < 0.92:
        return f"{first} {last}".upper()
    return last
