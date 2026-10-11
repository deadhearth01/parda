"""Shared helpers for the parda-pii training scripts."""

from __future__ import annotations

import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent

# Labels the parda model is trained on (GLiNER natural-language labels).
LABELS = [
    "person",
    "email",
    "phone number",
    "address",
    "organization",
    "date of birth",
    "aadhaar number",
    "pan number",
    "upi id",
    "bank account number",
    "ifsc code",
    "passport number",
    "credit card number",
    "ip address",
    "username",
    "password",
]

# Golden-corpus kinds (Rust EntityKind names) -> GLiNER labels.
KIND_TO_LABEL = {
    "Person": "person",
    "Email": "email",
    "Phone": "phone number",
    "Address": "address",
    "Organization": "organization",
    "DateOfBirth": "date of birth",
    "Aadhaar": "aadhaar number",
    "Pan": "pan number",
    "Upi": "upi id",
    "BankAccount": "bank account number",
    "Ifsc": "ifsc code",
    "Passport": "passport number",
    "CreditCard": "credit card number",
    "IpAddress": "ip address",
}


def ssd_env() -> None:
    """Keep every cache and temp file on the SSD (the boot disk is tiny)."""
    dev = Path("/Volumes/SSD_1TB/DEV")
    os.environ.setdefault("HF_HOME", str(dev / ".cache/huggingface"))
    os.environ.setdefault("TMPDIR", str(dev / ".tmp"))
    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
    os.environ.setdefault("PYTORCH_ENABLE_MPS_FALLBACK", "1")


def read_jsonl(path: str | Path) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def write_json(path: str | Path, obj) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
