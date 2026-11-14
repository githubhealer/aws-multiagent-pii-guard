"""Deterministic, validation-backed PII candidate detection."""
from __future__ import annotations

import csv
import io
import os
import re
from collections import Counter
from typing import Any

EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
PHONE = re.compile(r"(?<!\d)(?:\+91[ -]?)?[6-9]\d{9}(?!\d)")
INTERNATIONAL_PHONE = re.compile(r"(?<!\d)(?:\+\d{1,3}[ .-]?)?(?:\(?\d{1,4}\)?[ .-]?){2,4}\d{2,4}(?!\d)")
FORMATTED_PHONE = re.compile(r"(?<!\d)(?:\+\d{1,3}[ .-]?)?(?:\(?\d{1,4}\)?[ .-]?){2,5}\d{2,4}(?!\d)")
TOKEN = re.compile(r"\b(?:usr|eml|pan|uid|crd|phn|ip|prs|org|loc)_v[0-9A-Za-z]+_[0-9a-f]{24}\b", re.I)
PAN = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b", re.I)
AADHAAR = re.compile(r"(?<!\d)(?:\d[ -]?){12}(?!\d)")
CARD = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DATE = re.compile(r"\b(?:\d{4}[-/]\d{2}[-/]\d{2}|\d{2}[-/]\d{2}[-/]\d{4})\b")


def _named_entities(value: str) -> list[tuple[str, int, int]]:
    """Run packaged NLTK NER locally; never download resources at runtime."""
    try:
        import nltk
        from nltk import ne_chunk, pos_tag, wordpunct_tokenize
        bundled_data = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "nltk_data"))
        if bundled_data not in nltk.data.path:
            nltk.data.path.append(bundled_data)
        tagged = pos_tag(wordpunct_tokenize(value))
        tree = ne_chunk(tagged, binary=False)
    except (ImportError, LookupError):
        return []
    entities: list[tuple[str, int, int]] = []
    cursor = 0
    for node in tree:
        if hasattr(node, "label"):
            text = " ".join(token for token, _ in node.leaves())
            start = value.find(text, cursor)
            if start >= 0 and node.label() in {"PERSON", "ORGANIZATION", "GPE", "LOCATION"}:
                entities.append((node.label(), start, start + len(text)))
                cursor = start + len(text)
    return entities


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def luhn(value: str) -> bool:
    digits = _digits(value)
    if not 13 <= len(digits) <= 19:
        return False
    total = sum((int(d) if (i % 2 == 0) else (int(d) * 2 - 9 if int(d) * 2 > 9 else int(d) * 2)) for i, d in enumerate(reversed(digits)))
    return total % 10 == 0


def verhoeff(value: str) -> bool:
    digits = _digits(value)
    if len(digits) != 12:
        return False
    multiplication = ((0,1,2,3,4,5,6,7,8,9),(1,2,3,4,0,6,7,8,9,5),(2,3,4,0,1,7,8,9,5,6),(3,4,0,1,2,8,9,5,6,7),(4,0,1,2,3,9,5,6,7,8),(5,9,8,7,6,0,4,3,2,1),(6,5,9,8,7,1,0,4,3,2),(7,8,7,6,5,2,1,0,4,3),(8,7,6,5,4,3,2,1,0,4),(9,6,5,4,3,2,1,0,4,3))
    permutation = ((0,1,2,3,4,5,6,7,8,9),(0,5,7,6,2,8,3,9,4,1),(0,8,1,5,7,2,9,4,3,6),(0,3,8,0,6,4,1,7,5,2),(0,6,3,4,1,5,2,8,9,7),(0,9,0,2,4,8,6,1,7,3),(0,4,1,7,6,0,9,5,3,2),(0,2,7,6,3,1,5,9,8,4))
    inverse = (0,4,3,2,1,5,6,7,8,9)
    checksum = 0
    for position, digit in enumerate(reversed(digits)):
        checksum = multiplication[checksum][permutation[(position + 1) % 8][int(digit)]]
    return checksum == inverse[0]


def _kind(value: str, column_name: str = "") -> str | None:
    value = TOKEN.sub(" ", value)
    if EMAIL.search(value): return "email"
    if PAN.search(value): return "pan"
    if AADHAAR.search(value) and verhoeff(value): return "aadhaar"
    if CARD.search(value) and luhn(value): return "credit_card"
    phone_match = PHONE.search(value)
    if phone_match and (value.strip() == phone_match.group(0) or _contextual_phone(value)): return "phone"
    if _contextual_phone(value): return "phone"
    if IP.search(value) and all(int(part) <= 255 for part in IP.search(value).group(0).split(".")): return "ip_address"
    if DATE.search(value) and any(token in column_name.lower() for token in ("dob", "birth")): return "date_of_birth"
    return None


def _contextual_phone(value: str) -> bool:
    """Recognize international phone formatting without treating ordinary numbers as PII."""
    lowered = value.lower()
    context_words = ("phone", "call", "tel", "contact", "reach", "number")
    for match in FORMATTED_PHONE.finditer(value):
        if len(re.sub(r"\D", "", match.group(0))) < 7:
            continue
        start = max(0, match.start() - 48)
        end = min(len(value), match.end() + 48)
        if match.group(0).startswith("+") or any(token in lowered[start:end] for token in context_words) or len(re.sub(r"\D", "", match.group(0))) >= 10:
            return True
    return False


def detect_pii(raw_csv_text: str, profile: dict[str, Any]) -> dict[str, Any]:
    """Scan every cell; return counts and positions, never values."""
    reader = csv.reader(io.StringIO(raw_csv_text.lstrip("\ufeff"), newline=""))
    next(reader)
    findings: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    ner_findings: list[dict[str, Any]] = []
    for row_index, row in enumerate(reader):
        for column_index, value in enumerate(row):
            kinds: list[str] = []
            found = _kind(value, profile["headers"][column_index])
            if found: kinds.append(found)
            for kind in kinds:
                counts[kind] += 1
                findings.append({"row": row_index, "column": profile["headers"][column_index], "type": kind})
            if profile["columns"][column_index]["free_text"]:
                for label, start, end in _named_entities(value):
                    kind = {"PERSON": "person", "ORGANIZATION": "organization", "GPE": "location", "LOCATION": "location"}[label]
                    counts[kind] += 1
                    ner_findings.append({"row": row_index, "column": profile["headers"][column_index], "type": kind, "start": start, "end": end})
    by_column: dict[str, list[str]] = {}
    for finding in findings:
        by_column.setdefault(finding["column"], []).append(finding["type"])
    return {"findings": findings + ner_findings, "counts": dict(counts), "by_column": {k: dict(Counter(v)) for k, v in by_column.items()}, "ner_findings": ner_findings, "scanned_cells": profile["row_count"] * profile["column_count"]}
