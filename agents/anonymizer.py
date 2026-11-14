"""Schema-preserving HMAC pseudonymization and text scrubbing."""
from __future__ import annotations

import csv
import hashlib
import hmac
import io
import re
from typing import Any

from .detector import EMAIL, PHONE, FORMATTED_PHONE, PAN, AADHAAR, CARD, IP, TOKEN, luhn, verhoeff


def _key(master: str, column: str, version: str) -> bytes:
    salt = version.encode()
    prk = hmac.new(salt, master.encode(), hashlib.sha256).digest()
    return hmac.new(prk, ("pii-guard:" + column + ":" + version).encode() + b"\x01", hashlib.sha256).digest()


def _token(value: str, column: str, prefix: str, master: str, version: str) -> str:
    digest = hmac.new(_key(master, column, version), value.encode("utf-8"), hashlib.sha256).hexdigest()[:24]
    return f"{prefix}_{version}_{digest}"


def _formula_safe(value: str) -> str:
    dangerous = value.startswith(("=", "+", "@")) or (value.startswith("-") and not re.fullmatch(r"-\d+(?:\.\d+)?", value))
    return "'" + value if dangerous else value


def _scrub(value: str, column: str, master: str, version: str, known_names: list[str] | None = None) -> str:
    for name in sorted(known_names or [], key=len, reverse=True):
        normalized = re.sub(r"\s+", r"\\s+", name.strip())
        if name and len(name.split()) >= 2:
            value = re.sub(r"(?<!\w)" + normalized + r"(?!\w)", _token(name, column, "prs", master, version), value, flags=re.IGNORECASE)
    def replace(match: re.Match[str], prefix: str) -> str:
        return _token(match.group(0), column, prefix, master, version)
    value = EMAIL.sub(lambda m: replace(m, "eml"), value)
    value = PAN.sub(lambda m: replace(m, "pan"), value)
    value = PHONE.sub(lambda m: "***" + re.sub(r"\D", "", m.group(0))[-4:], value)
    value = AADHAAR.sub(lambda m: replace(m, "uid") if verhoeff(m.group(0)) else m.group(0), value)
    value = CARD.sub(lambda m: replace(m, "crd") if luhn(m.group(0)) else m.group(0), value)
    def replace_international(match: re.Match[str]) -> str:
        if len(re.sub(r"\D", "", match.group(0))) < 7:
            return match.group(0)
        token_match = TOKEN.search(value, max(0, match.start() - 40), min(len(value), match.end() + 40))
        if token_match and token_match.start() <= match.start() and token_match.end() >= match.end():
            return match.group(0)
        start = max(0, match.start() - 48)
        end = min(len(value), match.end() + 48)
        context = value[start:end].lower()
        if match.group(0).startswith("+") or any(token in context for token in ("phone", "call", "tel", "contact", "reach", "number")) or len(re.sub(r"\D", "", match.group(0))) >= 10:
            return "***" + re.sub(r"\D", "", match.group(0))[-4:]
        return match.group(0)
    value = FORMATTED_PHONE.sub(replace_international, value)
    value = IP.sub(lambda m: replace(m, "ip"), value)
    try:
        from .detector import _named_entities
        for label, start, end in reversed(_named_entities(value)):
            prefix = {"PERSON": "prs", "ORGANIZATION": "org", "GPE": "loc", "LOCATION": "loc"}[label]
            value = value[:start] + _token(value[start:end], column, prefix, master, version) + value[end:]
    except (ImportError, LookupError):
        pass
    return _formula_safe(value)


def anonymize_csv(raw_csv_text: str, policy: dict[str, Any], master_secret: str, key_version: str = "v1") -> tuple[str, int]:
    if not master_secret:
        raise ValueError("HMAC master key is not configured")
    reader = csv.reader(io.StringIO(raw_csv_text.lstrip("\ufeff"), newline=""))
    rows = list(reader)
    headers = rows[0]
    name_indexes = [index for index, header in enumerate(headers) if any(token in header.lower() for token in ("name", "customer"))]
    known_names = sorted({row[index].strip() for row in rows[1:] for index in name_indexes if len(row[index].strip().split()) >= 2}, key=len, reverse=True)
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(headers)
    transformed = 0
    for row in rows[1:]:
        new_row = []
        for index, value in enumerate(row):
            settings = policy["columns"][headers[index]]
            action = settings["action"]
            if action == "hash" and value:
                prefix = {"email": "eml", "phone": "phn", "pan": "pan", "credit_card": "crd"}.get((settings["entity_types"] or ["usr"])[0], "usr")
                value = _token(value, headers[index], prefix, master_secret, key_version)
                transformed += 1
            elif action == "mask_last4" and value:
                digits = re.sub(r"\D", "", value)
                value = "***" + digits[-4:] if len(digits) >= 4 else "***"
                transformed += 1
            elif action == "scrub_text":
                replacement = _scrub(value, headers[index], master_secret, key_version, known_names)
                transformed += replacement != value
                value = replacement
            else:
                value = _formula_safe(value)
            new_row.append(value)
        writer.writerow(new_row)
    return output.getvalue(), transformed
