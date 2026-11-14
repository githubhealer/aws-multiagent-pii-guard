"""Strict CSV validation and value-free dataset profiling."""
from __future__ import annotations

import csv
import io
import re
from collections import Counter
from typing import Any


class ProfileError(ValueError):
    """Raised when input is not a valid supported CSV document."""


def _type_for(values: list[str]) -> str:
    nonempty = [v.strip() for v in values if v.strip()]
    if not nonempty:
        return "null"
    if all(re.fullmatch(r"[-+]?\d+", v) for v in nonempty):
        return "integer"
    if all(re.fullmatch(r"[-+]?(?:\d+\.\d*|\d*\.\d+)", v) for v in nonempty):
        return "float"
    if all(re.fullmatch(r"\d{4}-\d{2}-\d{2}(?:[T ][^ ]+)?", v) for v in nonempty):
        return "date"
    return "string"


def profile_csv(raw_csv_text: str) -> dict[str, Any]:
    """Parse all rows and return metadata without retaining cell values."""
    if not isinstance(raw_csv_text, str) or not raw_csv_text.strip():
        raise ProfileError("CSV input is empty")
    try:
        reader = csv.reader(io.StringIO(raw_csv_text.lstrip("\ufeff"), newline=""))
        try:
            headers = next(reader)
        except StopIteration as exc:
            raise ProfileError("CSV has no header row") from exc
        if not headers or any(not h.strip() for h in headers):
            raise ProfileError("CSV contains an empty column name")
        if len(set(headers)) != len(headers):
            raise ProfileError("CSV contains duplicate column names")
        rows: list[list[str]] = []
        for row_number, row in enumerate(reader, 2):
            if len(row) != len(headers):
                raise ProfileError(f"CSV row {row_number} has the wrong number of fields")
            rows.append(row)
    except csv.Error as exc:
        raise ProfileError("CSV is malformed") from exc

    columns: list[dict[str, Any]] = []
    for index, name in enumerate(headers):
        values = [row[index] for row in rows]
        nonempty = [value for value in values if value.strip()]
        unique = len(set(nonempty))
        ratio = unique / len(nonempty) if nonempty else 0.0
        lower = name.lower().replace("-", "_").replace(" ", "_")
        free_text = (ratio < 0.8 and any(len(v) > 40 for v in nonempty)) or any(token in lower for token in ("comment", "description", "message", "note", "text", "address"))
        has_known_name = any(token in lower for token in ("email", "mail", "phone", "mobile", "pan", "aadhaar", "card", "address", "comment", "text", "name", "ip", "amount", "price", "total", "date", "id"))
        ambiguous = not has_known_name and _type_for(values) == "string"
        columns.append({
            "index": index, "name": name, "data_type": _type_for(values),
            "row_count": len(rows), "null_count": len(values) - len(nonempty),
            "null_percentage": round((len(values) - len(nonempty)) / len(values) * 100, 2) if values else 0.0,
            "cardinality_ratio": round(ratio, 4), "free_text": free_text, "ambiguous": ambiguous,
        })
    return {"headers": headers, "row_count": len(rows), "column_count": len(headers), "columns": columns}
