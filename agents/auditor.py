"""Independent deterministic audit of the produced CSV."""
from __future__ import annotations

import csv
import io
import re
from typing import Any

from .detector import detect_pii
from .profiler import profile_csv


def audit_csv(original_csv: str, cleaned_csv: str, policy: dict[str, Any], expected_rows: int) -> dict[str, Any]:
    try:
        profile = profile_csv(cleaned_csv)
        detection = detect_pii(cleaned_csv, profile)
    except Exception:
        return {"status": "FAIL", "potential_leaks": 1, "reason": "output_invalid"}
    headers = profile["headers"]
    original_rows = list(csv.reader(io.StringIO(original_csv.lstrip("\ufeff"))))
    clean_rows = list(csv.reader(io.StringIO(cleaned_csv.lstrip("\ufeff"))))
    failures: list[str] = []
    if profile["row_count"] != expected_rows or len(original_rows) != len(clean_rows): failures.append("row_count")
    for name, settings in policy["columns"].items():
        if settings["action"] == "review": failures.append("manual_review")
    if detection["findings"]: failures.append("residual_pii")
    original_names = []
    for index, header in enumerate(original_rows[0]):
        if any(token in header.lower() for token in ("name", "customer")):
            original_names.extend(row[index].strip() for row in original_rows[1:] if row[index].strip())
    if any(re.search(r"(?<!\w)" + re.sub(r"\s+", r"\\s+", name.strip()) + r"(?!\w)", cell, flags=re.IGNORECASE) for name in original_names if len(name.split()) >= 2 for row in clean_rows[1:] for cell in row):
        failures.append("residual_person_name")
    detected_cells = {(finding["row"], finding["column"]) for finding in detection["findings"]}
    for row_index, original_row in enumerate(original_rows[1:]):
        cleaned_row = clean_rows[row_index + 1]
        for column_index, name in enumerate(headers):
            if (row_index, name) in detected_cells and original_row[column_index] and original_row[column_index] == cleaned_row[column_index]:
                failures.append("unchanged_sensitive_value")
                break
    def is_formula(cell: str) -> bool:
        return cell.startswith(("=", "+", "@")) or (cell.startswith("-") and not cell.lstrip("-").replace(".", "", 1).isdigit())
    if any(is_formula(cell) for row in clean_rows for cell in row): failures.append("formula_injection")
    status = "PASS" if not failures else "FAIL"
    return {"status": status, "potential_leaks": len(detection["findings"]), "failures": failures, "total_rows": profile["row_count"], "total_columns": profile["column_count"], "validation": {key: ("FAIL" if detection["counts"].get(key) else "PASS") for key in ("email", "phone", "pan", "aadhaar", "credit_card")}}
