"""Conditional semantic classification using safe metadata only."""
from __future__ import annotations

from typing import Any


def deterministic_classify(profile: dict[str, Any], detection: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for column in profile["columns"]:
        name = column["name"].lower()
        found = detection["by_column"].get(column["name"], {})
        if found:
            entity = next(iter(found))
            label = {"credit_card": "FINANCIAL", "date_of_birth": "DATE_OF_BIRTH", "ip_address": "IP_ADDRESS"}.get(entity, entity.upper())
            result[column["name"]] = {"label": label, "confidence": 1.0, "source": "deterministic"}
        elif any(token in name for token in ("email", "mail")):
            result[column["name"]] = {"label": "EMAIL", "confidence": 0.95, "source": "deterministic"}
        elif any(token in name for token in ("phone", "mobile", "tel")):
            result[column["name"]] = {"label": "PHONE", "confidence": 0.95, "source": "deterministic"}
        elif any(token in name for token in ("address", "street")):
            result[column["name"]] = {"label": "ADDRESS", "confidence": 0.9, "source": "deterministic"}
        elif any(token in name for token in ("name", "customer")):
            result[column["name"]] = {"label": "PERSON", "confidence": 0.8, "source": "deterministic"}
        elif column["free_text"]:
            result[column["name"]] = {"label": "FREE_TEXT", "confidence": 0.7, "source": "deterministic"}
        elif column["ambiguous"]:
            result[column["name"]] = {"label": "UNKNOWN", "confidence": 0.0, "source": "fallback"}
        else:
            result[column["name"]] = {"label": "NON_PII", "confidence": 0.8, "source": "deterministic"}
    return result


def classify_columns(profile: dict[str, Any], detection: dict[str, Any], provider: Any = None) -> tuple[dict[str, dict[str, Any]], bool]:
    """Use a provider only for ambiguous metadata, with safe fallback."""
    base = deterministic_classify(profile, detection)
    ambiguous = [item for item in profile["columns"] if item["ambiguous"] and base[item["name"]]["label"] == "UNKNOWN"]
    if not ambiguous or provider is None:
        return base, False
    metadata = {"columns": [{k: item[k] for k in ("name", "data_type", "null_percentage", "cardinality_ratio", "free_text")} for item in ambiguous]}
    try:
        response = provider.classify_columns(metadata)
        for item in ambiguous:
            candidate = response.get(item["name"], {})
            if candidate.get("label") in {"PERSON", "EMAIL", "PHONE", "ADDRESS", "FINANCIAL", "LOCATION", "FREE_TEXT"}:
                base[item["name"]] = {"label": candidate["label"], "confidence": float(candidate.get("confidence", 0.0)), "source": "llm"}
        return base, bool(getattr(provider, "fallback_used", False))
    except Exception:
        return base, True
