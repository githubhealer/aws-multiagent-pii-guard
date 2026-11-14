"""Conservative, deterministic transformation policy."""
from __future__ import annotations

from typing import Any


def build_policy(profile: dict[str, Any], detection: dict[str, Any], classifications: dict[str, dict[str, Any]]) -> dict[str, Any]:
    actions: dict[str, dict[str, Any]] = {}
    for column in profile["columns"]:
        name = column["name"]
        types = detection["by_column"].get(name, {})
        label = classifications.get(name, {}).get("label", "UNKNOWN")
        if types:
            entity = next(iter(types))
            action = "scrub_text" if column["free_text"] else ("mask_last4" if entity in {"phone", "credit_card"} else "hash")
            if entity == "date_of_birth" and not column["free_text"]:
                action = "hash"
        elif label in {"EMAIL", "PHONE", "FINANCIAL", "PERSON", "ADDRESS", "LOCATION"}:
            action = "scrub_text" if column["free_text"] else "hash"
        elif label == "FREE_TEXT" or column["free_text"]:
            action = "scrub_text"
        elif label == "UNKNOWN" and column["ambiguous"]:
            # Unknown fields must be protected even when the optional LLM is unavailable.
            action = "scrub_text" if column["free_text"] else "hash"
        else:
            action = "keep"
        actions[name] = {"action": action, "entity_types": list(types), "classification": label}
    return {"columns": actions, "manual_review": False}
