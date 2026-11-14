"""Groq adapter; it receives metadata only, never raw CSV values."""
from __future__ import annotations

import json
import math
from typing import Any

LABELS = {"PERSON", "EMAIL", "PHONE", "ADDRESS", "FINANCIAL", "LOCATION", "FREE_TEXT", "NON_PII"}


class GroqProvider:
    def __init__(self, api_key: str, model: str):
        self.model = model
        self.fallback_used = False
        if not api_key:
            raise ValueError("Groq API key is not configured")
        from groq import Groq
        self.client = Groq(api_key=api_key)

    def classify_columns(self, metadata: dict[str, Any]) -> dict[str, dict[str, Any]]:
        prompt = "Return a JSON object mapping each supplied column name to exactly {label, confidence}. label must be one of PERSON, EMAIL, PHONE, ADDRESS, FINANCIAL, LOCATION, FREE_TEXT, NON_PII. confidence must be a number from 0 to 1. Use only the supplied metadata; never infer from values. Metadata: " + json.dumps(metadata, separators=(",", ":"))
        for attempt in range(2):
            try:
                response = self.client.chat.completions.create(model=self.model, temperature=0, response_format={"type": "json_object"}, messages=[{"role": "user", "content": prompt}])
                content = response.choices[0].message.content
                result = json.loads(content) if isinstance(content, str) else content
                if isinstance(result, dict) and isinstance(result.get("columns", result), dict):
                    result = result.get("columns", result)
                    validated: dict[str, dict[str, Any]] = {}
                    for column_name, value in result.items():
                        if not isinstance(column_name, str) or not isinstance(value, dict):
                            raise ValueError("invalid Groq classification shape")
                        label = value.get("label")
                        confidence = value.get("confidence")
                        if label not in LABELS or not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not math.isfinite(confidence) or not 0 <= confidence <= 1:
                            raise ValueError("invalid Groq classification value")
                        validated[column_name] = {"label": label, "confidence": float(confidence)}
                    return validated
                raise ValueError("invalid Groq JSON object")
            except Exception:
                if attempt == 1: raise
        raise ValueError("Groq returned invalid JSON")

    def audit_free_text(self, chunks: list[str]) -> dict[str, Any]:
        return {"status": "SKIPPED", "checked": 0}
