"""AWS Bedrock adapter; receives column metadata only, never raw CSV values."""
from __future__ import annotations

import json
import math
import re
from typing import Any

LABELS = {"PERSON", "EMAIL", "PHONE", "ADDRESS", "FINANCIAL", "LOCATION", "FREE_TEXT", "NON_PII"}


class BedrockProvider:
    def __init__(self, model: str = "amazon.nova-micro-v1:0", region_name: str = "us-east-1"):
        self.model = model
        self.fallback_used = False
        import boto3
        self.client = boto3.client("bedrock-runtime", region_name=region_name)

    def classify_columns(self, metadata: dict[str, Any]) -> dict[str, dict[str, Any]]:
        prompt = (
            "Return ONLY a valid JSON object mapping each supplied column name to exactly "
            '{"label": "<LABEL>", "confidence": <0_TO_1>}. '
            "label must be one of PERSON, EMAIL, PHONE, ADDRESS, FINANCIAL, LOCATION, FREE_TEXT, NON_PII. "
            "confidence must be a number from 0 to 1. Use only the supplied metadata; never infer from values. "
            "Metadata: " + json.dumps(metadata, separators=(",", ":"))
        )
        for attempt in range(2):
            try:
                response = self.client.converse(
                    modelId=self.model,
                    messages=[{"role": "user", "content": [{"text": prompt}]}],
                    inferenceConfig={"temperature": 0.0, "maxTokens": 512},
                )
                content = response["output"]["message"]["content"][0]["text"].strip()
                json_match = re.search(r"\{.*\}", content, re.DOTALL)
                if json_match:
                    content = json_match.group(0)
                result = json.loads(content)
                if isinstance(result, dict) and isinstance(result.get("columns", result), dict):
                    result = result.get("columns", result)
                    validated: dict[str, dict[str, Any]] = {}
                    for column_name, value in result.items():
                        if not isinstance(column_name, str) or not isinstance(value, dict):
                            raise ValueError("invalid Bedrock classification shape")
                        label = value.get("label")
                        confidence = value.get("confidence")
                        if (
                            label not in LABELS
                            or not isinstance(confidence, (int, float))
                            or isinstance(confidence, bool)
                            or not math.isfinite(confidence)
                            or not 0 <= confidence <= 1
                        ):
                            raise ValueError("invalid Bedrock classification value")
                        validated[column_name] = {"label": label, "confidence": float(confidence)}
                    return validated
                raise ValueError("invalid Bedrock JSON object")
            except Exception:
                if attempt == 1:
                    raise
        raise ValueError("Bedrock returned invalid JSON")

    def audit_free_text(self, chunks: list[str]) -> dict[str, Any]:
        return {"status": "SKIPPED", "checked": 0}
