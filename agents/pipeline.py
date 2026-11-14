"""In-memory multi-agent PII pipeline adapter for infra/lambda_function.py."""
from __future__ import annotations

import os
import uuid
from typing import Any

from agents.anonymizer import anonymize_csv
from agents.auditor import audit_csv
from agents.classifier import classify_columns
from agents.detector import detect_pii
from agents.policy_engine import build_policy
from agents.profiler import profile_csv

LLM_PROVIDER = os.getenv("LLM_PROVIDER", "bedrock").lower()
BEDROCK_MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "amazon.nova-micro-v1:0")
BEDROCK_REGION = os.getenv("BEDROCK_REGION", os.getenv("AWS_REGION", "us-east-1"))
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
HMAC_KEY_VERSION = os.getenv("HMAC_KEY_VERSION", "v1")
PIPELINE_VERSION = "1.0.0"


class PipelineError(RuntimeError):
    """Raised when input validation or independent audit fails."""


def run_pii_pipeline(raw_csv_text: str, salt: str) -> tuple[str, dict]:
    """Execute the 6-agent pipeline in RAM and return (clean_csv_string, audit_report_dict)."""
    if not salt:
        raise PipelineError("Pipeline salt is required")

    profile = profile_csv(raw_csv_text)
    detection = detect_pii(raw_csv_text, profile)

    provider = None
    fallback = False
    if any(item["ambiguous"] for item in profile["columns"]):
        if LLM_PROVIDER == "bedrock":
            try:
                from llm.bedrock_provider import BedrockProvider
                provider = BedrockProvider(BEDROCK_MODEL_ID, BEDROCK_REGION)
            except Exception:
                fallback = True
        elif LLM_PROVIDER == "groq" and GROQ_API_KEY:
            try:
                from llm.groq_provider import GroqProvider
                provider = GroqProvider(GROQ_API_KEY, GROQ_MODEL)
            except Exception:
                fallback = True
        elif LLM_PROVIDER != "disabled":
            fallback = True

    classifications, used_fallback = classify_columns(profile, detection, provider)
    policy = build_policy(profile, detection, classifications)

    has_transformations = any(item["action"] != "keep" for item in policy["columns"].values())
    cleaned = raw_csv_text
    transformed = 0
    if has_transformations:
        cleaned, transformed = anonymize_csv(raw_csv_text, policy, salt, HMAC_KEY_VERSION)

    audit = audit_csv(raw_csv_text, cleaned, policy, profile["row_count"])
    report = {
        "pipeline_version": PIPELINE_VERSION,
        "run_id": "run-" + uuid.uuid4().hex[:16],
        "llm_provider": LLM_PROVIDER,
        "status": audit["status"],
        "total_rows": profile["row_count"],
        "total_columns": profile["column_count"],
        "entities_detected": len(detection["findings"]),
        "entities_transformed": transformed,
        "fallback_used": fallback or used_fallback,
        "key_version": HMAC_KEY_VERSION,
        **audit,
    }
    if audit["status"] != "PASS":
        raise PipelineError(f"Independent audit did not pass: {audit.get('failures')}")
    return cleaned, report