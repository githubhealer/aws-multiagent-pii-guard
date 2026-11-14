from __future__ import annotations

from typing import Any, Protocol


class LLMProvider(Protocol):
    fallback_used: bool

    def classify_columns(self, metadata: dict[str, Any]) -> dict[str, dict[str, Any]]: ...
    def audit_free_text(self, chunks: list[str]) -> dict[str, Any]: ...
