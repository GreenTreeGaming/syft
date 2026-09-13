"""Persist sanitized, atomic JSON traces."""

from __future__ import annotations

import re
from pathlib import Path

from syft.models.analysis import TestAnalysis


_SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s\"']+"),
    re.compile(r"(?i)((?:github_token|api_key|password)\s*[:=]\s*)[^\s\"']+"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
)


def write_analysis_trace(analysis: TestAnalysis, trace_directory: Path) -> Path:
    trace_directory.mkdir(parents=True, exist_ok=True)
    timestamp = analysis.created_at.strftime("%Y%m%dT%H%M%SZ")
    test_name = re.sub(r"[^A-Za-z0-9_.-]+", "-", analysis.test.node_id).strip("-")[:100]
    target = trace_directory / f"{timestamp}-{analysis.analysis_id}-{test_name}.json"
    temporary = target.with_suffix(".tmp")
    content = analysis.model_dump_json(indent=2)
    for pattern in _SECRET_PATTERNS:
        content = pattern.sub(lambda match: f"{match.group(1)}[REDACTED]" if match.lastindex else "[REDACTED]", content)
    temporary.write_text(content + "\n", encoding="utf-8")
    temporary.replace(target)
    return target

