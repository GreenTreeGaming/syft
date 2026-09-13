"""High-level deterministic analysis pipeline."""

from __future__ import annotations

import logging
import re
from pathlib import Path

from syft.deterministic.classifier import classify_failure
from syft.deterministic.git_analysis import GitAnalysisError, analyze_related_code, failed_at_commit
from syft.deterministic.rerunner import rerun_test
from syft.models.analysis import (
    CIContext,
    ClassificationInput,
    CodeEvidence,
    CommitEvidence,
    RerunAttempt,
    RerunOutcome,
    RerunSummary,
    TestAnalysis,
    TestIdentity,
    TraceEvidence,
)


logger = logging.getLogger(__name__)


def analyze_failed_test(
    repo_path: Path,
    test_node_id: str,
    current_commit: str,
    last_green_commit: str | None,
    attempts: int = 5,
    timeout_seconds: int = 60,
    inspect_previous_commit: bool = True,
    ci_context: CIContext | None = None,
) -> TestAnalysis:
    repo_path = repo_path.resolve()
    logger.info("analysis_started", extra={"test_node_id": test_node_id, "current_commit": current_commit})
    reruns = rerun_test(repo_path, test_node_id, attempts, timeout_seconds)

    if last_green_commit is None:
        code_evidence = CodeEvidence(related_code_changed=None)
    else:
        related = analyze_related_code(repo_path, last_green_commit, current_commit, test_node_id)
        code_evidence = CodeEvidence.model_validate(related.model_dump())

    failed_on_previous: bool | None = None
    if last_green_commit and inspect_previous_commit:
        try:
            failed_on_previous = failed_at_commit(
                repo_path,
                last_green_commit,
                test_node_id,
                timeout_seconds,
            )
        except GitAnalysisError:
            failed_on_previous = None

    classification, confidence, reason = classify_failure(
        ClassificationInput(
            reruns=reruns,
            related_code_changed=code_evidence.related_code_changed,
            failed_on_previous_commit=failed_on_previous,
        )
    )
    analysis = TestAnalysis(
        test=TestIdentity.from_node_id(test_node_id),
        classification=classification,
        confidence=confidence,
        reason=reason,
        rerun_summary=RerunSummary.from_attempts(reruns),
        reruns=reruns,
        code_evidence=code_evidence,
        commit_evidence=CommitEvidence(
            current_commit=current_commit,
            last_green_commit=last_green_commit,
            failed_on_previous_commit=failed_on_previous,
        ),
        ci_context=ci_context,
        trace=_extract_trace(reruns),
    )
    logger.info(
        "analysis_completed",
        extra={
            "analysis_id": analysis.analysis_id,
            "test_node_id": test_node_id,
            "classification": analysis.classification.value,
        },
    )
    return analysis


def _extract_trace(reruns: list[RerunAttempt]) -> TraceEvidence | None:
    failed = next((item for item in reruns if item.outcome is not RerunOutcome.PASSED and item.output), None)
    if failed is None:
        return None
    lines = [line.strip() for line in failed.output.splitlines() if line.strip()]
    if not lines:
        return TraceEvidence(source="pytest_rerun")

    detailed = next(
        (
            line.removeprefix("E").lstrip()
            for line in lines
            if line.startswith("E") and ("Error" in line or "Exception" in line)
        ),
        None,
    )
    assertion = detailed or next(
        (line for line in reversed(lines) if "Error" in line or "Exception" in line),
        None,
    )
    failure_type = None
    message = None
    if assertion:
        match = re.search(r"([A-Za-z_][\w.]*(?:Error|Exception))(?::\s*(.*))?", assertion)
        if match:
            failure_type = match.group(1)
            raw_message = match.group(2) or None
            message = _humanize_assertion(raw_message)
    location = next((line for line in reversed(lines) if re.search(r"\.py:\d+", line)), None)
    return TraceEvidence(
        source="pytest_rerun",
        failure_type=failure_type,
        message=message,
        traceback_excerpt=location or assertion or lines[-1],
    )


def _humanize_assertion(message: str | None) -> str | None:
    if not message:
        return None
    equality = re.fullmatch(r"assert\s+(.+?)\s+==\s+(.+)", message)
    if equality:
        received, expected = equality.groups()
        return f"Expected {expected}, received {received}."
    return message
