"""Versioned Pydantic contracts for deterministic test analysis."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from pathlib import PurePosixPath
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    """Base model that rejects misspelled or unsupported fields."""

    model_config = ConfigDict(extra="forbid")


class Classification(str, Enum):
    FLAKY = "FLAKY"
    REGRESSION = "REGRESSION"
    ESCALATE = "ESCALATE"


class RerunOutcome(str, Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"


class RerunAttempt(StrictModel):
    attempt: int = Field(ge=1)
    outcome: RerunOutcome
    duration_seconds: float = Field(ge=0.0)
    exit_code: int
    output: str = ""
    passed: bool = False

    @model_validator(mode="after")
    def derive_passed(self) -> "RerunAttempt":
        """Keep the convenience field consistent with the authoritative outcome."""

        self.passed = self.outcome is RerunOutcome.PASSED
        return self


class RerunSummary(StrictModel):
    passed: int = Field(ge=0)
    failed: int = Field(ge=0)
    timed_out: int = Field(ge=0)
    total: int = Field(ge=0)

    @classmethod
    def from_attempts(cls, attempts: list[RerunAttempt]) -> "RerunSummary":
        return cls(
            passed=sum(item.outcome is RerunOutcome.PASSED for item in attempts),
            failed=sum(item.outcome is RerunOutcome.FAILED for item in attempts),
            timed_out=sum(item.outcome is RerunOutcome.TIMED_OUT for item in attempts),
            total=len(attempts),
        )


class TestIdentity(StrictModel):
    node_id: str
    file: str
    name: str

    @classmethod
    def from_node_id(cls, node_id: str) -> "TestIdentity":
        parts = node_id.split("::")
        file = PurePosixPath(parts[0]).as_posix()
        name = parts[-1] if len(parts) > 1 else PurePosixPath(file).stem
        return cls(node_id=node_id, file=file, name=name)


class CodeEvidence(StrictModel):
    related_code_changed: bool | None
    changed_files: list[str] = Field(default_factory=list)
    related_files: list[str] = Field(default_factory=list)
    matching_related_files: list[str] = Field(default_factory=list)


class CommitEvidence(StrictModel):
    current_commit: str
    last_green_commit: str | None
    failed_on_previous_commit: bool | None


class CIContext(StrictModel):
    repository: str
    branch: str = "main"
    workflow_run_id: int | None = None
    workflow_name: str | None = None
    artifact_name: str | None = None


class TraceEvidence(StrictModel):
    source: str
    failure_type: str | None = None
    message: str | None = None
    traceback_excerpt: str | None = None


class ClassificationInput(StrictModel):
    reruns: list[RerunAttempt]
    related_code_changed: bool | None
    failed_on_previous_commit: bool | None = None


class TestAnalysis(StrictModel):
    schema_version: str = "1.0"
    analysis_id: str = Field(default_factory=lambda: f"ta_{uuid4()}")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    test: TestIdentity
    classification: Classification
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str
    rerun_summary: RerunSummary
    reruns: list[RerunAttempt]
    code_evidence: CodeEvidence
    commit_evidence: CommitEvidence
    ci_context: CIContext | None = None
    trace: TraceEvidence | None = None

    def consumer_dump(self) -> dict[str, Any]:
        """Return the compact downstream contract without repeated raw output."""

        return self.model_dump(exclude={"reruns": {"__all__": {"output"}}})

    def consumer_dump_json(self, *, indent: int | None = None) -> str:
        """Serialize the compact downstream contract as JSON."""

        return self.model_dump_json(
            indent=indent,
            exclude={"reruns": {"__all__": {"output"}}},
        )


class ClassificationSummary(StrictModel):
    flaky: int = Field(ge=0)
    regression: int = Field(ge=0)
    escalate: int = Field(ge=0)
    total: int = Field(ge=0)


class WorkflowAnalysis(StrictModel):
    """Aggregate result for every failed test in one workflow run."""

    schema_version: str = "1.0"
    workflow_analysis_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    repository: str
    branch: str
    workflow_run_id: int
    workflow_name: str | None = None
    current_commit: str
    last_green_commit: str
    junit_artifact: str
    failed_tests: list[str]
    summary: ClassificationSummary
    analyses: list[TestAnalysis]

    def consumer_dump_json(self, *, indent: int | None = None) -> str:
        """Serialize compact analyses while retaining the run-level envelope."""

        return self.model_dump_json(
            indent=indent,
            exclude={"analyses": {"__all__": {"reruns": {"__all__": {"output"}}}}},
        )
