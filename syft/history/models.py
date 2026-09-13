"""Contracts for stored test-failure history."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from syft.models.analysis import Classification, StrictModel


class HistoryRecord(StrictModel):
    """One failed-test observation from a workflow run."""

    repository: str
    workflow_run_id: int
    test_node_id: str
    classification: Classification
    confidence: float = Field(ge=0.0, le=1.0)
    rerun_passed: int = Field(ge=0)
    rerun_failed: int = Field(ge=0)
    commit: str
    branch: str
    recorded_at: datetime


class FlakyRecurrence(StrictModel):
    """A test that has been classified FLAKY more than once in a repository."""

    test_node_id: str
    flaky_count: int = Field(ge=0)
    total: int = Field(ge=0)
    flaky_occurrence_rate: float = Field(ge=0.0, le=1.0)


class TrendSummary(StrictModel):
    """Compact history suitable for Slack or HTML reports."""

    repository: str
    records: int = Field(ge=0)
    tests: int = Field(ge=0)
    workflow_runs: int = Field(ge=0)
    recurring_flaky: list[FlakyRecurrence] = Field(default_factory=list)
    text: str
