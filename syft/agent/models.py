"""Contracts for agent explanations, plans, and execution results."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from syft.history.models import WorkflowHistorySummary
from syft.models.analysis import Classification


class AgentModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ActionKind(str, Enum):
    QUARANTINE_PR = "QUARANTINE_PR"
    REGRESSION_TICKET = "REGRESSION_TICKET"
    TRIAGE_TICKET = "TRIAGE_TICKET"
    SLACK_DIGEST = "SLACK_DIGEST"
    GITHUB_PR_SUMMARY = "GITHUB_PR_SUMMARY"


class ActionStatus(str, Enum):
    PLANNED = "PLANNED"
    CREATED = "CREATED"
    ALREADY_EXISTS = "ALREADY_EXISTS"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    UPDATED = "UPDATED"


class Explanation(AgentModel):
    """LLM output deliberately excludes classification and confidence."""

    headline: str = Field(min_length=1, max_length=160)
    summary: str = Field(min_length=1, max_length=1200)
    hypothesis: str = Field(min_length=1, max_length=1200)
    evidence: list[str] = Field(min_length=1, max_length=6)
    recommended_action: str = Field(min_length=1, max_length=600)


class ActionPlan(AgentModel):
    action_id: str
    analysis_id: str
    classification: Classification
    kind: ActionKind
    test_node_id: str
    test_file: str
    title: str
    body: str
    explanation: Explanation


class ActionResult(AgentModel):
    action_id: str
    kind: ActionKind
    status: ActionStatus
    external_id: str | None = None
    url: str | None = None
    detail: str


class ToolCallRecord(AgentModel):
    """One allowlisted tool invocation during explanation."""

    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    ok: bool
    preview: str = ""


class Investigation(AgentModel):
    """Persisted evidence that the explainer chose and invoked tools."""

    analysis_id: str
    test_node_id: str
    workflow_run_id: int | None = None
    turns: int = Field(ge=0)
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    timed_out: bool = False
    hit_tool_cap: bool = False
    used_template_fallback: bool = False


class AgentRun(AgentModel):
    schema_version: str = "1.0"
    workflow_analysis_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    dry_run: bool
    model: str | None = None
    plans: list[ActionPlan]
    results: list[ActionResult]
    slack_digest: str
    history: WorkflowHistorySummary | None = None
    investigations: list[Investigation] = Field(default_factory=list)
