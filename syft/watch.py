"""Continuous, idempotent processing of failed GitHub Actions runs."""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from syft.agent.explainer import Explainer
from syft.agent.models import ActionStatus, AgentRun
from syft.agent.orchestrator import run_agent
from syft.agent.state import ActionLedger
from syft.deterministic.coordinator import analyze_failed_workflow
from syft.deterministic.github_runs import GitHubActionsClient
from syft.integrations.github import GitHubQuarantineClient
from syft.integrations.linear import LinearClient
from syft.integrations.slack import SlackWebhookClient
from syft.models.analysis import WorkflowAnalysis

LOGGER = logging.getLogger(__name__)


class WatchError(RuntimeError):
    """Raised when a watch cycle cannot complete safely."""


class WatchStatus(str, Enum):
    NO_FAILURE = "NO_FAILURE"
    ALREADY_PROCESSED = "ALREADY_PROCESSED"
    PROCESSED = "PROCESSED"


@dataclass(frozen=True)
class WatchResult:
    status: WatchStatus
    workflow_run_id: int | None = None
    analysis_path: Path | None = None
    agent_run_path: Path | None = None


class ProcessedRunLedger:
    """Atomic ledger that separates rehearsals from real external execution."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._data = self._load()

    def completed(self, repository: str, branch: str, run_id: int, *, execute: bool) -> bool:
        record = self._data["runs"].get(self._key(repository, branch, run_id), {})
        return bool(record.get("execute" if execute else "dry_run"))

    def record(self, repository: str, branch: str, run_id: int, *, execute: bool) -> None:
        key = self._key(repository, branch, run_id)
        current = self._data["runs"].setdefault(
            key,
            {"repository": repository, "branch": branch, "run_id": run_id},
        )
        current["execute" if execute else "dry_run"] = True
        self._write()

    @staticmethod
    def _key(repository: str, branch: str, run_id: int) -> str:
        return f"{repository}:{branch}:{run_id}"

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"schema_version": "1.0", "runs": {}}
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise WatchError(f"Could not read watch state {self.path}: {error}") from error
        if not isinstance(payload, dict) or not isinstance(payload.get("runs"), dict):
            raise WatchError(f"Invalid watch state file: {self.path}")
        return payload

    def _write(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(json.dumps(self._data, indent=2) + "\n", encoding="utf-8")
        temporary.replace(self.path)


class WorkflowWatcher:
    """Process at most one latest failed run per cycle."""

    def __init__(
        self,
        *,
        repo_path: Path,
        github: GitHubActionsClient,
        explainer: Explainer,
        action_ledger: ActionLedger,
        run_ledger: ProcessedRunLedger,
        output_directory: Path,
        branch: str = "main",
        green_branch: str = "main",
        artifact_name: str | None = None,
        attempts: int = 5,
        timeout_seconds: int = 60,
        trace_directory: Path | None = None,
        execute: bool = False,
        github_actions: GitHubQuarantineClient | None = None,
        linear: LinearClient | None = None,
        slack: SlackWebhookClient | None = None,
        analyzer: Callable[..., WorkflowAnalysis] = analyze_failed_workflow,
    ) -> None:
        self.repo_path = repo_path
        self.github = github
        self.explainer = explainer
        self.action_ledger = action_ledger
        self.run_ledger = run_ledger
        self.output_directory = output_directory
        self.branch = branch
        self.green_branch = green_branch
        self.artifact_name = artifact_name
        self.attempts = attempts
        self.timeout_seconds = timeout_seconds
        self.trace_directory = trace_directory
        self.execute = execute
        self.github_actions = github_actions
        self.linear = linear
        self.slack = slack
        self.analyzer = analyzer

    def run_cycle(self) -> WatchResult:
        failed_run = self.github.latest_failed_run_or_none(self.branch)
        if failed_run is None:
            return WatchResult(status=WatchStatus.NO_FAILURE)
        if self.run_ledger.completed(
            self.github.repository,
            self.branch,
            failed_run.id,
            execute=self.execute,
        ):
            return WatchResult(
                status=WatchStatus.ALREADY_PROCESSED,
                workflow_run_id=failed_run.id,
            )

        workflow = self.analyzer(
            self.repo_path,
            self.github,
            failed_run,
            branch=self.branch,
            green_branch=self.green_branch,
            artifact_name=self.artifact_name,
            attempts=self.attempts,
            timeout_seconds=self.timeout_seconds,
            trace_directory=self.trace_directory,
        )
        agent_run = run_agent(
            workflow,
            self.explainer,
            self.action_ledger,
            dry_run=not self.execute,
            github=self.github_actions,
            linear=self.linear,
            slack=self.slack,
        )
        if self.execute:
            failures = [
                result.action_id
                for result in agent_run.results
                if result.status is ActionStatus.FAILED
            ]
            if failures:
                raise WatchError(
                    "External actions failed; the run remains retryable: " + ", ".join(failures)
                )

        analysis_path, agent_path = self._write_outputs(workflow, agent_run)
        self.run_ledger.record(
            self.github.repository,
            self.branch,
            failed_run.id,
            execute=self.execute,
        )
        return WatchResult(
            status=WatchStatus.PROCESSED,
            workflow_run_id=failed_run.id,
            analysis_path=analysis_path,
            agent_run_path=agent_path,
        )

    def _write_outputs(self, workflow: WorkflowAnalysis, agent_run: AgentRun) -> tuple[Path, Path]:
        destination = self.output_directory / str(workflow.workflow_run_id)
        destination.mkdir(parents=True, exist_ok=True)
        analysis_path = destination / "analysis.json"
        agent_path = destination / "agent-run.json"
        _atomic_write(analysis_path, workflow.consumer_dump_json(indent=2) + "\n")
        _atomic_write(agent_path, agent_run.model_dump_json(indent=2) + "\n")
        return analysis_path, agent_path


def watch_forever(
    watcher: WorkflowWatcher,
    *,
    interval_seconds: float,
    once: bool = False,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    """Run cycles until interrupted; transient failures remain eligible for retry."""

    if interval_seconds <= 0:
        raise ValueError("watch interval must be greater than zero")
    while True:
        try:
            result = watcher.run_cycle()
            LOGGER.info(
                "watch_cycle status=%s workflow_run_id=%s",
                result.status.value,
                result.workflow_run_id or "none",
            )
            if result.analysis_path:
                LOGGER.info("analysis_saved path=%s", result.analysis_path)
            if result.agent_run_path:
                LOGGER.info("agent_run_saved path=%s", result.agent_run_path)
        except Exception as error:
            message = _redact_error_message(str(error))
            if once:
                raise WatchError(f"Watch cycle failed: {message}") from error
            LOGGER.error(
                "watch_cycle_failed error_type=%s message=%s",
                type(error).__name__,
                message,
            )
        if once:
            return 0
        sleep(interval_seconds)


def _atomic_write(path: Path, content: str) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def _redact_error_message(message: str) -> str:
    for name in (
        "GITHUB_TOKEN",
        "OPENAI_API_KEY",
        "LINEAR_API_KEY",
        "LINEAR_TEAM_ID",
        "SLACK_WEBHOOK_URL",
    ):
        secret = os.getenv(name)
        if secret:
            message = message.replace(secret, "[REDACTED]")
    return message
