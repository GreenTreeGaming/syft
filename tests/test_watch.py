import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from syft.agent.explainer import TemplateExplainer
from syft.agent.models import ActionKind, ActionResult, ActionStatus, AgentRun
from syft.agent.state import ActionLedger
from syft.deterministic.github_runs import GitHubRun
from syft.history.store import HistoryStore
from syft.models.analysis import WorkflowAnalysis
from syft.watch import (
    ProcessedRunLedger,
    WatchError,
    WatchStatus,
    WorkflowWatcher,
    watch_forever,
)


class FakeGitHub:
    repository = "owner/repo"

    def __init__(self, run: GitHubRun | None) -> None:
        self.run = run

    def latest_failed_run_or_none(self, branch: str) -> GitHubRun | None:
        assert branch == "fixture"
        return self.run


def _failed_run() -> GitHubRun:
    return GitHubRun(
        id=42,
        head_sha="current-sha",
        name="CI",
        conclusion="failure",
        created_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
    )


def _watcher(
    tmp_path: Path,
    workflow: WorkflowAnalysis,
    analyzer,
    *,
    execute: bool = False,
) -> WorkflowWatcher:
    return WorkflowWatcher(
        repo_path=tmp_path,
        github=FakeGitHub(_failed_run()),  # type: ignore[arg-type]
        explainer=TemplateExplainer(),
        action_ledger=ActionLedger(tmp_path / "action-state.json"),
        run_ledger=ProcessedRunLedger(tmp_path / "watch-state.json"),
        output_directory=tmp_path / "runs",
        branch="fixture",
        green_branch="main",
        artifact_name="pytest-junit",
        attempts=3,
        timeout_seconds=10,
        trace_directory=tmp_path / "traces",
        execute=execute,
        analyzer=analyzer,
    )


def test_processes_once_writes_outputs_and_deduplicates(
    workflow_analysis: WorkflowAnalysis,
    tmp_path: Path,
    mocker,
) -> None:
    analyzer = mocker.Mock(return_value=workflow_analysis)
    watcher = _watcher(tmp_path, workflow_analysis, analyzer)

    first = watcher.run_cycle()
    second = watcher.run_cycle()

    assert first.status is WatchStatus.PROCESSED
    assert first.workflow_run_id == 42
    assert first.analysis_path == tmp_path / "runs" / "42" / "analysis.json"
    assert first.agent_run_path == tmp_path / "runs" / "42" / "agent-run.json"
    assert first.analysis_path.exists()
    assert first.agent_run_path.exists()
    assert "reruns" in first.analysis_path.read_text(encoding="utf-8")
    agent_payload = json.loads(first.agent_run_path.read_text(encoding="utf-8"))
    assert any(
        item["kind"] == "GITHUB_PR_SUMMARY" and item["status"] == "PLANNED"
        for item in agent_payload["results"]
    )
    assert second.status is WatchStatus.ALREADY_PROCESSED
    assert analyzer.call_count == 1
    _, _, passed_run = analyzer.call_args.args
    assert passed_run.id == 42


def test_dry_run_does_not_suppress_later_execution(tmp_path: Path) -> None:
    ledger = ProcessedRunLedger(tmp_path / "watch-state.json")
    ledger.record("owner/repo", "main", 42, execute=False)

    assert ledger.completed("owner/repo", "main", 42, execute=False)
    assert not ledger.completed("owner/repo", "main", 42, execute=True)

    ledger.record("owner/repo", "main", 42, execute=True)
    reloaded = ProcessedRunLedger(tmp_path / "watch-state.json")
    assert reloaded.completed("owner/repo", "main", 42, execute=False)
    assert reloaded.completed("owner/repo", "main", 42, execute=True)


def test_successful_cycle_records_history_in_agent_artifact(
    workflow_analysis: WorkflowAnalysis,
    tmp_path: Path,
    mocker,
) -> None:
    with HistoryStore(tmp_path / "history.sqlite") as history_store:
        watcher = _watcher(
            tmp_path,
            workflow_analysis,
            mocker.Mock(return_value=workflow_analysis),
        )
        watcher.history_store = history_store
        result = watcher.run_cycle()
        records = history_store.repository_history("owner/repo")
        saved = history_store.load_investigations("owner/repo", 42)

    payload = json.loads(result.agent_run_path.read_text(encoding="utf-8"))
    assert len(records) == 3
    assert payload["history"]["records"] == 3
    assert payload["history"]["workflow_runs"] == 1
    assert payload["history"]["by_test"]["tests/test_flaky.py::test_flaky"]["flaky_count"] == 1
    assert len(payload["investigations"]) == 3
    assert {item.test_node_id for item in saved} == {
        analysis.test.node_id for analysis in workflow_analysis.analyses
    }


def test_no_failed_run_is_a_normal_cycle(
    workflow_analysis: WorkflowAnalysis,
    tmp_path: Path,
    mocker,
) -> None:
    analyzer = mocker.Mock(return_value=workflow_analysis)
    watcher = _watcher(tmp_path, workflow_analysis, analyzer)
    watcher.github = FakeGitHub(None)  # type: ignore[assignment]

    result = watcher.run_cycle()

    assert result.status is WatchStatus.NO_FAILURE
    analyzer.assert_not_called()


def test_failed_external_action_keeps_run_retryable(
    workflow_analysis: WorkflowAnalysis,
    tmp_path: Path,
    mocker,
) -> None:
    failed_agent_run = AgentRun(
        workflow_analysis_id=workflow_analysis.workflow_analysis_id,
        dry_run=False,
        plans=[],
        results=[
            ActionResult(
                action_id="act_failed",
                kind=ActionKind.SLACK_DIGEST,
                status=ActionStatus.FAILED,
                detail="temporary failure",
            )
        ],
        slack_digest="digest",
    )
    mocker.patch("syft.watch.run_agent", return_value=failed_agent_run)
    watcher = _watcher(
        tmp_path,
        workflow_analysis,
        mocker.Mock(return_value=workflow_analysis),
        execute=True,
    )

    with pytest.raises(WatchError, match="remains retryable"):
        watcher.run_cycle()

    assert not watcher.run_ledger.completed("owner/repo", "fixture", 42, execute=True)
    assert not (tmp_path / "runs" / "42").exists()


def test_once_surfaces_cycle_failure(tmp_path: Path) -> None:
    class BrokenWatcher:
        def run_cycle(self):
            raise RuntimeError("temporary GitHub outage")

    with pytest.raises(WatchError, match="temporary GitHub outage"):
        watch_forever(BrokenWatcher(), interval_seconds=1, once=True)  # type: ignore[arg-type]


def test_cycle_errors_redact_environment_secrets(monkeypatch) -> None:
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.test/secret-value")

    class BrokenWatcher:
        def run_cycle(self):
            raise RuntimeError("failed at https://hooks.slack.test/secret-value")

    with pytest.raises(WatchError) as caught:
        watch_forever(BrokenWatcher(), interval_seconds=1, once=True)  # type: ignore[arg-type]
    assert "secret-value" not in str(caught.value)
    assert "[REDACTED]" in str(caught.value)


def test_continuous_mode_retries_after_transient_failure() -> None:
    class StopLoop(BaseException):
        pass

    class RecoveringWatcher:
        calls = 0

        def run_cycle(self):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("temporary GitHub outage")
            return type(
                "Result",
                (),
                {
                    "status": WatchStatus.NO_FAILURE,
                    "workflow_run_id": None,
                    "analysis_path": None,
                    "agent_run_path": None,
                },
            )()

    watcher = RecoveringWatcher()
    sleeps = 0

    def stop_after_retry(_: float) -> None:
        nonlocal sleeps
        sleeps += 1
        if sleeps == 2:
            raise StopLoop

    with pytest.raises(StopLoop):
        watch_forever(watcher, interval_seconds=1, sleep=stop_after_retry)  # type: ignore[arg-type]
    assert watcher.calls == 2


def test_rejects_non_positive_interval(tmp_path: Path) -> None:
    class UnusedWatcher:
        def run_cycle(self):
            raise AssertionError("must not run")

    with pytest.raises(ValueError, match="greater than zero"):
        watch_forever(UnusedWatcher(), interval_seconds=0, once=True)  # type: ignore[arg-type]
