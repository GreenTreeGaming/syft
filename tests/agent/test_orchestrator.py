from pathlib import Path

import pytest

from syft.agent.explainer import TemplateExplainer
from syft.agent.models import ActionKind, ActionResult, ActionStatus
from syft.agent.orchestrator import run_agent
from syft.agent.state import ActionLedger
from syft.history.store import HistoryStore
from syft.history.summary import workflow_history_summary
from syft.models.analysis import WorkflowAnalysis


def test_dry_run_plans_actions_without_clients(
    workflow_analysis: WorkflowAnalysis,
    tmp_path: Path,
) -> None:
    result = run_agent(
        workflow_analysis,
        TemplateExplainer(),
        ActionLedger(tmp_path / "state.json"),
    )
    assert result.dry_run is True
    assert [item.status for item in result.results] == [ActionStatus.PLANNED] * 4
    assert "1 flaky · 1 regression · 1 needs triage" in result.slack_digest
    assert "LLM only explains" in result.slack_digest


def test_execute_records_and_reuses_actions(
    mocker,
    workflow_analysis: WorkflowAnalysis,
    tmp_path: Path,
) -> None:
    github = mocker.Mock()
    linear = mocker.Mock()
    slack = mocker.Mock()
    github.create_quarantine_pr.side_effect = lambda plan, analysis, base_branch: ActionResult(
        action_id=plan.action_id,
        kind=plan.kind,
        status=ActionStatus.CREATED,
        external_id="10",
        url="https://github.test/pr/10",
        detail="created",
    )
    linear.create_issue.side_effect = lambda plan: ActionResult(
        action_id=plan.action_id,
        kind=plan.kind,
        status=ActionStatus.CREATED,
        external_id="ENG-1",
        url="https://linear.test/ENG-1",
        detail="created",
    )
    slack.post_digest.side_effect = lambda action_id, digest: ActionResult(
        action_id=action_id,
        kind=ActionKind.SLACK_DIGEST,
        status=ActionStatus.CREATED,
        detail="created",
    )
    ledger = ActionLedger(tmp_path / "state.json")

    first = run_agent(
        workflow_analysis,
        TemplateExplainer(),
        ledger,
        dry_run=False,
        github=github,
        linear=linear,
        slack=slack,
    )
    second = run_agent(
        workflow_analysis,
        TemplateExplainer(),
        ActionLedger(tmp_path / "state.json"),
        dry_run=False,
        github=github,
        linear=linear,
        slack=slack,
    )

    assert all(item.status is ActionStatus.CREATED for item in first.results)
    assert all(item.status is ActionStatus.ALREADY_EXISTS for item in second.results)
    assert github.create_quarantine_pr.call_count == 1
    assert linear.create_issue.call_count == 2
    assert slack.post_digest.call_count == 1


def test_dry_run_plans_github_pr_summary_when_enabled(
    workflow_analysis: WorkflowAnalysis,
    tmp_path: Path,
) -> None:
    result = run_agent(
        workflow_analysis,
        TemplateExplainer(),
        ActionLedger(tmp_path / "state.json"),
        publish_github_summary=True,
    )

    summaries = [
        item for item in result.results if item.kind is ActionKind.GITHUB_PR_SUMMARY
    ]
    assert len(summaries) == 1
    assert summaries[0].status is ActionStatus.PLANNED


def test_execute_publishes_github_pr_summary(
    mocker,
    workflow_analysis: WorkflowAnalysis,
    tmp_path: Path,
) -> None:
    github = mocker.Mock()
    linear = mocker.Mock()
    slack = mocker.Mock()
    summary = mocker.Mock()
    github.create_quarantine_pr.side_effect = lambda plan, analysis, base_branch: ActionResult(
        action_id=plan.action_id,
        kind=plan.kind,
        status=ActionStatus.CREATED,
        external_id="10",
        url="https://github.test/pr/10",
        detail="created",
    )
    linear.create_issue.side_effect = lambda plan: ActionResult(
        action_id=plan.action_id,
        kind=plan.kind,
        status=ActionStatus.CREATED,
        external_id="ENG-1",
        url="https://linear.test/ENG-1",
        detail="created",
    )
    summary.upsert_summary.return_value = ActionResult(
        action_id="act_summary",
        kind=ActionKind.GITHUB_PR_SUMMARY,
        status=ActionStatus.CREATED,
        external_id="99",
        url="https://github.test/pr/7#issuecomment-99",
        detail="created",
    )
    slack.post_digest.side_effect = lambda action_id, digest: ActionResult(
        action_id=action_id,
        kind=ActionKind.SLACK_DIGEST,
        status=ActionStatus.CREATED,
        detail="created",
    )

    result = run_agent(
        workflow_analysis,
        TemplateExplainer(),
        ActionLedger(tmp_path / "state.json"),
        dry_run=False,
        github=github,
        linear=linear,
        slack=slack,
        github_summary=summary,
        publish_github_summary=True,
    )

    summary.upsert_summary.assert_called_once()
    passed_workflow, passed_plans, passed_results = summary.upsert_summary.call_args.args
    assert passed_workflow is workflow_analysis
    assert len(passed_plans) == 3
    assert len(passed_results) == 3
    assert any(item.kind is ActionKind.GITHUB_PR_SUMMARY for item in result.results)


def test_history_is_read_only_context_for_slack_and_agent_run(
    workflow_analysis: WorkflowAnalysis,
    tmp_path: Path,
) -> None:
    original_labels = [item.classification for item in workflow_analysis.analyses]
    with HistoryStore(tmp_path / "history.sqlite") as store:
        store.record_workflow(workflow_analysis)
        history = workflow_history_summary(store, workflow_analysis)
    result = run_agent(
        workflow_analysis,
        TemplateExplainer(),
        ActionLedger(tmp_path / "state.json"),
        history=history,
    )

    assert result.history == history
    assert "history: 1 occurrence(s), 100% flaky, 40% rerun pass rate" in result.slack_digest
    assert "History: 3 observations across 3 tests and 1 workflow runs" in result.slack_digest
    assert [item.classification for item in workflow_analysis.analyses] == original_labels


def test_rejects_history_from_another_repository(
    workflow_analysis: WorkflowAnalysis,
    tmp_path: Path,
) -> None:
    with HistoryStore(tmp_path / "history.sqlite") as store:
        store.record_workflow(workflow_analysis)
        history = workflow_history_summary(store, workflow_analysis).model_copy(
            update={"repository": "other/repository"}
        )

    with pytest.raises(ValueError, match="History repository"):
        run_agent(
            workflow_analysis,
            TemplateExplainer(),
            ActionLedger(tmp_path / "state.json"),
            history=history,
        )
