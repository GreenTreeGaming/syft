from pathlib import Path

from syft.agent.explainer import TemplateExplainer
from syft.agent.models import ActionKind, ActionResult, ActionStatus
from syft.agent.orchestrator import run_agent
from syft.agent.state import ActionLedger
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

