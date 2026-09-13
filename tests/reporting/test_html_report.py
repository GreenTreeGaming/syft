from datetime import datetime, timezone
from pathlib import Path

import pytest

from syft.agent.explainer import TemplateExplainer
from syft.agent.models import ActionKind, ActionResult, ActionStatus, AgentRun, Explanation
from syft.agent.orchestrator import run_agent
from syft.agent.router import build_action_plans
from syft.agent.state import ActionLedger
from syft.eval.ground_truth import GroundTruthCase
from syft.models.analysis import Classification, WorkflowAnalysis
from syft.reporting import render_html_report
from syft.reporting.__main__ import main
from syft.reporting.html_report import write_html_report


SECRET_OUTPUT = "GITHUB_TOKEN=super-secret-value\nAWS_SECRET_ACCESS_KEY=also-secret"


def _with_poisoned_fields(workflow: WorkflowAnalysis) -> WorkflowAnalysis:
    poisoned = workflow.model_copy(deep=True)
    analysis = poisoned.analyses[0]
    analysis.test.node_id = 'tests/x.py::test_<script>alert("xss")</script>'
    analysis.analysis_id = "ta_<img src=x onerror=alert(1)>"
    analysis.trace.message = '<b>trace</b> & "quoted"'
    analysis.code_evidence.matching_related_files = ["app/<script>steal()</script>.py"]
    analysis.reruns[0].output = SECRET_OUTPUT
    poisoned.repository = "acme/<svg onload=alert(1)>"
    poisoned.current_commit = "abc<script>1</script>"
    return poisoned


def _executed_run(workflow: WorkflowAnalysis, tmp_path: Path) -> AgentRun:
    github_urls = {
        ActionKind.QUARANTINE_PR: "https://github.test/pr/10",
        ActionKind.REGRESSION_TICKET: "https://linear.test/ENG-1",
        ActionKind.TRIAGE_TICKET: "https://linear.test/ENG-2",
    }

    class Github:
        def create_quarantine_pr(self, plan, analysis, base_branch):
            return ActionResult(
                action_id=plan.action_id,
                kind=plan.kind,
                status=ActionStatus.CREATED,
                external_id="10",
                url=github_urls[plan.kind],
                detail="created",
            )

    class Linear:
        def create_issue(self, plan):
            return ActionResult(
                action_id=plan.action_id,
                kind=plan.kind,
                status=ActionStatus.CREATED,
                external_id="ENG",
                url=github_urls[plan.kind],
                detail="created",
            )

    class Slack:
        def post_digest(self, action_id, digest):
            return ActionResult(
                action_id=action_id,
                kind=ActionKind.SLACK_DIGEST,
                status=ActionStatus.CREATED,
                detail="created",
            )

    return run_agent(
        workflow,
        TemplateExplainer(),
        ActionLedger(tmp_path / "state.json"),
        dry_run=False,
        github=Github(),
        linear=Linear(),
        slack=Slack(),
    )


def test_escapes_external_strings_and_omits_secrets(workflow_analysis: WorkflowAnalysis) -> None:
    workflow = _with_poisoned_fields(workflow_analysis)
    plans = build_action_plans(workflow, TemplateExplainer())
    plans[0].explanation = Explanation(
        headline="ok",
        summary="ok",
        hypothesis='Inject <script>alert("hyp")</script>',
        evidence=["safe"],
        recommended_action="Do <img src=x> nothing",
    )
    agent_run = AgentRun(
        workflow_analysis_id=workflow.workflow_analysis_id,
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        dry_run=True,
        model=None,
        plans=plans,
        results=[],
        slack_digest="unused",
    )
    html = render_html_report(workflow, agent_run=agent_run)

    assert "<script>alert" not in html
    assert "<img src=x" not in html
    assert "<b>trace</b>" not in html
    assert "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;" in html
    assert "&lt;b&gt;trace&lt;/b&gt; &amp; &quot;quoted&quot;" in html
    assert "Inject &lt;script&gt;alert(&quot;hyp&quot;)&lt;/script&gt;" in html
    assert "Do &lt;img src=x&gt; nothing" in html
    assert SECRET_OUTPUT not in html
    assert "super-secret-value" not in html
    assert "AWS_SECRET_ACCESS_KEY" not in html
    assert "javascript:" not in html.lower()
    assert "cdn." not in html
    assert "<script src" not in html
    assert "http://" not in html.split("<style>", 1)[1].split("</style>", 1)[0]


def test_renders_classifications_and_rerun_counts(workflow_analysis: WorkflowAnalysis) -> None:
    html = render_html_report(workflow_analysis)
    assert html.count('data-classification="FLAKY"') == 1
    assert html.count('data-classification="REGRESSION"') == 1
    assert html.count('data-classification="ESCALATE"') == 1
    assert 'data-metric="flaky"' in html
    assert ">1<" in html
    assert "Rerun passed" in html
    assert "Rerun failed" in html
    assert "ta_flaky" in html
    assert "fixture failed" in html
    assert "app/checkout.py" in html
    assert "91%" in html
    assert "LLM never decides" in html


def test_shows_created_action_links_by_action_id(
    workflow_analysis: WorkflowAnalysis,
    tmp_path: Path,
) -> None:
    agent_run = _executed_run(workflow_analysis, tmp_path)
    html = render_html_report(workflow_analysis, agent_run=agent_run)
    by_kind = {plan.kind: plan for plan in agent_run.plans}
    github_id = by_kind[ActionKind.QUARANTINE_PR].action_id
    linear_ids = {
        by_kind[ActionKind.REGRESSION_TICKET].action_id,
        by_kind[ActionKind.TRIAGE_TICKET].action_id,
    }
    assert f'data-action-id="{github_id}"' in html
    assert 'data-channel="GitHub"' in html
    assert 'href="https://github.test/pr/10"' in html
    for action_id in linear_ids:
        assert f'data-action-id="{action_id}"' in html
    assert 'data-channel="Linear"' in html
    assert "https://linear.test/ENG-1" in html
    assert "https://linear.test/ENG-2" in html
    assert "SLACK_DIGEST" not in html


def test_confusion_matrix_and_false_negatives(workflow_analysis: WorkflowAnalysis) -> None:
    cases = [
        GroundTruthCase(test="tests/test_flaky.py::test_flaky", expected=Classification.FLAKY),
        GroundTruthCase(test="tests/test_checkout.py::test_checkout", expected=Classification.REGRESSION),
        GroundTruthCase(test="tests/test_ambiguous.py::test_ambiguous", expected=Classification.FLAKY),
    ]
    html = render_html_report(workflow_analysis, ground_truth=cases)
    assert 'data-testid="confusion"' in html
    assert 'data-expected="FLAKY" data-predicted="FLAKY"' in html
    assert 'data-expected="REGRESSION" data-predicted="REGRESSION"' in html
    assert 'data-expected="FLAKY" data-predicted="ESCALATE" data-diagonal="false">1</td>' in html
    fn_card = html.split('data-testid="metric-false-negatives"', 1)[1].split("</article>", 1)[0]
    assert ">0</div>" in fn_card
    assert "Accuracy 66.7%" in html


def test_incomplete_ground_truth_cannot_inflate_accuracy(workflow_analysis: WorkflowAnalysis) -> None:
    cases = [
        GroundTruthCase(test="tests/test_flaky.py::test_flaky", expected=Classification.FLAKY),
        GroundTruthCase(test="tests/test_checkout.py::test_checkout", expected=Classification.REGRESSION),
        GroundTruthCase(test="tests/test_ambiguous.py::test_ambiguous", expected=Classification.ESCALATE),
        GroundTruthCase(test="tests/unseen.py::test_unseen", expected=Classification.REGRESSION),
        GroundTruthCase(test="tests/also_missing.py::test_gone", expected=Classification.FLAKY),
    ]
    with pytest.raises(ValueError, match="tests/unseen.py::test_unseen") as caught:
        render_html_report(workflow_analysis, ground_truth=cases)
    message = str(caught.value)
    assert "Missing predictions for ground-truth tests:" in message
    assert "tests/also_missing.py::test_gone" in message
    assert "Accuracy 100.0%" not in message


def test_agent_run_must_match_workflow_analysis_id(
    workflow_analysis: WorkflowAnalysis,
    tmp_path: Path,
) -> None:
    agent_run = _executed_run(workflow_analysis, tmp_path).model_copy(
        update={"workflow_analysis_id": "wa_other_run"}
    )
    with pytest.raises(ValueError, match="wa_other_run") as caught:
        render_html_report(workflow_analysis, agent_run=agent_run)
    assert workflow_analysis.workflow_analysis_id in str(caught.value)
    output = tmp_path / "should-not-exist.html"
    with pytest.raises(ValueError, match="does not match analysis"):
        write_html_report(output, workflow_analysis, agent_run=agent_run)
    assert not output.exists()


def test_regression_false_negative_card(workflow_analysis: WorkflowAnalysis) -> None:
    workflow = workflow_analysis.model_copy(deep=True)
    workflow.analyses[1].classification = Classification.FLAKY
    workflow.summary.flaky = 2
    workflow.summary.regression = 0
    cases = [
        GroundTruthCase(test="tests/test_checkout.py::test_checkout", expected=Classification.REGRESSION),
    ]
    html = render_html_report(workflow, ground_truth=cases)
    fn_card = html.split('data-testid="metric-false-negatives"', 1)[1].split("</article>", 1)[0]
    assert ">1</div>" in fn_card
    assert 'data-expected="REGRESSION" data-predicted="FLAKY" data-diagonal="false">1</td>' in html


def test_missing_optional_inputs_are_explicit(workflow_analysis: WorkflowAnalysis) -> None:
    html = render_html_report(workflow_analysis)
    assert 'data-testid="confusion-missing"' in html
    assert "Ground truth was not provided" in html
    assert html.count('data-testid="actions-missing"') == 3
    assert "Not available — agent run not provided." in html
    fn_card = html.split('data-testid="metric-false-negatives"', 1)[1].split("</article>", 1)[0]
    assert ">n/a</div>" in fn_card


def test_rejects_javascript_action_urls(workflow_analysis: WorkflowAnalysis) -> None:
    plans = build_action_plans(workflow_analysis, TemplateExplainer())
    results = [
        ActionResult(
            action_id=plans[0].action_id,
            kind=plans[0].kind,
            status=ActionStatus.CREATED,
            url="javascript:alert(1)",
            detail="bad",
        )
    ]
    agent_run = AgentRun(
        workflow_analysis_id=workflow_analysis.workflow_analysis_id,
        dry_run=False,
        plans=plans,
        results=results,
        slack_digest="unused",
    )
    html = render_html_report(workflow_analysis, agent_run=agent_run)
    assert "javascript:alert" not in html
    assert "no public link" in html


def test_cli_writes_report_from_json_files(workflow_analysis: WorkflowAnalysis, tmp_path: Path) -> None:
    analysis_path = tmp_path / "analysis.json"
    agent_path = tmp_path / "agent.json"
    truth_path = tmp_path / "truth.json"
    output_path = tmp_path / "out" / "report.html"
    analysis_path.write_text(workflow_analysis.consumer_dump_json(indent=2), encoding="utf-8")
    agent_path.write_text(_executed_run(workflow_analysis, tmp_path).model_dump_json(indent=2), encoding="utf-8")
    truth_path.write_text(
        '[{"test":"tests/test_flaky.py::test_flaky","expected":"FLAKY"},'
        '{"test":"tests/test_checkout.py::test_checkout","expected":"REGRESSION"},'
        '{"test":"tests/test_ambiguous.py::test_ambiguous","expected":"ESCALATE"}]',
        encoding="utf-8",
    )
    assert main(
        [
            "--analysis",
            str(analysis_path),
            "--agent-run",
            str(agent_path),
            "--ground-truth",
            str(truth_path),
            "--output",
            str(output_path),
        ]
    ) == 0
    html = output_path.read_text(encoding="utf-8")
    assert "https://github.test/pr/10" in html
    assert 'data-testid="confusion"' in html
    assert write_html_report(tmp_path / "copy.html", workflow_analysis).exists()


def test_cli_allows_omitting_optional_inputs(workflow_analysis: WorkflowAnalysis, tmp_path: Path) -> None:
    analysis_path = tmp_path / "analysis.json"
    output_path = tmp_path / "report.html"
    analysis_path.write_text(workflow_analysis.consumer_dump_json(), encoding="utf-8")
    assert main(["--analysis", str(analysis_path), "--output", str(output_path)]) == 0
    html = output_path.read_text(encoding="utf-8")
    assert "Ground truth was not provided" in html
    assert "@media print" in html
    assert "@media (max-width: 720px)" in html
