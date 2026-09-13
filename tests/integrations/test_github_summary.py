import json

import httpx

from syft.agent.explainer import TemplateExplainer
from syft.agent.models import ActionResult, ActionStatus
from syft.agent.router import build_action_plans
from syft.integrations.github_summary import (
    GitHubPRSummaryClient,
    render_pr_summary,
    summary_marker,
)
from syft.history.store import HistoryStore
from syft.history.summary import workflow_history_summary
from syft.models.analysis import WorkflowAnalysis


def _action_results(workflow: WorkflowAnalysis) -> tuple[list, list[ActionResult]]:
    plans = build_action_plans(workflow, TemplateExplainer())
    results = [
        ActionResult(
            action_id=plan.action_id,
            kind=plan.kind,
            status=ActionStatus.CREATED,
            external_id=str(index),
            url=f"https://example.test/actions/{index}",
            detail="created",
        )
        for index, plan in enumerate(plans, start=1)
    ]
    return plans, results


def test_renders_escaped_evidence_table_and_action_links(
    workflow_analysis: WorkflowAnalysis,
) -> None:
    workflow = workflow_analysis.model_copy(deep=True)
    workflow.analyses[0].reason = (
        "timing | state <script>alert(1)</script> [click](https://evil.test) @octocat"
    )
    workflow.analyses[0].trace.message = "first line\nsecond line"
    plans, results = _action_results(workflow)

    body = render_pr_summary(workflow, plans, results)

    assert body.startswith(summary_marker())
    assert "**3 failed tests:** 1 flaky · 1 regression · 1 needs triage" in body
    assert "| Test | Classification | Confidence | Isolated reruns | History | Evidence | Action |" in body
    assert "tests/test_checkout.py::test_checkout" in body
    assert "2 passed / 3 failed" in body
    assert "timing \\| state &lt;script&gt;alert\\(1\\)&lt;/script&gt;" in body
    assert "first line<br>second line" in body
    assert "<script>alert" not in body
    assert "[click](https://evil.test)" not in body
    assert "@octocat" not in body
    assert "[View action](https://example.test/actions/1)" in body
    assert "https://github.com/owner/repo/actions/runs/42" in body
    assert "Classifications are deterministic" in body


def test_creates_summary_comment_when_none_exists(workflow_analysis: WorkflowAnalysis) -> None:
    plans, results = _action_results(workflow_analysis)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("/pulls"):
            assert request.url.params["head"] == "owner:fixture"
            return httpx.Response(200, json=[{"number": 7}])
        if request.url.path.endswith("/issues/7/comments") and request.method == "GET":
            return httpx.Response(200, json=[])
        if request.url.path.endswith("/issues/7/comments") and request.method == "POST":
            payload = json.loads(request.content)
            assert summary_marker() in payload["body"]
            return httpx.Response(
                201,
                json={"id": 99, "html_url": "https://github.test/owner/repo/pull/7#issuecomment-99"},
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = GitHubPRSummaryClient(
        "token",
        "owner/repo",
        transport=httpx.MockTransport(handler),
    )
    try:
        result = client.upsert_summary(workflow_analysis, plans, results)
    finally:
        client.close()

    assert result.status is ActionStatus.CREATED
    assert result.external_id == "99"
    assert result.url.endswith("#issuecomment-99")
    assert [request.method for request in requests] == ["GET", "GET", "POST"]


def test_updates_existing_marked_comment(workflow_analysis: WorkflowAnalysis) -> None:
    plans, results = _action_results(workflow_analysis)
    marker = summary_marker()
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("/pulls"):
            return httpx.Response(200, json=[{"number": 7}])
        if request.url.path.endswith("/issues/7/comments"):
            return httpx.Response(200, json=[{"id": 55, "body": f"old\n{marker}"}])
        if request.url.path.endswith("/issues/comments/55") and request.method == "PATCH":
            payload = json.loads(request.content)
            assert "Syft CI failure analysis" in payload["body"]
            return httpx.Response(
                200,
                json={"id": 55, "html_url": "https://github.test/owner/repo/pull/7#issuecomment-55"},
            )
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    client = GitHubPRSummaryClient(
        "token",
        "owner/repo",
        transport=httpx.MockTransport(handler),
    )
    try:
        result = client.upsert_summary(workflow_analysis, plans, results)
    finally:
        client.close()

    assert result.status is ActionStatus.UPDATED
    assert result.external_id == "55"
    assert [request.method for request in requests] == ["GET", "GET", "PATCH"]


def test_no_matching_pull_request_is_skipped(workflow_analysis: WorkflowAnalysis) -> None:
    plans, results = _action_results(workflow_analysis)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json=[])

    client = GitHubPRSummaryClient(
        "token",
        "owner/repo",
        transport=httpx.MockTransport(handler),
    )
    try:
        result = client.upsert_summary(workflow_analysis, plans, results)
    finally:
        client.close()

    assert result.status is ActionStatus.SKIPPED
    assert "No open pull request" in result.detail
    assert len(requests) == 1


def test_unsafe_action_url_is_not_linked(workflow_analysis: WorkflowAnalysis) -> None:
    plans, results = _action_results(workflow_analysis)
    results[0].url = "javascript:alert(1)"

    body = render_pr_summary(workflow_analysis, plans, results)

    assert "javascript:" not in body
    assert "Created" in body


def test_renders_historical_context(
    workflow_analysis: WorkflowAnalysis,
    tmp_path,
) -> None:
    plans, results = _action_results(workflow_analysis)
    with HistoryStore(tmp_path / "history.sqlite") as store:
        store.record_workflow(workflow_analysis)
        history = workflow_history_summary(store, workflow_analysis)

    body = render_pr_summary(
        workflow_analysis,
        plans,
        results,
        history=history,
    )

    assert "1 occurrence\\(s\\); 100% flaky; 40% rerun pass; 0 consecutive all-fail" in body
    assert "Historical coverage:** 3 observations across 3 tests and 1 workflow runs" in body
