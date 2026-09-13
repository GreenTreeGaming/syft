"""Publish one idempotent Syft evidence summary on the failed branch's pull request."""

from __future__ import annotations

import hashlib
from html import escape
from urllib.parse import urlparse

import httpx

from syft.agent.models import ActionKind, ActionPlan, ActionResult, ActionStatus
from syft.integrations import IntegrationError
from syft.models.analysis import TestAnalysis, WorkflowAnalysis


class GitHubPRSummaryClient:
    def __init__(
        self,
        token: str,
        repository: str,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not token:
            raise IntegrationError("GITHUB_TOKEN is required for --execute")
        if repository.count("/") != 1:
            raise IntegrationError("GitHub repository must have the form owner/repo")
        self.repository = repository
        self.owner = repository.split("/", 1)[0]
        self._client = httpx.Client(
            base_url="https://api.github.com",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=30.0,
            transport=transport,
            follow_redirects=True,
        )

    def close(self) -> None:
        self._client.close()

    def upsert_summary(
        self,
        workflow: WorkflowAnalysis,
        plans: list[ActionPlan],
        results: list[ActionResult],
    ) -> ActionResult:
        action_id = summary_action_id(workflow.workflow_analysis_id)
        pull = self._find_open_pull_request(workflow.branch)
        if pull is None:
            return ActionResult(
                action_id=action_id,
                kind=ActionKind.GITHUB_PR_SUMMARY,
                status=ActionStatus.SKIPPED,
                detail=f"No open pull request found for branch {workflow.branch!r}.",
            )

        try:
            pull_number = int(pull["number"])
        except (KeyError, TypeError, ValueError) as error:
            raise IntegrationError("GitHub returned a pull request without a valid number") from error

        marker = summary_marker()
        body = render_pr_summary(workflow, plans, results)
        existing = self._find_summary_comment(pull_number, marker)
        if existing is not None:
            try:
                comment_id = int(existing["id"])
            except (KeyError, TypeError, ValueError) as error:
                raise IntegrationError("GitHub returned a summary comment without a valid ID") from error
            comment = self._json(
                "PATCH",
                f"/repos/{self.repository}/issues/comments/{comment_id}",
                json={"body": body},
            )
            return _comment_result(
                action_id,
                comment,
                status=ActionStatus.UPDATED,
                detail="Existing Syft pull-request summary updated.",
            )

        comment = self._json(
            "POST",
            f"/repos/{self.repository}/issues/{pull_number}/comments",
            json={"body": body},
        )
        return _comment_result(
            action_id,
            comment,
            status=ActionStatus.CREATED,
            detail="Syft pull-request summary created.",
        )

    def _find_open_pull_request(self, branch: str) -> dict[str, object] | None:
        payload = self._json(
            "GET",
            f"/repos/{self.repository}/pulls",
            params={"state": "open", "head": f"{self.owner}:{branch}", "per_page": 1},
        )
        return payload[0] if isinstance(payload, list) and payload else None

    def _find_summary_comment(self, pull_number: int, marker: str) -> dict[str, object] | None:
        page = 1
        while True:
            payload = self._json(
                "GET",
                f"/repos/{self.repository}/issues/{pull_number}/comments",
                params={"per_page": 100, "page": page},
            )
            if not isinstance(payload, list):
                raise IntegrationError("GitHub returned an invalid pull-request comments response")
            for comment in payload:
                if isinstance(comment, dict) and marker in str(comment.get("body", "")):
                    return comment
            if len(payload) < 100:
                return None
            page += 1

    def _json(self, method: str, url: str, **kwargs: object) -> object:
        try:
            response = self._client.request(method, url, **kwargs)
            response.raise_for_status()
            return response.json()
        except (httpx.HTTPError, ValueError) as error:
            raise IntegrationError(f"GitHub PR-summary request failed for {url}: {error}") from error


def render_pr_summary(
    workflow: WorkflowAnalysis,
    plans: list[ActionPlan],
    results: list[ActionResult],
) -> str:
    """Render a compact, escaped GitHub-flavored Markdown evidence summary."""

    plans_by_analysis = {plan.analysis_id: plan for plan in plans}
    results_by_action = {result.action_id: result for result in results}
    run_url = f"https://github.com/{workflow.repository}/actions/runs/{workflow.workflow_run_id}"
    lines = [
        summary_marker(),
        "## Syft CI failure analysis",
        "",
        (
            f"**{workflow.summary.total} failed tests:** {workflow.summary.flaky} flaky · "
            f"{workflow.summary.regression} regression · {workflow.summary.escalate} needs triage"
        ),
        "",
        "> Classifications are deterministic. The LLM only explains collected evidence.",
        "",
        "| Test | Classification | Confidence | Isolated reruns | Evidence | Action |",
        "|---|---:|---:|---:|---|---|",
    ]
    for analysis in workflow.analyses:
        plan = plans_by_analysis.get(analysis.analysis_id)
        result = results_by_action.get(plan.action_id) if plan else None
        lines.append(_analysis_row(analysis, result))
    lines.extend(
        [
            "",
            f"[View GitHub Actions run]({_safe_markdown_url(run_url)})",
            "",
            (
                f"<sub>Workflow analysis {_code_cell(workflow.workflow_analysis_id)} · "
                f"commit {_code_cell(workflow.current_commit[:12])}</sub>"
            ),
        ]
    )
    return "\n".join(lines) + "\n"


def summary_action_id(workflow_analysis_id: str) -> str:
    digest = hashlib.sha256(
        f"{workflow_analysis_id}\0GITHUB_PR_SUMMARY".encode()
    ).hexdigest()[:20]
    return f"act_{digest}"


def summary_marker() -> str:
    """Return the stable marker used to keep exactly one Syft comment per PR."""

    return "<!-- syft-ci-summary:v1 -->"


def _analysis_row(analysis: TestAnalysis, result: ActionResult | None) -> str:
    reruns = f"{analysis.rerun_summary.passed} passed / {analysis.rerun_summary.failed} failed"
    evidence = analysis.reason
    if analysis.trace and analysis.trace.message:
        evidence = f"{evidence} Trace: {analysis.trace.message}"
    return "| " + " | ".join(
        [
            _code_cell(analysis.test.node_id),
            f"**{_markdown_cell(analysis.classification.value)}**",
            f"{analysis.confidence:.0%}",
            _markdown_cell(reruns),
            _markdown_cell(evidence),
            _action_cell(result),
        ]
    ) + " |"


def _action_cell(result: ActionResult | None) -> str:
    if result is None:
        return "Not available"
    url = _safe_http_url(result.url)
    if url:
        return f"[View action]({_safe_markdown_url(url)})"
    return _markdown_cell(result.status.value.replace("_", " ").title())


def _markdown_cell(value: object) -> str:
    text = escape(str(value), quote=False)
    text = text.replace("\\", "\\\\")
    for character in "`*_{}[]()#+!~>":
        text = text.replace(character, f"\\{character}")
    return (
        text.replace("@", "&#64;")
        .replace("|", "\\|")
        .replace("\r\n", "<br>")
        .replace("\n", "<br>")
    )


def _code_cell(value: object) -> str:
    text = escape(str(value), quote=False)
    text = text.replace("@", "&#64;").replace("|", "&#124;")
    text = text.replace("\r\n", "<br>").replace("\n", "<br>")
    return f"<code>{text}</code>"


def _safe_http_url(url: str | None) -> str | None:
    if not url:
        return None
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return url


def _safe_markdown_url(url: str) -> str:
    return escape(url, quote=True).replace("(", "%28").replace(")", "%29")


def _comment_result(
    action_id: str,
    payload: object,
    *,
    status: ActionStatus,
    detail: str,
) -> ActionResult:
    if not isinstance(payload, dict):
        raise IntegrationError("GitHub returned an invalid pull-request comment")
    external_id = payload.get("id")
    url = _safe_http_url(str(payload.get("html_url", "")))
    if external_id is None or url is None:
        raise IntegrationError("GitHub returned a pull-request comment without an ID or URL")
    return ActionResult(
        action_id=action_id,
        kind=ActionKind.GITHUB_PR_SUMMARY,
        status=status,
        external_id=str(external_id),
        url=url,
        detail=detail,
    )
