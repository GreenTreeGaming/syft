"""Plan and optionally execute actions without altering deterministic labels."""

from __future__ import annotations

import hashlib

from syft.agent.explainer import Explainer
from syft.agent.models import ActionKind, ActionResult, ActionStatus, AgentRun
from syft.agent.router import build_action_plans
from syft.agent.state import ActionLedger
from syft.integrations import IntegrationError
from syft.integrations.github import GitHubQuarantineClient
from syft.integrations.github_summary import GitHubPRSummaryClient, summary_action_id
from syft.integrations.linear import LinearClient
from syft.integrations.slack import SlackWebhookClient
from syft.history.models import WorkflowHistorySummary
from syft.models.analysis import WorkflowAnalysis


def run_agent(
    workflow: WorkflowAnalysis,
    explainer: Explainer,
    ledger: ActionLedger,
    *,
    dry_run: bool = True,
    github: GitHubQuarantineClient | None = None,
    linear: LinearClient | None = None,
    slack: SlackWebhookClient | None = None,
    github_summary: GitHubPRSummaryClient | None = None,
    publish_github_summary: bool = False,
    history: WorkflowHistorySummary | None = None,
) -> AgentRun:
    if history is not None and history.repository != workflow.repository:
        raise ValueError("History repository does not match workflow repository")
    if hasattr(explainer, "investigations"):
        explainer.investigations.clear()
    plans = build_action_plans(workflow, explainer)
    investigations = [
        item.model_copy(update={"workflow_run_id": workflow.workflow_run_id})
        for item in getattr(explainer, "investigations", [])
    ]
    results: list[ActionResult] = []

    for plan, analysis in zip(plans, workflow.analyses, strict=True):
        if dry_run:
            results.append(
                ActionResult(
                    action_id=plan.action_id,
                    kind=plan.kind,
                    status=ActionStatus.PLANNED,
                    detail=f"Dry run: would create {plan.kind.value}.",
                )
            )
            continue
        previous = ledger.result(plan.action_id)
        if previous and ledger.completed(plan.action_id):
            results.append(
                previous.model_copy(
                    update={
                        "status": ActionStatus.ALREADY_EXISTS,
                        "detail": "Action already recorded in the idempotency ledger.",
                    }
                )
            )
            continue
        try:
            if plan.kind is ActionKind.QUARANTINE_PR:
                if github is None:
                    raise IntegrationError("GitHub client is not configured")
                result = github.create_quarantine_pr(
                    plan,
                    analysis,
                    base_branch=workflow.branch,
                )
            else:
                if linear is None:
                    raise IntegrationError("Linear client is not configured")
                result = linear.create_issue(plan)
        except IntegrationError as error:
            result = ActionResult(
                action_id=plan.action_id,
                kind=plan.kind,
                status=ActionStatus.FAILED,
                detail=str(error),
            )
        ledger.record(result)
        results.append(result)

    if publish_github_summary:
        summary_id = summary_action_id(workflow.workflow_analysis_id)
        if dry_run:
            summary_result = ActionResult(
                action_id=summary_id,
                kind=ActionKind.GITHUB_PR_SUMMARY,
                status=ActionStatus.PLANNED,
                detail="Dry run: would create or update one GitHub pull-request summary.",
            )
        elif github_summary is None:
            summary_result = ActionResult(
                action_id=summary_id,
                kind=ActionKind.GITHUB_PR_SUMMARY,
                status=ActionStatus.FAILED,
                detail="GitHub PR-summary client is not configured",
            )
        else:
            try:
                summary_result = github_summary.upsert_summary(
                    workflow,
                    plans,
                    list(results),
                    history=history,
                )
            except IntegrationError as error:
                summary_result = ActionResult(
                    action_id=summary_id,
                    kind=ActionKind.GITHUB_PR_SUMMARY,
                    status=ActionStatus.FAILED,
                    detail=str(error),
                )
        results.append(summary_result)

    digest = build_slack_digest(workflow, results, history=history)
    digest_id = _digest_action_id(workflow.workflow_analysis_id)
    if dry_run:
        results.append(
            ActionResult(
                action_id=digest_id,
                kind=ActionKind.SLACK_DIGEST,
                status=ActionStatus.PLANNED,
                detail="Dry run: would post one Slack digest.",
            )
        )
    elif ledger.completed(digest_id):
        previous_digest = ledger.result(digest_id)
        if previous_digest:
            results.append(
                previous_digest.model_copy(
                    update={
                        "status": ActionStatus.ALREADY_EXISTS,
                        "detail": "Slack digest already recorded in the idempotency ledger.",
                    }
                )
            )
    elif slack is None:
        results.append(
            ActionResult(
                action_id=digest_id,
                kind=ActionKind.SLACK_DIGEST,
                status=ActionStatus.FAILED,
                detail="Slack client is not configured",
            )
        )
    else:
        try:
            digest_result = slack.post_digest(digest_id, digest)
        except IntegrationError as error:
            digest_result = ActionResult(
                action_id=digest_id,
                kind=ActionKind.SLACK_DIGEST,
                status=ActionStatus.FAILED,
                detail=str(error),
            )
        ledger.record(digest_result)
        results.append(digest_result)

    return AgentRun(
        workflow_analysis_id=workflow.workflow_analysis_id,
        dry_run=dry_run,
        model=explainer.model_name,
        plans=plans,
        results=results,
        slack_digest=digest,
        history=history,
        investigations=investigations,
    )


def build_slack_digest(
    workflow: WorkflowAnalysis,
    results: list[ActionResult],
    *,
    history: WorkflowHistorySummary | None = None,
) -> str:
    if history is not None and history.repository != workflow.repository:
        raise ValueError("History repository does not match workflow repository")
    links = {result.action_id: result.url for result in results if result.url}
    statuses = {result.action_id: result.status for result in results}
    lines = [
        f"*Syft CI triage* — `{_slack_code(workflow.repository)}` run `{workflow.workflow_run_id}`",
        (
            f"*{workflow.summary.total} failures:* {workflow.summary.flaky} flaky · "
            f"{workflow.summary.regression} regression · {workflow.summary.escalate} needs triage"
        ),
    ]
    for analysis in workflow.analyses:
        kind = {
            "FLAKY": ActionKind.QUARANTINE_PR,
            "REGRESSION": ActionKind.REGRESSION_TICKET,
            "ESCALATE": ActionKind.TRIAGE_TICKET,
        }[analysis.classification.value]
        action_id = _action_id(workflow.workflow_analysis_id, analysis.test.node_id, kind)
        if action_id in links:
            action = f"<{links[action_id]}|view action>"
        elif statuses.get(action_id) is ActionStatus.FAILED:
            action = "action failed"
        elif statuses.get(action_id) is ActionStatus.ALREADY_EXISTS:
            action = "action already exists"
        else:
            action = "action planned"
        trend = history.by_test.get(analysis.test.node_id) if history else None
        history_note = ""
        if trend:
            history_note = (
                f" — history: {trend.observations} occurrence(s), "
                f"{trend.flaky_occurrence_rate:.0%} flaky, "
                f"{trend.rerun_pass_rate:.0%} rerun pass rate"
            )
        lines.append(
            f"• `{_slack_code(analysis.test.name)}` — *{analysis.classification.value}* "
            f"({analysis.confidence:.0%}) — {action}{history_note}"
        )
    if history:
        lines.append(
            f"_History: {history.records} observations across {history.tests} tests "
            f"and {history.workflow_runs} workflow runs._"
        )
    lines.append("_Classifications are deterministic; the LLM only explains the evidence._")
    return "\n".join(lines)


def _digest_action_id(workflow_id: str) -> str:
    digest = hashlib.sha256(f"{workflow_id}\0SLACK_DIGEST".encode()).hexdigest()[:20]
    return f"act_{digest}"


def _action_id(workflow_id: str, test_node_id: str, kind: ActionKind) -> str:
    digest = hashlib.sha256(f"{workflow_id}\0{test_node_id}\0{kind.value}".encode()).hexdigest()[:20]
    return f"act_{digest}"


def _slack_code(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("@", "＠")
        .replace("`", "'")
        .replace("\r", " ")
        .replace("\n", " ")
    )
