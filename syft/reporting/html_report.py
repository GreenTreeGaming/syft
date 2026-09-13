"""Standalone, zero-network HTML reports for hackathon demos."""

from __future__ import annotations

import json
from html import escape
from pathlib import Path
from urllib.parse import urlparse

from syft.agent.models import (
    ActionKind,
    ActionPlan,
    ActionResult,
    ActionStatus,
    AgentRun,
    Investigation,
)
from syft.eval.ground_truth import GroundTruthCase
from syft.eval.metrics import EvalMetrics, evaluate_predictions
from syft.models.analysis import Classification, TestAnalysis, WorkflowAnalysis

_LABELS = [item.value for item in Classification]

_KIND_CHANNEL = {
    ActionKind.QUARANTINE_PR: "GitHub",
    ActionKind.REGRESSION_TICKET: "Linear",
    ActionKind.TRIAGE_TICKET: "Linear",
}

_CSS = """
:root {
  --bg: #070b12;
  --bg-elevated: #101826;
  --bg-card: linear-gradient(180deg, rgba(22, 32, 48, 0.96), rgba(12, 18, 28, 0.96));
  --line: rgba(232, 237, 247, 0.08);
  --text: #e8edf7;
  --muted: #8b97ad;
  --accent: #3ee0b2;
  --accent-2: #7aa2ff;
  --flaky: #f5c542;
  --regression: #ff6b6b;
  --escalate: #7aa2ff;
  --shadow: 0 18px 50px rgba(0, 0, 0, 0.35);
  --radius: 18px;
}
* { box-sizing: border-box; }
html { font-size: 16px; }
body {
  margin: 0;
  color: var(--text);
  background:
    radial-gradient(1200px 500px at 10% -10%, rgba(62, 224, 178, 0.12), transparent 50%),
    radial-gradient(900px 400px at 100% 0%, rgba(122, 162, 255, 0.14), transparent 45%),
    var(--bg);
  font-family: "Segoe UI", "Helvetica Neue", ui-sans-serif, system-ui, sans-serif;
  line-height: 1.5;
}
.wrap { width: min(1180px, calc(100% - 32px)); margin: 0 auto; padding: 32px 0 64px; }
.eyebrow {
  display: inline-flex;
  gap: 8px;
  align-items: center;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  font-size: 0.72rem;
  color: var(--accent);
  font-weight: 700;
}
h1 { font-size: clamp(1.8rem, 4vw, 2.6rem); letter-spacing: -0.03em; margin: 8px 0 6px; }
.lede { color: var(--muted); max-width: 46rem; margin: 0 0 28px; }
.safety {
  border: 1px solid rgba(62, 224, 178, 0.28);
  background: rgba(62, 224, 178, 0.08);
  color: #c8f8e8;
  border-radius: 999px;
  padding: 10px 16px;
  display: inline-block;
  font-size: 0.92rem;
  margin-bottom: 28px;
}
.meta {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 12px;
  margin: 24px 0 28px;
}
.meta-item, .card, .metric {
  border: 1px solid var(--line);
  background: var(--bg-card);
  box-shadow: var(--shadow);
  border-radius: var(--radius);
}
.meta-item { padding: 14px 16px; }
.meta-item .k { display: block; color: var(--muted); font-size: 0.75rem; letter-spacing: 0.08em; text-transform: uppercase; }
.meta-item .v { display: block; margin-top: 4px; font-weight: 650; word-break: break-word; }
.metrics {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 14px;
  margin-bottom: 36px;
}
.metric { padding: 18px 18px 16px; }
.metric .label { color: var(--muted); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.1em; }
.metric .value { font-size: 2rem; font-weight: 750; letter-spacing: -0.04em; margin-top: 6px; }
.metric[data-metric="flaky"] .value { color: var(--flaky); }
.metric[data-metric="regression"] .value { color: var(--regression); }
.metric[data-metric="escalate"] .value { color: var(--escalate); }
.metric.fn .value { color: var(--regression); }
h2 { font-size: 1.2rem; letter-spacing: -0.02em; margin: 8px 0 16px; }
.matrix-wrap, .empty-note { padding: 18px; margin-bottom: 36px; overflow-x: auto; }
table.confusion-matrix { width: 100%; border-collapse: collapse; min-width: 420px; }
table.confusion-matrix th, table.confusion-matrix td {
  padding: 10px 12px;
  border-bottom: 1px solid var(--line);
  text-align: center;
}
table.confusion-matrix th { color: var(--muted); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.06em; font-weight: 650; }
table.confusion-matrix td[data-diagonal="true"] { color: var(--accent); font-weight: 700; }
.tests { display: grid; gap: 18px; }
.card { padding: 22px; }
.card-head { display: flex; flex-wrap: wrap; gap: 10px; justify-content: space-between; align-items: flex-start; }
.badge {
  display: inline-block;
  border-radius: 999px;
  padding: 4px 10px;
  font-size: 0.75rem;
  font-weight: 750;
  letter-spacing: 0.08em;
}
.badge.FLAKY { background: rgba(245, 197, 66, 0.16); color: var(--flaky); }
.badge.REGRESSION { background: rgba(255, 107, 107, 0.16); color: var(--regression); }
.badge.ESCALATE { background: rgba(122, 162, 255, 0.16); color: var(--escalate); }
.node { font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace; font-size: 0.92rem; word-break: break-word; }
.facts { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin: 16px 0; }
.fact .k { color: var(--muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.08em; }
.fact .v { margin-top: 3px; }
.trace {
  margin: 8px 0 0;
  padding: 12px 14px;
  border-radius: 12px;
  background: rgba(0, 0, 0, 0.28);
  border: 1px solid var(--line);
  font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
  font-size: 0.88rem;
  white-space: pre-wrap;
  word-break: break-word;
}
.files { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 6px; }
.chip {
  border: 1px solid var(--line);
  border-radius: 999px;
  padding: 3px 10px;
  font-size: 0.8rem;
  font-family: ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace;
}
.investigation { margin-top: 12px; }
.investigation ol { margin: 8px 0 0; padding-left: 1.2rem; }
.investigation li { margin: 6px 0; }
.actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
.actions a {
  color: var(--bg);
  background: var(--accent);
  text-decoration: none;
  border-radius: 999px;
  padding: 6px 12px;
  font-weight: 700;
  font-size: 0.82rem;
}
.muted { color: var(--muted); }
@media (max-width: 720px) {
  .wrap { width: min(100% - 24px, 1180px); padding-top: 20px; }
  .metric .value { font-size: 1.6rem; }
}
@media print {
  body {
    background: #fff;
    color: #111;
  }
  .wrap { width: 100%; padding: 0; }
  .meta-item, .card, .metric, .matrix-wrap, .empty-note {
    background: #fff;
    box-shadow: none;
    border: 1px solid #d5d8e0;
    break-inside: avoid;
  }
  .safety { color: #0b3d30; border-color: #9ad9c5; background: #eefbf6; }
  .badge.FLAKY, .metric[data-metric="flaky"] .value { color: #8a6a00; }
  .badge.REGRESSION, .metric[data-metric="regression"] .value,
  .metric.fn .value { color: #9b1c1c; }
  .badge.ESCALATE, .metric[data-metric="escalate"] .value { color: #1d3f99; }
  .actions a { color: #063; background: #fff; border: 1px solid #063; }
  a[href]::after { content: " (" attr(href) ")"; font-size: 0.8em; color: #444; }
}
"""


def html_escape(value: object | None, *, fallback: str = "") -> str:
    """Escape any untrusted value before it is interpolated into HTML."""

    if value is None:
        text = fallback
    else:
        text = str(value)
        if text == "":
            text = fallback
    return escape(text, quote=True)


def render_html_report(
    workflow: WorkflowAnalysis,
    *,
    agent_run: AgentRun | None = None,
    ground_truth: list[GroundTruthCase] | None = None,
) -> str:
    """Return a self-contained HTML document. Never embeds rerun output or secrets."""

    _validate_report_inputs(workflow, agent_run=agent_run, ground_truth=ground_truth)
    metrics = _metrics(workflow, ground_truth)
    false_negatives = html_escape(metrics.regression_false_negatives if metrics else "n/a")
    title = html_escape(f"{workflow.repository} — Syft CI triage")
    body = "".join(
        [
            "<!DOCTYPE html>\n",
            '<html lang="en">\n<head>\n',
            '<meta charset="utf-8">\n',
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n',
            f"<title>{title}</title>\n",
            f"<style>{_CSS}</style>\n",
            "</head>\n<body>\n<div class=\"wrap\">\n",
            _render_header(workflow),
            _render_metrics(workflow, false_negatives),
            _render_confusion(metrics),
            _render_tests(workflow, agent_run),
            "</div>\n</body>\n</html>\n",
        ]
    )
    return body


def write_html_report(
    output: Path,
    workflow: WorkflowAnalysis,
    *,
    agent_run: AgentRun | None = None,
    ground_truth: list[GroundTruthCase] | None = None,
) -> Path:
    _validate_report_inputs(workflow, agent_run=agent_run, ground_truth=ground_truth)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        render_html_report(workflow, agent_run=agent_run, ground_truth=ground_truth),
        encoding="utf-8",
    )
    return output


def _validate_report_inputs(
    workflow: WorkflowAnalysis,
    *,
    agent_run: AgentRun | None,
    ground_truth: list[GroundTruthCase] | None,
) -> None:
    if agent_run is not None and agent_run.workflow_analysis_id != workflow.workflow_analysis_id:
        raise ValueError(
            "Agent run workflow_analysis_id "
            f"{agent_run.workflow_analysis_id!r} does not match analysis "
            f"{workflow.workflow_analysis_id!r}"
        )
    if not ground_truth:
        return
    predictions = {item.test.node_id for item in workflow.analyses}
    missing = [case.test for case in ground_truth if case.test not in predictions]
    if missing:
        raise ValueError(
            "Missing predictions for ground-truth tests: " + ", ".join(missing)
        )


def _metrics(
    workflow: WorkflowAnalysis,
    ground_truth: list[GroundTruthCase] | None,
) -> EvalMetrics | None:
    if not ground_truth:
        return None
    predictions = {item.test.node_id: item.classification for item in workflow.analyses}
    return evaluate_predictions(ground_truth, predictions)


def _render_header(workflow: WorkflowAnalysis) -> str:
    workflow_label = workflow.workflow_name or "workflow"
    return "".join(
        [
            '<p class="eyebrow">Syft · deterministic CI triage</p>',
            "<h1>Failure analysis report</h1>",
            '<p class="lede">Compact evidence for every failed test in this workflow run. ',
            "Classifications never leave the deterministic pipeline.</p>",
            '<p class="safety" data-testid="safety">',
            "Classifications are deterministic. An LLM never decides FLAKY, REGRESSION, or ESCALATE; ",
            "it may only explain evidence that the classifier already produced.",
            "</p>",
            '<section class="meta" aria-label="Run identity">',
            _meta("Repository", workflow.repository),
            _meta("Workflow", f"{workflow_label} · run {workflow.workflow_run_id}"),
            _meta("Commit", workflow.current_commit),
            _meta("Run ID", workflow.workflow_run_id),
            _meta("Workflow analysis", workflow.workflow_analysis_id),
            _meta("Branch", workflow.branch),
            "</section>",
        ]
    )


def _meta(label: str, value: object) -> str:
    return (
        f'<div class="meta-item"><span class="k">{html_escape(label)}</span>'
        f'<span class="v">{html_escape(value)}</span></div>'
    )


def _render_metrics(workflow: WorkflowAnalysis, false_negatives: str) -> str:
    summary = workflow.summary
    cards = [
        ("flaky", "FLAKY", summary.flaky),
        ("regression", "REGRESSION", summary.regression),
        ("escalate", "ESCALATE", summary.escalate),
        ("total", "Total failed tests", summary.total),
        ("false-negatives", "Regression false negatives", false_negatives),
    ]
    inner = "".join(
        f'<article class="metric{" fn" if key == "false-negatives" else ""}" '
        f'data-metric="{key}" data-testid="metric-{key}">'
        f'<div class="label">{html_escape(label)}</div>'
        f'<div class="value">{html_escape(value)}</div></article>'
        for key, label, value in cards
    )
    return f'<section class="metrics" aria-label="Summary">{inner}</section>'


def _render_confusion(metrics: EvalMetrics | None) -> str:
    if metrics is None:
        return (
            '<section class="empty-note card" data-testid="confusion-missing">'
            "<h2>Confusion matrix</h2>"
            '<p class="muted">Ground truth was not provided, so predicted labels are not scored.</p>'
            "</section>"
        )
    header = "".join(f"<th>{html_escape(label)}</th>" for label in _LABELS)
    rows: list[str] = []
    for expected in _LABELS:
        cells = [f"<th scope=\"row\">Expected {html_escape(expected)}</th>"]
        for predicted in _LABELS:
            count = metrics.confusion_matrix[expected][predicted]
            diagonal = "true" if expected == predicted else "false"
            cells.append(
                f'<td data-expected="{html_escape(expected)}" data-predicted="{html_escape(predicted)}" '
                f'data-diagonal="{diagonal}">{html_escape(count)}</td>'
            )
        rows.append("<tr>" + "".join(cells) + "</tr>")
    return (
        '<section class="matrix-wrap card" data-testid="confusion">'
        "<h2>Confusion matrix</h2>"
        '<p class="muted">Rows are ground truth. Columns are Syft predictions.</p>'
        '<table class="confusion-matrix">'
        f"<thead><tr><th>Expected \\ Predicted</th>{header}</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
        f'<p class="muted">Accuracy {html_escape(f"{metrics.accuracy:.1%}")} · '
        f"regression as flaky {html_escape(metrics.regression_as_flaky)}</p>"
        "</section>"
    )


def _render_tests(workflow: WorkflowAnalysis, agent_run: AgentRun | None) -> str:
    cards = "".join(_render_test_card(analysis, agent_run) for analysis in workflow.analyses)
    return f'<section class="tests" aria-label="Failed tests">{cards}</section>'


def _render_test_card(analysis: TestAnalysis, agent_run: AgentRun | None) -> str:
    plan, result = _match_action(analysis, agent_run)
    classification = analysis.classification.value
    files = analysis.code_evidence.matching_related_files
    file_html = (
        '<div class="files">' + "".join(f'<span class="chip">{html_escape(path)}</span>' for path in files) + "</div>"
        if files
        else '<p class="muted">None</p>'
    )
    hypothesis = plan.explanation.hypothesis if plan else "Not available — agent run not provided."
    recommended = plan.explanation.recommended_action if plan else "Not available — agent run not provided."
    message = analysis.trace.message if analysis.trace and analysis.trace.message else "No failure message recorded."
    return "".join(
        [
            f'<article class="card" data-analysis-id="{html_escape(analysis.analysis_id)}" ',
            f'data-classification="{html_escape(classification)}">',
            '<div class="card-head">',
            f'<div><div class="node">{html_escape(analysis.test.node_id)}</div>',
            f'<div class="muted">{html_escape(analysis.test.file)}</div></div>',
            f'<span class="badge {html_escape(classification)}">{html_escape(classification)}</span>',
            "</div>",
            '<div class="facts">',
            _fact("Confidence", f"{analysis.confidence:.0%}"),
            _fact("Rerun passed", analysis.rerun_summary.passed),
            _fact("Rerun failed", analysis.rerun_summary.failed),
            _fact("Analysis ID", analysis.analysis_id),
            "</div>",
            _fact("Exact trace message", ""),
            f'<div class="trace">{html_escape(message)}</div>',
            _fact("Changed related files", ""),
            file_html,
            _fact("Hypothesis", hypothesis),
            _fact("Recommended action", recommended),
            _render_investigation(_match_investigation(analysis, agent_run), agent_run),
            _render_action_links(plan, result),
            "</article>",
        ]
    )


def _fact(label: str, value: object) -> str:
    if value == "":
        return f'<div class="fact"><div class="k">{html_escape(label)}</div></div>'
    return (
        f'<div class="fact"><div class="k">{html_escape(label)}</div>'
        f'<div class="v">{html_escape(value)}</div></div>'
    )


def _match_investigation(
    analysis: TestAnalysis,
    agent_run: AgentRun | None,
) -> Investigation | None:
    if agent_run is None:
        return None
    match = next(
        (item for item in agent_run.investigations if item.analysis_id == analysis.analysis_id),
        None,
    )
    if match is not None:
        return match
    return next(
        (item for item in agent_run.investigations if item.test_node_id == analysis.test.node_id),
        None,
    )


def _render_investigation(investigation: Investigation | None, agent_run: AgentRun | None) -> str:
    if agent_run is None:
        return ""
    if investigation is None:
        return (
            '<div class="investigation" data-testid="investigation-missing">'
            '<div class="fact"><div class="k">Investigation</div>'
            '<div class="v muted">No investigation trace was recorded.</div></div></div>'
        )
    flags = []
    if investigation.timed_out:
        flags.append("timed out")
    if investigation.hit_tool_cap:
        flags.append("hit tool cap")
    if investigation.used_template_fallback:
        flags.append("template fallback")
    flag_text = f" ({', '.join(flags)})" if flags else ""
    header = (
        f'<div class="fact"><div class="k">Investigation</div>'
        f'<div class="v">{html_escape(investigation.turns)} turn'
        f"{'' if investigation.turns == 1 else 's'}"
        f"{html_escape(flag_text)}</div></div>"
    )
    if not investigation.tool_calls:
        return (
            f'<div class="investigation" data-testid="investigation">{header}'
            '<p class="muted">No tools were invoked.</p></div>'
        )
    items = []
    for call in investigation.tool_calls:
        status = "ok" if call.ok else "rejected"
        arguments = json.dumps(call.arguments, sort_keys=True)
        items.append(
            f'<li data-tool-name="{html_escape(call.name)}" data-tool-ok="{html_escape(call.ok)}">'
            f"<strong>{html_escape(call.name)}</strong> {html_escape(status)} "
            f"<code>{html_escape(arguments)}</code>"
            f'<div class="trace">{html_escape(call.preview)}</div></li>'
        )
    return (
        f'<div class="investigation" data-testid="investigation">{header}'
        f"<ol>{''.join(items)}</ol></div>"
    )


def _match_action(
    analysis: TestAnalysis,
    agent_run: AgentRun | None,
) -> tuple[ActionPlan | None, ActionResult | None]:
    if agent_run is None:
        return None, None
    plan = next((item for item in agent_run.plans if item.analysis_id == analysis.analysis_id), None)
    if plan is None:
        plan = next((item for item in agent_run.plans if item.test_node_id == analysis.test.node_id), None)
    if plan is None:
        return None, None
    result = next((item for item in agent_run.results if item.action_id == plan.action_id), None)
    return plan, result


def _render_action_links(plan: ActionPlan | None, result: ActionResult | None) -> str:
    if plan is None:
        return '<p class="muted" data-testid="actions-missing">No GitHub or Linear action was supplied.</p>'
    channel = _KIND_CHANNEL.get(plan.kind)
    if channel is None or result is None:
        return '<p class="muted" data-testid="actions-missing">No GitHub or Linear action was supplied.</p>'
    created = result.status in {ActionStatus.CREATED, ActionStatus.ALREADY_EXISTS}
    href = _safe_http_url(result.url) if created else None
    if not href:
        return (
            f'<p class="muted" data-action-id="{html_escape(plan.action_id)}">'
            f"{html_escape(channel)} action {html_escape(result.status.value)} — no public link.</p>"
        )
    label = f"Created {channel} action"
    if result.status is ActionStatus.ALREADY_EXISTS:
        label = f"Existing {channel} action"
    return (
        f'<div class="actions"><a data-action-id="{html_escape(plan.action_id)}" '
        f'data-channel="{html_escape(channel)}" href="{html_escape(href)}">'
        f"{html_escape(label)}</a></div>"
    )


def _safe_http_url(url: str | None) -> str | None:
    if not url:
        return None
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return url
