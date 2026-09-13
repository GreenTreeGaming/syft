"""Pure routing from immutable classification to external action plans."""

from __future__ import annotations

import hashlib

from syft.agent.explainer import Explainer
from syft.agent.models import ActionKind, ActionPlan, Explanation
from syft.models.analysis import Classification, TestAnalysis, WorkflowAnalysis


_ACTION_BY_CLASSIFICATION = {
    Classification.FLAKY: ActionKind.QUARANTINE_PR,
    Classification.REGRESSION: ActionKind.REGRESSION_TICKET,
    Classification.ESCALATE: ActionKind.TRIAGE_TICKET,
}


def build_action_plans(workflow: WorkflowAnalysis, explainer: Explainer) -> list[ActionPlan]:
    return [_build_plan(workflow, analysis, explainer) for analysis in workflow.analyses]


def _build_plan(
    workflow: WorkflowAnalysis,
    analysis: TestAnalysis,
    explainer: Explainer,
) -> ActionPlan:
    kind = _ACTION_BY_CLASSIFICATION[analysis.classification]
    explanation = explainer.explain(analysis)
    action_id = _stable_action_id(workflow.workflow_analysis_id, analysis.test.node_id, kind)
    title_prefix = {
        ActionKind.QUARANTINE_PR: "[Syft] Quarantine flaky test",
        ActionKind.REGRESSION_TICKET: "[Syft] Regression",
        ActionKind.TRIAGE_TICKET: "[Syft] Needs triage",
    }[kind]
    title = f"{title_prefix}: {analysis.test.name}"
    body = _markdown_body(workflow, analysis, explanation)
    return ActionPlan(
        action_id=action_id,
        analysis_id=analysis.analysis_id,
        classification=analysis.classification,
        kind=kind,
        test_node_id=analysis.test.node_id,
        test_file=analysis.test.file,
        title=title,
        body=body,
        explanation=explanation,
    )


def _stable_action_id(workflow_id: str, test_node_id: str, kind: ActionKind) -> str:
    digest = hashlib.sha256(f"{workflow_id}\0{test_node_id}\0{kind.value}".encode()).hexdigest()[:20]
    return f"act_{digest}"


def _markdown_body(workflow: WorkflowAnalysis, analysis: TestAnalysis, explanation: Explanation) -> str:
    details = explanation.model_dump()
    evidence = "\n".join(f"- {item}" for item in details["evidence"])
    changed = ", ".join(analysis.code_evidence.matching_related_files) or "None"
    return f"""## Syft deterministic triage

**Classification:** `{analysis.classification.value}`  
**Confidence:** `{analysis.confidence:.2f}`  
**Test:** `{analysis.test.node_id}`  
**Analysis ID:** `{analysis.analysis_id}`  
**Workflow analysis ID:** `{workflow.workflow_analysis_id}`

### Explanation

{details['summary']}

### Tentative hypothesis

{details['hypothesis']}

### Deterministic evidence

{evidence}
- Directly related changed files: {changed}
- Current commit: `{analysis.commit_evidence.current_commit}`
- Last green commit: `{analysis.commit_evidence.last_green_commit}`

### Recommended action

{details['recommended_action']}

---
The classification above was produced by deterministic rules. The LLM only generated the explanation.
<!-- syft-action-id: { _stable_action_id(workflow.workflow_analysis_id, analysis.test.node_id, _ACTION_BY_CLASSIFICATION[analysis.classification]) } -->
"""
