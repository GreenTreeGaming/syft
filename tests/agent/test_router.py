from syft.agent.explainer import TemplateExplainer
from syft.agent.models import ActionKind, Explanation
from syft.agent.router import build_action_plans
from syft.models.analysis import WorkflowAnalysis


def test_routes_each_immutable_classification(workflow_analysis: WorkflowAnalysis) -> None:
    plans = build_action_plans(workflow_analysis, TemplateExplainer())
    assert [plan.kind for plan in plans] == [
        ActionKind.QUARANTINE_PR,
        ActionKind.REGRESSION_TICKET,
        ActionKind.TRIAGE_TICKET,
    ]
    assert [plan.classification for plan in plans] == [
        item.classification for item in workflow_analysis.analyses
    ]


def test_explanation_schema_cannot_return_classification() -> None:
    assert "classification" not in Explanation.model_fields
    assert "confidence" not in Explanation.model_fields


def test_action_ids_are_stable_when_analysis_uuid_changes(workflow_analysis: WorkflowAnalysis) -> None:
    first = build_action_plans(workflow_analysis, TemplateExplainer())
    changed = workflow_analysis.model_copy(deep=True)
    changed.analyses[0].analysis_id = "ta_a-new-random-id"
    second = build_action_plans(changed, TemplateExplainer())
    assert [item.action_id for item in first] == [item.action_id for item in second]

