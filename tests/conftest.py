from datetime import datetime, timezone

import pytest

from syft.models.analysis import (
    Classification,
    ClassificationSummary,
    CodeEvidence,
    CommitEvidence,
    RerunAttempt,
    RerunOutcome,
    RerunSummary,
    TestAnalysis as AnalysisModel,
    TestIdentity as IdentityModel,
    TraceEvidence,
    WorkflowAnalysis,
)


def make_analysis(
    node_id: str,
    classification: Classification,
    passed: int,
    failed: int,
) -> AnalysisModel:
    attempts = [
        RerunAttempt(
            attempt=index + 1,
            outcome=RerunOutcome.PASSED if index < passed else RerunOutcome.FAILED,
            duration_seconds=0.1,
            exit_code=0 if index < passed else 1,
        )
        for index in range(passed + failed)
    ]
    changed = classification is Classification.REGRESSION
    return AnalysisModel(
        analysis_id=f"ta_{classification.value.lower()}",
        test=IdentityModel.from_node_id(node_id),
        classification=classification,
        confidence={
            Classification.FLAKY: 0.91,
            Classification.REGRESSION: 0.97,
            Classification.ESCALATE: 0.70,
        }[classification],
        reason=f"Deterministic {classification.value} evidence.",
        rerun_summary=RerunSummary.from_attempts(attempts),
        reruns=attempts,
        code_evidence=CodeEvidence(
            related_code_changed=changed,
            changed_files=["app/checkout.py"] if changed else [],
            related_files=["app/checkout.py"] if changed else [],
            matching_related_files=["app/checkout.py"] if changed else [],
        ),
        commit_evidence=CommitEvidence(
            current_commit="current-sha",
            last_green_commit="green-sha",
            failed_on_previous_commit=False if changed else None,
        ),
        trace=TraceEvidence(source="pytest_rerun", failure_type="AssertionError", message="fixture failed"),
    )


@pytest.fixture
def workflow_analysis() -> WorkflowAnalysis:
    analyses = [
        make_analysis("tests/test_flaky.py::test_flaky", Classification.FLAKY, 2, 3),
        make_analysis("tests/test_checkout.py::test_checkout", Classification.REGRESSION, 0, 5),
        make_analysis("tests/test_ambiguous.py::test_ambiguous", Classification.ESCALATE, 0, 5),
    ]
    return WorkflowAnalysis(
        workflow_analysis_id="wa_42_current",
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        repository="owner/repo",
        branch="fixture",
        workflow_run_id=42,
        workflow_name="CI",
        current_commit="current-sha",
        last_green_commit="green-sha",
        junit_artifact="pytest-junit",
        failed_tests=[item.test.node_id for item in analyses],
        summary=ClassificationSummary(flaky=1, regression=1, escalate=1, total=3),
        analyses=analyses,
    )

