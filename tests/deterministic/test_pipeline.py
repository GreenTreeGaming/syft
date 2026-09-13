from pathlib import Path

from syft.deterministic.git_analysis import RelatedCodeResult
from syft.deterministic.pipeline import analyze_failed_test
from syft.models.analysis import Classification, RerunAttempt, RerunOutcome


def test_pipeline_builds_versioned_analysis(mocker, tmp_path: Path) -> None:
    reruns = [
        RerunAttempt(attempt=index, outcome=RerunOutcome.FAILED, duration_seconds=0.1, exit_code=1, output="tests/test_x.py:4: AssertionError: wrong")
        for index in range(1, 6)
    ]
    mocker.patch("syft.deterministic.pipeline.rerun_test", return_value=reruns)
    mocker.patch(
        "syft.deterministic.pipeline.analyze_related_code",
        return_value=RelatedCodeResult(
            changed_files=["app/x.py"],
            related_files=["app/x.py"],
            matching_related_files=["app/x.py"],
            related_code_changed=True,
        ),
    )
    mocker.patch("syft.deterministic.pipeline.failed_at_commit", return_value=False)

    analysis = analyze_failed_test(
        tmp_path,
        "tests/test_x.py::TestX::test_value",
        "current",
        "green",
    )

    assert analysis.analysis_id.startswith("ta_")
    assert analysis.schema_version == "1.0"
    assert analysis.classification is Classification.REGRESSION
    assert analysis.rerun_summary.failed == 5
    assert analysis.test.file == "tests/test_x.py"
    assert analysis.trace.failure_type == "AssertionError"


def test_trace_humanizes_pytest_equality_failure(mocker, tmp_path: Path) -> None:
    output = """E       AssertionError: assert Decimal('92.00') == Decimal('108.00')
tests/test_checkout.py:7: AssertionError"""
    mocker.patch(
        "syft.deterministic.pipeline.rerun_test",
        return_value=[
            RerunAttempt(
                attempt=1,
                outcome=RerunOutcome.FAILED,
                duration_seconds=0.1,
                exit_code=1,
                output=output,
            )
        ],
    )
    analysis = analyze_failed_test(
        tmp_path,
        "tests/test_checkout.py::test_checkout",
        "current",
        None,
    )
    assert analysis.trace.message == "Expected Decimal('108.00'), received Decimal('92.00')."


def test_missing_last_green_does_not_invent_code_evidence(mocker, tmp_path: Path) -> None:
    mocker.patch(
        "syft.deterministic.pipeline.rerun_test",
        return_value=[
            RerunAttempt(attempt=1, outcome=RerunOutcome.FAILED, duration_seconds=0.1, exit_code=1, output="failed")
        ],
    )
    related = mocker.patch("syft.deterministic.pipeline.analyze_related_code")
    analysis = analyze_failed_test(tmp_path, "tests/test_x.py::test_x", "current", None)
    assert analysis.classification is Classification.ESCALATE
    assert analysis.code_evidence.related_code_changed is None
    related.assert_not_called()
