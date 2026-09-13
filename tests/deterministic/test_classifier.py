from syft.deterministic.classifier import classify_failure
from syft.models.analysis import Classification, ClassificationInput, RerunAttempt, RerunOutcome


def attempts(*outcomes: RerunOutcome) -> list[RerunAttempt]:
    return [
        RerunAttempt(attempt=index, outcome=outcome, duration_seconds=0.1, exit_code=0 if outcome is RerunOutcome.PASSED else 1, output="")
        for index, outcome in enumerate(outcomes, 1)
    ]


def classify(outcomes: list[RerunAttempt], changed: bool | None, previous: bool | None = None):
    return classify_failure(
        ClassificationInput(
            reruns=outcomes,
            related_code_changed=changed,
            failed_on_previous_commit=previous,
        )
    )


def test_mixed_reruns_without_related_change_are_flaky() -> None:
    result = classify(attempts(RerunOutcome.PASSED, RerunOutcome.FAILED), False)
    assert result[0] is Classification.FLAKY


def test_all_fail_with_related_change_is_regression() -> None:
    result = classify(attempts(*([RerunOutcome.FAILED] * 5)), True, False)
    assert result[0] is Classification.REGRESSION
    assert result[1] == 0.97


def test_mixed_reruns_with_related_change_escalate() -> None:
    result = classify(attempts(RerunOutcome.PASSED, RerunOutcome.FAILED), True)
    assert result[0] is Classification.ESCALATE


def test_all_fail_without_related_change_escalates() -> None:
    result = classify(attempts(*([RerunOutcome.FAILED] * 5)), False)
    assert result[0] is Classification.ESCALATE


def test_all_pass_escalates() -> None:
    result = classify(attempts(*([RerunOutcome.PASSED] * 5)), False)
    assert result[0] is Classification.ESCALATE


def test_timeout_escalates_even_with_code_change() -> None:
    result = classify(attempts(RerunOutcome.FAILED, RerunOutcome.TIMED_OUT), True)
    assert result[0] is Classification.ESCALATE


def test_missing_code_evidence_escalates() -> None:
    result = classify(attempts(*([RerunOutcome.FAILED] * 5)), None)
    assert result[0] is Classification.ESCALATE


def test_failure_at_previous_green_prevents_regression_label() -> None:
    result = classify(attempts(*([RerunOutcome.FAILED] * 5)), True, True)
    assert result[0] is Classification.ESCALATE


def test_no_reruns_escalates() -> None:
    result = classify([], False)
    assert result[0] is Classification.ESCALATE

