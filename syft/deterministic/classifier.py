"""Pure, explainable classification rules."""

from syft.models.analysis import (
    Classification,
    ClassificationInput,
    RerunOutcome,
)


def classify_failure(data: ClassificationInput) -> tuple[Classification, float, str]:
    """Classify a failure without probabilistic or LLM-based decisions."""

    total = len(data.reruns)
    if total == 0:
        return Classification.ESCALATE, 0.2, "No isolated rerun evidence is available."

    passed = sum(item.outcome is RerunOutcome.PASSED for item in data.reruns)
    failed = total - passed
    timed_out = sum(item.outcome is RerunOutcome.TIMED_OUT for item in data.reruns)

    if timed_out:
        return (
            Classification.ESCALATE,
            0.55,
            f"Evidence is incomplete: {timed_out} of {total} isolated reruns timed out.",
        )

    if 0 < passed < total and data.related_code_changed is False:
        balance = min(passed, failed) / total
        confidence = round(min(0.95, 0.75 + (0.4 * balance)), 2)
        return (
            Classification.FLAKY,
            confidence,
            f"The test passed on {passed} of {total} isolated reruns and no directly related implementation file changed.",
        )

    if failed == total and data.related_code_changed is True:
        if data.failed_on_previous_commit is True:
            return (
                Classification.ESCALATE,
                0.8,
                "The test failed on every isolated rerun and also failed at the last green commit, so the regression signal conflicts with prior behavior.",
            )
        confidence = 0.97 if data.failed_on_previous_commit is False else 0.93
        prior = " and passed at the last green commit" if data.failed_on_previous_commit is False else ""
        return (
            Classification.REGRESSION,
            confidence,
            f"The test failed on all {total} isolated reruns{prior}, and a directly related implementation file changed since the last green commit.",
        )

    if data.related_code_changed is None:
        return (
            Classification.ESCALATE,
            0.4,
            "Related-code evidence is unavailable, so the failure cannot be classified safely.",
        )

    if passed == total:
        return (
            Classification.ESCALATE,
            0.65,
            f"The test passed on all {total} isolated reruns; there is no observed mixed behavior or persistent failure.",
        )

    if 0 < passed < total:
        return (
            Classification.ESCALATE,
            0.7,
            f"Signals conflict: the test passed on {passed} of {total} isolated reruns, but related implementation code changed.",
        )

    return (
        Classification.ESCALATE,
        0.7,
        f"The test failed on all {total} isolated reruns, but no directly related implementation file changed.",
    )

