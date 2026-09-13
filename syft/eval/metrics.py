"""Safety-oriented classifier evaluation metrics."""

from pydantic import BaseModel, ConfigDict, Field

from syft.eval.ground_truth import GroundTruthCase
from syft.models.analysis import Classification


class EvalMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total: int = Field(ge=0)
    correct: int = Field(ge=0)
    accuracy: float = Field(ge=0.0, le=1.0)
    confusion_matrix: dict[str, dict[str, int]]
    regression_false_negatives: int = Field(ge=0)
    regression_as_flaky: int = Field(ge=0)


def evaluate_predictions(
    cases: list[GroundTruthCase],
    predictions: dict[str, Classification],
) -> EvalMetrics:
    labels = [item.value for item in Classification]
    matrix = {expected: {predicted: 0 for predicted in labels} for expected in labels}
    correct = 0
    regression_false_negatives = 0
    regression_as_flaky = 0

    for case in cases:
        if case.test not in predictions:
            raise ValueError(f"Missing prediction for {case.test}")
        predicted = predictions[case.test]
        matrix[case.expected.value][predicted.value] += 1
        correct += predicted is case.expected
        if case.expected is Classification.REGRESSION and predicted is not Classification.REGRESSION:
            regression_false_negatives += 1
        if case.expected is Classification.REGRESSION and predicted is Classification.FLAKY:
            regression_as_flaky += 1

    total = len(cases)
    return EvalMetrics(
        total=total,
        correct=correct,
        accuracy=(correct / total) if total else 0.0,
        confusion_matrix=matrix,
        regression_false_negatives=regression_false_negatives,
        regression_as_flaky=regression_as_flaky,
    )


def format_report(metrics: EvalMetrics) -> str:
    lines = [
        f"Total: {metrics.total}",
        f"Correct: {metrics.correct}",
        f"Accuracy: {metrics.accuracy:.1%}",
        f"Regression false negatives: {metrics.regression_false_negatives}",
        f"REGRESSION -> FLAKY: {metrics.regression_as_flaky}",
        "Confusion matrix:",
    ]
    for expected, row in metrics.confusion_matrix.items():
        values = ", ".join(f"{predicted}={count}" for predicted, count in row.items())
        lines.append(f"  {expected}: {values}")
    return "\n".join(lines)

