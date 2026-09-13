"""Run a hand-labeled boundary benchmark against the deterministic classifier."""

from __future__ import annotations

import argparse
from pathlib import Path

from pydantic import BaseModel, ConfigDict, TypeAdapter

from syft.deterministic.classifier import classify_failure
from syft.eval.ground_truth import GroundTruthCase
from syft.eval.metrics import EvalMetrics, evaluate_predictions, format_report
from syft.models.analysis import Classification, ClassificationInput, RerunAttempt, RerunOutcome


class BenchmarkCase(BaseModel):
    """One intentionally labeled classifier boundary condition."""

    model_config = ConfigDict(extra="forbid")

    test: str
    outcomes: list[RerunOutcome]
    related_code_changed: bool | None
    failed_on_previous_commit: bool | None = None
    expected: Classification


def load_benchmark(path: Path) -> list[BenchmarkCase]:
    return TypeAdapter(list[BenchmarkCase]).validate_json(path.read_text(encoding="utf-8"))


def evaluate_benchmark(cases: list[BenchmarkCase]) -> EvalMetrics:
    ground_truth: list[GroundTruthCase] = []
    predictions: dict[str, Classification] = {}
    for case in cases:
        reruns = [
            RerunAttempt(
                attempt=index,
                outcome=outcome,
                duration_seconds=0.01,
                exit_code=0 if outcome is RerunOutcome.PASSED else 1,
            )
            for index, outcome in enumerate(case.outcomes, start=1)
        ]
        predicted, _, _ = classify_failure(
            ClassificationInput(
                reruns=reruns,
                related_code_changed=case.related_code_changed,
                failed_on_previous_commit=case.failed_on_previous_commit,
            )
        )
        ground_truth.append(GroundTruthCase(test=case.test, expected=case.expected))
        predictions[case.test] = predicted
    return evaluate_predictions(ground_truth, predictions)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate deterministic classifier boundaries")
    parser.add_argument("--input", required=True, type=Path)
    arguments = parser.parse_args(argv)
    metrics = evaluate_benchmark(load_benchmark(arguments.input))
    print(format_report(metrics))
    return int(metrics.correct != metrics.total or metrics.regression_false_negatives != 0)


if __name__ == "__main__":
    raise SystemExit(main())
