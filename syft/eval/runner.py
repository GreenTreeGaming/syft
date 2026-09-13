"""Evaluate saved TestAnalysis traces against ground truth."""

from pathlib import Path

from syft.eval.ground_truth import load_ground_truth
from syft.eval.metrics import EvalMetrics, evaluate_predictions, format_report
from syft.models.analysis import Classification, TestAnalysis


def evaluate_trace_directory(ground_truth_path: Path, trace_directory: Path) -> EvalMetrics:
    cases = load_ground_truth(ground_truth_path)
    predictions: dict[str, Classification] = {}
    for trace_path in sorted(trace_directory.glob("*.json")):
        analysis = TestAnalysis.model_validate_json(trace_path.read_text(encoding="utf-8"))
        predictions[analysis.test.node_id] = analysis.classification
    return evaluate_predictions(cases, predictions)


def print_report(metrics: EvalMetrics) -> None:
    print(format_report(metrics))

