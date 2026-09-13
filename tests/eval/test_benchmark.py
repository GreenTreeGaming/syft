from pathlib import Path

from syft.eval.benchmark import evaluate_benchmark, load_benchmark, main


BENCHMARK = Path(__file__).parents[2] / "eval" / "classifier_benchmark.json"


def test_benchmark_covers_safety_boundaries() -> None:
    cases = load_benchmark(BENCHMARK)
    metrics = evaluate_benchmark(cases)

    assert len(cases) == 15
    assert metrics.total == 15
    assert metrics.correct == 15
    assert metrics.accuracy == 1.0
    assert metrics.regression_false_negatives == 0
    assert metrics.regression_as_flaky == 0
    assert all(metrics.confusion_matrix[label][label] > 0 for label in metrics.confusion_matrix)


def test_benchmark_cli_reports_and_succeeds(capsys) -> None:
    assert main(["--input", str(BENCHMARK)]) == 0
    output = capsys.readouterr().out
    assert "Total: 15" in output
    assert "Accuracy: 100.0%" in output
    assert "Regression false negatives: 0" in output
