from syft.eval.ground_truth import GroundTruthCase
from syft.eval.metrics import evaluate_predictions
from syft.models.analysis import Classification


def test_tracks_regression_as_flaky_separately() -> None:
    cases = [
        GroundTruthCase(test="a", expected=Classification.REGRESSION),
        GroundTruthCase(test="b", expected=Classification.FLAKY),
    ]
    metrics = evaluate_predictions(
        cases,
        {"a": Classification.FLAKY, "b": Classification.FLAKY},
    )
    assert metrics.accuracy == 0.5
    assert metrics.regression_false_negatives == 1
    assert metrics.regression_as_flaky == 1
    assert metrics.confusion_matrix["REGRESSION"]["FLAKY"] == 1

