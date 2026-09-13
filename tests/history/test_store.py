from datetime import datetime, timedelta, timezone
from pathlib import Path

from tests.conftest import make_analysis

from syft.history.store import HistoryStore
from syft.history.summary import (
    consecutive_failures,
    flaky_occurrence_rate,
    historical_pass_rate,
    recurring_flaky_tests,
    trend_summary,
)
from syft.models.analysis import (
    Classification,
    ClassificationSummary,
    WorkflowAnalysis,
)


def _workflow(
    *,
    repository: str = "owner/repo",
    run_id: int,
    created_at: datetime,
    commit: str = "sha-a",
    branch: str = "main",
    analyses: list,
) -> WorkflowAnalysis:
    return WorkflowAnalysis(
        workflow_analysis_id=f"wa_{run_id}_{commit}",
        created_at=created_at,
        repository=repository,
        branch=branch,
        workflow_run_id=run_id,
        workflow_name="CI",
        current_commit=commit,
        last_green_commit="green",
        junit_artifact="pytest-junit",
        failed_tests=[item.test.node_id for item in analyses],
        summary=ClassificationSummary(
            flaky=sum(item.classification is Classification.FLAKY for item in analyses),
            regression=sum(item.classification is Classification.REGRESSION for item in analyses),
            escalate=sum(item.classification is Classification.ESCALATE for item in analyses),
            total=len(analyses),
        ),
        analyses=analyses,
    )


def test_empty_history_has_zero_rates_and_explicit_trend(tmp_path: Path) -> None:
    with HistoryStore(tmp_path / "history.sqlite") as store:
        records = store.recent_history("owner/repo", "tests/test_a.py::test_a")
        assert records == []
        assert historical_pass_rate(records) == 0.0
        assert flaky_occurrence_rate(records) == 0.0
        assert consecutive_failures(records) == 0
        assert recurring_flaky_tests(store, "owner/repo") == []
        summary = trend_summary(store, "owner/repo")
        assert summary.records == 0
        assert summary.tests == 0
        assert "No recorded test failures." in summary.text
        assert "`owner/repo`" in summary.text


def test_duplicate_workflow_ingestion_does_not_duplicate_records(
    workflow_analysis: WorkflowAnalysis,
    tmp_path: Path,
) -> None:
    with HistoryStore(tmp_path / "history.sqlite") as store:
        first = store.record_workflow(workflow_analysis)
        second = store.record_workflow(workflow_analysis)
        assert first == 3
        assert second == 0
        flaky = store.recent_history("owner/repo", "tests/test_flaky.py::test_flaky")
        assert len(flaky) == 1
        assert flaky[0].classification is Classification.FLAKY
        assert flaky[0].confidence == 0.91
        assert flaky[0].rerun_passed == 2
        assert flaky[0].rerun_failed == 3
        assert flaky[0].commit == "current-sha"
        assert flaky[0].branch == "fixture"
        assert flaky[0].workflow_run_id == 42


def test_history_is_isolated_per_repository(tmp_path: Path) -> None:
    start = datetime(2026, 2, 1, tzinfo=timezone.utc)
    node = "tests/test_flaky.py::test_flaky"
    left = _workflow(
        repository="acme/one",
        run_id=1,
        created_at=start,
        analyses=[make_analysis(node, Classification.FLAKY, 1, 4)],
    )
    right = _workflow(
        repository="acme/two",
        run_id=1,
        created_at=start,
        analyses=[make_analysis(node, Classification.REGRESSION, 0, 5)],
    )
    with HistoryStore(tmp_path / "history.sqlite") as store:
        assert store.record_workflow(left) == 1
        assert store.record_workflow(right) == 1
        one = store.recent_history("acme/one", node)
        two = store.recent_history("acme/two", node)
        assert len(one) == 1
        assert len(two) == 1
        assert one[0].classification is Classification.FLAKY
        assert two[0].classification is Classification.REGRESSION
        assert recurring_flaky_tests(store, "acme/one") == []
        assert recurring_flaky_tests(store, "acme/two") == []


def test_recurring_flaky_tests_require_repeated_flaky_labels(tmp_path: Path) -> None:
    start = datetime(2026, 3, 1, tzinfo=timezone.utc)
    flaky_node = "tests/test_flaky.py::test_flaky"
    other_node = "tests/test_checkout.py::test_checkout"
    with HistoryStore(tmp_path / "history.sqlite") as store:
        store.record_workflow(
            _workflow(
                run_id=10,
                created_at=start,
                analyses=[
                    make_analysis(flaky_node, Classification.FLAKY, 2, 3),
                    make_analysis(other_node, Classification.REGRESSION, 0, 5),
                ],
            )
        )
        store.record_workflow(
            _workflow(
                run_id=11,
                created_at=start + timedelta(hours=1),
                commit="sha-b",
                analyses=[make_analysis(flaky_node, Classification.FLAKY, 1, 4)],
            )
        )
        store.record_workflow(
            _workflow(
                run_id=12,
                created_at=start + timedelta(hours=2),
                commit="sha-c",
                analyses=[make_analysis(other_node, Classification.FLAKY, 3, 2)],
            )
        )
        recurring = recurring_flaky_tests(store, "owner/repo", minimum=2)
        assert [item.test_node_id for item in recurring] == [flaky_node]
        assert recurring[0].flaky_count == 2
        assert recurring[0].total == 2
        assert recurring[0].flaky_occurrence_rate == 1.0
        once = recurring_flaky_tests(store, "owner/repo", minimum=1)
        assert {item.test_node_id for item in once} == {flaky_node, other_node}


def test_pass_rate_consecutive_failures_and_trend_text(tmp_path: Path) -> None:
    start = datetime(2026, 4, 1, tzinfo=timezone.utc)
    node = "tests/test_checkout.py::test_checkout"
    flaky = "tests/test_flaky.py::test_flaky"
    with HistoryStore(tmp_path / "history.sqlite") as store:
        store.record_workflow(
            _workflow(
                run_id=20,
                created_at=start,
                analyses=[
                    make_analysis(node, Classification.FLAKY, 2, 2),
                    make_analysis(flaky, Classification.FLAKY, 1, 4),
                ],
            )
        )
        store.record_workflow(
            _workflow(
                run_id=21,
                created_at=start + timedelta(hours=1),
                commit="sha-b",
                analyses=[
                    make_analysis(node, Classification.REGRESSION, 0, 5),
                    make_analysis(flaky, Classification.FLAKY, 2, 3),
                ],
            )
        )
        store.record_workflow(
            _workflow(
                run_id=22,
                created_at=start + timedelta(hours=2),
                commit="sha-c",
                analyses=[make_analysis(node, Classification.ESCALATE, 0, 5)],
            )
        )
        checkout = store.recent_history("owner/repo", node)
        assert [item.workflow_run_id for item in checkout] == [22, 21, 20]
        assert historical_pass_rate(checkout) == 2 / 14
        assert consecutive_failures(checkout) == 2
        assert flaky_occurrence_rate(checkout) == 1 / 3
        flaky_records = store.recent_history("owner/repo", flaky)
        assert historical_pass_rate(flaky_records) == 3 / 10
        assert consecutive_failures(flaky_records) == 0
        assert flaky_occurrence_rate(flaky_records) == 1.0
        summary = trend_summary(store, "owner/repo")
        assert summary.records == 5
        assert summary.tests == 2
        assert summary.workflow_runs == 3
        assert "Recurring flaky tests:" in summary.text
        assert "`test_flaky`" in summary.text
        assert "2/2 FLAKY" in summary.text
        assert "rerun pass rate 14%" in summary.text
        assert "2 consecutive all-fail runs" in summary.text
        assert "*Syft history*" in summary.text
