"""Derived rates and compact trend text from stored history."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence

from syft.history.models import (
    FlakyRecurrence,
    HistoryRecord,
    TestHistorySummary,
    TrendSummary,
    WorkflowHistorySummary,
)
from syft.history.store import HistoryStore
from syft.models.analysis import Classification, WorkflowAnalysis


def historical_pass_rate(records: Sequence[HistoryRecord]) -> float:
    """Rerun passes divided by pass+fail attempts across the records."""

    attempts = sum(item.rerun_passed + item.rerun_failed for item in records)
    if attempts == 0:
        return 0.0
    return sum(item.rerun_passed for item in records) / attempts


def flaky_occurrence_rate(records: Sequence[HistoryRecord]) -> float:
    """Share of stored observations classified as FLAKY."""

    if not records:
        return 0.0
    flaky = sum(item.classification is Classification.FLAKY for item in records)
    return flaky / len(records)


def consecutive_failures(records: Sequence[HistoryRecord]) -> int:
    """Newest-first streak of observations with zero rerun passes."""

    ordered = sorted(
        records,
        key=lambda item: (item.recorded_at, item.workflow_run_id),
        reverse=True,
    )
    streak = 0
    for item in ordered:
        if item.rerun_passed > 0:
            break
        streak += 1
    return streak


def recurring_flaky_tests(
    store: HistoryStore,
    repository: str,
    *,
    minimum: int = 2,
) -> list[FlakyRecurrence]:
    """Tests classified FLAKY at least `minimum` times in one repository."""

    if minimum < 1:
        raise ValueError("minimum must be >= 1")
    grouped: dict[str, list[HistoryRecord]] = defaultdict(list)
    for record in store.repository_history(repository):
        grouped[record.test_node_id].append(record)
    recurring: list[FlakyRecurrence] = []
    for node_id, items in grouped.items():
        flaky_count = sum(item.classification is Classification.FLAKY for item in items)
        if flaky_count < minimum:
            continue
        recurring.append(
            FlakyRecurrence(
                test_node_id=node_id,
                flaky_count=flaky_count,
                total=len(items),
                flaky_occurrence_rate=flaky_count / len(items),
            )
        )
    recurring.sort(key=lambda item: (-item.flaky_count, item.test_node_id))
    return recurring


def trend_summary(store: HistoryStore, repository: str, *, flaky_minimum: int = 2) -> TrendSummary:
    """Build a short Slack/HTML-ready history blurb for one repository."""

    records = store.repository_history(repository)
    recurring = recurring_flaky_tests(store, repository, minimum=flaky_minimum)
    tests = {item.test_node_id for item in records}
    runs = {item.workflow_run_id for item in records}
    lines = [f"*Syft history* — `{repository}`"]
    if not records:
        lines.append("No recorded test failures.")
        text = "\n".join(lines)
        return TrendSummary(
            repository=repository,
            records=0,
            tests=0,
            workflow_runs=0,
            recurring_flaky=[],
            text=text,
        )
    lines.append(
        f"{len(records)} recorded failures across {len(tests)} tests and {len(runs)} workflow runs."
    )
    if recurring:
        details = ", ".join(
            f"`{_short_name(item.test_node_id)}` ({item.flaky_count}/{item.total} FLAKY)"
            for item in recurring
        )
        lines.append(f"Recurring flaky tests: {details}")
    else:
        lines.append("No recurring flaky tests.")
    notable = _notable_tests(records)
    lines.extend(notable)
    return TrendSummary(
        repository=repository,
        records=len(records),
        tests=len(tests),
        workflow_runs=len(runs),
        recurring_flaky=recurring,
        text="\n".join(lines),
    )


def workflow_history_summary(
    store: HistoryStore,
    workflow: WorkflowAnalysis,
    *,
    limit: int = 20,
) -> WorkflowHistorySummary:
    """Build bounded historical context for the tests in one classified workflow."""

    if limit < 1:
        raise ValueError("history limit must be >= 1")
    repository_records = store.repository_history(workflow.repository)
    by_test: dict[str, TestHistorySummary] = {}
    for analysis in workflow.analyses:
        records = store.recent_history(
            workflow.repository,
            analysis.test.node_id,
            limit=limit,
        )
        flaky_count = sum(
            item.classification is Classification.FLAKY for item in records
        )
        by_test[analysis.test.node_id] = TestHistorySummary(
            test_node_id=analysis.test.node_id,
            observations=len(records),
            flaky_count=flaky_count,
            flaky_occurrence_rate=flaky_occurrence_rate(records),
            rerun_pass_rate=historical_pass_rate(records),
            consecutive_all_failures=consecutive_failures(records),
        )
    return WorkflowHistorySummary(
        repository=workflow.repository,
        records=len(repository_records),
        tests=len({item.test_node_id for item in repository_records}),
        workflow_runs=len({item.workflow_run_id for item in repository_records}),
        by_test=by_test,
    )


def _notable_tests(records: Sequence[HistoryRecord], *, limit: int = 3) -> list[str]:
    grouped: dict[str, list[HistoryRecord]] = defaultdict(list)
    for record in records:
        grouped[record.test_node_id].append(record)
    ranked = sorted(
        grouped.items(),
        key=lambda pair: (-consecutive_failures(pair[1]), -len(pair[1]), pair[0]),
    )
    lines: list[str] = []
    for node_id, items in ranked[:limit]:
        rate = historical_pass_rate(items)
        streak = consecutive_failures(items)
        lines.append(
            f"`{_short_name(node_id)}`: rerun pass rate {rate:.0%}, {streak} consecutive all-fail runs"
        )
    return lines


def _short_name(node_id: str) -> str:
    return node_id.rsplit("::", 1)[-1]
