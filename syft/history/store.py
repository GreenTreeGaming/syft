"""SQLite persistence for workflow test history."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from syft.history.models import HistoryRecord
from syft.models.analysis import Classification, WorkflowAnalysis

if TYPE_CHECKING:
    from syft.agent.models import Investigation

_SCHEMA = """
CREATE TABLE IF NOT EXISTS test_history (
    repository TEXT NOT NULL,
    workflow_run_id INTEGER NOT NULL,
    test_node_id TEXT NOT NULL,
    classification TEXT NOT NULL,
    confidence REAL NOT NULL,
    rerun_passed INTEGER NOT NULL,
    rerun_failed INTEGER NOT NULL,
    "commit" TEXT NOT NULL,
    branch TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    PRIMARY KEY (repository, workflow_run_id, test_node_id)
);
CREATE INDEX IF NOT EXISTS idx_test_history_lookup
    ON test_history (repository, test_node_id, recorded_at DESC, workflow_run_id DESC);
CREATE TABLE IF NOT EXISTS investigations (
    repository TEXT NOT NULL,
    workflow_run_id INTEGER NOT NULL,
    test_node_id TEXT NOT NULL,
    analysis_id TEXT NOT NULL,
    turns INTEGER NOT NULL,
    timed_out INTEGER NOT NULL,
    hit_tool_cap INTEGER NOT NULL,
    used_template_fallback INTEGER NOT NULL,
    calls_json TEXT NOT NULL,
    PRIMARY KEY (repository, workflow_run_id, test_node_id)
);
"""

_INSERT = """
INSERT OR IGNORE INTO test_history (
    repository, workflow_run_id, test_node_id, classification, confidence,
    rerun_passed, rerun_failed, "commit", branch, recorded_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

_SELECT_RECENT = """
SELECT repository, workflow_run_id, test_node_id, classification, confidence,
       rerun_passed, rerun_failed, "commit", branch, recorded_at
FROM test_history
WHERE repository = ? AND test_node_id = ?
ORDER BY recorded_at DESC, workflow_run_id DESC
LIMIT ?
"""

_SELECT_REPO = """
SELECT repository, workflow_run_id, test_node_id, classification, confidence,
       rerun_passed, rerun_failed, "commit", branch, recorded_at
FROM test_history
WHERE repository = ?
ORDER BY test_node_id ASC, recorded_at DESC, workflow_run_id DESC
"""


class HistoryStore:
    """Caller-provided SQLite file. Duplicate workflow ingestion is a no-op."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path)
        self._connection.row_factory = sqlite3.Row
        self._connection.executescript(_SCHEMA)
        self._connection.commit()

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "HistoryStore":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def record_workflow(self, workflow: WorkflowAnalysis) -> int:
        """Persist every analysis in the workflow. Returns newly inserted rows."""

        recorded_at = _as_utc(workflow.created_at).isoformat()
        rows = [
            (
                workflow.repository,
                workflow.workflow_run_id,
                analysis.test.node_id,
                analysis.classification.value,
                analysis.confidence,
                analysis.rerun_summary.passed,
                analysis.rerun_summary.failed,
                workflow.current_commit,
                workflow.branch,
                recorded_at,
            )
            for analysis in workflow.analyses
        ]
        if not rows:
            return 0
        before = self._connection.total_changes
        self._connection.executemany(_INSERT, rows)
        self._connection.commit()
        return self._connection.total_changes - before

    def recent_history(self, repository: str, test_node_id: str, *, limit: int = 20) -> list[HistoryRecord]:
        if limit < 1:
            raise ValueError("limit must be >= 1")
        cursor = self._connection.execute(_SELECT_RECENT, (repository, test_node_id, limit))
        return [_row_to_record(row) for row in cursor.fetchall()]

    def repository_history(self, repository: str) -> list[HistoryRecord]:
        cursor = self._connection.execute(_SELECT_REPO, (repository,))
        return [_row_to_record(row) for row in cursor.fetchall()]

    def record_investigations(
        self,
        workflow: WorkflowAnalysis,
        investigations: list[Investigation],
    ) -> None:
        rows = [
            (
                workflow.repository,
                workflow.workflow_run_id,
                item.test_node_id,
                item.analysis_id,
                item.turns,
                int(item.timed_out),
                int(item.hit_tool_cap),
                int(item.used_template_fallback),
                json.dumps([call.model_dump() for call in item.tool_calls]),
            )
            for item in investigations
        ]
        if not rows:
            return
        self._connection.executemany(
            """
            INSERT OR REPLACE INTO investigations (
                repository, workflow_run_id, test_node_id, analysis_id, turns,
                timed_out, hit_tool_cap, used_template_fallback, calls_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        self._connection.commit()

    def load_investigations(self, repository: str, workflow_run_id: int) -> list[Investigation]:
        from syft.agent.models import Investigation

        cursor = self._connection.execute(
            """
            SELECT analysis_id, test_node_id, workflow_run_id, turns, timed_out,
                   hit_tool_cap, used_template_fallback, calls_json
            FROM investigations
            WHERE repository = ? AND workflow_run_id = ?
            """,
            (repository, workflow_run_id),
        )
        results: list[Investigation] = []
        for row in cursor.fetchall():
            results.append(
                Investigation(
                    analysis_id=row["analysis_id"],
                    test_node_id=row["test_node_id"],
                    workflow_run_id=int(row["workflow_run_id"]),
                    turns=int(row["turns"]),
                    tool_calls=json.loads(row["calls_json"]),
                    timed_out=bool(row["timed_out"]),
                    hit_tool_cap=bool(row["hit_tool_cap"]),
                    used_template_fallback=bool(row["used_template_fallback"]),
                )
            )
        return results


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _row_to_record(row: sqlite3.Row) -> HistoryRecord:
    return HistoryRecord(
        repository=row["repository"],
        workflow_run_id=int(row["workflow_run_id"]),
        test_node_id=row["test_node_id"],
        classification=Classification(row["classification"]),
        confidence=float(row["confidence"]),
        rerun_passed=int(row["rerun_passed"]),
        rerun_failed=int(row["rerun_failed"]),
        commit=row["commit"],
        branch=row["branch"],
        recorded_at=datetime.fromisoformat(row["recorded_at"]),
    )
