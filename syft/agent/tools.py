"""Read-only investigation tools for the explanation agent loop."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

from syft.history.store import HistoryStore
from syft.models.analysis import TestAnalysis

GIT_TIMEOUT_SECONDS = 10
OUTPUT_LIMIT = 6000

TOOL_SCHEMAS = [
    {
        "type": "function",
        "name": "read_file",
        "description": "Read an allowlisted source file at the failing commit.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "start_line": {"type": "integer", "minimum": 1},
                "end_line": {"type": "integer", "minimum": 1},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "type": "function",
        "name": "git_blame",
        "description": "Blame an allowlisted file line range at the failing commit.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "start_line": {"type": "integer", "minimum": 1},
                "end_line": {"type": "integer", "minimum": 1},
            },
            "required": ["path", "start_line", "end_line"],
            "additionalProperties": False,
        },
    },
    {
        "type": "function",
        "name": "git_log",
        "description": "Show recent commits that touched an allowlisted file.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 10},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "type": "function",
        "name": "search_history",
        "description": "Look up prior Syft classifications for this same test.",
        "parameters": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
]


def allowed_paths(analysis: TestAnalysis) -> list[str]:
    paths: list[str] = [analysis.test.file]
    paths.extend(analysis.code_evidence.related_files)
    paths.extend(analysis.code_evidence.matching_related_files)
    unique: list[str] = []
    seen: set[str] = set()
    for raw in paths:
        posix = PurePosixPath(raw).as_posix()
        if posix in seen:
            continue
        seen.add(posix)
        unique.append(posix)
    return unique


def execute_tool(
    name: str,
    arguments: dict[str, Any],
    *,
    analysis: TestAnalysis,
    repo_path: Path | None,
    history_store: HistoryStore | None,
    repository: str | None,
) -> str:
    if name == "search_history":
        return _search_history(analysis, history_store, repository)
    if name not in {"read_file", "git_blame", "git_log"}:
        return f"Unknown tool: {name}"
    path = _allowed_path(arguments.get("path"), analysis)
    if path is None:
        return "Path is not allowlisted or is invalid."
    if repo_path is None:
        return "repository path not configured"
    commit = analysis.commit_evidence.current_commit
    if name == "read_file":
        return _read_file(repo_path, commit, path, arguments)
    if name == "git_blame":
        return _git_blame(repo_path, commit, path, arguments)
    return _git_log(repo_path, commit, path, arguments)


def _allowed_path(raw: object, analysis: TestAnalysis) -> str | None:
    if not isinstance(raw, str) or not raw:
        return None
    path = PurePosixPath(raw)
    if path.is_absolute() or ".." in path.parts:
        return None
    posix = path.as_posix()
    if posix not in allowed_paths(analysis):
        return None
    return posix


def _read_file(repo_path: Path, commit: str, path: str, arguments: dict[str, Any]) -> str:
    output = _git(repo_path, ["show", f"{commit}:{path}"])
    if output.startswith("git failed:"):
        return output
    start = arguments.get("start_line")
    end = arguments.get("end_line")
    if not isinstance(start, int) and start is not None:
        return "start_line must be an integer"
    if not isinstance(end, int) and end is not None:
        return "end_line must be an integer"
    if start is None and end is None:
        return _truncate(output)
    lines = output.splitlines(keepends=True)
    begin = (start or 1) - 1
    stop = end if isinstance(end, int) else len(lines)
    if begin < 0 or stop < begin:
        return "Invalid line range"
    return _truncate("".join(lines[begin:stop]))


def _git_blame(repo_path: Path, commit: str, path: str, arguments: dict[str, Any]) -> str:
    start = arguments.get("start_line")
    end = arguments.get("end_line")
    if not isinstance(start, int) or not isinstance(end, int):
        return "start_line and end_line must be integers"
    if start < 1 or end < start:
        return "Invalid line range"
    return _git(repo_path, ["blame", "-L", f"{start},{end}", commit, "--", path])


def _git_log(repo_path: Path, commit: str, path: str, arguments: dict[str, Any]) -> str:
    limit = arguments.get("limit", 5)
    if not isinstance(limit, int) or limit < 1:
        return "limit must be a positive integer"
    limit = min(limit, 10)
    return _git(repo_path, ["log", "-n", str(limit), "--oneline", commit, "--", path])


def _search_history(
    analysis: TestAnalysis,
    history_store: HistoryStore | None,
    repository: str | None,
) -> str:
    if history_store is None:
        return "history store not configured"
    repo = repository
    if analysis.ci_context is not None:
        repo = analysis.ci_context.repository
    if not repo:
        return "repository not configured"
    records = history_store.recent_history(repo, analysis.test.node_id, limit=10)
    if not records:
        return "No prior history for this test."
    payload = [
        {
            "workflow_run_id": item.workflow_run_id,
            "classification": item.classification.value,
            "rerun_passed": item.rerun_passed,
            "rerun_failed": item.rerun_failed,
            "commit": item.commit,
            "recorded_at": item.recorded_at.isoformat(),
        }
        for item in records
    ]
    return _truncate(json.dumps(payload))


def _git(repo_path: Path, args: list[str]) -> str:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=False,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return f"git failed: {error}"
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "unknown error").strip()
        return f"git failed: {detail[:500]}"
    return _truncate(completed.stdout)


def _truncate(text: str) -> str:
    if len(text) <= OUTPUT_LIMIT:
        return text
    return text[:OUTPUT_LIMIT] + "\n...[truncated]"
