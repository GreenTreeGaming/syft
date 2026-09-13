"""Read-only investigation tools for the explanation agent loop."""

from __future__ import annotations

import json
import re
import subprocess
import time
from pathlib import Path, PurePosixPath
from typing import Any

from syft.history.store import HistoryStore
from syft.models.analysis import TestAnalysis

GIT_TIMEOUT_SECONDS = 10
OUTPUT_LIMIT = 6000
SEARCH_RESULT_LIMIT = 20
QUERY_LIMIT = 200

_SEARCH_PATHSPECS = [
    ":(exclude).git",
    ":(exclude)**/.git/**",
    ":(exclude)**/__pycache__/**",
    ":(exclude)**/*.pyc",
    ":(exclude)**/.venv/**",
    ":(exclude)**/venv/**",
    ":(exclude)**/node_modules/**",
    ":(exclude)**/dist/**",
    ":(exclude)**/build/**",
    ":(exclude)**/*.egg-info/**",
    ":(exclude)**/.env",
    ":(exclude)**/.env.*",
    ":(exclude)**/*.pem",
    ":(exclude)**/*.key",
    ":(exclude)**/id_rsa",
    ":(exclude)**/credentials.json",
    ":(exclude)**/secrets.*",
]

_ERROR_PREFIXES = (
    "Path is not",
    "Unknown tool",
    "git failed:",
    "history store not configured",
    "repository not configured",
    "repository path not configured",
    "last-green commit not configured",
    "No rerun attempt",
    "attempt must",
    "query must",
    "Query is empty",
)

_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL|AUTHORIZATION)[A-Z0-9_]*)"
    r"\s*[=:]\s*\S+"
)
_BEARER = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._\-+=/]+")
_URL_CREDENTIALS = re.compile(r"(?i)(https?://)[^/\s:@]+:[^@\s/]+@")
_INSTALL = re.compile(
    r"(?im)^\s*(?:-\s+)?(?:run:\s*[>|]?\s*)?(pip(?:3)? install|poetry install|uv sync|uv pip install|"
    r"pip-sync|pipenv install).+$"
)
_PYTHON_VERSION = re.compile(r"(?i)python-version:\s*['\"]?([0-9][0-9.]*)")
_RUNS_ON = re.compile(r"(?im)^\s*runs-on:\s*[\[{]?\s*['\"]?([A-Za-z0-9._\-]+)")

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
        "name": "read_previous_file",
        "description": "Read an allowlisted source file at the last-green commit.",
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
        "name": "git_diff",
        "description": "Show the exact change to an allowlisted file between last-green and the failing commit.",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
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
        "name": "search_code",
        "description": "Fixed-string search of the failing commit. Returns at most 20 matches.",
        "parameters": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
            "additionalProperties": False,
        },
    },
    {
        "type": "function",
        "name": "get_rerun_output",
        "description": "Return sanitized output for one isolated rerun attempt.",
        "parameters": {
            "type": "object",
            "properties": {"attempt": {"type": "integer", "minimum": 1}},
            "required": ["attempt"],
            "additionalProperties": False,
        },
    },
    {
        "type": "function",
        "name": "inspect_ci_environment",
        "description": "Return bounded CI configuration. Environment variable names only, never values.",
        "parameters": {
            "type": "object",
            "properties": {},
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


def tool_ok(output: str) -> bool:
    return not output.startswith(_ERROR_PREFIXES)


def execute_tool(
    name: str,
    arguments: dict[str, Any],
    *,
    analysis: TestAnalysis,
    repo_path: Path | None,
    history_store: HistoryStore | None,
    repository: str | None,
    timeout_seconds: float | None = None,
) -> str:
    git_timeout = _git_timeout(timeout_seconds)
    if name == "search_history":
        return _search_history(analysis, history_store, repository)
    if name == "get_rerun_output":
        return _get_rerun_output(analysis, arguments)
    if name == "inspect_ci_environment":
        return _inspect_ci_environment(analysis, repo_path, repository, timeout_seconds)
    if name == "search_code":
        return _search_code(analysis, repo_path, arguments, git_timeout)
    if name not in {"read_file", "read_previous_file", "git_diff", "git_blame", "git_log"}:
        return f"Unknown tool: {name}"
    path = _allowed_path(arguments.get("path"), analysis)
    if path is None:
        return "Path is not allowlisted or is invalid."
    if repo_path is None:
        return "repository path not configured"
    current = analysis.commit_evidence.current_commit
    previous = analysis.commit_evidence.last_green_commit
    if name == "read_file":
        return _read_file(repo_path, current, path, arguments, git_timeout)
    if name == "read_previous_file":
        if not previous:
            return "last-green commit not configured"
        return _read_file(repo_path, previous, path, arguments, git_timeout)
    if name == "git_diff":
        if not previous:
            return "last-green commit not configured"
        return _git(
            repo_path,
            ["diff", "--no-color", "-U3", previous, current, "--", path],
            timeout_seconds=git_timeout,
        )
    if name == "git_blame":
        return _git_blame(repo_path, current, path, arguments, git_timeout)
    return _git_log(repo_path, current, path, arguments, git_timeout)


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


def _read_file(
    repo_path: Path,
    commit: str,
    path: str,
    arguments: dict[str, Any],
    timeout_seconds: float,
) -> str:
    output = _git(repo_path, ["show", f"{commit}:{path}"], timeout_seconds=timeout_seconds)
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


def _git_blame(
    repo_path: Path,
    commit: str,
    path: str,
    arguments: dict[str, Any],
    timeout_seconds: float,
) -> str:
    start = arguments.get("start_line")
    end = arguments.get("end_line")
    if not isinstance(start, int) or not isinstance(end, int):
        return "start_line and end_line must be integers"
    if start < 1 or end < start:
        return "Invalid line range"
    return _git(
        repo_path,
        ["blame", "-L", f"{start},{end}", commit, "--", path],
        timeout_seconds=timeout_seconds,
    )


def _git_log(
    repo_path: Path,
    commit: str,
    path: str,
    arguments: dict[str, Any],
    timeout_seconds: float,
) -> str:
    limit = arguments.get("limit", 5)
    if not isinstance(limit, int) or limit < 1:
        return "limit must be a positive integer"
    limit = min(limit, 10)
    return _git(
        repo_path,
        ["log", "-n", str(limit), "--oneline", commit, "--", path],
        timeout_seconds=timeout_seconds,
    )


def _search_code(
    analysis: TestAnalysis,
    repo_path: Path | None,
    arguments: dict[str, Any],
    timeout_seconds: float,
) -> str:
    query = arguments.get("query")
    if not isinstance(query, str):
        return "query must be a string"
    query = query.strip()
    if not query:
        return "Query is empty."
    if len(query) > QUERY_LIMIT:
        return f"query must be at most {QUERY_LIMIT} characters"
    if repo_path is None:
        return "repository path not configured"
    commit = analysis.commit_evidence.current_commit
    completed = _run_git(
        repo_path,
        ["grep", "-n", "-F", "-I", "-e", query, commit, "--", *_SEARCH_PATHSPECS],
        timeout_seconds=timeout_seconds,
    )
    if completed.returncode == 1 and not (completed.stderr or "").strip():
        return "No matches."
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "unknown error").strip()
        return f"git failed: {detail[:500]}"
    lines = [line for line in completed.stdout.splitlines() if line.strip()][:SEARCH_RESULT_LIMIT]
    if not lines:
        return "No matches."
    return _truncate(_sanitize("\n".join(lines) + "\n"))


def _get_rerun_output(analysis: TestAnalysis, arguments: dict[str, Any]) -> str:
    attempt = arguments.get("attempt")
    if isinstance(attempt, float) and attempt.is_integer():
        attempt = int(attempt)
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
        return "attempt must be a positive integer"
    match = next((item for item in analysis.reruns if item.attempt == attempt), None)
    if match is None:
        return f"No rerun attempt {attempt}."
    payload = {
        "attempt": match.attempt,
        "outcome": match.outcome.value,
        "duration_seconds": match.duration_seconds,
        "exit_code": match.exit_code,
        "output": _sanitize(_truncate(match.output)),
    }
    return _truncate(json.dumps(payload))


def _inspect_ci_environment(
    analysis: TestAnalysis,
    repo_path: Path | None,
    repository: str | None,
    timeout_seconds: float | None,
) -> str:
    context = analysis.ci_context
    payload: dict[str, Any] = {
        "workflow_name": context.workflow_name if context else None,
        "repository": (context.repository if context else None) or repository,
        "branch": context.branch if context else None,
        "workflow_run_id": context.workflow_run_id if context else None,
        "artifact_name": context.artifact_name if context else None,
        "failing_step": "not recorded",
        "runner_os": [],
        "python_version": [],
        "environment_variable_names": [],
        "dependency_install_commands": [],
        "workflow_files": [],
    }
    if repo_path is None:
        return _truncate(json.dumps(payload))
    budget = float(GIT_TIMEOUT_SECONDS) if timeout_seconds is None else max(0.001, timeout_seconds)
    deadline = time.monotonic() + budget
    commit = analysis.commit_evidence.current_commit
    listing = _run_git(
        repo_path,
        ["ls-tree", "-r", "--name-only", commit, "--", ".github/workflows"],
        timeout_seconds=_remaining_timeout(deadline),
    )
    if listing.returncode != 0:
        detail = (listing.stderr or listing.stdout or "unknown error").strip()
        return f"git failed: {detail[:500]}"
    files = [
        line.strip()
        for line in listing.stdout.splitlines()
        if line.strip().endswith((".yml", ".yaml")) and ".." not in PurePosixPath(line.strip()).parts
    ]
    payload["workflow_files"] = files
    runner_os: list[str] = []
    python_version: list[str] = []
    env_names: list[str] = []
    installs: list[str] = []
    for path in files:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        shown = _git(repo_path, ["show", f"{commit}:{path}"], timeout_seconds=remaining)
        if shown.startswith("git failed:"):
            continue
        runner_os.extend(_RUNS_ON.findall(shown))
        python_version.extend(_PYTHON_VERSION.findall(shown))
        env_names.extend(_env_names(shown))
        for match in _INSTALL.finditer(shown):
            installs.append(_sanitize(match.group(0).strip()))
    payload["runner_os"] = _unique(runner_os)
    payload["python_version"] = _unique(python_version)
    payload["environment_variable_names"] = _unique(env_names)
    payload["dependency_install_commands"] = _unique(installs)
    return _truncate(json.dumps(payload))


def _env_names(text: str) -> list[str]:
    names: list[str] = []
    in_env = False
    env_indent = 0
    for line in text.splitlines():
        env_header = re.match(r"^(\s*)env:\s*$", line)
        if env_header:
            in_env = True
            env_indent = len(env_header.group(1))
            continue
        if not in_env:
            continue
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= env_indent:
            in_env = False
            env_header = re.match(r"^(\s*)env:\s*$", line)
            if env_header:
                in_env = True
                env_indent = len(env_header.group(1))
            continue
        match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:", line.strip())
        if match:
            names.append(match.group(1))
    return names


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


def _git(repo_path: Path, args: list[str], *, timeout_seconds: float = GIT_TIMEOUT_SECONDS) -> str:
    completed = _run_git(repo_path, args, timeout_seconds=timeout_seconds)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "unknown error").strip()
        return f"git failed: {detail[:500]}"
    return _truncate(completed.stdout)


def _run_git(
    repo_path: Path,
    args: list[str],
    *,
    timeout_seconds: float = GIT_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", *args],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=False,
            timeout=_git_timeout(timeout_seconds),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return subprocess.CompletedProcess(["git", *args], 124, "", str(error))


def _sanitize(text: str) -> str:
    redacted = _SECRET_ASSIGNMENT.sub(r"\1=***", text)
    redacted = _BEARER.sub(r"\1 ***", redacted)
    return _URL_CREDENTIALS.sub(r"\1***:***@", redacted)


def _git_timeout(value: float | None) -> float:
    if value is None:
        return float(GIT_TIMEOUT_SECONDS)
    return max(0.001, min(float(GIT_TIMEOUT_SECONDS), value))


def _remaining_timeout(deadline: float) -> float:
    return _git_timeout(deadline - time.monotonic())


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in values:
        cleaned = item.strip().strip("'\"")
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        ordered.append(cleaned)
    return ordered


def _truncate(text: str) -> str:
    if len(text) <= OUTPUT_LIMIT:
        return text
    return text[:OUTPUT_LIMIT] + "\n...[truncated]"
