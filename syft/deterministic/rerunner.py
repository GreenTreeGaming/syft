"""Run one pytest node repeatedly in fresh processes."""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

from syft.models.analysis import RerunAttempt, RerunOutcome


class RerunError(RuntimeError):
    """Raised when a rerun cannot be started safely."""


def rerun_test(
    repo_path: Path,
    test_node_id: str,
    attempts: int = 5,
    timeout_seconds: int = 60,
) -> list[RerunAttempt]:
    if attempts < 1:
        raise ValueError("attempts must be at least 1")
    if timeout_seconds < 1:
        raise ValueError("timeout_seconds must be at least 1")
    if not repo_path.is_dir():
        raise RerunError(f"Repository path does not exist: {repo_path}")

    results: list[RerunAttempt] = []
    command = [sys.executable, "-m", "pytest", test_node_id, "-q"]
    for attempt in range(1, attempts + 1):
        started = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
            duration = time.monotonic() - started
            output = _combine_output(completed.stdout, completed.stderr)
            outcome = RerunOutcome.PASSED if completed.returncode == 0 else RerunOutcome.FAILED
            exit_code = completed.returncode
        except subprocess.TimeoutExpired as error:
            duration = time.monotonic() - started
            output = _combine_output(_as_text(error.stdout), _as_text(error.stderr))
            output = f"Pytest timed out after {timeout_seconds} seconds.\n{output}".strip()
            outcome = RerunOutcome.TIMED_OUT
            exit_code = -1

        results.append(
            RerunAttempt(
                attempt=attempt,
                outcome=outcome,
                duration_seconds=round(duration, 4),
                exit_code=exit_code,
                output=output,
            )
        )
    return results


def _as_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    return value.decode(errors="replace") if isinstance(value, bytes) else value


def _combine_output(stdout: str, stderr: str) -> str:
    return "\n".join(part.strip() for part in (stdout, stderr) if part and part.strip())

