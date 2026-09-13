"""Coordinate GitHub discovery, JUnit parsing, and per-test analysis."""

from __future__ import annotations

import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from syft.deterministic.github_runs import GitHubActionsClient
from syft.deterministic.junit_parser import parse_failed_tests
from syft.deterministic.pipeline import analyze_failed_test
from syft.deterministic.trace_writer import write_analysis_trace
from syft.models.analysis import (
    CIContext,
    Classification,
    ClassificationSummary,
    WorkflowAnalysis,
)


class CoordinatorError(RuntimeError):
    """Raised when a workflow cannot be analyzed with trustworthy evidence."""


def analyze_latest_failed_workflow(
    repo_path: Path,
    github: GitHubActionsClient,
    *,
    branch: str = "main",
    green_branch: str = "main",
    artifact_name: str | None = None,
    attempts: int = 5,
    timeout_seconds: int = 60,
    trace_directory: Path | None = None,
) -> WorkflowAnalysis:
    """Analyze every failed pytest test from the latest failed Actions run."""

    repo_path = repo_path.resolve()
    failed_run = github.latest_failed_run(branch)
    green_run = github.previous_successful_run(failed_run, green_branch)
    if green_run is None:
        raise CoordinatorError(
            f"No successful workflow run before {failed_run.id} was found on branch {green_branch!r}"
        )

    with tempfile.TemporaryDirectory(prefix="syft-artifacts-") as temporary:
        artifact = github.download_junit_artifact(
            failed_run.id,
            Path(temporary),
            artifact_name=artifact_name,
        )
        failed_tests = sorted(
            {
                node_id
                for xml_file in artifact.xml_files
                for node_id in parse_failed_tests(xml_file)
            }
        )
    if not failed_tests:
        raise CoordinatorError(f"JUnit artifact {artifact.name!r} contained no failed tests")

    context = CIContext(
        repository=github.repository,
        branch=branch,
        workflow_run_id=failed_run.id,
        workflow_name=failed_run.name,
        artifact_name=artifact.name,
    )
    with _detached_worktree(repo_path, failed_run.head_sha) as failed_checkout:
        analyses = [
            analyze_failed_test(
                repo_path=failed_checkout,
                test_node_id=node_id,
                current_commit=failed_run.head_sha,
                last_green_commit=green_run.head_sha,
                attempts=attempts,
                timeout_seconds=timeout_seconds,
                ci_context=context,
            )
            for node_id in failed_tests
        ]

    destination = trace_directory or repo_path / "traces"
    for analysis in analyses:
        write_analysis_trace(analysis, destination)

    summary = ClassificationSummary(
        flaky=sum(item.classification is Classification.FLAKY for item in analyses),
        regression=sum(item.classification is Classification.REGRESSION for item in analyses),
        escalate=sum(item.classification is Classification.ESCALATE for item in analyses),
        total=len(analyses),
    )
    return WorkflowAnalysis(
        workflow_analysis_id=f"wa_{failed_run.id}_{failed_run.head_sha[:12]}",
        repository=github.repository,
        branch=branch,
        workflow_run_id=failed_run.id,
        workflow_name=failed_run.name,
        current_commit=failed_run.head_sha,
        last_green_commit=green_run.head_sha,
        junit_artifact=artifact.name,
        failed_tests=failed_tests,
        summary=summary,
        analyses=analyses,
    )


@contextmanager
def _detached_worktree(repo_path: Path, commit: str) -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="syft-failed-run-") as temporary:
        checkout = Path(temporary) / "repo"
        _run_git(repo_path, ["worktree", "add", "--detach", str(checkout), commit])
        try:
            yield checkout
        finally:
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(checkout)],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=False,
            )


def _run_git(repo_path: Path, arguments: list[str]) -> None:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repo_path,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "unknown Git error"
        raise CoordinatorError(f"Git {' '.join(arguments)} failed: {detail}")

