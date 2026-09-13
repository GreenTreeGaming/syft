"""Command-line entry point for local deterministic analysis."""

from __future__ import annotations

import argparse
import logging
import os
import subprocess
from pathlib import Path

from syft.deterministic.git_analysis import GitAnalysisError
from syft.deterministic.pipeline import analyze_failed_test
from syft.deterministic.rerunner import RerunError
from syft.deterministic.trace_writer import write_analysis_trace
from syft.models.analysis import CIContext


def main() -> int:
    parser = argparse.ArgumentParser(description="Deterministically analyze a failed pytest test")
    parser.add_argument("test", help="pytest node ID, e.g. tests/test_checkout.py::test_checkout")
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--current-commit")
    parser.add_argument("--last-green-commit")
    parser.add_argument("--attempts", type=int, default=5)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--skip-previous-check", action="store_true")
    parser.add_argument("--trace-dir", type=Path, default=Path("traces"))
    parser.add_argument("--github-repository", default=os.getenv("GITHUB_REPOSITORY"))
    parser.add_argument("--branch", default=os.getenv("SYFT_BRANCH", "main"))
    parser.add_argument("--workflow-run-id", type=int)
    parser.add_argument("--workflow-name")
    parser.add_argument("--artifact-name", default=os.getenv("SYFT_JUNIT_ARTIFACT"))
    arguments = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    repo = arguments.repo.expanduser().resolve()
    if not repo.is_dir():
        parser.error(f"repository path does not exist: {repo}")

    ci_context = None
    if arguments.github_repository:
        ci_context = CIContext(
            repository=arguments.github_repository,
            branch=arguments.branch,
            workflow_run_id=arguments.workflow_run_id,
            workflow_name=arguments.workflow_name,
            artifact_name=arguments.artifact_name,
        )

    try:
        current_commit = arguments.current_commit or _head_commit(repo)
        analysis = analyze_failed_test(
            repo_path=repo,
            test_node_id=arguments.test,
            current_commit=current_commit,
            last_green_commit=arguments.last_green_commit,
            attempts=arguments.attempts,
            timeout_seconds=arguments.timeout,
            inspect_previous_commit=not arguments.skip_previous_check,
            ci_context=ci_context,
        )
        trace_path = write_analysis_trace(analysis, repo / arguments.trace_dir)
    except (GitAnalysisError, RerunError, ValueError) as error:
        parser.error(str(error))
    print(analysis.consumer_dump_json(indent=2))
    print(f"Trace written to {trace_path}")
    return 0


def _head_commit(repo: Path) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(f"Could not resolve HEAD: {completed.stderr.strip()}")
    return completed.stdout.strip()


if __name__ == "__main__":
    raise SystemExit(main())
