"""Command-line entry points for deterministic CI analysis."""

from __future__ import annotations

import argparse
import logging
import os
import subprocess
import sys
from pathlib import Path

from syft.deterministic.coordinator import CoordinatorError, analyze_latest_failed_workflow
from syft.deterministic.git_analysis import GitAnalysisError
from syft.deterministic.github_runs import (
    GitHubActionsClient,
    GitHubAPIError,
    GitHubConfigurationError,
)
from syft.deterministic.junit_parser import JUnitParseError
from syft.deterministic.pipeline import analyze_failed_test
from syft.deterministic.rerunner import RerunError
from syft.deterministic.trace_writer import write_analysis_trace
from syft.eval.ground_truth import load_ground_truth
from syft.eval.metrics import evaluate_predictions, format_report
from syft.models.analysis import CIContext


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    if arguments[:1] == ["poll"]:
        return _poll_main(arguments[1:])
    if arguments[:1] == ["analyze"]:
        arguments = arguments[1:]
    return _analyze_main(arguments)


def _analyze_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Deterministically analyze one failed pytest test")
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
    arguments = parser.parse_args(argv)

    repo = _validated_repo(parser, arguments.repo)
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
        trace_path = write_analysis_trace(analysis, _relative_to_repo(repo, arguments.trace_dir))
    except (GitAnalysisError, RerunError, ValueError) as error:
        parser.error(str(error))
    print(analysis.consumer_dump_json(indent=2))
    print(f"Trace written to {trace_path}", file=sys.stderr)
    return 0


def _poll_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Analyze the latest failed GitHub Actions workflow")
    parser.add_argument("--repo", required=True, type=Path, help="local clone of the repository under test")
    parser.add_argument("--branch", default=os.getenv("SYFT_BRANCH", "main"))
    parser.add_argument("--green-branch", default="main")
    parser.add_argument("--artifact-name", default=os.getenv("SYFT_JUNIT_ARTIFACT"))
    parser.add_argument("--attempts", type=int, default=5)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--trace-dir", type=Path, default=Path("traces"))
    parser.add_argument("--ground-truth", type=Path)
    arguments = parser.parse_args(argv)
    repo = _validated_repo(parser, arguments.repo)

    try:
        with GitHubActionsClient.from_environment() as github:
            result = analyze_latest_failed_workflow(
                repo_path=repo,
                github=github,
                branch=arguments.branch,
                green_branch=arguments.green_branch,
                artifact_name=arguments.artifact_name,
                attempts=arguments.attempts,
                timeout_seconds=arguments.timeout,
                trace_directory=_relative_to_repo(repo, arguments.trace_dir),
            )
        if arguments.ground_truth:
            cases = load_ground_truth(arguments.ground_truth)
            predictions = {item.test.node_id: item.classification for item in result.analyses}
            print(format_report(evaluate_predictions(cases, predictions)), file=sys.stderr)
    except (
        CoordinatorError,
        GitAnalysisError,
        GitHubAPIError,
        GitHubConfigurationError,
        JUnitParseError,
        OSError,
        RerunError,
        ValueError,
    ) as error:
        parser.error(str(error))
    print(result.consumer_dump_json(indent=2))
    return 0


def _validated_repo(parser: argparse.ArgumentParser, repo: Path) -> Path:
    resolved = repo.expanduser().resolve()
    if not resolved.is_dir():
        parser.error(f"repository path does not exist: {resolved}")
    return resolved


def _relative_to_repo(repo: Path, path: Path) -> Path:
    return path if path.is_absolute() else repo / path


def _head_commit(repo: Path) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RerunError(f"Could not resolve HEAD: {completed.stderr.strip()}")
    return completed.stdout.strip()


if __name__ == "__main__":
    raise SystemExit(main())
