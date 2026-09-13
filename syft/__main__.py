"""Command-line entry points for deterministic CI analysis."""

from __future__ import annotations

import argparse
import logging
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from syft.agent.explainer import ExplanationError, OpenAIExplainer, TemplateExplainer
from syft.agent.orchestrator import run_agent
from syft.agent.state import ActionLedger
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
from syft.integrations import IntegrationError
from syft.integrations.github import GitHubQuarantineClient
from syft.integrations.github_summary import GitHubPRSummaryClient
from syft.integrations.linear import LinearClient
from syft.integrations.slack import SlackWebhookClient
from syft.history.store import HistoryStore
from syft.history.summary import workflow_history_summary
from syft.models.analysis import CIContext, WorkflowAnalysis
from syft.watch import ProcessedRunLedger, WatchError, WorkflowWatcher, watch_forever


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    # httpx logs complete request URLs at INFO. Slack webhook URLs contain a
    # credential in the path, so third-party transport logs must stay quiet.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    if arguments[:1] == ["agent"]:
        return _agent_main(arguments[1:])
    if arguments[:1] == ["poll"]:
        return _poll_main(arguments[1:])
    if arguments[:1] == ["watch"]:
        return _watch_main(arguments[1:])
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


def _agent_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Explain and act on a Syft WorkflowAnalysis")
    parser.add_argument("--input", required=True, type=Path, help="compact WorkflowAnalysis JSON file")
    parser.add_argument("--repo", type=Path, help="local tested repo used for exact-commit source context")
    parser.add_argument(
        "--execute",
        action="store_true",
        help="perform real GitHub, Linear, and Slack writes",
    )
    parser.add_argument("--use-openai", action="store_true", help="generate explanations with OpenAI")
    parser.add_argument("--state-file", type=Path, default=Path(".syft-agent-state.json"))
    parser.add_argument("--history-db", type=Path, default=Path(".syft/history.sqlite3"))
    parser.add_argument("--history-limit", type=int, default=20)
    arguments = parser.parse_args(argv)
    if arguments.history_limit < 1:
        parser.error("--history-limit must be >= 1")

    openai = None
    github = None
    github_summary = None
    linear = None
    slack = None
    history_store = None
    try:
        workflow = WorkflowAnalysis.model_validate_json(arguments.input.read_text(encoding="utf-8"))
        history_store = HistoryStore(arguments.history_db)
        history_store.record_workflow(workflow)
        history = workflow_history_summary(
            history_store,
            workflow,
            limit=arguments.history_limit,
        )
        explainer = TemplateExplainer()
        if arguments.use_openai:
            openai = OpenAIExplainer.from_environment(
                arguments.repo,
                repository=workflow.repository,
                history_store=history_store,
            )
            explainer = openai
        if arguments.execute:
            github = GitHubQuarantineClient(
                os.getenv("GITHUB_TOKEN", ""),
                workflow.repository,
            )
            github_summary = GitHubPRSummaryClient(
                os.getenv("GITHUB_TOKEN", ""),
                workflow.repository,
            )
            linear = LinearClient(
                os.getenv("LINEAR_API_KEY", ""),
                os.getenv("LINEAR_TEAM_ID", ""),
            )
            slack = SlackWebhookClient(os.getenv("SLACK_WEBHOOK_URL", ""))
        result = run_agent(
            workflow,
            explainer,
            ActionLedger(arguments.state_file),
            dry_run=not arguments.execute,
            github=github,
            linear=linear,
            slack=slack,
            github_summary=github_summary,
            publish_github_summary=True,
            history=history,
        )
        history_store.record_investigations(workflow, result.investigations)
    except (ExplanationError, IntegrationError, OSError, sqlite3.Error, ValueError) as error:
        parser.error(str(error))
    finally:
        if openai:
            openai.close()
        if github:
            github.close()
        if github_summary:
            github_summary.close()
        if linear:
            linear.close()
        if slack:
            slack.close()
        if history_store:
            history_store.close()
    print(result.model_dump_json(indent=2))
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


def _watch_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Continuously process new failed GitHub Actions runs")
    parser.add_argument("--repo", required=True, type=Path, help="local clone of the repository under test")
    parser.add_argument("--github-repository", default=os.getenv("GITHUB_REPOSITORY"))
    parser.add_argument("--branch", default=os.getenv("SYFT_BRANCH", "main"))
    parser.add_argument("--green-branch", default="main")
    parser.add_argument("--artifact-name", default=os.getenv("SYFT_JUNIT_ARTIFACT"))
    parser.add_argument("--attempts", type=int, default=5)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--interval", type=float, default=60.0, help="seconds between GitHub polls")
    parser.add_argument("--once", action="store_true", help="run one cycle and exit")
    parser.add_argument("--use-openai", action="store_true", help="generate explanations with OpenAI")
    execution = parser.add_mutually_exclusive_group()
    execution.add_argument(
        "--execute",
        action="store_true",
        help="perform real GitHub, Linear, and Slack writes",
    )
    execution.add_argument(
        "--dry-run",
        action="store_false",
        dest="execute",
        help="plan actions without external writes",
    )
    parser.set_defaults(execute=False)
    parser.add_argument("--watch-state-file", type=Path, default=Path(".syft/watch-state.json"))
    parser.add_argument("--action-state-file", type=Path, default=Path(".syft/agent-state.json"))
    parser.add_argument("--output-dir", type=Path, default=Path(".syft/runs"))
    parser.add_argument("--trace-dir", type=Path, default=Path("traces"))
    parser.add_argument("--history-db", type=Path, default=Path(".syft/history.sqlite3"))
    parser.add_argument("--history-limit", type=int, default=20)
    arguments = parser.parse_args(argv)
    if arguments.history_limit < 1:
        parser.error("--history-limit must be >= 1")

    repo = _validated_repo(parser, arguments.repo)
    github_discovery = None
    openai = None
    github_actions = None
    github_summary = None
    linear = None
    slack = None
    history_store = None
    try:
        github_discovery = GitHubActionsClient(
            os.getenv("GITHUB_TOKEN", ""),
            arguments.github_repository or "",
        )
        history_store = HistoryStore(arguments.history_db)
        explainer = TemplateExplainer()
        if arguments.use_openai:
            openai = OpenAIExplainer.from_environment(
                repo,
                repository=github_discovery.repository,
                history_store=history_store,
            )
            explainer = openai
        if arguments.execute:
            github_actions = GitHubQuarantineClient(
                os.getenv("GITHUB_TOKEN", ""),
                github_discovery.repository,
            )
            github_summary = GitHubPRSummaryClient(
                os.getenv("GITHUB_TOKEN", ""),
                github_discovery.repository,
            )
            linear = LinearClient(
                os.getenv("LINEAR_API_KEY", ""),
                os.getenv("LINEAR_TEAM_ID", ""),
            )
            slack = SlackWebhookClient(os.getenv("SLACK_WEBHOOK_URL", ""))
        watcher = WorkflowWatcher(
            repo_path=repo,
            github=github_discovery,
            explainer=explainer,
            action_ledger=ActionLedger(arguments.action_state_file),
            run_ledger=ProcessedRunLedger(arguments.watch_state_file),
            output_directory=arguments.output_dir,
            branch=arguments.branch,
            green_branch=arguments.green_branch,
            artifact_name=arguments.artifact_name,
            attempts=arguments.attempts,
            timeout_seconds=arguments.timeout,
            trace_directory=_relative_to_repo(repo, arguments.trace_dir),
            execute=arguments.execute,
            github_actions=github_actions,
            github_summary=github_summary,
            linear=linear,
            slack=slack,
            history_store=history_store,
            history_limit=arguments.history_limit,
        )
        return watch_forever(
            watcher,
            interval_seconds=arguments.interval,
            once=arguments.once,
        )
    except KeyboardInterrupt:
        print("Syft watch stopped.", file=sys.stderr)
        return 130
    except (
        ExplanationError,
        GitAnalysisError,
        GitHubAPIError,
        GitHubConfigurationError,
        IntegrationError,
        JUnitParseError,
        OSError,
        RerunError,
        sqlite3.Error,
        ValueError,
        WatchError,
    ) as error:
        parser.error(str(error))
    finally:
        if github_discovery:
            github_discovery.close()
        if openai:
            openai.close()
        if github_actions:
            github_actions.close()
        if github_summary:
            github_summary.close()
        if linear:
            linear.close()
        if slack:
            slack.close()
        if history_store:
            history_store.close()


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
