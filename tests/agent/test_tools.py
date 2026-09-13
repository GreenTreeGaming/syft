import json
from datetime import datetime, timezone
from pathlib import Path

from tests.conftest import make_analysis

from syft.agent.tools import execute_tool
from syft.history.store import HistoryStore
from syft.models.analysis import (
    CIContext,
    Classification,
    ClassificationSummary,
    WorkflowAnalysis,
)


FLAKY = make_analysis("tests/test_flaky.py::test_flaky", Classification.FLAKY, 2, 3)
REGRESSION = make_analysis("tests/test_checkout.py::test_checkout", Classification.REGRESSION, 0, 5)


def test_read_file_rejects_path_traversal_without_git(mocker) -> None:
    git = mocker.patch("syft.agent.tools.subprocess.run")
    result = execute_tool(
        "read_file",
        {"path": "../etc/passwd"},
        analysis=FLAKY,
        repo_path=Path("/tmp/repo"),
        history_store=None,
        repository="owner/repo",
    )
    assert result == "Path is not allowlisted or is invalid."
    git.assert_not_called()


def test_read_file_rejects_absolute_path(mocker) -> None:
    git = mocker.patch("syft.agent.tools.subprocess.run")
    result = execute_tool(
        "read_file",
        {"path": "/etc/passwd"},
        analysis=FLAKY,
        repo_path=Path("/tmp/repo"),
        history_store=None,
        repository="owner/repo",
    )
    assert "allowlisted" in result
    git.assert_not_called()


def test_git_tools_use_failing_commit_and_timeout(mocker, tmp_path: Path) -> None:
    git = mocker.patch(
        "syft.agent.tools.subprocess.run",
        return_value=__import__("subprocess").CompletedProcess([], 0, "ok-output", ""),
    )
    read = execute_tool(
        "read_file",
        {"path": "app/checkout.py"},
        analysis=REGRESSION,
        repo_path=tmp_path,
        history_store=None,
        repository="owner/repo",
    )
    blame = execute_tool(
        "git_blame",
        {"path": "app/checkout.py", "start_line": 1, "end_line": 3},
        analysis=REGRESSION,
        repo_path=tmp_path,
        history_store=None,
        repository="owner/repo",
    )
    log = execute_tool(
        "git_log",
        {"path": "app/checkout.py", "limit": 4},
        analysis=REGRESSION,
        repo_path=tmp_path,
        history_store=None,
        repository="owner/repo",
    )
    assert read == "ok-output"
    assert blame == "ok-output"
    assert log == "ok-output"
    commands = [call.args[0] for call in git.call_args_list]
    assert commands[0][:3] == ["git", "show", "current-sha:app/checkout.py"]
    assert commands[1][:4] == ["git", "blame", "-L", "1,3"]
    assert "current-sha" in commands[1]
    assert commands[2][:4] == ["git", "log", "-n", "4"]
    diff = execute_tool(
        "git_diff",
        {"path": "app/checkout.py"},
        analysis=REGRESSION,
        repo_path=tmp_path,
        history_store=None,
        repository="owner/repo",
    )
    previous = execute_tool(
        "read_previous_file",
        {"path": "app/checkout.py", "start_line": 1, "end_line": 2},
        analysis=REGRESSION,
        repo_path=tmp_path,
        history_store=None,
        repository="owner/repo",
    )
    assert diff == "ok-output"
    assert previous == "ok-output"
    commands = [call.args[0] for call in git.call_args_list]
    assert commands[3][:6] == ["git", "diff", "--no-color", "-U3", "green-sha", "current-sha"]
    assert commands[3][-1] == "app/checkout.py"
    assert commands[4][:3] == ["git", "show", "green-sha:app/checkout.py"]
    assert all(call.kwargs["timeout"] == 10 for call in git.call_args_list)
    assert all(call.kwargs["cwd"] == tmp_path for call in git.call_args_list)


def test_search_code_is_fixed_string_at_failing_commit(mocker, tmp_path: Path) -> None:
    git = mocker.patch(
        "syft.agent.tools.subprocess.run",
        return_value=__import__("subprocess").CompletedProcess(
            [], 0, "app/checkout.py:3:assert total == 108\n" * 25, ""
        ),
    )
    result = execute_tool(
        "search_code",
        {"query": "assert total == 108"},
        analysis=REGRESSION,
        repo_path=tmp_path,
        history_store=None,
        repository="owner/repo",
    )
    command = git.call_args.args[0]
    assert command[:6] == ["git", "grep", "-n", "-F", "-I", "-e"]
    assert command[6] == "assert total == 108"
    assert command[7] == "current-sha"
    assert ":(exclude)**/.env" in command
    assert result.count("app/checkout.py") == 20


def test_search_code_sanitizes_matching_secrets(mocker, tmp_path: Path) -> None:
    mocker.patch(
        "syft.agent.tools.subprocess.run",
        return_value=__import__("subprocess").CompletedProcess(
            [], 0, "config.py:1:API_KEY=super-secret-value\n", ""
        ),
    )
    result = execute_tool(
        "search_code",
        {"query": "API_KEY"},
        analysis=REGRESSION,
        repo_path=tmp_path,
        history_store=None,
        repository="owner/repo",
    )
    assert "super-secret-value" not in result
    assert "API_KEY=***" in result


def test_search_code_rejects_path_traversal_in_diff(mocker) -> None:
    git = mocker.patch("syft.agent.tools.subprocess.run")
    result = execute_tool(
        "git_diff",
        {"path": "../.env"},
        analysis=REGRESSION,
        repo_path=Path("/tmp/repo"),
        history_store=None,
        repository="owner/repo",
    )
    assert result == "Path is not allowlisted or is invalid."
    git.assert_not_called()


def test_get_rerun_output_sanitizes_secrets() -> None:
    analysis = make_analysis("tests/test_checkout.py::test_checkout", Classification.REGRESSION, 0, 5)
    analysis.reruns[1].output = (
        "AssertionError: expected 108.00, received 92.00\nGITHUB_TOKEN=super-secret-value\n"
    )
    result = json.loads(
        execute_tool(
            "get_rerun_output",
            {"attempt": 2},
            analysis=analysis,
            repo_path=None,
            history_store=None,
            repository="owner/repo",
        )
    )
    assert result["attempt"] == 2
    assert result["outcome"] == "FAILED"
    assert result["exit_code"] == 1
    assert "expected 108.00, received 92.00" in result["output"]
    assert "super-secret-value" not in result["output"]
    assert "GITHUB_TOKEN=***" in result["output"]


def test_inspect_ci_environment_returns_names_not_values(mocker, tmp_path: Path) -> None:
    workflow = (
        "name: CI\n"
        "on: push\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    env:\n"
        "      GITHUB_TOKEN: super-secret-value\n"
        "      DATABASE_URL: postgres://user:password@example.com/database\n"
        "      PYTEST_ADDOPTS: -q\n"
        "    steps:\n"
        "      - uses: actions/setup-python@v5\n"
        "        with:\n"
        "          python-version: '3.12'\n"
        "      - run: pip install https://user:password@example.com/private-package.whl\n"
    )
    git = mocker.patch(
        "syft.agent.tools.subprocess.run",
        side_effect=[
            __import__("subprocess").CompletedProcess([], 0, ".github/workflows/ci.yml\n", ""),
            __import__("subprocess").CompletedProcess([], 0, workflow, ""),
        ],
    )
    analysis = make_analysis("tests/test_ambiguous.py::test_ambiguous", Classification.ESCALATE, 0, 5)
    analysis.ci_context = CIContext(
        repository="owner/repo",
        branch="main",
        workflow_name="CI",
        workflow_run_id=9,
    )
    payload = json.loads(
        execute_tool(
            "inspect_ci_environment",
            {},
            analysis=analysis,
            repo_path=tmp_path,
            history_store=None,
            repository="owner/repo",
        )
    )
    assert payload["workflow_name"] == "CI"
    assert payload["runner_os"] == ["ubuntu-latest"]
    assert payload["python_version"] == ["3.12"]
    assert payload["environment_variable_names"] == ["GITHUB_TOKEN", "DATABASE_URL", "PYTEST_ADDOPTS"]
    assert any("pip install" in item for item in payload["dependency_install_commands"])
    assert payload["failing_step"] == "not recorded"
    assert "super-secret-value" not in json.dumps(payload)
    assert "postgres://user:password" not in json.dumps(payload)
    assert "https://user:password@" not in json.dumps(payload)
    assert "https://***:***@example.com/private-package.whl" in json.dumps(payload)
    assert "workflow_excerpts" not in payload
    assert git.call_args_list[0].args[0][:5] == ["git", "ls-tree", "-r", "--name-only", "current-sha"]
    assert git.call_args_list[1].args[0][:3] == ["git", "show", "current-sha:.github/workflows/ci.yml"]


def test_git_tool_timeout_is_bounded_by_remaining_investigation_time(mocker, tmp_path: Path) -> None:
    git = mocker.patch(
        "syft.agent.tools.subprocess.run",
        return_value=__import__("subprocess").CompletedProcess([], 0, "ok-output", ""),
    )
    result = execute_tool(
        "git_diff",
        {"path": "app/checkout.py"},
        analysis=REGRESSION,
        repo_path=tmp_path,
        history_store=None,
        repository="owner/repo",
        timeout_seconds=2.5,
    )
    assert result == "ok-output"
    assert git.call_args.kwargs["timeout"] == 2.5


def test_ci_environment_stops_when_its_tool_budget_expires(mocker, tmp_path: Path) -> None:
    clock = iter([0.0, 0.1, 1.5])
    mocker.patch("syft.agent.tools.time.monotonic", side_effect=lambda: next(clock))
    git = mocker.patch(
        "syft.agent.tools.subprocess.run",
        return_value=__import__("subprocess").CompletedProcess(
            [], 0, ".github/workflows/ci.yml\n", ""
        ),
    )
    payload = json.loads(
        execute_tool(
            "inspect_ci_environment",
            {},
            analysis=REGRESSION,
            repo_path=tmp_path,
            history_store=None,
            repository="owner/repo",
            timeout_seconds=1.0,
        )
    )
    assert payload["workflow_files"] == [".github/workflows/ci.yml"]
    assert payload["runner_os"] == []
    assert git.call_count == 1
    assert git.call_args.kwargs["timeout"] == 0.9


def test_search_history_returns_prior_classifications(tmp_path: Path) -> None:
    analysis = make_analysis("tests/test_flaky.py::test_flaky", Classification.FLAKY, 2, 3)
    analysis.ci_context = CIContext(repository="owner/repo", branch="fixture")
    workflow = WorkflowAnalysis(
        workflow_analysis_id="wa_7",
        created_at=datetime(2026, 5, 1, tzinfo=timezone.utc),
        repository="owner/repo",
        branch="fixture",
        workflow_run_id=7,
        workflow_name="CI",
        current_commit="abc",
        last_green_commit="green",
        junit_artifact="pytest-junit",
        failed_tests=[analysis.test.node_id],
        summary=ClassificationSummary(flaky=1, regression=0, escalate=0, total=1),
        analyses=[analysis],
    )
    with HistoryStore(tmp_path / "history.sqlite") as store:
        store.record_workflow(workflow)
        result = execute_tool(
            "search_history",
            {},
            analysis=analysis,
            repo_path=tmp_path,
            history_store=store,
            repository="unused",
        )
    assert "FLAKY" in result
    assert "7" in result
    assert "abc" in result
