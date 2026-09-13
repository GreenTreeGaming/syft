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
    assert all(call.kwargs["timeout"] == 10 for call in git.call_args_list)
    assert all(call.kwargs["cwd"] == tmp_path for call in git.call_args_list)


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
