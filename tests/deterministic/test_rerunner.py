from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired

from syft.deterministic.rerunner import rerun_test
from syft.models.analysis import RerunOutcome


def test_successful_pass(mocker, tmp_path: Path) -> None:
    run = mocker.patch(
        "syft.deterministic.rerunner.subprocess.run",
        return_value=CompletedProcess([], 0, "1 passed", ""),
    )
    result = rerun_test(tmp_path, "tests/test_ok.py::test_ok", attempts=2)
    assert [item.outcome for item in result] == [RerunOutcome.PASSED, RerunOutcome.PASSED]
    assert run.call_count == 2
    assert all(call.kwargs["shell"] is False for call in run.call_args_list if "shell" in call.kwargs)


def test_failed_test(mocker, tmp_path: Path) -> None:
    mocker.patch(
        "syft.deterministic.rerunner.subprocess.run",
        return_value=CompletedProcess([], 1, "failed", "traceback"),
    )
    result = rerun_test(tmp_path, "tests/test_bad.py::test_bad", attempts=1)
    assert result[0].outcome is RerunOutcome.FAILED
    assert result[0].exit_code == 1
    assert "traceback" in result[0].output


def test_timeout_is_recorded(mocker, tmp_path: Path) -> None:
    mocker.patch(
        "syft.deterministic.rerunner.subprocess.run",
        side_effect=TimeoutExpired(["pytest"], 1, output="partial"),
    )
    result = rerun_test(tmp_path, "tests/test_slow.py::test_slow", attempts=1, timeout_seconds=1)
    assert result[0].outcome is RerunOutcome.TIMED_OUT
    assert result[0].exit_code == -1
    assert "timed out" in result[0].output

