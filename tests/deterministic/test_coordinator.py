from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path

from syft.deterministic.coordinator import analyze_latest_failed_workflow
from syft.deterministic.github_runs import DownloadedArtifact, GitHubRun
from syft.models.analysis import (
    Classification,
    CodeEvidence,
    CommitEvidence,
    RerunAttempt,
    RerunOutcome,
    RerunSummary,
    TestAnalysis as AnalysisModel,
    TestIdentity as IdentityModel,
)


class FakeGitHub:
    repository = "owner/repo"

    def __init__(self, xml_path: Path) -> None:
        self.xml_path = xml_path

    def latest_failed_run(self, branch: str) -> GitHubRun:
        assert branch == "fixture"
        return GitHubRun(
            id=42,
            head_sha="current-sha",
            name="CI",
            conclusion="failure",
            created_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        )

    def previous_successful_run(self, failed_run: GitHubRun, branch: str) -> GitHubRun:
        assert failed_run.id == 42
        assert branch == "main"
        return GitHubRun(
            id=41,
            head_sha="green-sha",
            name="CI",
            conclusion="success",
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )

    def download_junit_artifact(
        self,
        run_id: int,
        destination: Path,
        artifact_name: str | None = None,
    ) -> DownloadedArtifact:
        assert run_id == 42
        assert artifact_name == "pytest-junit"
        return DownloadedArtifact(name="pytest-junit", xml_files=[self.xml_path])


def _analysis(node_id: str, classification: Classification) -> AnalysisModel:
    rerun = RerunAttempt(
        attempt=1,
        outcome=RerunOutcome.FAILED,
        duration_seconds=0.1,
        exit_code=1,
        output="complete evidence",
    )
    return AnalysisModel(
        test=IdentityModel.from_node_id(node_id),
        classification=classification,
        confidence=0.9,
        reason="fixture",
        rerun_summary=RerunSummary.from_attempts([rerun]),
        reruns=[rerun],
        code_evidence=CodeEvidence(related_code_changed=False),
        commit_evidence=CommitEvidence(
            current_commit="current-sha",
            last_green_commit="green-sha",
            failed_on_previous_commit=None,
        ),
    )


def test_coordinates_all_failed_tests_and_builds_summary(mocker, tmp_path: Path) -> None:
    xml = tmp_path / "junit.xml"
    xml.write_text(
        """<testsuite>
<testcase classname="tests.test_a" name="test_a" file="tests/test_a.py"><failure /></testcase>
<testcase classname="tests.test_b" name="test_b" file="tests/test_b.py"><failure /></testcase>
<testcase classname="tests.test_c" name="test_c" file="tests/test_c.py"><failure /></testcase>
</testsuite>""",
        encoding="utf-8",
    )
    classifications = {
        "tests/test_a.py::test_a": Classification.FLAKY,
        "tests/test_b.py::test_b": Classification.REGRESSION,
        "tests/test_c.py::test_c": Classification.ESCALATE,
    }
    analyze = mocker.patch(
        "syft.deterministic.coordinator.analyze_failed_test",
        side_effect=lambda **kwargs: _analysis(
            kwargs["test_node_id"], classifications[kwargs["test_node_id"]]
        ),
    )
    mocker.patch(
        "syft.deterministic.coordinator._detached_worktree",
        return_value=nullcontext(tmp_path),
    )
    write_trace = mocker.patch("syft.deterministic.coordinator.write_analysis_trace")

    result = analyze_latest_failed_workflow(
        tmp_path,
        FakeGitHub(xml),  # type: ignore[arg-type]
        branch="fixture",
        artifact_name="pytest-junit",
        trace_directory=tmp_path / "traces",
    )

    assert result.workflow_analysis_id == "wa_42_current-sha"
    assert result.summary.model_dump() == {
        "flaky": 1,
        "regression": 1,
        "escalate": 1,
        "total": 3,
    }
    assert analyze.call_count == 3
    assert write_trace.call_count == 3
    assert "complete evidence" not in result.consumer_dump_json()

