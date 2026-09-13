from pathlib import Path

from syft.deterministic.trace_writer import write_analysis_trace
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


def test_writes_trace_and_redacts_secret(tmp_path: Path) -> None:
    rerun = RerunAttempt(
        attempt=1,
        outcome=RerunOutcome.FAILED,
        duration_seconds=0.1,
        exit_code=1,
        output="GITHUB_TOKEN=very-secret-value",
    )
    analysis = AnalysisModel(
        test=IdentityModel.from_node_id("tests/test_x.py::test_x"),
        classification=Classification.ESCALATE,
        confidence=0.5,
        reason="insufficient evidence",
        rerun_summary=RerunSummary.from_attempts([rerun]),
        reruns=[rerun],
        code_evidence=CodeEvidence(related_code_changed=None),
        commit_evidence=CommitEvidence(current_commit="abc", last_green_commit=None, failed_on_previous_commit=None),
    )
    path = write_analysis_trace(analysis, tmp_path)
    content = path.read_text(encoding="utf-8")
    assert analysis.analysis_id in path.name
    assert "very-secret-value" not in content
    assert "[REDACTED]" in content


def test_consumer_json_omits_output_but_full_trace_keeps_it(tmp_path: Path) -> None:
    rerun = RerunAttempt(
        attempt=1,
        outcome=RerunOutcome.FAILED,
        duration_seconds=0.1,
        exit_code=1,
        output="complete pytest evidence",
    )
    analysis = AnalysisModel(
        test=IdentityModel.from_node_id("tests/test_x.py::test_x"),
        classification=Classification.ESCALATE,
        confidence=0.5,
        reason="insufficient evidence",
        rerun_summary=RerunSummary.from_attempts([rerun]),
        reruns=[rerun],
        code_evidence=CodeEvidence(related_code_changed=None),
        commit_evidence=CommitEvidence(
            current_commit="abc",
            last_green_commit=None,
            failed_on_previous_commit=None,
        ),
    )

    assert "complete pytest evidence" not in analysis.consumer_dump_json()
    trace_path = write_analysis_trace(analysis, tmp_path)
    assert "complete pytest evidence" in trace_path.read_text(encoding="utf-8")
