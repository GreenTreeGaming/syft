from syft.models.analysis import WorkflowAnalysis


def test_compact_workflow_json_round_trips(workflow_analysis: WorkflowAnalysis) -> None:
    compact = workflow_analysis.consumer_dump_json()
    restored = WorkflowAnalysis.model_validate_json(compact)
    assert restored.workflow_analysis_id == workflow_analysis.workflow_analysis_id
    assert [attempt.passed for attempt in restored.analyses[0].reruns] == [True, True, False, False, False]
    assert all(attempt.output == "" for analysis in restored.analyses for attempt in analysis.reruns)
