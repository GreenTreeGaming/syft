import json
import subprocess
from pathlib import Path

import httpx

from syft.agent.explainer import OpenAIExplainer, TemplateExplainer
from syft.agent.models import Explanation
from syft.history.store import HistoryStore
from syft.models.analysis import Classification, WorkflowAnalysis


def _explanation_json(**overrides: str) -> str:
    payload = {
        "headline": "Flaky test",
        "summary": "Mixed results were observed.",
        "hypothesis": "Shared state may leak between processes.",
        "evidence": ["Two of five attempts passed."],
        "recommended_action": "Quarantine and investigate.",
        **overrides,
    }
    if "evidence" not in overrides:
        payload["evidence"] = ["Two of five attempts passed."]
    return Explanation(
        headline=payload["headline"],
        summary=payload["summary"],
        hypothesis=payload["hypothesis"],
        evidence=list(payload["evidence"]),
        recommended_action=payload["recommended_action"],
    ).model_dump_json()


def _message(text: str) -> dict:
    return {
        "output": [
            {
                "type": "message",
                "content": [{"type": "output_text", "text": text}],
            }
        ]
    }


def _function_call(name: str, arguments: dict, call_id: str = "call_1") -> dict:
    return {
        "output": [
            {
                "type": "function_call",
                "call_id": call_id,
                "name": name,
                "arguments": json.dumps(arguments),
            }
        ]
    }


def test_openai_explainer_uses_structured_schema_without_classification(
    workflow_analysis: WorkflowAnalysis,
) -> None:
    explanation = Explanation.model_validate_json(_explanation_json())

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        schema = payload["text"]["format"]["schema"]
        assert "classification" not in schema["properties"]
        assert payload["store"] is False
        assert payload["tools"]
        assert "allowed_paths" in json.loads(payload["input"][0]["content"])
        return httpx.Response(200, json=_message(explanation.model_dump_json()))

    provider = OpenAIExplainer("test-key", transport=httpx.MockTransport(handler))
    try:
        result = provider.explain(workflow_analysis.analyses[0])
    finally:
        provider.close()
    assert result == explanation


def test_openai_explainer_reads_file_through_tool_loop(
    workflow_analysis: WorkflowAnalysis, mocker, tmp_path: Path
) -> None:
    captured: list[dict] = []
    explanation = Explanation(
        headline="Checkout regression",
        summary="Persistent failure after a related change.",
        hypothesis="The calculation change may explain the mismatch.",
        evidence=["Failed 5/5 reruns.", "read app/checkout.py"],
        recommended_action="Investigate the related change.",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        captured.append(payload)
        if len(captured) == 1:
            return httpx.Response(
                200,
                json=_function_call("read_file", {"path": "app/checkout.py"}),
            )
        return httpx.Response(200, json=_message(explanation.model_dump_json()))

    show = mocker.patch(
        "syft.agent.tools.subprocess.run",
        return_value=subprocess.CompletedProcess([], 0, "def calculate(): pass\n", ""),
    )
    provider = OpenAIExplainer(
        "test-key",
        repo_path=tmp_path,
        transport=httpx.MockTransport(handler),
    )
    try:
        result = provider.explain(workflow_analysis.analyses[1])
    finally:
        provider.close()

    assert result == explanation
    assert len(captured) == 2
    follow_up = json.dumps(captured[1]["input"])
    assert "def calculate(): pass" in follow_up
    assert show.call_count == 1
    assert show.call_args.kwargs["timeout"] == 10
    assert "current-sha:app/checkout.py" in show.call_args.args[0]
    assert provider.tool_trace[0]["name"] == "read_file"
    assert provider.tool_trace[0]["ok"] is True


def test_turn_cap_falls_back_to_template(
    workflow_analysis: WorkflowAnalysis, mocker, tmp_path: Path
) -> None:
    mocker.patch(
        "syft.agent.tools.subprocess.run",
        return_value=subprocess.CompletedProcess([], 0, "source", ""),
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=_function_call("read_file", {"path": "tests/test_flaky.py"}),
        )

    provider = OpenAIExplainer(
        "test-key",
        repo_path=tmp_path,
        max_turns=3,
        transport=httpx.MockTransport(handler),
    )
    try:
        result = provider.explain(workflow_analysis.analyses[0])
    finally:
        provider.close()
    expected = TemplateExplainer().explain(workflow_analysis.analyses[0])
    assert result == expected
    assert "Flaky behavior detected" in result.headline
    assert len(provider.tool_trace) == 3


def test_escalate_does_not_call_openai(workflow_analysis: WorkflowAnalysis) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("ESCALATE must not call OpenAI")

    provider = OpenAIExplainer("test-key", transport=httpx.MockTransport(handler))
    try:
        result = provider.explain(workflow_analysis.analyses[2])
    finally:
        provider.close()
    assert result == TemplateExplainer().explain(workflow_analysis.analyses[2])
    assert provider.tool_trace == []


def test_search_history_tool_result_is_sent_back(
    workflow_analysis: WorkflowAnalysis, tmp_path: Path
) -> None:
    store = HistoryStore(tmp_path / "history.sqlite")
    store.record_workflow(workflow_analysis)
    captured: list[dict] = []
    explanation = Explanation.model_validate_json(_explanation_json())

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        captured.append(payload)
        if len(captured) == 1:
            return httpx.Response(200, json=_function_call("search_history", {}))
        return httpx.Response(200, json=_message(explanation.model_dump_json()))

    provider = OpenAIExplainer(
        "test-key",
        repository="owner/repo",
        history_store=store,
        transport=httpx.MockTransport(handler),
    )
    try:
        result = provider.explain(workflow_analysis.analyses[0])
    finally:
        provider.close()
        store.close()
    assert result == explanation
    follow_up = json.dumps(captured[1]["input"])
    assert any(item.get("type") == "function_call_output" for item in captured[1]["input"] if isinstance(item, dict))
    assert "FLAKY" in follow_up
    assert "workflow_run_id" in follow_up
    assert "42" in follow_up
