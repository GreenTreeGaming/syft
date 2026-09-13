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
    assert len(provider.investigations) == 1
    recorded = provider.investigations[0]
    assert recorded.tool_calls[0].name == "read_file"
    assert recorded.turns == 2
    assert recorded.used_template_fallback is False


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
    assert provider.investigations[0].used_template_fallback is True
    assert provider.investigations[0].turns == 3
    assert len(provider.investigations[0].tool_calls) == 3


def test_escalate_can_use_the_tool_loop(
    workflow_analysis: WorkflowAnalysis,
) -> None:
    explanation = Explanation(
        headline="Needs human triage",
        summary="Signals conflict and no safe automated label exists.",
        hypothesis="A missing CI service or environment variable may explain the persistent failure.",
        evidence=["All isolated reruns failed.", "No directly related implementation change."],
        recommended_action="Triage the CI environment and conflicting evidence.",
    )
    captured: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        captured.append(payload)
        names = {item["name"] for item in payload["tools"]}
        assert "inspect_ci_environment" in names
        assert "git_diff" in names
        assert "search_code" in names
        return httpx.Response(200, json=_message(explanation.model_dump_json()))

    provider = OpenAIExplainer("test-key", transport=httpx.MockTransport(handler))
    try:
        result = provider.explain(workflow_analysis.analyses[2])
    finally:
        provider.close()
    assert result == explanation
    assert captured
    assert provider.investigations[0].used_template_fallback is False
    assert workflow_analysis.analyses[2].classification.value == "ESCALATE"


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


def test_from_environment_keeps_the_passed_history_store(
    workflow_analysis: WorkflowAnalysis, tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("SYFT_HISTORY_PATH", str(tmp_path / "env-history.sqlite"))
    store = HistoryStore(tmp_path / "cli-history.sqlite")
    store.record_workflow(workflow_analysis)
    provider = OpenAIExplainer.from_environment(
        repository="owner/repo",
        history_store=store,
    )
    try:
        assert provider.history_store is store
        assert provider._owns_history is False
        assert provider.max_turns == 5
        assert provider.max_tool_calls == 12
        assert provider.investigation_timeout_seconds == 90.0
    finally:
        provider.close()
    leftover = store.recent_history("owner/repo", "tests/test_flaky.py::test_flaky")
    store.close()
    assert leftover[0].workflow_run_id == 42


def test_tool_call_cap_falls_back_after_twelve_calls(
    workflow_analysis: WorkflowAnalysis, mocker, tmp_path: Path
) -> None:
    mocker.patch(
        "syft.agent.tools.subprocess.run",
        return_value=subprocess.CompletedProcess([], 0, "source", ""),
    )
    requests = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        requests["count"] += 1
        return httpx.Response(
            200,
            json={
                "output": [
                    {
                        "type": "function_call",
                        "call_id": f"call_{index}",
                        "name": "read_file",
                        "arguments": json.dumps({"path": "tests/test_flaky.py"}),
                    }
                    for index in range(12)
                ]
            },
        )

    provider = OpenAIExplainer(
        "test-key",
        repo_path=tmp_path,
        transport=httpx.MockTransport(handler),
    )
    try:
        result = provider.explain(workflow_analysis.analyses[0])
    finally:
        provider.close()
    assert "Flaky behavior detected" in result.headline
    assert requests["count"] == 1
    assert len(provider.tool_trace) == 12
    assert provider.investigations[0].hit_tool_cap is True
    assert provider.investigations[0].used_template_fallback is True


def test_investigation_timeout_falls_back_without_reclassifying(
    workflow_analysis: WorkflowAnalysis, mocker, tmp_path: Path
) -> None:
    clock = {"value": 0.0}

    def monotonic() -> float:
        current = clock["value"]
        if current == 0.0:
            clock["value"] = 0.1
        else:
            clock["value"] = 91.0
        return current

    mocker.patch("syft.agent.explainer.time.monotonic", side_effect=monotonic)
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
        transport=httpx.MockTransport(handler),
    )
    try:
        result = provider.explain(workflow_analysis.analyses[0])
    finally:
        provider.close()
    assert result.headline.startswith("Flaky behavior detected")
    assert provider.investigations[0].timed_out is True
    assert provider.investigations[0].used_template_fallback is True
    assert len(provider.tool_trace) == 1
