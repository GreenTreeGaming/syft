import json
import subprocess
from pathlib import Path

import httpx

from syft.agent.explainer import OpenAIExplainer
from syft.agent.models import Explanation
from syft.models.analysis import WorkflowAnalysis


def test_openai_explainer_uses_structured_schema_without_classification(
    workflow_analysis: WorkflowAnalysis,
) -> None:
    explanation = Explanation(
        headline="Flaky test",
        summary="Mixed results were observed.",
        hypothesis="Shared state may leak between processes.",
        evidence=["Two of five attempts passed."],
        recommended_action="Quarantine and investigate.",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        schema = payload["text"]["format"]["schema"]
        assert "classification" not in schema["properties"]
        assert payload["store"] is False
        return httpx.Response(
            200,
            json={
                "output": [
                    {
                        "type": "message",
                        "content": [{"type": "output_text", "text": explanation.model_dump_json()}],
                    }
                ]
            },
        )

    provider = OpenAIExplainer("test-key", transport=httpx.MockTransport(handler))
    try:
        result = provider.explain(workflow_analysis.analyses[0])
    finally:
        provider.close()
    assert result == explanation


def test_openai_explainer_adds_exact_commit_source_context(
    workflow_analysis: WorkflowAnalysis, mocker, tmp_path: Path
) -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content))
        explanation = Explanation(
            headline="Checkout regression",
            summary="Persistent failure after a related change.",
            hypothesis="The calculation change may explain the mismatch.",
            evidence=["Failed 5/5 reruns."],
            recommended_action="Investigate the related change.",
        )
        return httpx.Response(
            200,
            json={
                "output": [
                    {
                        "type": "message",
                        "content": [{"type": "output_text", "text": explanation.model_dump_json()}],
                    }
                ]
            },
        )

    show = mocker.patch(
        "syft.agent.explainer.subprocess.run",
        return_value=subprocess.CompletedProcess([], 0, "def calculate(): pass\n", ""),
    )
    provider = OpenAIExplainer(
        "test-key",
        repo_path=tmp_path,
        transport=httpx.MockTransport(handler),
    )
    try:
        provider.explain(workflow_analysis.analyses[1])
    finally:
        provider.close()

    prompt = json.loads(captured["input"])
    assert prompt["repository_context"]
    assert "def calculate(): pass" in next(iter(prompt["repository_context"].values()))
    assert all(call.kwargs["timeout"] == 10 for call in show.call_args_list)
