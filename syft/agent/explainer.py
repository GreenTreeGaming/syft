"""Deterministic fallback and structured OpenAI explanation providers."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Protocol

import httpx

from syft.agent.models import Explanation
from syft.agent.tools import TOOL_SCHEMAS, allowed_paths, execute_tool
from syft.history.store import HistoryStore
from syft.models.analysis import Classification, TestAnalysis

_INSTRUCTIONS = (
    "You explain a deterministic CI classification. The classification and confidence in the "
    "input are immutable. Never reclassify, second-guess, or propose a different label. "
    "You may call the provided tools to inspect allowlisted files at the failing commit or "
    "prior Syft history. Ground every statement in the supplied evidence. Keep the hypothesis "
    "explicitly tentative. When you are done investigating, return the structured explanation."
)


class ExplanationError(RuntimeError):
    """Raised when an explanation provider cannot return valid structured output."""


class Explainer(Protocol):
    model_name: str | None

    def explain(self, analysis: TestAnalysis) -> Explanation: ...


class TemplateExplainer:
    """Predictable no-network explainer used by dry runs and tests."""

    model_name = None

    def explain(self, analysis: TestAnalysis) -> Explanation:
        evidence = [
            analysis.reason,
            (
                f"Reruns: {analysis.rerun_summary.passed} passed, "
                f"{analysis.rerun_summary.failed} failed, "
                f"{analysis.rerun_summary.timed_out} timed out."
            ),
        ]
        if analysis.code_evidence.matching_related_files:
            evidence.append(
                "Related changed files: " + ", ".join(analysis.code_evidence.matching_related_files)
            )
        if analysis.trace and analysis.trace.message:
            evidence.append(f"Failure: {analysis.trace.message}")

        if analysis.classification is Classification.FLAKY:
            return Explanation(
                headline=f"Flaky behavior detected in {analysis.test.name}",
                summary="The isolated reruns produced mixed outcomes without a directly related code change.",
                hypothesis="The test likely depends on timing, leaked state, execution order, or an unstable external boundary.",
                evidence=evidence,
                recommended_action="Quarantine this test temporarily and investigate its nondeterministic dependency.",
            )
        if analysis.classification is Classification.REGRESSION:
            return Explanation(
                headline=f"Regression detected in {analysis.test.name}",
                summary="The failure persisted across every isolated rerun and directly related implementation code changed.",
                hypothesis="The related implementation change plausibly altered behavior asserted by this test.",
                evidence=evidence,
                recommended_action="Create a regression ticket for human investigation without modifying the code automatically.",
            )
        return Explanation(
            headline=f"Human triage required for {analysis.test.name}",
            summary="The deterministic evidence does not safely support a flaky or regression classification.",
            hypothesis="The available signals are incomplete or conflicting, so an automated diagnosis would be unsafe.",
            evidence=evidence,
            recommended_action="Create a needs-triage ticket containing the conflicting evidence.",
        )


class OpenAIExplainer:
    """Investigate FLAKY/REGRESSION explanations with a bounded Responses tool loop."""

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-5.4-mini",
        *,
        repo_path: Path | None = None,
        repository: str | None = None,
        history_store: HistoryStore | None = None,
        max_turns: int = 3,
        transport: httpx.BaseTransport | None = None,
        owns_history: bool = False,
    ) -> None:
        if not api_key:
            raise ExplanationError("OPENAI_API_KEY is required when --use-openai is enabled")
        if max_turns < 1:
            raise ExplanationError("max_turns must be >= 1")
        self.model_name = model
        self.repo_path = repo_path.resolve() if repo_path else None
        self.repository = repository
        self.history_store = history_store
        self.max_turns = max_turns
        self.tool_trace: list[dict[str, Any]] = []
        self._owns_history = owns_history
        self._client = httpx.Client(
            base_url="https://api.openai.com/v1",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=60.0,
            transport=transport,
        )

    @classmethod
    def from_environment(
        cls,
        repo_path: Path | None = None,
        *,
        repository: str | None = None,
    ) -> "OpenAIExplainer":
        history_path = os.getenv("SYFT_HISTORY_PATH")
        history_store = HistoryStore(Path(history_path)) if history_path else None
        return cls(
            os.getenv("OPENAI_API_KEY", ""),
            os.getenv("OPENAI_MODEL", "gpt-5.4-mini"),
            repo_path=repo_path,
            repository=repository,
            history_store=history_store,
            owns_history=history_store is not None,
        )

    def close(self) -> None:
        self._client.close()
        if self._owns_history and self.history_store is not None:
            self.history_store.close()

    def explain(self, analysis: TestAnalysis) -> Explanation:
        self.tool_trace = []
        if analysis.classification is Classification.ESCALATE:
            return TemplateExplainer().explain(analysis)
        try:
            return self._explain_with_tools(analysis)
        except ExplanationError:
            return TemplateExplainer().explain(analysis)

    def _explain_with_tools(self, analysis: TestAnalysis) -> Explanation:
        conversation: list[Any] = [
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "deterministic_analysis": analysis.consumer_dump(),
                        "allowed_paths": allowed_paths(analysis),
                    },
                    default=str,
                ),
            }
        ]
        schema = Explanation.model_json_schema()
        for _turn in range(self.max_turns):
            payload = {
                "model": self.model_name,
                "store": False,
                "instructions": _INSTRUCTIONS,
                "input": conversation,
                "tools": TOOL_SCHEMAS,
                "tool_choice": "auto",
                "text": {
                    "format": {
                        "type": "json_schema",
                        "name": "syft_failure_explanation",
                        "strict": True,
                        "schema": schema,
                    }
                },
                "max_output_tokens": 900,
                "metadata": {"analysis_id": analysis.analysis_id},
            }
            try:
                response = self._client.post("/responses", json=payload)
                response.raise_for_status()
                result = response.json()
            except (httpx.HTTPError, ValueError) as error:
                raise ExplanationError(f"OpenAI explanation failed: {error}") from error
            calls = _function_calls(result)
            if calls:
                for item in result.get("output", []):
                    if isinstance(item, dict):
                        conversation.append(item)
                for call in calls:
                    output = execute_tool(
                        call["name"],
                        call["arguments"],
                        analysis=analysis,
                        repo_path=self.repo_path,
                        history_store=self.history_store,
                        repository=self.repository,
                    )
                    self.tool_trace.append(
                        {
                            "name": call["name"],
                            "arguments": call["arguments"],
                            "ok": not output.startswith(("Path is not", "Unknown tool", "git failed:")),
                            "preview": output[:200],
                        }
                    )
                    conversation.append(
                        {
                            "type": "function_call_output",
                            "call_id": call["call_id"],
                            "output": output,
                        }
                    )
                continue
            try:
                return Explanation.model_validate_json(_response_output_text(result))
            except (ExplanationError, ValueError) as error:
                raise ExplanationError(f"OpenAI explanation failed: {error}") from error
        return TemplateExplainer().explain(analysis)


def _function_calls(payload: dict[str, Any]) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    for item in payload.get("output", []):
        if not isinstance(item, dict) or item.get("type") != "function_call":
            continue
        raw_arguments = item.get("arguments", "{}")
        if isinstance(raw_arguments, str):
            try:
                parsed = json.loads(raw_arguments) if raw_arguments else {}
            except json.JSONDecodeError:
                parsed = {}
        elif isinstance(raw_arguments, dict):
            parsed = raw_arguments
        else:
            parsed = {}
        call_id = item.get("call_id") or item.get("id") or f"call_{len(calls)}"
        name = item.get("name") or ""
        calls.append({"name": str(name), "arguments": parsed, "call_id": str(call_id)})
    return calls


def _response_output_text(payload: dict[str, Any]) -> str:
    for item in payload.get("output", []):
        if not isinstance(item, dict) or item.get("type") != "message":
            continue
        for content in item.get("content", []):
            if isinstance(content, dict) and content.get("type") == "output_text":
                text = content.get("text")
                if isinstance(text, str):
                    return text
    raise ExplanationError("OpenAI response contained no output_text")
