"""Deterministic fallback and structured OpenAI explanation providers."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Protocol

import httpx

from syft.agent.models import Explanation, Investigation, ToolCallRecord
from syft.agent.tools import TOOL_SCHEMAS, allowed_paths, execute_tool, tool_ok
from syft.history.store import HistoryStore
from syft.models.analysis import Classification, TestAnalysis

_INSTRUCTIONS = (
    "You explain a deterministic CI classification. The classification and confidence in the "
    "input are immutable. Never reclassify, second-guess, or propose a different label. "
    "This includes ESCALATE: investigate and write a stronger human-triage explanation, but "
    "do not change the label. Prefer git_diff for code changes, batch tool calls, search_code "
    "at most once, then stop and return the structured explanation. Ground every statement in "
    "the supplied evidence. Keep the hypothesis explicitly tentative."
)


class ExplanationError(RuntimeError):
    """Raised when an explanation provider cannot return valid structured output."""


class Explainer(Protocol):
    model_name: str | None

    def explain(self, analysis: TestAnalysis) -> Explanation: ...


class TemplateExplainer:
    """Predictable no-network explainer used by dry runs and tests."""

    model_name = None

    def __init__(self) -> None:
        self.investigations: list[Investigation] = []

    def explain(self, analysis: TestAnalysis) -> Explanation:
        self.investigations.append(
            Investigation(
                analysis_id=analysis.analysis_id,
                test_node_id=analysis.test.node_id,
                turns=0,
                tool_calls=[],
            )
        )
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
    """Investigate explanations with a bounded Responses tool loop."""

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-5.4-mini",
        *,
        repo_path: Path | None = None,
        repository: str | None = None,
        history_store: HistoryStore | None = None,
        max_turns: int = 5,
        max_tool_calls: int = 12,
        investigation_timeout_seconds: float = 90.0,
        transport: httpx.BaseTransport | None = None,
        owns_history: bool = False,
    ) -> None:
        if not api_key:
            raise ExplanationError("OPENAI_API_KEY is required when --use-openai is enabled")
        if max_turns < 1:
            raise ExplanationError("max_turns must be >= 1")
        if max_tool_calls < 1:
            raise ExplanationError("max_tool_calls must be >= 1")
        if investigation_timeout_seconds <= 0:
            raise ExplanationError("investigation_timeout_seconds must be > 0")
        self.model_name = model
        self.repo_path = repo_path.resolve() if repo_path else None
        self.repository = repository
        self.history_store = history_store
        self.max_turns = max_turns
        self.max_tool_calls = max_tool_calls
        self.investigation_timeout_seconds = investigation_timeout_seconds
        self.tool_trace: list[dict[str, Any]] = []
        self.investigations: list[Investigation] = []
        self._owns_history = owns_history
        self._client = httpx.Client(
            base_url="https://api.openai.com/v1",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=90.0,
            transport=transport,
        )

    @classmethod
    def from_environment(
        cls,
        repo_path: Path | None = None,
        *,
        repository: str | None = None,
        history_store: HistoryStore | None = None,
    ) -> "OpenAIExplainer":
        owns_history = False
        if history_store is None:
            history_path = os.getenv("SYFT_HISTORY_PATH")
            if history_path:
                history_store = HistoryStore(Path(history_path))
                owns_history = True
        return cls(
            os.getenv("OPENAI_API_KEY", ""),
            os.getenv("OPENAI_MODEL", "gpt-5.4-mini"),
            repo_path=repo_path,
            repository=repository,
            history_store=history_store,
            owns_history=owns_history,
        )

    def close(self) -> None:
        self._client.close()
        if self._owns_history and self.history_store is not None:
            self.history_store.close()

    def explain(self, analysis: TestAnalysis) -> Explanation:
        self.tool_trace = []
        try:
            explanation, turns, timed_out, hit_tool_cap, fallback = self._explain_with_tools(analysis)
        except ExplanationError:
            explanation = TemplateExplainer().explain(analysis)
            self._record_investigation(analysis, turns=0, fallback=True, timed_out=False, hit_tool_cap=False)
            return explanation
        self._record_investigation(
            analysis,
            turns=turns,
            fallback=fallback,
            timed_out=timed_out,
            hit_tool_cap=hit_tool_cap,
        )
        return explanation

    def _record_investigation(
        self,
        analysis: TestAnalysis,
        *,
        turns: int,
        fallback: bool,
        timed_out: bool,
        hit_tool_cap: bool,
    ) -> None:
        run_id = analysis.ci_context.workflow_run_id if analysis.ci_context else None
        self.investigations.append(
            Investigation(
                analysis_id=analysis.analysis_id,
                test_node_id=analysis.test.node_id,
                workflow_run_id=run_id,
                turns=turns,
                tool_calls=[ToolCallRecord.model_validate(item) for item in self.tool_trace],
                timed_out=timed_out,
                hit_tool_cap=hit_tool_cap,
                used_template_fallback=fallback,
            )
        )

    def _explain_with_tools(self, analysis: TestAnalysis) -> tuple[Explanation, int, bool, bool, bool]:
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
        deadline = time.monotonic() + self.investigation_timeout_seconds
        timed_out = False
        hit_tool_cap = False
        turns = 0
        for _turn in range(self.max_turns):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            turns += 1
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
                response = self._client.post("/responses", json=payload, timeout=min(90.0, remaining))
                response.raise_for_status()
                result = response.json()
            except (httpx.TimeoutException, httpx.HTTPError, ValueError) as error:
                if isinstance(error, httpx.TimeoutException) or time.monotonic() >= deadline:
                    timed_out = True
                    break
                raise ExplanationError(f"OpenAI explanation failed: {error}") from error
            calls = _function_calls(result)
            if calls:
                remaining_slots = self.max_tool_calls - len(self.tool_trace)
                if remaining_slots <= 0:
                    hit_tool_cap = True
                    break
                if len(calls) > remaining_slots:
                    calls = calls[:remaining_slots]
                    hit_tool_cap = True
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
                            "ok": tool_ok(output),
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
                if hit_tool_cap or len(self.tool_trace) >= self.max_tool_calls:
                    hit_tool_cap = True
                    break
                continue
            try:
                explanation = Explanation.model_validate_json(_response_output_text(result))
            except (ExplanationError, ValueError) as error:
                raise ExplanationError(f"OpenAI explanation failed: {error}") from error
            return explanation, turns, False, False, False
        return TemplateExplainer().explain(analysis), turns, timed_out, hit_tool_cap, True


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
