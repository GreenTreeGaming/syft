"""Deterministic fallback and structured OpenAI explanation providers."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path, PurePosixPath
from typing import Protocol

import httpx

from syft.agent.models import Explanation
from syft.models.analysis import Classification, TestAnalysis


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
    """Generate an explanation with Structured Outputs via the Responses API."""

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-5.4-mini",
        *,
        repo_path: Path | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not api_key:
            raise ExplanationError("OPENAI_API_KEY is required when --use-openai is enabled")
        self.model_name = model
        self.repo_path = repo_path.resolve() if repo_path else None
        self._client = httpx.Client(
            base_url="https://api.openai.com/v1",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=60.0,
            transport=transport,
        )

    @classmethod
    def from_environment(cls, repo_path: Path | None = None) -> "OpenAIExplainer":
        return cls(
            api_key=os.getenv("OPENAI_API_KEY", ""),
            model=os.getenv("OPENAI_MODEL", "gpt-5.4-mini"),
            repo_path=repo_path,
        )

    def close(self) -> None:
        self._client.close()

    def explain(self, analysis: TestAnalysis) -> Explanation:
        evidence = {
            "deterministic_analysis": analysis.consumer_dump(),
            "repository_context": _repository_context(self.repo_path, analysis),
        }
        payload = {
            "model": self.model_name,
            "store": False,
            "instructions": (
                "You explain a deterministic CI classification. The classification and confidence in the "
                "input are immutable. Never reclassify, second-guess, or propose a different label. Ground "
                "every statement in the supplied evidence. Keep the hypothesis explicitly tentative."
            ),
            "input": json.dumps(evidence, default=str),
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "syft_failure_explanation",
                    "strict": True,
                    "schema": Explanation.model_json_schema(),
                }
            },
            "max_output_tokens": 700,
            "metadata": {"analysis_id": analysis.analysis_id},
        }
        try:
            response = self._client.post("/responses", json=payload)
            response.raise_for_status()
            result = response.json()
            return Explanation.model_validate_json(_response_output_text(result))
        except (httpx.HTTPError, KeyError, TypeError, ValueError) as error:
            raise ExplanationError(f"OpenAI explanation failed: {error}") from error


def _response_output_text(payload: dict[str, object]) -> str:
    for item in payload.get("output", []):  # type: ignore[union-attr]
        if not isinstance(item, dict) or item.get("type") != "message":
            continue
        for content in item.get("content", []):
            if isinstance(content, dict) and content.get("type") == "output_text":
                text = content.get("text")
                if isinstance(text, str):
                    return text
    raise ExplanationError("OpenAI response contained no output_text")


def _repository_context(repo_path: Path | None, analysis: TestAnalysis) -> dict[str, str]:
    if repo_path is None:
        return {}
    paths = [analysis.test.file, *analysis.code_evidence.related_files]
    context: dict[str, str] = {}
    for raw_path in dict.fromkeys(paths):
        path = PurePosixPath(raw_path)
        if path.is_absolute() or ".." in path.parts:
            continue
        try:
            completed = subprocess.run(
                ["git", "show", f"{analysis.commit_evidence.current_commit}:{path.as_posix()}"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if completed.returncode == 0:
            context[path.as_posix()] = completed.stdout[:6000]
        if len(context) == 4:
            break
    return context
