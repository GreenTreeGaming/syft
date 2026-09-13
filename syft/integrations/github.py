"""Create an idempotent quarantine pull request through the GitHub API."""

from __future__ import annotations

import ast
import base64
import json
import re
from urllib.parse import quote

import httpx

from syft.agent.models import ActionKind, ActionPlan, ActionResult, ActionStatus
from syft.integrations import IntegrationError
from syft.models.analysis import TestAnalysis


class GitHubQuarantineClient:
    def __init__(
        self,
        token: str,
        repository: str,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not token:
            raise IntegrationError("GITHUB_TOKEN is required for --execute")
        if repository.count("/") != 1:
            raise IntegrationError("GitHub repository must have the form owner/repo")
        self.repository = repository
        self.owner = repository.split("/", 1)[0]
        self._client = httpx.Client(
            base_url="https://api.github.com",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=30.0,
            transport=transport,
            follow_redirects=True,
        )

    def close(self) -> None:
        self._client.close()

    def create_quarantine_pr(
        self,
        plan: ActionPlan,
        analysis: TestAnalysis,
        *,
        base_branch: str,
    ) -> ActionResult:
        if plan.kind is not ActionKind.QUARANTINE_PR:
            raise IntegrationError("GitHub quarantine adapter received a non-quarantine action")
        branch = _quarantine_branch(plan)
        existing = self._find_pull_request(branch)
        if existing:
            return ActionResult(
                action_id=plan.action_id,
                kind=plan.kind,
                status=ActionStatus.ALREADY_EXISTS,
                external_id=str(existing["number"]),
                url=str(existing["html_url"]),
                detail="Existing quarantine pull request reused.",
            )

        self._ensure_branch(branch, analysis.commit_evidence.current_commit)
        path = quote(plan.test_file, safe="/")
        file_payload = self._json(
            "GET",
            f"/repos/{self.repository}/contents/{path}",
            params={"ref": branch},
        )
        try:
            source = base64.b64decode(file_payload["content"]).decode("utf-8")
            file_sha = str(file_payload["sha"])
        except (KeyError, ValueError, UnicodeDecodeError) as error:
            raise IntegrationError(f"Could not decode {plan.test_file} from GitHub") from error

        reason = (
            f"Syft: {analysis.rerun_summary.passed}/{analysis.rerun_summary.total} isolated reruns "
            f"passed; analysis {analysis.analysis_id}"
        )
        updated = quarantine_pytest_source(source, analysis.test.name, reason)
        if updated != source:
            self._json(
                "PUT",
                f"/repos/{self.repository}/contents/{path}",
                json={
                    "message": f"Quarantine flaky test {analysis.test.name}",
                    "content": base64.b64encode(updated.encode()).decode(),
                    "sha": file_sha,
                    "branch": branch,
                },
            )

        pull = self._json(
            "POST",
            f"/repos/{self.repository}/pulls",
            json={"title": plan.title, "body": plan.body, "head": branch, "base": base_branch},
        )
        return ActionResult(
            action_id=plan.action_id,
            kind=plan.kind,
            status=ActionStatus.CREATED,
            external_id=str(pull["number"]),
            url=str(pull["html_url"]),
            detail="Quarantine pull request created.",
        )

    def _find_pull_request(self, branch: str) -> dict[str, object] | None:
        payload = self._json(
            "GET",
            f"/repos/{self.repository}/pulls",
            params={"state": "all", "head": f"{self.owner}:{branch}", "per_page": 1},
        )
        return payload[0] if isinstance(payload, list) and payload else None

    def _ensure_branch(self, branch: str, commit: str) -> None:
        response = self._client.post(
            f"/repos/{self.repository}/git/refs",
            json={"ref": f"refs/heads/{branch}", "sha": commit},
        )
        if response.status_code == 422 and "Reference already exists" in response.text:
            return
        _raise_for_status(response)

    def _json(self, method: str, url: str, **kwargs: object) -> object:
        try:
            response = self._client.request(method, url, **kwargs)
            _raise_for_status(response)
            return response.json()
        except (httpx.HTTPError, ValueError) as error:
            raise IntegrationError(f"GitHub request failed for {url}: {error}") from error


def quarantine_pytest_source(source: str, test_name: str, reason: str) -> str:
    """Add a pytest skip decorator while preserving valid module structure."""

    try:
        tree = ast.parse(source)
    except SyntaxError as error:
        raise IntegrationError(f"Cannot quarantine a test file with invalid Python: {error}") from error
    function_name = test_name.split("[", 1)[0]
    target = next(
        (
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function_name
        ),
        None,
    )
    if target is None:
        raise IntegrationError(f"Could not find test function {function_name!r}")
    if any(_is_pytest_skip(item) for item in target.decorator_list):
        return source

    lines = source.splitlines(keepends=True)
    indent = re.match(r"\s*", lines[target.lineno - 1]).group(0)  # type: ignore[union-attr]
    decorator = f"{indent}@pytest.mark.skip(reason={json.dumps(reason)})\n"
    lines.insert(target.lineno - 1, decorator)

    if not _imports_pytest(tree):
        insert_at = _import_insertion_line(tree)
        lines.insert(insert_at, "import pytest\n")
        if insert_at + 1 < len(lines) and lines[insert_at + 1].strip():
            lines.insert(insert_at + 1, "\n")
    return "".join(lines)


def _imports_pytest(tree: ast.Module) -> bool:
    return any(
        isinstance(node, ast.Import) and any(alias.name == "pytest" for alias in node.names)
        for node in tree.body
    )


def _is_pytest_skip(node: ast.expr) -> bool:
    return isinstance(node, ast.Call) and "pytest.mark.skip" in ast.unparse(node.func)


def _import_insertion_line(tree: ast.Module) -> int:
    insertion = 0
    body = tree.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        if isinstance(body[0].value.value, str):
            insertion = body[0].end_lineno or body[0].lineno
    for node in body:
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            insertion = node.end_lineno or node.lineno
    return insertion


def _quarantine_branch(plan: ActionPlan) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", plan.test_node_id.lower()).strip("-")[-60:]
    return f"syft/quarantine-{slug}-{plan.action_id[-8:]}"


def _raise_for_status(response: httpx.Response) -> None:
    try:
        response.raise_for_status()
    except httpx.HTTPError as error:
        raise IntegrationError(f"GitHub API returned {response.status_code}: {response.text[:500]}") from error
