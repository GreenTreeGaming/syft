"""Small, mockable GitHub Actions API client."""

from __future__ import annotations

import io
import os
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict


class GitHubConfigurationError(RuntimeError):
    pass


class GitHubAPIError(RuntimeError):
    pass


class GitHubRun(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: int
    head_sha: str
    name: str | None = None
    conclusion: str | None = None
    created_at: datetime


class DownloadedArtifact(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")

    name: str
    xml_files: list[Path]


class GitHubActionsClient:
    def __init__(
        self,
        token: str,
        repository: str,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not token:
            raise GitHubConfigurationError("GITHUB_TOKEN is required")
        if repository.count("/") != 1:
            raise GitHubConfigurationError("GITHUB_REPOSITORY must have the form owner/repo")
        self.repository = repository
        self._client = httpx.Client(
            base_url="https://api.github.com",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=30.0,
            transport=transport,
        )

    @classmethod
    def from_environment(cls) -> "GitHubActionsClient":
        return cls(
            token=os.getenv("GITHUB_TOKEN", ""),
            repository=os.getenv("GITHUB_REPOSITORY", ""),
        )

    def __enter__(self) -> "GitHubActionsClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def latest_failed_run(self, branch: str = "main") -> GitHubRun:
        runs = self._list_runs(branch=branch, status="failure")
        if not runs:
            raise GitHubAPIError(f"No failed GitHub Actions run found for branch {branch!r}")
        return runs[0]

    def previous_successful_run(self, failed_run: GitHubRun, branch: str = "main") -> GitHubRun | None:
        runs = self._list_runs(branch=branch, status="success")
        eligible = [run for run in runs if run.created_at < failed_run.created_at]
        return max(eligible, key=lambda run: run.created_at, default=None)

    def download_junit_artifact(
        self,
        run_id: int,
        destination: Path,
        artifact_name: str | None = None,
    ) -> DownloadedArtifact:
        payload = self._get_json(f"/repos/{self.repository}/actions/runs/{run_id}/artifacts")
        artifacts = payload.get("artifacts", [])
        candidates = [item for item in artifacts if not item.get("expired", False)]
        if artifact_name:
            candidates = [item for item in candidates if item.get("name") == artifact_name]
        else:
            candidates = [
                item for item in candidates if any(term in item.get("name", "").lower() for term in ("junit", "pytest", "test-results"))
            ]
        if not candidates:
            requested = artifact_name or "a JUnit/pytest/test-results artifact"
            raise GitHubAPIError(f"Could not find {requested} for workflow run {run_id}")

        selected = candidates[0]
        response = self._request("GET", selected["archive_download_url"])
        destination.mkdir(parents=True, exist_ok=True)
        xml_files: list[Path] = []
        try:
            with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
                for member in archive.infolist():
                    if member.is_dir() or not member.filename.lower().endswith(".xml"):
                        continue
                    safe_name = Path(member.filename).name
                    target = destination / safe_name
                    target.write_bytes(archive.read(member))
                    xml_files.append(target)
        except zipfile.BadZipFile as error:
            raise GitHubAPIError("GitHub artifact response was not a valid ZIP file") from error
        if not xml_files:
            raise GitHubAPIError(f"Artifact {selected['name']!r} contained no XML files")
        return DownloadedArtifact(name=selected["name"], xml_files=xml_files)

    def _list_runs(self, *, branch: str, status: str) -> list[GitHubRun]:
        payload = self._get_json(
            f"/repos/{self.repository}/actions/runs",
            params={"branch": branch, "status": status, "per_page": 100},
        )
        return [GitHubRun.model_validate(item) for item in payload.get("workflow_runs", [])]

    def _get_json(self, url: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        response = self._request("GET", url, params=params)
        try:
            payload = response.json()
        except ValueError as error:
            raise GitHubAPIError(f"GitHub returned invalid JSON for {url}") from error
        if not isinstance(payload, dict):
            raise GitHubAPIError(f"GitHub returned an unexpected response for {url}")
        return payload

    def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        try:
            response = self._client.request(method, url, **kwargs)
            response.raise_for_status()
            return response
        except httpx.HTTPError as error:
            raise GitHubAPIError(f"GitHub API request failed: {error}") from error

