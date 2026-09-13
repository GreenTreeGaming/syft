from datetime import datetime, timezone
import io
import zipfile
from pathlib import Path

import httpx

from syft.deterministic.github_runs import GitHubActionsClient, GitHubRun


def test_latest_failed_run_uses_github_api() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["branch"] == "main"
        assert request.url.params["status"] == "failure"
        return httpx.Response(
            200,
            json={
                "workflow_runs": [
                    {"id": 42, "head_sha": "abc", "name": "CI", "conclusion": "failure", "created_at": "2026-01-02T00:00:00Z"}
                ]
            },
        )

    client = GitHubActionsClient("token", "owner/repo", transport=httpx.MockTransport(handler))
    try:
        assert client.latest_failed_run().id == 42
    finally:
        client.close()


def test_latest_failed_run_or_none_handles_green_branch() -> None:
    client = GitHubActionsClient(
        "token",
        "owner/repo",
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, json={"workflow_runs": []})
        ),
    )
    try:
        assert client.latest_failed_run_or_none("main") is None
    finally:
        client.close()


def test_selects_success_before_failure() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "workflow_runs": [
                    {"id": 1, "head_sha": "new", "created_at": "2026-01-03T00:00:00Z"},
                    {"id": 2, "head_sha": "green", "created_at": "2026-01-01T00:00:00Z"},
                ]
            },
        )

    failed = GitHubRun(id=9, head_sha="bad", created_at=datetime(2026, 1, 2, tzinfo=timezone.utc))
    client = GitHubActionsClient("token", "owner/repo", transport=httpx.MockTransport(handler))
    try:
        assert client.previous_successful_run(failed).head_sha == "green"
    finally:
        client.close()


def test_downloads_only_xml_from_artifact(tmp_path: Path) -> None:
    archive_bytes = io.BytesIO()
    with zipfile.ZipFile(archive_bytes, "w") as archive:
        archive.writestr("nested/junit.xml", "<testsuite />")
        archive.writestr("notes.txt", "ignore")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/artifacts"):
            return httpx.Response(
                200,
                json={
                    "artifacts": [
                        {
                            "name": "pytest-junit",
                            "expired": False,
                            "archive_download_url": "https://api.github.com/artifact.zip",
                        }
                    ]
                },
            )
        return httpx.Response(200, content=archive_bytes.getvalue())

    client = GitHubActionsClient("token", "owner/repo", transport=httpx.MockTransport(handler))
    try:
        result = client.download_junit_artifact(42, tmp_path)
        assert result.name == "pytest-junit"
        assert result.xml_files == [tmp_path / "junit.xml"]
        assert result.xml_files[0].read_text() == "<testsuite />"
    finally:
        client.close()
