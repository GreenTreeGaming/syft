"""Post one workflow digest through a Slack incoming webhook."""

from __future__ import annotations

import httpx

from syft.agent.models import ActionKind, ActionResult, ActionStatus
from syft.integrations import IntegrationError


class SlackWebhookClient:
    def __init__(
        self,
        webhook_url: str,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not webhook_url.startswith("https://hooks.slack.com/"):
            raise IntegrationError("SLACK_WEBHOOK_URL must be a Slack HTTPS incoming-webhook URL")
        self.webhook_url = webhook_url
        self._client = httpx.Client(timeout=30.0, transport=transport)

    def close(self) -> None:
        self._client.close()

    def post_digest(self, action_id: str, digest: str) -> ActionResult:
        try:
            response = self._client.post(self.webhook_url, json={"text": digest})
            response.raise_for_status()
        except httpx.HTTPStatusError as error:
            raise IntegrationError(
                f"Slack webhook failed with HTTP {error.response.status_code}"
            ) from error
        except httpx.HTTPError as error:
            raise IntegrationError("Slack webhook request failed") from error
        if response.text.strip() != "ok":
            raise IntegrationError("Slack webhook returned an unexpected response")
        return ActionResult(
            action_id=action_id,
            kind=ActionKind.SLACK_DIGEST,
            status=ActionStatus.CREATED,
            detail="Slack digest posted.",
        )
