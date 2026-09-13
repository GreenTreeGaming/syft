import httpx
import pytest

from syft.agent.models import ActionStatus
from syft.integrations import IntegrationError
from syft.integrations.slack import SlackWebhookClient


def test_posts_digest_to_incoming_webhook() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert b"Syft CI triage" in request.content
        return httpx.Response(200, text="ok")

    client = SlackWebhookClient(
        "https://hooks.slack.com/services/test/value/secret",
        transport=httpx.MockTransport(handler),
    )
    try:
        result = client.post_digest("digest-id", "Syft CI triage")
    finally:
        client.close()
    assert result.status is ActionStatus.CREATED


def test_failure_does_not_expose_webhook_secret() -> None:
    webhook = "https://hooks.slack.com/services/test/value/top-secret"
    client = SlackWebhookClient(
        webhook,
        transport=httpx.MockTransport(lambda request: httpx.Response(500, request=request)),
    )
    try:
        with pytest.raises(IntegrationError) as caught:
            client.post_digest("digest-id", "Syft CI triage")
    finally:
        client.close()

    assert "top-secret" not in str(caught.value)
    assert webhook not in str(caught.value)
