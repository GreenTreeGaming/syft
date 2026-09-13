import httpx

from syft.agent.models import ActionStatus
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

