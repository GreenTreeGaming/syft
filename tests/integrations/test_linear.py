import httpx
import pytest

from syft.agent.explainer import TemplateExplainer
from syft.agent.router import build_action_plans
from syft.integrations import IntegrationError
from syft.integrations.linear import LinearClient
from syft.models.analysis import WorkflowAnalysis


def test_creates_linear_issue(workflow_analysis: WorkflowAnalysis) -> None:
    plan = build_action_plans(workflow_analysis, TemplateExplainer())[1]

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "linear-key"
        return httpx.Response(
            200,
            json={
                "data": {
                    "issueCreate": {
                        "success": True,
                        "issue": {"id": "uuid", "identifier": "ENG-42", "url": "https://linear.app/ENG-42"},
                    }
                }
            },
        )

    client = LinearClient("linear-key", "team-id", transport=httpx.MockTransport(handler))
    try:
        result = client.create_issue(plan)
    finally:
        client.close()
    assert result.external_id == "ENG-42"
    assert result.url == "https://linear.app/ENG-42"


def test_surfaces_graphql_errors(workflow_analysis: WorkflowAnalysis) -> None:
    plan = build_action_plans(workflow_analysis, TemplateExplainer())[1]
    transport = httpx.MockTransport(
        lambda _: httpx.Response(200, json={"errors": [{"message": "team not found"}]})
    )
    client = LinearClient("linear-key", "team-id", transport=transport)
    try:
        with pytest.raises(IntegrationError, match="team not found"):
            client.create_issue(plan)
    finally:
        client.close()

