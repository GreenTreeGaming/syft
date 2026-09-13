"""Create regression and human-triage issues through Linear GraphQL."""

from __future__ import annotations

import httpx

from syft.agent.models import ActionKind, ActionPlan, ActionResult, ActionStatus
from syft.integrations import IntegrationError


_ISSUE_CREATE = """
mutation SyftIssueCreate($input: IssueCreateInput!) {
  issueCreate(input: $input) {
    success
    issue { id identifier url }
  }
}
"""


class LinearClient:
    def __init__(
        self,
        api_key: str,
        team_id: str,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not api_key or not team_id:
            raise IntegrationError("LINEAR_API_KEY and LINEAR_TEAM_ID are required for --execute")
        self.team_id = team_id
        self._client = httpx.Client(
            base_url="https://api.linear.app",
            headers={"Authorization": api_key, "Content-Type": "application/json"},
            timeout=30.0,
            transport=transport,
        )

    def close(self) -> None:
        self._client.close()

    def create_issue(self, plan: ActionPlan) -> ActionResult:
        if plan.kind not in {ActionKind.REGRESSION_TICKET, ActionKind.TRIAGE_TICKET}:
            raise IntegrationError("Linear adapter received a non-ticket action")
        try:
            response = self._client.post(
                "/graphql",
                json={
                    "query": _ISSUE_CREATE,
                    "variables": {
                        "input": {
                            "teamId": self.team_id,
                            "title": plan.title,
                            "description": plan.body,
                        }
                    },
                },
            )
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as error:
            raise IntegrationError(f"Linear request failed: {error}") from error
        if payload.get("errors"):
            messages = "; ".join(str(item.get("message")) for item in payload["errors"])
            raise IntegrationError(f"Linear GraphQL error: {messages}")
        try:
            created = payload["data"]["issueCreate"]
            issue = created["issue"]
            if not created["success"]:
                raise KeyError("success")
        except (KeyError, TypeError) as error:
            raise IntegrationError("Linear did not return a created issue") from error
        return ActionResult(
            action_id=plan.action_id,
            kind=plan.kind,
            status=ActionStatus.CREATED,
            external_id=str(issue["identifier"]),
            url=str(issue["url"]),
            detail="Linear issue created.",
        )

