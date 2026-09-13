from pathlib import Path

from syft.agent.models import ActionKind, ActionResult, ActionStatus
from syft.agent.state import ActionLedger


def test_ledger_persists_only_successful_external_actions(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    ledger = ActionLedger(path)
    created = ActionResult(
        action_id="created",
        kind=ActionKind.REGRESSION_TICKET,
        status=ActionStatus.CREATED,
        external_id="ENG-1",
        detail="created",
    )
    failed = ActionResult(
        action_id="failed",
        kind=ActionKind.TRIAGE_TICKET,
        status=ActionStatus.FAILED,
        detail="failed",
    )
    ledger.record(created)
    ledger.record(failed)
    reloaded = ActionLedger(path)
    assert reloaded.completed("created") is True
    assert reloaded.completed("failed") is False
    assert reloaded.result("created") == created

