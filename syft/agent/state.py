"""Small atomic ledger used to avoid duplicate external actions."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from syft.agent.models import ActionResult, ActionStatus


class ActionLedger:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._data = self._load()

    def completed(self, action_id: str) -> bool:
        action = self._data["actions"].get(action_id)
        return bool(action and action.get("status") in {"CREATED", "ALREADY_EXISTS"})

    def result(self, action_id: str) -> ActionResult | None:
        payload = self._data["actions"].get(action_id)
        return ActionResult.model_validate(payload) if payload else None

    def record(self, result: ActionResult) -> None:
        if result.status not in {ActionStatus.CREATED, ActionStatus.ALREADY_EXISTS}:
            return
        self._data["actions"][result.action_id] = result.model_dump(mode="json")
        self._write()

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"schema_version": "1.0", "actions": {}}
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(f"Could not read agent state {self.path}: {error}") from error
        if not isinstance(payload, dict) or not isinstance(payload.get("actions"), dict):
            raise ValueError(f"Invalid agent state file: {self.path}")
        return payload

    def _write(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self._data, indent=2) + "\n", encoding="utf-8")
        temporary.replace(self.path)

