"""Ground-truth case models and JSON loading."""

from pathlib import Path

from pydantic import BaseModel, ConfigDict, TypeAdapter

from syft.models.analysis import Classification


class GroundTruthCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    test: str
    expected: Classification


def load_ground_truth(path: Path) -> list[GroundTruthCase]:
    return TypeAdapter(list[GroundTruthCase]).validate_json(path.read_text(encoding="utf-8"))

