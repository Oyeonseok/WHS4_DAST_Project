"""Small structured contract for bounded UI exploration decisions."""

from __future__ import annotations

from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator


class UIChoice(BaseModel):
    model_config = ConfigDict(extra="forbid")

    candidate_index: int | None = Field(default=None, ge=0, le=100_000)
    goal: str = Field(default="", max_length=240)
    stop: bool = False

    @model_validator(mode="after")
    def require_candidate_for_action(self) -> "UIChoice":
        if not self.stop and self.candidate_index is None:
            raise ValueError("a continuing UI choice requires a candidate index")
        return self


class UIPlanner(Protocol):
    def propose(self, context: dict[str, Any]) -> UIChoice | dict[str, Any]: ...
