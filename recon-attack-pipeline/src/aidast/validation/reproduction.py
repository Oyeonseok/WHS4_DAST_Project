"""Execution ports used by the restricted Validation runtime."""

from __future__ import annotations

from typing import Any, Literal, Protocol
from pathlib import Path

from aidast.recon.policy import TargetPolicy

from .blind import BlindCase
from pydantic import Field, model_validator
from typing import Annotated

from .models import BlockerAxis, Digest, SignalType, StrictContract


class ReproductionObservation(StrictContract):
    outcome: Literal["observed", "not_observed", "blocked", "error"]
    signal_type: SignalType
    signal_observed: bool | None
    blocker_axis: BlockerAxis | None = None
    details: dict[str, Any]
    content_sha256: Digest
    content_length: Annotated[int, Field(ge=0, le=200_000)]
    explicit_non_exploit: bool = False
    policy_allowed: bool = True

    @model_validator(mode="after")
    def consistent_outcome(self) -> "ReproductionObservation":
        if self.outcome == "observed" and self.signal_observed is not True:
            raise ValueError("observed outcomes require a positive signal")
        if self.outcome == "not_observed" and self.signal_observed is not False:
            raise ValueError("not_observed outcomes require a negative signal")
        if self.blocker_axis is not None and self.outcome != "blocked":
            raise ValueError("blocker axes are valid only for blocked outcomes")
        if not self.policy_allowed and self.outcome != "blocked":
            raise ValueError("policy rejection must be represented as a blocked outcome")
        if self.explicit_non_exploit and self.signal_observed is not False:
            raise ValueError("non-exploit evidence cannot contain a positive signal")
        return self


class ReproductionPort(Protocol):
    def execute(
        self, blind_case: BlindCase, *, attempt_kind: Literal[
            "target", "positive_control", "negative_control"
        ], batch_no: int, ordinal: int, attempt_id: str, db_path: Path,
        scan_id: str, stage_run_id: str, case_id: str, policy: TargetPolicy,
    ) -> ReproductionObservation: ...


class PrerequisiteResolverPort(Protocol):
    def perform(
        self, blind_case: BlindCase, *, action_type: str, blocker_axis: str,
        contract: Any, action_id: str, db_path: Path, scan_id: str,
        stage_run_id: str, case_id: str, policy: TargetPolicy,
    ) -> dict[str, Any]: ...
