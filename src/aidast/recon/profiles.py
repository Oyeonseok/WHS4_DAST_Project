"""Shared execution-profile caps for CLI and WebUI launches."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field

ProfileId = Literal["safe-recon", "focused-discovery"]


class ProfileCaps(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    requests_per_second: float = Field(gt=0, le=50)
    concurrency: int = Field(ge=1, le=20)
    timeout_seconds: int = Field(ge=1, le=120)
    max_depth: int = Field(ge=0, le=10)
    max_requests: int = Field(ge=1, le=100_000)


EXECUTION_PROFILES: Final[Mapping[ProfileId, ProfileCaps]] = MappingProxyType(
    {
        "safe-recon": ProfileCaps(
            requests_per_second=0.5,
            concurrency=2,
            timeout_seconds=15,
            max_depth=2,
            max_requests=500,
        ),
        "focused-discovery": ProfileCaps(
            requests_per_second=1.0,
            concurrency=3,
            timeout_seconds=20,
            max_depth=3,
            max_requests=2000,
        ),
    }
)
