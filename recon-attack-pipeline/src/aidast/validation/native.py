"""Construct the trusted native Validation runtime from local pipeline artifacts."""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Mapping

from .coordinator import ValidationCoordinator, ValidationCoordinatorError
from .credentials import PipelineCredentialResolver
from .http_adapter import HttpReproductionPort
from .policy import TargetPolicyProvider


def build_native_validation_coordinator(
    *, db_path: Path, policy_path: Path,
    credential_resolver: Callable[[str], Mapping[str, str]] | None = None,
) -> ValidationCoordinator:
    """Build the default HTTP runtime; the Codex runner remains lazy per stage."""
    try:
        policy_provider = TargetPolicyProvider(policy_path)
    except (OSError, ValueError) as exc:
        raise ValidationCoordinatorError(f"cannot load current TargetPolicy: {exc}") from exc
    return ValidationCoordinator(
        db_path=db_path,
        agent=None,
        reproduction=HttpReproductionPort(
            credential_resolver=(
                credential_resolver or PipelineCredentialResolver(db_path)
            ),
        ),
        policy_provider=policy_provider,
    )
