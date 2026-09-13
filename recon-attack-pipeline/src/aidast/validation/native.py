"""Construct the trusted native Validation runtime from local pipeline artifacts."""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Mapping

from .coordinator import ValidationCoordinator, ValidationCoordinatorError
from .browser_adapter import BrowserExecutor, BrowserReproductionPort
from .credentials import PipelineCredentialResolver
from .http_adapter import HttpReproductionPort
from .oob_adapter import OobObserver, OobReproductionPort
from .policy import TargetPolicyProvider
from .playwright_browser import PlaywrightBrowserExecutor
from .runtime_adapter import RuntimeReproductionRouter


def build_native_validation_coordinator(
    *, db_path: Path, policy_path: Path,
    credential_resolver: Callable[[str], Mapping[str, str]] | None = None,
    browser_executor: BrowserExecutor | None = None,
    oob_observer: OobObserver | None = None,
) -> ValidationCoordinator:
    """Build the default HTTP runtime; the Codex runner remains lazy per stage."""
    try:
        policy_provider = TargetPolicyProvider(policy_path)
    except (OSError, ValueError) as exc:
        raise ValidationCoordinatorError(f"cannot load current TargetPolicy: {exc}") from exc
    resolver = credential_resolver or PipelineCredentialResolver(db_path)
    reproduction = RuntimeReproductionRouter(
        http=HttpReproductionPort(credential_resolver=resolver),
        browser=BrowserReproductionPort(
            executor=browser_executor or PlaywrightBrowserExecutor(),
            credential_resolver=resolver,
        ),
        oob=OobReproductionPort(
            observer=oob_observer, credential_resolver=resolver,
        ),
    )
    return ValidationCoordinator(
        db_path=db_path,
        agent=None,
        reproduction=reproduction,
        policy_provider=policy_provider,
    )
