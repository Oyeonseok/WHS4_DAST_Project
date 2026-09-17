"""Construct the trusted native Validation runtime from local pipeline artifacts."""

from __future__ import annotations

from pathlib import Path
from typing import Callable, Mapping

from .coordinator import ValidationCoordinator, ValidationCoordinatorError
from ..execution.browser_adapter import BrowserExecutor, BrowserReproductionPort
from ..execution.chain_adapter import ChainReproductionPort
from ..execution.credentials import PipelineCredentialResolver
from ..execution.http_adapter import HttpReproductionPort
from ..execution.http_oob_observer import HttpJsonOobObserver
from ..execution.oob_adapter import OobObserver, OobReproductionPort
from ..core.policy import TargetPolicyProvider
from ..execution.playwright_browser import PlaywrightBrowserExecutor
from ..contracts.models import PrerequisiteResolverPort
from ..execution.runtime_adapter import RuntimeReproductionRouter
from ..contracts.development import NativePrerequisiteResolver
from ..execution.native_impact import NativeImpactDevelopmentPort


def build_native_validation_coordinator(
    *, db_path: Path, policy_path: Path,
    credential_resolver: Callable[[str], Mapping[str, str]] | None = None,
    credential_backends: Mapping[str, Callable[[str], object]] | None = None,
    browser_executor: BrowserExecutor | None = None,
    oob_observer: OobObserver | None = None,
    prerequisite_resolver: PrerequisiteResolverPort | None = None,
    development_transport: Callable | None = None,
    impact_development_port: Callable | None = None,
    impact_agent_factory: Callable[[str], object] | None = None,
) -> ValidationCoordinator:
    """Build the default HTTP runtime; the Codex runner remains lazy per stage."""
    try:
        policy_provider = TargetPolicyProvider(policy_path)
    except (OSError, ValueError) as exc:
        raise ValidationCoordinatorError(f"cannot load current TargetPolicy: {exc}") from exc
    resolver = credential_resolver or PipelineCredentialResolver(
        db_path, backends=credential_backends,
    )
    try:
        observer = oob_observer or HttpJsonOobObserver.from_environment()
    except (TypeError, ValueError) as exc:
        raise ValidationCoordinatorError(f"cannot load OOB observer config: {exc}") from exc
    browser_port = BrowserReproductionPort(
        executor=browser_executor or PlaywrightBrowserExecutor(),
        credential_resolver=resolver,
    )
    oob_port = OobReproductionPort(
        observer=observer, credential_resolver=resolver,
    )
    reproduction = RuntimeReproductionRouter(
        http=HttpReproductionPort(credential_resolver=resolver),
        browser=browser_port, oob=oob_port,
        chain=ChainReproductionPort(
            credential_resolver=resolver, browser=browser_port, oob=oob_port,
        ),
    )
    return ValidationCoordinator(
        db_path=db_path,
        agent=None,
        reproduction=reproduction,
        policy_provider=policy_provider,
        impact_development_port=(
            impact_development_port
            if impact_development_port is not None
            else NativeImpactDevelopmentPort(
                credential_resolver=resolver,
                transport=development_transport,
                policy_provider=policy_provider,
            )
        ),
        impact_agent_factory=impact_agent_factory,
        prerequisite_resolver=(
            prerequisite_resolver
            if prerequisite_resolver is not None
            else NativePrerequisiteResolver(
                credential_resolver=resolver, transport=development_transport,
                policy_provider=policy_provider,
            )
        ),
    )
