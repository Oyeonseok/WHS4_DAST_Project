"""Shared live Validation with explicit legacy database compatibility."""

from .legacy.agent import (
    EvidenceOnlyReviewer,
    ValidationAgent,
    ValidationReviewer,
    load_skill,
    prepare_validation,
    record_validation,
    validate_assessment,
)
from .contracts.models import (
    AttackClaim,
    BlindCase,
    BlindDisclosureError,
    DevelopmentCapability,
    StagedBlindCase,
)
from .execution.browser_adapter import BrowserExecutor, BrowserReproductionPort
from .contracts.browser_contract import (
    BrowserAssertion,
    BrowserAttemptContract,
    BrowserElementSnapshot,
    BrowserObservationSnapshot,
    BrowserRuntimeContract,
    evaluate_browser_observation,
)
from .execution.chain_adapter import ChainReproductionPort
from .contracts.chain_contract import (
    ChainBindingContract,
    ChainRuntimeContract,
    ChainStepContract,
    extract_chain_value,
    inject_chain_value,
)
from .orchestration.coordinator import (
    PolicyProvider,
    ValidationAgentRunner,
    ValidationCoordinator,
    ValidationCoordinatorError,
)
from .orchestration.codex_runner import CodexBlindValidationRunner
from .execution.credentials import KeyringCredentialBackend, PipelineCredentialResolver
from .core.decision import DecisionEngine, DecisionInput
from .contracts.development import (
    DevelopmentActionContract,
    DevelopmentRuntimeContract,
    NativePrerequisiteResolver,
)
from .core.decision import ImpactGapAnalyzer
from .execution.http_adapter import HttpReproductionPort
from .execution.http_oob_observer import HttpJsonOobObserver, HttpOobObserverConfig
from .core.decision import ImpactResult, evaluate_impact
from .core.integrity import (
    CandidateIntegrityError,
    CandidateIntegrityGate,
    ValidatedCandidate,
    canonical_reproduction_spec,
    reproduction_spec_digest,
)
from .legacy.models import (
    PoCAssessment,
    QuestionAnswer,
    ValidationAssessment,
    ValidationError,
)
from .core.matching import (
    KnownCandidate,
    KnownMatch,
    KnownMatcher,
    canonical_payload,
    payload_structure_sha256,
)
from .contracts.models import (
    BlindAssessment,
    ClaimComparison,
    ValidationCaseSnapshot,
    ValidationStageResult,
    canonical_json,
    canonical_sha256,
)
from .orchestration.native import build_native_validation_coordinator
from .execution.oob_adapter import OobObserver, OobReproductionPort
from .contracts.oob_contract import (
    OobAttemptContract,
    OobEvent,
    OobObservationSnapshot,
    OobRuntimeContract,
    evaluate_oob_observation,
)
from .execution.playwright_browser import (
    BrowserExecutionError,
    BrowserPolicyRejection,
    PlaywrightBrowserExecutor,
)
from .core.policy import TargetPolicyProvider
from .core.profiles import (
    ResolvedValidationProfile,
    SkillProfileResolver,
    ValidationProfile,
    ValidationProfileError,
)
from .persistence.repository import (
    ConcurrentValidationUpdate,
    ValidationRepository,
    ValidationRepositoryError,
)
from .contracts.models import (
    PrerequisiteResolverPort,
    ReproductionObservation,
    ReproductionPort,
)
from .execution.request_broker import (
    ValidationPolicyRejection,
    ValidationRequestBroker,
    ValidationRequestError,
)
from .execution.runtime_adapter import RuntimeReproductionRouter
from .contracts.runtime_contract import (
    HttpAttemptContract,
    HttpRequestTemplate,
    HttpRuntimeContract,
    ResponseAssertion,
    evaluate_http_response,
    render_http_request,
    validate_runtime_contract,
)
from .contracts.runtime_semantics import RuntimeSemanticError, validate_runtime_semantics
from .persistence.repository import shared_validation_status
from .legacy.store import read_verified_validation, validation_status

SharedValidationError = ValidationCoordinatorError

__all__ = [
    "AttackClaim",
    "BlindAssessment",
    "BlindCase",
    "BlindDisclosureError",
    "BrowserAssertion",
    "BrowserAttemptContract",
    "BrowserElementSnapshot",
    "BrowserExecutionError",
    "BrowserExecutor",
    "BrowserObservationSnapshot",
    "BrowserPolicyRejection",
    "BrowserReproductionPort",
    "BrowserRuntimeContract",
    "CandidateIntegrityError",
    "CandidateIntegrityGate",
    "ChainBindingContract",
    "ChainReproductionPort",
    "ChainRuntimeContract",
    "ChainStepContract",
    "ClaimComparison",
    "CodexBlindValidationRunner",
    "ConcurrentValidationUpdate",
    "DecisionEngine",
    "DecisionInput",
    "DevelopmentActionContract",
    "DevelopmentCapability",
    "DevelopmentRuntimeContract",
    "EvidenceOnlyReviewer",
    "HttpAttemptContract",
    "HttpJsonOobObserver",
    "HttpOobObserverConfig",
    "HttpReproductionPort",
    "HttpRequestTemplate",
    "HttpRuntimeContract",
    "ImpactGapAnalyzer",
    "ImpactResult",
    "KeyringCredentialBackend",
    "KnownCandidate",
    "KnownMatch",
    "KnownMatcher",
    "NativePrerequisiteResolver",
    "OobAttemptContract",
    "OobEvent",
    "OobObservationSnapshot",
    "OobObserver",
    "OobReproductionPort",
    "OobRuntimeContract",
    "PipelineCredentialResolver",
    "PlaywrightBrowserExecutor",
    "PoCAssessment",
    "PolicyProvider",
    "PrerequisiteResolverPort",
    "QuestionAnswer",
    "ReproductionObservation",
    "ReproductionPort",
    "ResolvedValidationProfile",
    "ResponseAssertion",
    "RuntimeReproductionRouter",
    "RuntimeSemanticError",
    "SharedValidationError",
    "SkillProfileResolver",
    "StagedBlindCase",
    "TargetPolicyProvider",
    "ValidatedCandidate",
    "ValidationAgent",
    "ValidationAgentRunner",
    "ValidationAssessment",
    "ValidationCaseSnapshot",
    "ValidationCoordinator",
    "ValidationCoordinatorError",
    "ValidationError",
    "ValidationPolicyRejection",
    "ValidationProfile",
    "ValidationProfileError",
    "ValidationRepository",
    "ValidationRepositoryError",
    "ValidationRequestBroker",
    "ValidationRequestError",
    "ValidationReviewer",
    "ValidationStageResult",
    "build_native_validation_coordinator",
    "canonical_json",
    "canonical_payload",
    "canonical_reproduction_spec",
    "canonical_sha256",
    "evaluate_browser_observation",
    "evaluate_http_response",
    "evaluate_impact",
    "evaluate_oob_observation",
    "extract_chain_value",
    "inject_chain_value",
    "load_skill",
    "payload_structure_sha256",
    "prepare_validation",
    "read_verified_validation",
    "record_validation",
    "render_http_request",
    "reproduction_spec_digest",
    "shared_validation_status",
    "validate_assessment",
    "validate_runtime_contract",
    "validate_runtime_semantics",
    "validation_status",
]

# Preserve established module paths while implementations live in responsibility packages.
import sys as _sys
from importlib import import_module as _import_module

_COMPAT_MODULES = {
    "agent": "legacy.agent",
    "blind": "contracts.models",
    "browser_adapter": "execution.browser_adapter",
    "browser_contract": "contracts.browser_contract",
    "chain_adapter": "execution.chain_adapter",
    "chain_contract": "contracts.chain_contract",
    "codex_runner": "orchestration.codex_runner",
    "coordinator": "orchestration.coordinator",
    "credentials": "execution.credentials",
    "decision": "core.decision",
    "development": "contracts.development",
    "evidence_policy": "persistence.evidence_policy",
    "gaps": "core.decision",
    "http_adapter": "execution.http_adapter",
    "http_oob_observer": "execution.http_oob_observer",
    "impact": "core.decision",
    "integrity": "core.integrity",
    "matching": "core.matching",
    "models": "contracts.models",
    "native": "orchestration.native",
    "oob_adapter": "execution.oob_adapter",
    "oob_contract": "contracts.oob_contract",
    "playwright_browser": "execution.playwright_browser",
    "policy": "core.policy",
    "profiles": "core.profiles",
    "repository": "persistence.repository",
    "reproduction": "contracts.models",
    "request_broker": "execution.request_broker",
    "runtime_adapter": "execution.runtime_adapter",
    "runtime_contract": "contracts.runtime_contract",
    "runtime_semantics": "contracts.runtime_semantics",
    "source": "persistence.source",
    "status": "persistence.repository",
    "store": "legacy.store",
}
for _old_name, _new_name in _COMPAT_MODULES.items():
    _module = _import_module(f".{_new_name}", __name__)
    _sys.modules[f"{__name__}.{_old_name}"] = _module
    globals()[_old_name] = _module

del _COMPAT_MODULES, _import_module, _module, _new_name, _old_name, _sys
