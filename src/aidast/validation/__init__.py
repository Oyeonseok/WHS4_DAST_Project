"""Shared live Validation with explicit legacy database compatibility."""

from .agent import (
    EvidenceOnlyReviewer,
    ValidationAgent,
    ValidationReviewer,
    load_skill,
    prepare_validation,
    record_validation,
    validate_assessment,
)
from .blind import (
    AttackClaim,
    BlindCase,
    BlindDisclosureError,
    DevelopmentCapability,
    StagedBlindCase,
)
from .browser_adapter import BrowserExecutor, BrowserReproductionPort
from .browser_contract import (
    BrowserAssertion,
    BrowserAttemptContract,
    BrowserElementSnapshot,
    BrowserObservationSnapshot,
    BrowserRuntimeContract,
    evaluate_browser_observation,
)
from .chain_adapter import ChainReproductionPort
from .chain_contract import (
    ChainBindingContract,
    ChainRuntimeContract,
    ChainStepContract,
    extract_chain_value,
    inject_chain_value,
)
from .coordinator import (
    PolicyProvider,
    ValidationAgentRunner,
    ValidationCoordinator,
    ValidationCoordinatorError,
)
from .codex_runner import CodexBlindValidationRunner
from .credentials import KeyringCredentialBackend, PipelineCredentialResolver
from .decision import DecisionEngine, DecisionInput
from .development import (
    DevelopmentActionContract,
    DevelopmentRuntimeContract,
    NativePrerequisiteResolver,
)
from .gaps import ImpactGapAnalyzer
from .http_adapter import HttpReproductionPort
from .http_oob_observer import HttpJsonOobObserver, HttpOobObserverConfig
from .impact import ImpactResult, evaluate_impact
from .integrity import (
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
from .matching import (
    KnownCandidate,
    KnownMatch,
    KnownMatcher,
    canonical_payload,
    payload_structure_sha256,
)
from .models import (
    BlindAssessment,
    ClaimComparison,
    ValidationCaseSnapshot,
    ValidationStageResult,
    canonical_json,
    canonical_sha256,
)
from .native import build_native_validation_coordinator
from .oob_adapter import OobObserver, OobReproductionPort
from .oob_contract import (
    OobAttemptContract,
    OobEvent,
    OobObservationSnapshot,
    OobRuntimeContract,
    evaluate_oob_observation,
)
from .playwright_browser import (
    BrowserExecutionError,
    BrowserPolicyRejection,
    PlaywrightBrowserExecutor,
)
from .policy import TargetPolicyProvider
from .profiles import (
    ResolvedValidationProfile,
    SkillProfileResolver,
    ValidationProfile,
    ValidationProfileError,
)
from .repository import (
    ConcurrentValidationUpdate,
    ValidationRepository,
    ValidationRepositoryError,
)
from .reproduction import (
    PrerequisiteResolverPort,
    ReproductionObservation,
    ReproductionPort,
)
from .request_broker import (
    ValidationPolicyRejection,
    ValidationRequestBroker,
    ValidationRequestError,
)
from .runtime_adapter import RuntimeReproductionRouter
from .runtime_contract import (
    HttpAttemptContract,
    HttpRequestTemplate,
    HttpRuntimeContract,
    ResponseAssertion,
    evaluate_http_response,
    render_http_request,
    validate_runtime_contract,
)
from .runtime_semantics import RuntimeSemanticError, validate_runtime_semantics
from .status import shared_validation_status
from .store import read_verified_validation, validation_status

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
