"""Create integrity-protected Scope fixtures for the local functional lab."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from aidast.orchestration.scope import CoordinatorError, ScopeCoordinator
from aidast.paths import RESULT_ROOT
from aidast.scope.models import (
    AssetType,
    CaptureReason,
    CaptureStatus,
    ProgramPage,
    ScopeAnalysis,
    ScopeAsset,
    ScopeDocument,
    SourceEvidence,
    RequiredRequestHeader,
    HeaderInput,
    ScopeExecutionRules,
    RequestLimit,
    OptionLimit,
)
from aidast.scope.paths import resolve_scope_directory, validate_scope_artifact_directory


ACTIVE_AUTHORIZATION = (
    "이 로컬 교육용 애플리케이션에 대한 능동 취약점 테스트와 "
    "GET, HEAD, OPTIONS, POST 요청을 허용합니다."
)


@dataclass(frozen=True, slots=True)
class LabScope:
    name: str
    program_url: str
    target_url: str
    description: str
    extra_allowed: tuple[str, ...] = ()


LAB_SCOPES = {
    item.name: item
    for item in (
        LabScope(
            name="juice-shop",
            program_url="https://lab.aidast.invalid/juice-shop",
            target_url="http://127.0.0.1:3001/",
            description="로컬 OWASP Juice Shop 기능 및 탐지 평가 대상",
        ),
        LabScope(
            name="vuln-bank",
            program_url="https://lab.aidast.invalid/vuln-bank",
            target_url="http://127.0.0.1:5001/",
            description="로컬 Commando-X VulnBank 기능 및 탐지 평가 대상",
            extra_allowed=(
                "VulnBank의 /graphql 경로에서 harmless GraphQL introspection을 허용합니다.",
                "VulnBank 자체 컨테이너의 모의 /internal 및 /latest/meta-data 경로를 "
                "대상으로 하는 동일 앱 내부 SSRF 검증을 허용합니다.",
            ),
        ),
    )
}


PROHIBITED = (
    "PUT, PATCH, DELETE 요청을 금지합니다.",
    "서비스 거부, 대량 brute force 및 고동시성 race condition 테스트를 금지합니다.",
    "외부 도메인, 외부 OOB 서비스, 실제 cloud metadata 및 다른 컨테이너 접근을 금지합니다.",
    "관리자 계정 삭제, 계정 정지, 대량 데이터 삭제 및 서버 명령 실행을 금지합니다.",
)

CONSTRAINTS = (
    "requests_per_second는 0.5 이하입니다.",
    "concurrency는 2 이하입니다.",
    "timeout_seconds는 15입니다.",
    "max_depth는 2입니다.",
    "max_requests는 타깃당 500입니다.",
)

NEON_HEADER_QUOTE = (
    "Use a unique header with your HackerOne username "
    "(X-Bug-Bounty:HackerOne-username) in requests to help us identify your testing."
)
NEON_RATE_QUOTE = (
    "Avoid excessive automated scanning; keep requests to 10 per second or lower "
    "to prevent potential service impact."
)
NEON_LOCAL_CAPS = {"max_requests": 500, "concurrency": 1, "timeout_seconds": 15, "max_depth": 2}


def neon_lab_policy(document: ScopeDocument, markdown: str, *, username: str):
    """Compile the local grant; actual scan launch supplies the shared ledger."""
    from aidast.scope.identity_headers import resolve_scope_identity_headers
    from aidast.recon.policy import (
        ApiProbePolicy, PolicyLimits, RestrictionEvidence, TargetPolicy,
        validate_policy_for_target,
    )

    asset = document.analysis.in_scope_assets[0]
    url = urlsplit(asset.asset)
    local_quotes = {item.field: item.source_quote for item in document.analysis.execution_rules.option_limits}
    policy = TargetPolicy(
        scope_id=document.scope_id, policy_id=f"{document.scope_id}_policy",
        asset_type=asset.asset_type, asset=asset.asset,
        allowed_schemes=["http"], allowed_hosts=["127.0.0.1"], allowed_ports=[url.port],
        allowed_methods=["GET", "HEAD", "OPTIONS"],
        attack_allowed_methods=["GET", "HEAD", "OPTIONS", "POST"],
        attack_authorization_mode="active_non_destructive",
        attack_authorization_evidence=ACTIVE_AUTHORIZATION,
        required_identity_headers=resolve_scope_identity_headers(
            document.analysis, hackerone_username=username),
        limits=PolicyLimits(requests_per_second=10, **NEON_LOCAL_CAPS),
        restriction_evidence=[RestrictionEvidence(field="requests_per_second", source_quote=NEON_RATE_QUOTE),
                              *[RestrictionEvidence(field=key, source_quote=value) for key, value in local_quotes.items()]],
        api_probe=ApiProbePolicy(graphql=url.port == 5001, allowed_paths=["/graphql"] if url.port == 5001 else []),
        policy_notes=[*document.analysis.prohibited_activities,
                      "Only the Neon request ceiling and identification header are adapted; "
                      "remaining limits are local experiment settings, not Neon policy."],
    )
    validate_policy_for_target(policy, asset_type=asset.asset_type, asset=asset.asset,
                              scope_markdown=markdown)
    return policy


def prepare_neon_policy_lab(*, source_path: Path, output_root: Path, username: str,
                            approved_by: str, target: str = "all") -> dict[str, Path]:
    """Publish separate, evidence-grounded scopes without changing approved baselines."""
    from aidast.scope.identity_headers import resolve_scope_identity_headers

    source_path = Path(source_path)
    source = ScopeDocument.model_validate_json(source_path.read_text(encoding="utf-8"))
    for value in (source.source.requested_url, source.source.final_url):
        url = urlsplit(str(value))
        if url.scheme != "https" or url.hostname != "hackerone.com" or url.path.rstrip("/") not in {
            "/neon_bbp", "/neon_bbp/policy_scopes",
        }:
            raise ValueError("policy source must be a captured official Neon program page")
    if (source_path.parent / "Approval.json").exists():
        ScopeCoordinator(source_path.parent).load_approved_scope()
    for quote in (NEON_HEADER_QUOTE, NEON_RATE_QUOTE):
        if quote not in source.source.text:
            raise ValueError("captured Neon policy does not contain the exact supported control")
    if not approved_by.strip():
        raise ValueError("approved_by must not be blank")
    names = list(LAB_SCOPES) if target == "all" else [target]
    prepared = []
    for name in names:
        original = LAB_SCOPES[name]
        local = replace(original, name=f"neon-policy-{name}",
                        program_url=f"https://lab.aidast.invalid/neon-policy-{name}",
                        description=original.description + " — Neon common-control experiment")
        document = _document(local)
        quotes = {key: f"Local experiment: {key} = {value}; this is not a Neon program requirement."
                  for key, value in NEON_LOCAL_CAPS.items()}
        text = "\n".join([
            "AI DAST local lab authorization record. Local experiment, not a Neon target authorization.",
            f"Canonical asset: {local.target_url}", ACTIVE_AUTHORIZATION, *local.extra_allowed,
            *PROHIBITED, f"Adapted policy source: {source.source.final_url}",
            f"Captured source content SHA-256: {source.source.content_sha256}",
            NEON_HEADER_QUOTE, NEON_RATE_QUOTE, *quotes.values(),
        ])
        document.source = ProgramPage.model_validate(document.source.model_dump() | {
            "text": text, "content_sha256": hashlib.sha256(text.encode()).hexdigest(),
        })
        document.analysis = ScopeAnalysis.model_validate(document.analysis.model_dump() | {
            "program_name": f"Local Lab — Neon policy — {name}",
            "operational_constraints": [NEON_HEADER_QUOTE, NEON_RATE_QUOTE, *quotes.values()],
            "required_request_headers": [RequiredRequestHeader(
                name="X-Bug-Bounty", value_template="{hackerone_username}",
                inputs=[HeaderInput(key="hackerone_username", label="HackerOne username", kind="username")],
                source_quote=NEON_HEADER_QUOTE)],
            "execution_rules": ScopeExecutionRules(
                policy_review_version=2, exclusions=[],
                request_limits=[RequestLimit(maximum=10, period_seconds=1.0, scope="program", source_quote=NEON_RATE_QUOTE)],
                option_limits=[OptionLimit(field=key, value=value, source_quote=quotes[key]) for key, value in NEON_LOCAL_CAPS.items()]),
            "source_evidence": [*document.analysis.source_evidence,
                SourceEvidence(section="Adapted Neon identification header", quote=NEON_HEADER_QUOTE),
                SourceEvidence(section="Adapted Neon request ceiling", quote=NEON_RATE_QUOTE),
                *[SourceEvidence(section="Local experiment setting", quote=value) for value in quotes.values()]],
        })
        ScopeCoordinator._require_grounded_analysis(document.source, document.analysis)
        resolve_scope_identity_headers(document.analysis, hackerone_username=username)
        markdown = ScopeCoordinator._render_markdown(document)
        policy = neon_lab_policy(document, markdown, username=username)
        destination = validate_scope_artifact_directory(
            resolve_scope_directory(local.program_url, output_root).absolute(), Path(output_root).absolute())
        provenance = {
            "profile": "neon-common", "source_url": str(source.source.final_url),
            "source_captured_at": source.source.captured_at.isoformat(),
            "source_content_sha256": source.source.content_sha256,
            "adapted_controls": {"requests_per_second": {"maximum": 10, "period_seconds": 1.0, "source_quote": NEON_RATE_QUOTE},
                                 "required_identity_header": {"name": "X-Bug-Bounty", "source_quote": NEON_HEADER_QUOTE}},
            "local_experiment_controls": NEON_LOCAL_CAPS,
        }
        bundle = {"schema_version": "1.0", "scope_id": document.scope_id,
                  "policies": [policy.model_dump(mode="json")]}
        if destination.exists():
            existing, _ = ScopeCoordinator(destination).load_approved_scope()
            if existing.analysis != document.analysis or existing.source.text != document.source.text:
                raise ValueError(f"existing experiment Scope has different policy or provenance: {destination}")
            for filename, expected in [("TargetPolicy.json", bundle), ("LabPolicyProvenance.json", provenance)]:
                if json.loads((destination / filename).read_text()) != expected:
                    raise ValueError(f"existing experiment {filename} has different policy or identity")
        prepared.append((name, destination, document, bundle, provenance))
    # Check every existing destination before publishing any new profile.
    for _, destination, document, bundle, provenance in prepared:
        if destination.exists():
            continue
        coordinator = ScopeCoordinator(destination)
        staging = coordinator._create_scope_draft(document)
        try:
            for filename, value in [("TargetPolicy.json", bundle), ("LabPolicyProvenance.json", provenance)]:
                path = staging / filename
                path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                path.chmod(0o600)
            coordinator._publish_scope(staging, document, approved_by.strip())
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        coordinator.load_approved_scope()
    return {name: destination for name, destination, *_ in prepared}


def _document(scope: LabScope) -> ScopeDocument:
    allowed = (ACTIVE_AUTHORIZATION, *scope.extra_allowed)
    source_lines = (
        "AI DAST local lab authorization record.",
        f"Canonical asset: {scope.target_url}",
        *allowed,
        *PROHIBITED,
        *CONSTRAINTS,
    )
    source_text = "\n".join(source_lines)
    captured_at = datetime.now(timezone.utc)
    return ScopeDocument(
        scope_id=f"scope_local_lab_{scope.name.replace('-', '_')}",
        created_at=captured_at,
        source=ProgramPage(
            requested_url=scope.program_url,
            final_url=scope.program_url,
            title=f"AI DAST Local Lab: {scope.name}",
            captured_at=captured_at,
            capture_status=CaptureStatus.COMPLETE,
            capture_reason=CaptureReason.NONE,
            content_sha256=hashlib.sha256(source_text.encode("utf-8")).hexdigest(),
            text=source_text,
        ),
        analysis=ScopeAnalysis(
            program_name=f"AI DAST Local Lab: {scope.name}",
            program_description=scope.description,
            in_scope_assets=[
                ScopeAsset(
                    asset_type=AssetType.URL,
                    asset=scope.target_url,
                    description=scope.description,
                    eligibility="eligible",
                    maximum_severity="critical",
                )
            ],
            out_of_scope_assets=[],
            allowed_activities=list(allowed),
            prohibited_activities=list(PROHIBITED),
            submission_requirements=[
                "모든 finding은 로컬 evidence와 재현 절차를 포함해야 합니다."
            ],
            operational_constraints=list(CONSTRAINTS),
            safe_harbor="이 승인 기록은 위 loopback 자산의 로컬 교육용 평가에만 적용됩니다.",
            ambiguities=[],
            source_evidence=[
                SourceEvidence(section="Canonical asset", quote=scope.target_url),
                SourceEvidence(section="Active testing", quote=ACTIVE_AUTHORIZATION),
                SourceEvidence(section="External access", quote=PROHIBITED[2]),
            ],
        ),
    )


def _publish(scope: LabScope, *, output_root: Path, approved_by: str) -> Path:
    destination = resolve_scope_directory(scope.program_url, output_root)
    coordinator = ScopeCoordinator(destination)
    expected = _document(scope)
    if destination.exists():
        existing, _ = coordinator.load_approved_scope()
        if existing.analysis.in_scope_assets != expected.analysis.in_scope_assets:
            raise CoordinatorError(
                f"existing local Scope has a different target: {destination}"
            )
        print(f"Verified existing local Scope: {destination}")
        return destination

    # Reuse the production draft/publish path so the fixture has the same
    # manifest, approval, file-mode and atomic-publication contract.
    staging = coordinator._create_scope_draft(expected)
    try:
        coordinator._publish_scope(staging, expected, approved_by)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    coordinator.load_approved_scope()
    print(f"Published local Scope: {destination}")
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target",
        choices=("all", *LAB_SCOPES),
        default="all",
        help="local Scope fixture to create (default: all)",
    )
    parser.add_argument("--output-dir", type=Path, default=RESULT_ROOT / "Scope")
    parser.add_argument("--approved-by", default="local-lab-operator")
    parser.add_argument("--policy-profile", choices=("baseline", "neon-common"), default="baseline")
    parser.add_argument("--policy-source", type=Path,
                        default=RESULT_ROOT / "Scope/hackerone/neon_bbp/Scope.json")
    parser.add_argument("--hackerone-username", help="Identity value for the Neon X-Bug-Bounty header")
    args = parser.parse_args()
    if not args.approved_by.strip():
        parser.error("--approved-by must not be blank")

    if args.policy_profile == "neon-common":
        if not args.hackerone_username:
            parser.error("--hackerone-username is required for the neon-common profile")
        outputs = prepare_neon_policy_lab(
            source_path=args.policy_source, output_root=args.output_dir,
            username=args.hackerone_username, approved_by=args.approved_by, target=args.target)
        for directory in outputs.values():
            print(f"Verified Neon-policy local Scope: {directory}")
        return 0

    selected = LAB_SCOPES.values() if args.target == "all" else (LAB_SCOPES[args.target],)
    for scope in selected:
        _publish(
            scope,
            output_root=args.output_dir,
            approved_by=args.approved_by.strip(),
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
