"""Attack/Validator/Report의 Codex output schema용 Pydantic 모델.

LLM이 이 스키마에 맞는 JSON을 출력하면, 오케스트레이터가 파싱해서
db.py로 저장한다.

Codex --output-schema (Structured Output) 제약:
- 모든 프로퍼티가 required여야 함
- additionalProperties: false 필수
- Optional 필드는 nullable로 표현 (anyOf [type, null])
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Attack Agent output schema
# ---------------------------------------------------------------------------


class AttackEvidence(BaseModel):
    """LLM이 캡처한 HTTP 요청/응답 증거 1건."""
    model_config = ConfigDict(extra="forbid")
    role: str = Field(description="user_a, user_b, unauthenticated")
    method: str
    url: str
    request_headers: str = Field(default="", description="요청 헤더 (JSON 문자열 또는 raw text)")
    request_body: str = ""
    response_status: int = 0
    response_headers: str = Field(default="", description="응답 헤더 (JSON 문자열 또는 raw text)")
    response_body: str = ""
    response_time_ms: int = 0


class AttackFinding(BaseModel):
    """LLM이 발견한 취약점 1건."""
    model_config = ConfigDict(extra="forbid")
    endpoint_id: str = Field(
        default="", description="recon DB의 endpoint_id. 없으면 빈 문자열"
    )
    vuln_type: str = "IDOR"
    title: str
    description: str
    severity: str = Field(description="CRITICAL / HIGH / MEDIUM / LOW")
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cwe_id: str = "CWE-639"
    evidence: list[AttackEvidence] = Field(default_factory=list)


class AttackResult(BaseModel):
    """Attack Agent의 전체 출력."""
    model_config = ConfigDict(extra="forbid")
    findings: list[AttackFinding] = Field(default_factory=list)
    summary: str = Field(
        default="", description="테스트 요약 (findings이 비어있을 때 특히 중요)"
    )


# ---------------------------------------------------------------------------
# Validator Agent output schema
# ---------------------------------------------------------------------------


class GateDetail(BaseModel):
    """Gate 1개의 판정."""
    model_config = ConfigDict(extra="forbid")
    gate: str = Field(description="G1_reproducibility, G2_authorization_boundary, etc.")
    passed: str = Field(description="true, false, or null (as string)")
    detail: str = ""


class ValidationResult(BaseModel):
    """Validator Agent의 출력."""
    model_config = ConfigDict(extra="forbid")
    finding_id: str
    verdict: str = Field(description="CONFIRMED / REJECTED / INCONCLUSIVE")
    gate_results: list[GateDetail] = Field(default_factory=list)
    reasoning: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


# ---------------------------------------------------------------------------
# Report Agent output schema
# ---------------------------------------------------------------------------


class ReportResult(BaseModel):
    """Report Agent의 출력."""
    model_config = ConfigDict(extra="forbid")
    title: str
    severity: str
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cwe_id: str = "CWE-639"
    report_markdown: str = Field(description="완성된 마크다운 보고서 전문")
