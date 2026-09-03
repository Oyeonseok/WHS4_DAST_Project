"""Attack → Validator → Report 파이프라인 오케스트레이터.

Recon 완료 후 호출된다. Codex Agent를 순차적으로 생성하여:
1. IDOR 공격 실행 → findings JSON 수신 → DB 저장
2. 각 finding을 Validator에 전달 → verdict JSON 수신 → DB 저장
3. CONFIRMED finding을 Report에 전달 → 보고서 JSON 수신 → 파일 저장

LLM은 DB를 직접 건드리지 않는다. 모든 DB 저장은 이 오케스트레이터가 한다.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path

from aidast.agents.main import CodexMainAgent, MainAgentError
from aidast.attack import db as attackdb
from aidast.attack.models import (
    AttackResult,
    ReportResult,
    ValidationResult,
)

logger = logging.getLogger(__name__)


class AttackCoordinatorError(RuntimeError):
    pass


class AttackCoordinator:
    """Attack → Validator → Report 전체 파이프라인을 오케스트레이션한다."""

    def __init__(
        self,
        *,
        agent: CodexMainAgent,
        conn: sqlite3.Connection,
        scope_dir: Path,
        report_dir: Path | None = None,
    ) -> None:
        self._agent = agent
        self._conn = conn
        self._scope_dir = Path(scope_dir)
        self._report_dir = Path(report_dir) if report_dir else Path("reports")

    def run(self, scan_id: str) -> list[str]:
        """전체 파이프라인을 실행하고, confirmed finding_id 목록을 반환한다."""
        attackdb.init_attack_tables(self._conn)

        scope_markdown = self._load_scope()
        recon_data = self._load_recon_data(scan_id)

        # Phase 1: Attack
        logger.info("=== Phase 1: IDOR Attack ===")
        attack_result = self._run_attack(scan_id, recon_data, scope_markdown)

        if not attack_result.findings:
            logger.info("Finding 없음: %s", attack_result.summary)
            return []

        logger.info("Finding %d개 발견", len(attack_result.findings))

        # Phase 2: Validate each finding
        confirmed_ids: list[str] = []
        for finding in attack_result.findings:
            finding_id = attackdb.save_finding_with_evidence(
                self._conn,
                scan_id=scan_id,
                finding=finding.model_dump(),
                evidence=[e.model_dump() for e in finding.evidence],
            )
            logger.info("Finding 저장: %s — %s", finding_id, finding.title)

            # Validate
            logger.info("=== Phase 2: Validating %s ===", finding_id)
            verdict = self._run_validator(
                finding_id, finding, scope_markdown, scan_id
            )

            attackdb.save_validation(
                self._conn,
                finding_id=finding_id,
                validation=verdict.model_dump(),
            )
            logger.info(
                "Validation: %s → %s (%.2f)",
                finding_id, verdict.verdict, verdict.confidence,
            )

            if verdict.verdict == "CONFIRMED":
                confirmed_ids.append(finding_id)

        # Phase 3: Report for confirmed findings
        for finding_id in confirmed_ids:
            logger.info("=== Phase 3: Report for %s ===", finding_id)
            self._run_report(finding_id, scope_markdown)

        logger.info(
            "파이프라인 완료: %d findings, %d confirmed",
            len(attack_result.findings), len(confirmed_ids),
        )
        return confirmed_ids

    # ------------------------------------------------------------------
    # Phase 1: Attack
    # ------------------------------------------------------------------

    def _run_attack(
        self,
        scan_id: str,
        recon_data: str,
        scope_markdown: str,
    ) -> AttackResult:
        prompt = self._build_attack_prompt(scan_id, recon_data, scope_markdown)
        return self._agent._run_attack_agent(
            prompt=prompt,
            model_type=AttackResult,
            artifact_name="idor-hunt",
            operation="IDOR Hunt",
            native_skill=("aidast.skills.attack.idor", "aidast-hunt-idor"),
        )

    # ------------------------------------------------------------------
    # Phase 2: Validator
    # ------------------------------------------------------------------

    def _run_validator(
        self,
        finding_id: str,
        finding,
        scope_markdown: str,
        scan_id: str,
    ) -> ValidationResult:
        # 기존 confirmed findings 목록 (중복 확인용)
        existing = attackdb.get_findings_by_scan(
            self._conn, scan_id, status="confirmed"
        )

        evidence = attackdb.get_attack_requests(self._conn, finding_id)

        # Attack Agent가 토큰을 마스킹하므로, recon DB에서 실제 세션 토큰을 가져온다
        sessions = self._load_sessions(scan_id)

        prompt = self._build_validator_prompt(
            finding_id, finding, evidence, scope_markdown, existing, sessions
        )
        return self._agent._run_attack_agent(
            prompt=prompt,
            model_type=ValidationResult,
            artifact_name="validation",
            operation="Validation",
            native_skill=("aidast.skills.validator", "aidast-validator"),
        )

    # ------------------------------------------------------------------
    # Phase 3: Report
    # ------------------------------------------------------------------

    def _run_report(self, finding_id: str, scope_markdown: str) -> None:
        finding = attackdb.get_finding(self._conn, finding_id)
        evidence = attackdb.get_attack_requests(self._conn, finding_id)
        validation = attackdb.get_validation(self._conn, finding_id)

        prompt = self._build_report_prompt(
            finding, evidence, validation, scope_markdown
        )
        report = self._agent._run_attack_agent(
            prompt=prompt,
            model_type=ReportResult,
            artifact_name="report",
            operation="Report Generation",
            native_skill=("aidast.skills.report", "aidast-report"),
            model_override=self._agent._report_model,
        )

        # 보고서 파일 저장
        self._report_dir.mkdir(parents=True, exist_ok=True)
        report_path = self._report_dir / f"{finding_id}_report.md"
        report_path.write_text(report.report_markdown, encoding="utf-8")
        logger.info("Report 저장: %s", report_path)

    # ------------------------------------------------------------------
    # 데이터 로드
    # ------------------------------------------------------------------

    def _load_scope(self) -> str:
        scope_md = self._scope_dir / "Scope.md"
        if not scope_md.exists():
            raise AttackCoordinatorError(
                f"Scope.md not found: {scope_md}"
            )
        return scope_md.read_text(encoding="utf-8")

    def _load_sessions(self, scan_id: str) -> list[dict]:
        """Recon DB에서 실제 세션 토큰을 가져온다.
        Attack Agent가 토큰을 마스킹하므로 Validator에 원본을 전달해야 한다."""
        self._conn.row_factory = sqlite3.Row
        rows = self._conn.execute(
            """
            SELECT s.target, s.auth_state
            FROM sessions s
            JOIN origins o ON s.origin_id = o.origin_id
            JOIN assets a ON o.asset_id = a.asset_id
            WHERE a.scan_id = ?
            """,
            (scan_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def _load_recon_data(self, scan_id: str) -> str:
        """Recon DB에서 attack에 필요한 데이터를 JSON으로 추출한다."""
        self._conn.row_factory = sqlite3.Row

        # endpoints + parameters
        endpoints = self._conn.execute(
            """
            SELECT e.endpoint_id, e.origin_id, e.method, e.path,
                   e.normalized_path, e.auth_required, e.is_excluded,
                   o.base_url
            FROM endpoints e
            JOIN origins o ON e.origin_id = o.origin_id
            JOIN assets a ON o.asset_id = a.asset_id
            WHERE a.scan_id = ? AND e.is_excluded = 0
            """,
            (scan_id,),
        ).fetchall()

        endpoint_data = []
        for ep in endpoints:
            ep_dict = dict(ep)
            params = self._conn.execute(
                """
                SELECT name, location, data_type, example_value, is_identifier
                FROM parameters WHERE endpoint_id = ?
                """,
                (ep["endpoint_id"],),
            ).fetchall()
            ep_dict["parameters"] = [dict(p) for p in params]
            endpoint_data.append(ep_dict)

        # sessions
        sessions = self._conn.execute(
            """
            SELECT s.session_id, s.origin_id, s.target, s.auth_state
            FROM sessions s
            JOIN origins o ON s.origin_id = o.origin_id
            JOIN assets a ON o.asset_id = a.asset_id
            WHERE a.scan_id = ?
            """,
            (scan_id,),
        ).fetchall()

        recon = {
            "endpoints": endpoint_data,
            "sessions": [dict(s) for s in sessions],
        }
        return json.dumps(recon, ensure_ascii=False, indent=2)

    # ------------------------------------------------------------------
    # 프롬프트 빌더
    # ------------------------------------------------------------------

    @staticmethod
    def _build_attack_prompt(
        scan_id: str, recon_data: str, scope_markdown: str
    ) -> str:
        return f"""$aidast-hunt-idor

You are the IDOR hunting agent. Follow the aidast-hunt-idor Skill.

Scan ID: {scan_id}

<approved_scope>
{scope_markdown}
</approved_scope>

<recon_data>
{recon_data}
</recon_data>

Analyze the recon data, select IDOR candidates, send HTTP requests using curl,
analyze responses, and return findings as the structured JSON required by the
output schema. If no IDOR is found, return empty findings with a summary.
"""

    @staticmethod
    def _build_validator_prompt(
        finding_id: str,
        finding,
        evidence: list[dict],
        scope_markdown: str,
        existing_confirmed: list[dict],
        sessions: list[dict] | None = None,
    ) -> str:
        finding_json = (
            finding.model_dump_json(indent=2)
            if hasattr(finding, "model_dump_json")
            else json.dumps(finding, ensure_ascii=False, indent=2)
        )
        sessions_block = ""
        if sessions:
            sessions_block = f"""
<session_credentials>
The attack evidence may contain redacted tokens. Use these ACTUAL session
credentials from the database when re-executing curl requests for Gate 1.
{json.dumps(sessions, ensure_ascii=False, indent=2)}
</session_credentials>
"""
        return f"""$aidast-validator

You are the validation agent. Follow the aidast-validator Skill.
Validate finding {finding_id} using the 7 Gate Question framework.

<finding>
{finding_json}
</finding>

<evidence>
{json.dumps(evidence, ensure_ascii=False, indent=2)}
</evidence>
{sessions_block}
<approved_scope>
{scope_markdown}
</approved_scope>

<existing_confirmed_findings>
{json.dumps(existing_confirmed, ensure_ascii=False, indent=2)}
</existing_confirmed_findings>

Re-execute the attack requests using curl to verify reproducibility (Gate 1).
If evidence contains redacted tokens like [REDACTED_USER_A_TOKEN], use the
actual tokens from <session_credentials> instead.
Analyze all evidence for the remaining gates. Return the validation result
as the structured JSON required by the output schema.
"""

    @staticmethod
    def _build_report_prompt(
        finding: dict | None,
        evidence: list[dict],
        validation: dict | None,
        scope_markdown: str,
    ) -> str:
        return f"""$aidast-report

You are the report writer. Follow the aidast-report Skill.
Generate a bug bounty submission report for this confirmed finding.

<finding>
{json.dumps(finding, ensure_ascii=False, indent=2)}
</finding>

<evidence>
{json.dumps(evidence, ensure_ascii=False, indent=2)}
</evidence>

<validation>
{json.dumps(validation, ensure_ascii=False, indent=2)}
</validation>

<approved_scope>
{scope_markdown}
</approved_scope>

Write the report using ACTUAL values from the evidence. Return the result
as the structured JSON required by the output schema.
"""
