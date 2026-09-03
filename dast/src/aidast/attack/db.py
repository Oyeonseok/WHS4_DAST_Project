"""Attack/Validator 전용 DB 스키마와 헬퍼.

Recon DB(recon/db.py)와 같은 SQLite 파일을 공유하되, 기존 테이블은
절대 건드리지 않고 새 테이블 3개만 추가한다:
  - findings: 취약점 발견 기록
  - attack_requests: 공격 시 보낸 요청/응답 증거
  - validations: 7 Gate Question 판정 결과

오케스트레이터가 LLM 결과 JSON을 받아서 이 헬퍼들로 DB에 저장한다.
LLM은 DB를 직접 건드리지 않는다.
"""

from __future__ import annotations

import json
import sqlite3

from aidast.recon.db import new_id, now

# 응답 본문 최대 저장 길이. 증거로 충분한 양만 남긴다.
MAX_BODY_STORE = 10_000


ATTACK_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    endpoint_id TEXT,
    vuln_type TEXT NOT NULL,
    severity TEXT,
    title TEXT NOT NULL,
    description TEXT,
    cvss_score REAL,
    cvss_vector TEXT,
    cwe_id TEXT,
    status TEXT DEFAULT 'pending',
    found_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id),
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(endpoint_id)
);

CREATE TABLE IF NOT EXISTS attack_requests (
    request_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    role TEXT NOT NULL,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    request_headers TEXT,
    request_body TEXT,
    response_status INTEGER,
    response_headers TEXT,
    response_body TEXT,
    response_time_ms INTEGER,
    sent_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
);

CREATE TABLE IF NOT EXISTS validations (
    validation_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    verdict TEXT NOT NULL,
    gate_results TEXT,
    reasoning TEXT,
    confidence REAL,
    validated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_endpoint_id ON findings(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_attack_requests_finding_id ON attack_requests(finding_id);
CREATE INDEX IF NOT EXISTS idx_validations_finding_id ON validations(finding_id);
"""


def init_attack_tables(conn: sqlite3.Connection) -> None:
    """기존 recon DB 연결에 attack 테이블을 추가한다."""
    conn.executescript(ATTACK_SCHEMA)
    conn.commit()


def _truncate(text: str | None) -> str | None:
    """응답 본문을 최대 길이로 자른다."""
    if text and len(text) > MAX_BODY_STORE:
        return text[:MAX_BODY_STORE] + "\n... (truncated)"
    return text


# ---------------------------------------------------------------------------
# findings
# ---------------------------------------------------------------------------


def save_finding_with_evidence(
    conn: sqlite3.Connection,
    *,
    scan_id: str,
    finding: dict,
    evidence: list[dict],
) -> str:
    """finding 1개 + attack_requests N개를 하나의 트랜잭션으로 저장한다.

    오케스트레이터가 LLM 출력 JSON을 파싱한 뒤 이 함수를 호출한다.
    """
    finding_id = new_id("finding")
    conn.execute(
        """INSERT INTO findings
           (finding_id, scan_id, endpoint_id, vuln_type, severity, title,
            description, cvss_score, cvss_vector, cwe_id, found_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            finding_id,
            scan_id,
            finding.get("endpoint_id"),
            finding.get("vuln_type", "IDOR"),
            finding.get("severity"),
            finding.get("title", "Untitled Finding"),
            finding.get("description"),
            finding.get("cvss_score"),
            finding.get("cvss_vector"),
            finding.get("cwe_id"),
            now(),
        ),
    )
    for req in evidence:
        conn.execute(
            """INSERT INTO attack_requests
               (request_id, finding_id, role, method, url,
                request_headers, request_body, response_status,
                response_headers, response_body, response_time_ms, sent_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                new_id("areq"),
                finding_id,
                req.get("role", "unknown"),
                req.get("method", "GET"),
                req.get("url", ""),
                req.get("request_headers") or None,
                _truncate(req.get("request_body")),
                req.get("response_status"),
                req.get("response_headers") or None,
                _truncate(req.get("response_body")),
                req.get("response_time_ms"),
                now(),
            ),
        )
    conn.commit()
    return finding_id


def update_finding_status(
    conn: sqlite3.Connection, *, finding_id: str, status: str
) -> None:
    conn.execute(
        "UPDATE findings SET status = ? WHERE finding_id = ?",
        (status, finding_id),
    )
    conn.commit()


def get_finding(conn: sqlite3.Connection, finding_id: str) -> dict | None:
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM findings WHERE finding_id = ?", (finding_id,)
    ).fetchone()
    return dict(row) if row else None


def get_findings_by_scan(
    conn: sqlite3.Connection, scan_id: str, *, status: str | None = None
) -> list[dict]:
    conn.row_factory = sqlite3.Row
    if status:
        rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? AND status = ?",
            (scan_id, status),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ?", (scan_id,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_attack_requests(
    conn: sqlite3.Connection, finding_id: str
) -> list[dict]:
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM attack_requests WHERE finding_id = ?", (finding_id,)
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# validations
# ---------------------------------------------------------------------------


def save_validation(
    conn: sqlite3.Connection,
    *,
    finding_id: str,
    validation: dict,
) -> str:
    """validation 결과를 저장하고 finding 상태를 업데이트한다.
    하나의 트랜잭션으로 처리한다."""
    validation_id = new_id("val")
    verdict = validation.get("verdict", "INCONCLUSIVE")

    gate_results = validation.get("gate_results")
    conn.execute(
        """INSERT INTO validations
           (validation_id, finding_id, verdict, gate_results, reasoning,
            confidence, validated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            validation_id,
            finding_id,
            verdict,
            json.dumps(gate_results, ensure_ascii=False) if gate_results else None,
            validation.get("reasoning"),
            validation.get("confidence"),
            now(),
        ),
    )

    status_map = {
        "CONFIRMED": "confirmed",
        "REJECTED": "rejected",
        "INCONCLUSIVE": "inconclusive",
    }
    conn.execute(
        "UPDATE findings SET status = ? WHERE finding_id = ?",
        (status_map.get(verdict, "pending"), finding_id),
    )
    conn.commit()
    return validation_id


def get_validation(conn: sqlite3.Connection, finding_id: str) -> dict | None:
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM validations WHERE finding_id = ?", (finding_id,)
    ).fetchone()
    return dict(row) if row else None
