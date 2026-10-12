"""Resolve Attack prerequisites from durable evidence and expose bounded HITL."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import asdict, dataclass
from typing import Any

from .coverage import _credential_references, transition_coverage


def _id(prefix: str, *parts: str) -> str:
    value = "\x00".join(parts).encode("utf-8")
    return f"{prefix}_{hashlib.sha256(value).hexdigest()[:32]}"


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class PreconditionResolution:
    discovered: int = 0
    satisfied: int = 0
    actions_created: int = 0
    coverage_requeued: int = 0

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


_ACTION = {
    "usable_session": (
        "login", "로그인 세션이 필요합니다",
        "승인된 테스트 계정으로 대상에 로그인한 뒤 같은 스캔의 로그인 완료를 선택하세요.",
    ),
    "required_role": (
        "provide_role", "필요한 역할의 테스트 계정이 필요합니다",
        "표시된 역할을 가진 승인된 테스트 계정으로 로그인하고 로그인 완료를 선택하세요.",
    ),
    "second_identity": (
        "provide_second_identity", "두 번째 테스트 계정이 필요합니다",
        "IDOR 권한 비교를 위해 서로 다른 승인된 테스트 계정 두 개를 등록하고 로그인을 완료하세요.",
    ),
    "scanner_owned_object": (
        "create_owned_object", "스캐너 소유 테스트 객체가 필요합니다",
        "테스트 계정으로 삭제 가능한 객체 하나를 생성하세요. 완료 후 스캔을 다시 실행하면 소유권 증거를 확인합니다.",
    ),
    "fresh_token": (
        "refresh_token", "새 토큰이 필요합니다",
        "대상 화면에서 토큰을 새로 발급받거나 로그인 세션을 갱신한 뒤 완료를 선택하세요.",
    ),
    "prior_state": (
        "establish_state", "선행 상태 설정이 필요합니다",
        "안내된 테스트 흐름을 대상에서 한 번 수행한 뒤 완료를 선택하세요.",
    ),
}


def _needed_preconditions(row: sqlite3.Row) -> list[tuple[str, dict[str, Any]]]:
    """Classify only explicit blockers; do not invent requirements from a route."""
    reason = " ".join(str(row["disposition_reason"] or "").casefold().split())
    requirements: list[tuple[str, dict[str, Any]]] = []
    role = str(row["required_identity_role"] or "unauthenticated")
    if row["status"] == "blocked_auth" or role != "unauthenticated":
        requirements.append((
            "required_role" if role not in {"authenticated", "unknown", "unauthenticated"}
            else "usable_session",
            {"identity_role": role, "minimum_references": 1},
        ))
    if row["vuln_class"] == "idor" and (
        row["status"] == "blocked_auth"
        or any(marker in reason for marker in ("second identity", "two identit", "2 identit", "두 개", "두번째"))
    ):
        requirements.append((
            "second_identity",
            {"identity_role": role, "minimum_references": 2},
        ))
    if any(marker in reason for marker in (
        "owned object", "owned test object", "scanner-owned", "scanner created",
        "test fixture", "소유 객체",
    )):
        requirements.append(("scanner_owned_object", {"minimum_objects": 1}))
    if any(marker in reason for marker in (
        "fresh token", "expired token", "csrf token", "nonce", "새 토큰",
    )):
        requirements.append(("fresh_token", {"minimum_facts": 1}))
    if any(marker in reason for marker in (
        "prior state", "required state", "precondition state", "workflow state", "선행 상태",
    )):
        requirements.append(("prior_state", {"minimum_facts": 1}))
    # Keep one durable row per kind even if several reason phrases overlap.
    return list(dict(requirements).items())


def _credential_resolution(
    conn: sqlite3.Connection, row: sqlite3.Row, requirement: dict[str, Any],
) -> tuple[str, str] | None:
    references = _credential_references(
        conn, str(row["scan_id"]), str(requirement.get("identity_role") or "authenticated"),
        available_only=True, origin_url=str(row["origin_url"]),
    )
    minimum = int(requirement.get("minimum_references") or 1)
    if len(references) < minimum:
        return None
    # Store an opaque DB identifier only. For a two-identity prerequisite the
    # precondition document already records the required count.
    return "credential_reference", str(references[minimum - 1]["credential_reference_id"])


def _fact_resolution(
    conn: sqlite3.Connection, scan_id: str, kind: str,
) -> tuple[str, str] | None:
    fact_types = {
        "scanner_owned_object": ("owned_test_object",),
        "fresh_token": ("fresh_token", "csrf_token", "auth_behavior"),
        "prior_state": ("test_state", "workflow_state", "owned_test_object"),
    }[kind]
    placeholders = ",".join("?" for _ in fact_types)
    row = conn.execute(
        f"""SELECT fact_id FROM attack_facts
            WHERE scan_id=? AND fact_type IN ({placeholders})
            ORDER BY confidence DESC,created_at DESC,fact_id LIMIT 1""",
        (scan_id, *fact_types),
    ).fetchone()
    return ("attack_fact", str(row[0])) if row else None


def resolve_attack_preconditions(
    conn: sqlite3.Connection, scan_id: str,
) -> PreconditionResolution:
    """Discover explicit blockers, resolve them, and create actionable HITL rows."""
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """SELECT c.*,o.base_url AS origin_url
           FROM attack_coverage_items c
           JOIN endpoints e ON e.endpoint_id=c.endpoint_id
           JOIN origins o ON o.origin_id=e.origin_id
           WHERE c.scan_id=? AND c.status IN (
             'pending','error_retryable','blocked_auth','unsupported'
           ) ORDER BY c.coverage_id""",
        (scan_id,),
    ).fetchall()
    discovered = satisfied = actions_created = coverage_requeued = 0
    touched: set[str] = set()
    for row in rows:
        for kind, requirement in _needed_preconditions(row):
            touched.add(_id("precondition", scan_id, str(row["coverage_id"]), kind))
            precondition_id = _id("precondition", scan_id, str(row["coverage_id"]), kind)
            before = conn.total_changes
            conn.execute(
                """INSERT OR IGNORE INTO attack_preconditions
                   (precondition_id,scan_id,coverage_id,kind,requirement_json)
                   VALUES (?,?,?,?,?)""",
                (precondition_id, scan_id, row["coverage_id"], kind, _json(requirement)),
            )
            discovered += int(conn.total_changes > before)
            resolution = (
                _credential_resolution(conn, row, requirement)
                if kind in {"usable_session", "required_role", "second_identity"}
                else _fact_resolution(conn, scan_id, kind)
            )
            if resolution is not None:
                current = conn.execute(
                    "SELECT state FROM attack_preconditions WHERE precondition_id=?",
                    (precondition_id,),
                ).fetchone()
                if current and current[0] != "satisfied":
                    conn.execute(
                        """UPDATE attack_preconditions
                           SET state='satisfied',resolution_reference_type=?,
                               resolution_reference_id=?,satisfied_at=CURRENT_TIMESTAMP,
                               updated_at=CURRENT_TIMESTAMP WHERE precondition_id=?""",
                        (*resolution, precondition_id),
                    )
                    satisfied += 1
                conn.execute(
                    """UPDATE attack_operator_actions
                       SET status='completed',completed_at=CURRENT_TIMESTAMP,
                           updated_at=CURRENT_TIMESTAMP
                       WHERE precondition_id=? AND status IN ('pending','acknowledged')""",
                    (precondition_id,),
                )
                continue
            action_kind, title, instruction = _ACTION[kind]
            before = conn.total_changes
            conn.execute(
                """INSERT OR IGNORE INTO attack_operator_actions
                   (action_id,scan_id,precondition_id,action_kind,title,instruction)
                   VALUES (?,?,?,?,?,?)""",
                (_id("operator_action", precondition_id), scan_id, precondition_id,
                 action_kind, title, instruction),
            )
            actions_created += int(conn.total_changes > before)

    if touched:
        placeholders = ",".join("?" for _ in touched)
        conn.execute(
            f"""UPDATE attack_preconditions SET state='retired',updated_at=CURRENT_TIMESTAMP
                WHERE scan_id=? AND state='required' AND precondition_id NOT IN ({placeholders})""",
            (scan_id, *sorted(touched)),
        )

    blocked = conn.execute(
        """SELECT DISTINCT c.coverage_id,c.status,c.last_stage_run_id,c.last_task_id,
                          c.finding_id
           FROM attack_coverage_items c
           JOIN attack_preconditions p ON p.coverage_id=c.coverage_id
           WHERE c.scan_id=? AND c.status IN ('blocked_auth','unsupported')
             AND NOT EXISTS (
               SELECT 1 FROM attack_preconditions open
               WHERE open.coverage_id=c.coverage_id AND open.state='required'
             )""",
        (scan_id,),
    ).fetchall()
    for row in blocked:
        transition_coverage(
            conn, str(row["coverage_id"]), "pending",
            "all durable attack preconditions are satisfied",
            stage_run_id=row["last_stage_run_id"], task_id=row["last_task_id"],
            finding_id=row["finding_id"],
        )
        coverage_requeued += 1
    return PreconditionResolution(
        discovered=discovered, satisfied=satisfied,
        actions_created=actions_created, coverage_requeued=coverage_requeued,
    )


def list_operator_actions(conn: sqlite3.Connection, scan_id: str) -> list[dict[str, Any]]:
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """SELECT a.action_id,a.action_kind,a.status,a.title,a.instruction,
                  a.created_at,a.updated_at,p.precondition_id,p.kind,p.coverage_id,
                  p.state,c.vuln_class,e.method,e.normalized_path
           FROM attack_operator_actions a
           JOIN attack_preconditions p ON p.precondition_id=a.precondition_id
           JOIN attack_coverage_items c ON c.coverage_id=p.coverage_id
           JOIN endpoints e ON e.endpoint_id=c.endpoint_id
           WHERE a.scan_id=? ORDER BY
             CASE a.status WHEN 'pending' THEN 0 WHEN 'acknowledged' THEN 1 ELSE 2 END,
             a.created_at,a.action_id""",
        (scan_id,),
    ).fetchall()
    return [{key: row[key] for key in row.keys()} for row in rows]


def acknowledge_operator_action(
    conn: sqlite3.Connection, scan_id: str, action_id: str, *, operator: str,
) -> dict[str, Any]:
    row = conn.execute(
        """SELECT status FROM attack_operator_actions
           WHERE scan_id=? AND action_id=?""", (scan_id, action_id),
    ).fetchone()
    if row is None:
        raise KeyError(action_id)
    if row[0] in {"expired", "cancelled"}:
        raise ValueError("operator action is no longer active")
    if row[0] != "completed":
        conn.execute(
            """UPDATE attack_operator_actions
               SET status='acknowledged',acknowledged_by=?,updated_at=CURRENT_TIMESTAMP
               WHERE action_id=?""",
            (operator[:120], action_id),
        )
    result = resolve_attack_preconditions(conn, scan_id)
    action = next(
        item for item in list_operator_actions(conn, scan_id)
        if item["action_id"] == action_id
    )
    return {"action": action, "resolution": result.to_dict()}
