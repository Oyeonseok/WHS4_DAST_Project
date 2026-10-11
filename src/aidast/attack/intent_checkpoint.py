"""Bounded Attack intent checkpoints and terminal-negative quality gates.

Checkpoints preserve what a worker tried without retaining request bodies,
response bodies, credentials, or target URLs.  They let a later retry choose a
different strategy while preventing a single denied request from becoming a
false ``tested_negative`` disposition.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Mapping, Sequence
from typing import Any


_LABEL = re.compile(r"^[a-z0-9][a-z0-9._:/+ -]{0,79}$")
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_LONG_SECRET_SHAPE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_+/=-]{48,}(?![A-Za-z0-9])")
_JWT_SHAPE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]{8,})?\b")
_FEATURE_KEYS = frozenset({
    "request_id", "status", "response_signature", "body_sha256",
    "content_type", "response_bytes", "assertion_kinds",
})
_CHECKPOINT_KEYS = frozenset({
    "strategy_families", "payload_families", "response_features",
    "acquired_fact_refs", "remaining_todos", "control_request_ids",
})


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _labels(value: object, *, field: str, limit: int = 16) -> list[str]:
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError(f"{field} must be a list with at most {limit} items")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{field} contains a non-text label")
        label = " ".join(item.casefold().strip().split())
        if not _LABEL.fullmatch(label):
            raise ValueError(f"{field} contains an invalid label")
        if label not in result:
            result.append(label)
    return result


def _references(value: object, *, field: str, limit: int = 32) -> list[str]:
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError(f"{field} must be a list with at most {limit} items")
    result: list[str] = []
    for item in value:
        if (not isinstance(item, str) or not item.strip() or len(item) > 256
                or any(character.isspace() for character in item)):
            raise ValueError(f"{field} contains an invalid reference")
        if item not in result:
            result.append(item)
    return result


def _safe_todos(value: object) -> list[str]:
    if not isinstance(value, list) or len(value) > 32:
        raise ValueError("remaining_todos must be a list with at most 32 items")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError("remaining_todos contains a non-text item")
        text = " ".join(item.strip().split())
        lowered = text.casefold()
        if not text or len(text) > 240:
            raise ValueError("remaining_todos contains invalid text")
        if ("?" in text and "://" in text) or _JWT_SHAPE.search(text) or _LONG_SECRET_SHAPE.search(text):
            raise ValueError("remaining_todos may not contain URLs with queries or secret-shaped values")
        if any(marker in lowered for marker in ("authorization:", "cookie:", "password=", "token=")):
            raise ValueError("remaining_todos may not contain credentials")
        if text not in result:
            result.append(text)
    return result


def _completed_requests(
    conn: sqlite3.Connection, *, scan_id: str, task_id: str,
) -> dict[str, sqlite3.Row]:
    return {
        str(row["request_id"]): row for row in conn.execute(
            """SELECT request_id,response_status,response_bytes,result_json,
                      endpoint_reference_id,request_fingerprint
               FROM attack_http_requests
               WHERE scan_id=? AND task_id=? AND status='completed'""",
            (scan_id, task_id),
        ).fetchall()
    }


def _features(value: object, requests: Mapping[str, sqlite3.Row]) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > 32:
        raise ValueError("response_features must be a list with at most 32 items")
    result: list[dict[str, Any]] = []
    for raw in value:
        if not isinstance(raw, Mapping) or not raw.keys() <= _FEATURE_KEYS:
            raise ValueError("response_features contains unsupported fields")
        request_id = raw.get("request_id")
        if not isinstance(request_id, str) or request_id not in requests:
            raise ValueError("response feature request_id is not a completed task request")
        request = requests[request_id]
        feature: dict[str, Any] = {"request_id": request_id}
        status = raw.get("status", request["response_status"])
        if (not isinstance(status, int) or isinstance(status, bool)
                or status != request["response_status"]):
            raise ValueError("response feature status does not match the request ledger")
        feature["status"] = status
        for key in ("response_signature", "body_sha256"):
            digest = raw.get(key)
            if digest is not None:
                if not isinstance(digest, str) or not _HEX_DIGEST.fullmatch(digest):
                    raise ValueError(f"response feature {key} must be a SHA-256 digest")
                feature[key] = digest
        response_bytes = raw.get("response_bytes", request["response_bytes"])
        if response_bytes is not None:
            if (not isinstance(response_bytes, int) or isinstance(response_bytes, bool)
                    or response_bytes < 0):
                raise ValueError("response feature response_bytes is invalid")
            feature["response_bytes"] = response_bytes
        content_type = raw.get("content_type")
        if content_type is not None:
            if not isinstance(content_type, str) or len(content_type) > 160 or "\n" in content_type:
                raise ValueError("response feature content_type is invalid")
            feature["content_type"] = content_type
        assertions = raw.get("assertion_kinds", [])
        feature["assertion_kinds"] = _labels(
            assertions, field="response_features.assertion_kinds", limit=16,
        )
        result.append(feature)
    return result


def _quality(
    strategies: Sequence[str], payloads: Sequence[str], features: Sequence[object],
    controls: Sequence[str], remaining: Sequence[str],
) -> str:
    families = len(set(strategies) | set(payloads))
    feature_requests = {
        str(item.get("request_id")) for item in features if isinstance(item, Mapping)
    }
    if families >= 3 and len(controls) >= 2 and len(feature_requests) >= 3 and not remaining:
        return "strong"
    if families >= 2 and controls and len(feature_requests) >= 2 and not remaining:
        return "adequate"
    return "weak"


def commit_intent_checkpoint(
    conn: sqlite3.Connection, *, scan_id: str, task_id: str,
    document: Mapping[str, object],
) -> dict[str, Any]:
    """Validate and append one checkpoint for a running coverage task."""
    if not isinstance(document, Mapping):
        raise ValueError("intent checkpoint must be an object")
    if not document.keys() <= _CHECKPOINT_KEYS:
        raise ValueError("intent checkpoint contains unsupported fields")
    task = conn.execute(
        """SELECT t.stage_run_id,t.status,s.status AS stage_status,c.coverage_id
           FROM attack_tasks t
           JOIN stage_runs s ON s.stage_run_id=t.stage_run_id AND s.scan_id=t.scan_id
           JOIN attack_coverage_items c ON c.scan_id=t.scan_id AND c.last_task_id=t.task_id
           WHERE t.scan_id=? AND t.task_id=?""",
        (scan_id, task_id),
    ).fetchone()
    if task is None or task["status"] != "running" or task["stage_status"] != "running":
        raise ValueError("intent checkpoints require a running coverage task")
    requests = _completed_requests(conn, scan_id=scan_id, task_id=task_id)
    strategies = _labels(document.get("strategy_families", []), field="strategy_families")
    payloads = _labels(document.get("payload_families", []), field="payload_families")
    features = _features(document.get("response_features", []), requests)
    fact_refs = _references(document.get("acquired_fact_refs", []), field="acquired_fact_refs")
    if fact_refs:
        placeholders = ",".join("?" for _ in fact_refs)
        count = conn.execute(
            f"SELECT COUNT(*) FROM attack_facts WHERE scan_id=? AND fact_id IN ({placeholders})",
            (scan_id, *fact_refs),
        ).fetchone()[0]
        if count != len(fact_refs):
            raise ValueError("acquired_fact_refs contains a fact from outside this scan")
    remaining = _safe_todos(document.get("remaining_todos", []))
    controls = _references(document.get("control_request_ids", []), field="control_request_ids")
    if any(request_id not in requests for request_id in controls):
        raise ValueError("control_request_ids must reference completed requests from this task")
    feature_request_ids = {str(item["request_id"]) for item in features}
    if any(request_id not in feature_request_ids for request_id in controls):
        raise ValueError("every control request requires a bounded response feature")
    sequence = conn.execute(
        """SELECT COALESCE(MAX(sequence),0)+1 FROM attack_intent_checkpoints
           WHERE coverage_id=?""",
        (task["coverage_id"],),
    ).fetchone()[0]
    checkpoint_id = "checkpoint_" + hashlib.sha256(
        f"{scan_id}\0{task['coverage_id']}\0{sequence}".encode("utf-8")
    ).hexdigest()[:32]
    quality = _quality(strategies, payloads, features, controls, remaining)
    conn.execute(
        """INSERT INTO attack_intent_checkpoints
           (checkpoint_id,scan_id,coverage_id,stage_run_id,task_id,sequence,
            strategy_families_json,payload_families_json,response_features_json,
            acquired_fact_refs_json,remaining_todos_json,control_request_ids_json,
            evidence_quality)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            checkpoint_id, scan_id, task["coverage_id"], task["stage_run_id"],
            task_id, sequence, _json(strategies), _json(payloads), _json(features),
            _json(fact_refs), _json(remaining), _json(controls), quality,
        ),
    )
    return {
        "checkpoint_id": checkpoint_id, "coverage_id": task["coverage_id"],
        "sequence": sequence, "evidence_quality": quality,
    }


def latest_intent_checkpoint(
    conn: sqlite3.Connection, coverage_id: str,
) -> dict[str, Any] | None:
    row = conn.execute(
        """SELECT checkpoint_id,task_id,sequence,strategy_families_json,
                  payload_families_json,response_features_json,
                  acquired_fact_refs_json,remaining_todos_json,
                  control_request_ids_json,evidence_quality,created_at
           FROM attack_intent_checkpoints WHERE coverage_id=?
           ORDER BY sequence DESC LIMIT 1""",
        (coverage_id,),
    ).fetchone()
    if row is None:
        return None
    return {
        "checkpoint_id": row["checkpoint_id"], "task_id": row["task_id"],
        "sequence": row["sequence"],
        "strategy_families": json.loads(row["strategy_families_json"]),
        "payload_families": json.loads(row["payload_families_json"]),
        "response_features": json.loads(row["response_features_json"]),
        "acquired_fact_refs": json.loads(row["acquired_fact_refs_json"]),
        "remaining_todos": json.loads(row["remaining_todos_json"]),
        "control_request_ids": json.loads(row["control_request_ids_json"]),
        "evidence_quality": row["evidence_quality"], "created_at": row["created_at"],
    }


def negative_evidence_quality(
    conn: sqlite3.Connection, *, scan_id: str, coverage_id: str, task_id: str,
    selected_attempts: Sequence[Mapping[str, object]],
) -> tuple[bool, str, dict[str, Any] | None]:
    """Return whether the current task has enough proof for a negative verdict."""
    if any(
        str(item.get("payload_variant") or "").startswith("engineio-session-binding-")
        and str(item.get("outcome") or "") in {"negative", "rejected"}
        for item in selected_attempts
    ):
        return True, "deterministic Engine.IO session-binding contract", None
    checkpoint = latest_intent_checkpoint(conn, coverage_id)
    if checkpoint is None or checkpoint["task_id"] != task_id:
        return False, "current task has no intent checkpoint", checkpoint
    if checkpoint["evidence_quality"] not in {"adequate", "strong"}:
        return False, "intent checkpoint evidence quality is weak", checkpoint
    request_ids = checkpoint["control_request_ids"]
    if not request_ids:
        return False, "intent checkpoint has no completed control request", checkpoint
    placeholders = ",".join("?" for _ in request_ids)
    count = conn.execute(
        f"""SELECT COUNT(*) FROM attack_http_requests
            WHERE scan_id=? AND task_id=? AND status='completed'
              AND request_id IN ({placeholders})""",
        (scan_id, task_id, *request_ids),
    ).fetchone()[0]
    if count != len(request_ids):
        return False, "intent checkpoint control evidence is stale", checkpoint
    return True, f"{checkpoint['evidence_quality']} intent checkpoint with bounded controls", checkpoint
