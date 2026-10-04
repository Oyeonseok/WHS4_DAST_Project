"""Disposable authenticated identities for a loopback OWASP Juice Shop scan."""

from __future__ import annotations

import ipaddress
import json
import secrets
import sqlite3
import tempfile
from pathlib import Path
from typing import Callable
from urllib.error import HTTPError
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlopen

from aidast.pipeline.browser_credentials import register_browser_session_credentials
from aidast.recon.db import new_id
from aidast.recon.policy import TargetPolicy
from aidast.validation.execution.credentials import PipelineCredentialResolver


class JuiceShopBootstrapError(RuntimeError):
    """The disposable Juice Shop identity fixture could not be created safely."""


JsonTransport = Callable[[str, str, dict[str, object] | None], dict[str, object]]


def _default_transport(
    url: str, method: str, payload: dict[str, object] | None,
) -> dict[str, object]:
    request = Request(
        url,
        data=None if payload is None else json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "aidast-lab-bootstrap/1"},
        method=method,
    )
    try:
        with urlopen(request, timeout=15) as response:
            body = response.read(1_000_001)
    except HTTPError as exc:
        # Response bodies can echo submitted identity fields. Do not copy them
        # into an exception, dashboard log, or report artifact.
        exc.read(1_000_001)
        raise JuiceShopBootstrapError(
            f"fixture request failed with HTTP {exc.code}"
        ) from exc
    if len(body) > 1_000_000:
        raise JuiceShopBootstrapError("fixture response exceeded 1 MB")
    try:
        document = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JuiceShopBootstrapError("fixture returned invalid JSON") from exc
    if not isinstance(document, dict):
        raise JuiceShopBootstrapError("fixture returned a non-object JSON response")
    return document


def _loopback_origin(target_url: str) -> str:
    parsed = urlsplit(target_url)
    try:
        loopback = (
            parsed.hostname == "localhost"
            or ipaddress.ip_address(parsed.hostname or "").is_loopback
        )
    except ValueError:
        loopback = False
    if parsed.scheme not in {"http", "https"} or not loopback:
        raise JuiceShopBootstrapError("Juice Shop benchmark bootstrap is loopback-only")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"{parsed.scheme}://{parsed.hostname}:{port}"


def _scope_authorizes_disposable_fixtures(scope: str) -> bool:
    normalized = " ".join(scope.casefold().split())
    return (
        (
            "scanner-created synthetic account" in normalized
            and "disposable" in normalized
            and "authorized" in normalized
        )
        or (
            "스캐너가 생성한 합성 계정" in scope
            and "일회성 데이터" in scope
            and "허용" in scope
        )
    )


def _load_policy(path: Path, target_url: str) -> TargetPolicy:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    policies = [TargetPolicy.model_validate(item) for item in document.get("policies", [])]
    matching = [
        policy for policy in policies
        if policy.allows_attack_url(
            urljoin(target_url, "/rest/user/login"), method="POST",
        )
    ]
    if len(matching) != 1:
        raise JuiceShopBootstrapError("exactly one policy must authorize the fixture origin")
    return matching[0]


def _available_roles(
    database: Path, *, scan_id: str, result_root: Path, target_url: str,
) -> set[str]:
    resolver = PipelineCredentialResolver(
        database, result_root=result_root, browser_sessions=True,
    )
    roles: set[str] = set()
    with sqlite3.connect(database) as conn:
        for reference_id, role in conn.execute(
            "SELECT credential_reference_id,identity_role FROM credential_references WHERE scan_id=?",
            (scan_id,),
        ):
            if resolver.unsupported_reason(
                str(reference_id), destination_url=target_url,
            ) is None:
                roles.add(str(role))
    return roles


def _backfill_public_identity_fields(database: Path, *, scan_id: str) -> int:
    """Expose only synthetic login identifiers needed to build safe request bodies."""
    updated = 0
    with sqlite3.connect(database) as conn, conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT fact_id,fact_value FROM attack_facts
               WHERE scan_id=? AND fact_type='owned_test_object'""",
            (scan_id,),
        ).fetchall()
        for row in rows:
            try:
                value = json.loads(row["fact_value"])
            except (TypeError, json.JSONDecodeError):
                continue
            principal = value.get("principal") if isinstance(value, dict) else None
            if (
                not isinstance(principal, str)
                or not principal.endswith("@example.invalid")
                or value.get("email") == principal
            ):
                continue
            value["email"] = principal
            value["login_identifier"] = principal
            conn.execute(
                "UPDATE attack_facts SET fact_value=? WHERE fact_id=?",
                (json.dumps(value, ensure_ascii=False, sort_keys=True), row["fact_id"]),
            )
            updated += 1
    return updated


def bootstrap_juice_shop(
    database: Path, *, scan_id: str, target_url: str,
    scope_path: Path, policy_path: Path, result_root: Path,
    transport: JsonTransport | None = None,
) -> dict[str, object]:
    """Create three private same-origin sessions without persisting secrets in SQLite."""
    origin = _loopback_origin(target_url)
    scope = Path(scope_path).read_text(encoding="utf-8")
    if "juice shop" not in scope.casefold():
        raise JuiceShopBootstrapError("Scope is not for OWASP Juice Shop")
    if not _scope_authorizes_disposable_fixtures(scope):
        raise JuiceShopBootstrapError("Scope does not authorize disposable lab fixtures")
    policy = _load_policy(policy_path, target_url)
    for path, method in (
        ("/api/SecurityQuestions", "GET"),
        ("/api/Users", "POST"),
        ("/rest/user/login", "POST"),
    ):
        if not policy.allows_attack_url(urljoin(target_url, path), method=method):
            raise JuiceShopBootstrapError(
                f"TargetPolicy does not authorize fixture path: {path}"
            )

    database = Path(database).expanduser().resolve(strict=True)
    result_root = Path(result_root).expanduser().resolve()
    required_roles = {"authenticated", "identity_b", "identity_synthetic"}
    present = _available_roles(
        database, scan_id=scan_id, result_root=result_root, target_url=target_url,
    )
    if required_roles <= present:
        _backfill_public_identity_fields(database, scan_id=scan_id)
        return {
            "credential_reference_count": len(required_roles),
            "owned_test_object_count": 0,
            "roles": sorted(required_roles),
            "reused": True,
        }

    send = transport or _default_transport
    questions = send(urljoin(target_url, "/api/SecurityQuestions"), "GET", None)
    question_rows = questions.get("data")
    first_question = question_rows[0] if isinstance(question_rows, list) and question_rows else None
    question_id = first_question.get("id") if isinstance(first_question, dict) else None
    if not isinstance(question_id, (str, int)):
        raise JuiceShopBootstrapError("fixture discovery omitted a security question")

    identities: list[dict[str, str]] = []
    nonce = secrets.token_hex(6)
    for index, role in enumerate(("authenticated", "identity_b", "identity_synthetic"), 1):
        email = f"aidast-{nonce}-{index}-{secrets.token_hex(2)}@example.invalid"
        password = secrets.token_urlsafe(20)
        answer = secrets.token_urlsafe(12)
        created = send(urljoin(target_url, "/api/Users"), "POST", {
            "email": email,
            "password": password,
            "passwordRepeat": password,
            "securityQuestion": {"id": question_id},
            "securityAnswer": answer,
        })
        created_data = created.get("data")
        user_id = created_data.get("id") if isinstance(created_data, dict) else None
        logged_in = send(urljoin(target_url, "/rest/user/login"), "POST", {
            "email": email, "password": password,
        })
        authentication = logged_in.get("authentication")
        token = authentication.get("token") if isinstance(authentication, dict) else None
        basket_id = authentication.get("bid") if isinstance(authentication, dict) else None
        if not isinstance(token, str) or not isinstance(user_id, (str, int)):
            raise JuiceShopBootstrapError("fixture response omitted token or user ID")
        identities.append({
            "role": role,
            "token": token,
            "email": email,
            "user_id": str(user_id),
            **({"basket_id": str(basket_id)} if isinstance(basket_id, (str, int)) else {}),
        })

    private_root = result_root / ".aidast_sessions"
    private_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    sessions: list[tuple[str, Path, bool, str]] = []
    with tempfile.TemporaryDirectory(prefix="juice-fixtures-", dir=private_root) as temporary:
        temporary_path = Path(temporary)
        for identity in identities:
            snapshot = temporary_path / f"{identity['role']}.json"
            snapshot.write_text(json.dumps({
                "cookies": [],
                "origins": [{
                    "origin": origin,
                    "localStorage": [
                        {"name": "token", "value": identity["token"]},
                        {"name": "bid", "value": identity.get("basket_id", "")},
                        {"name": "email", "value": identity["email"]},
                    ],
                }],
            }, separators=(",", ":")), encoding="utf-8")
            snapshot.chmod(0o600)
            marker = Path(str(snapshot) + ".authenticated")
            marker.write_text("authenticated\n", encoding="utf-8")
            marker.chmod(0o600)
            sessions.append((target_url, snapshot, True, identity["role"]))

        with sqlite3.connect(database) as conn, conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            if conn.execute(
                "SELECT 1 FROM scans WHERE scan_id=?", (scan_id,),
            ).fetchone() is None:
                raise JuiceShopBootstrapError("unknown benchmark scan")
            references = register_browser_session_credentials(
                conn, scan_id=scan_id, result_root=result_root, sessions=sessions,
            )
            reference_by_role = {
                item["identity_role"]: item["label"] for item in references
            }
            if set(reference_by_role) != required_roles:
                raise JuiceShopBootstrapError("fixture sessions were not persisted")
            fact_count = 0
            for identity in identities:
                label = reference_by_role[identity["role"]]
                for object_type in ("user_id", "basket_id"):
                    if object_type not in identity:
                        continue
                    fact_value = {
                        "credential_label": label,
                        "object_id": identity[object_type],
                        "object_type": object_type,
                        "principal": identity["email"],
                        "email": identity["email"],
                        "login_identifier": identity["email"],
                        "resource": "account" if object_type == "user_id" else "basket",
                        "disposable": True,
                        "cleanup_allowed": True,
                    }
                    conn.execute(
                        """INSERT INTO attack_facts
                           (fact_id,scan_id,fact_type,fact_key,fact_value,confidence)
                           VALUES (?,?,'owned_test_object',?,?,1.0)
                           ON CONFLICT(scan_id,fact_type,fact_key)
                           DO UPDATE SET fact_value=excluded.fact_value,confidence=1.0""",
                        (
                            new_id("fact"), scan_id,
                            f"{identity['role']}.{object_type}",
                            json.dumps(fact_value, ensure_ascii=False, sort_keys=True),
                        ),
                    )
                    fact_count += 1

    return {
        "credential_reference_count": len(required_roles),
        "owned_test_object_count": fact_count,
        "roles": sorted(required_roles),
        "reused": False,
    }
