"""Ephemeral credential bootstrap for the loopback VulnBank benchmark."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import secrets
import sqlite3
from pathlib import Path
from typing import Callable, Mapping
from urllib.error import HTTPError
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlopen

from aidast.pipeline.lifecycle import register_credential_reference
from aidast.recon.db import new_id
from aidast.recon.policy import TargetPolicy


class VulnBankBootstrapError(RuntimeError):
    """The disposable benchmark fixture could not be created safely."""


JsonTransport = Callable[[str, dict[str, object]], dict[str, object]]
AuthenticatedJsonTransport = Callable[
    [str, dict[str, object], Mapping[str, str]], dict[str, object]
]
JsonReadTransport = Callable[[str, Mapping[str, str]], dict[str, object]]
TextReadTransport = Callable[[str, Mapping[str, str]], str]


def _default_transport(url: str, payload: dict[str, object]) -> dict[str, object]:
    request = Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "aidast-lab-bootstrap/1"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=15) as response:
            body = response.read(1_000_001)
    except HTTPError as exc:
        body = exc.read(1_000_001)
        raise VulnBankBootstrapError(
            f"fixture request failed with HTTP {exc.code}: {body[:256]!r}"
        ) from exc
    if len(body) > 1_000_000:
        raise VulnBankBootstrapError("fixture response exceeded 1 MB")
    try:
        result = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VulnBankBootstrapError("fixture returned invalid JSON") from exc
    if not isinstance(result, dict):
        raise VulnBankBootstrapError("fixture returned a non-object JSON response")
    return result


def _default_authenticated_transport(
    url: str, payload: dict[str, object], headers: Mapping[str, str],
) -> dict[str, object]:
    request = Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "User-Agent": "aidast-lab-bootstrap/1",
            **dict(headers),
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=15) as response:
            body = response.read(1_000_001)
    except HTTPError as exc:
        body = exc.read(1_000_001)
        raise VulnBankBootstrapError(
            f"authenticated fixture request failed with HTTP {exc.code}: {body[:256]!r}"
        ) from exc
    if len(body) > 1_000_000:
        raise VulnBankBootstrapError("authenticated fixture response exceeded 1 MB")
    try:
        result = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VulnBankBootstrapError("authenticated fixture returned invalid JSON") from exc
    if not isinstance(result, dict):
        raise VulnBankBootstrapError("authenticated fixture returned a non-object JSON response")
    return result


def _default_read_transport(
    url: str, headers: Mapping[str, str],
) -> dict[str, object]:
    request = Request(
        url,
        headers={"User-Agent": "aidast-lab-bootstrap/1", **dict(headers)},
        method="GET",
    )
    try:
        with urlopen(request, timeout=15) as response:
            body = response.read(1_000_001)
    except HTTPError as exc:
        body = exc.read(1_000_001)
        raise VulnBankBootstrapError(
            f"fixture discovery failed with HTTP {exc.code}: {body[:256]!r}"
        ) from exc
    if len(body) > 1_000_000:
        raise VulnBankBootstrapError("fixture discovery response exceeded 1 MB")
    try:
        result = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VulnBankBootstrapError("fixture discovery returned invalid JSON") from exc
    if not isinstance(result, dict):
        raise VulnBankBootstrapError("fixture discovery returned a non-object JSON response")
    return result


def _default_text_read_transport(
    url: str, headers: Mapping[str, str],
) -> str:
    request = Request(
        url,
        headers={"User-Agent": "aidast-lab-bootstrap/1", **dict(headers)},
        method="GET",
    )
    try:
        with urlopen(request, timeout=15) as response:
            body = response.read(1_000_001)
    except HTTPError as exc:
        body = exc.read(1_000_001)
        raise VulnBankBootstrapError(
            f"fixture page discovery failed with HTTP {exc.code}: {body[:256]!r}"
        ) from exc
    if len(body) > 1_000_000:
        raise VulnBankBootstrapError("fixture page exceeded 1 MB")
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VulnBankBootstrapError("fixture page was not UTF-8") from exc


def _load_policy(path: Path, target_url: str) -> TargetPolicy:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    policies = [TargetPolicy.model_validate(item) for item in document.get("policies", [])]
    matching = [policy for policy in policies if policy.allows_attack_url(
        urljoin(target_url, "/register"), method="POST",
    )]
    if len(matching) != 1:
        raise VulnBankBootstrapError("exactly one policy must authorize the fixture origin")
    return matching[0]


def _environment_name(scan_id: str, label: str) -> str:
    suffix = scan_id.removeprefix("scan_")[:12].upper()
    return f"AIDAST_VULNBANK_{suffix}_{label.upper().replace('-', '_')}"


def bootstrap_vulnbank(
    database: Path, *, scan_id: str, target_url: str,
    scope_path: Path, policy_path: Path,
    transport: JsonTransport | None = None,
    authenticated_transport: AuthenticatedJsonTransport | None = None,
    read_transport: JsonReadTransport | None = None,
    text_read_transport: TextReadTransport | None = None,
) -> dict[str, object]:
    """Create disposable identities and expose tokens only through this process env."""
    parsed = urlsplit(target_url)
    try:
        loopback = (
            parsed.hostname == "localhost"
            or ipaddress.ip_address(parsed.hostname or "").is_loopback
        )
    except ValueError:
        loopback = False
    if parsed.scheme not in {"http", "https"} or not loopback:
        raise VulnBankBootstrapError("VulnBank benchmark bootstrap is loopback-only")
    scope = Path(scope_path).read_text(encoding="utf-8")
    if "disposable local lab fixtures is authorized" not in scope:
        raise VulnBankBootstrapError("Scope does not authorize disposable lab fixtures")
    policy = _load_policy(policy_path, target_url)
    for path in (
        "/register", "/login", "/api/v1/merchants/register",
        "/api/virtual-cards/create", "/request_loan",
    ):
        if not policy.allows_attack_url(urljoin(target_url, path), method="POST"):
            raise VulnBankBootstrapError(f"TargetPolicy does not authorize fixture path: {path}")
    admin_fixture_path = "/sup3r_s3cr3t_admin"
    if not policy.allows_attack_url(
        urljoin(target_url, admin_fixture_path), method="GET",
    ):
        raise VulnBankBootstrapError(
            f"TargetPolicy does not authorize fixture path: {admin_fixture_path}"
        )

    send = transport or _default_transport
    send_authenticated = (
        authenticated_transport
        if authenticated_transport is not None
        else (_default_authenticated_transport if transport is None else None)
    )
    read_json = (
        read_transport
        if read_transport is not None
        else (_default_read_transport if transport is None else None)
    )
    read_text = (
        text_read_transport
        if text_read_transport is not None
        else (_default_text_read_transport if transport is None else None)
    )
    nonce = secrets.token_hex(5)
    identities: list[dict[str, str]] = []
    for label, extra_fields in (
        ("user-a", {}), ("user-b", {}), ("admin-a", {"is_admin": True}),
    ):
        username = f"aidast_{label.replace('-', '')}_{nonce}_{secrets.token_hex(2)}"
        password = secrets.token_urlsafe(18)
        registration = send(urljoin(target_url, "/register"), {
            "username": username, "password": password, **extra_fields,
        })
        login = send(urljoin(target_url, "/login"), {
            "username": username, "password": password,
        })
        token = login.get("token")
        debug = registration.get("debug_data")
        account = debug.get("account_number") if isinstance(debug, dict) else None
        user_id = debug.get("user_id") if isinstance(debug, dict) else None
        if not all(isinstance(value, (str, int)) for value in (token, account, user_id)):
            raise VulnBankBootstrapError("user fixture response omitted token or owned object")
        identities.append({
            "label": label, "role": label, "token": str(token),
            "principal": username, "account_number": str(account),
            "user_id": str(user_id),
        })

    if send_authenticated is not None:
        for identity in identities:
            token = identity["token"]
            card_result = send_authenticated(
                urljoin(target_url, "/api/virtual-cards/create"),
                {"card_limit": 100.0, "card_type": "benchmark", "currency": "USD"},
                {"Authorization": f"Bearer {token}"},
            )
            card = card_result.get("card_details")
            card_id = card.get("id") if isinstance(card, dict) else None
            if not isinstance(card_id, (str, int)):
                raise VulnBankBootstrapError("virtual-card fixture response omitted card ID")
            identity["card_id"] = str(card_id)

        user_a = next(item for item in identities if item["label"] == "user-a")
        admin_a = next(item for item in identities if item["label"] == "admin-a")
        loan_amount = "123.45"
        loan_result = send_authenticated(
            urljoin(target_url, "/request_loan"), {"amount": loan_amount},
            {"Authorization": f"Bearer {user_a['token']}"},
        )
        if loan_result.get("status") != "success":
            raise VulnBankBootstrapError("loan fixture creation did not succeed")
        if read_text is not None:
            row_pattern = re.compile(
                rf"<td>\s*#(?P<loan_id>\d+)\s*</td>\s*"
                rf"<td>\s*{re.escape(user_a['user_id'])}\s*</td>\s*"
                rf'<td[^>]*>\s*\${re.escape(loan_amount)}\s*</td>',
                re.IGNORECASE,
            )
            # Pending loans are paginated oldest first. Existing benchmark
            # volumes can therefore place the freshly-created owned loan on a
            # later page. Search a bounded number of local pages and stop if
            # the application starts repeating the final page.
            match = None
            seen_pages: set[str] = set()
            for page_number in range(1, 33):
                admin_html = read_text(
                    urljoin(
                        target_url,
                        f"/sup3r_s3cr3t_admin?loan_page={page_number}",
                    ),
                    {"Authorization": f"Bearer {admin_a['token']}"},
                )
                page_digest = hashlib.sha256(admin_html.encode("utf-8")).hexdigest()
                if page_digest in seen_pages:
                    break
                seen_pages.add(page_digest)
                match = row_pattern.search(admin_html)
                if match is not None:
                    break
            if match is None:
                raise VulnBankBootstrapError("admin fixture page omitted the owned loan ID")
            user_a["loan_id"] = match.group("loan_id")

    for label in ("merchant-a", "merchant-b"):
        email = f"aidast-{label}-{nonce}-{secrets.token_hex(2)}@example.invalid"
        result = send(urljoin(target_url, "/api/v1/merchants/register"), {
            "name": f"AIDAST {label}", "email": email,
            "password": secrets.token_urlsafe(18),
        })
        merchant = result.get("merchant")
        token = result.get("token")
        merchant_id = merchant.get("id") if isinstance(merchant, dict) else None
        if not isinstance(token, str) or not isinstance(merchant_id, (str, int)):
            raise VulnBankBootstrapError("merchant fixture response omitted token or object ID")
        identities.append({
            "label": label, "role": label, "token": token,
            "principal": email, "merchant_id": str(merchant_id),
        })

    benchmark_fixtures: list[tuple[str, dict[str, str]]] = []
    if read_json is not None:
        category_result = read_json(urljoin(target_url, "/api/bill-categories"), {})
        categories = category_result.get("categories")
        category = categories[0] if isinstance(categories, list) and categories else None
        category_id = category.get("id") if isinstance(category, dict) else None
        if not isinstance(category_id, (str, int)):
            raise VulnBankBootstrapError("biller fixture discovery omitted category ID")
        biller_result = read_json(
            urljoin(target_url, f"/api/billers/by-category/{category_id}"), {},
        )
        billers = biller_result.get("billers")
        biller = billers[0] if isinstance(billers, list) and billers else None
        biller_id = biller.get("id") if isinstance(biller, dict) else None
        if not isinstance(biller_id, (str, int)):
            raise VulnBankBootstrapError("biller fixture discovery omitted biller ID")
        benchmark_fixtures.extend((
            ("category.category_id", {
                "object_id": str(category_id), "object_type": "category_id",
            }),
            ("biller.biller_id", {
                "object_id": str(biller_id), "object_type": "biller_id",
            }),
        ))

    database = Path(database).expanduser().resolve(strict=True)
    with sqlite3.connect(database) as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        if conn.execute("SELECT 1 FROM scans WHERE scan_id=?", (scan_id,)).fetchone() is None:
            raise VulnBankBootstrapError("unknown benchmark scan")
        reference_ids = []
        for identity in identities:
            env_name = _environment_name(scan_id, identity["label"])
            os.environ[env_name] = json.dumps({
                "Authorization": f"Bearer {identity.pop('token')}"
            }, separators=(",", ":"))
            reference_uri = f"env://{env_name}"
            existing = conn.execute(
                """SELECT credential_reference_id,reference_uri,identity_role
                   FROM credential_references WHERE scan_id=? AND label=?""",
                (scan_id, identity["label"]),
            ).fetchone()
            if existing is None:
                reference_ids.append(register_credential_reference(
                    conn, scan_id=scan_id, label=identity["label"],
                    reference_uri=reference_uri, identity_role=identity["role"],
                ))
            else:
                if existing[1:] != (reference_uri, identity["role"]):
                    raise VulnBankBootstrapError(
                        "existing credential reference has incompatible provenance"
                    )
                reference_ids.append(existing[0])
            for object_type in (
                "account_number", "user_id", "merchant_id", "card_id", "loan_id",
            ):
                if object_type not in identity:
                    continue
                key = f"{identity['label']}.{object_type}"
                value = json.dumps({
                    "credential_label": identity["label"],
                    "object_id": identity[object_type],
                    "object_type": object_type,
                    "principal": identity["principal"],
                }, ensure_ascii=False, sort_keys=True)
                conn.execute(
                    """INSERT INTO attack_facts
                       (fact_id,scan_id,fact_type,fact_key,fact_value,confidence)
                       VALUES (?,?,'owned_test_object',?,?,1.0)
                       ON CONFLICT(scan_id,fact_type,fact_key)
                       DO UPDATE SET fact_value=excluded.fact_value,confidence=1.0""",
                    (new_id("fact"), scan_id, key, value),
                )
        for key, fixture in benchmark_fixtures:
            conn.execute(
                """INSERT INTO attack_facts
                   (fact_id,scan_id,fact_type,fact_key,fact_value,confidence)
                   VALUES (?,?,'benchmark_fixture',?,?,1.0)
                   ON CONFLICT(scan_id,fact_type,fact_key)
                   DO UPDATE SET fact_value=excluded.fact_value,confidence=1.0""",
                (new_id("fact"), scan_id, key, json.dumps(
                    fixture, ensure_ascii=False, sort_keys=True,
                )),
            )
        conn.commit()
    return {
        "credential_reference_count": len(reference_ids),
        "owned_test_object_count": sum(
            object_type in identity
            for identity in identities
            for object_type in (
                "account_number", "user_id", "merchant_id", "card_id", "loan_id",
            )
        ),
        "benchmark_fixture_count": len(benchmark_fixtures),
        "labels": [identity["label"] for identity in identities],
    }
