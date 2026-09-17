"""Local Ed25519 authorization for the trusted Attack workflow."""

from __future__ import annotations

import base64
import json
import uuid
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .authorization import RunAuthorization
from .skill_agent import AttackTestExecutor
from .store import AttackStore


def _canonical(document: Mapping[str, Any]) -> bytes:
    return json.dumps(
        document, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()


def generate_keypair(private_path: Path, public_path: Path) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    key = Ed25519PrivateKey.generate()
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_bytes(
        key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    )
    public_path.write_bytes(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )


def sign_authorization(
    document: Mapping[str, Any], private_path: Path, output: Path
) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    key = Ed25519PrivateKey.from_private_bytes(private_path.read_bytes())
    payload = dict(document)
    public_key = base64.urlsafe_b64encode(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode().rstrip("=")
    envelope = {"document": payload, "public_key": public_key}
    envelope["signature"] = base64.urlsafe_b64encode(
        key.sign(_canonical(envelope))
    ).decode().rstrip("=")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(envelope, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def load_verified(path: Path) -> dict[str, Any]:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    envelope = json.loads(path.read_text(encoding="utf-8"))
    document = envelope.get("document")
    signature = envelope.get("signature")
    public_key = envelope.get("public_key")
    if not isinstance(document, dict) or not isinstance(
        signature, str
    ) or not isinstance(public_key, str):
        raise ValueError("invalid Ed25519 authorization envelope")

    def decode(value: str) -> bytes:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

    try:
        Ed25519PublicKey.from_public_bytes(decode(public_key)).verify(
            decode(signature),
            _canonical({"document": document, "public_key": public_key}),
        )
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ValueError(
            "Ed25519 authorization signature verification failed"
        ) from exc
    return document


def to_run_authorization(document: Mapping[str, Any]) -> RunAuthorization:
    try:
        return RunAuthorization.model_validate(dict(document))
    except Exception as exc:
        raise ValueError("authorization does not satisfy the Attack contract") from exc


class LocalEd25519AuthorizationProvider:
    """Verify signed documents and construct an injected bounded executor."""

    def __init__(
        self,
        executor_factory: Callable[[Mapping[str, Any], AttackStore], AttackTestExecutor],
        revoker: Callable[[str], None] | None = None,
    ) -> None:
        self._executor_factory = executor_factory
        self._revoker = revoker

    def verify(
        self,
        authorization: Path,
        store: AttackStore,
        *,
        approved_by: str | None = None,
    ) -> Mapping:
        document = to_run_authorization(load_verified(authorization)).model_dump(
            mode="json"
        )
        if approved_by is not None and document.get("approver") != approved_by:
            raise ValueError("authorization approver does not match reviewer")
        now = datetime.now(timezone.utc)
        not_before = datetime.fromisoformat(
            str(document["not_before"]).replace("Z", "+00:00")
        )
        expires = datetime.fromisoformat(
            str(document["expires_at"]).replace("Z", "+00:00")
        )
        if not_before > now or expires <= now:
            raise ValueError("authorization is not currently valid")
        run = store.get_run()
        plan = store.get_plan(document.get("plan_revision", ""))
        bindings = {
            "plan_digest": plan["plan_digest"] if plan else None,
            "scope_digest": run["scope_digest"],
            "policy_digest": run["policy_digest"],
            "handoff_digest": run.get("source_manifest_sha256"),
            "catalog_digest": run["catalog_digest"],
            "revocation_generation": run["revocation_generation"],
        }
        for key, expected in bindings.items():
            if expected is None:
                raise ValueError(f"current run is missing {key}")
            if document.get(key) != expected:
                raise ValueError(f"authorization {key} does not match current run")
        return document

    def executor(
        self, authorization: Mapping, store: AttackStore
    ) -> AttackTestExecutor:
        return self._executor_factory(authorization, store)

    def revoke(self, authorization_id: str) -> None:
        if self._revoker is None:
            raise ValueError("an external authorization revoker is required")
        self._revoker(authorization_id)


def new_document(
    store: AttackStore,
    *,
    issuer: str,
    approver: str,
    lifetime_minutes: int = 30,
) -> dict[str, Any]:
    if lifetime_minutes <= 0:
        raise ValueError("lifetime_minutes must be positive")
    run = store.get_run()
    plan = store.get_plan(run["plan_revision"])
    if plan is None:
        raise ValueError("current Attack plan not found")
    now = datetime.now(timezone.utc)
    task_ids = tuple(item["task_id"] for item in store.list_tasks(plan["revision"]))
    return {
        "authorization_id": "auth_" + uuid.uuid4().hex,
        "issuer": issuer,
        "approver": approver,
        "issued_at": now.isoformat(),
        "not_before": now.isoformat(),
        "expires_at": (now + timedelta(minutes=lifetime_minutes)).isoformat(),
        "run_id": store.run_id,
        "scan_id": store.scan_id,
        "plan_revision": plan["revision"],
        "plan_digest": plan["plan_digest"],
        "scope_digest": run["scope_digest"],
        "handoff_digest": run["source_manifest_sha256"],
        "policy_digest": run["policy_digest"],
        "catalog_digest": run["catalog_digest"],
        "revocation_generation": run["revocation_generation"],
        "task_ids": task_ids,
        "adapter_ids": ("policy-service",),
        "identity_roles": ("identity_a", "identity_b"),
        "activity_classes": ("bounded-observation",),
        "excluded_actions": ("state-changing-request", "external-process"),
        "evidence_retention": "redacted-metadata-only",
        "budget": {
            "max_requests": 20,
            "max_bytes": 200_000,
            "max_seconds": 300,
            "requests_per_second": 1,
            "concurrency": 1,
            "timeout_seconds": 20,
        },
    }
