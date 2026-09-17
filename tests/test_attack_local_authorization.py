from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from aidast.attack.authorization import (
    RunAuthorization,
    sign_ed25519,
    verify_ed25519,
)
from aidast.attack.ed25519_authorization import (
    generate_keypair,
    load_verified,
    sign_authorization,
    to_run_authorization,
)


def authorization_document(**updates) -> dict:
    now = datetime.now(timezone.utc)
    values = {
        "run_id": "run",
        "scan_id": "scan",
        "scope_digest": "1" * 64,
        "policy_digest": "2" * 64,
        "handoff_digest": "3" * 64,
        "plan_digest": "4" * 64,
        "catalog_digest": "5" * 64,
        "plan_revision": 1,
        "authorization_id": "authorization",
        "issuer": "trusted-local-issuer",
        "approver": "operator",
        "issued_at": now.isoformat(),
        "not_before": now.isoformat(),
        "expires_at": (now + timedelta(minutes=5)).isoformat(),
        "task_ids": ["task"],
        "adapter_ids": ["policy-service"],
        "identity_roles": ["identity_a", "identity_b"],
    }
    values.update(updates)
    return values


def test_signed_envelope_round_trips_and_rejects_tampering(tmp_path: Path) -> None:
    private = tmp_path / "private.key"
    public = tmp_path / "public.key"
    envelope = tmp_path / "Authorization.json"
    generate_keypair(private, public)
    document = authorization_document()

    sign_authorization(document, private, envelope)

    assert load_verified(envelope) == document
    assert to_run_authorization(document).identity_roles == (
        "identity_a",
        "identity_b",
    )
    changed = json.loads(envelope.read_text(encoding="utf-8"))
    changed["document"]["approver"] = "attacker"
    envelope.write_text(json.dumps(changed), encoding="utf-8")
    with pytest.raises(ValueError, match="signature verification failed"):
        load_verified(envelope)


def test_typed_authorization_rejects_unknown_fields() -> None:
    with pytest.raises(ValueError, match="Attack contract"):
        to_run_authorization(authorization_document(untrusted=True))


def test_current_authorization_supports_ed25519_without_changing_hmac_api(
    tmp_path: Path,
) -> None:
    private = tmp_path / "private.key"
    public = tmp_path / "public.key"
    generate_keypair(private, public)
    authorization = RunAuthorization.model_validate(authorization_document())

    signed = sign_ed25519(authorization, private.read_bytes())

    assert signed.signature.startswith("ed25519:")
    assert verify_ed25519(signed, public.read_bytes())
    assert not verify_ed25519(
        signed.model_copy(update={"task_ids": ("other",)}),
        public.read_bytes(),
    )
