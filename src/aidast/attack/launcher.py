"""Composition root for approved session-bound Attack services."""

from __future__ import annotations

from pathlib import Path

from aidast.core.policy_service import PolicyService
from aidast.recon.policy import TargetPolicy

from .authorization import RunAuthorization
from .intent_manifest import load_intent_manifest
from .service_factory import build_policy_service
from .session_binding import SessionBindings
from .session_pool import PersistentSessionPool


class SessionAttackLauncher:
    """Create one reusable service per approved target and identity."""

    def __init__(
        self,
        *,
        session_bindings: SessionBindings,
        public_key: bytes,
        headless: bool = True,
    ) -> None:
        if len(public_key) != 32:
            raise ValueError("Ed25519 public keys must be exactly 32 bytes")
        self.bindings = session_bindings
        self.public_key = public_key
        self.pool = PersistentSessionPool(headless=headless)

    def services_for(
        self,
        *,
        target: str,
        policy: TargetPolicy,
        authorization: RunAuthorization,
        intent_manifest: str | Path,
        ledger,
        identity: str,
    ) -> PolicyService:
        intents = tuple(
            item
            for item in load_intent_manifest(intent_manifest)
            if item.identity_role in {None, identity}
        )
        if not intents:
            raise ValueError("no approved intents are bound to the selected identity")
        state = self.bindings.resolve(target, identity)
        transport = self.pool.transport(
            target=target,
            identity=identity,
            storage_state=state,
        )
        return build_policy_service(
            authorization,
            policy=policy,
            ledger=ledger,
            transport=transport,
            public_key=self.public_key,
            intents=intents,
        )

    def close(self) -> None:
        self.pool.close()
