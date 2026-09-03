"""Compile and atomically publish a validated recon policy artifact."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Protocol

from aidast.recon.policy import PolicyError, ReconPolicy, load_policy


class ReconPolicyCompiler(Protocol):
    def compile_recon_policy(
        self, *, scope_path: Path, scope_markdown: str
    ) -> ReconPolicy: ...


class ReconPolicyCoordinator:
    def __init__(self, output_path: Path):
        self.output_path = output_path

    def compile(
        self,
        *,
        scope_path: Path,
        scope_markdown: str,
        main_agent: ReconPolicyCompiler,
    ) -> ReconPolicy:
        policy = main_agent.compile_recon_policy(
            scope_path=scope_path,
            scope_markdown=scope_markdown,
        )
        if policy.source.scope_md_path != str(scope_path):
            raise PolicyError(
                "compiled policy does not reference the approved Scope.md"
            )
        self._publish(policy)
        return policy

    def _publish(self, policy: ReconPolicy) -> None:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{self.output_path.name}.",
            dir=self.output_path.parent,
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(policy.model_dump_json(indent=2) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            temporary_path.chmod(0o600)
            load_policy(temporary_path)
            os.replace(temporary_path, self.output_path)
        finally:
            temporary_path.unlink(missing_ok=True)
