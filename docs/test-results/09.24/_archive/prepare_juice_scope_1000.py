"""Publish an isolated, integrity-protected 1000-request local Juice Shop Scope."""

from __future__ import annotations

import hashlib
from pathlib import Path

from aidast.orchestration.scope import ScopeCoordinator
from aidast.scope.models import ScopeDocument
from aidast.scope.paths import resolve_scope_directory


SOURCE = Path("result/Scope/lab-aidast-invalid/juice-shop")
ROOT = Path("result/test-runs/09.24/seclists-api-1000/Scope")
PROGRAM_URL = "https://lab.aidast.invalid/juice-shop"
OLD = "max_requests는 타깃당 500입니다."
NEW = "max_requests는 타깃당 1000입니다."


def main() -> None:
    original, _ = ScopeCoordinator(SOURCE).load_approved_scope()
    if original.source.text.count(OLD) != 1:
        raise ValueError("unexpected source request cap")
    if original.analysis.operational_constraints.count(OLD) != 1:
        raise ValueError("unexpected analysis request cap")

    source_text = original.source.text.replace(OLD, NEW)
    source = original.source.model_copy(update={
        "text": source_text,
        "content_sha256": hashlib.sha256(source_text.encode("utf-8")).hexdigest(),
    })
    constraints = [
        NEW if value == OLD else value
        for value in original.analysis.operational_constraints
    ]
    analysis = original.analysis.model_copy(update={"operational_constraints": constraints})
    document = ScopeDocument(
        scope_id=original.scope_id,
        created_at=original.created_at,
        source=source,
        analysis=analysis,
    )

    destination = resolve_scope_directory(PROGRAM_URL, ROOT)
    coordinator = ScopeCoordinator(destination)
    if destination.exists():
        existing, _ = coordinator.load_approved_scope()
        if existing != document:
            raise ValueError(f"different Scope already exists: {destination}")
        print(f"Verified existing Scope: {destination}")
        return

    draft = coordinator._create_scope_draft(document)
    coordinator.approve_draft(draft, approved_by="local-lab-operator")
    coordinator.load_approved_scope()
    print(f"Published approved Scope: {destination}")


if __name__ == "__main__":
    main()
