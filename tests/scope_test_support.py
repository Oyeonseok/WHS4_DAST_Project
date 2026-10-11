"""Historical Scope fixture creation without invoking current fresh collection."""
from datetime import datetime, timezone

from aidast.orchestration.scope import ScopeCoordinator
from aidast.scope.models import ScopeDocument


def publish_legacy_scope(directory, page, analysis):
    """Write a new temporary test archive using its original incomplete schema.

    This deliberately bypasses fresh collection/approval checks. It does not edit
    an existing approved artifact or relax production validation.
    """
    coordinator = ScopeCoordinator(directory)
    document = ScopeDocument(scope_id='legacy_test_scope', created_at=datetime.now(timezone.utc),
                             source=page, analysis=analysis)
    staging = coordinator._create_scope_draft(document)
    coordinator._publish_scope(staging, document, approved_by='historical-test-fixture')
    return document
