from __future__ import annotations

import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from aidast.attack.workflow import SkillAttackWorkflow


class FakeStore:
    run_id = "run"
    scan_id = "scan"
    path = Path("/tmp/attack/Attack.db")

    def __init__(self, *, authorization_id="authorization"):
        self.authorization_id = authorization_id
        self.revocations = []

    def __enter__(self): return self
    def __exit__(self, *args): return False

    def get_run(self):
        return {"authorization_id": self.authorization_id, "source_manifest_path": "Handoff.json",
                "source_database_path": "Recon.db"}

    def revoke_run(self, reason, *, revoke_authorization=None):
        if revoke_authorization is not None and self.authorization_id:
            revoke_authorization(self.authorization_id)
        self.revocations.append(reason)
        self.authorization_id = None
        return 1


class SkillAttackWorkflowTests(unittest.TestCase):
    def test_failed_external_revocation_leaves_local_grant_retryable(self):
        store = FakeStore()
        provider = Mock()
        provider.revoke.side_effect = RuntimeError("broker unavailable")
        workflow = SkillAttackWorkflow(planner=Mock(), authorization_provider=provider)
        with patch("aidast.attack.workflow.AttackStore.open", return_value=store):
            with self.assertRaisesRegex(RuntimeError, "broker unavailable"):
                workflow.revoke(Path("Attack.db"), run_id="run", reason="stop")
        self.assertEqual(store.authorization_id, "authorization")
        self.assertEqual(store.revocations, [])

    def test_noncompleted_agent_result_is_an_execution_error(self):
        store = FakeStore()
        provider = Mock()
        provider.verify.return_value = {"authorization_id": "authorization"}
        failed = SimpleNamespace(run_id="run", status="failed", hypothesis_count=0,
                                 finding_ids=(), reason="ValueError")
        workflow = SkillAttackWorkflow(planner=Mock(), authorization_provider=provider)
        with patch("aidast.attack.workflow.AttackStore.open", return_value=store), \
             patch("aidast.attack.workflow.prepare_review", return_value=SimpleNamespace()), \
             patch("aidast.attack.workflow.SQLiteEvidenceReader.read", return_value=SimpleNamespace()), \
             patch("aidast.attack.workflow.SkillAttackAgent.run", return_value=failed), \
             patch("pathlib.Path.resolve", return_value=Path("/tmp/source")):
            with self.assertRaisesRegex(RuntimeError, "did not complete: failed"):
                workflow.execute(Path("Attack.db"), run_id="run", authorization=Path("Authorization.json"))


if __name__ == "__main__":
    unittest.main()
