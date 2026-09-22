from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from aidast.recon.executor import ReconExecutor
from aidast.recon.models import ReconStep, ReconTask, ReconTaskTarget
from aidast.recon.policy import TargetPolicy
from aidast.scope.models import AssetType


class ReconUrlSelectionTests(unittest.TestCase):
    def test_approved_url_target_keeps_its_port_for_http_probe(self) -> None:
        asset = "http://127.0.0.1:5001/"
        target = (AssetType.URL.value, asset)
        policy = TargetPolicy(
            scope_id="scope_local",
            policy_id="policy_local",
            asset_type=AssetType.URL,
            asset=asset,
            allowed_schemes=["http"],
            allowed_hosts=["127.0.0.1"],
            allowed_ports=[5001],
        )
        task = ReconTask(
            task_id="task_probe",
            plan_id="plan_local",
            scope_id="scope_local",
            task_type=ReconStep.HTTP_PROBE,
            sequence=1,
            target=ReconTaskTarget(asset_type=AssetType.URL, asset=asset),
            depends_on_task_ids=[],
            constraints=[],
        )
        with tempfile.TemporaryDirectory() as directory:
            executor = ReconExecutor(
                scan_id="scan_local",
                scope_type="approved_scope",
                scope_value="scope_local",
                db_path=Path(directory) / "Recon.db",
                target_policies={target: policy},
                require_policy_enforcement=True,
            )
            try:
                start_url = executor._url_for(task)
                self.assertEqual(start_url, asset)
                self.assertTrue(policy.allows_url(start_url))
            finally:
                executor.close()


if __name__ == "__main__":
    unittest.main()
