"""Run the normal Recon CLI with a previously approved target policy fixture.

This test harness bypasses only the model's policy-generation call. The CLI
still validates the pinned policy against the current approved Scope and runs
the usual Recon executor, discovery tools, DB export, and Surface export.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

from aidast import cli
from aidast.recon.policy import TargetPolicy, validate_policy_for_target


def main() -> int:
    if len(sys.argv) < 4 or sys.argv[1] != "--pinned-policy":
        raise SystemExit("usage: recon_with_pinned_policy.py --pinned-policy FILE recon ...")
    policy_path = Path(sys.argv[2])
    data = json.loads(policy_path.read_text(encoding="utf-8"))
    if data.get("schema_version") != "1.0" or len(data.get("policies", [])) != 1:
        raise ValueError("expected exactly one approved policy")
    policy = TargetPolicy.model_validate(data["policies"][0])

    def pinned_policies(self, *, scope_id, scope_markdown, plan, execution_start_urls=None):
        if scope_id != data["scope_id"] or scope_id != policy.scope_id:
            raise ValueError("pinned policy Scope mismatch")
        targets = {(target.asset_type.value, target.asset) for target in plan.targets}
        key = (policy.asset_type.value, policy.asset)
        if targets != {key}:
            raise ValueError(f"pinned policy target mismatch: {targets}")
        validate_policy_for_target(
            policy,
            asset_type=policy.asset_type,
            asset=policy.asset,
            scope_markdown=scope_markdown,
        )
        print(f"Using pinned approved TargetPolicy: {policy_path}", flush=True)
        return {key: policy}

    with patch.object(cli.CodexMainAgent, "create_target_policies", pinned_policies):
        return cli.main(sys.argv[3:])


if __name__ == "__main__":
    raise SystemExit(main())
