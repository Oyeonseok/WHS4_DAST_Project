"""Run artex's real ``AttackCoordinator`` (hypothesis planning + coverage +
bounded native Attack batches) directly against a scan that was recon'd
through the Strix bridge (``aidast recon``), bypassing ``aidast resume``.

Why this script exists
-----------------------
``aidast resume`` requires a ``Runs/<scan_id>/Handoff.json`` and a
materialized ``AttackRuns/<scan_id>/Pipeline.db`` snapshot -- artifacts that
only artex's own native ``aidast run`` (``ReconExecutor``) writes. The Strix
bridge path never produces them, by design (the two-installs architecture
keeps recon and attack as separate processes sharing one DB file, rather
than merging the two divergent ``cli.py`` recon implementations).

``AttackCoordinator`` itself (``aidast.orchestration.attack``) does not
actually require that Handoff machinery -- its constructor just takes a
``db_path``, ``scope_path``, and ``policy_path``, all of which a Strix-bridge
scan already has (the shared Recon.db, and the approved Scope's own
Scope.md/TargetPolicy.json). This script calls it directly, the same way
``aidast run`` does internally, without needing the Handoff/Runs/AttackRuns
layout at all.

This script makes no changes to recon, attack, or core code.

Usage
-----
    python scripts/run_attack_coordinator.py \\
        --db /path/to/Recon.db \\
        --scan-id <scan_id> \\
        --scope /path/to/Scope.md \\
        --policy /path/to/TargetPolicy.json \\
        --codex-timeout 3600
"""

from __future__ import annotations

import argparse
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--scan-id", required=True)
    parser.add_argument("--scope", type=Path, required=True, help="path to Scope.md")
    parser.add_argument("--policy", type=Path, required=True, help="path to TargetPolicy.json")
    parser.add_argument("--codex-timeout", type=int, default=3600)
    parser.add_argument("--attack-model", default=None)
    args = parser.parse_args(argv)

    from aidast.agents.main import CodexMainAgent
    from aidast.orchestration.attack import AttackCoordinator

    agent = CodexMainAgent(timeout_seconds=args.codex_timeout)
    planning_agent = (
        CodexMainAgent(timeout_seconds=args.codex_timeout, main_model=args.attack_model)
        if args.attack_model else agent
    )
    coordinator = AttackCoordinator(
        agent=agent, planning_agent=planning_agent,
        db_path=args.db, scope_path=args.scope, policy_path=args.policy,
    )
    result = coordinator.run(args.scan_id)
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
