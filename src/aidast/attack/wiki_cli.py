"""Offline Attack Wiki CLI: ``python -m aidast.attack.wiki_cli``."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from aidast.attack.wiki import AttackWikiError, compare_sources, ingest_database, init_wiki, lint_wiki


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Maintain a post-run Attack evaluation wiki")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "ingest", "compare", "lint"):
        command = commands.add_parser(name)
        command.add_argument("--root", type=Path, required=True)
        if name == "ingest":
            command.add_argument("database", type=Path)
            command.add_argument("--kind", choices=("runtime", "source", "benchmark"), required=True)
            command.add_argument("--scan-id")
            command.add_argument("--target-id")
            command.add_argument("--label")
        elif name == "compare":
            command.add_argument("--observed-source", required=True)
            command.add_argument("--baseline-source", action="append", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            value = {"wiki_root": str(init_wiki(args.root))}
        elif args.command == "ingest":
            value = ingest_database(args.root, args.database, kind=args.kind, scan_id=args.scan_id,
                                    target_id=args.target_id, label=args.label)
        elif args.command == "compare":
            value = compare_sources(args.root, observed_source_id=args.observed_source,
                                    baseline_source_ids=args.baseline_source)
        else:
            issues = lint_wiki(args.root)
            value = {"ok": not issues, "issues": issues}
        print(json.dumps(value, ensure_ascii=False))
        return 1 if args.command == "lint" and not value["ok"] else 0
    except (AttackWikiError, OSError) as exc:
        parser.exit(2, f"Attack Wiki: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
