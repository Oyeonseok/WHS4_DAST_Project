"""Archive pinned Juice Shop candidates for post-run AttackWiki evaluation.

This creates a sanitized source snapshot, never a fabricated Pipeline.db or
Attack finding. Without a reviewed mapping manifest, all 116 official challenges remain
unmapped and unassessed and all recall denominators are zero (recall is N/A).
The candidate inventory's four separate Juice Shop controls are not challenges
and are excluded from this official baseline.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from pathlib import Path

from aidast.attack.candidate_baseline import SOURCE_FIELDS, ingest_candidate_baseline
from aidast.attack.wiki import AttackWikiError, _load
from scripts.build_validation_candidates import JUICE_SHA256, JUICE_VERSION, ROOT, juice_candidates


def build_baseline(
    root: Path, observed_source_id: str, *,
    juice_source: Path = ROOT / "resources/lab/juice-shop-v20.2.0-challenges.yml",
    candidate_inventory: Path | None = None, mapping_path: Path | None = None,
    route_reference: Path = ROOT / "resources/lab/juice-shop-v20.2.0-routes.json",
) -> dict:
    raw = juice_source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != JUICE_SHA256:
        raise AttackWikiError("Juice Shop source differs from pinned v20.2.0 challenges")
    candidates = juice_candidates(juice_source)
    if candidate_inventory is not None:
        # A shared inventory may contain VulnBank and controls; only exact
        # official Juice Shop rows are admitted into this version-bound set.
        with sqlite3.connect(candidate_inventory.resolve().as_uri() + "?mode=ro", uri=True) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("BEGIN")
            rows = [dict(row) for row in conn.execute(
                "SELECT * FROM attack_candidates WHERE project='juice-shop' AND claim_basis='official_challenge'")]
            metadata = dict(conn.execute("SELECT key,value FROM inventory_metadata"))
        expected = {row["candidate_id"]: {key: row[key] for key in SOURCE_FIELDS} for row in candidates}
        actual = {row["candidate_id"]: {key: row[key] for key in SOURCE_FIELDS} for row in rows}
        if (metadata.get("juice_shop_version") != JUICE_VERSION
                or metadata.get("juice_shop_source_sha256") != JUICE_SHA256 or actual != expected
                or len(rows) != len(actual)):
            raise AttackWikiError("candidate inventory does not match the pinned official Juice Shop set")

    sources = {row["source_id"]: row for row in _load(root.expanduser().resolve())}
    observed = sources.get(observed_source_id)
    if observed is None or observed["kind"] != "runtime":
        raise AttackWikiError("Juice Shop baseline requires an archived terminal runtime observation")
    reference = json.loads(route_reference.read_text(encoding="utf-8"))
    if (reference.get("reference_id") != "owasp-juice-shop-v20.2.0-source-routes"
            or reference.get("version") != JUICE_VERSION.removeprefix("v")):
        raise AttackWikiError("Juice Shop route reference is not the pinned application version")
    # This guards against the original accidental VulnBank selection. Route
    # overlap is an application consistency check, not proof of runtime version.
    routes = {tuple(route.split(" ", 1)) for route in reference["routes"]
              if route.split(" ", 1)[1].startswith(("/api/", "/rest/"))}
    observed_routes = {(item["method"], item["path"]) for item in observed["inventory"]["items"]}
    if not routes & observed_routes:
        raise AttackWikiError("observed route inventory does not overlap the Juice Shop application reference")
    manifest = json.loads(mapping_path.read_text(encoding="utf-8")) if mapping_path is not None else None
    return ingest_candidate_baseline(root, candidates, project="juice-shop",
                                     observed_source_id=observed_source_id,
                                     source_version=JUICE_VERSION, source_sha256=JUICE_SHA256,
                                     mapping_manifest=manifest)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--observed-source", required=True)
    parser.add_argument("--juice-source", type=Path,
                        default=ROOT / "resources/lab/juice-shop-v20.2.0-challenges.yml")
    parser.add_argument("--candidate-inventory", type=Path)
    parser.add_argument("--mapping", type=Path)
    args = parser.parse_args(argv)
    try:
        value = build_baseline(args.root, args.observed_source, juice_source=args.juice_source,
                               candidate_inventory=args.candidate_inventory, mapping_path=args.mapping)
    except (AttackWikiError, OSError, sqlite3.Error, ValueError, KeyError) as exc:
        parser.exit(2, f"Juice Shop AttackWiki baseline: {exc}\n")
    print(json.dumps(value, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
