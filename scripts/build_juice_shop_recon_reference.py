#!/usr/bin/env python3
"""Build the pinned OWASP Juice Shop source-route Recon.db."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from aidast.recon.reference import build_reference_database


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest", type=Path,
        default=Path("resources/lab/juice-shop-v20.2.0-routes.json"),
    )
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--target-url", default="http://127.0.0.1:5001/")
    args = parser.parse_args()
    result = build_reference_database(
        args.manifest, args.database, target_url=args.target_url,
    )
    payload = asdict(result)
    payload["database"] = str(payload["database"])
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
