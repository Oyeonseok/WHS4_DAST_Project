"""Read-only GET coverage evaluation for standalone ReconExecutor runs."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sqlite3
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[4]
TRUTH_PATH = ROOT / "docs/test-results/09.24/_archive/JUICE_SHOP_GET_GROUND_TRUTH.json"
spec = importlib.util.spec_from_file_location(
    "route_evaluation", ROOT / "docs/test-results/09.24/_archive/evaluate_recon_get_routes.py"
)
assert spec is not None and spec.loader is not None
evaluation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evaluation)


def analyze(label: str, directory: Path, truth: dict) -> dict:
    summary = json.loads((directory / "summary.json").read_text())
    if summary["failures"]:
        raise ValueError(f"failed standalone run: {label}")
    with sqlite3.connect((directory / "Recon.db").resolve().as_uri() + "?mode=ro", uri=True) as conn:
        conn.row_factory = sqlite3.Row
        latest = {}
        for row in conn.execute("SELECT task_id,status FROM pipeline_runs ORDER BY rowid"):
            latest[row["task_id"]] = row["status"]
        if len(latest) != 3 or set(latest.values()) != {"success"}:
            raise ValueError(f"recon tasks not successful: {label}: {latest}")
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError(f"DB integrity failed: {label}")
        if conn.execute("PRAGMA foreign_key_check").fetchall():
            raise ValueError(f"DB references failed: {label}")
        transactions = list(conn.execute("""
            SELECT t.url,t.response_status,e.is_excluded
            FROM http_transactions t LEFT JOIN endpoints e USING(endpoint_id)
            WHERE t.method='GET' AND t.response_status IS NOT NULL
        """))
        origin = urlsplit(truth["origin"])
        transactions = [
            row for row in transactions
            if (urlsplit(row["url"]).scheme, urlsplit(row["url"]).netloc)
            == (origin.scheme, origin.netloc)
        ]
        surface = json.loads((directory / "Surface.json").read_text())
        paths = [
            e["path"] for o in surface["origins"] if o["base_url"] == truth["origin"]
            for e in o["endpoints"] if e["method"] == "GET"
        ]
        routes = {}
        for route in truth["routes"]:
            matching = [r for r in transactions if evaluation._matches(route[4:], urlsplit(r["url"]).path)]
            routes[route] = {
                "included_http_statuses": sorted({r["response_status"] for r in matching if r["is_excluded"] == 0}),
                "all_http_statuses": sorted({r["response_status"] for r in matching}),
                "in_surface": any(evaluation._matches(route[4:], path) for path in paths),
            }
        deferred = list(conn.execute("SELECT url,priority FROM deferred_candidates"))
    diagnostics = [json.loads(line) for line in (directory / "recon.jsonl").read_text().splitlines()]
    progress = json.loads(next(directory.glob("*.progress.json")).read_text())
    return {
        "label": label, "summary": {k: v for k, v in summary.items() if k != "phases"},
        "recon_tasks": latest,
        "db_integrity": "ok", "foreign_key_errors": 0,
        "scan_row_note": "Standalone runner leaves scans.status=running; all three Recon tasks must have success records.",
        "coverage": {key: sum(bool(r[key]) for r in routes.values()) for key in ("included_http_statuses", "all_http_statuses", "in_surface")},
        "routes": routes, "proxy_progress": progress,
        "deferred_target_requests": sum(urlsplit(r["url"]).netloc == origin.netloc for r in deferred),
        "adaptive_js": [x["details"] for x in diagnostics if x["event"] == "completed" and x["details"].get("component") == "adaptive_js"],
        "phase_errors": [x for x in diagnostics if x["event"] == "phase_error"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="append", required=True, metavar="LABEL=DIRECTORY")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    truth = json.loads(TRUTH_PATH.read_text())
    runs = [analyze(label, Path(path), truth) for label, path in (value.split("=", 1) for value in args.run)]
    result = {"truth": str(TRUTH_PATH.relative_to(ROOT)), "truth_sha256": hashlib.sha256(TRUTH_PATH.read_bytes()).hexdigest(), "route_count": len(truth["routes"]), "runs": runs}
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2))
    for run in runs:
        print(run["label"], json.dumps({"coverage": run["coverage"], "proxy": run["proxy_progress"], "adaptive_js": run["adaptive_js"]}))


if __name__ == "__main__":
    main()
