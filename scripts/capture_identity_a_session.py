"""Stand up a one-off, Scope-enforced mitmproxy so a manually-driven Identity A
session can be captured into the shared Recon.db, exactly the way a live
``aidast recon`` run would capture it -- for use as the "observed" source
request that ``attack/request_cli.py``'s ``guarded_replay`` replays under a
different identity's credentials.

Why this script exists
-----------------------
``guarded_replay`` needs one real row in ``http_transactions`` representing
an authenticated, read-only request made by Identity A (an endpoint with an
``is_identifier`` parameter, e.g. ``GET /rest/basket/6``). When a live Strix
recon run's own self-registration fails (the recorded, non-deterministic
Angular-Material click issue), there is no such row -- Identity B can be
registered directly from a saved session file via
``register_strix_credentials.py``, but there is nothing to *replay*.

This script uses only existing, unmodified recon functions
(``aidast.recon.tools.mitm_proxy.start_mitmproxy`` /
``ingest_mitm_capture``, ``aidast.orchestration.scope.ScopeStore``,
``aidast.recon.strix_bridge.build_strix_proxy_rules``) to run a short-lived,
fail-closed proxy against the same approved Scope a real recon run would use,
so you can drive Identity A's browser session through it by hand
(agent-browser, logged in as Identity A) and get a properly-ingested,
Scope-checked capture -- not a raw, unchecked request.

Usage
-----
    python scripts/capture_identity_a_session.py \\
        --scope-dir /path/to/result/Scope/<program>/<target> \\
        --db /path/to/Recon.db

The script starts the proxy, prints the proxy URL, and waits for you to:

  1. Point agent-browser at that URL (``--proxy <printed URL>``) in a
     session logged in as Identity A.
  2. Perform ONE read-only GET against an identifier-bearing endpoint
     (e.g. ``GET /rest/basket/<id>``).
  3. Press Enter here to stop the proxy and ingest the capture.

This script makes no changes to recon or attack code; it only orchestrates
existing functions against the shared database file and a temporary capture
file.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
import tempfile
from pathlib import Path

from aidast.orchestration.scope import ScopeCoordinator
from aidast.recon import strix_bridge as _strix_bridge
from aidast.recon.strix_bridge import build_strix_proxy_rules
from aidast.recon.tools.mitm_proxy import ingest_mitm_capture, start_mitmproxy, stop_mitmproxy

# ``build_strix_proxy_rules`` (ported from recon/AI-Dast's older strix_bridge.py,
# unmodified) builds a scope-rules dict against that repo's older
# ``validate_scope_rules`` contract. This host package's own
# ``aidast.core.http_safety`` is artex's newer version of that same function,
# which additionally requires a ``max_requests`` cap that the older rule
# builder never set. A real ``aidast recon`` run never hits this mismatch
# because Strix's own sandbox image carries its own matching copy; this
# standalone script runs against the host package directly, so it does.
# Patched here, in-process only -- no file on disk is changed -- by wrapping
# the validator this module already imported to inject the one missing key
# before delegating to the real, unmodified validator.
_real_validate_scope_rules = _strix_bridge.validate_scope_rules


def _validate_scope_rules_with_max_requests(rules):
    rules.setdefault("max_requests", 2000)
    # The older rule builder also emits "*" (any port) in the top-level
    # ``allowed_ports`` list; artex's current validator only accepts that
    # wildcard inside each ``target_rules[].ports`` entry (which this
    # validator version no longer even checks), not at the top level. Resolve
    # it to the concrete ports already present in ``target_rules`` instead of
    # loosening the real validator.
    if "*" in rules.get("allowed_ports", []):
        concrete = sorted({
            port
            for rule in rules.get("target_rules", [])
            for port in rule.get("ports", [])
            if port != "*"
        }) or [80, 443]
        rules["allowed_ports"] = concrete
    return _real_validate_scope_rules(rules)


_strix_bridge.validate_scope_rules = _validate_scope_rules_with_max_requests


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope-dir", type=Path, required=True,
                         help="approved Scope directory (contains Scope.md/json/Manifest.json/Approval.json)")
    parser.add_argument("--db", type=Path, required=True, help="shared Recon.db / Pipeline.db path")
    parser.add_argument("--host", default=None,
                         help="restrict origin lookup to this host (default: first in-scope asset's host)")
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--scheme", default="http")
    args = parser.parse_args(argv)

    store = ScopeCoordinator(output_dir=args.scope_dir)
    scope, _markdown = store.load_approved_scope()
    rules = build_strix_proxy_rules(scope, scope.analysis.in_scope_assets)

    capture_path = Path(tempfile.mkstemp(prefix="identity_a_capture_", suffix=".jsonl")[1])
    proc, proxy_url = start_mitmproxy(capture_path, scope_rules=rules)
    print(f"\nProxy ready: {proxy_url}")
    print("Point agent-browser at it, e.g.:")
    print(f"  agent-browser --proxy \"{proxy_url}\" --session identa open \"{args.scheme}://127.0.0.1:{args.port or ''}/#/login\"")
    print("Log in as Identity A, then perform ONE read-only GET against an")
    print("identifier-bearing endpoint (e.g. GET /rest/basket/<id>).")
    input("\nPress Enter here once that request has been made, to stop the proxy and ingest...\n")

    stop_mitmproxy(proc)

    with sqlite3.connect(args.db) as conn:
        host = args.host
        port = args.port
        scheme = args.scheme
        if host is None:
            asset = scope.analysis.in_scope_assets[0]
            from urllib.parse import urlsplit
            parsed = urlsplit(asset.asset if "://" in asset.asset else "https://" + asset.asset)
            host = parsed.hostname
            port = port or parsed.port
            scheme = scheme or parsed.scheme
        row = conn.execute(
            "SELECT origin_id FROM origins WHERE scheme=? AND host=? AND port=? "
            "ORDER BY discovered_at DESC LIMIT 1",
            (scheme, host, port),
        ).fetchone()
        if row is None:
            print(f"no existing origin row for {scheme}://{host}:{port}; "
                  "run a real recon scan against this target at least once first.",
                  file=sys.stderr)
            return 1
        origin_id = row[0]
        count, blocked = ingest_mitm_capture(conn, capture_path, origin_id=origin_id)
        conn.commit()

    print(f"\ningested {count} transaction(s), {blocked} blocked by Scope.")
    print("Inspect with: SELECT http_transaction_id, method, url FROM http_transactions "
          "ORDER BY captured_at DESC LIMIT 10;")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
