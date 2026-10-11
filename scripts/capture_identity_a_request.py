"""Record one authenticated, read-only request as a proper Recon capture --
without starting a live mitmproxy -- so it can serve as the "observed"
source request for ``attack/request_cli.py``'s ``guarded_replay`` (IDOR
cross-account replay).

Why this script exists (and why not the proxy)
------------------------------------------------
``guarded_replay`` needs one real row in ``http_transactions`` for a
read-only, identifier-bearing endpoint (e.g. ``GET /rest/basket/<id>``)
observed under Identity A. A live Strix recon run would capture this
automatically if its own self-registration succeeds, but that step is
non-deterministic (documented separately), and the Identity-B path already
proved that credentials can be registered from an externally-obtained
session file (``register_strix_credentials.py``) with no live recon run at
all.

An earlier version of this helper tried to stand up a second,
out-of-band mitmdump (``aidast.recon.tools.mitm_proxy.start_mitmproxy``)
against a hand-built Scope-rules dict, for a human to drive one request
through. That path kept surfacing schema drift between recon/AI-Dast's
older rule-builder and artex's current ``core/http_safety.validate_scope_rules``
(``max_requests``, wildcard ports) and ultimately failed to even bind its
port reliably. None of that is needed: the actual HTTP response from the
single request we care about can be captured directly (we are the client
making it, not sniffing someone else's traffic), and
``aidast.recon.tools.mitm_proxy.ingest_mitm_capture`` already knows how to
turn one capture-shaped JSON line into the same ``http_transactions`` /
``endpoints`` rows a live proxy would have produced. This script builds
that one line itself and calls the same, unmodified ingestion function --
no proxy process, no Scope-rules schema to reconcile.

This script makes no changes to recon, attack, or core code.

Usage
-----
    python scripts/capture_identity_a_request.py \\
        --db /path/to/Recon.db \\
        --origin http://127.0.0.1:3001 \\
        --session-file /path/to/identity_a.json \\
        --path /rest/basket/6
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from aidast.recon.tools.mitm_proxy import ingest_mitm_capture


def _cookie_header(session_file: Path, host: str) -> str:
    state = json.loads(session_file.read_text(encoding="utf-8"))
    pairs = [
        f"{c['name']}={c['value']}"
        for c in state.get("cookies", [])
        if host == c.get("domain", "").lstrip(".") or host.endswith(c.get("domain", "").lstrip("."))
    ]
    if not pairs:
        raise SystemExit(f"no cookies in {session_file} match host {host}")
    return "; ".join(pairs)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--origin", required=True, help="scheme://host[:port]")
    parser.add_argument("--session-file", type=Path, required=True,
                         help="Playwright storage_state JSON for the authenticated identity")
    parser.add_argument("--path", required=True, help="path (and query) to GET, e.g. /rest/basket/6")
    args = parser.parse_args(argv)

    if not args.session_file.is_file():
        print(f"session file not found: {args.session_file}", file=sys.stderr)
        return 1

    parsed = urlsplit(args.origin)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        print("--origin must be scheme://host[:port]", file=sys.stderr)
        return 1
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    url = f"{args.origin.rstrip('/')}{args.path}"

    cookie_header = _cookie_header(args.session_file, host)
    req = urllib.request.Request(url, headers={"Cookie": cookie_header, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 - target is the user's own approved lab asset
            response_status = resp.status
            response_headers = dict(resp.headers.items())
            response_body = resp.read().decode("utf-8", errors="replace")
            content_type = resp.headers.get("Content-Type")
    except urllib.error.HTTPError as exc:
        response_status = exc.code
        response_headers = dict(exc.headers.items()) if exc.headers else {}
        response_body = exc.read().decode("utf-8", errors="replace")
        content_type = response_headers.get("Content-Type")

    record = {
        "method": "GET",
        "url": url,
        "request_headers": {"Cookie": cookie_header, "Accept": "application/json"},
        "response_status": response_status,
        "response_headers": response_headers,
        "response_body": response_body,
        "content_type": content_type,
        "scope_allowed": True,
        "policy_blocked": False,
        "capture_bodies": True,
        "source_tool": "capture_identity_a_request",
        "captured_at": datetime.now(timezone.utc).isoformat(),
    }

    capture_path = Path(tempfile.mkstemp(prefix="identity_a_", suffix=".jsonl")[1])
    capture_path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    with sqlite3.connect(args.db) as conn:
        row = conn.execute(
            "SELECT origin_id FROM origins WHERE scheme=? AND host=? AND port=? "
            "ORDER BY discovered_at DESC LIMIT 1",
            (parsed.scheme, host, port),
        ).fetchone()
        if row is None:
            print(f"no existing origin row for {parsed.scheme}://{host}:{port}; "
                  "run a real recon scan against this target at least once first.",
                  file=sys.stderr)
            return 1
        origin_id = row[0]
        count, blocked = ingest_mitm_capture(conn, capture_path, origin_id=origin_id)
        conn.commit()
        if count:
            tx_row = conn.execute(
                "SELECT http_transaction_id FROM http_transactions "
                "WHERE url=? ORDER BY captured_at DESC LIMIT 1",
                (url,),
            ).fetchone()
            print(f"http_transaction_id: {tx_row[0] if tx_row else '(not found)'}")

    print(f"ingested {count} transaction(s), {blocked} blocked. response_status={response_status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
