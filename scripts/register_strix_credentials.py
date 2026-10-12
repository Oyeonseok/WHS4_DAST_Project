"""Bridge Strix Recon's lab-account session into artex's credential_references.

Why this script exists
-----------------------
artex's own ``aidast recon`` (the deterministic ``ReconExecutor``) registers
Attack's dual-identity credentials automatically: the executor accumulates
``auth_session_files`` while it runs, and ``cli.py`` calls
``register_browser_session_credentials(executor.conn, ...)`` right after Recon
finishes, in the same process.

The Strix engine (``recon/AI-Dast``) runs as a **separate install** against
the same shared Pipeline.db/Recon.db file (confirmed schema-identical:
``pipeline/schema.py`` is byte-for-byte the same in both repos, and
``recon/db.py`` calls ``migrate_pipeline_schema`` in both). There is no
in-process ``executor`` object to hook into, so this script performs the same
registration as a standalone step between the Strix recon run and the
artex-based Attack run.

Usage
-----
After a Strix recon run with ``--allow-lab-account-creation`` (or
``--allow-authorized-account-registration``) that created a *second* account
(Identity B), the agent-browser tool already wrote a Playwright-format
session/storage-state file (see ``recon/AI-Dast``'s
``src/aidast/recon/tools/agent_browser.py``, the ``session_file`` passed to
the browser CLI). Point this script at that file:

    python scripts/register_strix_credentials.py \\
        --db /path/to/Recon.db \\
        --scan-id <scan_id> \\
        --origin https://lab.example.invalid \\
        --session-file /path/to/identity_b.storage_state.json \\
        --identity-role identity_b

This calls artex's own, already-tested ``register_browser_session_credentials``
(``src/aidast/pipeline/browser_credentials.py``) — the exact same function
artex's deterministic Recon uses — so Identity B gets the same validation
(same-origin, authenticated, real auth material) and ends up as a normal row
in ``credential_references`` that ``attack/request_cli.py``'s
``_credential_headers`` / the ported ``guarded_replay`` can resolve.

For the first (primary) account, pass ``--identity-role authenticated``
instead; that is the default single-account role
``register_browser_session_credentials`` already understands.

This script makes no changes to recon or attack code; it only calls an
existing artex function against the shared database file.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

from aidast.pipeline.browser_credentials import register_browser_session_credentials


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True, help="shared Recon.db / Pipeline.db path")
    parser.add_argument("--scan-id", required=True)
    parser.add_argument("--result-root", type=Path, default=None,
                         help="defaults to the --db file's parent directory")
    parser.add_argument("--origin", required=True,
                         help="scheme://host[:port] the session was authenticated against")
    parser.add_argument("--session-file", type=Path, required=True,
                         help="Playwright storage_state JSON written by agent-browser")
    parser.add_argument("--identity-role", default="authenticated",
                         help="'authenticated' for the primary account, or a stable "
                              "role such as 'identity_b' for a second test account")
    args = parser.parse_args(argv)

    if not args.session_file.is_file():
        print(f"session file not found: {args.session_file}", file=sys.stderr)
        return 1

    result_root = args.result_root or args.db.resolve().parent
    session_entry = (
        (args.origin, args.session_file, True)
        if args.identity_role == "authenticated"
        else (args.origin, args.session_file, True, args.identity_role)
    )

    with sqlite3.connect(args.db) as conn:
        registered = register_browser_session_credentials(
            conn, scan_id=args.scan_id, result_root=result_root,
            sessions=[session_entry],
        )

    if not registered:
        print(
            "no credential reference was registered — register_browser_session_credentials "
            "rejected the session (not same-origin, not authenticated, or no real auth "
            "material found in the cookies/headers). Check --origin and --session-file.",
            file=sys.stderr,
        )
        return 1

    for entry in registered:
        print(f"registered: {entry}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
