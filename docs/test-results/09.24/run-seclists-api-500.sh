#!/usr/bin/env bash
set -euo pipefail

# Run from the repository root. Uses the existing primary Juice Shop session.
.venv/bin/python -m aidast recon https://lab.aidast.invalid/juice-shop \
  --target http://127.0.0.1:3001/ \
  --start-url http://127.0.0.1:3001/ \
  --session-bundle result/test-runs/09.23/phase-c/sessions/29784ce2455caab98f3e025b/986a1b7135f4986150aa5fa0/60cc869d838607505f62c5a6/Session.json \
  --login-mode none \
  --max-rps 0.5 \
  --max-requests 500 \
  --max-depth 2 \
  --max-concurrency 1 \
  --timeout-seconds 15 \
  --ffuf-wordlist result/test-runs/09.24/wordlists/common-api-endpoints-mazen160.txt \
  --db-path result/test-runs/09.24/seclists-api-500/Recon.db \
  --surface-path result/test-runs/09.24/seclists-api-500/Surface.json \
  --diagnostic-logs \
  --execute
