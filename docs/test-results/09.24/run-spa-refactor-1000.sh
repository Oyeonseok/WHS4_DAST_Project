#!/usr/bin/env bash
set -euo pipefail

# Run from the repository root. Preserve the original 1000-request Scope.
RUN_ROOT=result/test-runs/09.24/spa-refactor-1000
SCOPE_SOURCE=result/test-runs/09.24/seclists-api-1000/Scope/lab-aidast-invalid/juice-shop
SCOPE_ROOT="$RUN_ROOT/Scope"
SCOPE_DEST="$SCOPE_ROOT/lab-aidast-invalid/juice-shop"
if [[ ! -e "$SCOPE_DEST" ]]; then
  mkdir -p "$(dirname "$SCOPE_DEST")"
  cp -R "$SCOPE_SOURCE" "$SCOPE_DEST"
  rm -f "$SCOPE_DEST/TargetPolicy.json"
fi

.venv/bin/python -m aidast recon https://lab.aidast.invalid/juice-shop \
  --output-dir "$SCOPE_ROOT" \
  --target http://127.0.0.1:3001/ \
  --start-url http://127.0.0.1:3001/ \
  --session-bundle result/test-runs/09.23/phase-c/sessions/29784ce2455caab98f3e025b/986a1b7135f4986150aa5fa0/60cc869d838607505f62c5a6/Session.json \
  --login-mode none \
  --max-rps 0.5 \
  --max-requests 1000 \
  --max-depth 2 \
  --max-concurrency 1 \
  --timeout-seconds 15 \
  --ffuf-wordlist result/test-runs/09.24/wordlists/common-api-endpoints-mazen160.txt \
  --ffuf-max-time-seconds 150 \
  --db-path "$RUN_ROOT/Recon.db" \
  --surface-path "$RUN_ROOT/Surface.json" \
  --diagnostic-logs \
  --execute
