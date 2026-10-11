#!/usr/bin/env bash
set -euo pipefail

# Same authenticated Recon inputs as the prior 1000-request run. The approved
# TargetPolicy is pinned because the live policy model call timed out.
RUN_ROOT=${RECON_TEST_RUN_ROOT:-result/test-runs/09.24/recon-retest-pinned-policy-2026-09-26}
RECON_WRAPPER=${RECON_TEST_WRAPPER:-docs/test-results/09.24/_archive/recon_with_pinned_policy.py}
SCOPE_SOURCE=result/test-runs/09.24/spa-refactor-1000/Scope/lab-aidast-invalid/juice-shop
POLICY_SOURCE=result/test-runs/09.24/browser-luna-full-1000/Scope/lab-aidast-invalid/juice-shop/TargetPolicy.json
SCOPE_ROOT="$RUN_ROOT/Scope"
SCOPE_DEST="$SCOPE_ROOT/lab-aidast-invalid/juice-shop"
if [[ ! -e "$SCOPE_DEST" ]]; then
  mkdir -p "$(dirname "$SCOPE_DEST")"
  cp -R "$SCOPE_SOURCE" "$SCOPE_DEST"
  rm -f "$SCOPE_DEST/TargetPolicy.json"
fi

.venv/bin/python "$RECON_WRAPPER" \
  --pinned-policy "$POLICY_SOURCE" \
  recon https://lab.aidast.invalid/juice-shop \
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
