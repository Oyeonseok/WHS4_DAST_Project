# Source Recon Import and VulnBank Pipeline Validation

Date: 2026-09-24 (Asia/Seoul)

## Objective

Exercise AIDAST's Attack, Validation, and Report stages without running the normal
Scope or network Recon stages. The operator supplies an authorized local source
tree and the URL of the matching target. AIDAST passively converts that source
into its normal completed Recon handoff contract.

The validation target was the intentionally vulnerable VulnBank training
application at source commit `4bb7cd5f46921959f034455e5615782481966177`.
Active replay was performed only against an isolated loopback deployment at
`http://127.0.0.1:5001`.

## New command

```bash
aidast import-recon SOURCE \
  --target-url TARGET_URL \
  --result-root RESULT_ROOT \
  --by OPERATOR \
  --source-ref COMMIT_OR_VERSION
```

The importer currently supports Flask route decorators. It parses Python with
the standard AST and does not import or execute target source code.

Generated artifacts include:

- `Scope.md` and its authorization snapshot
- `TargetPolicy.json`
- a completed `Recon.db`
- `Surface.json`, `ReconReview.json`, and `SourceInventory.json`
- `Handoff.json`
- a materialized `Pipeline.db` ready for `aidast resume`

## Safety boundaries

- Public targets must use HTTPS. Plain HTTP is accepted only for loopback hosts.
- Source comments become bounded vulnerability-class planning signals, not
  findings or proof of exploitability.
- Source values and hard-coded secrets are never copied into Recon observations.
- The generated policy forbids destructive methods, denial of service, brute
  force, external SSRF/OOB callbacks, and destructive or bulk operations.
- A finding still requires Attack evidence and an atomic reproduction contract.
- A report still requires an independently confirmed Validation case.

## Implementation changes

- `src/aidast/recon/source_import.py`
  - Enumerates Flask route decorators and GET/POST method variants.
  - Normalizes Flask route variables into AIDAST endpoint templates.
  - Extracts path, query, form, and JSON parameter names.
  - Associates bounded source vulnerability annotations with exact endpoints and
    source locations.
  - Writes the production Recon and Pipeline handoff artifacts.
- `src/aidast/cli.py`
  - Adds `import-recon`.
  - Adds `--codex-timeout` to `aidast resume`.
- `src/aidast/attack/skill_selector.py`
  - Converts source vulnerability annotations into weighted planning signals.
  - Preserves the existing maximum of eight selected Attack skills.
- `src/aidast/orchestration/attack.py`
  - Allows a resumed agent to return already-persisted finding IDs while still
    requiring all newly committed findings to be reported and all reported IDs
    to exist in the database.
- `src/aidast/validation/core/integrity.py`
  - Accepts evidence from an individually completed task in a failed stage only
    when explicit `resume_from_stage_run_id` links lead to a later completed
    Attack stage.
  - Does not accept failed-stage evidence without that completed resume lineage.
- `tests/test_source_recon_import.py`
  - Covers route/parameter extraction, artifact generation, target restrictions,
    and source-driven skill selection.
- `tests/test_validation_coordinator.py`
  - Covers both acceptance and rejection boundaries for resumed evidence.

## Imported inventory

The source inventory contains:

- 81 method-and-route endpoints: 49 GET and 32 POST
- 84 parameters: 66 JSON, 13 path, 4 query, and 1 form
- 108 source annotations across 14 bounded classes
- 21 SQLi, 8 API misconfiguration, 8 auth bypass, 7 brute force,
  7 IDOR, 4 JWT/crypto, 4 race-condition, 3 LLM/AI, 2 SSRF, and one
  each for CSRF, file upload, LFI, and XSS; 40 source-leak annotations

These numbers describe source markers and attack hypotheses. They do not mean
that 108 remotely exploitable vulnerabilities were confirmed.

## Pipeline result

Authoritative local scan: `scan_1cc0a5e796604722adfc8b4dd932f39b`

- Recon: completed from the passive source import
- Attack: completed after a durable resume
- Chaining: completed; no demonstrated chain was promoted
- Validation: completed with one CONFIRMED and one INCONCLUSIVE case
- Report: drafted for the confirmed case only

Confirmed case:

- `GET /transactions/{account_number}`
- Unauthenticated UNION-based SQL injection
- Three target replays observed the signal
- The positive control succeeded and the inert negative control did not produce
  the target signal
- Validation severity: MEDIUM; impact score: 6

Inconclusive case:

- AI system configuration/system-prompt exposure
- Attack evidence exists, but the finding lacked an executable HTTP runtime
  contract, so Validation correctly stopped at reproduction preflight

The public `https://www.vulnbank.org` trial returned HTTP 403 for every probe.
It produced no findings and was not treated as proof that the source hypotheses
were false. The isolated local deployment was used for deterministic functional
validation instead.

## Verification

Focused regression suite:

```text
88 passed, 109 subtests passed
```

The earlier full repository run completed with `1004 passed`, `6 skipped`, and
`509 subtests passed`; its 64 failures were environment-specific existing issues
(macOS `/var` path alias assertions and sandbox-denied loopback binds), not source
import failures.

The final Pipeline database passed `PRAGMA integrity_check` and returned no rows
from `PRAGMA foreign_key_check`.

## Reproduction commands

```bash
RESULT_ROOT="$PWD/result/VulnBankSourceRun"
SOURCE_ROOT="/path/to/vuln-bank"
SOURCE_REF="$(git -C "$SOURCE_ROOT" rev-parse HEAD)"

aidast import-recon "$SOURCE_ROOT" \
  --target-url "http://127.0.0.1:5001" \
  --result-root "$RESULT_ROOT" \
  --by "local-operator" \
  --source-ref "$SOURCE_REF"

aidast resume SCAN_ID \
  --result-root "$RESULT_ROOT" \
  --codex-timeout 86400

aidast validate status \
  "$RESULT_ROOT/AttackRuns/SCAN_ID/Pipeline.db" \
  --scan-id SCAN_ID

aidast report run \
  "$RESULT_ROOT/AttackRuns/SCAN_ID/Pipeline.db" \
  --case-id CONFIRMED_CASE_ID \
  --platform hackerone \
  --output-dir "$RESULT_ROOT/ReportRun/CONFIRMED_CASE_ID"
```

The generated report is a local benchmark draft and must not be submitted as a
real bounty report for the intentionally vulnerable training application.
