# Persistent Attack coverage evaluation

Attack Wiki accumulates sanitized post-run evidence from `Pipeline.db` (or a
compatible `Attack.db`) for the same logical target. It follows the immutable
raw sources, derived wiki, schema, index and log pattern from
[Karpathy's LLM Wiki idea file](https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f).
Compilation here is deterministic so model summaries cannot invent evidence.

The Wiki is an evaluation artifact. Attack planners, coordinators and request
executors never import or read it. Source and benchmark baselines are selected
after a scan reaches a terminal state; comparison never inserts annotations,
hypotheses, findings or work into the running database. Snapshot reads use one
read-only SQLite transaction, including committed WAL changes, without schema
migrations. Active stages and requests prevent runtime ingestion. Interrupted
terminal runs may retain unfinished coverage, which remains untested.

`raw/*.json` stores immutable content-addressed inventories with scan/stage IDs,
coverage/endpoint/annotation IDs, policy hashes, completed HTTP request IDs and
independent Validation decisions. Request bodies, credential values, query
values, payload variants and replay instructions are omitted. The inventory
SHA256 and identity are checked when loading snapshots. `wiki/sources` links
to raw evidence; `wiki/targets` retains each run, a deduplicated historical
union, and contradictory outcomes. The union records history, not the current
deployment's vulnerability status. `wiki/comparisons` stores Markdown and JSON
reports. Duplicate ingestion preserves the raw snapshot and adds no log entry.

Kinds have explicit semantics: `runtime` is evidence from terminal execution;
`source` and `benchmark` supply evaluation coordinates rather than runtime
discoveries. Source-imported or vulnerability-annotated execution is labeled
`source_assisted`, separate from `black_box`. This is a provenance diagnostic;
it is not proof against knowledge passed through external agent context.

The exact comparison key is `(origin, HTTP method, normalized path,
vulnerability class, injection location, parameter name, identity role)`.
Origins include non-default ports; path placeholders normalize to `:id`.
Methods, inputs and authentication roles are never collapsed. Explicit target
IDs group scans, but mismatching origins still reject a comparison. Endpoint
IDs may change between runs without changing the coverage key.

Planned recall measures selected hypotheses. Tested recall additionally requires
a persisted tested/candidate/confirmed disposition and completed same-task,
same-stage HTTP evidence bound to the endpoint/method/origin. An unknown outcome,
skipped task or authentication/policy blocker is never an actual test. Candidate
recall needs a finding; confirmed recall needs completed independent Validation
with `CONFIRMED`. Attack's own `confirmed` label is insufficient.

For source/benchmark comparisons, all supplied coverage coordinates are the
claim denominator. For historical runtime comparisons, only previously tested
coordinates form the coverage denominator; only independently confirmed
coordinates form the positive finding denominator. Source/benchmark provenance
alone is not a positive verdict: their positive denominator requires an explicit
`VULNERABLE` adjudication with an evidence reference. Existing source coverage
imports without adjudications therefore have no positive denominator.
Candidate/confirmed recall is `null` (displayed N/A) when no adjudicated or
historically confirmed positives exist. Multiple explicit
baseline snapshot IDs form a deduplicated union. Runtime baselines must precede
the observed run; a run cannot be compared to itself.

Comparisons retain the full baseline denominator and report missing tests by
their persisted disposition (`policy_excluded`, `blocked_auth`, `unsupported`,
or other statuses); absent hypotheses are `not_planned`. These are execution
diagnostics, not independently reviewed eligibility labels. `unsupported` can
also mean exhausted execution budgets, so dropping it would inflate coverage.
No eligible vulnerability detection recall is inferred from these inventories.

## Offline workflow

```sh
python -m aidast.attack.wiki_cli ingest result/earlier/Pipeline.db \
  --root result/AttackWiki/example --kind runtime --target-id example
python -m aidast.attack.wiki_cli ingest result/current/Pipeline.db \
  --root result/AttackWiki/example --kind runtime --target-id example
python -m aidast.attack.wiki_cli compare --root result/AttackWiki/example \
  --observed-source runtime-CURRENT_ID --baseline-source runtime-EARLIER_ID
python -m aidast.attack.wiki_cli lint --root result/AttackWiki/example
```

Use `--kind source` or `--kind benchmark` for an existing coverage database
whose coordinates are evaluation claims. Ingestion does not generate a coverage
manifest from source code. Add `--scan-id` for a database with multiple scans.

### Official Juice Shop candidate baseline

Juice Shop v20.2.0 has **116 official challenges**. The shared inventory's
120 Juice Shop candidates also include four separate controls, which this
official baseline excludes. The source statuses remain 92 `UNASSESSED`,
18 `OUT_OF_TEST_SCOPE` (disabled in Docker), and six `MANUAL_ONLY`.
An official challenge is a candidate, not an established true positive.

First archive the terminal runtime with the existing `ingest --kind runtime`
command, then create the baseline in that same Wiki:

```sh
python -m scripts.build_juice_shop_attack_baseline \
  --root result/AttackWiki/juice-shop --observed-source runtime-CURRENT_ID
python -m aidast.attack.wiki_cli compare --root result/AttackWiki/juice-shop \
  --observed-source runtime-CURRENT_ID --baseline-source source-CANDIDATE_ID
```

The builder validates the pinned source hash and checks observed API route
overlap with the Juice Shop route reference, rejecting a disjoint application
such as VulnBank. This consistency check does not prove the deployment version.
Optional `--candidate-inventory CandidateInventory.db` reads only matching
official rows and requires their provenance and complete set to match the
pinned definitions. It never creates a synthetic `Pipeline.db` or modifies
the runtime database. The snapshot is bound to the archived observation and
inherits its target and deployment origins.

By default, all 116 candidates remain unmapped and unadjudicated. They remain
visible in immutable evidence and reports; coverage and positive denominators
are zero and recall is N/A. Use optional `--mapping reviewed-mappings.json`
only after independent review. A manifest has `schema_version: 1`,
`project: "juice-shop"`, `source_version: "v20.2.0"`, the pinned
`source_sha256`, and an `entries` list. Each entry names `candidate_id`,
`mapping_evidence_ref`, and `coordinates`, a list of complete seven-field
coverage keys. Routes, taxonomy, parameters and identity roles are never
inferred from challenge titles or categories. Missing entries remain unmapped.
An optional `adjudication_status` is `UNASSESSED`, `VULNERABLE`, or
`NOT_VULNERABLE`; either verdict requires `adjudication_evidence_ref`.
Mapped unassessed candidates contribute only to coverage, while source scope
exclusions and unmapped adjudications contribute to neither recall denominator.
Conflicting positive/negative coordinate adjudications are reported and
excluded from the positive denominator. Multi-snapshot comparisons preserve
each candidate's mapping and verdict history; unique candidate status counts
may overlap when reviews disagree. These are evaluation snapshots under
AttackWiki, consumed only after execution; do not pass them or their manifests
to Attack agents.

## Dashboard API

`GET /api/v1/attack-wiki/databases` catalogs coverage databases below the
configured result root. Opaque IDs address databases; symlink escapes are
excluded. `GET /api/v1/scans/{scan_id}/attack-wiki` returns saved evaluation.
The same-origin `POST` requires a completed, failed or cancelled scan and
accepts `{baseline_id, baseline_kind, target_id}`. Omit `baseline_id` to archive
only; select `runtime`, `source` or explicitly `benchmark` to compare. Results
include planned/tested/candidate/confirmed counts, execution provenance, recall
denominators, missing-test count, integrity lint and the full comparison report.
All Wiki writes remain under `result/AttackWiki/{program}`.

This initial dashboard interface uses explicit accumulation and one selected
baseline per comparison. The offline comparator supports a union of prior
snapshots. Runtime executors have no access path to these baselines.

## Dashboard workflow for local labs

1. Register and approve the local lab program, then open **New scan**.
2. Select `gpt-6.1-sol` for Recon and Attack. Use the safe Recon profile and
   keep the request limits within the approved local policy.
3. Select **Browser login** when authenticated routes are part of the expected
   coverage. Finish login or local-lab signup in the Chromium window and use a
   disposable account. An anonymous scan cannot test authenticated hypotheses.
4. Let the scan finish through Report. On **Scans**, review endpoint Attack
   coverage before the Wiki score: attempted/tested endpoints, authentication
   blockers, policy exclusions and unsupported contracts explain the gaps.
5. In **Attack Wiki accumulation and evaluation**, set a stable logical target
   and version ID. Accumulate the current result. Select a source/benchmark DB
   only when it represents the same deployed version, then compare.
6. Treat **tested recall** as executed coverage and **confirmed recall** as the
   independently validated subset. `N/A` means the selected baseline contains
   no independently confirmed positive denominator.

The current browser-login workflow captures one identity per origin. Tests that
require two principals, such as owner-versus-foreign IDOR differentials, remain
`blocked_auth` unless two opaque credential references already exist in the
scan. Challenges requiring destructive state changes, social engineering,
external services or unsupported protocols stay outside the eligible safe
black-box evaluation scope and remain visible as explicit blockers. The current
Wiki does not have a reviewed eligibility manifest: its full-baseline coverage
recall retains those coordinates in the denominator and reports their distinct
dispositions. An eligible detection recall requires a separately reviewed,
version-bound eligibility baseline.
