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
coordinates form the positive finding denominator. Candidate/confirmed recall
is `null` (displayed N/A) when no historical positives exist. Multiple explicit
baseline snapshot IDs form a deduplicated union. Runtime baselines must precede
the observed run; a run cannot be compared to itself.

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
black-box denominator and remain visible as explicit blockers.
