# Shared pipeline database contract

Use only `pipeline_db_path` and `db_helper_path` from `config.json`. Invoke the
helper with the configured `python_executable`. Never search for another DB.

Read rows with:

```text
PYTHON DB_HELPER query --db PIPELINE_DB --sql-file QUERY.sql
```

The query command opens SQLite read-only. Build endpoint URLs from
`origins.base_url` plus `endpoints.path`. Select rows for one scan through:

```sql
SELECT e.endpoint_id,e.method,e.path,e.normalized_path,e.auth_required,
       o.base_url,p.name,p.location,p.example_value,p.is_identifier
FROM endpoints e
JOIN origins o ON o.origin_id=e.origin_id
JOIN assets a ON a.asset_id=o.asset_id
LEFT JOIN parameters p ON p.endpoint_id=e.endpoint_id
WHERE a.scan_id='SCAN_ID' AND e.is_excluded=0;
```

Write one JSON object at a time with:

```text
PYTHON DB_HELPER commit-attempt --db PIPELINE_DB --scan-id SCAN_ID --payload FILE
PYTHON DB_HELPER resolve-attempt --db PIPELINE_DB --scan-id SCAN_ID --payload FILE
PYTHON DB_HELPER commit-fact --db PIPELINE_DB --scan-id SCAN_ID --payload FILE
PYTHON DB_HELPER commit-finding --db PIPELINE_DB --scan-id SCAN_ID --payload FILE
PYTHON DB_HELPER transition-task --db PIPELINE_DB --scan-id SCAN_ID --stage-run-id STAGE_RUN_ID --task-id TASK_ID --status running|completed|skipped|failed [--reason TEXT]
```

Each configured task starts as `pending`. Start it before its first probe and
finish it only after all of its leads are closed. A directly inapplicable task
may move from `pending` to `skipped`; a failed task requires a reason.

Send exactly one HTTP hop with:

```text
PYTHON HTTP_REQUEST_HELPER request --db PIPELINE_DB --scan-id SCAN_ID --stage-run-id STAGE_RUN_ID --task-id TASK_ID --policy TARGET_POLICY --payload REQUEST.json
```

The request payload contains `method`, `url`, optional string `headers`, optional
UTF-8 `body` (or `body_base64`), and optional `timeout_seconds`. The helper
validates task state and TargetPolicy, reserves the durable shared request/rate/
concurrency budget, disables proxies and redirects, and returns a JSON response
with `request_id`, `request_fingerprint`, status, sanitized headers, and a
bounded body. Never use another HTTP transport. Treat a 3xx `Location` as a new
candidate and submit it as another guarded request only if needed.

`commit-attempt` fields:

```json
{"task_id":"configured task ID","skill_name":"hunt-example","endpoint_id":"endpoint_id or empty","request_fingerprint":"fingerprint returned by HTTP helper","method":"GET","url":"https://target/path","identity_role":"unauthenticated","payload_variant":"short label","response_status":200,"response_signature":"sha256 digest","outcome":"negative|lead|inconclusive"}
```

`commit-finding` requires `scan_id`, optional `endpoint_id`, `vuln_type`,
`severity`, `title`, `description`, optional CVSS/CWE fields, and a non-empty
`evidence` array. Include the IDs of every supporting open lead in
`lead_attempt_ids`; the helper atomically changes them to `confirmed` and links
them to the finding. It also requires exactly one `reproduction` object:

```json
{"method":"GET","endpoint_template":"/api/items/{id}","injection_location":"path","parameter_name":"id","payload_template":{"id":"<slot:string>"},"required_identity_roles":[],"source_request_ids":["HTTP ledger request ID"],"runtime_contract":{"schema_version":1,"target":{"request":{"path_parameters":{"id":"target-object"}},"assertions":[{"assertion_id":"target-effect","kind":"status_equals","expected":200}]},"positive_control":{"request":{"path_parameters":{"id":"owned-object"}},"assertions":[{"assertion_id":"healthy-path","kind":"status_equals","expected":200}]},"negative_control":{"request":{"path_parameters":{"id":"inert-object"}},"assertions":[{"assertion_id":"target-effect","kind":"status_equals","expected":200}]}}}
```

For HTTP findings, include `runtime_contract` whenever the target effect can be
expressed with bounded response assertions. Each attempt declares path/query
values, non-secret headers, one JSON or text body, and one to sixteen assertions.
Supported assertion kinds are `status_equals`, `header_equals`, `body_contains`,
`json_equals`, `duration_at_least_ms`, and `duration_at_most_ms`.

The target assertions describe the vulnerability effect and should pass when it
is reproduced. The positive-control assertions describe a healthy transport,
identity, and parser path and should pass. Negative-control assertions also
describe the vulnerability effect, so they should fail for the inert input. Do
not write an "effect is absent" assertion for the negative control because a
passing assertion means `signal_observed=true`.

Do not place credentials in runtime headers. Declare `required_identity_roles`
and let the trusted Validation runtime resolve their opaque references. Browser,
OOB, and multi-step findings may omit this HTTP-only contract until their
dedicated runtime contract is available.

The native Validation runtime currently resolves `env://NAME` references. The
environment variable must contain a JSON object whose keys and values are the
HTTP credential headers, for example `{"Authorization":"Bearer ..."}`. The
resolved object exists only in memory at dispatch; the request ledger sanitizes
sensitive header values. `keyring://` and `vault://` references require a future
configured backend and are treated as unavailable by the default runtime.

Every source request must be completed, share the supporting attempt's task and
fingerprint, and have one non-null TargetPolicy digest. Each evidence item contains role, method, URL, redacted
request headers/body, response status, redacted response headers/body, and
elapsed ms.

An open lead that does not meet the active Hunt Skill's confirmation gate must
be closed with `resolve-attempt` and a payload such as:

```json
{"attempt_id":"attempt_id","resolution":"rejected|inconclusive","reason":"bounded evidence-based reason"}
```

Never mark a confirmed behavior rejected merely to pass the completion gate.

The helper validates completed-scan ownership and endpoint membership and uses
parameterized transactions. It contains no HTTP or vulnerability logic.
