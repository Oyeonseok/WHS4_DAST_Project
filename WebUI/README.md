# AI DAST workspace

A React + TypeScript dashboard for [WHS4_DAST_Project](https://github.com/Oyeonseok/WHS4_DAST_Project). The local FastAPI adapter projects persisted runs and starts constrained scans; the Python CLI remains responsible for execution, policy, approvals, and state transitions.

## Run

On the prepared Windows workspace, double-click `start-dashboard.cmd`. It starts the
Python adapter in WSL and opens `http://127.0.0.1:8000`; keep the server terminal open.
Opening `dist/index.html` directly with a `file://` URL is not supported because the
live dashboard requires same-origin REST and WebSocket endpoints.

Use Node **22.18+** (Node 24 recommended) and npm. From this directory, including when delivered as `C:\Users\yeonbug\Desktop\UI`:

```sh
npm ci
npm run dev
```

Open `http://localhost:4173`. The development server uses a fixed port. For a production build and local preview:

```sh
npm test
npm run build
npm run preview -- --port 4173
```

Dependencies are pinned in `package.json` and `package-lock.json`. React is the only runtime dependency family. Tests use Node's built-in `node:test` and native TypeScript stripping; no testing dependency is needed.

## Implemented views

- **Overview:** snapshot-derived metrics, all six workflow stages, finding distribution, scope readiness, and review queue.
- **Scopes / Programs:** an empty-by-default URL/visibility intake, durable local collection jobs and activity, public or interactive-browser capture, full draft review, and explicit **Yes / No** approval. Only programs registered by the operator appear in the queue; registration and collection never grant scan authorization by themselves.
- **Scans:** approved-scope-only scan creation, optional scope-checked start URL, persisted-run selection, stage progress, and the real artifact/provenance boundary: `Scope.json`, `Approval.json`, `Recon.db`, `Surface.json`, `Handoff.json`, `Pipeline.db`, and report files.
- **Findings:** severity/text filters and accessible detail dialogs using the existing finding review statuses.
- **Validation:** candidate queue and evidence requirements. This MVP does not fake validation-case records or make confirmation decisions.
- **Reports:** preview/download of an explicitly synthetic Markdown draft in demo mode; live mode lists only local `Report.db` drafts whose stored Markdown hash verifies.
- **Audit log:** clearly labeled fixture decisions in demo mode; live mode projects metadata-only records from append-only `audit_events` while omitting `details_json` entirely.
- **Settings:** connection contract, persisted 한국어/English and System/Dark/Light preferences, session-only density/privacy preferences, and snapshot reload/demo restart.

The top-right language selector switches the full operator UI between **한국어** and **English**. The choice is stored only in local browser storage; the first visit follows the browser language (Korean browsers default to 한국어).

Hash navigation works with browser back/forward. Every view keeps the same scan transport and activity state mounted. The right activity panel supports text, level, and stage filters; pause/resume following; current progress; and collapse/expand. Pausing only pauses scrolling, never ingestion. The latest 500 log entries remain in memory across views; reloading the page resets demo state or fetches a fresh live snapshot. At 900 px and below, activity moves below the main content instead of squeezing it; at 660 px and below, navigation moves to a fixed bottom bar and program cards/forms become single-column. Controls have accessible names, visible focus, and native dialog keyboard/focus behavior.

## Demo and privacy boundary

Demo mode is the default. `demo_local_042` is a synthetic local fixture and has **no relationship to any registered program**. Simulated events tick every 4.2 seconds; progress stops at 96% while illustrative logs continue. This is a replay-style UI demonstration, not a real scan or execution engine.

No program inventory is preloaded. Demo mode cannot launch anything. In live local mode, the Scope page accepts a program URL and Public/Private visibility, then stores only that operator-supplied program in the local intake queue. The operator starts collection separately, follows durable status events, reviews every extracted asset and rule, and must choose **Yes** or **No**. Yes records the reviewer and publishes hash-bound approval artifacts; No deletes the draft. New scan exposes only server-verified approved Scopes and requires explicit target and budget confirmation. Programs without an approved Scope fail closed. A private name and URL are masked in normal API/dashboard views. This protects casual screen sharing, not a compromised local operator session; production private metadata still needs authenticated API authorization before broader distribution. No private metadata is exported by the demo report or written to browser storage.

Demo mode contacts no target and runs no command. Live mode starts the selected authorized scan through the local Python backend. There are no third-party fonts, trackers, analytics, or remote assets.

## Live integration

Copy `.env.example` to `.env.local` and explicitly configure an implemented backend:

```dotenv
VITE_TRANSPORT=live
VITE_SCAN_ID=your_scan_id
VITE_API_BASE_URL=http://127.0.0.1:8000
VITE_WS_BASE_URL=ws://127.0.0.1:8000
```

Restart Vite (or rebuild production assets) after changing variables. API/WS bases default to the browser's origin and paths resolve from the origin root. `VITE_*` values are public: do not put API keys, tokens, cookies, or private endpoints in them. Prefer a same-origin authenticated reverse proxy and HTTPS/WSS in production. REST uses `credentials: same-origin`; the browser supplies same-origin session cookies to WebSockets. Cross-origin cookie authentication is not implemented. The old `VITE_WS_ENABLED` setting is no longer used.

Live mode **never substitutes demo data** after a backend error. It displays loading/offline/reconnecting status and allows snapshot reload. The included adapter registers program intake, runs asynchronous Scope collection, exposes redacted collection activity, requires explicit draft approval, verifies approval artifacts, and starts approved scans from New scan.

Build live assets and serve them with the included backend from the repository root:

```sh
npm run build
cd ..
aidast dashboard --ui-dir WebUI/dist
```

Open `http://127.0.0.1:8000`. The server only accepts loopback binds until remote authentication is implemented. When the UI is served this way, omit API and WebSocket base variables so both use the same origin.

### REST snapshot

`GET /api/v1/scans/{scan_id}` returns a consistent projection with the durable event cursor at which that snapshot was produced. See `Snapshot` in `src/lib/events.ts` for the complete checked schema:

```json
{
  "version": 1,
  "scan_id": "your_scan_id",
  "last_event_id": 7,
  "status": "running",
  "stage": "Attack",
  "progress": 62,
  "requests": 391,
  "budget": 2000,
  "endpoints": 218,
  "scope_approved": true,
  "scope_id": "scope_...",
  "program_id": "h1-prism-vdp",
  "program_name": "PRISM VDP",
  "findings": [],
  "logs": []
}
```

`stage` is one of `Scope`, `Recon`, `Attack`, `Chaining`, `Validation`, `Report`. `status` is `pending`, `running`, `completed`, `failed`, or `cancelled`. Findings contain `id`, `title`, `severity`, `status`, `endpoint`, and `cwe`; review statuses are `unreviewed`, `confirmed`, `rejected`, `resolved`, matching the current SQLite finding contract. Each log contains numeric `id`, ISO `time`, `stage`, `level`, and `message`. REST has a 15-second timeout, cancellation on unmount/reload, runtime validation, and an explicit retry button.

### WebSocket deltas

After a valid snapshot, subscribe to:

```text
/ws/scans/{scan_id}?after={last_event_id}
```

Every frame is a JSON envelope:

```json
{
  "version": 1,
  "event_id": 8,
  "scan_id": "your_scan_id",
  "occurred_at": "2026-09-20T06:00:00Z",
  "type": "log.appended",
  "payload": {
    "stage": "Attack",
    "level": "info",
    "message": "Redacted evidence reference stored"
  }
}
```

Supported type / payload mappings:

| Type | Payload |
| --- | --- |
| `log.appended` | `{ stage, level, message }`; level: `info`, `success`, `warning`, `error` |
| `task.progress.updated` | `{ progress, requests }` |
| `stage.status.changed` | `{ stage }`; resets stage progress to zero |
| `scan.status.changed` | `{ status }` |
| `finding.updated` | Complete finding object; upserts by ID |
| `heartbeat` | `{}`; event ID is the current cursor and does not consume a durable ID |

Durable IDs must be **contiguous and monotonically increasing within the scan**, independent of SQLite audit IDs. All clients subscribed at the same cursor must receive the same durable sequence; do not filter events server-side in a way that introduces gaps. Replay every durable event strictly after `after`, then atomically join the live stream. Heartbeats should arrive at least every 15 seconds and never advance the cursor.

The client validates versions, IDs, scan ownership, timestamps, and payloads before applying events. Duplicate/old events are ignored. Out-of-order frames buffer up to 128 IDs and apply only after the gap closes. An unresolved gap reconnects from the last contiguous cursor at the next 10-second watchdog tick. A larger gap displays a reload instruction. If replay retention has expired, the operator must reload the snapshot; the backend should close the stream with a clear reason. Unknown/malformed events are ignored with a visible protocol message and never advance the cursor, so a version mismatch cannot silently skip state.

Disconnects reconnect with exponential backoff (1–30 seconds plus up to 500 ms jitter). A valid frame resets backoff. After 45 seconds without a valid frame, the watchdog closes the stale socket and reconnects (checked every 10 seconds). Cleanup cancels the REST request, reconnect timer, watchdog, and socket handlers on reload, scan change, or unmount; it is compatible with React StrictMode.

### Included server and remaining work

`aidast dashboard` implements program intake, asynchronous Scope collection and durable job events, explicit draft review/approval, approved-scope listing and program-URL resolution, constrained scan creation, snapshot/list/health endpoints, metadata-only audit projection, integrity-checked local report reads, and the per-scan WebSocket replay contract. Scope drafts remain under `result/.webui/scope-drafts` until a Yes decision atomically publishes `Scope.json`, `Scope.md`, `Manifest.json`, and `Approval.json`; No removes the draft. It keeps `Recon.db`/`Pipeline.db`/`Report.db` read-only, re-verifies approval and report integrity, sanitizes audit messages, omits `details_json`, and stores replay cursors in the separate `result/.webui/events.db` projection cache. The launch endpoint accepts exact approved assets only, validates a specific start URL against its selected canonical target, caps profiles and budgets, requires same-origin browser requests, and invokes `aidast run` without a shell.

The server must enforce scope/approval hash integrity, `TargetPolicy`, request budgets, and authorization envelopes for every request, independent of UI controls. It must authorize reads by scan/program and redact secrets, cookies, authorization headers, credential references, and sensitive bodies **before** sending snapshots, logs, or evidence. Rendering text safely in React is not a replacement for redaction. Do not stream raw tool stdout. Bound event message sizes and persist replay events durably.

Remaining domain endpoints/workflows: authenticated remote access; pause/cancel controls; authorization decisions; validation cases/evidence; report generation or submission; and authoritative audit pagination. None of these writes are faked by this MVP.

## Layout and code

`src/App.tsx` holds the workspace shell and small view components; `src/styles.css` contains the responsive visual system. `src/data/demo.ts` is an isolated fixture. `src/lib/events.ts` owns schema validation, reducers, and ordered replay. `src/hooks/useScanSocket.ts` owns snapshot loading, connection lifecycle, demo timing, and bounded activity state. Only the non-sensitive theme and display-language choices are stored in `localStorage`; private-name visibility, density, operational data, and secrets are not persisted.

`npm test` runs 14 contract tests: exact inventory/privacy, stage order, snapshot rejection and log normalization, malformed frames, ownership/version checks, payload bounds, deduplication, ordering and gap limits, heartbeat semantics, state updates, and bounded log retention. Build verifies strict TypeScript and Vite production bundling. Browser verification notes and a desktop screenshot are in `verification/`.
