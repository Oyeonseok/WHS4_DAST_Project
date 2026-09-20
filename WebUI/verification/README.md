# Verification record

Verified on 2026-09-20 with Node 24.18.1 and the available Chromium/Playwright browser tools.

- `npm test`: **14 passed, 0 failed**. Native Node contract tests cover the exact inventory, private flag, stage order, snapshot validation, malformed/foreign/versioned frames, bounds, duplicate handling, ordered replay, gap limits, heartbeat cursor semantics, finding/stage/status updates, and 500-log retention.
- `npm run build`: **passed**, strict TypeScript plus Vite production bundle. Approximate compressed output: JavaScript 95 kB, CSS 11 kB. No extra runtime dependencies beyond React/React DOM.
- Browser: all eight sidebar destinations render their expected heading, including hash navigation. The program inventory starts empty and displays only programs registered through the local intake API. Private names start masked and can be revealed or hidden again. Verified Scope counts come from `GET /api/v1/scopes`, not from whichever scan happens to be selected.
- Scope intake accepts a program URL plus Public/Private visibility and creates a durable local queue entry. Private API/dashboard output masks the stored name and URL. Registration does not approve an executable Scope.
- New scan lists only integrity-verified approved Scopes and their canonical targets. The specific start-URL control remains disabled until exactly one target is selected. With one approved target, an in-scope start URL, platform identity, and authorization confirmation, Start scan becomes enabled. The button was not clicked and no real target scan was launched.
- Activity ingestion continued from 22 to 23 visible log entries while scrolling was paused and the user navigated from Overview to Findings. Resume following worked.
- Responsive check: all eight destinations plus the Add Program and New Scan dialogs were exercised at **768 and 390 px**, with desktop regression checks at **1024 and 1440 px**. There is no document-level horizontal overflow. At 390 px navigation is fixed to the bottom; Scope cards/forms, scan statistics, settings, and action rows reflow without clipping; the six-stage pipeline uses a two-column layout. At 768 px Live activity stacks below the main content; desktop retains the full sidebar and right activity rail. Narrow finding tables scroll within their panel. Sidebar icon buttons retain accessible labels on tablets/phones.
- Mocked live test: REST snapshot cursor 7, received WS events 9, malformed JSON, 8, duplicate 8. Display order was 8 then 9; duplicate was ignored; protocol warning was visible. After a simulated disconnect, the next subscription used `after=9`, applied event 10, and showed exactly three messages in order. First URL: `/ws/scans/demo_local_042?after=7`; second: `/ws/scans/demo_local_042?after=9`.
- Mocked live REST 503 test: backend-unavailable state and retry control appeared; zero fixture log entries and no synthetic lab scan were displayed.
- Live audit API returned the selected scan's newest-first event metadata and omitted `details_json`, request bodies, headers, tokens, and cookies. The 390 px Audit view rendered both persisted records without horizontal overflow.
- Report API tests accepted a valid hash-bound `Report.db` draft, omitted Markdown bodies from list responses, returned the selected Markdown through an identifier-validated endpoint, and rejected traversal-shaped identifiers. The current real result root contains no report draft, so the live UI correctly renders its empty state.

Backend verification covered durable program registration, same-origin enforcement, private-field masking, approved-scope discovery, out-of-scope rejection, fixed non-shell argv construction with a mocked process, pre-database WebSocket events, CLI scan-ID validation, and existing snapshot replay. No real target scan was launched.

Browser screenshots are local verification artifacts and are intentionally excluded
from Git so the repository does not accumulate generated binary files. They contained
no executed real-target scan results.
