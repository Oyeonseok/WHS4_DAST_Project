import type { Snapshot } from '../lib/events';

export const DEMO_SCAN = 'demo_local_042';
export function demoSnapshot(): Snapshot {
  return {
    version: 1, scan_id: DEMO_SCAN, last_event_id: 7, status: 'running', stage: 'Attack', progress: 62, requests: 391, budget: 2000, endpoints: 218,
    findings: [
      { id: 'F-0042', title: 'Object access differs across test identities', severity: 'HIGH', status: 'unreviewed', endpoint: 'GET /api/accounts/{id}', cwe: 'CWE-639' },
      { id: 'F-0041', title: 'Reflected input in search response', severity: 'MEDIUM', status: 'unreviewed', endpoint: 'GET /search', cwe: 'CWE-79' },
      { id: 'F-0040', title: 'Server version in response headers', severity: 'LOW', status: 'confirmed', endpoint: 'GET /health', cwe: 'CWE-200' },
      { id: 'F-0039', title: 'Missing response hardening header', severity: 'INFO', status: 'rejected', endpoint: 'GET /', cwe: 'CWE-693' },
    ],
    logs: [
      { id: 1, time: '2026-09-20T05:28:00Z', stage: 'Scope', level: 'success', message: 'Fixture scope and approval hashes matched. Synthetic lab only.' },
      { id: 2, time: '2026-09-20T05:28:04Z', stage: 'Recon', level: 'success', message: 'Fixture inventory finalized · 218 routes in Recon.db' },
      { id: 3, time: '2026-09-20T05:28:09Z', stage: 'Recon', level: 'info', message: 'Handoff.json provenance verified · Pipeline.db materialized' },
      { id: 4, time: '2026-09-20T05:28:12Z', stage: 'Attack', level: 'info', message: 'Starting access-control template batch · 84 of 136 tasks' },
      { id: 5, time: '2026-09-20T05:28:18Z', stage: 'Attack', level: 'warning', message: 'Response differential detected. Candidate requires validation.' },
      { id: 6, time: '2026-09-20T05:28:21Z', stage: 'Attack', level: 'success', message: 'Redacted evidence pair stored · credential references omitted' },
      { id: 7, time: '2026-09-20T05:28:24Z', stage: 'Attack', level: 'info', message: 'F-0042 added to review queue · no verdict inferred from matcher' },
    ],
  };
}
