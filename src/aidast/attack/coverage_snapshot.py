"""Read-only dashboard views of the entire endpoint hypothesis queue."""
from __future__ import annotations

import sqlite3
from urllib.parse import urlsplit, urlunsplit

from aidast.attack.coverage import TERMINAL_STATUSES
from aidast.recon.annotations import safe_text


def _url(base: str, path: str) -> str:
    value = urlsplit(base.rstrip('/') + '/' + path.lstrip('/'))
    host = value.hostname or ''
    if ':' in host:
        host = '[' + host + ']'
    if value.port:
        host += ':' + str(value.port)
    return urlunsplit((value.scheme, host, value.path, '', ''))


def read_coverage_snapshot(conn: sqlite3.Connection, scan_id: str, *, include_gaps: bool = True) -> dict | None:
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if 'attack_coverage_items' not in tables:
        return None
    counts = dict(conn.execute('SELECT status,count(*) FROM attack_coverage_items WHERE scan_id=? GROUP BY status', (scan_id,)))
    reviews = dict(conn.execute('SELECT status,count(*) FROM attack_endpoint_reviews WHERE scan_id=? GROUP BY status', (scan_id,))) if 'attack_endpoint_reviews' in tables else {}
    diagnostics = dict(conn.execute('SELECT status,count(*) FROM attack_planning_diagnostics WHERE scan_id=? GROUP BY status', (scan_id,))) if 'attack_planning_diagnostics' in tables else {}
    if not counts and not reviews and not diagnostics:
        return None
    included = conn.execute('''SELECT count(*) FROM endpoints e JOIN origins o ON o.origin_id=e.origin_id
        JOIN assets a ON a.asset_id=o.asset_id WHERE a.scan_id=? AND e.is_excluded=0''', (scan_id,)).fetchone()[0]
    resolved = sum(counts.get(status, 0) for status in TERMINAL_STATUSES)
    total = sum(counts.values())
    budget_limited = conn.execute('''SELECT count(*) FROM attack_coverage_items WHERE scan_id=? AND status='unsupported'
        AND (lower(disposition_reason) LIKE '%budget%' OR lower(disposition_reason) LIKE '%time limit%' OR disposition_reason LIKE '%예산%')''', (scan_id,)).fetchone()[0]
    result = {'total': total, 'by_status': counts, 'resolved': resolved, 'unfinished': total - resolved,
              'tested': sum(counts.get(status, 0) for status in ('tested_negative', 'candidate', 'confirmed')),
              'budget_limited': budget_limited, 'endpoints_total': included,
              'endpoints_reviewed': sum(reviews.values()),
              'insufficient_evidence_endpoints': reviews.get('insufficient_evidence', 0),
              'not_applicable_endpoints': reviews.get('not_applicable', 0),
              'planning_rejected': sum(diagnostics.values()), 'planning_unresolved': diagnostics.get('unresolved', 0),
              'planning_resolved': diagnostics.get('resolved', 0),
              'gaps': [], 'gaps_total': 0, 'gaps_truncated': False}
    if include_gaps:
        gap_query = '''SELECT e.method,o.base_url,e.normalized_path,r.status,r.reason,NULL AS vuln_class
            FROM attack_endpoint_reviews r JOIN endpoints e ON e.endpoint_id=r.endpoint_id
            JOIN origins o ON o.origin_id=e.origin_id WHERE r.scan_id=? AND r.status<>'planned'
            UNION ALL SELECT e.method,o.base_url,e.normalized_path,c.status,c.disposition_reason,c.vuln_class
            FROM attack_coverage_items c JOIN endpoints e ON e.endpoint_id=c.endpoint_id
            JOIN origins o ON o.origin_id=e.origin_id WHERE c.scan_id=?
            AND c.status IN ('blocked_auth','policy_excluded','unsupported','error_terminal')'''
        if 'attack_endpoint_reviews' not in tables:
            gap_query = gap_query.split('UNION ALL ', 1)[1]
            params = (scan_id,)
        else:
            params = (scan_id, scan_id)
        if 'attack_planning_diagnostics' in tables:
            gap_query += """ UNION ALL SELECT e.method,o.base_url,e.normalized_path,'planning_rejected',d.reason,
                json_extract(d.proposal_json,'$.vuln_class') FROM attack_planning_diagnostics d
                JOIN endpoints e ON e.endpoint_id=d.endpoint_id JOIN origins o ON o.origin_id=e.origin_id
                WHERE d.scan_id=? AND d.status='unresolved'"""
            params += (scan_id,)
        result['gaps_total'] = conn.execute('SELECT count(*) FROM (' + gap_query + ')', params).fetchone()[0]
        for row in conn.execute(gap_query + ' ORDER BY normalized_path,status LIMIT 200', params):
            result['gaps'].append({'method': row['method'], 'url': _url(row['base_url'], row['normalized_path']),
                'status': row['status'], 'reason': safe_text(row['reason'] or '')[:1000], 'vuln_class': row['vuln_class']})
        result['gaps_truncated'] = result['gaps_total'] > len(result['gaps'])
    return result


def attack_work_unfinished(conn: sqlite3.Connection, scan_id: str) -> bool:
    """A completed batch is not whole-stage completion while durable work remains."""
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if 'attack_coverage_items' in tables:
        marks = ','.join('?' for _ in TERMINAL_STATUSES)
        if conn.execute(f'SELECT 1 FROM attack_coverage_items WHERE scan_id=? AND status NOT IN ({marks}) LIMIT 1', (scan_id, *TERMINAL_STATUSES)).fetchone():
            return True
    if 'attack_endpoint_reviews' in tables:
        reviewed = conn.execute('SELECT count(*) FROM attack_endpoint_reviews WHERE scan_id=?', (scan_id,)).fetchone()[0]
        if reviewed:
            included = conn.execute('SELECT count(*) FROM endpoints e JOIN origins o ON o.origin_id=e.origin_id JOIN assets a ON a.asset_id=o.asset_id WHERE a.scan_id=? AND e.is_excluded=0', (scan_id,)).fetchone()[0]
            return reviewed < included
    return False
