"""Read-only dashboard views of the entire endpoint hypothesis queue."""
from __future__ import annotations

import sqlite3
from urllib.parse import urlsplit, urlunsplit

from aidast.attack.coverage import TERMINAL_STATUSES
from aidast.recon.annotations import safe_text


_INCLUDED_ENDPOINTS = '''SELECT e.endpoint_id FROM endpoints e
    JOIN origins o ON o.origin_id=e.origin_id JOIN assets a ON a.asset_id=o.asset_id
    WHERE a.scan_id=? AND e.is_excluded=0'''
_TESTED_STATUSES = ('tested_negative', 'candidate', 'confirmed')


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
    reviews = dict(conn.execute(f'''SELECT status,count(*) FROM attack_endpoint_reviews
        WHERE scan_id=? AND endpoint_id IN ({_INCLUDED_ENDPOINTS}) GROUP BY status''',
        (scan_id, scan_id))) if 'attack_endpoint_reviews' in tables else {}
    diagnostics = dict(conn.execute('SELECT status,count(*) FROM attack_planning_diagnostics WHERE scan_id=? GROUP BY status', (scan_id,))) if 'attack_planning_diagnostics' in tables else {}
    has_reviews = 'attack_endpoint_reviews' in tables and conn.execute(
        'SELECT 1 FROM attack_endpoint_reviews WHERE scan_id=? LIMIT 1', (scan_id,)).fetchone() is not None
    if not counts and not reviews and not diagnostics and not has_reviews:
        return None
    included = conn.execute('SELECT count(*) FROM (' + _INCLUDED_ENDPOINTS + ')', (scan_id,)).fetchone()[0]
    resolved = sum(counts.get(status, 0) for status in TERMINAL_STATUSES)
    total = sum(counts.values())
    budget_limited = conn.execute('''SELECT count(*) FROM attack_coverage_items WHERE scan_id=? AND status='unsupported'
        AND (lower(disposition_reason) LIKE '%budget%' OR lower(disposition_reason) LIKE '%time limit%' OR disposition_reason LIKE '%예산%')''', (scan_id,)).fetchone()[0]
    by_vulnerability: dict[str, dict[str, int]] = {}
    for vuln_class, status, count in conn.execute('''SELECT vuln_class,status,count(*)
            FROM attack_coverage_items WHERE scan_id=? GROUP BY vuln_class,status
            ORDER BY vuln_class,status''', (scan_id,)):
        by_vulnerability.setdefault(vuln_class, {})[status] = count
    tested_endpoints = conn.execute(f'''SELECT count(DISTINCT endpoint_id)
        FROM attack_coverage_items WHERE scan_id=? AND status IN ('tested_negative','candidate','confirmed')
        AND endpoint_id IN ({_INCLUDED_ENDPOINTS})''', (scan_id, scan_id)).fetchone()[0]
    attempted_endpoints = conn.execute(f'''SELECT count(DISTINCT endpoint_id)
        FROM attack_attempts WHERE scan_id=? AND endpoint_id IN ({_INCLUDED_ENDPOINTS})''',
        (scan_id, scan_id)).fetchone()[0] if 'attack_attempts' in tables else 0
    finding_ids = {row[0] for row in conn.execute('''SELECT DISTINCT finding_id
        FROM attack_coverage_items WHERE scan_id=? AND finding_id IS NOT NULL''', (scan_id,))}
    validation_counts: dict[str, int] = {}
    if finding_ids and 'validation_cases' in tables:
        # Coverage can still say candidate in an immutable Attack snapshot.
        # Only the latest independent decision for each distinct bound finding
        # establishes confirmation; multiple hypotheses never multiply it.
        validation_counts = dict(conn.execute('''SELECT coalesce(v.current_status,'PENDING'),count(*)
            FROM validation_cases v JOIN (
                SELECT finding_id,max(rowid) latest_rowid FROM validation_cases
                WHERE scan_id=? AND finding_id IN (
                    SELECT finding_id FROM attack_coverage_items WHERE scan_id=?
                    AND finding_id IS NOT NULL)
                GROUP BY finding_id
            ) latest ON latest.latest_rowid=v.rowid GROUP BY v.current_status''', (scan_id, scan_id)))
    pending_findings = len(finding_ids) - sum(validation_counts.values())
    if pending_findings:
        validation_counts['PENDING'] = validation_counts.get('PENDING', 0) + pending_findings
    result = {'total': total, 'by_status': counts, 'resolved': resolved, 'unfinished': total - resolved,
              'by_vulnerability': by_vulnerability,
              'tested': sum(counts.get(status, 0) for status in _TESTED_STATUSES),
              'budget_limited': budget_limited, 'endpoints_total': included,
              'endpoints_reviewed': sum(reviews.values()),
              'endpoints_unreviewed': included - sum(reviews.values()),
              'endpoints_attempted': attempted_endpoints, 'endpoints_tested': tested_endpoints,
              'candidate_findings': len(finding_ids),
              'independently_confirmed_findings': validation_counts.get('CONFIRMED', 0),
              'validation_by_status': validation_counts,
              'insufficient_evidence_endpoints': reviews.get('insufficient_evidence', 0),
              'not_applicable_endpoints': reviews.get('not_applicable', 0),
              'planning_rejected': sum(diagnostics.values()), 'planning_unresolved': diagnostics.get('unresolved', 0),
              'planning_resolved': diagnostics.get('resolved', 0),
              'gaps': [], 'gaps_total': 0, 'gaps_truncated': False}
    if include_gaps:
        gap_query = '''SELECT e.method,o.base_url,e.normalized_path,r.status,r.reason,NULL AS vuln_class
            FROM attack_endpoint_reviews r JOIN endpoints e ON e.endpoint_id=r.endpoint_id
            JOIN origins o ON o.origin_id=e.origin_id JOIN assets a ON a.asset_id=o.asset_id
            WHERE r.scan_id=? AND a.scan_id=r.scan_id AND e.is_excluded=0 AND r.status<>'planned'
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
        has_reviews = conn.execute('SELECT 1 FROM attack_endpoint_reviews WHERE scan_id=? LIMIT 1', (scan_id,)).fetchone()
        if has_reviews:
            return conn.execute(f'''SELECT 1 FROM ({_INCLUDED_ENDPOINTS}) included
                WHERE NOT EXISTS (SELECT 1 FROM attack_endpoint_reviews r
                    WHERE r.scan_id=? AND r.endpoint_id=included.endpoint_id) LIMIT 1''',
                (scan_id, scan_id)).fetchone() is not None
    return False
