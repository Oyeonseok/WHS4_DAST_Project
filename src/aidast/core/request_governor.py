"""Dependency-free durable outbound safety limits, also loaded by mitmdump.

Reservations never refund request units. Periods are rolling windows; pending
reservations count toward them too. Capacity exhaustion rejects immediately so
synchronous proxy hooks cannot deadlock waiting for their own response hooks.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import math
from pathlib import Path
import sqlite3
import time
from urllib.parse import urlsplit
from uuid import uuid4


class GovernorError(ValueError):
    """Shared request accounting cannot authorize a dispatch."""


def _number(value, name, maximum=1e12, integer=False):
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or not 0 < value <= maximum
            or (integer and type(value) is not int)):
        raise GovernorError('invalid governor ' + name)
    return value


def _origin(url):
    try:
        p = urlsplit(url)
        if p.scheme not in ('http', 'https', 'ws', 'wss') or not p.hostname or p.username is not None or p.password is not None:
            raise ValueError()
        scheme = {'ws': 'http', 'wss': 'https'}.get(p.scheme, p.scheme)
        host = p.hostname.lower().rstrip('.').encode('idna').decode('ascii')
        return json.dumps([scheme, host, p.port or (443 if scheme == 'https' else 80)])
    except (ValueError, UnicodeError) as exc:
        raise GovernorError('invalid governor destination') from exc


class RequestGovernor:
    def __init__(self, binding, *, clock=time.time, sleeper=time.sleep):
        self.clock, self.sleeper = clock, sleeper
        if hasattr(binding, 'model_dump'):
            binding = binding.model_dump(mode='json')
        self.binding = binding
        if binding is None:
            return
        if not isinstance(binding, dict):
            raise GovernorError('invalid governor binding')
        required = {'ledger_path', 'scan_id', 'program_id', 'scan_max_requests',
                    'scan_max_seconds', 'requests_per_second', 'concurrency', 'request_limits'}
        if set(binding) != required:
            raise GovernorError('invalid governor binding fields')
        for key in ('scan_id', 'program_id'):
            if not isinstance(binding[key], str) or not binding[key].strip() or len(binding[key]) > 160 or any(not (c.isascii() and (c.isalnum() or c in '_-')) for c in binding[key]):
                raise GovernorError('invalid governor identifier')
        path = binding['ledger_path']
        if not isinstance(path, str) or not Path(path).is_absolute() or '\x00' in path or '..' in Path(path).parts:
            raise GovernorError('invalid governor ledger path')
        self.path = path
        _number(binding['scan_max_requests'], 'budget', maximum=100000, integer=True)
        _number(binding['concurrency'], 'concurrency', maximum=20, integer=True)
        _number(binding['requests_per_second'], 'rate', maximum=50)
        if binding['scan_max_seconds'] is not None:
            _number(binding['scan_max_seconds'], 'deadline', maximum=86400)
        if not isinstance(binding['request_limits'], list) or len(binding['request_limits']) > 64:
            raise GovernorError('invalid governor request limits')
        for rule in binding['request_limits']:
            if not isinstance(rule, dict) or set(rule) != {'maximum', 'period_seconds', 'scope', 'source_quote'}:
                raise GovernorError('invalid governor quota')
            _number(rule['maximum'], 'quota', maximum=100000000, integer=True)
            if rule['period_seconds'] is not None:
                _number(rule['period_seconds'], 'period', maximum=315360000)
            if rule['scope'] not in ('scan', 'program', 'target') or not isinstance(rule['source_quote'], str) or not rule['source_quote'].strip():
                raise GovernorError('invalid governor quota scope/evidence')
        # Freeze a trusted binding so later mutable caller edits cannot widen it.
        self.binding = json.loads(json.dumps(binding, allow_nan=False))

    @contextmanager
    def _transaction(self):
        conn = None
        try:
            conn = sqlite3.connect(self.path, timeout=5, isolation_level=None)
            conn.execute('PRAGMA busy_timeout=5000')
            conn.execute('BEGIN IMMEDIATE')
            conn.execute('CREATE TABLE IF NOT EXISTS governor_scans (program TEXT, scan TEXT, started REAL NOT NULL, configuration TEXT NOT NULL, last_dispatch REAL, PRIMARY KEY(program,scan))')
            conn.execute('CREATE TABLE IF NOT EXISTS governor_requests (id TEXT PRIMARY KEY, program TEXT NOT NULL, scan TEXT NOT NULL, origin TEXT NOT NULL, units INTEGER NOT NULL, capacity INTEGER NOT NULL, charged REAL NOT NULL, expires REAL NOT NULL, state TEXT NOT NULL)')
            conn.execute('CREATE INDEX IF NOT EXISTS governor_requests_scope ON governor_requests(program,scan,charged)')
            yield conn
            conn.execute('COMMIT')
        except sqlite3.Error as exc:
            if conn is not None and conn.in_transaction: conn.rollback()
            raise GovernorError('shared governor ledger unavailable or invalid') from exc
        except BaseException:
            if conn is not None and conn.in_transaction: conn.rollback()
            raise
        finally:
            if conn is not None: conn.close()

    def _scan(self, conn, now):
        b = self.binding
        config = json.dumps({k: v for k, v in b.items() if k not in ('ledger_path',)}, sort_keys=True)
        conn.execute('INSERT OR IGNORE INTO governor_scans VALUES (?,?,?,?,NULL)',
                     (b['program_id'], b['scan_id'], now, config))
        row = conn.execute('SELECT started,configuration,last_dispatch FROM governor_scans WHERE program=? AND scan=?',
                           (b['program_id'], b['scan_id'])).fetchone()
        if row[1] != config:
            raise GovernorError('shared governor scan binding changed')
        deadline = row[0] + b['scan_max_seconds'] if b['scan_max_seconds'] is not None else float('inf')
        if now >= deadline:
            raise GovernorError('shared scan deadline exhausted')
        return deadline, row[2]

    def _quotas(self, conn, origin, units, now, exclude=''):
        b = self.binding
        for rule in b['request_limits']:
            where, args = 'program=? AND id<>?', [b['program_id'], exclude]
            if rule['scope'] == 'scan': where += ' AND scan=?'; args.append(b['scan_id'])
            elif rule['scope'] == 'target': where += ' AND origin=?'; args.append(origin)
            if rule['period_seconds'] is not None:
                where += ' AND charged>?'; args.append(now - rule['period_seconds'])
            used = conn.execute('SELECT coalesce(sum(units),0) FROM governor_requests WHERE ' + where, args).fetchone()[0]
            if used + units > rule['maximum']:
                raise GovernorError('shared policy request quota exhausted')

    def reserve(self, url, units=1, timeout_seconds=30, *, concurrency_units=1):
        if self.binding is None:
            return _Permit(None, None, timeout_seconds)
        _number(units, 'request units', integer=True)
        if type(concurrency_units) is not int or concurrency_units not in (0, 1):
            raise GovernorError('invalid governor concurrency units')
        _number(timeout_seconds, 'request timeout', maximum=86400)
        origin, ident = _origin(url), uuid4().hex
        b = self.binding
        with self._transaction() as conn:
            now = self.clock()
            deadline, _ = self._scan(conn, now)
            used, active = conn.execute("SELECT coalesce(sum(units),0),coalesce(sum(CASE WHEN state IN ('reserved','running') AND expires>? THEN capacity ELSE 0 END),0) FROM governor_requests WHERE program=? AND scan=?", (now, b['program_id'], b['scan_id'])).fetchone()
            if used + units > b['scan_max_requests']:
                raise GovernorError('shared scan request budget exhausted')
            if active + concurrency_units > b['concurrency']:
                raise GovernorError('shared request concurrency limit reached')
            self._quotas(conn, origin, units, now)
            expires = min(now + timeout_seconds + 30, deadline)
            conn.execute("INSERT INTO governor_requests VALUES (?,?,?,?,?,?,?,?,'reserved')", (ident, b['program_id'], b['scan_id'], origin, units, concurrency_units, now, expires))
        return _Permit(self, ident, timeout_seconds)


class _Permit:
    def __init__(self, governor, ident, timeout):
        self.governor, self.ident, self.timeout = governor, ident, timeout
        self.done = False
        self.timeout_seconds = timeout

    def wait(self):
        g = self.governor
        if g is None: return
        while True:
            with g._transaction() as conn:
                now = g.clock()
                deadline, previous = g._scan(conn, now)
                row = conn.execute('SELECT origin,units,expires,state,charged FROM governor_requests WHERE id=?', (self.ident,)).fetchone()
                # Lock acquisition and ledger reads are part of admission time.
                now = g.clock()
                if now >= deadline:
                    raise GovernorError('shared scan deadline exhausted')
                if self.done or row is None or row[3] != 'reserved' or now >= row[2]:
                    raise GovernorError('request permit expired or already dispatched')
                rate = g.binding['requests_per_second']
                due = max(now, previous + row[1] / rate if previous is not None else row[4] + (row[1] - 1) / rate)
                if due >= deadline or due >= row[2]:
                    raise GovernorError('shared request deadline exhausted while pacing')
                if due <= now:
                    self.timeout_seconds = min(self.timeout, deadline - now)
                    g._quotas(conn, row[0], row[1], now, self.ident)
                    conn.execute("UPDATE governor_requests SET state='running',charged=?,expires=? WHERE id=?", (now, min(now + self.timeout + 30, deadline), self.ident))
                    conn.execute('UPDATE governor_scans SET last_dispatch=? WHERE program=? AND scan=?', (now, g.binding['program_id'], g.binding['scan_id']))
                    return
            g.sleeper(due - now)

    def complete(self, outcome='completed'):
        if self.governor is None or self.done: return
        with self.governor._transaction() as conn:
            conn.execute("UPDATE governor_requests SET state='complete' WHERE id=?", (self.ident,))
        self.done = True
