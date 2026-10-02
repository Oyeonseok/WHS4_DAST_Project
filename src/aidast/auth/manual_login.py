"""Secret-free operator confirmation shared by the dashboard and scan process."""

from __future__ import annotations

import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable
from uuid import uuid4


class ManualLoginStore:
    def __init__(self, result_root: Path) -> None:
        self.path = Path(result_root) / '.webui' / 'manual_login.db'
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            if os.name == 'posix':
                os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        with self._connect() as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS manual_login (
                scan_id TEXT PRIMARY KEY, request_id TEXT NOT NULL,
                target_origin TEXT NOT NULL, status TEXT NOT NULL,
                created_at REAL NOT NULL, expires_at REAL NOT NULL,
                confirmed_at REAL, auth_state TEXT, problem TEXT
            )''')
            columns = {row[1] for row in conn.execute('PRAGMA table_info(manual_login)')}
            if 'action_kind' not in columns:
                try:
                    conn.execute("ALTER TABLE manual_login ADD COLUMN action_kind TEXT NOT NULL DEFAULT 'login'")
                except sqlite3.OperationalError:
                    if 'action_kind' not in {row[1] for row in conn.execute('PRAGMA table_info(manual_login)')}:
                        raise

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def begin(self, scan_id: str, target_origin: str, timeout_seconds: float, *,
              action_kind: str = 'login', problem: str | None = None) -> dict:
        if action_kind not in {'login', 'recon_login', 'mfa', 'captcha', 'access'}:
            raise ValueError('invalid operator action kind')
        if problem not in {None, 'login_form_visible', 'mfa_required', 'captcha_required',
                           'access_required', 'runtime_browser_required'}:
            raise ValueError('invalid operator action problem')
        now = time.time()
        request_id = uuid4().hex
        with self._connect() as conn:
            conn.execute('''INSERT OR REPLACE INTO manual_login
                (scan_id, request_id, target_origin, status, created_at, expires_at,
                 confirmed_at, auth_state, problem, action_kind)
                VALUES (?, ?, ?, 'waiting', ?, ?, NULL, NULL, ?, ?)''',
                (scan_id, request_id, target_origin, now, now + timeout_seconds, problem, action_kind))
        return self.read(scan_id)

    def read(self, scan_id: str) -> dict | None:
        with self._connect() as conn:
            conn.execute('''UPDATE manual_login SET status='expired'
                WHERE scan_id=? AND status IN ('waiting', 'confirmed') AND expires_at<=?''',
                (scan_id, time.time()))
            row = conn.execute('SELECT * FROM manual_login WHERE scan_id=?', (scan_id,)).fetchone()
        return dict(row) if row else None

    def confirm(self, scan_id: str, request_id: str) -> dict:
        now = time.time()
        with self._connect() as conn:
            changed = conn.execute('''UPDATE manual_login
                SET status='confirmed', confirmed_at=?, problem=NULL
                WHERE scan_id=? AND request_id=? AND status='waiting' AND expires_at>?''',
                (now, scan_id, request_id, now)).rowcount
            if not changed:
                raise ValueError('login request is no longer waiting or does not match this scan')
        return self.read(scan_id)

    def reject_confirmation(self, scan_id: str, request_id: str, problem: str) -> None:
        with self._connect() as conn:
            conn.execute('''UPDATE manual_login SET status='waiting', problem=?, confirmed_at=NULL
                WHERE scan_id=? AND request_id=? AND status='confirmed' ''',
                (problem, scan_id, request_id))

    def finish(self, scan_id: str, request_id: str, status: str) -> None:
        if status not in {'accepted', 'failed', 'expired'}:
            raise ValueError('invalid final login state')
        with self._connect() as conn:
            condition = ("status='confirmed' AND expires_at>?" if status == 'accepted'
                         else "status IN ('waiting', 'confirmed', 'expired')")
            params = (status, 'operator_confirmed' if status == 'accepted' else None,
                      scan_id, request_id)
            if status == 'accepted':
                params += (time.time(),)
            changed = conn.execute('''UPDATE manual_login SET status=?, auth_state=?
                WHERE scan_id=? AND request_id=? AND ''' + condition, params).rowcount
            if not changed:
                raise ValueError('login request was replaced or is already finished')


class ManualLoginGate:
    def __init__(self, store: ManualLoginStore, scan_id: str, target_origin: str, *,
                 timeout_seconds: float = 300, poll_interval: float = 0.25) -> None:
        self.store = store
        self.scan_id = scan_id
        self.target_origin = target_origin
        self.timeout_seconds = timeout_seconds
        self.poll_interval = poll_interval

    def wait(self, browser_problem: Callable[[], str | None], *,
             action_kind: str = 'login', problem: str | None = None,
             poll_browser: Callable[[], None] | None = None) -> bool:
        request = self.store.begin(self.scan_id, self.target_origin, self.timeout_seconds,
                                   action_kind=action_kind, problem=problem)
        request_id = request['request_id']
        print('  [Playwright] 열린 브라우저에서 필요한 사용자 조치를 마친 뒤 대시보드에서 완료를 확인해주세요.', flush=True)
        try:
            while True:
                current = self.store.read(self.scan_id)
                if current is None or current['request_id'] != request_id:
                    raise RuntimeError('manual login request was replaced')
                if current['status'] == 'expired':
                    raise RuntimeError('manual login operator confirmation timed out')
                if current['status'] == 'confirmed':
                    problem = browser_problem()
                    if problem is None:
                        self.store.finish(self.scan_id, request_id, 'accepted')
                        return True
                    self.store.reject_confirmation(self.scan_id, request_id, problem)
                elif current['status'] != 'waiting':
                    raise RuntimeError('manual login request is no longer active')
                if poll_browser is not None:
                    # Dispatch the existing Playwright route/event handlers so
                    # operator input is not stalled while the worker is waiting.
                    poll_browser()
                time.sleep(self.poll_interval)
        except BaseException:
            current = self.store.read(self.scan_id)
            if current and current['request_id'] == request_id and current['status'] in {'waiting', 'confirmed'}:
                self.store.finish(self.scan_id, request_id, 'failed')
            raise
