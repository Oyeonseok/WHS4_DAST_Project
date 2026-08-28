"""SQLite schema and helpers for the recon pipeline (MVP).

Schema follows the team's agreed ERD: scans -> assets -> origins -> endpoints
-> parameters, with sessions and observations hanging off origins.
scan_id is only stored on `scans`/`assets` (and `pipeline_runs`) - everything
else is reached through the foreign-key chain to avoid duplicating scan_id
in places where it could drift out of sync.
"""

from __future__ import annotations

import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
-- WAL은 -wal/-shm 보조 파일에 mmap 기반 공유 락이 필요한데, WSL에서
-- Windows 드라이브를 마운트한 경로(/mnt/c/...)의 DrvFs는 이걸 지원하지
-- 않아 "unable to open database file"로 죽는다. 이 파이프라인은 단일
-- 연결/순차 실행이라 WAL의 동시성 이점도 필요 없으므로 기본 저널 모드를
-- 그대로 쓴다.
PRAGMA journal_mode=DELETE;

CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    scope_type TEXT NOT NULL,
    scope_value TEXT NOT NULL,
    status TEXT DEFAULT 'running',
    started_at TEXT DEFAULT CURRENT_TIMESTAMP,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS assets (
    asset_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    identifier TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    discovered_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
);

CREATE TABLE IF NOT EXISTS origins (
    origin_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    scheme TEXT,
    host TEXT,
    port INTEGER,
    base_url TEXT NOT NULL,
    http_probe_status INTEGER,
    spa_detected INTEGER,
    framework_signature TEXT,
    main_crawler_mode TEXT,
    discovered_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id),
    UNIQUE(asset_id, host, port, scheme)
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    origin_id TEXT NOT NULL,
    target TEXT,
    auth_state TEXT,
    isolation_scope TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT,
    FOREIGN KEY (origin_id) REFERENCES origins(origin_id)
);

CREATE TABLE IF NOT EXISTS endpoints (
    endpoint_id TEXT PRIMARY KEY,
    origin_id TEXT NOT NULL,
    session_id TEXT,
    method TEXT,
    path TEXT,
    normalized_path TEXT NOT NULL,
    content_type TEXT,
    auth_required INTEGER,
    source_tools TEXT,
    is_excluded INTEGER DEFAULT 0,
    exclude_reason TEXT,
    discovered_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (origin_id) REFERENCES origins(origin_id),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id),
    UNIQUE(origin_id, method, normalized_path)
);

CREATE TABLE IF NOT EXISTS parameters (
    parameter_id TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL,
    name TEXT NOT NULL,
    location TEXT NOT NULL,
    data_type TEXT,
    example_value TEXT,
    is_identifier INTEGER DEFAULT 0,
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(endpoint_id),
    UNIQUE(endpoint_id, name, location)
);

CREATE TABLE IF NOT EXISTS observations (
    observation_id TEXT PRIMARY KEY,
    origin_id TEXT NOT NULL,
    type TEXT,
    key TEXT,
    value TEXT,
    source TEXT,
    discovered_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (origin_id) REFERENCES origins(origin_id)
);

CREATE TABLE IF NOT EXISTS http_exchanges (
    exchange_id TEXT PRIMARY KEY,
    origin_id TEXT NOT NULL,
    session_id TEXT,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    query_string TEXT,
    request_headers TEXT,
    status_code INTEGER,
    content_type TEXT,
    response_size INTEGER,
    is_authenticated INTEGER DEFAULT 0,
    captured_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (origin_id) REFERENCES origins(origin_id),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE TABLE IF NOT EXISTS surface_signals (
    signal_id TEXT PRIMARY KEY,
    origin_id TEXT NOT NULL,
    signal_type TEXT NOT NULL,
    value TEXT,
    detected_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (origin_id) REFERENCES origins(origin_id)
);

CREATE TABLE IF NOT EXISTS pipeline_runs (
    pipeline_run_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    task_id TEXT,
    stage TEXT NOT NULL,
    status TEXT NOT NULL,
    error_type TEXT,
    message TEXT,
    recoverable INTEGER,
    started_at TEXT,
    ended_at TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
);
"""


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


@contextmanager
def connect(db_path: Path):
    conn = init_db(db_path)
    try:
        yield conn
    finally:
        conn.close()


# --- insert / upsert helpers ----------------------------------------------


def insert_scan(
    conn: sqlite3.Connection, *, scan_id: str, scope_type: str, scope_value: str
) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO scans (scan_id, scope_type, scope_value) VALUES (?, ?, ?)",
        (scan_id, scope_type, scope_value),
    )
    conn.commit()


def insert_asset(
    conn: sqlite3.Connection, *, scan_id: str, identifier: str, asset_type: str
) -> str:
    asset_id = new_id("asset")
    conn.execute(
        "INSERT INTO assets (asset_id, scan_id, identifier, asset_type) VALUES (?, ?, ?, ?)",
        (asset_id, scan_id, identifier, asset_type),
    )
    conn.commit()
    return asset_id


def upsert_origin(
    conn: sqlite3.Connection,
    *,
    asset_id: str,
    scheme: str,
    host: str,
    port: int | None,
    base_url: str,
    http_probe_status: int | None = None,
    spa_detected: bool | None = None,
    framework_signature: str | None = None,
    main_crawler_mode: str | None = None,
) -> str:
    row = conn.execute(
        "SELECT origin_id FROM origins WHERE asset_id=? AND host=? AND port IS ? AND scheme=?",
        (asset_id, host, port, scheme),
    ).fetchone()
    spa_value = int(bool(spa_detected)) if spa_detected is not None else None
    if row:
        origin_id = row[0]
        conn.execute(
            """UPDATE origins SET http_probe_status=?, spa_detected=?, framework_signature=?,
               main_crawler_mode=?, base_url=? WHERE origin_id=?""",
            (
                http_probe_status,
                spa_value,
                framework_signature,
                main_crawler_mode,
                base_url,
                origin_id,
            ),
        )
    else:
        origin_id = new_id("origin")
        conn.execute(
            """INSERT INTO origins
               (origin_id, asset_id, scheme, host, port, base_url, http_probe_status,
                spa_detected, framework_signature, main_crawler_mode)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                origin_id,
                asset_id,
                scheme,
                host,
                port,
                base_url,
                http_probe_status,
                spa_value,
                framework_signature,
                main_crawler_mode,
            ),
        )
    conn.commit()
    return origin_id


def insert_session(
    conn: sqlite3.Connection,
    *,
    origin_id: str,
    target: str,
    auth_state: str,
    isolation_scope: str = "origin",
) -> str:
    """login.py가 캡처한 세션(쿠키/토큰을 JSON 문자열로 직렬화한 것)을
    감사 기록으로 남긴다. auth_state는 raw 쿠키/토큰 값을 그대로 담으니
    이 DB 파일을 커밋/공유할 때는 주의할 것 - 실제 계정 자격증명이 들어있는
    게 아니라 로그인 이후 발급된 세션 토큰이라도, 스캔이 끝난 뒤엔 값을
    비우거나 파기하는 걸 권장한다."""
    session_id = new_id("session")
    conn.execute(
        """INSERT INTO sessions (session_id, origin_id, target, auth_state, isolation_scope)
           VALUES (?, ?, ?, ?, ?)""",
        (session_id, origin_id, target, auth_state, isolation_scope),
    )
    conn.commit()
    return session_id


def insert_http_exchange(
    conn: sqlite3.Connection,
    *,
    origin_id: str,
    session_id: str | None,
    method: str,
    path: str,
    query_string: str | None = None,
    request_headers: str | None = None,
    status_code: int | None = None,
    content_type: str | None = None,
    response_size: int | None = None,
    is_authenticated: bool = False,
) -> str:
    """mitmproxy가 관찰한 실제 요청/응답 1건을 감사 기록으로 남긴다.
    request_body/response_body는 일부러 안 받는다 - 실제 로그인 세션
    토큰이나 입력값이 그대로 DB에 박히는 걸 막기 위해서다. 나중에 body를
    남기기로 하면 민감한 헤더/필드를 마스킹하는 정책부터 정하고 컬럼을
    추가할 것."""
    exchange_id = new_id("exchange")
    conn.execute(
        """INSERT INTO http_exchanges
           (exchange_id, origin_id, session_id, method, path, query_string,
            request_headers, status_code, content_type, response_size, is_authenticated)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            exchange_id, origin_id, session_id, method, path, query_string,
            request_headers, status_code, content_type, response_size,
            int(bool(is_authenticated)),
        ),
    )
    conn.commit()
    return exchange_id


def update_origin_spa_verdict(
    conn: sqlite3.Connection, *, origin_id: str, spa_detected: bool, framework_signature: str | None = None
) -> None:
    """origin_discovery의 정적 HTML 시그니처 판단이 endpoint_discovery의
    실측 Gap Ratio와 어긋날 때 이 함수로 origins 테이블을 정정한다.
    정정 없이는 origins.spa_detected가 계속 틀린 채로 남아, DB만 보는
    사람은 실측 증거와 반대되는 값을 믿게 된다."""
    conn.execute(
        "UPDATE origins SET spa_detected=?, framework_signature=COALESCE(framework_signature, ?) WHERE origin_id=?",
        (int(bool(spa_detected)), framework_signature, origin_id),
    )
    conn.commit()


def upsert_endpoint(
    conn: sqlite3.Connection,
    *,
    origin_id: str,
    method: str,
    path: str,
    normalized_path: str,
    content_type: str | None = None,
    auth_required: bool | None = None,
    source_tool: str = "",
    is_excluded: bool = False,
    exclude_reason: str | None = None,
) -> str:
    row = conn.execute(
        "SELECT endpoint_id, source_tools FROM endpoints WHERE origin_id=? AND method=? AND normalized_path=?",
        (origin_id, method, normalized_path),
    ).fetchone()
    if row:
        endpoint_id, existing_tools = row
        tools = set(filter(None, (existing_tools or "").split(",")))
        tools.update(filter(None, source_tool.split(",")))
        conn.execute(
            "UPDATE endpoints SET source_tools=? WHERE endpoint_id=?",
            (",".join(sorted(tools)), endpoint_id),
        )
    else:
        endpoint_id = new_id("endpoint")
        conn.execute(
            """INSERT INTO endpoints
               (endpoint_id, origin_id, method, path, normalized_path, content_type,
                auth_required, source_tools, is_excluded, exclude_reason)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                endpoint_id,
                origin_id,
                method,
                path,
                normalized_path,
                content_type,
                int(bool(auth_required)) if auth_required is not None else None,
                source_tool,
                int(is_excluded),
                exclude_reason,
            ),
        )
    conn.commit()
    return endpoint_id


def upsert_parameter(
    conn: sqlite3.Connection,
    *,
    endpoint_id: str,
    name: str,
    location: str,
    data_type: str | None = None,
    example_value: str | None = None,
    is_identifier: bool = False,
) -> str:
    """엔드포인트에 딸린 파라미터 1건을 남긴다. 같은 (endpoint, name,
    location)이 다시 들어오면 새로 만들지 않고 기존 행을 쓴다 - 실제
    트래픽에는 같은 파라미터가 값만 바뀐 채로 여러 번 오기 때문이다.

    example_value는 이름 그대로 '예시 하나'다. 값을 모으는 자리가 아니라
    나중에 공격 페이로드를 만들 때 형태를 참고하는 용도라 한 건만 남긴다.
    """
    row = conn.execute(
        "SELECT parameter_id FROM parameters WHERE endpoint_id=? AND name=? AND location=?",
        (endpoint_id, name, location),
    ).fetchone()
    if row:
        parameter_id = row[0]
        # 처음 넣을 때 비어 있던 칸만 뒤늦게 채운다. 이미 있는 값은 건드리지
        # 않는다 - 먼저 관찰된 쪽을 대표값으로 본다.
        conn.execute(
            """UPDATE parameters
               SET data_type = COALESCE(data_type, ?),
                   example_value = COALESCE(example_value, ?),
                   is_identifier = MAX(is_identifier, ?)
               WHERE parameter_id = ?""",
            (data_type, example_value, int(bool(is_identifier)), parameter_id),
        )
    else:
        parameter_id = new_id("param")
        conn.execute(
            """INSERT INTO parameters
               (parameter_id, endpoint_id, name, location, data_type, example_value, is_identifier)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                parameter_id, endpoint_id, name, location, data_type,
                example_value, int(bool(is_identifier)),
            ),
        )
    conn.commit()
    return parameter_id


def insert_observation(
    conn: sqlite3.Connection, *, origin_id: str, obs_type: str, key: str, value: str, source: str
) -> None:
    conn.execute(
        "INSERT INTO observations (observation_id, origin_id, type, key, value, source) VALUES (?, ?, ?, ?, ?, ?)",
        (new_id("obs"), origin_id, obs_type, key, value, source),
    )
    conn.commit()


def insert_surface_signal(
    conn: sqlite3.Connection, *, origin_id: str, signal_type: str, value: str
) -> None:
    conn.execute(
        "INSERT INTO surface_signals (signal_id, origin_id, signal_type, value) VALUES (?, ?, ?, ?)",
        (new_id("signal"), origin_id, signal_type, value),
    )
    conn.commit()


def log_pipeline_run(
    conn: sqlite3.Connection,
    *,
    scan_id: str,
    task_id: str | None,
    stage: str,
    status: str,
    error_type: str | None = None,
    message: str | None = None,
    recoverable: bool | None = None,
) -> None:
    conn.execute(
        """INSERT INTO pipeline_runs
           (pipeline_run_id, scan_id, task_id, stage, status, error_type, message, recoverable, started_at, ended_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            new_id("run"),
            scan_id,
            task_id,
            stage,
            status,
            error_type,
            message,
            int(bool(recoverable)) if recoverable is not None else None,
            now(),
            now(),
        ),
    )
    conn.commit()
