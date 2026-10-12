"""mitmdump 프로세스를 띄우고/끄고, 캡처된 JSONL을 DB로 적재하는 헬퍼.

katana/ffuf/Playwright 전부가 이 프록시를 거쳐가게 되며, mitmdump가
정책 강제가 필수인 경우에는 시작 실패를 오류로 보고한다.
"""

from __future__ import annotations

import json
import importlib.util
from collections import deque
import os
import socket
import subprocess
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

from aidast.recon import db as dbmod
from aidast.core.http_safety import sanitize_headers, validate_scope_rules

_ADDON_PATH = Path(__file__).parent / "mitm_addon.py"


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        candidate.bind(("127.0.0.1", 0))
        return int(candidate.getsockname()[1])


def _wait_for_proxy_port(
    port: int,
    *,
    process: subprocess.Popen | None = None,
    timeout: float = 30.0,
) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def start_mitmproxy(
    capture_path: Path, *, port: int | None = None, scope_rules: dict | None = None,
) -> tuple[subprocess.Popen | None, str | None]:
    required = scope_rules is not None and scope_rules.get("enforcement_required", True) is not False
    scope_file: Path | None = None
    auth_file: Path | None = None
    if scope_rules is not None:
        validate_scope_rules(scope_rules)
    if importlib.util.find_spec("mitmproxy") is None:
        if required:
            raise RuntimeError(
                "required policy proxy is unavailable: mitmproxy is not installed "
                "in the AI DAST Python environment; run uv sync "
                "(for an editable tool installation: uv tool install --force --editable .)"
            )
        print("  [건너뜀] 현재 Python 환경에 mitmproxy 미설치 - uv sync로 설치하세요")
        return None, None

    selected_port = port if port is not None else _find_free_port()
    if port is not None:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                if required:
                    raise RuntimeError("required policy proxy port is already in use")
                print(f"  [경고] 요청한 mitmproxy 포트 {port}가 이미 사용 중")
                return None, None
        except OSError:
            pass

    command = [
        sys.executable, "-c", "from mitmproxy.tools.main import mitmdump; mitmdump()",
        "-s", str(_ADDON_PATH), "-p", str(selected_port),
        "--set", "http2=false",
        "--set", f"out_file={capture_path}",
        "--set", f"enforcement_required={'true' if required else 'false'}",
    ]

    # External crawlers normally receive authenticated browser headers through
    # command-line flags.  Process listings expose those values to every local
    # observer.  Give the policy proxy a private, mutable handoff file instead;
    # endpoint discovery fills it only after the browser session is available.
    auth_handle = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", encoding="utf-8", delete=False
    )
    auth_file = Path(auth_handle.name)
    json.dump({"version": 1, "headers": {}}, auth_handle)
    auth_handle.close()
    os.chmod(auth_file, 0o600)
    command += ["--set", f"auth_file={auth_file}"]

    if scope_rules is not None:
        handle = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", encoding="utf-8", delete=False
        )
        scope_file = Path(handle.name)
        json.dump(scope_rules, handle)
        handle.close()
        command += ["--set", f"scope_file={scope_file}"]

    try:
        proc = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as exc:
        if scope_file is not None:
            scope_file.unlink(missing_ok=True)
        if auth_file is not None:
            auth_file.unlink(missing_ok=True)
        if required:
            raise RuntimeError("required policy proxy could not start") from exc
        print(f"  [경고] mitmdump 실행 실패: {exc} - mitmproxy 관찰 없이 진행")
        return None, None

    if not _wait_for_proxy_port(selected_port, process=proc):
        print("  [경고] mitmdump가 제시간에 포트를 열지 않음 - mitmproxy 관찰 없이 진행")
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if scope_file is not None:
            scope_file.unlink(missing_ok=True)
        if auth_file is not None:
            auth_file.unlink(missing_ok=True)
        if required:
            raise RuntimeError("required policy proxy did not become ready")
        return None, None

    # Keep cleanup metadata on the process without changing the public return
    # contract used by the executor and embedding applications.
    proc._aidast_scope_file = scope_file  # type: ignore[attr-defined]
    proc._aidast_auth_file = auth_file  # type: ignore[attr-defined]
    print(f"  [mitmproxy] 127.0.0.1:{selected_port}에서 관찰 시작")
    return proc, f"http://127.0.0.1:{selected_port}"


def stop_mitmproxy(proc: subprocess.Popen | None) -> None:
    if proc is None:
        return
    scope_file = getattr(proc, "_aidast_scope_file", None)
    auth_file = getattr(proc, "_aidast_auth_file", None)
    try:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)
    finally:
        if isinstance(scope_file, Path):
            scope_file.unlink(missing_ok=True)
        if isinstance(auth_file, Path):
            auth_file.unlink(missing_ok=True)


def update_mitmproxy_auth(
    proc: subprocess.Popen | None,
    headers: dict[str, str] | None,
) -> bool:
    """Atomically publish browser credentials without putting them in argv."""
    if proc is None:
        return False
    auth_file = getattr(proc, "_aidast_auth_file", None)
    if not isinstance(auth_file, Path):
        return False
    safe_headers: dict[str, str] = {}
    for name, value in (headers or {}).items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise ValueError("proxy auth headers must be strings")
        if not name or len(name) > 128 or any(
            ord(char) <= 32 or ord(char) >= 127 or char in "()<>@,;:\\\"/[]?={}"
            for char in name
        ):
            raise ValueError("proxy auth header name is invalid")
        if len(value) > 16384 or "\r" in value or "\n" in value:
            raise ValueError("proxy auth header value is invalid")
        if name.casefold() in {
            "host", "content-length", "transfer-encoding", "connection",
            "proxy-connection", "upgrade", "te", "trailer",
            "x-aidast-source", "x-aidast-phase",
        }:
            raise ValueError("proxy auth header cannot control routing or framing")
        safe_headers[name] = value
    handle = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", encoding="utf-8",
        dir=auth_file.parent, delete=False,
    )
    replacement = Path(handle.name)
    try:
        json.dump({"version": 1, "headers": safe_headers}, handle)
        handle.flush()
        os.fsync(handle.fileno())
        handle.close()
        os.chmod(replacement, 0o600)
        os.replace(replacement, auth_file)
    finally:
        if not handle.closed:
            handle.close()
        replacement.unlink(missing_ok=True)
    return True


def ingest_mitm_capture(conn: sqlite3.Connection, jsonl_path: Path, *, origin_id: str | None = None) -> tuple[int, int]:
    if not jsonl_path.is_file():
        return 0, 0

    count = 0
    blocked = 0
    static_resources = 0
    duplicates = 0
    deferred = 0
    with jsonl_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            static_resources += int(record.get("static_resource", False) is True)
            duplicates += int(record.get("duplicate", False) is True)
            deferred += int(record.get("deferred_candidate", False) is True)
            if record.get("policy_blocked", False):
                blocked += 1
                if record.get("deferred_candidate") and origin_id is not None:
                    conn.execute(
                        "INSERT INTO deferred_candidates VALUES (?,?,?,?,?,?,?)",
                        (dbmod.new_id("deferred"), origin_id,
                         record.get("method", "GET").upper(), record.get("url", ""),
                         record.get("priority"), "request_budget", dbmod.now()),
                    )
                    conn.commit()
                continue
            if record.get("browser_support") == "passive":
                continue
            capture_bodies = record.get("capture_bodies", False) is True
            request_body = record.get("request_body") if capture_bodies else None
            response_body = record.get("response_body") if capture_bodies else None
            endpoint_id = None
            if origin_id is not None:
                from urllib.parse import urlsplit
                from aidast.recon.judgment import normalize_path
                row = conn.execute(
                    "SELECT endpoint_id,verification_status FROM endpoints WHERE origin_id=? AND method=? AND normalized_path=?",
                    (origin_id, record["method"].upper(), normalize_path(urlsplit(record["url"]).path)),
                ).fetchone()
                endpoint_id = row[0] if row else None
            stored_response = response_body.encode('utf-8') if isinstance(response_body, str) else None
            receipt = record.get('request_receipt')
            if receipt is not None:
                from aidast.core.capture_receipt import validate_capture_receipt
                try:
                    if any(record.get(k) for k in ('candidate_probe','deferred_candidate','duplicate','static_resource')):
                        raise ValueError('non-resource capture')
                    receipt = validate_capture_receipt(receipt, url=record['url'], method=record['method'], response_body=stored_response)
                except (ValueError, TypeError):
                    receipt = None
            transaction_id = dbmod.insert_http_transaction(
                conn,
                endpoint_id=endpoint_id,
                source=record.get("source", "mitmproxy"),
                method=record["method"],
                url=record["url"],
                request_headers=sanitize_headers(record.get("request_headers")),
                request_body=request_body.encode("utf-8") if request_body else None,
                response_status=record.get("response_status"),
                response_headers=sanitize_headers(record.get("response_headers")),
                response_body=stored_response,
                request_receipt=receipt,
                content_type=record.get("content_type"),
            )
            if origin_id is not None:
                conn.execute("UPDATE http_transactions SET origin_id=? WHERE http_transaction_id=?",
                             (origin_id, transaction_id))
                if endpoint_id is not None:
                    from aidast.recon.annotations import persist_url_parameters, safe_url
                    from aidast.recon.judgment import query_signature
                    from aidast.recon.verification import successful_response
                    # A proxy 200 can be a SPA or API error fallback. Only the
                    # response-aware verifier may promote a spec candidate.
                    succeeded = (successful_response(record.get("response_status"))
                                 and record.get("candidate_probe") is not True
                                 and row[1] != "candidate")
                    dbmod.upsert_endpoint(
                        conn, origin_id=origin_id, method=record["method"].upper(),
                        path=urlsplit(record["url"]).path,
                        normalized_path=normalize_path(urlsplit(record["url"]).path),
                        query_signature=query_signature(record["url"]),
                        source_tool="mitmproxy",
                        verification_status="verified" if succeeded else "observed",
                        is_excluded=not succeeded,
                    )
                    persist_url_parameters(conn, endpoint_id, record["url"])
                    conn.execute("""INSERT INTO endpoint_observations
                        (observation_id,endpoint_id,http_transaction_id,source_tool,
                         discovery_kind,observed_url,association_method,observed_at)
                        VALUES (?,?,?,'mitmproxy','http_request',?,'proxy_capture',?)""",
                        (dbmod.new_id('observation'), endpoint_id, transaction_id,
                         safe_url(record['url']), record.get('captured_at') or dbmod.now()))
                conn.commit()
            count += 1

    jsonl_path.unlink(missing_ok=True)
    print(
        "  [mitmproxy] 별도 집계: "
        f"정적 리소스 {static_resources}건, 중복 요청 {duplicates}건, "
        f"예산 보류 후보 {deferred}건"
    )
    return count, blocked


def read_recent_json_responses(jsonl_path: Path | None) -> list[dict]:
    """Read complete positive JSON evidence across the capture, with bounded memory."""
    rows = ReconCaptureCursor().read(jsonl_path)
    return [row for row in reversed(rows) if type(row.get('response_status')) is int
            and 200 <= row['response_status'] < 300 and not row.get('candidate_probe')
            and any(str(k).lower() == 'content-type' and (
                str(v).split(';', 1)[0].strip().lower() == 'application/json'
                or str(v).split(';', 1)[0].strip().lower().endswith('+json'))
                for k, v in row['response_headers'].items())][:100]


def read_observed_collection_responses(jsonl_path: Path | None) -> list[dict]:
    """Read a bounded snapshot of existing capture; never store headers or bodies elsewhere."""
    return _read_observed_responses(jsonl_path, include_documents=False)


def read_observed_recon_responses(jsonl_path: Path | None, *, cursor=None) -> list[dict]:
    """Include captured HTML script declarations and JSON response binding inputs."""
    return cursor.read(jsonl_path) if cursor is not None else _read_observed_responses(jsonl_path, include_documents=True)


class ReconCaptureCursor:
    """Consume appended complete records; bound retained evidence, not traffic.

    Noise and oversized complete rows never prevent reading later evidence.
    An incomplete tail remains unread until the writer finishes its newline.
    """

    def __init__(self):
        self.offset = 0
        self.identity = None
        self.evicted_records = 0

    def read(self, jsonl_path: Path | None) -> list[dict]:
        if jsonl_path is None or not Path(jsonl_path).is_file():
            return []
        path = Path(jsonl_path)
        stat = path.stat()
        identity = (str(path.resolve()), stat.st_dev, stat.st_ino)
        if self.identity != identity or stat.st_size < self.offset:
            self.offset = 0
        self.identity = identity
        retained = {False: deque(), True: deque()}
        retained_bytes = {False: 0, True: 0}
        with path.open('rb') as capture:
            capture.seek(self.offset)
            while capture.tell() < stat.st_size:
                start = capture.tell()
                line = capture.readline(min(2_100_000, stat.st_size - start))
                if not line.endswith(b'\n'):
                    # Skip a completed oversized row using fixed-size chunks.
                    while capture.tell() < stat.st_size and not line.endswith(b'\n'):
                        line = capture.readline(min(65536, stat.st_size - capture.tell()))
                    if not line.endswith(b'\n'):
                        self.offset = start
                        break
                    self.offset = capture.tell()
                    continue
                self.offset = capture.tell()
                try:
                    record = json.loads(line)
                except (ValueError, UnicodeDecodeError):
                    continue
                if not isinstance(record, dict) or (record.get('method') != 'GET'
                        or record.get('capture_bodies') is not True or record.get('policy_blocked')):
                    continue
                headers = record.get('response_headers')
                body = record.get('response_body')
                if not isinstance(headers, dict) or not isinstance(body, str):
                    continue
                media = next((str(v).split(';', 1)[0].strip().lower()
                              for k, v in headers.items() if str(k).lower() == 'content-type'), '')
                status = record.get('response_status')
                script = media in {'application/javascript', 'text/javascript', 'application/ecmascript',
                                   'text/ecmascript', 'application/x-javascript'}
                if (record.get('static_resource') or record.get('duplicate')) and not script:
                    continue
                if media in {'text/html', 'application/xhtml+xml'} or script:
                    if type(status) is not int or not 200 <= status < 300:
                        continue
                elif media != 'application/json' and not media.endswith('+json'):
                    continue
                elif type(status) is not int or not (200 <= status < 300 or status in {401, 403}):
                    continue
                size = len(line)
                snapshot = {key: record.get(key) for key in (
                    'method', 'url', 'response_status', 'response_headers', 'response_body',
                    'policy_blocked', 'capture_bodies', 'authentication_key', 'candidate_probe',
                    'static_resource', 'duplicate',
                )}
                denied = status in {401, 403}
                retained[denied].append((snapshot, size, self.offset))
                retained_bytes[denied] += size
                while (len(retained[denied]) > (30 if denied else 120)
                       or retained_bytes[denied] > (1_000_000 if denied else 7_000_000)):
                    _, previous_size, _ = retained[denied].popleft()
                    retained_bytes[denied] -= previous_size
                    self.evicted_records += 1
        return [row for row, size, position in sorted(
            (*retained[False], *retained[True]), key=lambda value: value[2])]


def _read_observed_responses(jsonl_path: Path | None, *, include_documents: bool) -> list[dict]:
    rows = ReconCaptureCursor().read(jsonl_path)
    if include_documents:
        return rows
    from urllib.parse import urlsplit
    results = []
    for row in rows:
        try:
            segments = urlsplit(row.get('url', '')).path.strip('/').split('/')
        except (TypeError, ValueError):
            continue
        if len(segments) == 2 and segments[0].lower() == 'api':
            results.append(row)
    return results[-100:]
