"""mitmdump 프로세스를 띄우고/끄고, 캡처된 JSONL을 DB로 적재하는 헬퍼.

katana/ffuf/Playwright 전부가 이 프록시를 거쳐가게 되며, mitmdump가
설치돼 있지 않거나 제시간에 포트를 열지 못하면 조용히 건너뛴다(fail-open) -
mitmproxy는 관찰/스코프 강제용 부가 기능이라, 이게 없다고 recon 자체가
막히면 안 된다.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sqlite3
import tempfile
import time
from pathlib import Path

from aidast.recon import db as dbmod

_ADDON_PATH = Path(__file__).parent / "mitm_addon.py"


def _wait_for_proxy_port(port: int, *, timeout: float = 8.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def start_mitmproxy(
    capture_path: Path, *, port: int = 8080, scope_rules: dict | None = None
) -> tuple[subprocess.Popen | None, str | None]:
    if shutil.which("mitmdump") is None:
        print("  [건너뜀] mitmdump 미설치 - mitmproxy 관찰 없이 진행")
        return None, None

    command = [
        "mitmdump", "-s", str(_ADDON_PATH), "-p", str(port),
        "--set", f"out_file={capture_path}",
    ]

    if scope_rules is not None:
        scope_file = Path(tempfile.mktemp(suffix=".json"))
        scope_file.write_text(json.dumps(scope_rules), encoding="utf-8")
        command += ["--set", f"scope_file={scope_file}"]

    try:
        proc = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as exc:
        print(f"  [경고] mitmdump 실행 실패: {exc} - mitmproxy 관찰 없이 진행")
        return None, None

    if not _wait_for_proxy_port(port):
        print("  [경고] mitmdump가 제시간에 포트를 열지 않음 - mitmproxy 관찰 없이 진행")
        proc.terminate()
        return None, None

    print(f"  [mitmproxy] 127.0.0.1:{port}에서 관찰 시작")
    return proc, f"http://127.0.0.1:{port}"


def stop_mitmproxy(proc: subprocess.Popen | None) -> None:
    if proc is None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


def ingest_mitm_capture(conn: sqlite3.Connection, jsonl_path: Path) -> int:
    if not jsonl_path.is_file():
        return 0

    count = 0
    with jsonl_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            request_body = record.get("request_body")
            response_body = record.get("response_body")
            dbmod.insert_http_transaction(
                conn,
                endpoint_id=None,
                source=record.get("source", "mitmproxy"),
                method=record["method"],
                url=record["url"],
                request_headers=record.get("request_headers"),
                request_body=request_body.encode("utf-8") if request_body else None,
                response_status=record.get("response_status"),
                response_headers=record.get("response_headers"),
                response_body=response_body.encode("utf-8") if response_body else None,
                content_type=record.get("content_type"),
            )
            count += 1

    jsonl_path.unlink(missing_ok=True)
    return count
