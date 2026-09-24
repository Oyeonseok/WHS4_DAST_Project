"""ffuf must ignore policy-proxy rejections without hiding target 403s."""

from __future__ import annotations

import shutil
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
from urllib.parse import urlsplit

import pytest

from aidast.recon.tools.endpoint_discovery import discover_with_ffuf


class _ProxyHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/blocked":
            status, body = 403, b"Blocked by AI-DAST TargetPolicy\n"
        elif path == "/denied":
            status, body = 403, b"Access denied by target"
        else:
            status, body = 404, b"Not Found"
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        pass


@pytest.mark.skipif(shutil.which("ffuf") is None, reason="ffuf unavailable")
def test_ffuf_drops_proxy_block_but_keeps_target_403() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ProxyHandler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        with TemporaryDirectory() as directory:
            wordlist = Path(directory) / "words.txt"
            wordlist.write_text("blocked\ndenied\n", encoding="utf-8")
            results = discover_with_ffuf(
                "http://example.test",
                wordlist=str(wordlist),
                seed_endpoints=[],
                auth_headers=None,
                proxy_url=f"http://127.0.0.1:{server.server_port}",
                root_selector=lambda _: ["/"],
            )
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)

    assert [(item["path"], item["evidence"]["response_status"]) for item in results] == [
        ("/denied", 403),
    ]
