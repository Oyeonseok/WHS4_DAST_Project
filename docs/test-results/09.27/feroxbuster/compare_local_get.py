"""Bounded, GET-only feroxbuster/ffuf comparison against approved Juice Shop."""

from __future__ import annotations

import http.client
import json
import os
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from aidast.recon.policy import TargetPolicy


ROOT = Path("result/test-runs/09.27/feroxbuster-get-comparison")
SOURCE_WORDLIST = Path("result/test-runs/09.24/wordlists/common-api-endpoints-mazen160.txt")
POLICY_FILE = Path(
    "result/test-runs/09.24/browser-luna-full-1000/Scope/"
    "lab-aidast-invalid/juice-shop/TargetPolicy.json"
)
ORIGIN = "http://127.0.0.1:3001"
MAX_FORWARDED_REQUESTS = 100
PLANNED_TOOL_RUNS = 3
REQUEST_INTERVAL_SECONDS = 2.0


class ScopedProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        policy: TargetPolicy = self.server.policy  # type: ignore[attr-defined]
        url = self.path
        parsed = urlsplit(url)
        if (parsed.scheme != "http" or parsed.netloc != "127.0.0.1:3001"
                or not policy.allows_url(url, method="GET")):
            self._reject(403)
            return
        if self.server.forwarded >= MAX_FORWARDED_REQUESTS:  # type: ignore[attr-defined]
            self._reject(429)
            return

        now = time.monotonic()
        delay = self.server.rate_state[0] - now  # type: ignore[attr-defined]
        if delay > 0:
            time.sleep(delay)
        self.server.rate_state[0] = time.monotonic() + REQUEST_INTERVAL_SECONDS  # type: ignore[attr-defined]
        self.server.forwarded += 1  # type: ignore[attr-defined]

        connection = http.client.HTTPConnection("127.0.0.1", 3001, timeout=15)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        try:
            forwarded_at = time.time()
            connection.request("GET", path, headers={
                "Host": "127.0.0.1:3001",
                "Accept": self.headers.get("Accept", "*/*"),
                "User-Agent": self.headers.get("User-Agent", "feroxbuster-comparison"),
            })
            response = connection.getresponse()
            body = response.read(2_000_000)
            self.send_response(response.status)
            for header in ("Content-Type", "Location"):
                value = response.getheader(header)
                if value:
                    self.send_header(header, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            self.server.requests.append({  # type: ignore[attr-defined]
                "url": url, "status": response.status, "bytes": len(body),
                "started_at": forwarded_at,
            })
        except (BrokenPipeError, ConnectionResetError):
            pass
        except (OSError, http.client.HTTPException):
            try:
                self._reject(502)
            except (BrokenPipeError, ConnectionResetError):
                pass
        finally:
            connection.close()

    def do_CONNECT(self) -> None:
        self._reject(405)

    def do_HEAD(self) -> None:
        self._reject(405)

    def do_POST(self) -> None:
        self._reject(405)

    def _reject(self, status: int) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, _format: str, *_args: object) -> None:
        pass


class QuietHTTPServer(HTTPServer):
    def handle_error(self, _request, _client_address) -> None:
        # Timed scanner clients may close a keep-alive connection first.
        pass


def run_tool(
    name: str, command: list[str], policy: TargetPolicy,
    *, rate_state: list[float] | None = None,
) -> dict:
    server = QuietHTTPServer(("127.0.0.1", 0), ScopedProxyHandler)
    server.policy = policy  # type: ignore[attr-defined]
    server.forwarded = 0  # type: ignore[attr-defined]
    server.rate_state = rate_state if rate_state is not None else [0.0]  # type: ignore[attr-defined]
    server.requests = []  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    proxy = f"http://127.0.0.1:{server.server_port}"
    resolved = [part.replace("{proxy}", proxy) for part in command]
    env = dict(os.environ, NO_PROXY="", no_proxy="")
    started = time.monotonic()
    try:
        completed = subprocess.run(
            resolved, capture_output=True, text=True, timeout=240, env=env,
        )
        returncode = completed.returncode
        stdout, stderr = completed.stdout, completed.stderr
    except subprocess.TimeoutExpired as exc:
        returncode = 124
        stdout = (exc.stdout or b"").decode(errors="replace") if isinstance(exc.stdout, bytes) else exc.stdout or ""
        stderr = (exc.stderr or b"").decode(errors="replace") if isinstance(exc.stderr, bytes) else exc.stderr or ""
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
    (ROOT / f"{name}.stdout.log").write_text(stdout, encoding="utf-8")
    (ROOT / f"{name}.stderr.log").write_text(stderr, encoding="utf-8")
    (ROOT / f"{name}.requests.json").write_text(
        json.dumps(server.requests, ensure_ascii=False, indent=2), encoding="utf-8",  # type: ignore[attr-defined]
    )
    return {
        "tool": name, "returncode": returncode,
        "elapsed_seconds": round(time.monotonic() - started, 2),
        "forwarded_requests": server.forwarded,  # type: ignore[attr-defined]
        "statuses": {str(status): sum(item["status"] == status for item in server.requests)
                     for status in sorted({item["status"] for item in server.requests})},  # type: ignore[attr-defined]
        "urls": sorted({item["url"] for item in server.requests if item["status"] != 404}),  # type: ignore[attr-defined]
    }


def main() -> None:
    ROOT.mkdir(parents=True, exist_ok=True)
    policy_data = json.loads(POLICY_FILE.read_text(encoding="utf-8"))
    policy = TargetPolicy.model_validate(policy_data["policies"][0])
    if PLANNED_TOOL_RUNS * MAX_FORWARDED_REQUESTS > policy.limits.max_requests:
        raise ValueError("experiment-wide request ceiling exceeds TargetPolicy")
    rate_state = [0.0]
    words = SOURCE_WORDLIST.read_text(encoding="utf-8").splitlines()[:50]
    wordlist = ROOT / "wordlist-50.txt"
    wordlist.write_text("\n".join(words) + "\n", encoding="utf-8")

    ferox = run_tool("feroxbuster", [
        "feroxbuster", "--url", ORIGIN + "/", "--wordlist", str(wordlist),
        "--methods", "GET", "--no-recursion", "--dont-extract-links",
        "--threads", "1", "--scan-limit", "1", "--rate-limit", "1",
        "--time-limit", "3m", "--timeout", "15", "--proxy", "{proxy}",
        "--json", "--output", str(ROOT / "feroxbuster.jsonl"),
        "--no-state", "--quiet",
    ], policy, rate_state=rate_state)
    print(json.dumps({key: value for key, value in ferox.items() if key != "urls"},
                     ensure_ascii=False), flush=True)

    ffuf = run_tool("ffuf", [
        "ffuf", "-u", ORIGIN + "/FUZZ", "-w", str(wordlist),
        "-of", "json", "-o", str(ROOT / "ffuf.json"), "-s", "-ac",
        "-t", "1", "-p", "2", "-timeout", "15", "-maxtime", "180",
        "-x", "{proxy}",
    ], policy, rate_state=rate_state)
    print(json.dumps({key: value for key, value in ffuf.items() if key != "urls"},
                     ensure_ascii=False), flush=True)

    filtered = run_tool("feroxbuster_filtered", [
        "feroxbuster", "--url", ORIGIN + "/", "--wordlist", str(wordlist),
        "--methods", "GET", "--no-recursion", "--dont-extract-links",
        "--threads", "1", "--scan-limit", "1", "--rate-limit", "1",
        "--time-limit", "3m", "--timeout", "15", "--proxy", "{proxy}",
        "--filter-size", "9393", "--json",
        "--output", str(ROOT / "feroxbuster_filtered.jsonl"),
        "--no-state", "--quiet",
    ], policy, rate_state=rate_state)
    print(json.dumps({key: value for key, value in filtered.items() if key != "urls"},
                     ensure_ascii=False), flush=True)
    (ROOT / "summary.json").write_text(
        json.dumps([ferox, ffuf, filtered], ensure_ascii=False, indent=2), encoding="utf-8",
    )


if __name__ == "__main__":
    main()
