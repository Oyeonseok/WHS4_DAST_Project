"""HTTP_PROBE - external-tool-free liveness/basic-info check for an origin.

Uses only the standard library so this always works, even before any of the
recon binaries (httpx, katana, ...) are installed locally.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


@dataclass
class ProbeResult:
    ok: bool
    status_code: int | None
    scheme: str
    host: str
    port: int | None
    body: str
    headers: dict[str, str]


def probe(url: str, *, timeout: float = 8.0) -> ProbeResult:
    parsed = urlsplit(url)
    request = Request(url, headers={"User-Agent": "aidast-recon/0.1"})
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read(200_000).decode("utf-8", errors="replace")
            return ProbeResult(
                ok=True,
                status_code=response.status,
                scheme=parsed.scheme,
                host=parsed.hostname or "",
                port=parsed.port,
                body=body,
                headers=dict(response.headers.items()),
            )
    except HTTPError as exc:
        body = exc.read(200_000).decode("utf-8", errors="replace") if exc.fp else ""
        return ProbeResult(
            ok=True,
            status_code=exc.code,
            scheme=parsed.scheme,
            host=parsed.hostname or "",
            port=parsed.port,
            body=body,
            headers=dict(exc.headers.items()) if exc.headers else {},
        )
    except URLError:
        return ProbeResult(
            ok=False,
            status_code=None,
            scheme=parsed.scheme,
            host=parsed.hostname or "",
            port=parsed.port,
            body="",
            headers={},
        )
