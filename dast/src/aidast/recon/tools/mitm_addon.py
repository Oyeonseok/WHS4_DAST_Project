"""mitmproxy addon - Playwright 로그인/상호작용 세션 동안 오간 요청/응답을
관찰해서 기록한다.

mitmproxy addon은 우리 메인 파이썬 프로세스가 아니라 mitmdump가 띄우는
별도 프로세스 안에서 돈다. SQLite에 바로 쓰면 두 프로세스가 같은 DB
파일에 동시에 쓰게 되니, 여기서는 JSONL 파일로만 남기고 mitm_ingest.py가
나중에 그 파일을 읽어서 DB에 넣는다.

실행 예시:
    mitmdump -s src/aidast/recon/tools/mitm_addon.py \
        --set flow_log=mitm_flows.jsonl -p 8080

body 정책: request/response body는 아예 읽지 않는다. 로그인 세션 토큰이나
입력값이 파일에 그대로 박히기 때문이다(db.insert_http_exchange()가 body를
일부러 안 받는 것과 같은 이유). 대신 response_size로 크기만 남긴다.

헤더 정책: 헤더는 전부 남기되 인증 관련 헤더의 '값'만 REDACTED로 가린다.
값을 지우고 키는 남기는 이유는, mitm_ingest.py의 is_authenticated 판단에
"Authorization 헤더가 붙어 있었는가"가 필요하기 때문이다.

JSONL 한 줄의 형태:
    {"timestamp", "scheme", "host", "port", "method", "path",
     "query_string", "request_headers", "status_code", "content_type",
     "response_size"}
"""

from __future__ import annotations

import json
import time
from typing import TextIO

from mitmproxy import ctx, http

# 값을 가릴 헤더 (소문자 비교). 키 자체는 남긴다.
SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
}

REDACTED = "<redacted>"


def _safe_headers(headers) -> dict[str, str]:
    """헤더를 dict로 바꾸되 인증 관련 값은 가린다."""
    result: dict[str, str] = {}
    for key, value in headers.items():
        result[key] = REDACTED if key.lower() in SENSITIVE_HEADERS else value
    return result


class ObservationLogger:
    def __init__(self) -> None:
        self._fp: TextIO | None = None
        self._count = 0

    def load(self, loader):
        loader.add_option(
            name="flow_log",
            typespec=str,
            default="mitm_flows.jsonl",
            help="캡처한 flow를 남길 로그 파일 경로",
        )

    def running(self):
        # append 모드 - 같은 로그에 여러 세션을 이어 붙일 수 있게 둔다.
        self._fp = open(ctx.options.flow_log, "a", encoding="utf-8")
        ctx.log.info(f"[observation] flow 로그: {ctx.options.flow_log}")

    def done(self):
        if self._fp is not None:
            self._fp.close()
            self._fp = None
        ctx.log.info(f"[observation] flow {self._count}건 기록")

    def response(self, flow: http.HTTPFlow) -> None:
        if self._fp is None:
            return

        req = flow.request
        res = flow.response

        record = {
            # is_authenticated 판단(로그인 완료 시각 이후인지)에 쓰려고 남긴다.
            "timestamp": time.time(),
            "scheme": req.scheme,
            "host": req.host,
            "port": req.port,
            "method": req.method,
            "path": req.path.split("?", 1)[0],
            "query_string": req.path.partition("?")[2] or None,
            "request_headers": _safe_headers(req.headers),
            "status_code": res.status_code if res else None,
            "content_type": res.headers.get("content-type") if res else None,
            # body는 읽지 않고 크기만. Content-Length가 없으면 None.
            "response_size": (
                int(res.headers["content-length"])
                if res and "content-length" in res.headers
                and res.headers["content-length"].isdigit()
                else None
            ),
        }

        try:
            self._fp.write(json.dumps(record, ensure_ascii=False) + "\n")
            self._fp.flush()
            self._count += 1
        except Exception as exc:  # 기록 실패로 프록시 자체가 죽지 않게 한다
            ctx.log.warn(f"[observation] flow 기록 실패: {exc}")


addons = [ObservationLogger()]
