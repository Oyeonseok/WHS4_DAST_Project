"""mitmproxy addon - Playwright 로그인/상호작용 세션 동안 오간 요청/응답을
관찰해서 기록한다.

mitmproxy addon은 우리 메인 파이썬 프로세스가 아니라 mitmdump가 띄우는
별도 프로세스 안에서 돈다. SQLite에 바로 쓰면 두 프로세스가 같은 DB
파일에 동시에 쓰게 되니, 파일(JSONL)로 남기고 mitm_ingest.py가 나중에
그 파일을 읽어서 DB에 넣는 식으로 나눈다.

실행 예시:
    mitmdump -s src/aidast/recon/tools/mitm_addon.py \
        --set flow_log=mitm_flows.jsonl -p 8080

주의: request/response body를 그대로 남기면 로그인 세션 토큰이나 입력값이
파일에 박힌다. 현재는 MVP로 body를 그대로 남기고, 마스킹은 이후 과제로 둔다.

정적 자산(이미지/폰트/CSS/JS/octet-stream)은 노이즈가 커서 기록에서
제외하고, 그 외(HTML/JSON/XML/폼 인코딩/알 수 없는 타입)는 전부 남긴다.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from urllib.parse import urlsplit

from mitmproxy import ctx, http

# 이 접두사로 시작하는 content-type은 정적 자산으로 보고 기록하지 않는다.
SKIP_CONTENT_TYPE_PREFIXES = (
    "image/",
    "font/",
    "text/css",
    "application/javascript",
    "application/octet-stream",
)


def _headers_to_dict(headers) -> dict[str, str]:
    """mitmproxy의 Headers 객체를 평범한 dict로 변환한다."""
    return dict(headers.items())


def _get_text_safe(message: http.Message) -> str:
    """request/response 본문을 텍스트로 디코딩한다. 바이너리/빈 본문이면
    빈 문자열을 반환한다."""
    if not message.raw_content:
        return ""
    try:
        return message.get_text() or ""
    except (UnicodeDecodeError, ValueError):
        return ""


class ObservationLogger:
    def load(self, loader):
        loader.add_option(
            name="flow_log",
            typespec=str,
            default="mitm_flows.jsonl",
            help="캡처한 flow를 남길 로그 파일 경로",
        )

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return

        content_type = flow.response.headers.get("content-type", "")
        if content_type.lower().startswith(SKIP_CONTENT_TYPE_PREFIXES):
            return

        request = flow.request
        response = flow.response

        # request.path에는 쿼리 스트링이 포함돼 있어 urlsplit으로 분리한다.
        split_path = urlsplit(request.path)

        record = {
            "method": request.method,
            "url": request.pretty_url,
            "path": split_path.path,
            "query": split_path.query,
            "status_code": response.status_code,
            "request_headers": _headers_to_dict(request.headers),
            "response_headers": _headers_to_dict(response.headers),
            "content_type": content_type,
            "request_body": _get_text_safe(request),
            "response_body": _get_text_safe(response),
            "response_size": len(response.raw_content) if response.raw_content else 0,
            "captured_at": datetime.now(timezone.utc).isoformat(),
        }

        with open(ctx.options.flow_log, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


addons = [ObservationLogger()]
