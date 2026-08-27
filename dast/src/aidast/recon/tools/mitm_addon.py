"""mitmproxy addon - Playwright 로그인/상호작용 세션 동안 오간 요청/응답을
JSONL로 기록한다.

mitmproxy addon은 우리 메인 파이썬 프로세스가 아니라 mitmdump가 띄우는
별도 프로세스 안에서 돈다. 그래서 여기서 SQLite에 바로 쓰지 않고 일단
파일로 남긴 다음, mitm_ingest.py가 나중에 그 파일을 읽어서 DB에 넣는
방식으로 갈라놨다 - 두 프로세스가 같은 SQLite 파일에 동시에 쓰는 것보다
훨씬 덜 골치아프다.

실행 (Juice Shop 등 http 타겟 기준, HTTPS 인터셉션용 CA 인증서 설치는
불필요):
    mitmdump -s src/aidast/recon/tools/mitm_addon.py \
        --set flow_log=mitm_flows.jsonl -p 8080

그 상태에서 Playwright가 http://127.0.0.1:8080를 프록시로 쓰도록 띄우면
지나가는 모든 요청/응답이 flow_log에 한 줄씩 쌓인다.

주의: request/response body는 기록하지 않는다. 로그인 세션이 오가는
트래픽을 그대로 남기면 토큰/개인정보가 파일에 박히기 때문. body가 정말
필요해지면 마스킹 정책부터 정하고 추가할 것 (mitm_ingest.py 상단 TODO
참고).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from mitmproxy import ctx, http


class ObservationLogger:
    def load(self, loader):
        loader.add_option(
            name="flow_log",
            typespec=str,
            default="mitm_flows.jsonl",
            help="캡처한 flow를 한 줄씩 남길 JSONL 파일 경로",
        )

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return
        request = flow.request
        response = flow.response
        record = {
            "method": request.method,
            "path": request.path.split("?")[0],
            "query": list(request.query.items()) if request.query else [],
            "request_headers": dict(request.headers),
            "status_code": response.status_code,
            "content_type": response.headers.get("content-type"),
            "response_size": len(response.content) if response.content else 0,
            "captured_at": datetime.now(timezone.utc).isoformat(),
        }
        with open(ctx.options.flow_log, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


addons = [ObservationLogger()]
