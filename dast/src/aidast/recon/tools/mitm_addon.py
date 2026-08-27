"""mitmproxy addon - Playwright 로그인/상호작용 세션 동안 오간 요청/응답을
관찰해서 기록한다. (스켈레톤 - 구현 필요)

mitmproxy addon은 우리 메인 파이썬 프로세스가 아니라 mitmdump가 띄우는
별도 프로세스 안에서 돈다. SQLite에 바로 쓰면 두 프로세스가 같은 DB
파일에 동시에 쓰게 되니, 일단 파일(JSONL 등)로 남기고 mitm_ingest.py가
나중에 그 파일을 읽어서 DB에 넣는 식으로 나누는 걸 권장.

실행 예시:
    mitmdump -s src/aidast/recon/tools/mitm_addon.py \
        --set flow_log=mitm_flows.jsonl -p 8080

주의: request/response body를 그대로 남기면 로그인 세션 토큰이나 입력값이
파일에 박힌다. body를 남길지, 남긴다면 어떤 필드를 마스킹할지부터 정할 것.

정해야 할 것:
- flow마다 어떤 필드를 남길지 (method/path/status/content-type 정도로
  충분한지, 헤더는 얼마나 남길지)
- 결과를 어디에 쓸지 (파일 로그 / 다른 방식)
"""

from __future__ import annotations

from mitmproxy import ctx, http


class ObservationLogger:
    def load(self, loader):
        loader.add_option(
            name="flow_log",
            typespec=str,
            default="mitm_flows.jsonl",
            help="캡처한 flow를 남길 로그 파일 경로",
        )

    def response(self, flow: http.HTTPFlow) -> None:
        # TODO: flow.request / flow.response에서 필요한 필드를 뽑아
        # ctx.options.flow_log에 한 줄씩 기록한다.
        raise NotImplementedError


addons = [ObservationLogger()]
