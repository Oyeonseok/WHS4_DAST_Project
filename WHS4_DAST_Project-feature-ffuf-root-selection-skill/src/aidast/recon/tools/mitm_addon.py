"""mitmdump가 로드하는 addon 스크립트.

mitmdump -s tools/mitm_addon.py -p 8080 \\
    --set out_file=mitm_capture.jsonl \\
    --set scope_file=/path/to/scope_rules.json   # 스코프 확정 전엔 생략

역할 두 가지:
1. 지나가는 모든 요청/응답을 한 쌍으로 JSONL 파일에 append(관찰)
2. scope_file이 주어지면 그 안의 allowed_hosts에 없는 호스트로 가는
   요청을 막는다(스코프 강제). scope_file이 없으면 fail-open으로
   아무것도 막지 않는다 - 아직 Scope.md 파이프라인이 없는 상태에서
   로컬 테스트가 이유 없이 막히면 안 되기 때문이다.

이 파일은 mitmdump 자체 파이썬 프로세스 안에서 실행되므로(우리 aidast
패키지가 깔린 venv가 아님), aidast 쪽 코드를 import하지 않는다.
"""

from __future__ import annotations

import json
from pathlib import Path

from mitmproxy import ctx, http


class ScopeAndCaptureAddon:
    def __init__(self) -> None:
        self.allowed_hosts: set[str] = set()
        self.scope_loaded = False
        self.out_path: Path | None = None

    def load(self, loader) -> None:
        loader.add_option(
            name="scope_file",
            typespec=str,
            default="",
            help="승인된 Scope에서 뽑은 allow-list JSON 경로. 비어있으면 fail-open(전부 허용).",
        )
        loader.add_option(
            name="out_file",
            typespec=str,
            default="mitm_capture.jsonl",
            help="캡처한 요청/응답을 append하는 JSONL 경로.",
        )

    def configure(self, updated) -> None:
        if "scope_file" in updated and ctx.options.scope_file:
            path = Path(ctx.options.scope_file)
            if path.is_file():
                data = json.loads(path.read_text(encoding="utf-8"))
                self.allowed_hosts = set(data.get("allowed_hosts", []))
                self.scope_loaded = True
                ctx.log.info(f"[scope] {len(self.allowed_hosts)}개 호스트 로드됨")
            else:
                ctx.log.warn(f"[scope] scope_file을 찾을 수 없음: {path} - fail-open")

        if "out_file" in updated and ctx.options.out_file:
            self.out_path = Path(ctx.options.out_file)

    def request(self, flow: http.HTTPFlow) -> None:
        if not self.scope_loaded:
            return
        if flow.request.pretty_host not in self.allowed_hosts:
            ctx.log.warn(f"[scope 차단] {flow.request.method} {flow.request.pretty_url}")
            flow.kill()

    def response(self, flow: http.HTTPFlow) -> None:
        if self.out_path is None:
            return
        record = {
            "source": "mitmproxy",
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "request_headers": dict(flow.request.headers),
            "request_body": flow.request.get_text(strict=False) if flow.request.content else None,
            "response_status": flow.response.status_code if flow.response else None,
            "response_headers": dict(flow.response.headers) if flow.response else None,
            "response_body": (
                flow.response.get_text(strict=False)
                if flow.response and flow.response.content
                else None
            ),
            "content_type": flow.response.headers.get("content-type") if flow.response else None,
        }
        with self.out_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


addons = [ScopeAndCaptureAddon()]
