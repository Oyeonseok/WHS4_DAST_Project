"""Executes a ReconCoordinator-produced task list without Codex/Main Agent.

Each ReconTask.task_type dispatches to a handler below. Handlers are wrapped
with `_stage`, which mirrors the recon_stage/ReconFailureReport pattern from
the design docs: unexpected exceptions are logged to pipeline_runs and
re-raised as ReconExecutionError rather than being swallowed.

MVP scope: ENDPOINT_DISCOVERY runs katana in both standard and headless
modes unconditionally, computes Gap Ratio from those two alone, takes
action on the result (deep_path signal + origins.spa_detected correction),
and only then runs ffuf (brute force) - see the 7-step order in
_handle_endpoint_discovery. ffuf is deliberately excluded from the Gap
Ratio calculation so its result volume can't dilute the ratio.
"""

from __future__ import annotations

import functools
import json
from pathlib import Path

from aidast.recon import db as dbmod
from aidast.recon.judgment import assess_gap_ratio, merge_and_normalize
from aidast.recon.models import ReconStep, ReconTask, ReconTaskStatus
from aidast.recon.origin import resolve_origin
from aidast.recon.tools.asset_dns_port import run_dnsx, run_naabu, run_subfinder
from aidast.recon.tools.endpoint_discovery import discover_endpoints, discover_with_ffuf
from aidast.recon.tools.http_probe import ProbeResult, probe
from aidast.recon.tools.login import SessionCredentials, login_and_capture_session


class ReconExecutionError(RuntimeError):
    pass


def _stage(stage_name: str):
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(self: "ReconExecutor", task: ReconTask, *args, **kwargs):
            try:
                return fn(self, task, *args, **kwargs)
            except Exception as exc:  # noqa: BLE001 - intentionally broad
                dbmod.log_pipeline_run(
                    self.conn,
                    scan_id=self.scan_id,
                    task_id=task.task_id,
                    stage=stage_name,
                    status="failed",
                    error_type=type(exc).__name__,
                    message=str(exc),
                    recoverable=False,
                )
                task.status = ReconTaskStatus.FAILED
                raise ReconExecutionError(
                    f"{stage_name} 실패 (task={task.task_id}): {exc}"
                ) from exc

        return wrapper

    return decorator


def _as_url(asset: str) -> str:
    return asset if asset.startswith("http") else f"https://{asset}"


class ReconExecutor:
    def __init__(
        self,
        *,
        scan_id: str,
        scope_type: str,
        scope_value: str,
        db_path: Path,
        ffuf_wordlist: str | None = None,
        login_email: str | None = None,
        login_password: str | None = None,
        login_path: str = "/login",
        proxy: str | None = None,
    ):
        self.scan_id = scan_id
        self.conn = dbmod.init_db(db_path)
        dbmod.insert_scan(self.conn, scan_id=scan_id, scope_type=scope_type, scope_value=scope_value)
        self.ffuf_wordlist = ffuf_wordlist
        self.login_email = login_email
        self.login_password = login_password
        self.login_path = login_path
        # proxy를 주면 로그인(Playwright)과 katana/ffuf 요청이 이 프록시(mitmproxy)를
        # 거쳐 나가서, mitm_addon.py가 같은 트래픽을 관찰할 수 있다.
        self.proxy = proxy
        self._asset_ids: dict[str, str] = {}
        self._origin_ids: dict[str, str] = {}
        self._probe_cache: dict[str, ProbeResult] = {}
        # origin_id -> 이미 캡처한 세션. 같은 origin에 대해 매 ENDPOINT_DISCOVERY
        # 마다 다시 로그인하지 않도록 캐시한다.
        self._session_cache: dict[str, SessionCredentials] = {}

    def run(self, tasks: list[ReconTask]) -> None:
        completed_ids: set[str] = set()
        pending = list(tasks)
        while pending:
            progressed = False
            for task in list(pending):
                if all(dep in completed_ids for dep in task.depends_on_task_ids):
                    self._execute(task)
                    completed_ids.add(task.task_id)
                    pending.remove(task)
                    progressed = True
            if not progressed:
                raise ReconExecutionError("의존관계를 풀 수 없는 Task가 남아 있음")

    def _execute(self, task: ReconTask) -> None:
        task.status = ReconTaskStatus.RUNNING
        handler = {
            ReconStep.ASSET_DISCOVERY: self._handle_asset_discovery,
            ReconStep.DNS_RESOLUTION: self._handle_dns_resolution,
            ReconStep.HOST_PORT_DISCOVERY: self._handle_host_port_discovery,
            ReconStep.HTTP_PROBE: self._handle_http_probe,
            ReconStep.ORIGIN_DISCOVERY: self._handle_origin_discovery,
            ReconStep.ENDPOINT_DISCOVERY: self._handle_endpoint_discovery,
        }[task.task_type]
        print(f"-> {task.task_type.value} 시작 (target={task.target.asset})")
        handler(task)
        task.status = ReconTaskStatus.COMPLETED
        dbmod.log_pipeline_run(
            self.conn, scan_id=self.scan_id, task_id=task.task_id,
            stage=task.task_type.value, status="success",
        )
        print("   완료")

    def _ensure_asset(self, task: ReconTask) -> str:
        asset_id = self._asset_ids.get(task.target.asset)
        if asset_id is None:
            asset_id = dbmod.insert_asset(
                self.conn, scan_id=self.scan_id,
                identifier=task.target.asset, asset_type=task.target.asset_type.value,
            )
            self._asset_ids[task.target.asset] = asset_id
        return asset_id

    @_stage("asset_discovery")
    def _handle_asset_discovery(self, task: ReconTask) -> None:
        asset_id = self._ensure_asset(task)
        if task.target.asset_type.value == "DOMAIN":
            for sub in run_subfinder(task.target.asset):
                dbmod.insert_observation(
                    self.conn, origin_id=asset_id, obs_type="subdomain",
                    key="subfinder", value=sub, source="subfinder",
                )

    @_stage("dns_resolution")
    def _handle_dns_resolution(self, task: ReconTask) -> None:
        run_dnsx([task.target.asset])

    @_stage("host_port_discovery")
    def _handle_host_port_discovery(self, task: ReconTask) -> None:
        run_naabu([task.target.asset])

    @_stage("http_probe")
    def _handle_http_probe(self, task: ReconTask) -> None:
        url = _as_url(task.target.asset)
        result = probe(url)
        self._probe_cache[task.target.asset] = result
        if not result.ok:
            raise ReconExecutionError(f"{url} 응답 없음")

    @_stage("origin_discovery")
    def _handle_origin_discovery(self, task: ReconTask) -> None:
        asset_id = self._ensure_asset(task)
        url = _as_url(task.target.asset)

        probe_result = self._probe_cache.get(task.target.asset) or probe(url)
        resolution = resolve_origin(probe_result)

        origin_id = dbmod.upsert_origin(
            self.conn, asset_id=asset_id,
            scheme=probe_result.scheme, host=probe_result.host, port=probe_result.port,
            base_url=url, http_probe_status=probe_result.status_code,
            spa_detected=resolution.spa_detected,
            framework_signature=resolution.framework_signature,
            main_crawler_mode=resolution.main_crawler_mode,
        )
        self._origin_ids[task.target.asset] = origin_id
        print(
            f"   SPA={resolution.spa_detected} "
            f"({resolution.framework_signature or '시그니처 없음'}) "
            f"-> {resolution.main_crawler_mode}"
        )

    @_stage("endpoint_discovery")
    def _handle_endpoint_discovery(self, task: ReconTask) -> None:
        origin_id = self._origin_ids.get(task.target.asset)
        if origin_id is None:
            raise ReconExecutionError("ORIGIN_DISCOVERY가 먼저 끝나야 함")

        url = _as_url(task.target.asset)

        # 로그인 자격증명이 주어졌으면 Playwright로 한 번만 로그인해서 세션을
        # 캡처하고(팀 설계: Playwright는 로그인 전용), 그 세션 헤더를 katana/
        # ffuf에 넘겨 인증된 상태로 크롤링한다. 캐시가 있으면 재사용한다.
        session = self._session_cache.get(origin_id)
        if session is None and self.login_email and self.login_password:
            session = login_and_capture_session(
                url, email=self.login_email, password=self.login_password,
                login_path=self.login_path, proxy=self.proxy,
            )
            self._session_cache[origin_id] = session
            if not session.is_empty():
                dbmod.insert_session(
                    self.conn, origin_id=origin_id, target=self.login_email,
                    auth_state=json.dumps(
                        {"cookie_header": session.cookie_header, "extra_headers": session.extra_headers}
                    ),
                )
        header_args = session.as_header_args() if session else None

        # 팀 회의에서 정리된 순서 그대로:
        # 1) standard + headless 결과를 (2) 합쳐서 전체로 두고
        # 3) headless에만 나온 것을 (4) 분자로 (5) 비율을 구한 뒤
        # 6) 그 결과에 따라 조치를 취하고, 그게 다 끝난 뒤에야
        # 7) 브루트포스(ffuf)를 진행한다.

        # 1~2) standard+headless
        katana_raw = discover_endpoints(url, header_args=header_args, proxy=self.proxy)
        katana_merged = merge_and_normalize(katana_raw)
        katana_included = [e for e in katana_merged if not e["is_excluded"]]

        # 3~5) headless 전용 비율
        gap = assess_gap_ratio(katana_included)
        dbmod.insert_surface_signal(
            self.conn, origin_id=origin_id, signal_type="dynamic_gap_ratio", value=f"{gap.ratio:.3f}",
        )
        print(f"   {gap.reasoning}")

        # 6) 결과에 따른 조치
        if gap.needs_deep_crawl:
            dbmod.insert_surface_signal(
                self.conn, origin_id=origin_id, signal_type="deep_path_needed", value="true",
            )
            print("   SPA 성격 강함 확인 (katana_headless 전용 발견 비율 높음) - headless 결과 이미 포함됨")

            # origin_discovery의 정적 시그니처 판단(spa_detected)이 이 실측
            # 증거와 어긋나면 origins 테이블도 같이 정정한다. 안 그러면
            # origins.spa_detected는 계속 틀린 값으로 남아, DB만 보는 사람은
            # 실측과 반대되는 결론을 믿게 된다.
            row = self.conn.execute(
                "SELECT spa_detected FROM origins WHERE origin_id=?", (origin_id,)
            ).fetchone()
            if row and not row[0]:
                dbmod.update_origin_spa_verdict(
                    self.conn, origin_id=origin_id, spa_detected=True,
                    framework_signature="gap_ratio_evidence",
                )
                print("   origins.spa_detected 정정: False -> True (정적 시그니처 판단이 실측과 어긋남)")

        # 7) 조치가 끝난 뒤에야 브루트포스 진행
        ffuf_raw = discover_with_ffuf(url, wordlist=self.ffuf_wordlist, header_args=header_args, proxy=self.proxy)

        # 최종 DB 저장은 katana+ffuf를 합친 전체 집합으로.
        merged = merge_and_normalize(katana_raw + ffuf_raw)
        for item in merged:
            dbmod.upsert_endpoint(
                self.conn, origin_id=origin_id, method=item["method"],
                path=item["path"], normalized_path=item["normalized_path"],
                content_type=item.get("content_type"),
                source_tool=",".join(sorted(item["source_tools"])),
                is_excluded=item["is_excluded"], exclude_reason=item["exclude_reason"],
            )
        included = [e for e in merged if not e["is_excluded"]]
        print(f"   최종 발견 {len(included)}건 (제외 {len(merged) - len(included)}건, ffuf 포함)")
