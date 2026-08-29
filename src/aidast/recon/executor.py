"""Executes a ReconCoordinator-produced task list without Codex/Main Agent.

Each ReconTask.task_type dispatches to a handler below. Handlers are wrapped
with `_stage`, which mirrors the recon_stage/ReconFailureReport pattern from
the design docs: unexpected exceptions are logged to pipeline_runs and
re-raised as ReconExecutionError rather than being swallowed.

MVP scope: ENDPOINT_DISCOVERY runs katana in both standard and headless
modes unconditionally (see tools/endpoint_discovery.py), so the two modes'
results are always merged together with no separate re-crawl decision.
"""

from __future__ import annotations

import functools
from pathlib import Path

from aidast.recon import db as dbmod
from aidast.recon.judgment import merge_and_normalize
from aidast.recon.models import ReconStep, ReconTask, ReconTaskStatus
from aidast.recon.origin import resolve_origin
from aidast.recon.tools.asset_dns_port import run_dnsx, run_naabu, run_subfinder
from aidast.recon.tools.endpoint_discovery import discover_endpoints
from aidast.recon.tools.http_probe import ProbeResult, probe
from aidast.recon.tools.mitm_proxy import ingest_mitm_capture, start_mitmproxy, stop_mitmproxy


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
        # 승인된 Scope에서 뽑은 {"allowed_hosts": [...]} 형태.
        # 아직 Scope 파이프라인이 안 붙어서 None이면 mitmproxy가
        # 스코프 강제 없이(fail-open) 관찰만 한다.
        scope_rules: dict | None = None,
    ):
        self.scan_id = scan_id
        self.conn = dbmod.init_db(db_path)
        dbmod.insert_scan(self.conn, scan_id=scan_id, scope_type=scope_type, scope_value=scope_value)
        self.ffuf_wordlist = ffuf_wordlist
        self.scope_rules = scope_rules
        self._asset_ids: dict[str, str] = {}
        self._origin_ids: dict[str, str] = {}
        self._probe_cache: dict[str, ProbeResult] = {}

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
        # katana_standard/headless를 discover_endpoints()가 둘 다 돌리므로
        # origins.main_crawler_mode(SPA 추정값)는 더 이상 실행 분기에 쓰이지
        # 않는다 - 참고용 기록으로만 origins 테이블에 남아 있다.
        capture_path = Path(f"mitm_capture_{self.scan_id}.jsonl")
        proxy_process, proxy_url = start_mitmproxy(capture_path, scope_rules=self.scope_rules)
        try:
            raw = discover_endpoints(url, ffuf_wordlist=self.ffuf_wordlist, mitm_proxy_url=proxy_url)
        finally:
            stop_mitmproxy(proxy_process)
            if proxy_url is not None:
                ingested = ingest_mitm_capture(self.conn, capture_path)
                print(f"   [mitmproxy] {ingested}건 적재")

        merged = merge_and_normalize(raw)
        for item in merged:
            dbmod.upsert_endpoint(
                self.conn, origin_id=origin_id, method=item["method"],
                path=item["path"], normalized_path=item["normalized_path"],
                content_type=item.get("content_type"),
                source_tool=",".join(sorted(item["source_tools"])),
                is_excluded=item["is_excluded"], exclude_reason=item["exclude_reason"],
            )

        included = [e for e in merged if not e["is_excluded"]]
        print(f"   발견 {len(included)}건 (제외 {len(merged) - len(included)}건)")
