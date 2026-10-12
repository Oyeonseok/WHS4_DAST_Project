"""Run embedded Strix Recon and persist its observations in the shared Recon DB.

The embedded engine owns discovery.  This adapter owns the application
boundary: approved targets, canonical origins, durable evidence, and a native
fallback when the optional Docker runtime cannot start.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Sequence
from urllib.parse import urlsplit, urlunsplit

from aidast.pipeline.lifecycle import audit_event
from aidast.recon import db as dbmod
from aidast.recon.activity import activity_from_diagnostic
from aidast.recon.api_spec_ingestion import (
    _canonical_url,
    _matching_rule,
    ingest_llm_api_inventory,
)
from aidast.recon.judgment import merge_and_normalize
from aidast.recon.models import ReconTask
from aidast.recon.policy import TargetPolicy
from aidast.recon.strix_bridge import build_strix_proxy_rules, run_strix_recon
from aidast.recon.tools.mitm_proxy import ingest_mitm_capture
from aidast.scope.models import AssetType, ScopeAsset, ScopeDocument


def strix_model_name(model: str | None) -> str | None:
    """Route dashboard Codex model IDs through Strix's ChatGPT provider."""
    if model is None or not model.strip():
        return None
    value = model.strip()
    return value if "/" in value else f"chatgpt/{value}"


class StrixAccountingError(RuntimeError):
    """Strix traffic cannot be charged to the application-owned request ledger."""


class StrixReconExecutor:
    """ReconExecutor-compatible adapter for the embedded Strix runtime.

    ``fallback_factory`` is intentionally lazy.  Docker, provider, or sandbox
    startup failures therefore do not terminate an otherwise valid dashboard
    scan, while strict callers can omit the factory and receive the error.
    """

    def __init__(
        self,
        *,
        scan_id: str,
        scope_document: ScopeDocument,
        targets: Sequence[ScopeAsset],
        db_path: Path,
        capture_directory: Path,
        start_urls: dict[tuple[str, str], str] | None = None,
        request_headers: dict[str, str] | None = None,
        recon_model: str | None = None,
        target_policies: dict[tuple[str, str], TargetPolicy] | None = None,
        diagnostic_logs: bool = False,
        interactive_login: bool = False,
        fallback_factory: Callable[[], Any] | None = None,
    ) -> None:
        self.scan_id = scan_id
        self.scope_document = scope_document
        self.targets = list(targets)
        self.capture_directory = Path(capture_directory)
        self.start_urls = dict(start_urls or {})
        self.request_headers = dict(request_headers or {})
        self.recon_model = strix_model_name(recon_model)
        self.target_policies = dict(target_policies or {})
        self.diagnostic_logs = bool(diagnostic_logs)
        self.interactive_login = bool(interactive_login)
        self._fallback_factory = fallback_factory
        self._fallback = None
        self._host_governor_binding: dict[str, object] | None = None
        self.auth_session_files: list[tuple[str, Path, bool]] = []
        self.conn = dbmod.init_db(Path(db_path))
        dbmod.insert_scan(
            self.conn,
            scan_id=scan_id,
            scope_type="approved_scope",
            scope_value=scope_document.scope_id,
        )
        self._asset_ids: dict[tuple[str, str], str] = {}

    def close(self) -> None:
        if self._fallback is not None:
            self._fallback.close()
        self.conn.close()

    def _diagnostic(self, event: str, **details: object) -> None:
        activity = activity_from_diagnostic(event, details)
        if activity is not None:
            audit_event(
                self.conn,
                scan_id=self.scan_id,
                event_type="recon.activity",
                details=activity,
            )

    def _run_fallback(self, tasks: list[ReconTask], reason: BaseException | str) -> int:
        if self._fallback_factory is None:
            if isinstance(reason, BaseException):
                raise reason
            raise RuntimeError(reason)
        self._diagnostic(
            "phase_error",
            phase="mitm_capture",
            error_type=(type(reason).__name__ if isinstance(reason, BaseException) else "RuntimeError"),
        )
        error_type = type(reason).__name__ if isinstance(reason, BaseException) else "RuntimeError"
        try:
            from aidast.attack.store import _redact

            detail = str(_redact(str(reason))).replace("\n", " ").replace("\r", " ")[:500]
        except (TypeError, ValueError):
            detail = ""
        print(
            "Strix 정찰을 시작하지 못해 같은 승인 정책으로 기본 정찰 엔진을 실행합니다: "
            f"{error_type}" + (f": {detail}" if detail else ""),
            flush=True,
        )
        self._fallback = self._fallback_factory()
        failures = self._fallback.run(tasks)
        self.auth_session_files = list(
            getattr(self._fallback, "auth_session_files", [])
        )
        return failures

    def run(self, tasks: list[ReconTask]) -> int:
        # The native executor owns the operator-controlled browser/HITL path.
        # Running Strix first would open a separate sandbox session that cannot
        # consume that login, so route this explicit mode directly.
        if self.interactive_login:
            return self._run_fallback(tasks, "runtime-browser login requires the native session adapter")

        self._diagnostic("phase_started", phase="mitm_capture")
        try:
            _result, capture_file, rules = asyncio.run(
                run_strix_recon(
                    self.scope_document,
                    self.targets,
                    scan_id=self.scan_id,
                    capture_directory=self.capture_directory,
                    start_urls=self.start_urls,
                    request_headers=self.request_headers,
                    model=self.recon_model,
                    execution_limits=self._execution_limits(),
                    diagnostic_logs=self.diagnostic_logs,
                )
            )
            captured, blocked, endpoint_count, inventory = self._ingest_strix_artifacts(
                capture_file, rules,
            )
            if endpoint_count == 0:
                return self._run_fallback(tasks, "Strix completed without an in-scope endpoint")
            print(
                "Strix Recon 적재 완료: "
                f"캡처 {captured}건, 차단 {blocked}건, 엔드포인트 {endpoint_count}개, "
                f"API 명세 {inventory.get('endpoints', 0)}개",
                flush=True,
            )
            return 0
        except (KeyboardInterrupt, SystemExit):
            raise
        except StrixAccountingError:
            raise
        except Exception as exc:  # optional runtime failures use the native path
            # A provider stream can fail after the governed runtime already
            # collected useful responses.  Preserve those verified partial
            # observations and charge their request ledger before continuing
            # with the native executor.  Failure to account forwarded traffic
            # remains fatal; malformed optional artifacts do not replace the
            # original recoverable Strix error.
            capture_file = self.capture_directory / "mitm_capture.jsonl"
            if capture_file.is_file() and capture_file.stat().st_size:
                try:
                    rules = build_strix_proxy_rules(
                        self.scope_document,
                        self.targets,
                        request_headers=self.request_headers,
                        execution_limits=self._execution_limits(),
                    )
                    captured, blocked, endpoints, inventory = self._ingest_strix_artifacts(
                        capture_file, rules,
                    )
                    print(
                        "중단 전 Strix 정찰 결과를 보존했습니다: "
                        f"캡처 {captured}건, 차단 {blocked}건, "
                        f"엔드포인트 {endpoints}개, API 명세 {inventory.get('endpoints', 0)}개",
                        flush=True,
                    )
                except StrixAccountingError:
                    raise
                except (OSError, ValueError, TypeError, sqlite3.Error, json.JSONDecodeError) as partial_exc:
                    print(
                        "중단된 Strix 부분 결과를 적재하지 못했습니다: "
                        f"{type(partial_exc).__name__}",
                        flush=True,
                    )
            return self._run_fallback(tasks, exc)

    def _ingest_strix_artifacts(
        self, capture_file: Path, rules: dict[str, object],
    ) -> tuple[int, int, int, dict[str, object]]:
        """Persist governed Strix output for both complete and partial runs."""
        self._merge_request_governor_ledger(capture_file)
        captured, blocked, endpoint_count = self._ingest_capture(capture_file, rules)
        inventory = ingest_llm_api_inventory(
            self.conn,
            scan_id=self.scan_id,
            inventory_path=self.capture_directory / "openapi_llm_inventory.json",
            rules=rules,
        )
        endpoint_count += int(inventory.get("endpoints", 0))
        self._diagnostic(
            "proxy_capture_ingested",
            count=captured,
            blocked_count=blocked,
        )
        return captured, blocked, endpoint_count, inventory

    def _execution_limits(self) -> dict[str, object]:
        policies = list(self.target_policies.values())
        if not policies:
            return {"max_requests": 3000, "budget_total": 3000}
        maximum = min(policy.limits.max_requests for policy in policies)
        timeout = min(policy.limits.timeout_seconds for policy in policies)
        result: dict[str, object] = {
            "max_requests": maximum,
            "budget_total": maximum,
            "timeout_seconds": timeout,
        }
        governors = [policy.request_governor for policy in policies if policy.request_governor]
        if governors:
            binding = governors[0].model_dump(mode="json")
            self._host_governor_binding = binding
            sandbox_binding = dict(binding)
            sandbox_binding["ledger_path"] = "/workspace/aidast-capture/request_governor.db"
            result["request_governor"] = sandbox_binding
            result["requests_per_second"] = binding["requests_per_second"]
        return result

    def _merge_request_governor_ledger(self, capture_file: Path) -> None:
        binding = self._host_governor_binding
        if binding is None:
            return
        source_path = self.capture_directory / "request_governor.db"
        if not source_path.is_file():
            try:
                has_forwarded_request = False
                with capture_file.open(encoding="utf-8") as stream:
                    for line in stream:
                        if not line.strip():
                            continue
                        record = json.loads(line)
                        if isinstance(record, dict) and record.get("policy_blocked") is not True:
                            has_forwarded_request = True
                            break
            except (OSError, UnicodeError, json.JSONDecodeError):
                has_forwarded_request = True
            if not has_forwarded_request:
                return
            raise StrixAccountingError("Strix request ledger was not produced")
        destination_path = Path(str(binding["ledger_path"]))
        destination_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            with sqlite3.connect(source_path) as source:
                scan_rows = source.execute(
                    "SELECT program,scan,started,configuration,last_dispatch FROM governor_scans"
                ).fetchall()
                request_rows = source.execute(
                    "SELECT id,program,scan,origin,units,capacity,charged,expires,state "
                    "FROM governor_requests"
                ).fetchall()
            with sqlite3.connect(destination_path, timeout=30) as destination:
                destination.execute("BEGIN IMMEDIATE")
                destination.execute(
                    "CREATE TABLE IF NOT EXISTS governor_scans "
                    "(program TEXT, scan TEXT, started REAL NOT NULL, configuration TEXT NOT NULL, "
                    "last_dispatch REAL, PRIMARY KEY(program,scan))"
                )
                destination.execute(
                    "CREATE TABLE IF NOT EXISTS governor_requests "
                    "(id TEXT PRIMARY KEY, program TEXT NOT NULL, scan TEXT NOT NULL, "
                    "origin TEXT NOT NULL, units INTEGER NOT NULL, capacity INTEGER NOT NULL, "
                    "charged REAL NOT NULL, expires REAL NOT NULL, state TEXT NOT NULL)"
                )
                destination.execute(
                    "CREATE INDEX IF NOT EXISTS governor_requests_scope "
                    "ON governor_requests(program,scan,charged)"
                )
                for row in scan_rows:
                    existing = destination.execute(
                        "SELECT configuration,last_dispatch FROM governor_scans "
                        "WHERE program=? AND scan=?",
                        row[:2],
                    ).fetchone()
                    if existing is not None and existing[0] != row[3]:
                        raise StrixAccountingError("request governor binding changed")
                    destination.execute(
                        "INSERT OR IGNORE INTO governor_scans VALUES (?,?,?,?,?)", row,
                    )
                    if existing is not None and row[4] is not None:
                        destination.execute(
                            "UPDATE governor_scans SET last_dispatch=max(coalesce(last_dispatch,0),?) "
                            "WHERE program=? AND scan=?",
                            (row[4], row[0], row[1]),
                        )
                destination.executemany(
                    "INSERT OR IGNORE INTO governor_requests VALUES (?,?,?,?,?,?,?,?,?)",
                    request_rows,
                )
        except (OSError, sqlite3.Error, KeyError, TypeError) as exc:
            raise StrixAccountingError("Strix request accounting could not be synchronized") from exc

    def _asset_for_url(self, url: str) -> ScopeAsset | None:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        for target in self.targets:
            raw = target.asset.strip()
            candidate = urlsplit(raw if "://" in raw else "https://" + raw)
            pattern = (candidate.hostname or "").lower().rstrip(".")
            if target.asset_type is AssetType.WILDCARD:
                if pattern.startswith("*.") and host.endswith(pattern[1:]) and host != pattern[2:]:
                    return target
            elif host == pattern:
                return target
        return None

    def _asset_id(self, target: ScopeAsset) -> str:
        key = (target.asset_type.value, target.asset)
        asset_id = self._asset_ids.get(key)
        if asset_id is None:
            row = self.conn.execute(
                "SELECT asset_id FROM assets WHERE scan_id=? AND asset_type=? AND identifier=? "
                "ORDER BY discovered_at LIMIT 1",
                (self.scan_id, *key),
            ).fetchone()
            asset_id = str(row[0]) if row else dbmod.insert_asset(
                self.conn,
                scan_id=self.scan_id,
                identifier=target.asset,
                asset_type=target.asset_type.value,
            )
            self._asset_ids[key] = asset_id
        return asset_id

    def _origin_for_record(self, record: dict[str, Any], rules: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
        method = str(record.get("method") or "GET").upper()
        url = record.get("url")
        if not isinstance(url, str):
            return None
        canonical = _canonical_url(url, rules)
        if _matching_rule(canonical, method, rules, allow_query=True) is None:
            return None
        parsed = urlsplit(canonical)
        target = self._asset_for_url(canonical)
        if target is None or not parsed.hostname:
            return None
        scheme = parsed.scheme.lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        host = parsed.hostname.lower().rstrip(".")
        default_port = 443 if scheme == "https" else 80
        netloc = f"[{host}]" if ":" in host else host
        if port != default_port:
            netloc += f":{port}"
        base_url = urlunsplit((scheme, netloc, "", "", ""))
        origin_id = dbmod.upsert_origin(
            self.conn,
            asset_id=self._asset_id(target),
            scheme=scheme,
            host=host,
            port=port,
            base_url=base_url,
            http_probe_status=(
                record.get("response_status")
                if type(record.get("response_status")) is int else None
            ),
            main_crawler_mode="strix",
        )
        normalized = dict(record)
        normalized["url"] = canonical
        normalized["method"] = method
        return origin_id, normalized

    def _ingest_capture(self, capture_file: Path, rules: dict[str, Any]) -> tuple[int, int, int]:
        if not capture_file.is_file():
            return 0, 0, 0
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        blocked = 0
        with capture_file.open(encoding="utf-8") as stream:
            for line in stream:
                try:
                    record = json.loads(line)
                except (json.JSONDecodeError, UnicodeError):
                    continue
                if not isinstance(record, dict):
                    continue
                if record.get("policy_blocked") is True:
                    blocked += 1
                    continue
                if record.get("browser_support") == "passive":
                    continue
                resolved = self._origin_for_record(record, rules)
                if resolved is None:
                    blocked += 1
                    continue
                origin_id, normalized = resolved
                groups[origin_id].append(normalized)

        endpoint_ids: set[str] = set()
        captured = 0
        temporary_root = self.capture_directory / ".ingest"
        temporary_root.mkdir(parents=True, exist_ok=True)
        try:
            for origin_id, records in groups.items():
                raw = []
                for record in records:
                    parsed = urlsplit(str(record["url"]))
                    raw.append({
                        "method": record["method"],
                        "path": parsed.path or "/",
                        "url": record["url"],
                        "content_type": record.get("content_type"),
                        "source": "strix_mitmproxy",
                        "evidence": {"response_status": record.get("response_status")},
                    })
                for endpoint in merge_and_normalize(raw):
                    endpoint_id = dbmod.upsert_endpoint(
                        self.conn,
                        origin_id=origin_id,
                        method=endpoint["method"],
                        path=endpoint["path"],
                        normalized_path=endpoint["normalized_path"],
                        query_signature=endpoint["query_signature"],
                        content_type=endpoint.get("content_type"),
                        source_tool="strix_mitmproxy",
                        is_excluded=endpoint["is_excluded"],
                        exclude_reason=endpoint["exclude_reason"],
                        verification_status=endpoint["verification_status"],
                    )
                    if not endpoint["is_excluded"]:
                        endpoint_ids.add(endpoint_id)
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    encoding="utf-8",
                    suffix=".jsonl",
                    dir=temporary_root,
                    delete=False,
                ) as output:
                    grouped_path = Path(output.name)
                    for record in records:
                        output.write(json.dumps(record, ensure_ascii=False) + "\n")
                count, newly_blocked = ingest_mitm_capture(
                    self.conn, grouped_path, origin_id=origin_id,
                )
                captured += count
                blocked += newly_blocked
                self._reconcile_passive_declarations(origin_id)
                for record in records:
                    self._diagnostic(
                        "url_discovered",
                        method=record["method"],
                        url=record["url"],
                        source="strix_mitmproxy",
                        response_status=record.get("response_status"),
                    )
        finally:
            capture_file.unlink(missing_ok=True)
            try:
                temporary_root.rmdir()
            except OSError:
                pass
        return captured, blocked, len(endpoint_ids)

    def _reconcile_passive_declarations(self, origin_id: str) -> int:
        """Apply the native value-free declaration parser to Strix captures."""
        origin = self.conn.execute(
            "SELECT base_url FROM origins WHERE origin_id=?", (origin_id,),
        ).fetchone()
        if origin is None:
            return 0
        base_url = str(origin[0])
        target = self._asset_for_url(base_url)
        policy = (
            self.target_policies.get((target.asset_type.value, target.asset))
            if target is not None else None
        )
        captured = self.conn.execute(
            """SELECT url,content_type,response_body FROM http_transactions
               WHERE origin_id=? AND method='GET'
                 AND response_status BETWEEN 200 AND 299
                 AND response_body IS NOT NULL ORDER BY captured_at""",
            (origin_id,),
        ).fetchall()
        from aidast.recon.annotations import ObservationRecorder
        from aidast.recon.tools.passive_declarations import (
            declarations_from_captured_responses,
        )

        declarations = declarations_from_captured_responses(
            captured, base_url=base_url, target_policy=policy, limit=500,
        )
        if declarations:
            ObservationRecorder(
                self.conn, origin_id=origin_id, scan_id=self.scan_id, agent=None,
            ).record("passive_reconciliation", declarations)
        self._diagnostic(
            "passive_reconciliation", origin=base_url,
            declaration_count=len(declarations),
        )
        return len(declarations)
