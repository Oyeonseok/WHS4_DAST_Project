"""Persist the embedded Strix proxy capture into the current Recon contract."""

from __future__ import annotations

import asyncio
import ipaddress
import json
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit, urlunsplit

from aidast.pipeline.lifecycle import finish_stage_run, start_stage_run
from aidast.recon import db as dbmod
from aidast.recon.api_spec_ingestion import ingest_llm_api_inventory
from aidast.recon.executor import ReconExecutionError
from aidast.recon.surface import export_surface
from aidast.recon.tools.mitm_proxy import ingest_mitm_capture
from aidast.recon.strix_bridge import run_strix_recon


def _matches_rule(url: str, method: str, rule: dict) -> bool:
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except (TypeError, ValueError):
        return False
    path = parsed.path or "/"
    return (
        parsed.username is None and parsed.password is None
        and parsed.scheme in rule["schemes"]
        and fnmatchcase(host, rule["host_pattern"].lower())
        and ("*" in rule["ports"] or port in rule["ports"])
        and method in rule["methods"]
        and any(path == prefix.rstrip("/") or prefix == "/"
                or path.startswith(prefix.rstrip("/") + "/")
                for prefix in rule["paths"])
    )


def _canonical_url(url: str, rules: dict) -> str:
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except (TypeError, ValueError):
        return url
    alias = next((item for item in rules.get("loopback_host_aliases", [])
                  if item["host"] == host and item["port"] == port), None)
    if alias is None:
        return url
    canonical_host = str(alias["canonical_host"])
    canonical_port = int(alias["canonical_port"])
    authority = f"[{canonical_host}]" if ":" in canonical_host else canonical_host
    if canonical_port != (443 if parsed.scheme == "https" else 80):
        authority += f":{canonical_port}"
    return urlunsplit(parsed._replace(netloc=authority))


def persist_strix_capture(
    *, scan_id: str, scope_id: str, capture_path: Path,
    db_path: Path, surface_path: Path, rules: dict,
    manage_lifecycle: bool = True,
) -> dict[str, int]:
    """Ingest only positively approved proxy records, then export Surface.json."""
    conn = dbmod.init_db(db_path)
    dbmod.insert_scan(conn, scan_id=scan_id, scope_type="approved_scope", scope_value=scope_id)
    stage_run_id = (
        start_stage_run(conn, scan_id=scan_id, stage="recon")
        if manage_lifecycle else None
    )
    origin_cache: dict[tuple[str, str, int], str] = {}

    def permitted(url: str, method: str) -> bool:
        try:
            host = (urlsplit(url).hostname or "").lower().rstrip(".")
        except (TypeError, ValueError):
            return False
        return (
            any(_matches_rule(url, method, rule) for rule in rules["target_rules"])
            and not any(fnmatchcase(host, pattern.lower())
                        for pattern in rules.get("excluded_hosts", []))
            and not any(_matches_rule(url, method, rule)
                        for rule in rules.get("excluded_target_rules", []))
        )

    def origin_for_record(record: dict) -> str | None:
        url = record.get("url")
        method = str(record.get("method") or "").upper()
        if not isinstance(url, str) or not permitted(url, method):
            return None
        canonical = _canonical_url(url, rules)
        parsed = urlsplit(canonical)
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        record["url"] = canonical
        permitted_forms = []
        for form in record.get("discovered_forms", []):
            if isinstance(form, dict) and isinstance(form.get("action"), str):
                action = _canonical_url(form["action"], rules)
                if permitted(action, str(form.get("method") or "GET").upper()):
                    form["action"] = action
                    permitted_forms.append(form)
        record["discovered_forms"] = permitted_forms
        key = (parsed.scheme, host, port)
        if key in origin_cache:
            return origin_cache[key]
        try:
            ipaddress.ip_address(host)
            asset_type = "IP_ADDRESS"
        except ValueError:
            asset_type = "DOMAIN"
        asset_id = dbmod.insert_asset(
            conn, scan_id=scan_id, identifier=host, asset_type=asset_type,
        )
        base_url = f"{parsed.scheme}://{host}"
        if port != (443 if parsed.scheme == "https" else 80):
            base_url += f":{port}"
        origin_id = dbmod.upsert_origin(
            conn, asset_id=asset_id, scheme=parsed.scheme, host=host,
            port=port, base_url=base_url,
            http_probe_status=record.get("response_status"),
            main_crawler_mode="strix",
        )
        origin_cache[key] = origin_id
        return origin_id

    try:
        if not capture_path.is_file():
            raise FileNotFoundError(f"Strix proxy capture was not written: {capture_path}")
        observed, blocked = ingest_mitm_capture(
            conn, capture_path, origin_resolver=origin_for_record,
            preserve_capture=True, require_origin=True,
        )
        inventory = ingest_llm_api_inventory(
            conn, scan_id=scan_id,
            inventory_path=capture_path.parent / "openapi_llm_inventory.json",
            rules=rules,
        )
        endpoint_count = conn.execute(
            """SELECT COUNT(*) FROM endpoints e JOIN origins o ON o.origin_id=e.origin_id
               JOIN assets a ON a.asset_id=o.asset_id WHERE a.scan_id=? AND e.is_excluded=0""",
            (scan_id,),
        ).fetchone()[0]
        conn.commit()
        if manage_lifecycle:
            conn.execute(
                "UPDATE scans SET status='completed', finished_at=CURRENT_TIMESTAMP WHERE scan_id=?",
                (scan_id,),
            )
            conn.commit()
            export_surface(conn, scan_id=scan_id, output_path=surface_path)
            finish_stage_run(conn, stage_run_id, status="completed")
        return {
            "observed": observed, "blocked": blocked, "endpoints": endpoint_count,
            "api_endpoints": int(inventory["endpoints"]),
        }
    except BaseException as exc:
        conn.rollback()
        if manage_lifecycle:
            conn.execute(
                "UPDATE scans SET status='failed', finished_at=CURRENT_TIMESTAMP WHERE scan_id=?",
                (scan_id,),
            )
            conn.commit()
            finish_stage_run(conn, stage_run_id, status="failed", error_message=str(exc))
        raise
    finally:
        conn.close()


class StrixReconExecutor:
    """Expose Strix capture through the current standalone Recon lifecycle."""

    def __init__(
        self, *, scan_id: str, scope_document, selected_targets,
        target_policies, start_urls, request_headers, db_path: Path,
        surface_path: Path, capture_directory: Path,
        diagnostic_logs: bool,
        recon_model: str | None = None,
        progress_callback: Callable[[int, str], None] | None = None,
        allow_lab_account_creation: bool = False,
        allow_lab_state_changing_discovery: bool = False,
        allow_authorized_account_registration: bool = False,
    ) -> None:
        self.scan_id = scan_id
        self.scope_document = scope_document
        self.selected_targets = selected_targets
        self.target_policies = target_policies
        self.start_urls = start_urls
        self.request_headers = request_headers
        self.db_path = db_path
        self.surface_path = surface_path
        self.capture_directory = capture_directory
        self.diagnostic_logs = diagnostic_logs
        self.recon_model = recon_model
        self.progress_callback = progress_callback
        self.allow_lab_account_creation = allow_lab_account_creation
        self.allow_lab_state_changing_discovery = allow_lab_state_changing_discovery
        self.allow_authorized_account_registration = allow_authorized_account_registration
        self.auth_session_files: list = []
        self.conn = dbmod.init_db(db_path)
        dbmod.insert_scan(
            self.conn, scan_id=scan_id, scope_type="approved_scope",
            scope_value=scope_document.scope_id,
        )

    def run(self, _tasks) -> int:
        try:
            result, capture_path, rules = asyncio.run(run_strix_recon(
                self.scope_document, self.selected_targets,
                scan_id=self.scan_id, capture_directory=self.capture_directory,
                start_urls=self.start_urls, request_headers=self.request_headers,
                user_instructions=(
                    "Perform surface discovery only. Do not test or exploit vulnerabilities. "
                    "Do not access out-of-scope assets. Preserve broad endpoint and parameter coverage. "
                    + (
                        "First discover read-only across the selected targets. Then, only where observed "
                        "login gates or protected routes make it valuable and a clear self-service signup "
                        "exists, the root agent may create at most one disposable low-privilege account "
                        "per exact canonical in-scope origin. Never register on wildcard-derived or linked "
                        "hosts; do not perform business transactions or destructive actions."
                        if self.allow_authorized_account_registration else (
                            "On this explicitly approved local lab, inspect the login/signup UI even if no "
                            "401/403 occurs. If self-service signup is present, create exactly one disposable "
                            "low-privilege account and log in immediately to discover authenticated routes; "
                            "record why if unavailable. "
                            + (
                                "Then validate disclosed state-changing endpoint operations once each using "
                                "their observed method/schema and synthetic data belonging only to that account. "
                                "Do not fuzz or touch another identity; no external payment/provider calls."
                                if self.allow_lab_state_changing_discovery else
                                "Do not perform business transactions."
                            )
                            if (self.allow_lab_account_creation or self.allow_lab_state_changing_discovery)
                            else "Do not submit forms or perform state-changing actions."
                        )
                    )
                ),
                diagnostic_logs=self.diagnostic_logs,
                allow_lab_account_creation=self.allow_lab_account_creation,
                allow_lab_state_changing_discovery=self.allow_lab_state_changing_discovery,
                allow_authorized_account_registration=self.allow_authorized_account_registration,
                model=self.recon_model,
                progress_callback=self.progress_callback,
            ))
            if result is None:
                raise ValueError("Strix Recon stopped before completion")
            final = getattr(result, "final_output", None)
            if isinstance(final, str):
                try:
                    final = json.loads(final)
                except ValueError:
                    final = None
            if isinstance(final, dict) and final.get("recon_blocked"):
                raise ValueError(str(final.get("error") or "Strix Recon coverage is incomplete"))
            counts = persist_strix_capture(
                scan_id=self.scan_id, scope_id=self.scope_document.scope_id,
                capture_path=capture_path, db_path=self.db_path,
                surface_path=self.surface_path, rules=rules,
                manage_lifecycle=False,
            )
            if counts["endpoints"] == 0:
                raise ValueError("Strix Recon produced no approved endpoints")
        except Exception as exc:
            raise ReconExecutionError(f"Strix Recon failed: {type(exc).__name__}: {exc}") from exc
        print(
            f"Strix Recon capture: {capture_path}; "
            f"observations={counts['observed']}, blocked={counts['blocked']}, "
            f"endpoints={counts['endpoints']}"
        )
        return 0

    def close(self) -> None:
        self.conn.close()
