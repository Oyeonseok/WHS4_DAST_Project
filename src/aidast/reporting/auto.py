"""Draft reports for current confirmed cases after an integrated scan."""

from __future__ import annotations

import hashlib
import re
import sqlite3
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import closing
from contextvars import copy_context
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from aidast.agents.main import CodexMainAgent, CodexReportWriter
from aidast.pipeline.lifecycle import audit_event, finish_stage_run, start_stage_run

from .runtime import (
    PLATFORMS, ReportAgent, ReportDraftError, ReportError, ReportWriter,
    ReportWriterError, _path,
)
from .scan_summary import write_scan_summary


class ScanReportResults(list[dict]):
    """Successful drafts plus explicit batch diagnostics and summary artifacts."""

    def __init__(self) -> None:
        super().__init__()
        self.errors: list[dict] = []
        self.summary: dict = {}


_REPORT_MODEL_WORKERS = 3


@dataclass(frozen=True)
class _DraftWork:
    case_id: str
    language: str | None
    prepared: dict
    future: Future[dict] | None


def _generate_draft(agent: ReportAgent, prepared: dict, *, case_id: str, platform: str) -> dict:
    """Generate one draft with the existing bounded source-hash retry."""
    for attempt in range(3):
        try:
            return agent.draft(prepared, case_id=case_id, platform=platform)
        except ReportDraftError as exc:
            if (
                str(exc) != "draft source context hash does not match prepared report"
                or attempt == 2
            ):
                raise
    raise AssertionError("unreachable report retry state")


def report_platform_for_program_url(program_url: str) -> str:
    """Select a known platform template, otherwise use the general report."""
    host = (urlsplit(program_url).hostname or "").casefold().removeprefix("www.")
    for platform, domain in (
        ("hackerone", "hackerone.com"),
        ("bugcrowd", "bugcrowd.com"),
        ("intigriti", "intigriti.com"),
    ):
        if host == domain or host.endswith("." + domain):
            return platform
    return "generic"


def _case_directory(case_id: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_-]{1,128}", case_id):
        return case_id
    return "case_" + hashlib.sha256(case_id.encode("utf-8")).hexdigest()


def generate_scan_reports(
    pipeline_db: Path,
    output_root: Path,
    *,
    scan_id: str,
    platform: str = "generic",
    writer: ReportWriter | None = None,
    language: str | None = None,
    model: str | None = None,
) -> ScanReportResults:
    """Draft verified findings independently and always publish an execution report.

    Writer failures leave prepared, source-bound artifacts available for a
    retry. Input, authorization, integrity, and persistence failures still stop
    the batch. The returned list contains only successful drafts; ``errors``
    and ``summary`` expose partial completion without claiming success.
    """
    if platform not in PLATFORMS:
        raise ReportError("automatic reports require a supported program platform")
    if language is not None and (language not in {"ko", "en"} or platform != "generic"):
        raise ReportError("language selection requires ko or en and generic reports")
    pipeline_db = _path(pipeline_db, existing=True)
    output_root = _path(output_root)
    with closing(sqlite3.connect(pipeline_db)) as conn:
        if conn.execute("SELECT 1 FROM scans WHERE scan_id=?", (scan_id,)).fetchone() is None:
            raise ReportError("automatic reports require an existing scan")
        cases = [row[0] for row in conn.execute(
            """SELECT case_id FROM validation_cases
            WHERE scan_id=? AND current_status='CONFIRMED'
            AND processing_phase='completed'
            AND decision_stage_run_id=latest_stage_run_id
            ORDER BY case_id""",
            (scan_id,),
        )]
        stage_run_id = start_stage_run(conn, scan_id=scan_id, stage="report")

    results = ScanReportResults()
    languages = ("ko", "en") if platform == "generic" and language is None else (language,)
    try:
        agent = ReportAgent(
            writer or CodexReportWriter(
                CodexMainAgent(main_model=model or "gpt-6-sol")
            )
        ) if cases else None
        work: list[_DraftWork] = []
        # Preparation and publication remain deterministic.  Only independent
        # writer/model calls run concurrently; each worker receives its own
        # ContextVar snapshot so model-call correlation and sinks are retained.
        with ThreadPoolExecutor(max_workers=_REPORT_MODEL_WORKERS,
                                thread_name_prefix="aidast-report") as executor:
            preparation_error: BaseException | None = None
            try:
                for case_id in cases:
                    for locale in languages:
                        output_dir = output_root / ("en" if platform == "generic" and locale == "en" else "") / _case_directory(case_id)
                        prepared = agent.prepare(
                            pipeline_db,
                            output_dir,
                            platform=platform,
                            case_id=case_id,
                            language=locale,
                        )
                        future = None
                        if prepared.get("status") != "drafted":
                            context = copy_context()
                            future = executor.submit(
                                context.run,
                                _generate_draft,
                                agent,
                                prepared,
                                case_id=case_id,
                                platform=platform,
                            )
                        work.append(_DraftWork(case_id, locale, prepared, future))
            except BaseException as exc:
                # Preserve work preceding a later corrupt input, matching the
                # previous sequential failure boundary.
                preparation_error = exc

            from .case_runtime import record_case_report

            # Joining in input order makes result, audit, and database updates
            # stable even when model calls finish in a different order.
            for item in work:
                try:
                    result = item.prepared
                    if item.future is not None:
                        draft = item.future.result()
                        result = record_case_report(Path(item.prepared["report_db"]), draft)
                    if result.get("status") != "drafted":
                        raise ReportError(
                            f"report draft was not completed for case {item.case_id} "
                            f"({item.language or platform})"
                        )
                    results.append(result)
                except (ReportWriterError, ReportDraftError) as exc:
                    issue = {"stage": "report", "case_id": item.case_id,
                             "language": item.language,
                             "error_type": exc.cause_type if isinstance(exc, ReportWriterError) else "InvalidReportDraft"}
                    results.errors.append(issue)
                    with closing(sqlite3.connect(pipeline_db)) as conn:
                        audit_event(conn, scan_id=scan_id, stage_run_id=stage_run_id,
                                    event_type="report.draft_failed", details=issue)
            if preparation_error is not None:
                raise preparation_error
    except BaseException as exc:
        with closing(sqlite3.connect(pipeline_db)) as conn:
            finish_stage_run(conn, stage_run_id,
                             status="cancelled" if isinstance(exc, (KeyboardInterrupt, SystemExit)) else "failed",
                             error_message=type(exc).__name__)
        write_scan_summary(pipeline_db, output_root, scan_id=scan_id, report_results=results,
                           errors=[*results.errors, {"stage": "report", "error_type": type(exc).__name__}])
        raise
    with closing(sqlite3.connect(pipeline_db)) as conn:
        finish_stage_run(conn, stage_run_id,
                         status="failed" if results.errors else "completed" if cases else "skipped",
                         error_message=f"{len(results.errors)} report drafts failed" if results.errors else None)
    results.summary = write_scan_summary(pipeline_db, output_root, scan_id=scan_id,
                                        report_results=results, errors=results.errors)
    return results
