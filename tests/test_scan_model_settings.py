"""Model persistence survives restarts while resume retains evidence boundaries."""

import json
import os
import sqlite3
from argparse import Namespace
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, call, patch

import pytest

import test_scan_resume as resume_fixture
import test_shared_validation_reporting as report_fixture
from aidast.cli import _run_resume, main
from aidast.pipeline.lifecycle import finish_stage_run, start_stage_run
from aidast.pipeline.model_settings import (
    MAX_SETTINGS_BYTES, MODEL_SETTINGS_FILE, ScanModelChoices,
    load_scan_model_choices, read_scan_model_choices, scan_model_settings_path,
    write_scan_model_choices,
)
from aidast.pipeline.resume import ResumePlan, execute_resume, inspect_resume
from aidast.reporting.scan_summary import write_scan_summary
from aidast.web.reports import ReportCatalog


def choices() -> ScanModelChoices:
    return ScanModelChoices.resolve(recon_model="gpt-6.1-sol", attack_model="gpt-6-luna",
                                   validation_model="gpt-6-astra", report_model="gpt-6-sol")


def test_effective_choices_are_private_immutable_and_bound_to_one_scan(tmp_path):
    models = choices()
    path = scan_model_settings_path(tmp_path, "scan_one")
    write_scan_model_choices(path, scan_id="scan_one", models=models)
    before = path.read_bytes()
    assert load_scan_model_choices(tmp_path, "scan_one") == models
    assert load_scan_model_choices(tmp_path, "scan_two") is None
    assert models.main_model == models.recon_model
    assert models.chaining_model == models.attack_model
    assert set(json.loads(before)["models"]) == {
        "main_model", "recon_model", "attack_model", "chaining_model", "validation_model", "report_model"}
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600
    assert write_scan_model_choices(path, scan_id="scan_one", models=models) == path.resolve()
    assert path.read_bytes() == before
    unsafe = models.model_copy(update={"report_model": "--sandbox none"})
    with pytest.raises(ValueError):
        write_scan_model_choices(tmp_path / "unsafe.json", scan_id="scan_one", models=unsafe)
    assert not (tmp_path / "unsafe.json").exists()
    with pytest.raises(ValueError, match="cannot be changed"):
        write_scan_model_choices(path, scan_id="scan_one",
                                 models=models.model_copy(update={"report_model": "gpt-6.1-sol"}))
    with pytest.raises(ValueError, match="different scan"):
        read_scan_model_choices(path, scan_id="scan_two")
    assert path.read_bytes() == before


@pytest.mark.parametrize("name", ["--model", "gpt-6-sol --sandbox=none", "https://model.example/api", "$(command)", "", "a" * 129])
def test_model_settings_reject_command_fragments_urls_and_unbounded_identifiers(name):
    with pytest.raises(ValueError):
        ScanModelChoices.resolve(recon_model=name)


@pytest.mark.parametrize("damage", ["oversized", "extra_secret", "wrong_scan", "non_object", "invalid_model"])
def test_bad_saved_settings_are_rejected_instead_of_silent_defaults(tmp_path, damage):
    path = scan_model_settings_path(tmp_path, "scan_one")
    write_scan_model_choices(path, scan_id="scan_one", models=choices())
    document = json.loads(path.read_text())
    if damage == "oversized":
        path.write_bytes(b" " * (MAX_SETTINGS_BYTES + 1))
    else:
        if damage == "extra_secret": document["api_key"] = "private-key"
        elif damage == "wrong_scan": document["scan_id"] = "scan_two"
        elif damage == "non_object": document = []
        else: document["models"]["attack_model"] = "--unsafe"
        path.write_text(json.dumps(document))
    with pytest.raises(ValueError) as error:
        load_scan_model_choices(tmp_path, "scan_one")
    assert "private-key" not in str(error.value)


def test_model_settings_reject_symlinked_files_and_directories(tmp_path):
    source = write_scan_model_choices(tmp_path / "original.json", scan_id="scan_one", models=choices())
    linked = tmp_path / "linked.json"
    linked.symlink_to(source)
    with pytest.raises(ValueError, match="symlinks"):
        read_scan_model_choices(linked, scan_id="scan_one")
    webui = tmp_path / ".webui"
    webui.symlink_to(tmp_path / "outside", target_is_directory=True)
    with pytest.raises(ValueError, match="symlinks"):
        load_scan_model_choices(tmp_path, "scan_one")
    with pytest.raises(ValueError, match="invalid scan identifier"):
        scan_model_settings_path(tmp_path, "../outside")


def test_resume_reloads_verified_choices_after_process_restart(tmp_path):
    models = choices()
    resume_fixture._fixture(tmp_path, grouped=True, models=models)
    plan = inspect_resume(tmp_path, resume_fixture.SCAN_ID)
    assert plan.models == models
    assert plan.program_url == "https://hackerone.com/example"
    # A changed application default cannot replace choices already saved.
    with patch("aidast.agents.native_pipeline.CodexMainAgent.DEFAULT_ATTACK_MODEL", "new-default"):
        assert inspect_resume(tmp_path, resume_fixture.SCAN_ID).models.attack_model == "gpt-6-luna"


@pytest.mark.parametrize("damage", ["hashed_file_changed", "private_record_changed", "hashed_file_missing"])
def test_resume_model_configuration_must_match_handoff_and_private_record(tmp_path, damage):
    resume_fixture._fixture(tmp_path, models=choices())
    record = tmp_path / "Runs" / resume_fixture.SCAN_ID / MODEL_SETTINGS_FILE
    if damage == "hashed_file_changed":
        record.write_text(record.read_text() + "\n")
    elif damage == "hashed_file_missing":
        record.unlink()
    else:
        record = scan_model_settings_path(tmp_path, resume_fixture.SCAN_ID)
        data = json.loads(record.read_text())
        data["models"]["report_model"] = "gpt-6.1-sol"
        record.write_text(json.dumps(data))
    with pytest.raises((ValueError, FileNotFoundError)):
        inspect_resume(tmp_path, resume_fixture.SCAN_ID)


def test_legacy_resume_without_model_record_keeps_documented_defaults(tmp_path):
    resume_fixture._fixture(tmp_path)
    plan = inspect_resume(tmp_path, resume_fixture.SCAN_ID)
    assert plan.models == ScanModelChoices.resolve()
    assert load_scan_model_choices(tmp_path, resume_fixture.SCAN_ID) is None


def test_resume_passes_saved_models_to_agent_and_validation(tmp_path):
    resume_fixture._fixture(tmp_path, models=choices())
    plan = inspect_resume(tmp_path, resume_fixture.SCAN_ID)
    factory = Mock()
    with patch("aidast.agents.main.CodexMainAgent") as agent, patch(
        "aidast.orchestration.attack.AttackCoordinator"
    ) as attack, patch("aidast.orchestration.chaining.ChainingCoordinator") as chaining:
        execution_agent, planning_agent = Mock(), Mock()
        agent.side_effect = [execution_agent, planning_agent]
        execute_resume(plan, validation_factory=factory)
    assert agent.call_args_list == [
        call(**plan.models.agent_options()),
        call(main_model=plan.models.attack_model),
    ]
    assert attack.call_args.kwargs["agent"] is execution_agent
    assert attack.call_args.kwargs["planning_agent"] is planning_agent
    assert chaining.call_args.kwargs["agent"] is execution_agent
    assert factory.call_args.kwargs["validation_model"] == plan.models.validation_model
    factory.return_value.run.assert_called_once_with(plan.scan_id)

    factory.reset_mock()
    validation_plan = replace(plan, stage="validation", stage_run_id="interrupted_validation")
    execute_resume(validation_plan, validation_factory=factory)
    factory.return_value.resume.assert_called_once_with("interrupted_validation")
    assert factory.call_args.kwargs["validation_model"] == plan.models.validation_model


@pytest.mark.parametrize("persisted", [True, False])
def test_resume_cli_refreshes_stale_partial_scan_summary_and_model_choices(tmp_path, monkeypatch, persisted):
    models = choices() if persisted else ScanModelChoices.resolve()
    monkeypatch.setattr(resume_fixture, "SCAN_ID", "scan_" + "c" * 32)
    database = resume_fixture._fixture(tmp_path, models=models if persisted else None)
    scan_id = resume_fixture.SCAN_ID
    output = tmp_path / "ReportRun" / scan_id
    write_scan_summary(database, output, scan_id=scan_id,
                       errors=[{"stage": "attack", "error_type": "InterruptedRun"}])
    assert ReportCatalog(tmp_path).scan_summary(scan_id)["execution_status"] == "partial"
    validation_options = []

    class Stage:
        def __init__(self, name, **kwargs):
            self.name = name

        def run(self, identifier):
            with sqlite3.connect(database) as conn:
                stage = start_stage_run(conn, scan_id=identifier, stage=self.name)
                finish_stage_run(conn, stage, status="skipped" if self.name == "chaining" else "completed")

    def validation_factory(**kwargs):
        validation_options.append(kwargs)
        return Stage("validation", **kwargs)

    monkeypatch.setattr("aidast.orchestration.attack.AttackCoordinator", lambda **kwargs: Stage("attack", **kwargs))
    monkeypatch.setattr("aidast.orchestration.chaining.ChainingCoordinator", lambda **kwargs: Stage("chaining", **kwargs))
    monkeypatch.setattr("aidast.validation.build_native_validation_coordinator", validation_factory)
    with patch("aidast.cli.CodexMainAgent") as agent:
        assert main(["resume", scan_id, "--result-root", str(tmp_path), "--codex-timeout", "42"]) == 0
    assert agent.call_args_list == [
        call(timeout_seconds=42, **models.agent_options()),
        call(timeout_seconds=42, main_model=models.attack_model),
    ]
    assert load_scan_model_choices(tmp_path, scan_id) == models
    assert validation_options[0]["validation_model"] == models.validation_model
    summary = ReportCatalog(tmp_path).scan_summary(scan_id)
    assert summary["execution_status"] == "completed"
    assert summary["errors"] == []
    assert any(stage["stage"] == "attack" and stage["status"] == "failed" for stage in summary["stages"])
    assert summary["latest_stages"][-1]["stage"] == "report"
    assert summary["latest_stages"][-1]["status"] == "skipped"
    assert "InterruptedRun" not in summary["markdown"]


def test_failed_report_is_resumed_offline_without_repeating_execution_stages(tmp_path, monkeypatch):
    monkeypatch.setattr(resume_fixture, "SCAN_ID", "scan_" + "d" * 32)
    database = resume_fixture._fixture(tmp_path, models=choices())
    scan_id = resume_fixture.SCAN_ID
    with sqlite3.connect(database) as conn:
        for stage_name, status in (("attack", "completed"), ("chaining", "skipped"),
                                   ("validation", "completed"), ("report", "failed")):
            stage = start_stage_run(conn, scan_id=scan_id, stage=stage_name)
            finish_stage_run(conn, stage, status=status)
    output = tmp_path / "ReportRun" / scan_id
    write_scan_summary(database, output, scan_id=scan_id,
                       errors=[{"stage": "report", "error_type": "InterruptedWriter"}])
    plan = inspect_resume(tmp_path, scan_id)
    assert plan.stage == "report" and plan.models == choices()
    with patch("aidast.orchestration.attack.AttackCoordinator") as attack, patch(
        "aidast.orchestration.chaining.ChainingCoordinator"
    ) as chaining, patch("aidast.validation.build_native_validation_coordinator") as validation:
        assert main(["resume", scan_id, "--result-root", str(tmp_path)]) == 0
    attack.assert_not_called()
    chaining.assert_not_called()
    validation.assert_not_called()
    summary = ReportCatalog(tmp_path).scan_summary(scan_id)
    assert summary["execution_status"] == "completed"
    assert summary["errors"] == []
    with pytest.raises(ValueError, match="already completed"):
        inspect_resume(tmp_path, scan_id)


def test_resume_cli_drafts_only_verified_cases_with_saved_report_model_and_refreshes_projection(monkeypatch):
    fixture = report_fixture.SharedValidationReportingTests(methodName="runTest")
    fixture.setUp()
    try:
        evidence = fixture.complete()
        finish_stage_run(fixture.conn, fixture.run)
        fixture.conn.execute("UPDATE scans SET status='completed' WHERE scan_id='scan'")
        fixture.conn.commit()
        interrupted = start_stage_run(fixture.conn, scan_id="scan", stage="attack")
        finish_stage_run(fixture.conn, interrupted, status="failed", error_message="InterruptedRun")
        models = choices()
        plan = ResumePlan("scan", "scope", "attack", interrupted, fixture.path,
                          fixture.path.parent / "Scope.md", fixture.path.parent / "TargetPolicy.json",
                          (), models, "https://hackerone.com/example")
        root = fixture.path.parent.parent
        write_scan_summary(fixture.path, root / "ReportRun" / "scan", scan_id="scan")
        monkeypatch.setattr("aidast.cli.inspect_resume", lambda result_root, scan_id: plan)

        def continue_persisted_stage(plan, **kwargs):
            stage = start_stage_run(fixture.conn, scan_id="scan", stage="attack")
            finish_stage_run(fixture.conn, stage)

        monkeypatch.setattr("aidast.cli.execute_resume", continue_persisted_stage)
        with patch("aidast.cli.CodexMainAgent"), patch("aidast.reporting.auto.CodexReportWriter") as writer:
            writer.return_value.write.side_effect = lambda context: fixture.draft(context, evidence)
            assert _run_resume(Namespace(scan_id="scan", result_root=root, codex_timeout=42)) == 0
        assert writer.call_args.args[0]._main_model == models.report_model
        report, = ReportCatalog(root).list(scan_id="scan")
        assert report["case_id"] == "case" and report["platform"] == "hackerone"
        summary = ReportCatalog(root).scan_summary("scan")
        assert summary["execution_status"] == "completed"
        assert [item["case_id"] for item in summary["reports"]] == ["case"]
    finally:
        fixture.doCleanups()
