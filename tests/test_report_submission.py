"""Real source-bound report submission preparation and package safety."""
import importlib.util
import io
import json
import sqlite3
import zipfile
from pathlib import Path

import pytest
from pydantic import ValidationError

from aidast.reporting import CaseReportAgent, record_case_report
from aidast.reporting.runtime import ReportError


@pytest.fixture
def case():
    from test_shared_validation_reporting import SharedValidationReportingTests
    helper = SharedValidationReportingTests(methodName="runTest")
    helper.setUp()
    try:
        yield helper
    finally:
        helper.tearDown()
        helper.doCleanups()


def prepare(case, *, platform="hackerone", changes=None, details=None, kind=None):
    evidence = case.complete()
    if details is not None or kind is not None:
        case.conn.execute("DROP TRIGGER validation_evidence_no_update")
        if details is not None:
            case.conn.execute("PRAGMA ignore_check_constraints=ON")
            case.conn.execute("UPDATE validation_evidence SET details_json=?", (json.dumps(details),))
        if kind is not None:
            case.conn.execute("UPDATE validation_evidence SET evidence_kind=?", (kind,))
        case.conn.commit()
    prepared = CaseReportAgent().run(case.path, case.output, platform=platform, case_id="case")
    context = json.loads(Path(prepared["context_path"]).read_text())
    draft = case.draft(context, evidence)
    draft.update(changes or {})
    record_case_report(Path(prepared["report_db"]), draft)
    return Path(prepared["report_db"])


def service():
    from aidast.reporting.submission import ProgramRequirements, inspect_report, save_requirements, export_report
    return ProgramRequirements, inspect_report, save_requirements, export_report


def verified(report_db, **kwargs):
    Requirements, _, save, _ = service()
    return save(report_db, Requirements(**{"verified": True, "source": "https://example.invalid/program", "severity_required": False, **kwargs}))


def test_submission_service_exists():
    assert importlib.util.find_spec("aidast.reporting.submission") is not None, "Submission service is missing"


def test_automatic_checks_export_only_masked_package_without_approval(case):
    Requirements, inspect, save, export = service()
    report_db = prepare(case)
    originals = {p: p.read_bytes() for p in case.output.iterdir()}
    view = inspect(report_db)
    assert not view["ready"]
    assert any(c["code"] == "program_requirements" and c["level"] == "blocker" for c in view["checks"])
    view = save(report_db, Requirements(verified=True, source="https://example.invalid/program", severity_required=False))
    assert view["ready"]
    assert len(view["revision_sha256"]) == 64
    payload = export(report_db, expected_revision=view["revision_sha256"])
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        assert set(archive.namelist()) == {"Report.md", "Submission.json", "Evidence/evidence-001.json", "Manifest.json"}
        manifest = json.loads(archive.read("Manifest.json"))
        assert manifest["revision_sha256"] == view["revision_sha256"]
        evidence = json.loads(archive.read("Evidence/evidence-001.json"))
        assert evidence["details"]["summary"] == "bounded fixture"
        text = b"".join(archive.read(name) for name in archive.namelist()).decode()
        assert str(case.path) not in text
        assert "source_path" not in text
        assert "Report.db" not in text
    for p, contents in originals.items():
        assert p.read_bytes() == contents


@pytest.mark.parametrize("platform,missing", [("hackerone", "severity"), ("intigriti", "severity"), ("bugcrowd", "vrt_category")])
def test_platform_mandatory_classification_blocks(case, platform, missing):
    Requirements, inspect, save, export = service()
    report_db = prepare(case, platform=platform)
    view = save(report_db, Requirements(verified=True, source="Rules", severity_required=platform != "bugcrowd"))
    assert not view["ready"]
    assert any(c["field"] in {missing, "technical_severity"} for c in view["checks"] if c["level"] == "blocker")
    with pytest.raises(ReportError):
        export(report_db)


@pytest.mark.parametrize("platform,severity_key,asset_key,summary_key", [
    ("hackerone", "severity", "asset", "summary"),
    ("intigriti", "severity", "asset", "description"),
    ("bugcrowd", "technical_severity", "target", "description"),
])
def test_platform_fields_follow_profile(case, platform, severity_key, asset_key, summary_key):
    _, inspect, _, export = service()
    citation = {"text": "Low", "evidence_ids": ["evidence_case"]}
    changes = {"severity": citation}
    if platform == "bugcrowd":
        changes["vrt_category"] = {"text": "Broken Access Control > IDOR", "evidence_ids": ["evidence_case"]}
    report_db = prepare(case, platform=platform, changes=changes)
    view = verified(report_db)
    assert view["ready"]
    assert view["fields"][severity_key] == "Low"
    assert view["fields"][asset_key] == "Local fixture"
    assert view["fields"][summary_key] == "A bounded fixture was validated."
    assert export(report_db).startswith(b"PK")


def test_custom_fields_templates_and_revision_are_checked(case):
    _, inspect, _, export = service()
    report_db = prepare(case)
    old = verified(report_db)
    view = verified(report_db, required_fields=["test_ip"], additional_fields={"test_ip": "192.0.2.7"},
                    report_template="Program report\n{summary}\n{steps_to_reproduce}", impact_template="Impact: {impact}")
    assert view["ready"]
    assert view["fields"]["test_ip"] == "192.0.2.7"
    assert "Program report" in view["markdown"]
    assert "Impact: Boundary crossed" in view["markdown"]
    assert old["revision_sha256"] != view["revision_sha256"]
    with pytest.raises(ReportError, match="revision"):
        export(report_db, expected_revision=old["revision_sha256"])
    view = verified(report_db, required_fields=["test_ip"])
    assert not view["ready"]
    assert any(c["field"] == "test_ip" for c in view["checks"])
    view = verified(report_db, report_template="{unknown_field}")
    assert not view["ready"]
    view = verified(report_db, report_template="{remediation}")
    assert not view["ready"]


@pytest.mark.parametrize("kwargs", [
    {"verified": True}, {"verified": "yes"}, {"unknown": True},
    {"required_fields": ["Title"]}, {"additional_fields": {"title": "Override"}},
    {"additional_fields": {"asset": "Override"}}, {"additional_fields": {"bad key": "value"}},
    {"required_fields": ["title", "title"]}, {"source": "x" * 8193},
])
def test_requirements_strict_bounded_and_cannot_override_fields(kwargs):
    Requirements, _, _, _ = service()
    with pytest.raises(ValidationError):
        Requirements(**kwargs)


def test_masking_covers_prose_metadata_and_program_templates_without_merging_accounts(case):
    _, inspect, _, export = service()
    secret = "Authorization: Bearer fixture-token-A\nCookie: sid=fixture-cookie-B\npassword=fixture-password\nhttps://test/item?access_token=fixture-query&item=7\nAccount A: alice@example.com; Account B: bob@example.com"
    citation = {"text": secret, "evidence_ids": ["evidence_case"]}
    report_db = prepare(case, changes={"summary": citation, "impact": citation, "remediation": secret,
                                      "attachment_evidence_ids": ["evidence_case"]},
                        details={"summary": secret, "account_email": "alice@example.com", "password": "fixture-password",
                                 "request": {"url": "https://test/?token=fixture-query", "api_key": "fixture-api-key"}})
    view = verified(report_db, additional_fields={"extra": secret}, required_fields=["extra"], report_template="{summary}\n" + secret)
    assert view["ready"]
    exported = export(report_db)
    with zipfile.ZipFile(io.BytesIO(exported)) as archive:
        text = "\n".join(archive.read(name).decode() for name in archive.namelist())
    for raw in ("fixture-token-A", "fixture-cookie-B", "fixture-password", "fixture-query", "fixture-api-key", "alice@example.com", "bob@example.com"):
        assert raw not in json.dumps(view)
        assert raw not in text
    assert "item=7" in view["fields"]["summary"]
    assert "Account A" in view["fields"]["summary"] and "Account B" in view["fields"]["summary"]
    import re
    identities = re.findall(r"\[EMAIL_\d+\]", view["fields"]["summary"])
    assert len(set(identities)) == 2
    assert view["redactions"]
    assert "metadata" in view["markdown"].lower()


def test_stale_source_blocks_and_changes_revision(case):
    _, inspect, _, export = service()
    report_db = prepare(case)
    before = verified(report_db)
    case.eligibility()
    view = inspect(report_db)
    assert not view["ready"]
    assert view["revision_sha256"] != before["revision_sha256"]
    assert any(c["code"] == "source_integrity" for c in view["checks"])
    with pytest.raises(ReportError):
        export(report_db, expected_revision=before["revision_sha256"])


@pytest.mark.parametrize("change", ["draft", "evidence"])
def test_tampered_draft_or_evidence_never_exports(case, change):
    _, inspect, _, export = service()
    report_db = prepare(case)
    before = verified(report_db)
    if change == "draft":
        with sqlite3.connect(report_db) as conn:
            conn.execute("UPDATE report_drafts SET draft_json='{}'")
    else:
        case.conn.execute("DROP TRIGGER validation_evidence_no_update")
        case.conn.execute("UPDATE validation_evidence SET details_json='{}'")
        case.conn.commit()
    view = inspect(report_db)
    assert not view["ready"]
    assert view["revision_sha256"] != before["revision_sha256"]
    with pytest.raises(ReportError):
        export(report_db)


@pytest.mark.parametrize("details,kind", [({"summary": "x" * 70000}, None), ({"file_path": "/private/raw.png", "mime_type": "image/png"}, None), ({"summary": "video"}, "video")])
def test_oversize_and_unsupported_evidence_blocks_without_truncation(case, details, kind):
    _, inspect, _, export = service()
    report_db = prepare(case, details=details, kind=kind, changes={"attachment_evidence_ids": ["evidence_case"]})
    view = verified(report_db)
    assert not view["ready"]
    assert any(c["code"] == "evidence_metadata" for c in view["checks"])
    assert "/private/raw.png" not in json.dumps(view)
    with pytest.raises(ReportError):
        export(report_db)


def test_requirements_sidecar_symlink_rejected_without_mutating_target(case):
    Requirements, inspect, save, export = service()
    report_db = prepare(case)
    target = Path(case.temp.name) / "original.json"
    target.write_text("original")
    (report_db.parent / "ProgramRequirements.json").symlink_to(target)
    with pytest.raises(ReportError):
        save(report_db, Requirements())
    assert target.read_text() == "original"
    assert not inspect(report_db)["ready"]


def test_legacy_preview_masks_secrets():
    from aidast.reporting.submission import sanitize_preview
    masked = sanitize_preview("Authorization: Bearer secret\nuser@example.com https://test/?token=private")
    assert "secret" not in masked and "user@example.com" not in masked and "private" not in masked


def test_report_writer_receives_masked_copy_preserving_source_and_evidence_bindings(case):
    evidence = case.complete()
    case.conn.execute("DROP TRIGGER validation_evidence_no_update")
    case.conn.execute("UPDATE validation_evidence SET details_json=?", (json.dumps({"summary": "Authorization: Bearer writer-secret\nAccount A: writer@example.com"}),))
    case.conn.commit()
    seen = []
    class Writer:
        def write(self, context):
            seen.append(context)
            return case.draft(context, evidence)
    result = CaseReportAgent(writer=Writer()).run(case.path, case.output, platform="hackerone", case_id="case")
    context = json.loads(Path(result["context_path"]).read_text())
    assert "writer-secret" not in json.dumps(seen[0])
    assert "writer@example.com" not in json.dumps(seen[0])
    assert seen[0]["source"] == context["source"]
    assert seen[0]["context_sha256"] == context["context_sha256"]
    assert seen[0]["allowed_evidence_ids"] == [evidence]
    assert "writer-secret" in json.dumps(context)


def test_writer_context_rejects_unsupported_raw_evidence():
    from aidast.reporting.submission import sanitize_writer_context
    with pytest.raises(ReportError):
        sanitize_writer_context({"validation": {"evidence": [{"details": {"raw_body": "private"}}]}})


def test_short_secrets_do_not_corrupt_structural_hashes_ids_or_numbered_steps(case):
    _, inspect, _, export = service()
    report_db = prepare(case, changes={"summary": {"text": "password=1 and secret=aaaa", "evidence_ids": ["evidence_case"]}},
                        details={"summary": "password=1", "password": "1", "api_key": "aaaa"})
    view = verified(report_db)
    assert view["ready"]
    assert view["evidence"][0]["content_sha256"] == "a" * 64
    assert view["evidence"][0]["evidence_id"] == "evidence_case"
    assert view["fields"]["steps_to_reproduce"].startswith("1. ")
    assert "password=1" not in view["fields"]["summary"]
    assert "aaaa" not in view["evidence"][0]["details"]["api_key"]


def test_writer_masking_does_not_change_decision_citations():
    from aidast.reporting.submission import sanitize_writer_context
    original = {"validation": {"decision": {"evidence_ids": ["evidence_case"], "summary": "password=case"},
                               "evidence": [{"evidence_id": "evidence_case", "content_sha256": "a" * 64, "details": {"password": "case"}}]},
                "source": {"case_id": "case"}, "allowed_evidence_ids": ["evidence_case"]}
    masked = sanitize_writer_context(original)
    assert masked["validation"]["decision"]["evidence_ids"] == ["evidence_case"]
    assert masked["validation"]["evidence"][0]["evidence_id"] == "evidence_case"
    assert masked["validation"]["decision"]["summary"] != original["validation"]["decision"]["summary"]


def test_remote_url_paths_survive_preview_masking_while_local_paths_do_not():
    from aidast.reporting.submission import sanitize_preview
    value = "GET https://test/home/user?token=credential-secret\nhttps://test/private/item\nLocal evidence: /private/tmp/source.txt"
    masked = sanitize_preview(value)
    assert "https://test/home/user?token=" in masked
    assert "https://test/private/item" in masked
    assert "/private/tmp/source.txt" not in masked
    assert "credential-secret" not in masked


def test_short_sensitive_headers_are_masked_in_legacy_preview():
    from aidast.reporting.submission import sanitize_preview
    masked = sanitize_preview("Cookie: a\nAuthorization: b\nGET /item/1")
    assert "Cookie: a" not in masked
    assert "Authorization: b" not in masked
    assert "GET /item/1" in masked


def test_source_changes_between_integrity_reads_block_inspection(case, monkeypatch):
    from aidast.reporting import case_runtime
    _, inspect, _, _ = service()
    report_db = prepare(case)
    verified(report_db)
    original = case_runtime._load
    changed = False
    def concurrent_change(*args, **kwargs):
        nonlocal changed
        result = original(*args, **kwargs)
        if not changed:
            case.eligibility()
            changed = True
        return result
    monkeypatch.setattr(case_runtime, "_load", concurrent_change)
    view = inspect(report_db)
    assert not view["ready"]
    assert any(c["code"] == "source_integrity" and c["level"] == "blocker" for c in view["checks"])


def test_preview_masks_url_credentials_encoded_query_keys_and_bearer_tokens():
    from aidast.reporting.submission import sanitize_preview
    masked = sanitize_preview("https://login-user:login-password@test/home/a?access%5Ftoken=query-secret&item=7\nBearer plain-token-secret")
    for value in ("login-user", "login-password", "query-secret", "plain-token-secret"):
        assert value not in masked
    assert "item=7" in masked and "/home/a" in masked


def test_non_hex_evidence_digest_blocks_export(case):
    _, inspect, _, export = service()
    evidence = case.complete()
    case.conn.execute("DROP TRIGGER validation_evidence_no_update")
    case.conn.execute("UPDATE validation_evidence SET content_sha256=?", ("z" * 64,))
    case.conn.commit()
    result = CaseReportAgent().run(case.path, case.output, platform="hackerone", case_id="case")
    report_db = Path(result["report_db"])
    record_case_report(report_db, case.draft(json.loads(Path(result["context_path"]).read_text()), evidence))
    view = verified(report_db)
    assert not view["ready"]
    with pytest.raises(ReportError):
        export(report_db)


def test_secret_equal_to_canonical_field_name_does_not_change_submission_schema(case):
    _, inspect, _, export = service()
    report_db = prepare(case, changes={"summary": {"text": "password=title", "evidence_ids": ["evidence_case"]}})
    view = verified(report_db)
    assert view["ready"]
    assert view["fields"]["title"] == "Fixture report"
    assert "password=title" not in view["fields"]["summary"]
    assert "report_template" in view["requirements"]
    assert export(report_db).startswith(b"PK")


def test_structured_short_secrets_are_masked_in_writer_decision():
    from aidast.reporting.submission import sanitize_writer_context
    context = {"validation": {"decision": {"password": "1"}, "evidence": []}}
    masked = sanitize_writer_context(context)
    assert masked["validation"]["decision"]["password"] != "1"
    assert context["validation"]["decision"]["password"] == "1"


def test_short_url_credentials_and_query_aliases_are_masked():
    from aidast.reporting.submission import sanitize_preview
    masked = sanitize_preview('https://a:b@test/?auth=x&key=ab&sig=c&code=1&item=7')
    for fragment in ('a:b@', 'auth=x', 'key=ab', 'sig=c', 'code=1'):
        assert fragment not in masked
    assert 'item=7' in masked


def test_short_url_secrets_are_absent_from_real_package(case):
    _, _, _, export = service()
    url = 'https://a:b@test/?auth=x&key=ab&sig=c&code=1&item=7'
    report_db = prepare(case, changes={'summary': {'text': url, 'evidence_ids': ['evidence_case']}},
                        details={'url': url})
    view = verified(report_db)
    assert view['ready']
    with zipfile.ZipFile(io.BytesIO(export(report_db))) as archive:
        text = b''.join(archive.read(name) for name in archive.namelist()).decode()
        for fragment in ('a:b@', 'auth=x', 'key=ab', 'sig=c', 'code=1'):
            assert fragment not in text
        assert 'item=7' in text


def test_template_expansion_is_bounded_before_final_export(case):
    report_db = prepare(case, changes={'summary': {'text': 'X' * 8192, 'evidence_ids': ['evidence_case']}})
    view = verified(report_db, report_template='{summary}' * 300)
    assert not view['ready']
    assert any(check['code'] == 'program_template' and check['level'] == 'blocker' for check in view['checks'])


@pytest.mark.parametrize('secret', ['report_template', 'test_account'])
def test_requirements_identifiers_and_template_placeholders_are_preserved(case, secret):
    report_db = prepare(case)
    view = verified(report_db, source='password=' + secret,
                    additional_fields={'test_account': 'Account A'}, required_fields=['test_account'],
                    report_template='{title}\n{test_account}\n{summary}')
    assert view['ready']
    assert 'test_account' in view['fields']
    assert 'Account A' in view['markdown']


def test_bound_relative_and_absolute_source_paths_are_omitted_from_export(case):
    import os
    source = os.path.relpath(case.path, case.output)
    report_db = prepare(case, changes={'summary': {'text': 'Internal source: ' + source + '\n' + str(case.path),
                                                 'evidence_ids': ['evidence_case']}})
    view = verified(report_db)
    assert view['ready']
    assert source not in view['markdown']
    assert str(case.path) not in view['markdown']


def test_aggregate_evidence_budget_blocks_without_truncating(case, monkeypatch):
    import aidast.reporting.submission as submission
    report_db = prepare(case)
    monkeypatch.setattr(submission, 'MAX_EVIDENCE_BYTES', 8, raising=False)
    view = verified(report_db)
    assert not view['ready']
    assert any(check['code'] == 'evidence_metadata' and check['level'] == 'blocker' for check in view['checks'])


def test_submission_package_budget_is_an_automatic_blocker(case, monkeypatch):
    import aidast.reporting.submission as submission
    report_db = prepare(case)
    monkeypatch.setattr(submission, 'MAX_PACKAGE_BYTES', 128, raising=False)
    view = verified(report_db)
    assert not view['ready']
    with pytest.raises(ReportError):
        submission.export_report(report_db)


def identity_writer_report(case, *, original_placeholder=""):
    """Persist a real writer-produced draft whose identity labels came from source."""
    evidence = case.complete()
    case.conn.execute("DROP TRIGGER validation_evidence_no_update")
    details = {"summary": "Account B: bob@example.com" + original_placeholder}
    case.conn.execute("UPDATE validation_evidence SET details_json=?", (json.dumps(details),))
    case.conn.commit()
    seen = []
    class Writer:
        def write(self, context):
            summary = context["validation"]["evidence"][0]["details"]["summary"]
            seen.append(summary)
            draft = case.draft(context, evidence)
            draft["summary"]["text"] = summary
            return draft
    result = CaseReportAgent(writer=Writer()).run(case.path, case.output, platform="hackerone", case_id="case")
    return Path(result["report_db"]), seen[0]


def test_writer_identity_matches_prose_evidence_and_new_program_identity_in_zip(case):
    report_db, writer_summary = identity_writer_report(case)
    assert writer_summary == "Account B: [EMAIL_1]"
    originals = {p: p.read_bytes() for p in case.output.iterdir()}
    view = verified(report_db, additional_fields={"contact": "Account A: alice@example.com"})
    assert view["ready"]
    assert view["fields"]["summary"] == writer_summary
    assert view["evidence"][0]["details"]["summary"] == writer_summary
    assert view["fields"]["contact"] == "Account A: [EMAIL_2]"
    _, _, _, export = service()
    with zipfile.ZipFile(io.BytesIO(export(report_db))) as archive:
        submission = json.loads(archive.read("Submission.json"))
        evidence = json.loads(archive.read("Evidence/evidence-001.json"))
        assert submission["fields"]["summary"] == writer_summary
        assert evidence["details"]["summary"] == writer_summary
        assert submission["fields"]["contact"] == "Account A: [EMAIL_2]"
        shared = "\n".join(archive.read(name).decode() for name in archive.namelist())
        assert "bob@example.com" not in shared and "alice@example.com" not in shared
        assert "replacement" not in shared.lower()
    for path, content in originals.items():
        assert path.read_bytes() == content


def test_masked_program_rules_roundtrip_retains_private_values_and_identity_labels(case):
    Requirements, inspect, save, export = service()
    report_db, writer_summary = identity_writer_report(case)
    first = verified(report_db, source="Program contact: alice@example.com",
                     additional_fields={"contact": "alice@example.com", "test_account": "Original Account"},
                     report_template="Contact alice@example.com\n{summary}",
                     impact_template="Contact alice@example.com\n{impact}")
    assert first["ready"]
    payload = json.loads(json.dumps(first["requirements"]))
    payload["required_fields"] = ["contact"]
    payload["additional_fields"]["test_account"] = "Edited Account"
    payload["additional_fields"]["new_contact"] = "carol@example.com"
    second = save(report_db, Requirements.model_validate(payload))
    assert second["ready"]
    assert second["fields"]["summary"] == writer_summary
    assert second["evidence"][0]["details"]["summary"] == writer_summary
    assert second["fields"]["contact"] == "[EMAIL_2]"
    assert second["fields"]["new_contact"] == "[EMAIL_3]"
    private = json.loads((report_db.parent / "ProgramRequirements.json").read_text())["requirements"]
    assert private["source"] == "Program contact: alice@example.com"
    assert private["report_template"] == "Contact alice@example.com\n{summary}"
    assert private["impact_template"] == "Contact alice@example.com\n{impact}"
    assert private["additional_fields"]["contact"] == "alice@example.com"
    assert private["additional_fields"]["test_account"] == "Edited Account"
    assert private["additional_fields"]["new_contact"] == "carol@example.com"
    assert (report_db.parent / "ProgramRequirements.json").stat().st_mode & 0o777 == 0o600
    third = save(report_db, Requirements.model_validate(second["requirements"]))
    assert third["revision_sha256"] == second["revision_sha256"]
    assert export(report_db).startswith(b"PK")


def test_original_placeholder_is_reserved_without_shifting_writer_issued_labels(case):
    report_db, writer_summary = identity_writer_report(case, original_placeholder="; Existing label: [EMAIL_1]")
    assert writer_summary == "Account B: [EMAIL_2]; Existing label: [EMAIL_1]"
    view = verified(report_db, additional_fields={"contact": "Account A: alice@example.com; Existing label: [EMAIL_3]"})
    assert view["ready"]
    assert view["fields"]["summary"] == writer_summary
    assert view["evidence"][0]["details"]["summary"] == writer_summary
    assert view["fields"]["contact"] == "Account A: [EMAIL_4]; Existing label: [EMAIL_3]"


def test_edited_rules_strings_are_saved_as_edits_instead_of_restoring_old_templates(case):
    Requirements, _, save, _ = service()
    report_db = prepare(case)
    first = verified(report_db, source="Contact alice@example.com", report_template="{summary}\nalice@example.com")
    edited = {**first["requirements"], "source": "Edited program rules", "report_template": "{summary}\nChanged contact: carol@example.com"}
    view = save(report_db, Requirements.model_validate(edited))
    assert view["ready"]
    private = json.loads((report_db.parent / "ProgramRequirements.json").read_text())["requirements"]
    assert private["source"] == "Edited program rules"
    assert private["report_template"] == "{summary}\nChanged contact: carol@example.com"
