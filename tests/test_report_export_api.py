"""Submission export uses the same automatic checks through HTTP and CLI."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import sqlite3
import zipfile
from pathlib import Path

import httpx
import pytest

from aidast.cli import main
from aidast.reporting.runtime import ReportAgent, record_report
from aidast.web.server import create_app
import test_shared_validation_reporting as shared_fixtures


@pytest.fixture
def report_case():
    fixture = shared_fixtures.SharedValidationReportingTests(methodName='test_confirmed_case_without_eligibility_is_not_reportable')
    fixture.setUp()
    try:
        evidence = fixture.complete()
        root = fixture.path.parent.parent
        fixture.output = root / 'ReportRun' / 'scan' / 'case'
        prepared = ReportAgent().run(fixture.path, fixture.output, platform='hackerone', case_id='case')
        context = json.loads(Path(prepared['context_path']).read_text())
        record_report(Path(prepared['report_db']), fixture.draft(context, evidence))
        yield fixture, prepared, root
    finally:
        fixture.doCleanups()


RULES = {'verified': True, 'source': 'https://example.invalid/program', 'severity_required': False}


def request_scenario(root, scenario):
    async def run():
        app = create_app(result_root=root)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
            return await scenario(client)
    return asyncio.run(run())


def test_automatic_checks_allow_export_without_approval(report_case):
    _, prepared, root = report_case
    endpoint = '/api/v1/reports/' + prepared['report_id']

    async def run(client):
        initial = await client.get(endpoint + '/submission')
        assert initial.status_code == 200
        assert initial.json()['ready'] is False
        blocked = await client.get(endpoint + '/export')
        assert blocked.status_code == 409
        saved = await client.post(endpoint + '/requirements', json=RULES, headers={'Origin': 'http://test'})
        assert saved.status_code == 200
        view = saved.json()
        assert view['ready'] is True
        exported = await client.get(endpoint + '/export', params={'revision': view['revision_sha256']})
        assert exported.status_code == 200
        assert exported.headers['content-type'] == 'application/zip'
        with zipfile.ZipFile(io.BytesIO(exported.content)) as package:
            assert {'Report.md', 'Submission.json', 'Manifest.json'} <= set(package.namelist())
        assert 'approval' not in view
    request_scenario(root, run)


def test_requirement_save_requires_same_origin(report_case):
    _, prepared, root = report_case

    async def run(client):
        url = '/api/v1/reports/' + prepared['report_id'] + '/requirements'
        assert (await client.post(url, json=RULES)).status_code == 403
        assert (await client.post(url, json=RULES, headers={'Origin': 'https://outside.invalid'})).status_code == 403
    request_scenario(root, run)


def test_invalid_requirement_response_does_not_echo_secrets(report_case):
    _, prepared, root = report_case

    async def run(client):
        response = await client.post('/api/v1/reports/' + prepared['report_id'] + '/requirements',
                                     json={**RULES, 'password': 'never-echo-this-fixture'},
                                     headers={'Origin': 'http://test'})
        assert response.status_code == 422
        assert 'never-echo-this-fixture' not in response.text
    request_scenario(root, run)


def test_report_requirements_body_is_bounded_before_json_parsing(report_case):
    _, prepared, root = report_case
    async def run(client):
        response = await client.post('/api/v1/reports/' + prepared['report_id'] + '/requirements',
                                     content=b'not-json:' + b'x' * 131072,
                                     headers={'Origin': 'http://test', 'Content-Type': 'application/json'})
        assert response.status_code == 413
        assert 'not-json' not in response.text
    request_scenario(root, run)


def test_old_revision_cannot_export_after_requirements_change(report_case):
    _, prepared, root = report_case
    endpoint = '/api/v1/reports/' + prepared['report_id']

    async def run(client):
        first = (await client.post(endpoint + '/requirements', json=RULES, headers={'Origin': 'http://test'})).json()
        changed = {**RULES, 'additional_fields': {'test_account': 'Account A'}}
        assert (await client.post(endpoint + '/requirements', json=changed, headers={'Origin': 'http://test'})).status_code == 200
        assert (await client.get(endpoint + '/export', params={'revision': first['revision_sha256']})).status_code == 409
    request_scenario(root, run)


def test_export_rechecks_current_validation_after_inspection(report_case):
    fixture, prepared, root = report_case
    endpoint = '/api/v1/reports/' + prepared['report_id']

    async def run(client):
        view = (await client.post(endpoint + '/requirements', json=RULES, headers={'Origin': 'http://test'})).json()
        fixture.conn.execute("UPDATE validation_cases SET current_status='DISPROVEN' WHERE case_id='case'")
        fixture.conn.commit()
        assert (await client.get(endpoint + '/export', params={'revision': view['revision_sha256']})).status_code == 409
    request_scenario(root, run)


def test_export_api_cannot_load_source_outside_result_root(report_case, tmp_path):
    _, prepared, root = report_case
    foreign = tmp_path / 'outside.db'
    foreign.write_bytes(b'unrelated')
    with sqlite3.connect(prepared['report_db']) as conn:
        conn.execute('UPDATE report_runs SET source_path=?', (str(foreign),))

    async def run(client):
        response = await client.get('/api/v1/reports/' + prepared['report_id'] + '/submission')
        assert response.status_code == 409
        assert str(foreign) not in response.text
    request_scenario(root, run)


def test_legacy_preview_and_titles_are_masked(report_case):
    _, prepared, root = report_case
    secret = 'fixture-token-value'
    markdown = '# Local report\n\nAuthorization: Bearer ' + secret + '\n'
    with sqlite3.connect(prepared['report_db']) as conn:
        conn.execute('UPDATE report_drafts SET markdown=?,markdown_sha256=?',
                     (markdown, hashlib.sha256(markdown.encode()).hexdigest()))

    async def run(client):
        response = await client.get('/api/v1/reports/' + prepared['report_id'])
        assert response.status_code == 200
        assert secret not in response.text
        assert (await client.get('/api/v1/reports/' + prepared['report_id'] + '/export')).status_code == 409
    request_scenario(root, run)


def test_cli_check_and_export_share_rules_without_approval(report_case, tmp_path, capsys):
    _, prepared, _ = report_case
    database = prepared['report_db']
    assert main(['report', 'check', database]) == 1
    assert json.loads(capsys.readouterr().out)['ready'] is False
    rules = tmp_path / 'rules.json'
    rules.write_text(json.dumps(RULES))
    assert main(['report', 'check', database, '--requirements', str(rules)]) == 0
    assert json.loads(capsys.readouterr().out)['ready'] is True
    output = tmp_path / 'report.zip'
    assert main(['report', 'export', database, '--output', str(output)]) == 0
    assert output.read_bytes().startswith(b'PK')


def test_cli_export_refuses_to_overwrite_source_file(report_case, tmp_path):
    fixture, prepared, _ = report_case
    rules = tmp_path / 'rules.json'
    rules.write_text(json.dumps(RULES))
    before = fixture.path.read_bytes()
    assert main(['report', 'export', prepared['report_db'], '--requirements', str(rules),
                 '--output', str(fixture.path)]) != 0
    assert fixture.path.read_bytes() == before


def test_poc_api_origin_revision_blocking_and_cached_video(report_case, monkeypatch):
    from aidast.reporting import poc_video
    import threading
    renderer_threads = []
    def render(storyboard, directory, deadline):
        renderer_threads.append(threading.get_ident())
        return b'\x1a\x45\xdf\xa3' + b'fixture video' * 12, ['a' * 64] * len(storyboard['chapters'])
    monkeypatch.setattr(poc_video, '_render_and_encode', render)
    _, prepared, root = report_case
    endpoint = '/api/v1/reports/' + prepared['report_id']
    async def run(client):
        event_thread = threading.get_ident()
        assert (await client.get(endpoint + '/poc')).json()['status'] == 'blocked'
        assert (await client.post(endpoint + '/poc')).status_code == 403
        assert (await client.post(endpoint + '/poc', headers={'Origin': 'https://outside.invalid'})).status_code == 403
        assert (await client.post(endpoint + '/poc', headers={'Origin': 'http://test'})).status_code == 409
        assert (await client.get(endpoint + '/poc/video')).status_code == 422
        for path, method in [('/poc', client.post), ('/poc/video', client.get)]:
            invalid = await method(endpoint + path, params={'revision': 'private-secret-invalid'}, headers={'Origin': 'http://test'})
            assert invalid.status_code == 422 and 'private-secret-invalid' not in invalid.text
        view = (await client.post(endpoint + '/requirements', json=RULES, headers={'Origin': 'http://test'})).json()
        assert (await client.get(endpoint + '/poc')).json()['status'] == 'missing'
        assert (await client.get(endpoint + '/poc/video', params={'revision': view['revision_sha256']})).status_code == 409
        assert renderer_threads == []
        ready = await client.post(endpoint + '/poc', params={'revision': view['revision_sha256']}, headers={'Origin': 'http://test'})
        assert ready.status_code == 200 and ready.json()['status'] == 'ready'
        assert renderer_threads and renderer_threads[0] != event_thread
        video = await client.get(endpoint + '/poc/video', params={'revision': view['revision_sha256']})
        assert video.status_code == 200 and video.headers['content-type'] == 'video/webm'
        assert video.headers['cache-control'] == 'no-store'
        assert hashlib.sha256(video.content).hexdigest() == ready.json()['sha256']
        archive = await client.get(endpoint + '/export', params={'revision': view['revision_sha256'], 'include_poc': 'true'})
        assert archive.status_code == 200
        with zipfile.ZipFile(io.BytesIO(archive.content)) as package:
            assert package.read('PoC/Video.webm') == video.content
        await client.post(endpoint + '/requirements', json={**RULES, 'source': 'changed rules'}, headers={'Origin': 'http://test'})
        assert (await client.get(endpoint + '/poc')).json()['status'] == 'stale'
        assert (await client.get(endpoint + '/poc/video', params={'revision': view['revision_sha256']})).status_code == 409
    request_scenario(root, run)


def test_cli_poc_export_includes_verified_media(report_case, tmp_path, monkeypatch):
    from aidast.reporting import poc_video
    monkeypatch.setattr(poc_video, '_render_and_encode', lambda storyboard, directory, deadline:
                        (b'\x1a\x45\xdf\xa3' + b'fixture video' * 12, ['b' * 64] * len(storyboard['chapters'])))
    _, prepared, _ = report_case
    rules = tmp_path / 'rules.json'
    rules.write_text(json.dumps(RULES))
    output = tmp_path / 'video-report.zip'
    assert main(['report', 'export', prepared['report_db'], '--requirements', str(rules), '--output', str(output), '--poc']) == 0
    with zipfile.ZipFile(output) as package:
        assert 'PoC/Video.webm' in package.namelist()
