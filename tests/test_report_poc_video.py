"""Stored evidence replay: masking, bounded provenance and fail-closed cache."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import zipfile

import pytest
from aidast.reporting.runtime import ReportError
from aidast.reporting.submission import export_report, inspect_report
from test_report_submission import case, prepare, verified


def test_poc_service_exists():
    assert importlib.util.find_spec('aidast.reporting.poc_video') is not None, 'PoC replay service is missing'


@pytest.fixture
def codec(monkeypatch):
    from aidast.reporting import poc_video as service
    captured = []
    def render(storyboard, directory, deadline):
        captured.append(storyboard)
        return b'\x1a\x45\xdf\xa3' + b'fixture encoded video' * 12, ['a' * 64] * len(storyboard['chapters'])
    monkeypatch.setattr(service, '_render_and_encode', render)
    return service, captured


def test_ready_video_only_contains_masked_source_and_is_revision_bound(case, codec):
    service, captured = codec
    secret = 'Authorization: Bearer fixture-private-token\npassword=fixture-password alice@example.com'
    db = prepare(case, details={'summary': secret}, changes={'summary': {'text': secret, 'evidence_ids': ['evidence_case']}})
    view = verified(db)
    assert service.inspect_poc(db)['status'] == 'missing'
    info = service.prepare_poc(db, expected_revision=view['revision_sha256'])
    assert info['status'] == 'ready'
    metadata, media = service.read_poc_video(db, expected_revision=view['revision_sha256'])
    assert metadata['sha256'] == hashlib.sha256(media).hexdigest()
    assert info['source_revision'] == view['revision_sha256']
    assert 1 <= info['chapters'] <= 12 and info['duration_seconds'] == 5 * info['chapters']
    text = json.dumps(captured)
    for raw in ('fixture-private-token', 'fixture-password', 'alice@example.com', str(case.path)):
        assert raw not in text
    assert '[TOKEN_' in text and 'evidence_case' in text
    assert view['evidence'][0]['content_sha256'] in text
    assert service.inspect_poc(db)['status'] == 'ready'
    assert inspect_report(db)['revision_sha256'] == view['revision_sha256']
    service.prepare_poc(db)
    assert len(captured) == 1
    verified(db, source='Changed program rules')
    assert service.inspect_poc(db)['status'] == 'stale'
    with pytest.raises(ReportError):
        service.read_poc_video(db, expected_revision=view['revision_sha256'])


def test_blocked_or_wrong_revision_never_generates(case, codec):
    service, captured = codec
    db = prepare(case)
    assert service.inspect_poc(db)['status'] == 'blocked'
    with pytest.raises(ReportError):
        service.prepare_poc(db)
    verified(db)
    with pytest.raises(ReportError):
        service.prepare_poc(db, expected_revision='0' * 64)
    assert captured == []


@pytest.mark.parametrize('name', ['Video.webm', 'Storyboard.json', 'Metadata.json', 'Integrity.json'])
@pytest.mark.parametrize('attack', ['tamper', 'symlink'])
def test_artifact_tamper_or_symlink_blocks_reads_and_regeneration(case, codec, tmp_path, name, attack):
    service, _ = codec
    db = prepare(case)
    view = verified(db)
    service.prepare_poc(db)
    artifact = next(db.parent.glob('.poc-video/*/' + name))
    if attack == 'symlink':
        outside = tmp_path / name
        outside.write_bytes(artifact.read_bytes())
        artifact.unlink()
        artifact.symlink_to(outside)
    else:
        artifact.write_bytes(artifact.read_bytes() + b'changed')
    assert service.inspect_poc(db)['status'] == 'blocked'
    for action in (lambda: service.read_poc_video(db, expected_revision=view['revision_sha256']), lambda: service.prepare_poc(db)):
        with pytest.raises(ReportError, match='PoC automatic checks failed'):
            action()


def test_source_drift_during_render_prevents_publication(case, codec, monkeypatch):
    service, _ = codec
    db = prepare(case)
    verified(db)
    original = service._render_and_encode
    def drift(*args):
        result = original(*args)
        verified(db, source='changed during rendering')
        return result
    monkeypatch.setattr(service, '_render_and_encode', drift)
    with pytest.raises(ReportError):
        service.prepare_poc(db)
    assert not list(db.parent.glob('.poc-video/*/Video.webm'))


def test_poc_zip_binds_media_to_revision_and_preserves_text(case, codec):
    service, _ = codec
    db = prepare(case)
    view = verified(db)
    original = export_report(db)
    payload = export_report(db, expected_revision=view['revision_sha256'], include_poc=True)
    with zipfile.ZipFile(io.BytesIO(payload)) as package, zipfile.ZipFile(io.BytesIO(original)) as text_only:
        assert {'PoC/Video.webm', 'PoC/Metadata.json', 'PoC/Storyboard.json'} <= set(package.namelist())
        metadata = json.loads(package.read('PoC/Metadata.json'))
        assert metadata['source_revision'] == view['revision_sha256']
        assert metadata['mode'] == 'evidence_replay'
        assert hashlib.sha256(package.read('PoC/Video.webm')).hexdigest() == metadata['sha256']
        for name in text_only.namelist():
            if name != 'Manifest.json':
                assert package.read(name) == text_only.read(name)
        manifest = json.loads(package.read('Manifest.json'))
        for entry in manifest['files']:
            assert hashlib.sha256(package.read(entry['name'])).hexdigest() == entry['sha256']
            assert len(package.read(entry['name'])) == entry['size_bytes']


def test_storyboard_escape_and_limits(case, codec):
    service, _ = codec
    db = prepare(case, details={'summary': '<img src="https://outside.invalid/x" onerror="alert(1)"> & text'})
    verified(db)
    service.prepare_poc(db)
    storyboard = json.loads(next(db.parent.glob('.poc-video/*/Storyboard.json')).read_bytes())
    html = ''.join(service._chapter_html(chapter, index + 1, len(storyboard['chapters'])) for index, chapter in enumerate(storyboard['chapters']))
    assert '<img' not in html and '&lt;img' in html
    assert "default-src 'none'" in html
    view = inspect_report(db)
    view['fields']['steps_to_reproduce'] = 'huge evidence ' * 10000
    with pytest.raises(ReportError):
        service._storyboard(view)


def test_video_export_blocks_without_automatic_checks(case):
    db = prepare(case)
    with pytest.raises(ReportError):
        export_report(db, include_poc=True)


def test_metadata_numeric_types_are_strict_even_with_updated_receipt(case, codec):
    service, _ = codec
    db = prepare(case)
    verified(db)
    service.prepare_poc(db)
    path = next(db.parent.glob('.poc-video/*/Metadata.json'))
    metadata = json.loads(path.read_bytes())
    metadata['width'] = 1280.0
    data = (json.dumps(metadata, sort_keys=True, ensure_ascii=False, separators=(',', ':')) + '\n').encode()
    path.write_bytes(data)
    receipt_path = path.parent / 'Integrity.json'
    receipt = json.loads(receipt_path.read_bytes())
    receipt['Metadata.json'] = hashlib.sha256(data).hexdigest()
    receipt_path.write_text(json.dumps(receipt, sort_keys=True, ensure_ascii=False, separators=(',', ':')) + '\n')
    assert service.inspect_poc(db)['status'] == 'blocked'


def test_concurrent_generation_publishes_one_complete_cache(case, codec):
    from concurrent.futures import ThreadPoolExecutor
    service, captured = codec
    db = prepare(case)
    verified(db)
    with ThreadPoolExecutor(max_workers=3) as executor:
        results = list(executor.map(lambda _: service.prepare_poc(db), range(3)))
    assert all(result['status'] == 'ready' for result in results)
    assert len(captured) == 1
    assert len({result['sha256'] for result in results}) == 1
    assert not list(db.parent.glob('.poc-video/.staging-*'))


@pytest.mark.parametrize('text', ['W' * 1100, '界' * 1100], ids=['wide-latin', 'cjk'])
def test_browser_layout_rejects_clipped_wide_text(monkeypatch, text):
    """A browser geometry rejection must prevent publishing a clipped storyboard."""
    import sys
    import types
    from aidast.reporting import poc_video as service
    # This boundary double represents Chromium reporting out-of-bounds geometry;
    # real CJK/long-word geometry is also checked by the separate browser smoke.
    class Page:
        def set_content(self, html, **kwargs):
            assert text[:50] in html
        def evaluate(self, script):
            return False
        def screenshot(self, **kwargs):
            return b'\xff\xd8fixture'
    class Browser:
        def new_context(self, **kwargs):
            return self
        def route(self, *args):
            pass
        def new_page(self):
            return Page()
        def close(self):
            pass
    class Driver:
        def __enter__(self):
            self.chromium = self
            return self
        def __exit__(self, *args):
            pass
        def launch(self, **kwargs):
            return Browser()
    monkeypatch.setitem(sys.modules, 'playwright.sync_api', types.SimpleNamespace(sync_playwright=Driver))
    import time
    def unexpected_codec():
        raise AssertionError('Layout must be checked before encoding')
    monkeypatch.setattr(service, '_ffmpeg', unexpected_codec)
    storyboard = {'chapters': [{'title': 'Wide text', 'text': text, 'evidence': None}]}
    with pytest.raises(ReportError):
        service._render_and_encode(storyboard, Path('/unused'), time.monotonic() + 10)


@pytest.mark.parametrize('failure', ['unavailable', 'timeout', 'oversize', 'bad-container'])
def test_generation_failure_is_generic_and_preserves_original_report(case, codec, monkeypatch, failure):
    import subprocess
    service, _ = codec
    db = prepare(case)
    verified(db)
    originals = {path: path.read_bytes() for path in db.parent.iterdir() if path.is_file()}
    def fail(storyboard, directory, deadline):
        if failure == 'unavailable':
            raise OSError('private-browser-path /Users/private secret-token')
        if failure == 'timeout':
            raise subprocess.TimeoutExpired('private-codec-path', 90)
        if failure == 'oversize':
            return b'\x1a\x45\xdf\xa3' + b'x' * 10_000_000, ['a' * 64] * len(storyboard['chapters'])
        return b'not a WebM', ['a' * 64] * len(storyboard['chapters'])
    monkeypatch.setattr(service, '_render_and_encode', fail)
    with pytest.raises(ReportError) as error:
        service.prepare_poc(db)
    assert str(error.value) == 'PoC automatic checks failed'
    assert service.inspect_poc(db)['status'] == 'missing'
    assert not list(db.parent.glob('.poc-video/.staging-*'))
    assert all(path.read_bytes() == data for path, data in originals.items())


def test_private_cache_root_symlink_blocks_all_access(case, codec, tmp_path):
    service, _ = codec
    db = prepare(case)
    verified(db)
    (db.parent / '.poc-video').symlink_to(tmp_path, target_is_directory=True)
    assert service.inspect_poc(db)['status'] == 'blocked'
    with pytest.raises(ReportError):
        service.prepare_poc(db)
    assert not list(tmp_path.iterdir())


def test_video_read_rechecks_source_after_loading_cache(case, codec, monkeypatch):
    service, _ = codec
    db = prepare(case)
    view = verified(db)
    service.prepare_poc(db)
    original = service._load
    def changed(*args):
        result = original(*args)
        verified(db, source='Rules changed while reading media')
        return result
    monkeypatch.setattr(service, '_load', changed)
    with pytest.raises(ReportError):
        service.read_poc_video(db, expected_revision=view['revision_sha256'])


@pytest.mark.parametrize('include_poc', [False, True], ids=['text-only', 'with-video'])
def test_export_rejects_revision_drift_during_zip_compression(case, codec, monkeypatch, include_poc):
    db = prepare(case)
    view = verified(db)
    originals = {path: path.read_bytes() for path in db.parent.iterdir()
                 if path.is_file() and path.name != 'ProgramRequirements.json'}
    original_writestr = zipfile.ZipFile.writestr
    changed = False
    def mutate_after_compression(archive, *args, **kwargs):
        nonlocal changed
        result = original_writestr(archive, *args, **kwargs)
        if not changed:
            changed = True
            verified(db, source='Program rules changed during ZIP compression')
        return result
    monkeypatch.setattr(zipfile.ZipFile, 'writestr', mutate_after_compression)
    with pytest.raises(ReportError, match='revision changed during export'):
        export_report(db, expected_revision=view['revision_sha256'], include_poc=include_poc)
    assert changed
    assert all(path.read_bytes() == contents for path, contents in originals.items())


def test_dashboard_and_text_export_remain_available_without_unix_lock(case, tmp_path):
    """An optional video lock must not break the existing dashboard/report paths."""
    import subprocess
    import sys

    database = prepare(case)
    verified(database)
    script = '''
import builtins
from pathlib import Path
import sys
import time

original_import = builtins.__import__
def without_unix_lock(name, *args, **kwargs):
    if name == 'fcntl':
        raise ModuleNotFoundError("No module named 'fcntl'")
    return original_import(name, *args, **kwargs)
builtins.__import__ = without_unix_lock

from aidast.web.server import create_app
from aidast.reporting.submission import export_report
from aidast.reporting.poc_video import _generation_lock
from aidast.reporting.runtime import ReportError
assert callable(create_app)
assert export_report(Path(sys.argv[1])).startswith(b'PK')
root = Path(sys.argv[2])
try:
    with _generation_lock(root, time.monotonic() + 1):
        raise AssertionError('Video generation must require its supported lock')
except ReportError as exc:
    assert str(exc) == 'PoC automatic checks failed'
assert not (root / '.lock').exists()
'''
    result = subprocess.run([sys.executable, '-c', script, str(database), str(tmp_path)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
