"""Offline, masked replay of stored report evidence; never executes a target PoC."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import html
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import tempfile
import textwrap
import time

from aidast.validation.models import canonical_json
from .runtime import ReportError, _path
from .submission import inspect_report

MODE = 'evidence_replay'
WIDTH, HEIGHT, FPS = 1280, 720, 2
CHAPTER_SECONDS, MAX_CHAPTERS = 5, 12
MAX_MEDIA_BYTES = 10_000_000
MAX_POC_METADATA_BYTES = 256_000
GENERATION_TIMEOUT = 90
ERROR = 'PoC automatic checks failed'
_HEX = re.compile(r'^[a-f0-9]{64}$')
_FILES = ('Video.webm', 'Storyboard.json', 'Metadata.json', 'Integrity.json')
_INFO = ('source_revision', 'filename', 'sha256', 'byte_size', 'duration_seconds', 'width', 'height', 'chapters')


def _encoded(value: dict) -> bytes:
    return (canonical_json(value) + '\n').encode()


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ReportError(ERROR)
    return remaining


def _source(report_db: Path, revision: str | None = None) -> dict:
    view = inspect_report(report_db)
    if not view['ready']:
        raise ReportError(ERROR)
    if revision is not None and (not _HEX.fullmatch(revision) or revision != view['revision_sha256']):
        raise ReportError('Report changed; run checks again')
    return view


def _storyboard(view: dict) -> dict:
    """Paginate whole sanitized text; block over-budget sources instead of omitting evidence."""
    fields = view['fields']
    chapters = []
    def section(title: str, content: str, evidence: dict | None = None) -> None:
        # Fixed wrapping keeps untrusted long words and markup within the viewport.
        lines = []
        for line in content.splitlines():
            lines.extend(textwrap.wrap(line, width=88, replace_whitespace=True, drop_whitespace=True) or [''])
        for start in range(0, max(1, len(lines)), 13):
            chapters.append({'title': title, 'text': '\n'.join(lines[start:start + 13]),
                             'evidence': evidence})
            if len(chapters) > MAX_CHAPTERS:
                raise ReportError(ERROR)
    section('Report', fields.get('title', '') + '\n\n' + fields.get('summary', fields.get('description', '')))
    section('Target and comparison', 'Target: ' + fields.get('asset', fields.get('target', '')) + '\n\nExpected: ' + fields.get('expected_behavior', '') + '\n\nObserved: ' + fields.get('actual_behavior', ''))
    section('Masked steps from the report', fields.get('steps_to_reproduce', ''))
    for evidence in view['evidence']:
        provenance = {key: evidence[key] for key in ('evidence_id', 'content_sha256', 'sanitized_sha256')}
        section('Stored evidence: ' + evidence['kind'], json.dumps(evidence['details'], ensure_ascii=False, indent=2), provenance)
    section('Reported impact', fields.get('impact', fields.get('demonstrated_impact', '')))
    result = {'schema_version': 1, 'mode': MODE, 'source_revision': view['revision_sha256'],
              'label': 'Evidence replay of stored masked evidence. Not live reproduction footage.',
              'width': WIDTH, 'height': HEIGHT, 'chapter_seconds': CHAPTER_SECONDS, 'chapters': chapters}
    if len(_encoded(result)) > MAX_POC_METADATA_BYTES // 2:
        raise ReportError(ERROR)
    return result


def _chapter_html(chapter: dict, number: int, total: int) -> str:
    evidence = chapter['evidence']
    footer = ''
    if evidence:
        footer = ('Evidence ID: ' + evidence['evidence_id'] + '\nOriginal SHA-256: ' + evidence['content_sha256'] + '\nMasked SHA-256: ' + evidence['sanitized_sha256'])
    return '''<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<style>*{box-sizing:border-box}body{margin:0;width:1280px;height:720px;overflow:hidden;background:#101b2a;color:#edf4fa;font-family:Arial,sans-serif;padding:36px 52px}.mode{font-size:18px;letter-spacing:2px;color:#77dccc}h1{font-size:30px;margin:18px 0 14px}pre{font-family:Arial,sans-serif;white-space:pre-wrap;overflow-wrap:anywhere;font-size:22px;line-height:31px;margin:0}.provenance{position:absolute;bottom:57px;font:13px/19px monospace;white-space:pre-wrap;max-width:1170px;overflow-wrap:anywhere}.bottom{position:absolute;bottom:23px;font-size:16px;color:#adbfcc}</style></head><body>
<div class="mode">EVIDENCE REPLAY · STORED MASKED EVIDENCE</div><h1>''' + html.escape(chapter['title']) + '</h1><pre>' + html.escape(chapter['text']) + '</pre><div class="provenance">' + html.escape(footer) + '</div><div class="bottom">Not live reproduction footage · ' + str(number) + ' / ' + str(total) + '</div></body></html>'


def _ffmpeg() -> str:
    system = shutil.which('ffmpeg')
    if system:
        return system
    roots = [Path.home() / 'Library/Caches/ms-playwright', Path.home() / '.cache/ms-playwright']
    if os.environ.get('PLAYWRIGHT_BROWSERS_PATH'):
        roots.insert(0, Path(os.environ['PLAYWRIGHT_BROWSERS_PATH']))
    if os.environ.get('LOCALAPPDATA'):
        roots.append(Path(os.environ['LOCALAPPDATA']) / 'ms-playwright')
    for root in roots:
        for candidate in sorted(root.glob('ffmpeg-*/ffmpeg*'), reverse=True):
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
    raise ReportError(ERROR)


def _run_codec(command: list[str], deadline: float, *, data: bytes | None = None) -> bytes:
    result = subprocess.run(command, input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=_remaining(deadline), check=False)
    if result.returncode != 0 or len(result.stdout) > MAX_POC_METADATA_BYTES:
        raise ReportError(ERROR)
    return result.stdout


def _render_and_encode(storyboard: dict, directory: Path, deadline: float) -> tuple[bytes, list[str]]:
    from playwright.sync_api import sync_playwright
    frames = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, timeout=_remaining(deadline) * 1000)
        try:
            context = browser.new_context(viewport={'width': WIDTH, 'height': HEIGHT}, device_scale_factor=1,
                                          service_workers='block', java_script_enabled=False, offline=True)
            context.route('**/*', lambda route: route.abort())
            page = context.new_page()
            for index, chapter in enumerate(storyboard['chapters']):
                page.set_content(_chapter_html(chapter, index + 1, len(storyboard['chapters'])),
                                 wait_until='load', timeout=_remaining(deadline) * 1000)
                if not page.evaluate("""() => {
                    const nodes = ['.mode', 'h1', 'pre', '.provenance', '.bottom'].map(s => document.querySelector(s));
                    const boxes = nodes.map(node => node.getBoundingClientRect());
                    const contained = nodes.every((node, i) => boxes[i].left >= 0 && boxes[i].right <= 1280 &&
                        boxes[i].top >= 0 && boxes[i].bottom <= 720 && node.scrollWidth <= node.clientWidth);
                    return contained && boxes[0].bottom <= boxes[1].top && boxes[1].bottom <= boxes[2].top &&
                        boxes[2].bottom + 12 <= boxes[3].top && boxes[3].bottom <= boxes[4].top;
                }"""):
                    raise ReportError(ERROR)
                frame = page.screenshot(type='jpeg', quality=85, timeout=_remaining(deadline) * 1000)
                if not frame.startswith(b'\xff\xd8') or len(frame) > 1_000_000:
                    raise ReportError(ERROR)
                frames.append(frame)
        finally:
            browser.close()
    codec = _ffmpeg()
    video_path = directory / 'encoded.webm'
    duration = len(frames) * CHAPTER_SECONDS
    _run_codec([codec, '-hide_banner', '-loglevel', 'error', '-f', 'image2pipe', '-vcodec', 'mjpeg',
                '-framerate', str(FPS), '-i', 'pipe:0', '-an', '-c:v', 'libvpx', '-deadline', 'realtime',
                '-cpu-used', '8', '-threads', '2', '-pix_fmt', 'yuv420p', '-r', str(FPS),
                '-fs', str(MAX_MEDIA_BYTES + 1), '-f', 'webm', '-y', str(video_path)], deadline,
               data=b''.join(frame * (FPS * CHAPTER_SECONDS) for frame in frames))
    media = _read_file(video_path, MAX_MEDIA_BYTES)
    if not media.startswith(b'\x1a\x45\xdf\xa3'):
        raise ReportError(ERROR)
    # Bundled Playwright FFmpeg has no null muxer. Fully decode to one repeatedly
    # overwritten PNG, then verify decoder frame count, timing, and actual dimensions.
    decoded_path = directory / 'decoded.png'
    progress = _run_codec([codec, '-hide_banner', '-loglevel', 'error', '-xerror', '-err_detect', 'explode',
                           '-c:v', 'libvpx', '-i', str(video_path), '-an', '-c:v', 'png', '-f', 'image2',
                           '-update', '1', '-y', str(decoded_path), '-progress', 'pipe:1', '-nostats'], deadline).decode('ascii')
    counts = re.findall(r'^frame=(\d+)$', progress, re.M)
    timings = re.findall(r'^out_time_us=(\d+)$', progress, re.M)
    png = _read_file(decoded_path, WIDTH * HEIGHT * 4 + 65536)
    if (not png.startswith(b'\x89PNG\r\n\x1a\n') or len(png) < 24 or
            struct.unpack('>II', png[16:24]) != (WIDTH, HEIGHT) or
            not counts or int(counts[-1]) != duration * FPS or
            not timings or abs(int(timings[-1]) / 1_000_000 - duration) > 1 / FPS or
            'progress=end' not in progress):
        raise ReportError(ERROR)
    video_path.unlink()
    decoded_path.unlink()
    return media, [_digest(frame) for frame in frames]


def _root(report_db: Path, *, create: bool = False) -> Path:
    root = _path(_path(report_db, existing=True).parent / '.poc-video')
    if create:
        root.mkdir(mode=0o700, exist_ok=True)
    if root.exists() and (not root.is_dir() or root.stat().st_mode & 0o077):
        raise ReportError(ERROR)
    return root


def _read_file(path: Path, maximum: int) -> bytes:
    _path(path, existing=True)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= maximum:
            raise ReportError(ERROR)
        data = stream.read(maximum + 1)
    if not 0 < len(data) <= maximum:
        raise ReportError(ERROR)
    return data


def _read_json(path: Path) -> tuple[dict, bytes]:
    data = _read_file(path, MAX_POC_METADATA_BYTES)
    value = json.loads(data)
    if not isinstance(value, dict) or _encoded(value) != data:
        raise ReportError(ERROR)
    return value, data


def _load(root: Path, view: dict) -> tuple[dict, dict[str, bytes]]:
    folder = _path(root / view['revision_sha256'])
    if not folder.is_dir() or folder.stat().st_mode & 0o077 or set(item.name for item in folder.iterdir()) != set(_FILES):
        raise ReportError(ERROR)
    media = _read_file(folder / 'Video.webm', MAX_MEDIA_BYTES)
    storyboard, storyboard_bytes = _read_json(folder / 'Storyboard.json')
    metadata, metadata_bytes = _read_json(folder / 'Metadata.json')
    receipt, receipt_bytes = _read_json(folder / 'Integrity.json')
    files = {'Video.webm': media, 'Storyboard.json': storyboard_bytes, 'Metadata.json': metadata_bytes}
    if receipt != {name: _digest(data) for name, data in files.items()}:
        raise ReportError(ERROR)
    if not media.startswith(b'\x1a\x45\xdf\xa3') or storyboard_bytes != _encoded(_storyboard(view)):
        raise ReportError(ERROR)
    frame_hashes = metadata.get('frame_sha256')
    count = len(storyboard['chapters'])
    if (not isinstance(frame_hashes, list) or len(frame_hashes) != count or
            any(not isinstance(value, str) or not _HEX.fullmatch(value) for value in frame_hashes)):
        raise ReportError(ERROR)
    expected = _metadata(view, media, storyboard_bytes, frame_hashes)
    if metadata_bytes != _encoded(expected) or len(storyboard_bytes) + len(metadata_bytes) + len(receipt_bytes) > MAX_POC_METADATA_BYTES:
        raise ReportError(ERROR)
    return metadata, files


def _metadata(view: dict, media: bytes, storyboard: bytes, frames: list[str]) -> dict:
    return {'schema_version': 1, 'mode': MODE, 'source_revision': view['revision_sha256'],
            'filename': 'Video.webm', 'sha256': _digest(media), 'byte_size': len(media),
            'storyboard_sha256': _digest(storyboard), 'frame_sha256': frames,
            'chapters': len(frames), 'duration_seconds': len(frames) * CHAPTER_SECONDS,
            'width': WIDTH, 'height': HEIGHT, 'fps': FPS, 'verified_frames': len(frames) * CHAPTER_SECONDS * FPS,
            'codec': 'vp8', 'container': 'webm'}


def _info(status: str, metadata: dict | None = None) -> dict:
    return {'status': status, 'mode': MODE, **{key: metadata[key] if metadata else None for key in _INFO}}


@contextmanager
def _generation_lock(root: Path, deadline: float):
    try:
        import fcntl
    except ImportError:
        raise ReportError(ERROR) from None
    lock = _path(root / '.lock')
    descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ReportError(ERROR)
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                time.sleep(min(0.05, _remaining(deadline)))
        yield
    finally:
        os.close(descriptor)


def prepare_poc(report_db: Path, *, expected_revision: str | None = None) -> dict:
    """Prepare and atomically cache an offline evidence replay after automatic checks."""
    deadline = time.monotonic() + GENERATION_TIMEOUT
    try:
        view = _source(report_db, expected_revision)
        root = _root(report_db, create=True)
        with _generation_lock(root, deadline):
            view = _source(report_db, view['revision_sha256'])
            destination = _path(root / view['revision_sha256'])
            if destination.exists():
                metadata, _ = _load(root, view)
                _source(report_db, view['revision_sha256'])
                return _info('ready', metadata)
            storyboard = _storyboard(view)
            with tempfile.TemporaryDirectory(prefix='.staging-', dir=root) as name:
                staging = Path(name)
                media, frames = _render_and_encode(storyboard, staging, deadline)
                _remaining(deadline)
                if not 0 < len(media) <= MAX_MEDIA_BYTES or not media.startswith(b'\x1a\x45\xdf\xa3'):
                    raise ReportError(ERROR)
                storyboard_bytes = _encoded(storyboard)
                metadata = _metadata(view, media, storyboard_bytes, frames)
                files = {'Video.webm': media, 'Storyboard.json': storyboard_bytes, 'Metadata.json': _encoded(metadata)}
                files['Integrity.json'] = _encoded({key: _digest(value) for key, value in files.items()})
                if sum(len(value) for key, value in files.items() if key != 'Video.webm') > MAX_POC_METADATA_BYTES:
                    raise ReportError(ERROR)
                for filename, data in files.items():
                    fd = os.open(staging / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(fd, 'wb') as stream:
                        stream.write(data)
                        stream.flush()
                        os.fsync(stream.fileno())
                _source(report_db, view['revision_sha256'])
                _remaining(deadline)
                _path(destination)
                os.rename(staging, destination)
            metadata, _ = _load(root, view)
            _source(report_db, view['revision_sha256'])
            return _info('ready', metadata)
    except Exception:
        # Browser/tool stderr, source paths and captured content never enter APIs or CLI errors.
        raise ReportError(ERROR) from None


def inspect_poc(report_db: Path) -> dict:
    try:
        view = inspect_report(report_db)
        root = _root(report_db)
        if not view['ready']:
            return _info('blocked')
        if not root.exists():
            return _info('missing')
        destination = _path(root / view['revision_sha256'])
        if not destination.exists():
            return _info('stale' if any(_HEX.fullmatch(item.name) for item in root.iterdir()) else 'missing')
        metadata, _ = _load(root, view)
        _source(report_db, view['revision_sha256'])
        return _info('ready', metadata)
    except Exception:
        return _info('blocked')


def _read_poc_files(report_db: Path, *, expected_revision: str) -> tuple[dict, dict[str, bytes]]:
    try:
        view = _source(report_db, expected_revision)
        metadata, files = _load(_root(report_db), view)
        _source(report_db, expected_revision)
        return metadata, files
    except Exception:
        raise ReportError(ERROR) from None


def read_poc_video(report_db: Path, *, expected_revision: str) -> tuple[dict, bytes]:
    """Read only a verified cache for the current revision; never render on GET."""
    metadata, files = _read_poc_files(report_db, expected_revision=expected_revision)
    return metadata, files['Video.webm']
