"""Program URL identification and artifact path resolution."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit


class ScopePathError(ValueError):
    pass


@dataclass(frozen=True)
class ProgramScopePath:
    platform: str
    program: str

    def under(self, root: Path | str) -> Path:
        return Path(root) / self.platform / self.program


def identify_program(program_url: str) -> ProgramScopePath:
    parsed = urlsplit(program_url)
    host = (parsed.hostname or "").lower().removeprefix("www.")
    segments = [unquote(segment) for segment in parsed.path.split("/") if segment]
    if parsed.scheme != "https" or not host:
        raise ScopePathError("program URL must be an absolute HTTPS URL")

    if host == "hackerone.com" or host.endswith(".hackerone.com"):
        platform = "hackerone"
        program = _segment_at(segments, 0, "HackerOne program handle")
    elif host == "bugcrowd.com" or host.endswith(".bugcrowd.com"):
        platform = "bugcrowd"
        if len(segments) < 2 or segments[0].lower() != "engagements":
            raise ScopePathError(
                "Bugcrowd program URL must contain /engagements/<program>"
            )
        program = segments[1]
    elif host == "yeswehack.com" or host.endswith(".yeswehack.com"):
        platform = "yeswehack"
        if len(segments) < 2 or segments[0].lower() != "programs":
            raise ScopePathError(
                "YesWeHack program URL must contain /programs/<program>"
            )
        program = segments[1]
    else:
        platform = _slug(host.replace(".", "-"), "platform hostname")
        program = _segment_at(segments, -1, "program path")

    return ProgramScopePath(
        platform=_slug(platform, "platform"),
        program=_slug(program, "program"),
    )


def resolve_scope_directory(program_url: str, root: Path | str = "Scope") -> Path:
    return identify_program(program_url).under(root)


def _segment_at(segments: list[str], index: int, label: str) -> str:
    try:
        return segments[index]
    except IndexError as exc:
        raise ScopePathError(f"program URL is missing its {label}") from exc


def _slug(value: str, label: str) -> str:
    normalized = re.sub(r"[^a-z0-9._-]+", "-", value.casefold()).strip("-._")
    if not normalized or normalized in {".", ".."}:
        raise ScopePathError(f"program URL has an invalid {label}")
    return normalized


_SCOPE_REVISION_ID = re.compile(r'^scopejob_[0-9a-f]{32}$')


def validate_scope_artifact_directory(directory: Path, root: Path) -> Path:
    """Accept only canonical archives or app-owned revisions without symlinks."""
    root = root.absolute()
    directory = directory.absolute()
    try:
        parts = directory.relative_to(root).parts
    except ValueError as exc:
        raise ScopePathError('Scope destination path is outside the Scope root') from exc
    if not (len(parts) == 2 or (len(parts) == 4 and parts[2] == 'revisions'
                               and _SCOPE_REVISION_ID.fullmatch(parts[3]))):
        raise ScopePathError('Scope destination path has an invalid archive layout')
    if any(part in {'.', '..'} for part in parts):
        raise ScopePathError('Scope destination path cannot contain relative segments')
    current = root
    for part in ('', *parts):
        if part:
            current = current / part
        if current.is_symlink():
            raise ScopePathError('Scope destination path must not contain a symbolic link')
    if directory.resolve(strict=False) != directory:
        raise ScopePathError('Scope destination path must not contain a symbolic link or alias')
    return directory


def scope_revision_directory(program_url: str, root: Path, revision: str | None = None) -> Path:
    directory = identify_program(program_url).under(root)
    if revision is not None:
        if not _SCOPE_REVISION_ID.fullmatch(revision):
            raise ScopePathError('Scope revision must be an application-owned job ID')
        directory = directory / 'revisions' / revision
    return validate_scope_artifact_directory(directory, root)


def scope_archive_directories(root: Path):
    """Bounded-depth discovery; only the original two-level identity is used."""
    if not root.is_dir():
        return
    for pattern in ('*/*/Scope.json', '*/*/revisions/scopejob_*/Scope.json'):
        for scope_json in root.glob(pattern):
            try:
                directory = validate_scope_artifact_directory(scope_json.parent, root)
                if any((directory / name).is_symlink() for name in
                       ('Scope.json', 'Scope.md', 'Manifest.json', 'Approval.json')):
                    continue
                yield directory
            except (OSError, ValueError):
                continue
