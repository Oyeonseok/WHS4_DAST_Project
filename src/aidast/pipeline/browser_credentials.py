"""Bind a verified Recon browser snapshot to an opaque Pipeline credential."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import sqlite3
from pathlib import Path
from urllib.parse import urlsplit

from aidast.pipeline.lifecycle import register_credential_reference
from aidast.recon import db as recon_db
from aidast.recon.tools.playwright_driver import ManualSessionConfig, PlaywrightDriver


_SCAN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_DIGEST = re.compile(r"[0-9a-f]{24}\Z")
_IDENTITY_ROLE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_AUTH_COOKIE = re.compile(
    r"(?:^|[._-])(?:session|sessionid|sessid|sid|auth|token|jwt|login|logged_in|access)"
    r"(?:$|[._-])|^(?:PHPSESSID|JSESSIONID)$", re.I,
)


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("invalid browser session origin")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    host = parsed.hostname.lower()
    return f"{parsed.scheme}://{host}:{port}"


def _origin_key(value: str) -> str:
    return hashlib.sha256(_origin(value).encode()).hexdigest()[:24]


def _session_key(value: str, identity_role: str) -> str:
    """Return a stable snapshot key while retaining legacy primary paths."""
    if identity_role == "authenticated":
        return _origin_key(value)
    return hashlib.sha256(
        f"{_origin(value)}\0{identity_role}".encode()
    ).hexdigest()[:24]


def _snapshot_path(result_root: Path, scan_id: str, origin_key: str) -> Path:
    return (result_root / ".aidast_sessions" /
            hashlib.sha256(scan_id.encode()).hexdigest()[:24] /
            "attack" / f"{origin_key}.json")


def _snapshot_headers(path: Path, origin_url: str) -> dict[str, str]:
    driver = PlaywrightDriver(
        origin_url,
        ManualSessionConfig(login_url=origin_url, session_file=str(path)),
    )
    return driver.get_auth_headers()


def _has_auth_material(headers: dict[str, str]) -> bool:
    if any(name.casefold() != "cookie" for name in headers):
        return True
    cookie = next((value for name, value in headers.items() if name.casefold() == "cookie"), "")
    return any(
        _AUTH_COOKIE.search(part.partition("=")[0].strip()) is not None
        for part in cookie.split(";") if "=" in part
    )


def register_browser_session_credentials(
    conn: sqlite3.Connection, *, scan_id: str, result_root: Path,
    sessions: list[
        tuple[str, Path, bool]
        | tuple[str, Path, bool, str]
    ],
) -> list[dict[str, str]]:
    """Persist opaque references for authenticated, same-scan browser snapshots.

    A three-item input keeps the original single-account ``authenticated`` role.
    A four-item input supplies a stable identity role (for example ``identity_b``),
    allowing two authorized test accounts on the same origin to remain isolated.
    """
    if not _SCAN.fullmatch(scan_id):
        raise ValueError("invalid scan identifier")
    root = result_root.expanduser().resolve()
    origins = conn.execute(
        """SELECT o.origin_id,o.base_url FROM origins o JOIN assets a ON a.asset_id=o.asset_id
           WHERE a.scan_id=?""", (scan_id,),
    ).fetchall()
    references: list[dict[str, str]] = []
    seen_sessions: set[tuple[str, str]] = set()
    for raw_session in sessions:
        if len(raw_session) == 3:
            origin_url, source, authenticated = raw_session
            identity_role = "authenticated"
        else:
            origin_url, source, authenticated, identity_role = raw_session
        if not isinstance(identity_role, str) or not _IDENTITY_ROLE.fullmatch(identity_role):
            raise ValueError("invalid browser session identity role")
        if not authenticated:
            continue
        canonical = _origin(origin_url)
        session_key = (canonical, identity_role)
        if session_key in seen_sessions:
            continue
        matching = [row for row in origins if _origin(str(row[1])) == canonical]
        if not matching:
            raise ValueError("authenticated session has no Recon origin")
        source = Path(source).expanduser().resolve(strict=True)
        key = _session_key(origin_url, identity_role)
        destination = _snapshot_path(root, scan_id, key)
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not destination.parent.resolve().is_relative_to((root / ".aidast_sessions").resolve()):
            raise ValueError("browser snapshot escapes the result root")
        shutil.copyfile(source, destination)
        destination.chmod(0o600)
        source_storage = Path(str(source) + ".sessionstorage.json")
        destination_storage = Path(str(destination) + ".sessionstorage.json")
        if source_storage.is_file():
            shutil.copyfile(source_storage, destination_storage)
            destination_storage.chmod(0o600)
        else:
            destination_storage.unlink(missing_ok=True)
        headers = _snapshot_headers(destination, origin_url)
        confirmed_login = Path(str(source) + ".authenticated").is_file()
        has_non_cookie_header = any(name.casefold() != "cookie" for name in headers)
        if not _has_auth_material(headers) or (not has_non_cookie_header and not confirmed_login):
            destination.unlink(missing_ok=True)
            Path(str(destination) + ".sessionstorage.json").unlink(missing_ok=True)
            continue
        origin_id = str(sorted(matching, key=lambda row: str(row[0]))[0][0])
        row = conn.execute(
            "SELECT session_id FROM sessions WHERE origin_id=? ORDER BY rowid DESC LIMIT 1",
            (origin_id,),
        ).fetchone()
        if row is None:
            session_id = recon_db.new_id("session")
            conn.execute(
                "INSERT INTO sessions(session_id,origin_id,auth_state,isolation_scope) VALUES (?,?,?,?)",
                (session_id, origin_id, "authenticated", "recon_browser"),
            )
        else:
            session_id = str(row[0])
            conn.execute("UPDATE sessions SET auth_state='authenticated' WHERE session_id=?", (session_id,))
        label = f"recon-browser:{origin_id}"
        if identity_role != "authenticated":
            label += f":{identity_role}"
        reference_uri = f"vault://aidast-browser-session/{scan_id}/{key}"
        existing = conn.execute(
            """SELECT credential_reference_id,reference_uri FROM credential_references
               WHERE scan_id=? AND label=?""", (scan_id, label),
        ).fetchone()
        if existing is not None:
            if str(existing[1]) != reference_uri:
                raise ValueError("browser credential label is bound to another origin")
            reference_id = str(existing[0])
            conn.execute(
                """UPDATE credential_references SET session_id=?,identity_role=?
                   WHERE credential_reference_id=?""",
                (session_id, identity_role, reference_id),
            )
        else:
            reference_id = register_credential_reference(
                conn, scan_id=scan_id, session_id=session_id,
                label=label, identity_role=identity_role, reference_uri=reference_uri,
            )
        references.append({
            "credential_reference_id": reference_id,
            "label": label,
            "identity_role": identity_role,
        })
        seen_sessions.add(session_key)
    return references


class BrowserSessionCredentialBackend:
    """Resolve one recorded origin's private snapshot at request dispatch time."""

    def __init__(self, db_path: Path, result_root: Path) -> None:
        self.db_path = Path(db_path)
        self.result_root = Path(result_root).expanduser().resolve()

    def __call__(self, uri: str, *, destination_url: str | None = None) -> dict[str, str]:
        parsed = urlsplit(uri)
        parts = parsed.path.strip("/").split("/")
        if (parsed.scheme != "vault" or parsed.netloc != "aidast-browser-session"
                or parsed.query or parsed.fragment or len(parts) != 2
                or not _SCAN.fullmatch(parts[0]) or not _DIGEST.fullmatch(parts[1])):
            raise ValueError("invalid browser session reference")
        scan_id, key = parts
        with sqlite3.connect(self.db_path.resolve().as_uri() + "?mode=ro", uri=True) as conn:
            rows = conn.execute(
                """SELECT o.base_url,c.label,c.identity_role FROM credential_references c
                   JOIN sessions s ON s.session_id=c.session_id
                   JOIN origins o ON o.origin_id=s.origin_id
                   JOIN assets a ON a.asset_id=o.asset_id
                   WHERE c.reference_uri=? AND c.scan_id=? AND a.scan_id=?
                     AND s.auth_state='authenticated'""",
                (uri, scan_id, scan_id),
            ).fetchall()
        bound_origins = {_origin(str(row[0])) for row in rows}
        valid_keys = {
            _origin_key(str(row[0])) if str(row[2]) == "authenticated"
            else _session_key(str(row[0]), str(row[2]))
            for row in rows
        }
        if (len(bound_origins) != 1 or valid_keys != {key}
                or destination_url is None or _origin(destination_url) not in bound_origins):
            raise ValueError("browser session reference is not bound to this origin")
        snapshot = _snapshot_path(self.result_root, scan_id, key)
        if (snapshot.is_symlink() or not snapshot.is_file()
                or not snapshot.resolve().is_relative_to((self.result_root / ".aidast_sessions").resolve())):
            raise ValueError("browser session snapshot is unavailable")
        if os.name == "posix" and snapshot.stat().st_mode & 0o077:
            raise ValueError("browser session snapshot is not private")
        headers = _snapshot_headers(snapshot, str(rows[0][0]))
        if not _has_auth_material(headers):
            raise ValueError("browser session has no authentication material")
        return headers
