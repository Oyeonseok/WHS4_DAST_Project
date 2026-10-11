"""Immutable, bounded model choices for a single local scan.

Only model identifiers are persisted here. Scope, credentials, environment
variables, and commands remain in their existing independently checked stores.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


MODEL_SETTINGS_FILE = "Models.json"
MAX_SETTINGS_BYTES = 8192
_SCAN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
ModelIdentifier = Annotated[str, Field(strict=True, min_length=1, max_length=128,
                                     pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")]


class ScanModelChoices(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, revalidate_instances="always")

    main_model: ModelIdentifier
    recon_model: ModelIdentifier
    attack_model: ModelIdentifier
    chaining_model: ModelIdentifier
    validation_model: ModelIdentifier
    report_model: ModelIdentifier

    @field_validator("main_model", "recon_model", "attack_model", "chaining_model",
                     "validation_model", "report_model")
    @classmethod
    def identifier_not_url(cls, value: str) -> str:
        if "://" in value:
            raise ValueError("model must be an identifier, not a URL")
        return value

    @classmethod
    def resolve(cls, *, recon_model: str | None = None, attack_model: str | None = None,
                validation_model: str | None = None, report_model: str | None = None) -> ScanModelChoices:
        from aidast.agents.native_pipeline import CodexMainAgent, RECON_MODEL

        recon = recon_model if recon_model is not None else RECON_MODEL
        attack = attack_model if attack_model is not None else CodexMainAgent.DEFAULT_ATTACK_MODEL
        return cls(main_model=recon, recon_model=recon, attack_model=attack,
                   chaining_model=attack_model if attack_model is not None else CodexMainAgent.DEFAULT_CHAINING_MODEL,
                   validation_model=validation_model if validation_model is not None else CodexMainAgent.DEFAULT_VALIDATION_MODEL,
                   report_model=report_model if report_model is not None else CodexMainAgent.DEFAULT_MAIN_MODEL)

    def agent_options(self) -> dict[str, str]:
        return {name: getattr(self, name) for name in
                ("main_model", "attack_model", "chaining_model", "validation_model")}


class _ScanModelRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    scan_id: Annotated[str, Field(strict=True, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")]
    models: ScanModelChoices


def _settings_path(path: Path, *, existing: bool = False) -> Path:
    candidate = Path(path).expanduser().absolute()
    # Resolve only macOS's fixed OS temp aliases; reject caller-created links.
    for alias in (Path("/var"), Path("/tmp")):
        if alias.is_symlink() and candidate.is_relative_to(alias):
            candidate = alias.resolve(strict=True) / candidate.relative_to(alias)
            break
    if any(item.is_symlink() for item in (candidate, *candidate.parents)):
        raise ValueError("scan model settings must not traverse symlinks")
    candidate = candidate.resolve(strict=existing)
    if existing and not candidate.is_file():
        raise ValueError("scan model settings require a regular file")
    return candidate


def scan_model_settings_path(result_root: Path, scan_id: str) -> Path:
    if not _SCAN_ID.fullmatch(scan_id):
        raise ValueError("invalid scan identifier")
    return _settings_path(Path(result_root) / ".webui" / "scan-models" / f"{scan_id}.json")


def read_scan_model_choices(path: Path, *, scan_id: str) -> ScanModelChoices:
    source = _settings_path(path, existing=True)
    with source.open("rb") as stream:
        raw = stream.read(MAX_SETTINGS_BYTES + 1)
    if len(raw) > MAX_SETTINGS_BYTES:
        raise ValueError("scan model settings exceed the size limit")
    try:
        record = _ScanModelRecord.model_validate_json(raw)
    except ValueError as exc:
        raise ValueError("invalid scan model settings") from exc
    if record.scan_id != scan_id:
        raise ValueError("scan model settings belong to a different scan")
    return record.models


def load_scan_model_choices(result_root: Path, scan_id: str) -> ScanModelChoices | None:
    path = scan_model_settings_path(result_root, scan_id)
    # lexists distinguishes a missing record from a broken symlink.
    if not os.path.lexists(path):
        return None
    return read_scan_model_choices(path, scan_id=scan_id)


def write_scan_model_choices(path: Path, *, scan_id: str, models: ScanModelChoices) -> Path:
    """Publish once; retries with identical choices are safe and idempotent."""
    target = _settings_path(path)
    try:
        record = _ScanModelRecord(scan_id=scan_id, models=models)
    except ValueError as exc:
        raise ValueError("invalid scan model settings") from exc
    if target.exists():
        if read_scan_model_choices(target, scan_id=scan_id) != models:
            raise ValueError("initial scan model choices cannot be changed")
        return target
    encoded = json.dumps(record.model_dump(mode="json"), ensure_ascii=False,
                         sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n"
    if len(encoded) > MAX_SETTINGS_BYTES:
        raise ValueError("scan model settings exceed the size limit")
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    handle, name = tempfile.mkstemp(prefix=".scan-models-", dir=target.parent)
    staging = Path(name)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(staging, target)
        except FileExistsError:
            if read_scan_model_choices(target, scan_id=scan_id) != models:
                raise ValueError("initial scan model choices cannot be changed") from None
    finally:
        staging.unlink(missing_ok=True)
    return target
