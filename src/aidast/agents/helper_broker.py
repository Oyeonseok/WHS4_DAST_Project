"""Authenticated local broker for policy-checked native-agent helper calls."""

from __future__ import annotations

import json
import os
import secrets
import socket
import subprocess
import sys
import threading
from pathlib import Path
from typing import Literal, Self

PIPELINE_DATABASE_TOKEN = "broker://pipeline"
HelperName = Literal["attack_db", "attack_request", "chaining_db"]
_HELPER_MODULES: dict[HelperName, str] = {
    "attack_db": "aidast.attack.db_cli",
    "attack_request": "aidast.attack.request_cli",
    "chaining_db": "aidast.chaining.db_cli",
}
_MAX_MESSAGE_BYTES = 64 * 1024
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class HelperBrokerError(RuntimeError):
    """The trusted helper broker rejected or failed one command."""


class HelperCommandBroker:
    """Run allowlisted packaged helpers outside the Codex sandbox."""

    def __init__(
        self,
        *,
        database: Path,
        work_dir: Path,
        python_executable: Path,
    ) -> None:
        self.database = database.expanduser().resolve(strict=True)
        self.work_dir = work_dir.expanduser().resolve(strict=True)
        self.python_executable = python_executable.expanduser().resolve(strict=True)
        self.socket_path = self.work_dir / ".aidast-helper.sock"
        self.token = secrets.token_urlsafe(32)
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._errors: list[Exception] = []
        self._thread = threading.Thread(
            target=self._serve,
            name="aidast-helper-broker",
            daemon=True,
        )

    def __enter__(self) -> Self:
        self.start()
        return self

    def start(self) -> None:
        self._thread.start()
        if not self._ready.wait(timeout=5):
            raise HelperBrokerError("helper broker did not start")
        if self._errors:
            raise HelperBrokerError(
                f"helper broker failed to start: {self._errors[0]}"
            )

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self._stop.set()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as wake:
                wake.connect(str(self.socket_path))
        except OSError:
            pass
        self._thread.join(timeout=5)
        self.socket_path.unlink(missing_ok=True)
        if self._errors:
            raise HelperBrokerError(f"helper broker failed: {self._errors[0]}")

    def prepare_arguments(self, arguments: list[str]) -> list[str]:
        """Replace the opaque DB token and reject host paths."""
        if (
            not arguments
            or len(arguments) > 64
            or any(not isinstance(value, str) or len(value) > 16_384 for value in arguments)
        ):
            raise ValueError("invalid helper argument list")
        prepared: list[str] = []
        path_flags = {"--payload", "--policy", "--sql-file"}

        def checked_path(value: str) -> str:
            candidate = Path(value).expanduser()
            resolved = (
                candidate if candidate.is_absolute() else self.work_dir / candidate
            ).resolve(strict=False)
            if not resolved.is_relative_to(self.work_dir):
                raise ValueError("helper path is outside the staged work directory")
            return value

        for index, value in enumerate(arguments):
            equals_flag, separator, equals_value = value.partition("=")
            if separator and equals_flag == "--db":
                if equals_value != PIPELINE_DATABASE_TOKEN:
                    raise ValueError("helper database must use the broker token")
                prepared.append(f"--db={self.database}")
                continue
            if separator and equals_flag in path_flags:
                prepared.append(f"{equals_flag}={checked_path(equals_value)}")
                continue
            if value == PIPELINE_DATABASE_TOKEN:
                if index == 0 or arguments[index - 1] != "--db":
                    raise ValueError("unexpected helper database token")
                prepared.append(str(self.database))
                continue
            if index > 0 and arguments[index - 1] == "--db":
                raise ValueError("helper database must use the broker token")
            candidate = Path(value).expanduser()
            if candidate.is_absolute() or (
                index > 0 and arguments[index - 1] in path_flags
            ):
                checked_path(value)
            prepared.append(value)
        return prepared

    def _serve(self) -> None:
        try:
            self.socket_path.unlink(missing_ok=True)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(str(self.socket_path))
                self.socket_path.chmod(0o600)
                server.listen(8)
                server.settimeout(0.2)
                self._ready.set()
                while not self._stop.is_set():
                    try:
                        connection, _ = server.accept()
                    except TimeoutError:
                        continue
                    with connection:
                        if self._stop.is_set():
                            break
                        self._handle(connection)
        except OSError as exc:
            self._errors.append(exc)
            self._ready.set()

    def _handle(self, connection: socket.socket) -> None:
        try:
            request = json.loads(_receive(connection).decode("utf-8"))
            if (
                not isinstance(request, dict)
                or request.get("token") != self.token
                or request.get("helper") not in _HELPER_MODULES
                or not isinstance(request.get("arguments"), list)
            ):
                raise ValueError("invalid helper broker request")
            helper: HelperName = request["helper"]
            arguments = self.prepare_arguments(request["arguments"])
            completed = subprocess.run(
                [
                    str(self.python_executable),
                    "-m",
                    _HELPER_MODULES[helper],
                    *arguments,
                ],
                cwd=self.work_dir,
                env={
                    **os.environ,
                    "PYTHONPATH": os.pathsep.join(
                        value for value in sys.path if isinstance(value, str)
                    ),
                },
                text=True,
                capture_output=True,
                timeout=180,
                check=False,
            )
            response = {
                "returncode": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
            }
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            response = {
                "returncode": 1,
                "stdout": "",
                "stderr": f"aidast-helper: {exc}\n",
            }
        raw_response = json.dumps(response).encode("utf-8")
        if len(raw_response) > _MAX_RESPONSE_BYTES:
            raw_response = json.dumps(
                {
                    "returncode": 1,
                    "stdout": "",
                    "stderr": "aidast-helper: helper response is too large\n",
                }
            ).encode("utf-8")
        try:
            connection.sendall(raw_response)
        except OSError:
            if not self._stop.is_set():
                raise


def _receive(connection: socket.socket) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = connection.recv(min(8192, _MAX_MESSAGE_BYTES - total + 1))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > _MAX_MESSAGE_BYTES:
            raise ValueError("helper broker request is too large")
    return b"".join(chunks)


def stage_helper_client(
    path: Path,
    *,
    broker: HelperCommandBroker,
    helper: HelperName,
) -> Path:
    """Write a narrow client that can invoke exactly one allowlisted helper."""
    if helper not in _HELPER_MODULES:
        raise ValueError("unsupported helper")
    script = f'''"""Generated AI-Dast helper client."""
import json
import socket
import sys

request = {{
    "token": {broker.token!r},
    "helper": {helper!r},
    "arguments": sys.argv[1:],
}}
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.connect({str(broker.socket_path)!r})
    client.sendall(json.dumps(request).encode("utf-8"))
    client.shutdown(socket.SHUT_WR)
    chunks = []
    total = 0
    while True:
        chunk = client.recv(8192)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > {_MAX_RESPONSE_BYTES}:
            raise RuntimeError("helper response is too large")
    response = json.loads(b"".join(chunks).decode("utf-8"))
sys.stdout.write(response["stdout"])
sys.stderr.write(response["stderr"])
raise SystemExit(response["returncode"])
'''
    path.write_text(script, encoding="utf-8")
    return path
