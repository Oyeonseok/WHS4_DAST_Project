"""Isolated, verifiable Scope worker processes for dashboard controls."""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path
from uuid import uuid4


class ScopeProcessController:
    def __init__(
        self,
        result_root: Path,
        *,
        project_root: Path | None = None,
        worker_module: str = "aidast.web.scope_worker",
    ) -> None:
        self.result_root = result_root.resolve()
        self.project_root = (project_root or Path.cwd()).resolve()
        self.worker_module = worker_module

    def _marker(self, job_id: str) -> Path:
        if re.fullmatch(r"scopejob_[0-9a-f]{32}", job_id) is None:
            raise ValueError("invalid Scope job identifier")
        return self.result_root / ".webui" / "scope-processes" / f"{job_id}.json"

    @staticmethod
    def _process_stat(pid: int) -> tuple[str, str]:
        fields = Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1].split()
        return fields[0], fields[19]

    def start(
        self, job_id: str, program_id: str, request_json: str
    ) -> subprocess.Popen[str]:
        if os.name != "posix":
            raise OSError("Scope process controls require a POSIX host")
        env = os.environ.copy()
        env["AIDAST_RESULT_ROOT"] = str(self.result_root)
        source_root = self.project_root / "src"
        if source_root.is_dir():
            previous = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = str(source_root) + (
                os.pathsep + previous if previous else ""
            )
        process = subprocess.Popen(
            [
                sys.executable, "-m", self.worker_module,
                str(self.result_root), program_id, job_id,
            ],
            cwd=self.project_root,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            start_new_session=True,
        )
        try:
            if os.getpgid(process.pid) != process.pid:
                raise OSError("Scope worker did not start in an isolated session")
            _state, started = self._process_stat(process.pid)
            marker = self._marker(job_id)
            marker.parent.mkdir(parents=True, exist_ok=True)
            temporary = marker.with_name(f".{marker.name}.{uuid4().hex}.tmp")
            temporary.write_text(
                json.dumps({
                    "pid": process.pid, "started": started,
                    "program_id": program_id,
                }),
                encoding="utf-8",
            )
            os.chmod(temporary, 0o600)
            temporary.replace(marker)
            if process.stdin is None:
                raise OSError("Scope worker input pipe is unavailable")
            process.stdin.write(request_json)
            process.stdin.close()
        except Exception:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            self.forget(job_id)
            raise
        return process

    def pid(self, job_id: str) -> int | None:
        if os.name != "posix":
            return None
        try:
            marker = json.loads(self._marker(job_id).read_text(encoding="utf-8"))
            pid, started = marker["pid"], marker["started"]
            program_id = marker["program_id"]
            if type(pid) is not int or pid < 2 or not isinstance(started, str):
                return None
            if not isinstance(program_id, str):
                return None
            state, current_start = self._process_stat(pid)
            if state == "Z" or current_start != started or os.getpgid(pid) != pid:
                return None
            entry = Path(f"/proc/{pid}")
            if Path(os.readlink(entry / "cwd")).resolve() != self.project_root:
                return None
            args = [
                value.decode("utf-8", "replace")
                for value in (entry / "cmdline").read_bytes().split(b"\0")
                if value
            ]
            if args[1:] != [
                "-m", self.worker_module, str(self.result_root),
                program_id, job_id,
            ]:
                return None
            return pid
        except (OSError, ValueError, KeyError, IndexError, TypeError):
            return None

    def signal(self, job_id: str, signum: int) -> int:
        pid = self.pid(job_id)
        if pid is None:
            raise ValueError("Scope job has no isolated active worker")
        os.killpg(pid, signum)
        return pid

    def forget(self, job_id: str) -> None:
        self._marker(job_id).unlink(missing_ok=True)

    def wait_for_exit(self, job_id: str, *, timeout_seconds: float) -> bool:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if self.pid(job_id) is None:
                return True
            time.sleep(0.1)
        return self.pid(job_id) is None
