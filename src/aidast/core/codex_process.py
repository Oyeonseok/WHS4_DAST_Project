"""Synchronous Codex execution with independent total, idle and tool deadlines.

Regular-file spools deliberately replace subprocess pipes: both output streams can
advance while Codex reads a large prompt, and inherited handles cannot strand a
reader thread on cancellation. Only the monitor reads the stdout spool.
"""

from __future__ import annotations

import codecs
import io
import json
import os
import signal
import subprocess
import tempfile
from pathlib import Path
from time import monotonic as _monotonic
from typing import BinaryIO, Final, Literal, TextIO, assert_never

DEFAULT_CODEX_TIMEOUT_SECONDS: Final = 3600
CODEX_IDLE_TIMEOUT_SECONDS: Final = 900
CODEX_TOOL_TIMEOUT_SECONDS: Final = 900
# A native orchestrator waiting for its child is not itself a stuck finite tool.
DEFAULT_TOOL_TIMEOUT_EXEMPTIONS: Final = frozenset({"collab_tool_call.wait"})
_MONITOR_INTERVAL_SECONDS: Final = 0.1
_TOOL_TYPES: Final = frozenset({
    "command_execution", "mcp_tool_call", "web_search", "collab_tool_call",
})
_ITEM_TYPES: Final = _TOOL_TYPES | {
    "agent_message", "reasoning", "file_change", "todo_list",
}
type TimeoutReason = Literal["total", "idle", "tool"]


class CodexProcessTimeout(subprocess.TimeoutExpired):
    """A deadline violation, retaining subprocess-compatible output fields."""

    def __init__(
        self, command: list[str], timeout: float, *, reason: TimeoutReason,
        output: str | None = None, stderr: str = "", tool_id: str | None = None,
        tool_name: str | None = None,
    ) -> None:
        super().__init__(command, timeout, output=output, stderr=stderr)
        self.reason = reason
        self.tool_id = tool_id
        self.tool_name = tool_name

    def __str__(self) -> str:
        match self.reason:
            case "total":
                return f"Codex 전체 실행 제한({self.timeout:g}초)을 초과했습니다."
            case "idle":
                return f"Codex 진행 이벤트가 {self.timeout:g}초 동안 없어 실행을 중단했습니다."
            case "tool":
                return (
                    f"Codex 개별 도구 실행 제한({self.timeout:g}초)을 초과했습니다: "
                    f"{self.tool_name} [item_id={self.tool_id}]"
                )
            case unreachable:
                assert_never(unreachable)


class _Progress:
    """Accumulate genuine event changes; tool start times are never refreshed."""

    def __init__(
        self, started: float, timeout: float, idle_timeout: float,
        tool_timeout: float, tool_timeout_exemptions: frozenset[str],
    ) -> None:
        self.total_deadline = started + timeout
        self.last_progress = started
        self.idle_timeout = idle_timeout
        self.tool_timeout = tool_timeout
        self.exemptions = tool_timeout_exemptions
        self.active: dict[str, tuple[float, str, bool]] = {}
        self.items: dict[str, tuple[str, str]] = {}
        self.thread_id: str | None = None
        self.turn_state: str | None = None

    def observe(self, line: str, now: float) -> None:
        try:
            event = json.loads(line)
        except (json.JSONDecodeError, RecursionError):
            return
        if not isinstance(event, dict) or event.get("error"):
            return
        kind = event.get("type")
        if kind == "thread.started":
            thread_id = event.get("thread_id")
            if not isinstance(thread_id, str) or not thread_id or thread_id == self.thread_id:
                return
            self.thread_id = thread_id
        elif kind in ("turn.started", "turn.completed"):
            if self.turn_state == kind:
                return
            self.turn_state = kind
        elif kind in ("item.started", "item.updated", "item.completed"):
            item = event.get("item")
            if not isinstance(item, dict):
                return
            item_id, item_type = item.get("id"), item.get("type")
            if (
                not isinstance(item_id, str) or not item_id
                or not isinstance(item_type, str) or item_type not in _ITEM_TYPES
            ):
                return
            fingerprint = json.dumps(item, sort_keys=True, ensure_ascii=False)
            previous = self.items.get(item_id)
            if previous == (kind, fingerprint) or (
                kind == "item.updated" and previous is not None and previous[1] == fingerprint
            ):
                return
            self.items[item_id] = (kind, fingerprint)
            if kind == "item.completed":
                self.active.pop(item_id, None)
            elif item_type in _TOOL_TYPES and item_id not in self.active:
                tool = item.get("tool")
                name = f"{item_type}.{tool}" if isinstance(tool, str) else item_type
                self.active[item_id] = (now, name, name in self.exemptions)
        else:
            return
        self.last_progress = now

    def deadline(self) -> tuple[float, TimeoutReason, str | None]:
        deadlines: list[tuple[float, TimeoutReason, str | None]] = [
            (self.total_deadline, "total", None),
            (self.last_progress + self.idle_timeout, "idle", None),
        ]
        deadlines.extend(
            (started + self.tool_timeout, "tool", item_id)
            for item_id, (started, _name, exempt) in self.active.items() if not exempt
        )
        return min(deadlines, key=lambda entry: entry[0])


class _Output:
    """Incrementally decode UTF-8 and deliver complete, unchanged JSONL lines."""

    def __init__(self, source: BinaryIO, sink: TextIO) -> None:
        self.source = source
        self.sink = sink
        self.decoder = codecs.getincrementaldecoder("utf-8")()
        self.pending = ""

    def drain(self, *, final: bool = False) -> list[str]:
        # A snapshot bounds the final read even if a descendant still has a handle.
        size = os.fstat(self.source.fileno()).st_size - self.source.tell()
        raw = self.source.read(size if final else min(size, 1024 * 1024))
        self.pending += self.decoder.decode(raw, final=final)
        pieces = self.pending.split("\n")
        self.pending = pieces.pop()
        lines = [piece + "\n" for piece in pieces]
        if final and self.pending:
            lines.append(self.pending)
            self.pending = ""
        for line in lines:
            self.sink.write(line)
        if lines:
            self.sink.flush()
        return lines


def _wait_for_update(process: subprocess.Popen[bytes], delay: float) -> None:
    """Narrow clock/wait seam: file spools never require blocked pipe readers."""
    try:
        process.wait(timeout=min(delay, _MONITOR_INTERVAL_SECONDS))
    except subprocess.TimeoutExpired:
        return


def _kill_process_tree(process: subprocess.Popen[bytes]) -> None:
    """Terminate Codex descendants and reap the direct child without reader waits."""
    try:
        if os.name == "nt":
            import psutil

            # Windows retains parent PIDs after exit. Scanning also finds children
            # when the root has already exited and Process.children() cannot run.
            processes = list(psutil.process_iter(["pid", "ppid"]))
            parents = {process.pid}
            descendants = []
            while parents:
                children = [child for child in processes if child.info["ppid"] in parents]
                descendants.extend(children)
                parents = {child.pid for child in children}
                processes = [child for child in processes if child.pid not in parents]
            for child in reversed(descendants):
                try:
                    child.kill()
                except psutil.NoSuchProcess:
                    continue
            if process.poll() is None:
                process.kill()
            _gone, alive = psutil.wait_procs(descendants, timeout=5)
            if alive:
                raise OSError(f"Codex descendants did not exit: {[child.pid for child in alive]}")
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                # The whole group has already exited, not a cleanup failure.
                return
    finally:
        process.wait(timeout=5)


def run_codex(
    command: list[str], *, input: str, timeout: float, stdout: TextIO | None = None,
    idle_timeout: float = CODEX_IDLE_TIMEOUT_SECONDS,
    tool_timeout: float = CODEX_TOOL_TIMEOUT_SECONDS,
    tool_timeout_exemptions: frozenset[str] = DEFAULT_TOOL_TIMEOUT_EXEMPTIONS,
) -> subprocess.CompletedProcess[str]:
    """Run Codex without resetting its absolute cap on progress.

    ``stdout`` receives exact JSONL lines and remains caller-owned; when supplied,
    CompletedProcess.stdout is None, as with subprocess.run's redirected output.
    Exemptions use ``<item type>.<tool>`` names. Only collaboration ``wait`` is
    exempt by default, and idle/total limits still apply to it.
    """
    started = _monotonic()
    progress = _Progress(started, timeout, idle_timeout, tool_timeout, tool_timeout_exemptions)
    # A dedicated group retains descendants after Codex exits. Keep the worker
    # session so dashboard session-wide controls still pause or cancel all work.
    captured = io.StringIO() if stdout is None else stdout
    expired: tuple[TimeoutReason, str | None] | None = None
    with tempfile.TemporaryDirectory(prefix="aidast-codex-process-") as directory:
        root = Path(directory)
        with (
            (root / "stdin").open("w+b") as prompt,
            (root / "stdout").open("wb") as out_writer,
            (root / "stderr").open("w+b") as errors,
            (root / "stdout").open("rb") as out_reader,
        ):
            prompt.write(input.encode("utf-8"))
            prompt.seek(0)
            process = subprocess.Popen(
                command, stdin=prompt, stdout=out_writer, stderr=errors,
                process_group=0 if os.name != "nt" else None,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
            )
            output = _Output(out_reader, captured)
            try:
                while True:
                    finished = process.poll() is not None
                    now = _monotonic()
                    deadline, reason, tool_id = progress.deadline()
                    if not finished and now >= deadline:
                        # Close the poll/check race before deciding to kill.
                        if process.poll() is None:
                            expired = (reason, tool_id)
                        break
                    for line in output.drain():
                        progress.observe(line, now)
                    # Scheduling delays must not turn an already exited process
                    # into a timeout. Do not wait for inherited handles to close.
                    if finished:
                        break
                    _wait_for_update(process, progress.deadline()[0] - now)
            finally:
                _kill_process_tree(process)
            output.drain(final=True)
            errors.seek(0)
            stderr = errors.read().decode("utf-8")
    result_stdout = captured.getvalue() if isinstance(captured, io.StringIO) and stdout is None else None
    if expired is not None:
        reason, tool_id = expired
        limit = {"total": timeout, "idle": idle_timeout, "tool": tool_timeout}[reason]
        tool_name = progress.active[tool_id][1] if tool_id is not None else None
        raise CodexProcessTimeout(
            command, limit, reason=reason, output=result_stdout, stderr=stderr,
            tool_id=tool_id, tool_name=tool_name,
        )
    return subprocess.CompletedProcess(command, process.returncode, result_stdout, stderr)
