"""Codex monitor contracts, using virtual time and real signalled subprocesses."""

from __future__ import annotations

import ctypes
import io
import json
import os
import select
import signal
import socket
import subprocess
import sys
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from typing import Self
from unittest.mock import patch

from aidast.core import codex_process as codex

_SCRIPT = r"""
import json, os, socket, subprocess, sys
control = socket.create_connection(('127.0.0.1', int(sys.argv[1])), timeout=5)
control.settimeout(None)
with control, control.makefile('rb') as messages:
    for message in messages:
        step = json.loads(message)
        descendants = []
        if step.get('spawn'):
            child = subprocess.Popen([
                sys.executable, '-c', 'import threading; threading.Event().wait()'
            ])
            descendants.append(child.pid)
        os.write(1, step.get('stdout', '').encode('utf-8'))
        os.write(2, step.get('stderr', '').encode('utf-8'))
        control.sendall((json.dumps(descendants) + '\n').encode())
        if 'exit' in step:
            sys.exit(step['exit'])
"""


def _pidfd_open(pid: int) -> int:
    # The workstation's Python omits os.pidfd_open despite kernel/libc support.
    libc = ctypes.CDLL(None, use_errno=True)
    descriptor = libc.pidfd_open(pid, 0)
    if descriptor < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return descriptor


def _event(kind: str, **fields: str | int | dict) -> str:
    return json.dumps({"type": kind, **fields}, ensure_ascii=False) + "\n"


def _item(kind: str, item_type: str = "agent_message", item_id: str = "message", **fields: str) -> str:
    return _event(kind, item={"type": item_type, "id": item_id, **fields})


class _ScriptedClock:
    """Advance only after the child acknowledges that bytes reached its spools."""

    def __init__(self, steps: list[dict]) -> None:
        self.steps = iter(steps)
        self.now = 0.0
        self.resources = ExitStack()
        self.listener = self.resources.enter_context(socket.socket())
        self.listener.settimeout(5)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.command = [sys.executable, "-u", "-c", _SCRIPT, str(self.listener.getsockname()[1])]
        self.connection: socket.socket | None = None
        self.messages = None
        self.process: subprocess.Popen[bytes] | None = None
        self.pidfds: list[int] = []

    def __enter__(self) -> Self:
        self.resources.enter_context(patch.object(codex, "_monotonic", lambda: self.now))
        self.resources.enter_context(patch.object(codex, "_wait_for_update", self.advance))
        return self

    def __exit__(self, *exc) -> None:
        self.resources.close()

    def advance(self, process: subprocess.Popen[bytes], delay: float) -> None:
        assert delay > 0
        self.process = process
        if self.connection is None:
            connection, _address = self.listener.accept()
            self.connection = self.resources.enter_context(connection)
            self.connection.settimeout(5)
            self.messages = self.resources.enter_context(connection.makefile("rb"))
        step = next(self.steps, None)
        assert step is not None, "runner ignored the scripted deadline or exit"
        self.connection.sendall((json.dumps(step) + "\n").encode())
        assert self.messages is not None
        descendants = json.loads(self.messages.readline())
        if sys.platform == "linux":
            for pid in descendants:
                descriptor = _pidfd_open(pid)
                self.resources.callback(os.close, descriptor)
                self.pidfds.append(descriptor)
        self.now = step["at"]
        if "exit" in step:
            # Subscribe to exit via wait, not a scheduling-dependent poll/sleep.
            process.wait(timeout=5)
        if step.get("interrupt"):
            raise KeyboardInterrupt

    def assert_reaped(self, test: unittest.TestCase) -> None:
        test.assertIsNotNone(self.process)
        assert self.process is not None
        test.assertIsNotNone(self.process.returncode)
        for descriptor in self.pidfds:
            ready, _writers, _errors = select.select([descriptor], [], [], 5)
            test.assertEqual(ready, [descriptor], "descendant survived runner cleanup")


class CodexProcessContractTests(unittest.TestCase):
    def test_success_preserves_utf8_input_exact_jsonl_and_stderr(self) -> None:
        event = _event("turn.completed", usage={"input_tokens": 7}).rstrip("\n")
        output = event + "\r\n" + "마지막 줄"
        command = [sys.executable, "-c", (
            "import sys; data=sys.stdin.buffer.read(); "
            "sys.stderr.buffer.write(data); "
            f"sys.stdout.buffer.write({output.encode()!r})"
        )]
        result = codex.run_codex(command, input="한글 입력", timeout=10)
        self.assertIsInstance(result, subprocess.CompletedProcess)
        self.assertEqual(result.args, command)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, output)
        self.assertEqual(result.stderr, "한글 입력")

    def test_redirect_delivers_lines_without_closing_the_caller_sink(self) -> None:
        class Sink(io.StringIO):
            def __init__(self) -> None:
                super().__init__()
                self.lines: list[str] = []

            def write(self, value: str) -> int:
                self.lines.append(value)
                return super().write(value)

        sink = Sink()
        lines = [_event("thread.started", thread_id="session"), _event("turn.completed"), "tail"]
        with _ScriptedClock([{"at": 0, "stdout": "".join(lines), "exit": 0}]) as clock:
            result = codex.run_codex(clock.command, input="", stdout=sink, timeout=3600)
        self.assertIsNone(result.stdout)
        self.assertFalse(sink.closed)
        self.assertEqual(sink.lines, lines)
        self.assertEqual(sink.getvalue(), "".join(lines))

    def test_nonzero_exit_preserves_diagnostics(self) -> None:
        with _ScriptedClock([{"at": 0, "stderr": "diagnostic\n", "exit": 17}]) as clock:
            result = codex.run_codex(clock.command, input="", timeout=3600)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (17, "", "diagnostic\n"))

    def test_large_outputs_before_reading_large_input_cannot_deadlock(self) -> None:
        size = 2 * 1024 * 1024
        command = [sys.executable, "-c", (
            "import sys; "
            f"sys.stdout.buffer.write(b'o' * {size}); sys.stdout.flush(); "
            f"sys.stderr.buffer.write(b'e' * {size}); sys.stderr.flush(); "
            "data=sys.stdin.buffer.read(); sys.stderr.buffer.write(data)"
        )]
        result = codex.run_codex(command, input="i" * size, timeout=10)
        self.assertEqual(result.stdout, "o" * size)
        self.assertEqual(result.stderr, "e" * size + "i" * size)

    def test_genuine_progress_outlives_the_old_300_second_limit(self) -> None:
        steps = [
            {"at": 0, "stdout": _event("thread.started", thread_id="session")},
            {"at": 400, "stdout": _item("item.started", "reasoning", text="thinking")},
            {"at": 1000, "stdout": _item("item.updated", "reasoning", text="more thinking")},
            {"at": 1600, "stdout": _event("turn.completed", usage={"output_tokens": 19}), "exit": 0},
        ]
        with _ScriptedClock(steps) as clock:
            result = codex.run_codex(clock.command, input="", timeout=codex.DEFAULT_CODEX_TIMEOUT_SECONDS)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "".join(step["stdout"] for step in steps))
        self.assertEqual(json.loads(result.stdout.splitlines()[-1])["usage"]["output_tokens"], 19)

    def test_idle_timeout_also_bounds_a_child_that_never_reads_a_large_prompt(self) -> None:
        with _ScriptedClock([
            {"at": 0, "stdout": _event("turn.started")}, {"at": 900},
        ]) as clock, self.assertRaises(codex.CodexProcessTimeout) as caught:
            codex.run_codex(clock.command, input="x" * (2 * 1024 * 1024), timeout=3600)
        self.assertEqual(caught.exception.reason, "idle")
        self.assertEqual(caught.exception.timeout, 900)
        self.assertIsInstance(caught.exception, subprocess.TimeoutExpired)
        clock.assert_reaped(self)

    def test_total_cap_never_resets_despite_continuous_progress(self) -> None:
        steps = [{"at": at, "stdout": _item("item.completed", item_id=str(at))}
                 for at in (0, 800, 1600, 2400, 3200, 3600)]
        with _ScriptedClock(steps) as clock, self.assertRaises(codex.CodexProcessTimeout) as caught:
            codex.run_codex(clock.command, input="", timeout=3600)
        self.assertEqual(caught.exception.reason, "total")
        self.assertEqual(caught.exception.timeout, 3600)

    def test_tool_deadline_survives_updates_and_unrelated_progress(self) -> None:
        for item_type in ("command_execution", "mcp_tool_call", "web_search", "collab_tool_call"):
            with self.subTest(item_type=item_type):
                steps = [
                    {"at": 0, "stdout": _item("item.started", item_type, "tool-7", tool="execute")},
                    {"at": 400, "stdout": _item("item.updated", item_type, "tool-7", tool="execute", status="running")},
                    {"at": 800, "stdout": _item("item.completed", item_id="unrelated")},
                    {"at": 900, "stdout": _item("item.completed", item_id="other")},
                ]
                with _ScriptedClock(steps) as clock, self.assertRaises(codex.CodexProcessTimeout) as caught:
                    codex.run_codex(clock.command, input="", timeout=3600)
                self.assertEqual(caught.exception.reason, "tool")
                self.assertEqual(caught.exception.tool_id, "tool-7")
                self.assertEqual(caught.exception.tool_name, item_type + ".execute")

    def test_tool_completion_removes_its_deadline(self) -> None:
        steps = [
            {"at": 0, "stdout": _item("item.started", "command_execution", "tool")},
            {"at": 899, "stdout": _item("item.completed", "command_execution", "tool")},
            {"at": 1200, "stdout": _event("turn.completed"), "exit": 0},
        ]
        with _ScriptedClock(steps) as clock:
            result = codex.run_codex(clock.command, input="", timeout=3600)
        self.assertEqual(result.returncode, 0)

    def test_late_tool_completion_cannot_erase_an_expired_deadline(self) -> None:
        steps = [
            {"at": 0, "stdout": _item("item.started", "command_execution", "tool")},
            {"at": 800, "stdout": _item("item.completed", item_id="other")},
            {"at": 901, "stdout": _item("item.completed", "command_execution", "tool")},
        ]
        with _ScriptedClock(steps) as clock, self.assertRaises(codex.CodexProcessTimeout) as caught:
            codex.run_codex(clock.command, input="", timeout=3600)
        self.assertEqual(caught.exception.reason, "tool")

    def test_chatter_errors_malformed_events_and_no_op_updates_do_not_reset_idle(self) -> None:
        initial = _item("item.started", "reasoning", text="same")
        chatter = "not json\n[]\nnull\n" + "".join([
            _event("heartbeat"), _event("error", message="retrying"),
            _event("turn.failed"), _event("item.updated"),
            _item("item.completed", "error", "error", message="retrying"),
            _item("item.updated", "heartbeat", "heartbeat"),
            _item("item.updated", "reasoning", text="same"),
            initial,
        ])
        with _ScriptedClock([
            {"at": 0, "stdout": initial},
            {"at": 800, "stdout": chatter, "stderr": _event("turn.started")},
            {"at": 900},
        ]) as clock, self.assertRaises(codex.CodexProcessTimeout) as caught:
            codex.run_codex(clock.command, input="", timeout=3600)
        self.assertEqual(caught.exception.reason, "idle")
        self.assertEqual(caught.exception.stderr, _event("turn.started"))

    def test_all_recognized_genuine_lifecycle_changes_reset_idle(self) -> None:
        progress = codex._Progress(0, 3600, 900, 900, frozenset())
        events = [
            _event("thread.started", thread_id="session"), _event("turn.started"),
            _item("item.started", "reasoning", text="first"),
            _item("item.updated", "reasoning", text="second"),
            _item("item.completed", "reasoning", text="second"),
            _event("turn.completed", usage={"output_tokens": 1}),
        ]
        for number, event in enumerate(events, 1):
            with self.subTest(event=event):
                progress.observe(event, number * 100)
                self.assertEqual(progress.deadline(), (number * 100 + 900, "idle", None))

    def test_collaboration_wait_is_exempt_but_child_progress_is_still_required(self) -> None:
        steps = [
            {"at": 0, "stdout": _item("item.started", "collab_tool_call", "wait-1", tool="wait")},
            {"at": 800, "stdout": _item("item.completed", item_id="child-1")},
            {"at": 1600, "stdout": _item("item.completed", item_id="child-2")},
            {"at": 2400, "stdout": _event("turn.completed"), "exit": 0},
        ]
        with _ScriptedClock(steps) as clock:
            result = codex.run_codex(clock.command, input="", timeout=3600)
        self.assertEqual(result.returncode, 0)

    def test_collaboration_wait_exemption_is_configurable_and_still_has_idle_total_caps(self) -> None:
        wait = _item("item.started", "collab_tool_call", "wait-1", tool="wait")
        cases = [
            ({}, [{"at": 0, "stdout": wait}, {"at": 900}], "idle"),
            ({"timeout": 500}, [{"at": 0, "stdout": wait}, {"at": 500}], "total"),
            ({"tool_timeout_exemptions": frozenset(), "tool_timeout": 100},
             [{"at": 0, "stdout": wait}, {"at": 100}], "tool"),
        ]
        for options, steps, reason in cases:
            with self.subTest(reason=reason):
                kwargs = {"timeout": 3600, **options}
                with _ScriptedClock(steps) as clock, self.assertRaises(codex.CodexProcessTimeout) as caught:
                    codex.run_codex(clock.command, input="", **kwargs)
                self.assertEqual(caught.exception.reason, reason)

    def test_already_successful_exit_is_not_a_scheduling_timeout(self) -> None:
        with _ScriptedClock([{"at": 4000, "stdout": _event("turn.completed"), "exit": 0}]) as clock:
            result = codex.run_codex(clock.command, input="", timeout=3600)
        self.assertEqual(result.returncode, 0)

    def test_timeout_keeps_partial_stdout_and_stderr(self) -> None:
        with _ScriptedClock([
            {"at": 0, "stdout": "partial 한글", "stderr": "failure detail"}, {"at": 3},
        ]) as clock, self.assertRaises(codex.CodexProcessTimeout) as caught:
            codex.run_codex(clock.command, input="", timeout=30, idle_timeout=3)
        self.assertEqual(caught.exception.output, "partial 한글")
        self.assertEqual(caught.exception.stdout, "partial 한글")
        self.assertEqual(caught.exception.stderr, "failure detail")

    @unittest.skipUnless(sys.platform == "linux", "requires Linux process-exit signals")
    def test_timeout_kills_descendants_and_reaps_root(self) -> None:
        with _ScriptedClock([{"at": 0, "spawn": True}, {"at": 3}]) as clock:
            with self.assertRaises(codex.CodexProcessTimeout):
                codex.run_codex(clock.command, input="", timeout=30, idle_timeout=3)
            clock.assert_reaped(self)

    @unittest.skipUnless(sys.platform == "linux", "requires Linux process-exit signals")
    def test_keyboard_interrupt_kills_descendants_and_reaps_root(self) -> None:
        with _ScriptedClock([{"at": 0, "spawn": True, "interrupt": True}]) as clock:
            with self.assertRaises(KeyboardInterrupt):
                codex.run_codex(clock.command, input="", timeout=30)
            clock.assert_reaped(self)

    @unittest.skipUnless(sys.platform == "linux", "requires Linux process-exit signals")
    def test_success_with_inherited_handles_cleans_descendants_without_reader_threads(self) -> None:
        with _ScriptedClock([{"at": 0, "spawn": True, "exit": 0}]) as clock:
            result = codex.run_codex(clock.command, input="", timeout=30)
            self.assertEqual(result.returncode, 0)
            clock.assert_reaped(self)

    def test_sink_failure_is_propagated_after_process_cleanup(self) -> None:
        failure = OSError("test sink failure")

        class BrokenSink(io.StringIO):
            def write(self, value: str) -> int:
                raise failure

        with _ScriptedClock([{"at": 0, "stdout": _event("turn.started")}]) as clock:
            with self.assertRaises(OSError) as caught:
                codex.run_codex(clock.command, input="", timeout=30, stdout=BrokenSink())
            self.assertIs(caught.exception, failure)
            clock.assert_reaped(self)

    @unittest.skipUnless(sys.platform == "linux", "requires POSIX worker groups and Linux exit signals")
    def test_managed_worker_preserves_session_and_survives_interruption_cleanup(self) -> None:
        child = (
            "import json,os,subprocess,sys,threading; "
            "child=subprocess.Popen([sys.executable,'-c','import threading; threading.Event().wait()']); "
            "print(json.dumps({'pid':os.getpid(),'pgid':os.getpgrp(),'sid':os.getsid(0),'child':child.pid}),flush=True); "
            "threading.Event().wait()"
        )
        worker = f"""
import ctypes,io,json,os,select,sys
from aidast.core.codex_process import run_codex
class Sink(io.StringIO):
    def write(self, line):
        global info, descriptors
        info=json.loads(line)
        libc=ctypes.CDLL(None,use_errno=True)
        descriptors=[libc.pidfd_open(info['pid'],0),libc.pidfd_open(info['child'],0)]
        assert all(fd >= 0 for fd in descriptors)
        raise KeyboardInterrupt
try:
    run_codex([sys.executable,'-c',{child!r}], input='', timeout=10, stdout=Sink())
except KeyboardInterrupt:
    info['worker']=os.getpid()
    info['dead']=all(select.select([fd],[],[],5)[0] == [fd] for fd in descriptors)
    print(json.dumps(info),flush=True)
"""
        environment = {**os.environ, "PYTHONPATH": str(Path(codex.__file__).resolve().parents[2])}
        process = subprocess.Popen(
            [sys.executable, "-c", worker], env=environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=15)
            self.assertEqual(process.returncode, 0, stderr.decode())
            info = json.loads(stdout)
            self.assertEqual(info["pgid"], info["pid"])
            self.assertNotEqual(info["pgid"], info["worker"])
            self.assertEqual(info["sid"], info["worker"])
            self.assertTrue(info["dead"])
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)

    def test_windows_cleanup_finds_descendants_even_after_root_exit(self) -> None:
        actions: list[int | str] = []

        class Process:
            def __init__(self, pid: int, parent: int) -> None:
                self.pid = pid
                self.info = {"pid": pid, "ppid": parent}

            def kill(self) -> None:
                actions.append(self.pid)

            def poll(self) -> int:
                return 0

            def wait(self, timeout: float) -> int:
                self.assert_timeout(timeout)
                actions.append("reaped")
                return 0

            @staticmethod
            def assert_timeout(timeout: float) -> None:
                assert timeout == 5

        root, child, grandchild, unrelated = Process(10, 1), Process(11, 10), Process(12, 11), Process(20, 1)
        fake_psutil = SimpleNamespace(
            process_iter=lambda attrs: [child, unrelated, grandchild],
            NoSuchProcess=ProcessLookupError,
            wait_procs=lambda processes, timeout: (processes, []),
        )
        with patch.object(codex.os, "name", "nt"), patch.dict(sys.modules, {"psutil": fake_psutil}):
            codex._kill_process_tree(root)
        self.assertEqual(actions, [12, 11, "reaped"])


if __name__ == "__main__":
    unittest.main()
