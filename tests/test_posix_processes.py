"""Session controls reach dedicated Codex groups without unrelated sessions."""

from __future__ import annotations

import json
import os
import select
import signal
import subprocess
import sys
import unittest
from contextlib import ExitStack
from unittest.mock import patch

from aidast.core.posix_processes import signal_session
from tests.test_codex_process import _pidfd_open


@unittest.skipUnless(os.name == "posix", "requires POSIX process groups")
class SessionControlTests(unittest.TestCase):
    def test_pause_resume_and_terminate_reach_only_the_selected_session(self) -> None:
        snapshot = subprocess.CompletedProcess(
            [], 0, "42 42\n42 51\n99 77\n42 51\n", "",
        )
        expected = {
            signal.SIGSTOP: [(42, signal.SIGSTOP), (51, signal.SIGSTOP), (42, signal.SIGSTOP)],
            signal.SIGCONT: [(51, signal.SIGCONT), (42, signal.SIGCONT)],
            signal.SIGTERM: [
                (42, signal.SIGSTOP), (51, signal.SIGTERM),
                (42, signal.SIGTERM), (42, signal.SIGCONT),
            ],
        }
        for signum, calls in expected.items():
            with self.subTest(signum=signum):
                with (
                    patch("aidast.core.posix_processes.subprocess.run", return_value=snapshot),
                    patch("aidast.core.posix_processes.os.killpg") as send,
                ):
                    signal_session(42, signum)
                self.assertEqual([call.args for call in send.call_args_list], calls)

    def test_discovery_failure_resumes_the_worker_and_preserves_the_error(self) -> None:
        failure = subprocess.TimeoutExpired(["ps"], 5)
        with (
            patch("aidast.core.posix_processes.subprocess.run", side_effect=failure),
            patch("aidast.core.posix_processes.os.killpg") as send,
            self.assertRaises(subprocess.TimeoutExpired) as caught,
        ):
            signal_session(42, signal.SIGSTOP)
        self.assertIs(caught.exception, failure)
        self.assertEqual(
            [call.args for call in send.call_args_list],
            [(42, signal.SIGSTOP), (42, signal.SIGCONT)],
        )

    @unittest.skipUnless(sys.platform == "linux", "requires Linux process-exit signals")
    def test_real_worker_termination_also_terminates_the_separate_tool_group(self) -> None:
        worker_code = (
            "import json,os,subprocess,sys,threading; "
            "child=subprocess.Popen([sys.executable,'-c',"
            "'import threading; threading.Event().wait()'],process_group=0); "
            "print(json.dumps({'worker':os.getpid(),'tool':child.pid}),flush=True); "
            "threading.Event().wait()"
        )
        process = subprocess.Popen(
            [sys.executable, "-u", "-c", worker_code],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        )
        tool_pid: int | None = None
        try:
            assert process.stdout is not None
            ready, _, _ = select.select([process.stdout], [], [], 5)
            self.assertEqual(ready, [process.stdout])
            info = json.loads(process.stdout.readline())
            tool_pid = info["tool"]
            self.assertEqual(os.getsid(tool_pid), process.pid)
            self.assertEqual(os.getpgid(tool_pid), tool_pid)
            with ExitStack() as resources:
                descriptors = [_pidfd_open(pid) for pid in (process.pid, tool_pid)]
                for descriptor in descriptors:
                    resources.callback(os.close, descriptor)

                signal_session(process.pid, signal.SIGTERM)

                for descriptor in descriptors:
                    ready, _, _ = select.select([descriptor], [], [], 5)
                    self.assertEqual(ready, [descriptor])
            process.wait(timeout=5)
            self.assertEqual(process.returncode, -signal.SIGTERM)
        finally:
            for group in (tool_pid, process.pid):
                if group is not None:
                    try:
                        os.killpg(group, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            process.wait(timeout=5)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()


if __name__ == "__main__":
    unittest.main()
