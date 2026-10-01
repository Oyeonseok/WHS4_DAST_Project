"""Signal all process groups in one verified operator-worker session."""

from __future__ import annotations

import os
import signal
import subprocess


def signal_session(session_id: int, signum: int) -> None:
    """Keep Codex groups controllable even after their immediate parent exits."""
    freeze = signum in (signal.SIGSTOP, signal.SIGTERM, signal.SIGKILL)
    if freeze:
        # Prevent the worker from launching another Codex group during discovery.
        os.killpg(session_id, signal.SIGSTOP)
    completed = False
    try:
        snapshot = subprocess.run(
            ["ps", "-A", "-o", "sid=,pgid="],
            check=True, stdout=subprocess.PIPE, text=True, timeout=5,
        )
        groups = {
            int(group) for line in snapshot.stdout.splitlines()
            for session, group in [line.split()]
            if int(session) == session_id and int(group) != session_id
        }
        for group in sorted(groups):
            try:
                os.killpg(group, signum)
            except ProcessLookupError:
                continue
        os.killpg(session_id, signum)
        completed = True
    finally:
        # SIGTERM is pending while the worker is stopped. Also roll back a
        # failed discovery instead of leaving an unreported frozen worker.
        if freeze and (not completed or signum == signal.SIGTERM):
            try:
                os.killpg(session_id, signal.SIGCONT)
            except ProcessLookupError:
                pass
