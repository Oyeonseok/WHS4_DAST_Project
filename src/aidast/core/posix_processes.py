"""Signal every process group descended from one verified operator worker."""

from __future__ import annotations

import os
import signal
import subprocess


def signal_session(session_id: int, signum: int) -> None:
    """Keep separately grouped Codex descendants under dashboard control."""
    freeze = signum in (signal.SIGSTOP, signal.SIGTERM, signal.SIGKILL)
    if freeze:
        # Prevent the worker from launching another Codex group during discovery.
        os.killpg(session_id, signal.SIGSTOP)
    completed = False
    try:
        try:
            snapshot = subprocess.run(
                ["ps", "-A", "-o", "pid=,ppid=,pgid="],
                check=True, stdout=subprocess.PIPE, text=True, timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            # Process discovery is an enhancement for separately grouped
            # helpers. The verified worker session remains the authoritative
            # control boundary, so a transient/host-level ps failure must not
            # leave that worker frozen or make cancellation fail.
            if signum != signal.SIGSTOP:
                try:
                    os.killpg(session_id, signum)
                except ProcessLookupError:
                    pass
            completed = True
            return
        processes = {
            int(pid): (int(parent), int(group))
            for line in snapshot.stdout.splitlines()
            for pid, parent, group in [line.split()]
        }
        descendants: set[int] = set()
        parents = {session_id}
        while parents:
            children = {
                pid for pid, (parent, _group) in processes.items()
                if parent in parents and pid not in descendants
            }
            descendants.update(children)
            parents = children
        groups = {
            processes[pid][1] for pid in descendants
            if processes[pid][1] != session_id
        }
        for group in sorted(groups):
            try:
                os.killpg(group, signum)
            except (ProcessLookupError, PermissionError):
                # Sandboxed Codex may place its code-mode host in a protected
                # descendant group. Signalling its controllable ancestors and
                # the worker session closes the transport and lets it exit.
                continue
        try:
            os.killpg(session_id, signum)
        except ProcessLookupError:
            # A worker can exit after its descendants are signalled.
            pass
        completed = True
    finally:
        # SIGTERM is pending while the worker is stopped. Also roll back a
        # failed discovery instead of leaving an unreported frozen worker.
        if freeze and (not completed or signum == signal.SIGTERM):
            try:
                os.killpg(session_id, signal.SIGCONT)
            except ProcessLookupError:
                pass
