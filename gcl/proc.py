"""Run a user-supplied command (an adapter, a system under probe) under supervision.

Manifests name executables, and `gcl` runs them: treat a manifest like code you would
run yourself. What `gcl` does guarantee: the command runs in its own process group and
the whole group is killed at the deadline; output is read with a byte cap while it
arrives (a chatty or hostile command cannot exhaust memory); cleanup itself has a
deadline.
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import threading
from dataclasses import dataclass


@dataclass
class Run:
    returncode: int | None   # None: killed at the deadline (or never finished)
    output: str              # stdout (+stderr if merged), decoded, possibly truncated
    truncated: bool
    error: str | None = None  # could not start: why


def run_supervised(argv: list[str], stdin: str, *, timeout_s: float, cwd: str | None = None,
                   env: dict | None = None, max_bytes: int = 64 * 1024 * 1024,
                   keep: str = "head", merge_stderr: bool = False) -> Run:
    """keep="head" keeps the first max_bytes (adapters: answers come first);
    keep="tail" keeps the last max_bytes (probe evidence: the last line matters)."""
    try:
        proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT if merge_stderr else subprocess.DEVNULL,
            cwd=cwd, env=env, start_new_session=True)
    except (FileNotFoundError, PermissionError, OSError) as e:
        return Run(None, "", False, error=f"{type(e).__name__}: {e}")

    chunks: list[bytes] = []
    state = {"size": 0, "truncated": False, "stop": False}
    lock = threading.Lock()

    fd = proc.stdout.fileno()

    def reader():
        # os.read on the raw descriptor: no buffered-reader lock that a supervisor could
        # block on, so the supervisor can always walk away from this thread.
        while not state["stop"]:
            try:
                b = os.read(fd, 65536)
            except OSError:
                return
            if not b:
                return
            with lock:  # held only to append/trim, never across a read
                if keep == "head":
                    room = max_bytes - state["size"]
                    if room <= 0:
                        state["truncated"] = True
                        continue  # keep draining so the child is never blocked on us
                    if len(b) > room:
                        b = b[:room]
                        state["truncated"] = True
                    chunks.append(b)
                    state["size"] += len(b)
                else:
                    chunks.append(b)
                    state["size"] += len(b)
                    while state["size"] > max_bytes:
                        state["truncated"] = True
                        extra = state["size"] - max_bytes
                        if len(chunks[0]) <= extra:
                            state["size"] -= len(chunks.pop(0))
                        else:
                            chunks[0] = chunks[0][extra:]
                            state["size"] -= extra

    def writer():
        try:
            proc.stdin.write(stdin.encode("utf-8"))
            proc.stdin.close()
        except (BrokenPipeError, OSError):
            pass

    rt = threading.Thread(target=reader, daemon=True)
    wt = threading.Thread(target=writer, daemon=True)
    rt.start()
    wt.start()
    import time

    deadline = time.monotonic() + timeout_s
    code: int | None
    try:
        code = proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        code = None
    # Whether the command exited or not, its process group (helpers it started included)
    # must not outlive the deadline: a descendant holding our pipe would otherwise keep
    # the reader waiting forever.
    rt.join(timeout=max(0.0, deadline - time.monotonic()))
    if code is None or rt.is_alive():
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, signal.SIGKILL)
        if code is None:
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=5)
        rt.join(timeout=2)
        if rt.is_alive():
            # A helper that left our process group (its own session) still holds the
            # pipe. Abandon the reader (a daemon thread) rather than wait: never close
            # the pipe from here, which could block on a read in progress.
            state["stop"] = True
    truncated = state["truncated"]
    with lock:
        data = b"".join(chunks)
    return Run(code, data.decode("utf-8", errors="replace"), truncated)
