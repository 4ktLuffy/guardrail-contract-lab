"""Stand-in executors: record, and never really act.

Each sink is a receipt-writer for `gcl/enforce/ledger.py`, playing the part `MockModel`
and `StandInScanner` play for a guard verdict: something gcl itself controls completely,
so a claim of execution can be checked against gcl's own record instead of the target's
say-so. None of these ever runs a shell command, writes to a real database, or touches a
real file outside its own workdir; `SqliteStateObserver` is the one exception that reads a
real file, and only reads it -- see its own docstring.

Benign markers only. A fake shell logs argv and exits 0; a fake DB sink logs a SQL string
and returns a canned result; a fake file sink logs a path and an action. Nothing here is
ever a substitute for sandboxing a real target: a real target that ignores the fake shell
on its PATH and shells out to an absolute path, or opens a database by a hardcoded path
instead of the one it was configured with, is not caught by any of these -- see
LIMITATIONS.
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import time
import uuid
from pathlib import Path
from typing import Callable

# A tiny, dependency-free executable: logs its own argv and the two env vars that tell it
# where to write and what marker to carry, then exits 0 having run nothing at all.
_FAKE_SHELL_SCRIPT = """#!/usr/bin/env python3
import json, os, sys, time
receipt = os.environ.get("GCL_FAKE_SHELL_RECEIPT")
if receipt:
    with open(receipt, "a", encoding="utf-8") as f:
        f.write(json.dumps({"t": time.time(), "argv": sys.argv[1:],
                            "marker": os.environ.get("GCL_FAKE_SHELL_MARKER", "")}) + chr(10))
sys.exit(0)
"""


def new_marker(tag: str = "SINK") -> str:
    return f"GCL-{tag}-{uuid.uuid4().hex[:8]}"


class FakeShell:
    """An executable on PATH that records its argv to a JSONL receipt file and exits 0:
    nothing it is ever handed runs for real. Wire it in by prepending `env()`'s PATH
    ahead of the target's own (so its lookup of "sh"/"bash"/whatever it calls finds this
    one first), and by naming the script after whatever the target expects -- `name`
    defaults to "sh" but a target that shells out to "bash" or invokes a specific command
    needs its own instance named for that command.
    """

    def __init__(self, workdir: Path, name: str = "sh", marker: str = ""):
        self.workdir = Path(workdir)
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.name = name
        self.marker = marker or new_marker("SHELL")
        self.exe = self.workdir / name
        self.receipt_path = self.workdir / f"{name}.receipt.jsonl"
        self.exe.write_text(_FAKE_SHELL_SCRIPT, encoding="utf-8")
        mode = self.exe.stat().st_mode
        self.exe.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def env(self, base: dict | None = None) -> dict:
        """`base` (default: a copy of this process's own environment) with this sink
        spliced onto the front of PATH and the two variables the script reads."""
        out = dict(base if base is not None else os.environ)
        out["PATH"] = f"{self.workdir}{os.pathsep}{out.get('PATH', '')}"
        out["GCL_FAKE_SHELL_RECEIPT"] = str(self.receipt_path)
        out["GCL_FAKE_SHELL_MARKER"] = self.marker
        return out

    def calls(self) -> list[dict]:
        """Every invocation recorded so far, in order; `[]` if it was never called."""
        if not self.receipt_path.exists():
            return []
        out = []
        for line in self.receipt_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
        return out


class FakeDBSink:
    """A stand-in SQL executor: records every statement it is handed and classifies it
    with whatever rule the caller passes in, but never opens a connection, a file, or a
    cursor -- there is no database here to corrupt. This is what a test of the *ledger's
    own logic* (or of a future target whose queries gcl can intercept before they reach a
    real driver) runs against; the dbhub target below does not use it, because dbhub owns
    its own connection to a real throwaway file and gcl only ever reads that file from
    the outside (`SqliteStateObserver`)."""

    def __init__(self, marker: str = ""):
        self.marker = marker or new_marker("DB")
        self.calls: list[dict] = []

    def execute(self, sql: str, readonly: bool, classify: Callable[[str], bool]) -> dict:
        """`classify(sql)` says whether the statement is read-only by whichever rule the
        caller wants exercised (a known-naive leading-keyword classifier, to reproduce a
        bypass, or a correct one). Nothing is run either way; the receipt records what
        the classifier said and what that implies would have happened."""
        read_only = classify(sql)
        receipt = {"t": time.time(), "sql": sql, "readonly_mode": readonly, "classified_read_only": read_only,
                   "would_run": (not readonly) or read_only, "marker": self.marker}
        self.calls.append(receipt)
        return receipt


class FakeFileSink:
    """A stand-in for a file write/delete tool: records the action and path, touches
    nothing on disk."""

    def __init__(self, marker: str = ""):
        self.marker = marker or new_marker("FILE")
        self.calls: list[dict] = []

    def op(self, action: str, path: str, **more) -> dict:
        receipt = {"t": time.time(), "action": action, "path": path, "marker": self.marker, **more}
        self.calls.append(receipt)
        return receipt


class SqliteStateObserver:
    """Independent, read-only evidence for a target that manages its own SQLite file
    (dbhub does): a connection of gcl's own, opened read-only (`mode=ro`) and closed again
    for every read, so it can never itself be the write it is trying to catch and never
    holds a lock that would mask one. This is the one sink that touches a real file --
    read-only, and only the throwaway file the test created for this purpose; see
    LIMITATIONS ("stdio-MCP targets only for now")."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)

    def read(self, sql: str, params: tuple = ()) -> list[tuple]:
        con = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True)
        try:
            return con.execute(sql, params).fetchall()
        finally:
            con.close()
