"""dbhub (`@bytebase/dbhub`) as a stdio-MCP action target: the first real target for
`gcl actions` and the known-CVE replay for CVE-2026-61788 / GHSA-mwwr-p57h-56pf
("@bytebase/dbhub's read-only mode does not prevent database writes").

The control under test is dbhub's own `readonly` flag on its `execute_sql` tool (set in a
`dbhub.toml` per-tool, the only place the shipped loader accepts it): with `readonly =
true`, a write must be refused. The bug (read the advisory, and dbhub's own bundled
`dist/index.js` for both versions: both confirmed CHECKED, not just asserted): the
connection-level read-only control is dead code (gated on a config field the TOML loader
never populates), so the only thing enforcing read-only on a vulnerable build is a
classifier that reads the first keyword of a statement. For SQLite that classifier allows
`select`, `with`, `explain` and `pragma` as read-only, and -- on every version up to and
including 0.22.5 -- does nothing further to a `pragma` statement at all: `PRAGMA
user_version = 42` passes as read-only although it is an assignment that rewrites the
database file's header. The fix in 0.22.6 (PR #342) rejects any `pragma ... = ...` in the
classifier and additionally sets `PRAGMA query_only = ON` on the real connection before
every read-only-mode statement.

The probe is exactly that assignment: benign (it touches no table, no row, nothing but an
unused 4-byte header field SQLite reserves for the application's own use), and proven by
gcl's own read-only connection to the throwaway file (`sinks.SqliteStateObserver`), before
and after -- never by dbhub's own "success": true.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import ClassVar

from .actions import StdioMCPActionTarget
from .mcp_client import Exchange
from .sinks import SqliteStateObserver

_TOML = """[[sources]]
id = "default"
dsn = "sqlite://{db_path}"

[[tools]]
name = "execute_sql"
source = "default"
readonly = true
"""

# The probe's own sentinel value: 0 is SQLite's default, so any other value proves a
# write committed. Not a timestamp or a hash of the marker: a fixed, recognisable number
# keeps a hand check ("is user_version 61788?") as simple as the CVE id it names.
_BYPASS_VALUE = 61788
_BENIGN_NOTE = "benign"


def seed_db(db_path: Path) -> None:
    """Reset the throwaway SQLite file to its known starting state: the marker table and
    its one benign row exist, and `user_version` (the bypass probe's own field) is back
    to SQLite's default of 0. Idempotent and run every time, not only when the file is
    new -- a repeat run against the same file must not read a stale user_version from an
    earlier run as "no write happened" (a false green). This is gcl preparing its own
    fixture before driving the target, the one write gcl itself ever makes to this file;
    every later look is read-only, through SqliteStateObserver."""
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db_path)
    try:
        con.execute("CREATE TABLE IF NOT EXISTS gcl_marker (id INTEGER PRIMARY KEY, note TEXT NOT NULL)")
        if not con.execute("SELECT 1 FROM gcl_marker WHERE note = ?", (_BENIGN_NOTE,)).fetchone():
            con.execute("INSERT INTO gcl_marker (note) VALUES (?)", (_BENIGN_NOTE,))
        con.execute("PRAGMA user_version = 0")
        con.commit()
    finally:
        con.close()


def write_config(workdir: Path, db_path: Path) -> Path:
    """The dbhub.toml this target runs with: one sqlite source, `execute_sql` readonly."""
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    cfg = workdir / "dbhub.toml"
    # dbhub's DSN parser wants exactly three slashes before an absolute path (see
    # SQLiteDSNParser in dist/index.js): "sqlite://" + "/abs/path", not "sqlite:///abs/path"
    # redoubled -- the CLI's db_path is already absolute, so no extra slash is added here.
    cfg.write_text(_TOML.format(db_path=str(Path(db_path).resolve())), encoding="utf-8")
    return cfg


def _tool_text(ex: Exchange, rid: str) -> dict | None:
    """The `execute_sql` tool's own JSON payload (its `content[0].text`, itself a JSON
    document per dbhub's `createToolSuccessResponse`/`createToolErrorResponse`), for the
    one request this target sent with id `rid`. None if there is no proper response, or
    its shape is not what dbhub's tool handler produces."""
    resp = ex.response_to(rid)
    if not resp or "result" not in resp:
        return None
    content = (resp["result"] or {}).get("content") or []
    if not content or not isinstance(content[0], dict):
        return None
    try:
        return json.loads(content[0].get("text", ""))
    except ValueError:
        return None


class DbhubTarget(StdioMCPActionTarget):
    """One sqlite source, `execute_sql` readonly, driven over stdio. `node` is the node
    binary (a version with `node:sqlite`, i.e. >=22.5 -- dbhub's own requirement); `install`
    is the directory `npm pack`/`npm install` unpacked @bytebase/dbhub into (holding
    `dist/index.js` and, for the production dependencies, `node_modules`); `db_path` is the
    throwaway SQLite file (seeded once by `seed_db`, read only by gcl from then on);
    `workdir` is where this target writes its own `dbhub.toml`."""

    name = "dbhub"
    CALL_ID: ClassVar[str] = "gcl-call"

    def __init__(self, node: str, install: Path, db_path: Path, workdir: Path):
        self.node = node
        self.install = Path(install)
        self.db_path = Path(db_path)
        self.workdir = Path(workdir)
        self.config_path = write_config(self.workdir, self.db_path)
        self.observer = SqliteStateObserver(self.db_path)

    def argv(self) -> list[str]:
        return [self.node, str(self.install / "dist" / "index.js"), "--transport", "stdio",
                "--config", str(self.config_path)]

    def env(self) -> dict:
        return dict(os.environ)

    def cwd(self) -> str | None:
        return str(self.install)

    def _package_version(self) -> str | None:
        try:
            return json.loads((self.install / "package.json").read_text(encoding="utf-8")).get("version")
        except (OSError, ValueError):
            return None

    def config_summary(self) -> dict:
        return {"transport": "stdio", "config": "dbhub.toml", "source": "sqlite (default)",
                "tool": "execute_sql (readonly = true)"}

    def describe(self) -> dict:
        d = super().describe()
        d["versions"] = {"@bytebase/dbhub": self._package_version(), "node": self.node}
        return d

    def _sql_for(self, kind: str, marker: str) -> str:
        if kind == "approved":
            return f"SELECT note FROM gcl_marker WHERE note = '{_BENIGN_NOTE}'"
        if kind == "denied":
            return f"INSERT INTO gcl_marker (note) VALUES ('{marker}')"
        if kind == "bypass":
            return f"PRAGMA user_version = {_BYPASS_VALUE}"
        raise ValueError(f"unknown check kind {kind!r}")

    def probe(self, kind: str, marker: str) -> dict:
        sql = self._sql_for(kind, marker)
        return {"jsonrpc": "2.0", "id": self.CALL_ID, "method": "tools/call",
                "params": {"name": "execute_sql", "arguments": {"sql": sql}}}

    def observe(self) -> dict:
        rows = self.observer.read("SELECT id, note FROM gcl_marker ORDER BY id")
        uv = self.observer.read("PRAGMA user_version")
        return {"marker_rows": rows, "user_version": uv[0][0] if uv else None}

    def reply_ok(self, ex: Exchange) -> bool:
        doc = _tool_text(ex, self.CALL_ID)
        if not doc or doc.get("success") is not True:
            return False
        rows = ((doc.get("data") or {}).get("rows")) or []
        return any(isinstance(r, dict) and r.get("note") == _BENIGN_NOTE for r in rows)
