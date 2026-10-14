"""Run receipts: what exactly produced a result.

A result is only worth something if it can be tied to the code that produced it: gcl's
own source (commit, uncommitted and untracked files, a hash over the package), the
integration's installed distributions (version, where they were imported from, and
whether the installed files still match the hashes they were installed with), the
vendor spec, and the documentation version each expectation was read for.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import subprocess
from pathlib import Path

from .. import __version__

_PKG = Path(__file__).resolve().parent.parent  # the gcl package directory


def new_run_id() -> str:
    """Six hex characters, carried in every sentinel of the run: an answer cached by an
    integration from an earlier run carries another run's id and is not evidence."""
    return secrets.token_hex(3)


def _git(*args: str) -> str | None:
    try:
        r = subprocess.run(["git", "-C", str(_PKG.parent), *args], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout if r.returncode == 0 else None


def source_hash(root: Path = _PKG) -> str:
    """sha256 over every source file of the package (path and content), so a local edit
    to a driver or adapter changes it whether or not git sees the file."""
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        if p.is_file() and "__pycache__" not in p.parts and p.suffix not in (".pyc", ".pyo"):
            h.update(str(p.relative_to(root)).encode() + b"\0" + p.read_bytes() + b"\0")
    return h.hexdigest()


def gcl_source() -> dict:
    commit = _git("rev-parse", "HEAD")
    status = _git("status", "--porcelain", "--untracked-files=all", "--", ".")
    dirty = [line[3:] for line in (status or "").splitlines() if line.strip()]
    return {"version": __version__, "commit": commit.strip() if commit else None,
            "dirty_files": dirty, "source_sha256": source_hash()}


def file_digest(path: str | Path, limit: int = 8_000_000) -> dict | None:
    """{"path" (resolved), "sha256", "bytes"} of a regular file, or None if it is not one or is
    unreadable or larger than `limit`. Used to pin the files that served a control."""
    try:
        p = Path(path).resolve()
        if not p.is_file() or p.stat().st_size > limit:
            return None
        data = p.read_bytes()
    except (OSError, ValueError):
        return None
    return {"path": str(p), "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def spec_hash(spec: dict | None) -> str | None:
    if spec is None:
        return None
    return hashlib.sha256(json.dumps(spec, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


# Run in the integration's own interpreter, with its environment and working directory
# (not isolated: the integration itself is not), so the answer describes what it imports.
VERSION_PROBE = r"""
import base64, hashlib, json, sys, importlib.metadata as m
out = {"python": sys.version.split()[0], "executable": sys.executable, "dists": {}}
for name in json.loads(sys.argv[1]):
    try:
        d = m.distribution(name)
    except m.PackageNotFoundError:
        out[name] = None
        out["dists"][name] = None
        continue
    checked = modified = missing = 0
    changed = []
    for f in d.files or []:
        if f.hash is None or f.hash.mode != "sha256":
            continue
        p = f.locate()
        try:
            data = open(p, "rb").read()
        except OSError:
            missing += 1
            continue
        checked += 1
        got = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        if got != f.hash.value:
            modified += 1
            changed.append(str(f))
    out[name] = d.version
    out["dists"][name] = {"version": d.version, "location": str(d.locate_file("")),
                          "files_checked": checked, "files_modified": modified,
                          "files_missing": missing, "modified": changed[:20]}
print(json.dumps(out))
"""


def probe_versions(python: str, dists: list[str], cwd: Path | None = None, env: dict | None = None) -> dict:
    """Versions as the integration's interpreter sees them, plus install integrity: every
    installed file whose RECORD carries a hash is re-hashed. A locally patched install
    is reported as modified, so a result is not credited to a release it did not run."""
    try:
        r = subprocess.run([python, "-c", VERSION_PROBE, json.dumps(dists)], capture_output=True,
                           text=True, timeout=120, cwd=str(cwd) if cwd else None, env=env)
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"error": str(e)}
    try:
        return json.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"error": (r.stderr or r.stdout)[-300:]}


def integrity_problems(versions: dict) -> list[str]:
    out = []
    for name, d in (versions.get("dists") or {}).items():
        if d is None:
            out.append(f"{name} is not installed in the integration's environment")
        elif d.get("files_modified") or d.get("files_missing"):
            out.append(f"{name} {d['version']}: {d['files_modified']} installed file(s) differ from the "
                       f"release and {d['files_missing']} are missing (locally patched?)")
    return out


def docs_version_problems(documented_source: dict, versions: dict) -> list[str]:
    """Expectations are quoted from docs read for a stated version. If the installed
    version of a package named there differs, the documented verdict may not apply."""
    read_for = (documented_source or {}).get("read_for") or ""
    out = []
    for name, ver in versions.items():
        if name in ("python", "executable", "dists", "node", "error") or not isinstance(ver, str):
            continue
        m = re.search(rf"(?<![\w@/-]){re.escape(name)}\s+v?(\d[\w.+-]*)", read_for)
        if m and m.group(1).rstrip(".,;)") != ver:
            out.append(f"docs were read for {name} {m.group(1).rstrip('.,;)')}, installed is {ver}")
    return out


def _vtuple(v: str) -> tuple | None:
    """Leading numeric release of a version ("1.105.0rc1" -> (1, 105, 0)); None if it has none.
    Only used to say "past" or "before"; a version that cannot be read is reported as "differs"."""
    m = re.match(r"v?(\d+(?:\.\d+)*)", v)
    return tuple(int(x) for x in m.group(1).split(".")) if m else None


def docs_versions(documented_source: dict, versions: dict) -> list[dict]:
    """For each package the expectations name a docs version for: the version the docs were
    read for, the installed one, and how they relate ("matches", "past" the docs, "before" them,
    "differs" when the order cannot be read). The same match rule as docs_version_problems, but it
    keeps the matches too, so an upgrade report can say which docs are due for a re-read."""
    read_for = (documented_source or {}).get("read_for") or ""
    out = []
    for name, ver in versions.items():
        if name in ("python", "executable", "dists", "node", "error") or not isinstance(ver, str):
            continue
        m = re.search(rf"(?<![\w@/-]){re.escape(name)}\s+v?(\d[\w.+-]*)", read_for)
        if not m:
            continue
        doc = m.group(1).rstrip(".,;)")
        a, b = _vtuple(doc), _vtuple(ver)
        rel = ("matches" if doc == ver else "differs" if a is None or b is None or a == b
               else "past" if b > a else "before")
        out.append({"package": name, "docs_read_for": doc, "installed": ver, "relation": rel})
    return out
