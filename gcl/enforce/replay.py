"""`gcl replay BUNDLE`: re-run exactly one stored finding, offline, from its pinned inputs.

A repro bundle (contracts.write_bundles) says what gcl saw. Replay asks the harder question a
maintainer, or a later reader of a disclosure, cares about: does it happen again, from nothing
but the bundle? It rebuilds the adapter from what the bundle recorded (integration, profile,
the interpreter or environment, the vendor spec, the extras the run used), runs the controls
plus that one scenario, and compares what was observed and judged with what the bundle stored.

Three answers, and the third is never a polite way of saying the first:

  reproduced       same observed outcome, same policy and documented verdicts, with the controls
                   held and every pin matching
  not reproduced   it ran cleanly and came out differently (fixed upstream, or a race)
  unverified       it cannot be said: the bundle is damaged, unsealed or incomplete, the integration
                   is not installed where the bundle says, a pinned version or file changed, the
                   scenario at that id is not the stored one, or the controls broke in the replay

Nothing is guessed to fill a gap. The seal (bundle.json: a sha256 per file) catches a bundle that
was edited, truncated or half-copied; it cannot catch someone who edits a file and its digest
together, which needs a signature (see LIMITATIONS.md).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import shutil
import sys
import tempfile
import time
import zipfile
from pathlib import Path

MANIFEST = "bundle.json"
FORMAT = 1
MAX_ZIP_FILES, MAX_ZIP_BYTES = 200, 64_000_000
VENDOR = ("litellm-vendor", "nemo-vendor")   # adapters built from a --spec
_REQUIRED = ("integration", "scenario", "observed", "verdicts", "client_timeout_s", "replay")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def seal_bundle(d: Path) -> dict:
    """Write bundle.json next to the bundle's files: the sha256 of every file, and one digest over
    all of them. Called by write_bundles once a bundle is complete."""
    files = {p.name: _sha256(p) for p in sorted(d.iterdir()) if p.is_file() and p.name != MANIFEST}
    doc = {"format": FORMAT, "files": files, "bundle_sha256": _bundle_digest(files)}
    (d / MANIFEST).write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return doc


def _bundle_digest(files: dict[str, str]) -> str:
    return hashlib.sha256("".join(f"{n}\0{h}\n" for n, h in sorted(files.items())).encode()).hexdigest()


def verify_seal(d: Path) -> list[str]:
    """Why the bundle cannot be trusted as written; [] when every file matches its digest."""
    mp = d / MANIFEST
    if not mp.is_file():
        return [(f"no {MANIFEST}: the bundle is unsealed (written before replay existed, or the seal was "
                 "removed), so it cannot be shown to be untouched")]
    try:
        doc = json.loads(mp.read_text(encoding="utf-8"))
        files = doc["files"]
        assert isinstance(files, dict) and all(isinstance(h, str) for h in files.values())
    except (ValueError, KeyError, AssertionError, OSError):
        return [f"{MANIFEST} cannot be read"]
    out = []
    if "finding.json" not in files:
        out.append("finding.json is not covered by the seal")
    for name, digest in files.items():
        p = d / name
        if not p.is_file():
            out.append(f"{name} is missing")
        elif _sha256(p) != digest:
            out.append(f"{name} was changed after the bundle was written")
    out += [f"{p.name} is not in the seal (added later)" for p in sorted(d.iterdir())
            if p.is_file() and p.name != MANIFEST and p.name not in files]
    if doc.get("bundle_sha256") != _bundle_digest(files):
        out.append(f"{MANIFEST}'s own digest does not match its file list")
    return out


def _extract(zpath: Path, into: Path) -> None:
    """Unpack a zip without trusting it: no absolute or escaping names, no links, bounded size."""
    with zipfile.ZipFile(zpath) as z:
        infos = z.infolist()
        if len(infos) > MAX_ZIP_FILES or sum(i.file_size for i in infos) > MAX_ZIP_BYTES:
            raise ValueError("the zip is larger than a bundle can be")
        for i in infos:
            name = Path(i.filename)
            if name.is_absolute() or ".." in name.parts or (i.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError(f"the zip holds an unsafe entry: {i.filename}")
        z.extractall(into)


def locate(path: Path, scratch: Path) -> Path:
    """The directory holding finding.json, for a bundle directory or a zip of one."""
    if path.is_file() and zipfile.is_zipfile(path):
        _extract(path, scratch)
        path = scratch
    if not path.is_dir():
        raise FileNotFoundError(f"{path} is not a bundle directory or a zip")
    if (path / "finding.json").is_file():
        return path
    hits = sorted({p.parent for p in path.rglob("finding.json")})
    if len(hits) == 1:
        return hits[0]
    raise FileNotFoundError(f"no finding.json in {path}" if not hits else
                            f"{len(hits)} bundles under {path}: give the one bundle directory to replay")


def _unverified(res: dict, why: str) -> dict:
    res["status"], res["reason"] = "unverified", why
    return res


def replay(path: str | Path, python: str | None = None, allow_drift: bool = False, attest: bool = False,
           progress=None) -> dict:
    """Replay one bundle. See the module docstring for the three statuses. `python` overrides the
    interpreter / environment the bundle recorded. `allow_drift` lets a changed integration
    version or control file through as a note instead of making the replay unverified: the
    question then becomes "does it still happen on this version", which is upgrade-check's."""
    from .adapters import ADAPTERS
    from .contracts import run_contracts

    t0 = time.monotonic()
    res: dict = {"status": "unverified", "reason": "", "bundle": str(path), "checks": [], "notes": [],
                 "scenario": None, "stored": None, "replayed": None}

    def check(name: str, ok: bool, detail: str = "") -> bool:
        res["checks"].append({"check": name, "ok": ok, "detail": detail})
        return ok

    scratch = Path(tempfile.mkdtemp(prefix="gcl-replay-"))
    try:
        try:
            d = locate(Path(path), scratch / "bundle")
        except (OSError, ValueError, zipfile.BadZipFile) as e:
            return _unverified(res, f"the bundle cannot be opened: {e}")
        problems = verify_seal(d)
        if not check("seal", not problems, "; ".join(problems) or "every file matches its digest"):
            return _unverified(res, "the bundle is not intact: " + "; ".join(problems))
        res["bundle_sha256"] = json.loads((d / MANIFEST).read_text(encoding="utf-8"))["bundle_sha256"]
        try:
            f = json.loads((d / "finding.json").read_text(encoding="utf-8"))
            missing = [k for k in _REQUIRED if k not in f]
            assert not missing, "missing " + ", ".join(missing)
            sid, stored_obs = f["scenario"]["id"], f["observed"]
            stored = {"observed": stored_obs, "policy": f["verdicts"]["policy"],
                      "documented": f["verdicts"]["documented"]}
            name, profile = f["integration"]["integration"], f["integration"]["profile"]
        except (ValueError, KeyError, TypeError, AssertionError) as e:
            return _unverified(res, f"finding.json does not hold what a replay needs ({e})")
        res["scenario"] = {k: f["scenario"].get(k) for k in ("id", "stage", "mode", "lang", "role")}
        res["stored"] = stored
        rp = f["replay"]
        cls = ADAPTERS.get(name)
        if cls is None or profile not in cls.documented:
            return _unverified(res, f"this gcl has no adapter {name!r} with profile {profile!r}")
        if rp.get("attack_mode"):
            return _unverified(res, "attack-mode findings need the frozen attack plan, which a bundle does not "
                                    "carry yet: rerun with the --attack-plan the run wrote")

        # The environment: what the bundle was run against, or what the caller points at instead.
        target = python or rp.get("target")
        if not (target and Path(str(target)).exists()):
            installed = (f["integration"].get("install") or {}).get("dists")
            if installed:   # a real package: do not substitute another environment
                return _unverified(res, f"the integration's environment {target!r} is not available: pass "
                                        f"--python (or --env) pointing at one with {', '.join(installed)} installed")
            if cls.runtime != "python":
                return _unverified(res, f"the integration's environment {target!r} is not available: pass --env")
            target = sys.executable   # a script that needs only a Python 3 (the bundled reference gateways)
            res["notes"].append(f"the recorded interpreter is not here; used {target}")
        (scratch / "work").mkdir(exist_ok=True)
        if name in VENDOR:
            if not rp.get("spec"):
                return _unverified(res, f"{name} needs the vendor spec, and the bundle does not carry it")
            adapter = cls(str(target), scratch / "work", profile, spec=rp["spec"])
        else:
            adapter = cls(str(target), scratch / "work", profile)
        if rp.get("judge_latency_s"):
            adapter.scanner_latency_s = rp["judge_latency_s"]

        # Pins that can be checked before anything is started.
        try:
            now = adapter.describe()
        except Exception as e:   # the version probe could not run in that environment
            return _unverified(res, f"the integration could not be inspected: {type(e).__name__}: {e}")
        drift = []
        for pkg, was in (f["integration"].get("versions") or {}).items():
            if pkg in ("python", "node", "error") or not isinstance(was, str):
                continue
            if (now["versions"] or {}).get(pkg) != was:
                drift.append(f"{pkg} was {was}, is {(now['versions'] or {}).get(pkg)}")
        was_mod = (((f.get("receipt") or {}).get("control_path") or {}).get("control_module") or {})
        now_mod = adapter._control_module() or {}
        if was_mod.get("sha256") and was_mod["sha256"] != now_mod.get("sha256"):
            drift.append(f"the control module {Path(str(was_mod.get('path'))).name} changed "
                         f"(sha256 {str(was_mod['sha256'])[:12]} -> {str(now_mod.get('sha256'))[:12]})")
        if not check("pins", not drift or allow_drift, "; ".join(drift) or "versions and control file match"):
            return _unverified(res, "a pinned input changed, so this is not a replay of that finding: "
                               + "; ".join(drift) + " (--allow-version-drift runs it anyway)")
        if drift:
            res["notes"].append("ran on drifted inputs (--allow-version-drift): " + "; ".join(drift))

        timeout = float(f["client_timeout_s"])
        try:
            run = run_contracts(adapter, timeout, progress=progress, only={sid},
                                extra=tuple(rp.get("extra") or ()), mcp_protocol=rp.get("mcp_protocol") or "2025-03-26",
                                attest=attest)
        except Exception as e:   # the integration did not start, or the run itself failed
            return _unverified(res, f"the replay could not run: {type(e).__name__}: {e}")
        got = next((r for r in run["results"] if r["scenario"]["id"] == sid), None)
        if got is None:
            return _unverified(res, f"scenario {sid} does not exist in the rebuilt plan (extras {rp.get('extra')})")
        same_scenario = all(got["scenario"].get(k) == f["scenario"].get(k)
                            for k in ("stage", "mode", "lang", "role", "user_text", "reply_text")
                            if k in got["scenario"] and k in f["scenario"])
        if not check("scenario", same_scenario, "the scenario at this id is the stored one"
                     if same_scenario else "the scenario at this id differs from the stored one"):
            return _unverified(res, f"scenario {sid} is not the stored scenario any more (this gcl plans it "
                                    "differently)")
        res["replayed"] = {"observed": got["observed"], "policy": got["policy"], "documented": got["documented"]}
        res["controls"] = [{"id": r["scenario"]["id"], "stage": r["scenario"]["stage"], "mode": r["scenario"]["mode"],
                            "observed": r["observed"], "policy": r["policy"]}
                           for r in run["results"] if r["scenario"]["control"]]
        mc = run.get("mutation_control") or {}
        if mc.get("requested"):
            check("mutation control", mc["state"] == "passed", mc["reason"])
        # The launched files, now, against the ones the bundle named: same control code?
        was_files = {Path(x["path"]).name: x["sha256"] for la in ((f.get("receipt") or {}).get("control_path") or {})
                     .get("launched") or [] for x in la.get("files") or []}
        now_files = {Path(x["path"]).name: x["sha256"] for la in (run["receipt"].get("control_path") or {})
                     .get("launched") or [] for x in la.get("files") or []}
        moved = sorted(n for n, h in was_files.items() if now_files.get(n) != h)
        if not check("launched files", not moved or allow_drift, ", ".join(moved) + " differ from the bundle's"
                     if moved else "the files the integration was launched from match the bundle's"):
            return _unverified(res, "the files the integration was launched from differ from the bundle's ("
                               + ", ".join(moved) + "): not the same control")
        config_bundle = {p.name[len("config-"):]: p.read_text(encoding="utf-8") for p in d.glob("config-*")}
        config_now = {Path(n).name: t for n, t in (run.get("config_files") or {}).items()}
        res["config_identical"] = config_bundle == config_now if (config_bundle or config_now) else None
        if res["config_identical"] is False:
            res["notes"].append("the regenerated configuration differs from the bundle's (ports and paths are "
                                "expected to; compare config-* if the setup matters)")
        if mc.get("state") == "failed":
            return _unverified(res, "the mutation control failed on replay: " + mc["reason"])
        if got["policy"] == "unverified" and stored["policy"] != "unverified":
            return _unverified(res, "the replay could not be judged: " + "; ".join(got["notes"][-2:]))
        if res["replayed"] == stored:
            res["status"] = "reproduced"
            res["reason"] = (f"{res['scenario']['stage']} {res['scenario']['mode']}: observed {got['observed']}, "
                             f"policy {got['policy']}, as stored" + (" (the finding was unverified and still is)"
                                                                     if stored["policy"] == "unverified" else ""))
        else:
            res["status"] = "not reproduced"
            res["reason"] = (f"stored observed {stored['observed']} / {stored['policy']} / {stored['documented']}; "
                             f"replayed {got['observed']} / {got['policy']} / {got['documented']}")
        return res
    finally:
        res["elapsed_s"] = round(time.monotonic() - t0, 1)
        with contextlib.suppress(OSError):
            shutil.rmtree(scratch, ignore_errors=True)
