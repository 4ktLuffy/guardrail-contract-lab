"""A findings ledger that only holds what runs can back.

A finding is created from a scenario in a stored `gcl enforce` report, never typed by
hand. It moves through states, each change naming its evidence:

  proposed      one run shows it
  repeated      a second, separate run (another run id) shows the same outcome; this
                shares gcl's stand-in, so it is not independent evidence
  confirmed     repeated, plus a hand reproduction that declares where its guard answers
                came from — not from gcl's stand-in — and does not reuse them; never for a
                result that rests on a guessed stand-in unless the reproduction used real
                (recorded or live) vendor answers
  contradicted  a later run of the same scenario, same versions, came out differently
  retracted     withdrawn, with a reason; the record and its history stay

`check` re-validates every finding against the reports it names (present, unchanged,
still showing the claimed outcome) and against any newer reports: a newer report with
the same scenario and versions that disagrees marks it contradicted; one with a changed
gcl source, stand-in or spec marks it stale. The ledger is private material: it may not
live inside gcl's own checkout.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import subprocess
from pathlib import Path

from . import severity as S

LEAKY = ("violated",)
ANSWER_SOURCES = ("recorded", "live-vendor", "vendor-docs")
STANDIN_MARK = "GCL-BLOCKED by the stand-in"


class LedgerError(ValueError):
    pass


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def _sha(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _gcl_checkout() -> Path | None:
    root = Path(__file__).resolve().parent.parent
    return root if (root / ".git").exists() else None


def guard_location(ledger: Path) -> list[str]:
    """Refuse a ledger inside gcl's own (public) checkout; warn when it would be tracked
    by some other git repository."""
    ledger = ledger.resolve()
    co = _gcl_checkout()
    if co and (ledger == co or co in ledger.parents):
        raise LedgerError(f"{ledger} is inside gcl's own checkout ({co}); findings are private — keep the "
                          "ledger outside any public repository")
    warn = []
    try:
        r = subprocess.run(["git", "-C", str(ledger.parent), "check-ignore", "-q", str(ledger)],
                           capture_output=True, timeout=10)
        inside = subprocess.run(["git", "-C", str(ledger.parent), "rev-parse", "--is-inside-work-tree"],
                                capture_output=True, text=True, timeout=10).stdout.strip() == "true"
        if inside and r.returncode != 0:
            warn.append(f"{ledger} is inside a git work tree and not ignored: make sure that repository is private")
    except (OSError, subprocess.TimeoutExpired):
        pass
    return warn


def load(ledger: Path) -> dict:
    if not ledger.exists():
        return {"ledger": "gcl findings", "version": 1, "findings": []}
    return json.loads(ledger.read_text(encoding="utf-8"))


def save(ledger: Path, doc: dict) -> None:
    ledger.parent.mkdir(parents=True, exist_ok=True)
    tmp = ledger.with_suffix(ledger.suffix + ".tmp")
    tmp.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(ledger)


def _runs_in(report: Path) -> list[dict]:
    doc = json.loads(report.read_text(encoding="utf-8"))
    if "enforce_by_latency" in doc:
        return doc["enforce_by_latency"]
    if "enforce" in doc:
        return [doc["enforce"]]
    raise LedgerError(f"{report} is not a gcl enforce report")


def _key(run: dict, r: dict) -> dict:
    i, s = run["integration"], r["scenario"]
    return {"integration": i["integration"], "profile": i["profile"], "stage": s["stage"], "mode": s["mode"],
            "role": s.get("role") or "", "lang": s["lang"], "judge_latency_s": run.get("judge_latency_s"),
            "stream": bool(s.get("stream")), "history": bool(s.get("history")), "attack": s.get("attack") or ""}


# Fields of a run's evidence that are derived from the report: `check` recomputes them all.
DERIVED = ("run_id", "scenario_id", "lang", "observed", "policy", "documented", "confidence", "stand_in",
           "versions", "gcl_commit", "gcl_source_sha256", "gcl_dirty", "spec_sha256", "receipt_problems")


def _receipt_ok(run: dict) -> None:
    """A run counts only with a receipt: a run id, and no listed problems."""
    rc = run.get("receipt")
    if not isinstance(rc, dict) or not rc.get("run_id") or not (rc.get("gcl") or {}).get("source_sha256"):
        raise LedgerError("the run has no receipt (run id and gcl source): it cannot back a finding")
    if rc.get("problems"):
        raise LedgerError("the run's receipt lists problems (" + "; ".join(rc["problems"]) +
                          "): re-run from a clean checkout and an unmodified install")


def _evidence(report: Path, run: dict, r: dict) -> dict:
    rc = run.get("receipt") or {}
    g = rc.get("gcl") or {}
    i = run["integration"]
    return {"report": str(report.resolve()), "report_sha256": _sha(report), "run_id": rc.get("run_id"),
            "scenario_id": r["scenario"]["id"], "lang": r["scenario"]["lang"],
            "observed": r["observed"], "policy": r["policy"], "documented": r["documented"],
            "confidence": r["evidence"].get("confidence"), "stand_in": r["evidence"].get("stand_in"),
            "versions": i.get("versions"), "gcl_commit": g.get("commit"), "gcl_source_sha256": g.get("source_sha256"),
            "gcl_dirty": bool(g.get("dirty_files")), "spec_sha256": rc.get("spec_sha256"),
            "receipt_problems": rc.get("problems") or [], "added": _now()}


def _find(run_list: list[dict], scenario: str, run_id: str | None = None) -> tuple[dict, dict]:
    hits = [(run, r) for run in run_list if run_id is None or (run.get("receipt") or {}).get("run_id") == run_id
            for r in run["results"] if r["scenario"]["id"] == scenario]
    if not hits:
        raise LedgerError(f"scenario {scenario}" + (f" of run {run_id}" if run_id else "") + " is not in the report")
    if len(hits) > 1:
        raise LedgerError(f"scenario {scenario} is in several runs of this report: name the run (latency)")
    return hits[0]


def _get(doc: dict, fid: str) -> dict:
    for f in doc["findings"]:
        if f["id"] == fid:
            return f
    raise LedgerError(f"no finding {fid}")


def _move(f: dict, to: str, why: str, runs: list[str] | None = None) -> None:
    f["history"].append({"at": _now(), "from": f["status"], "to": to, "why": why, "runs": runs or []})
    f["status"] = to


def add(doc: dict, report: Path, scenario: str, title: str, latency: float | None = None) -> dict:
    runs = _runs_in(report)
    if latency is not None:
        runs = [r for r in runs if r.get("judge_latency_s") == latency]
    run, r = _find(runs, scenario)
    if r["policy"] == "unverified":
        raise LedgerError(f"{scenario} is unverified in this run: not evidence of anything")
    if r["policy"] not in LEAKY and r["documented"] != "deviates":
        raise LedgerError(f"{scenario} held and conforms to the docs: nothing to report")
    _receipt_ok(run)
    ev = _evidence(report, run, r)
    key = _key(run, r)
    fid = "F-" + hashlib.sha256(json.dumps(key, sort_keys=True).encode()).hexdigest()[:8]
    if any(f["id"] == fid for f in doc["findings"]):
        raise LedgerError(f"{fid} already exists for this scenario; use `repeat`")
    f = {"id": fid, "title": title, "key": key, "status": "proposed",
         "guessed": ev["confidence"] == "guessed", "evidence_level": "end-to-end run", "runs": [ev],
         "hand_repro": None, "history": []}
    f["history"].append({"at": _now(), "from": None, "to": "proposed", "why": "created from a run",
                         "runs": [ev["run_id"]]})
    f["severity"] = S.score(f)
    doc["findings"].append(f)
    return f


def set_field(doc: dict, fid: str, name: str, value, reason: str) -> dict:
    """A rating input only a person can know (is this the default configuration? who
    really has to misbehave?), with the reason written down."""
    f = _get(doc, fid)
    if name not in S.HUMAN_FIELDS:
        raise LedgerError(f"settable fields: {', '.join(S.HUMAN_FIELDS)}")
    if name == "trigger" and value not in S.TRIGGER_POINTS:
        raise LedgerError(f"trigger is one of: {', '.join(S.TRIGGER_POINTS)}")
    if not reason.strip():
        raise LedgerError("a reason is required")
    f.setdefault("human_fields", {})[name] = {"value": value, "reason": reason, "at": _now()}
    f["severity"] = S.score(f)
    f["history"].append({"at": _now(), "from": f["status"], "to": f["status"],
                         "why": f"{name} set to {value!r}: {reason}", "runs": []})
    return f


def override(doc: dict, fid: str, value: int, reason: str) -> dict:
    """A person's own number, kept next to the computed one, never instead of it."""
    f = _get(doc, fid)
    if not 1 <= value <= 10 or not reason.strip():
        raise LedgerError("an override is 1..10 and needs a reason")
    f["severity_override"] = {"score": value, "reason": reason, "at": _now()}
    f["history"].append({"at": _now(), "from": f["status"], "to": f["status"],
                         "why": f"severity overridden to {value}: {reason}", "runs": []})
    return f


def repeat(doc: dict, fid: str, report: Path) -> dict:
    f = _get(doc, fid)
    if f["status"] == "retracted":
        raise LedgerError(f"{fid} is retracted")
    candidates = [(run, r) for run in _runs_in(report) for r in run["results"] if _key(run, r) == f["key"]]
    if len(candidates) != 1:
        raise LedgerError(f"the report has {len(candidates)} scenarios matching {f['key']}: need exactly one")
    run, r = candidates[0]
    _receipt_ok(run)
    ev = _evidence(report, run, r)
    if ev["run_id"] in {x["run_id"] for x in f["runs"]}:
        raise LedgerError(f"run {ev['run_id']} is already part of {fid}: a repeat needs a separate run")
    f["runs"].append(ev)
    first = f["runs"][0]
    same = (ev["observed"], ev["policy"]) == (first["observed"], first["policy"])
    if not same:
        _move(f, "contradicted", f"run {ev['run_id']} observed {ev['observed']}/{ev['policy']}, "
              f"first run {first['observed']}/{first['policy']}", [ev["run_id"]])
    elif f["status"] == "proposed":
        _move(f, "repeated", "a separate run shows the same outcome (same stand-in: not independent)",
              [ev["run_id"]])
    f["severity"] = S.score(f)
    return f


def confirm(doc: dict, fid: str, repro: Path, answer_source: str, note: str) -> dict:
    f = _get(doc, fid)
    if f["status"] != "repeated":
        raise LedgerError(f"{fid} is {f['status']}: confirm needs a repeated finding")
    if answer_source not in ANSWER_SOURCES:
        raise LedgerError(f"declare where the reproduction's guard answers came from: {', '.join(ANSWER_SOURCES)} "
                          "(gcl's own stand-in answers are not independent evidence)")
    if f["guessed"] and answer_source == "vendor-docs":
        raise LedgerError(f"{fid} rests on a guessed stand-in answer: confirm it with recorded or live vendor answers")
    text = repro.read_text(encoding="utf-8", errors="replace")
    if not text.strip() or not note.strip():
        raise LedgerError("a confirmation needs a non-empty reproduction and a note saying what it showed")
    if STANDIN_MARK in text:
        raise LedgerError(f"{repro} reuses gcl's stand-in answers ({STANDIN_MARK!r}): not an independent reproduction")
    f["hand_repro"] = {"path": str(repro.resolve()), "sha256": _sha(repro), "answer_source": answer_source,
                       "note": note, "added": _now()}
    f["evidence_level"] = "end-to-end run + independent reproduction"
    _move(f, "confirmed", f"hand reproduction with {answer_source} answers: {note}")
    f["severity"] = S.score(f)
    return f


def disclose(doc: dict, fid: str, where: str) -> dict:
    """Mark a finding as disclosed to its maintainers (where: an issue URL, an advisory,
    a dated email reference). Only disclosed findings appear in a public table."""
    f = _get(doc, fid)
    if not where.strip():
        raise LedgerError("say where it was disclosed (issue URL, advisory, dated reference)")
    if f["status"] == "retracted":
        raise LedgerError(f"{fid} is retracted")
    f["disclosed"] = {"where": where, "at": _now()}
    f["history"].append({"at": _now(), "from": f["status"], "to": f["status"], "why": f"disclosed: {where}",
                         "runs": []})
    return f


def retract(doc: dict, fid: str, reason: str) -> dict:
    f = _get(doc, fid)
    if not reason.strip():
        raise LedgerError("a retraction needs a reason")
    _move(f, "retracted", reason)
    return f


def check(doc: dict, runs_dir: Path | None = None) -> list[dict]:
    """Problems, one per finding and cause. Retracted findings are only checked for an
    intact record."""
    problems = []

    def bad(f, what):
        problems.append({"id": f["id"], "problem": what})

    newer = []
    if runs_dir is not None:
        for rep in sorted(runs_dir.rglob("report.json")):
            try:
                for run in _runs_in(rep):
                    newer.append((rep, run))
            except (LedgerError, ValueError, KeyError):
                continue
    for f in doc["findings"]:
        if not f.get("history"):
            bad(f, "no history: the record was edited by hand")
        if f["status"] == "retracted":
            continue
        ids = {x["run_id"] for x in f["runs"]}
        derived_guessed = False
        for ev in f["runs"]:
            p = Path(ev["report"])
            if not p.exists():
                bad(f, f"run {ev['run_id']}: report {p} is missing")
                continue
            if _sha(p) != ev["report_sha256"]:
                bad(f, f"run {ev['run_id']}: report {p} changed since it was added")
                continue
            try:
                run, r = _find(_runs_in(p), ev["scenario_id"], ev["run_id"])
                _receipt_ok(run)
            except LedgerError as e:
                bad(f, f"run {ev['run_id']}: {e}")
                continue
            if _key(run, r) != f["key"]:
                bad(f, f"run {ev['run_id']}: the report's scenario is {_key(run, r)}, not the finding's")
            fresh = _evidence(p, run, r)
            for k in DERIVED:
                if fresh[k] != ev.get(k):
                    bad(f, f"run {ev['run_id']}: the ledger says {k}={ev.get(k)!r}, the report {fresh[k]!r}")
            derived_guessed |= fresh["confidence"] == "guessed"
        if len(ids) != len(f["runs"]):
            bad(f, "the same run is listed twice")
        if bool(f.get("guessed")) != derived_guessed:
            bad(f, f"the ledger says guessed={f.get('guessed')}, its runs say {derived_guessed}")
        for name, h in (f.get("human_fields") or {}).items():
            why = S.invalid_human_field(name, h)
            if why:
                bad(f, f"human field {name}: {why}")
        ov = f.get("severity_override")
        if ov is not None and not (isinstance(ov.get("score"), int) and 1 <= ov["score"] <= 10
                                   and str(ov.get("reason") or "").strip()):
            bad(f, "the severity override needs a 1..10 score and a reason")
        if (f.get("history") or [{}])[-1].get("to") != f["status"]:
            bad(f, f"status {f['status']} is not where its history ends")
        if f["status"] in ("repeated", "confirmed") and len(ids) < 2:
            bad(f, f"{f['status']} needs two separate runs, it has {len(ids)}")
        if f["status"] == "confirmed":
            hr = f.get("hand_repro") or {}
            rp = Path(hr.get("path") or "/nonexistent")
            if hr.get("answer_source") not in ANSWER_SOURCES:
                bad(f, "confirmed without a declared answer source")
            if not rp.exists():
                bad(f, f"its reproduction {rp} is missing")
            elif _sha(rp) != hr.get("sha256") or not rp.read_text(errors="replace").strip():
                bad(f, f"its reproduction {rp} changed or is empty")
        again = S.score(f)
        if (f.get("severity") or {}).get("score") != again["score"]:
            bad(f, f"severity drift: stored {(f.get('severity') or {}).get('score')}, the rubric gives "
                   f"{again['score']} ({again['why']})")
        versions = {json.dumps(ev["versions"], sort_keys=True) for ev in f["runs"]}
        if len(versions) > 1:
            bad(f, "its runs were made on different versions")
        if f["status"] == "confirmed" and f["guessed"] and (f.get("hand_repro") or {}).get("answer_source") \
                not in ("recorded", "live-vendor"):
            bad(f, "confirmed on a guessed stand-in without recorded or live vendor answers")
        last = f["runs"][-1]
        for rep, run in newer:
            rid = (run.get("receipt") or {}).get("run_id")
            if rid in ids:
                continue
            for r in run["results"]:
                if _key(run, r) != f["key"] or r["policy"] == "unverified":
                    continue
                if run["integration"].get("versions") != last["versions"]:
                    continue  # another version: a separate question, not a contradiction
                if (r["observed"], r["policy"]) != (last["observed"], last["policy"]):
                    bad(f, f"contradicted by run {rid} ({rep}): {r['observed']}/{r['policy']}")
                g = (run.get("receipt") or {}).get("gcl") or {}
                if g.get("source_sha256") != last["gcl_source_sha256"] or \
                        (run.get("receipt") or {}).get("spec_sha256") != last["spec_sha256"]:
                    bad(f, f"stale: run {rid} used another gcl source or spec; re-run and `repeat`")
    return problems


def render(doc: dict) -> str:
    """The ledger as a table. Every qualifier is a column, so a summary cannot drop it."""
    head = ("| Id | Status | Finding | Integration (profile) | Stage / mode | Observed | Stand-in | Runs | "
            "Versions | Evidence | Severity |")
    lines = [head, "|" + "---|" * 11]
    for f in doc["findings"]:
        k, last = f["key"], f["runs"][-1]
        vers = ", ".join(f"{a} {b}" for a, b in (last["versions"] or {}).items() if b)
        lines.append(f"| {f['id']} | {f['status']} | {f['title']} | {k['integration']} ({k['profile']}) | "
                     f"{k['stage']} / {k['mode']}{' (' + k['role'] + ')' if k['role'] else ''} | "
                     f"{last['observed']} / {last['policy']} | "
                     f"{'GUESSED ' if f['guessed'] else ''}{last['stand_in']} | {len(f['runs'])} | {vers} | "
                     f"{f['evidence_level']} | {_sev(f)} |")
    return "\n".join(lines)


def _sev(f: dict) -> str:
    sv, ov = f.get("severity") or {}, f.get("severity_override")
    txt = f"{sv.get('score')} ({sv.get('why')})"
    return txt + (f"; a person rates it {ov['score']}: {ov['reason']}" if ov else "")
