"""`gcl upgrade-check`: the same enforce plan against the installed version and the one you are
about to move to, and one report of what that move changed.

Why a command of its own, when `gcl compare` exists: a before/after run has to be done the same
way twice (same plan, same options), and an upgrade breaks things in ways a plain diff of two
reports under-reports. LiteLLM v1.101.4 shipped a default that broke every request on one kind of
guardrail; a guard can start silently absent after an upgrade; NeMo changed fail-open / fail-closed
in a minor release. So on top of compare's logic (`compare.classify`, shared, so the two commands
never disagree about a regression) this adds:

* a row that held before and is only "unverified" now is a regression too (the run can no longer
  show what it showed), unless the after-run's own controls are broken, in which case nothing in
  that run is evidence and the comparison is reported unverified, not regressed;
* "was the guard consulted at all": the controls send a benign and a flagged message through each
  stage, so a stage whose controls produced no valid scanner request in the after-run (and some in
  the before-run) means the guard is absent after the upgrade, whether or not the scenarios that
  followed leaked. A guard silent in BOTH runs proves nothing about either and is unverified;
* which documented expectations are due a re-read: the version each expectation's docs were read for
  against each installed version. That is the only default-drift signal gcl can PROVE: it does not
  read the integration's effective defaults, so a changed default shows up only through a changed
  scenario result, never through this table.

Exit: 1 on any regression (held -> violated, held -> unverified, a guard gone absent), 2 if there is
none but the comparison could not be made (a side's controls unusable, the guard never consulted,
scenarios on one side only), 0 otherwise. Nothing is "held" or "violated" here that the enforce runs
did not prove; unproven is "unverified".
"""

from __future__ import annotations

from types import SimpleNamespace

from .compare import _index, _name, _runs, classify, compare_runs
from .enforce import receipt as _rc

CATEGORIES = ("regressions", "unverified_regressions", "improvements", "now_verified", "unverified_changes",
              "changed", "unchanged", "unverified_comparison")


def controls_usable(run: dict) -> tuple[bool, list[str]]:
    """Whether the opening and closing controls of one run were usable (the same test the run
    itself applied: contracts._usable). Returns (ok, ids of the controls that were not)."""
    from .enforce.contracts import _usable

    bad = []
    for r in run["results"]:
        s = r["scenario"]
        if s.get("role") not in ("open", "close"):
            continue
        shim = SimpleNamespace(observed=r["observed"], policy=r["policy"], documented=r["documented"],
                               scenario=SimpleNamespace(mode=s["mode"]))
        if not _usable(shim):
            bad.append(s["id"])
    return (not bad), bad


def guard_consulted(run: dict) -> dict:
    """Valid scanner requests recorded on the controls, per stage: {"input": n, "output": n}.
    A stage the integration has no controls for is left out. 0 on a stage with controls means the
    guard was never asked there, which no verdict of that run can contradict."""
    out: dict[str, int] = {}
    for r in run["results"]:
        s = r["scenario"]
        if s.get("role") not in ("open", "close"):
            continue
        n = sum(1 for e in (r.get("evidence") or {}).get("scanner_events") or [] if e.get("valid"))
        out[s["stage"]] = out.get(s["stage"], 0) + n
    return out


def _docs(before: dict, after: dict) -> list[dict]:
    """Per package and docs version (an adapter's sources may be read for different versions): both
    installed versions, and whether those docs are due a re-read (the after-install is not the
    version they were read for)."""
    rows: dict[str, dict] = {}
    for side, run in (("before", before), ("after", after)):
        i = run["integration"]
        sources = [i.get("documented_source") or {}, *(i.get("config_documented_source") or [])]
        for src in sources:
            for d in _rc.docs_versions(src, i.get("versions") or {}):
                row = rows.setdefault((d["package"], d["docs_read_for"]),
                                      {"package": d["package"], "docs_read_for": d["docs_read_for"]})
                row[f"installed_{side}"] = d["installed"]
                row[f"relation_{side}"] = d["relation"]
    out = []
    for row in rows.values():
        row["docs_due"] = row.get("relation_after", "matches") != "matches"
        out.append(row)
    return sorted(out, key=lambda r: (r["package"], r["docs_read_for"]))


def _row(k: tuple, x: dict, y: dict, cat: str) -> dict:
    side = lambda r: {"id": r["scenario"]["id"], "outcome": r["observed"], "policy": r["policy"],  # noqa: E731
                      "documented": r["documented"]}
    return {"scenario": _name(k), "category": cat, "before": side(x), "after": side(y)}


def upgrade_check(before: dict, after: dict) -> dict:
    """Compare two loaded enforce runs (one per install) and judge the upgrade."""
    legacy = compare_runs([before], [after], same_profile=False)  # raises if not the same integration
    a, b = _index([before], "before"), _index([after], "after")
    ok_b, bad_b = controls_usable(before)
    ok_a, bad_a = controls_usable(after)
    rows = []
    for k in sorted(set(a) & set(b), key=str):
        x, y = a[k], b[k]
        cat = classify(x, y)
        if cat is None:
            cat = "unchanged"
        elif cat == "fixes":
            cat = "improvements"
        elif cat == "unverified_changes":
            if x["policy"] == "held" and y["policy"] == "unverified":
                # Only a regression if the after-run could judge anything at all.
                cat = "unverified_regressions" if ok_a else "unverified_comparison"
            elif x["policy"] == "unverified" and y["policy"] == "held":
                cat = "now_verified" if ok_b else "unverified_comparison"
        rows.append(_row(k, x, y, cat))
    g_b, g_a = guard_consulted(before), guard_consulted(after)
    guard = {}
    for st in sorted(set(g_b) | set(g_a)):
        nb, na = g_b.get(st, 0), g_a.get(st, 0)
        status = ("absent_after" if nb > 0 and na == 0 else "never_consulted" if nb == 0 and na == 0
                  else "ok")
        guard[st] = {"before": nb, "after": na, "status": status}
    problems = {"before": list((before.get("receipt") or {}).get("problems") or []),
                "after": list((after.get("receipt") or {}).get("problems") or [])}
    by = {c: [r for r in rows if r["category"] == c] for c in CATEGORIES}
    absent = [st for st, g in guard.items() if g["status"] == "absent_after"]
    never = [st for st, g in guard.items() if g["status"] == "never_consulted"]
    regress = len(by["regressions"]) + len(by["unverified_regressions"]) + len(absent)
    reasons = []
    if not ok_b:
        reasons.append(f"before: controls not usable ({', '.join(bad_b)}): nothing in that run is evidence")
    if not ok_a:
        reasons.append(f"after: controls not usable ({', '.join(bad_a)}): nothing in that run is evidence")
    if never:
        reasons.append(f"guard never consulted at {', '.join(never)} in either run: the controls show nothing")
    if legacy["only_old"] or legacy["only_new"]:
        reasons.append("scenarios on one side only: " + ", ".join(legacy["only_old"] + legacy["only_new"]))
    if not rows:
        reasons.append("no scenario exists on both sides")
    if by["unverified_comparison"]:
        reasons.append(f"{len(by['unverified_comparison'])} row(s) cannot be compared (a side's controls are broken)")
    return {
        "before": {"profile": before["integration"]["profile"], "versions": before["integration"].get("versions"),
                   "run_id": (before.get("receipt") or {}).get("run_id"), "controls_usable": ok_b},
        "after": {"profile": after["integration"]["profile"], "versions": after["integration"].get("versions"),
                  "run_id": (after.get("receipt") or {}).get("run_id"), "controls_usable": ok_a},
        "rows": rows,
        "counts": {c: len(v) for c, v in by.items()},
        "guard": guard,
        "docs": _docs(before, after),
        "receipt_problems": problems,
        "same_generated_config": before["integration"].get("config") == after["integration"].get("config"),
        "only_before": legacy["only_old"], "only_after": legacy["only_new"],
        "regression_count": regress,
        "unverified_reasons": reasons,
        "verdict": "regression" if regress else "unverified" if reasons else "no regression",
        "exit_code": 1 if regress else 2 if reasons else 0,
    }


def check_files(before_path, after_path) -> dict:
    """upgrade_check on two saved enforce reports (single-run reports only)."""
    rb, ra = _runs(before_path), _runs(after_path)
    if len(rb) != 1 or len(ra) != 1:
        raise ValueError("upgrade-check compares single runs, not latency sweeps")
    return upgrade_check(rb[0], ra[0])


def render(d: dict) -> str:
    def ver(side):
        return ", ".join(f"{k} {v}" for k, v in (side["versions"] or {}).items() if v) or "(no versions reported)"

    lines = [f"before: {ver(d['before'])}  profile {d['before']['profile']}  run {d['before']['run_id']}",
             f"after:  {ver(d['after'])}  profile {d['after']['profile']}  run {d['after']['run_id']}", ""]
    lines.append("guard consulted (valid scanner requests on the controls):")
    for st, g in d["guard"].items():
        note = {"absent_after": "  <- GUARD ABSENT AFTER THE UPGRADE",
                "never_consulted": "  <- never asked, in either run"}.get(g["status"], "")
        lines.append(f"  {st}: before {g['before']}, after {g['after']}{note}")
    titles = {"regressions": "REGRESSIONS (held -> violated)",
              "unverified_regressions": "REGRESSIONS (held -> unverified: the run no longer shows it)",
              "improvements": "improvements (violated -> held)", "now_verified": "now verifiable (unverified -> held)",
              "unverified_changes": "unverified in one of the runs", "changed": "other changes",
              "unverified_comparison": "cannot be compared (a side's controls are broken)"}
    for cat, title in titles.items():
        rows = [r for r in d["rows"] if r["category"] == cat]
        if rows:
            lines += ["", f"{title}:"]
            for r in rows:
                b, a = r["before"], r["after"]
                lines.append(f"  {r['scenario']} [{b['id']}->{a['id']}]: {b['outcome']}/{b['policy']}"
                             f"/doc {b['documented']}  ->  {a['outcome']}/{a['policy']}/doc {a['documented']}")
    lines += ["", f"unchanged: {d['counts']['unchanged']} scenario(s)"]
    due = [r for r in d["docs"] if r["docs_due"]]
    lines += ["", "documented expectations (read for a version; the after-install moved past or off it => re-read):"]
    if d["docs"]:
        for r in d["docs"]:
            lines.append(f"  {r['package']}: docs read for {r['docs_read_for']}, "
                         f"before {r.get('installed_before', '?')}, after {r.get('installed_after', '?')}"
                         + ("  <- DOCS RE-READ DUE" if r["docs_due"] else ""))
    else:
        lines.append("  no package version is named in the documented sources of this adapter")
    if due:
        lines.append("  a changed default is only visible above as a changed scenario: gcl does not read the "
                     "integration's effective defaults")
    for side in ("before", "after"):
        for p in d["receipt_problems"][side]:
            lines.append(f"  receipt problem ({side}): {p}")
    if d["unverified_reasons"]:
        lines += ["", "UNVERIFIED:"] + [f"  {x}" for x in d["unverified_reasons"]]
    lines += ["", f"verdict: {d['verdict']} ({d['regression_count']} regression(s))"]
    return "\n".join(lines)
