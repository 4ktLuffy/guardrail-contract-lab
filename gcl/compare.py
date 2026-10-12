"""`gcl compare`: what changed between two enforce reports — typically the same
integration before and after an upgrade.

Scenarios are matched by what they test (stage, guard behaviour, role, language), not by
id. A result that held before and is violated now is a regression; violated → held is a
fix; anything that became or stopped being unverified is listed separately, because it
says the run, not the integration, changed. MCP surfaces (`--extra mcp`) are matched by
surface id; a surface that became or stopped being carried ("n/a") is a change, except that
one that became carried and is violated now (n/a -> violated) is a regression: a new leak.
"""

from __future__ import annotations

import json
from pathlib import Path


def _runs(path: Path) -> list[dict]:
    """Every run in a report: all latencies of a sweep, or the one run."""
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    runs = doc.get("enforce_by_latency") or [doc.get("enforce") or doc]
    if not all("results" in r for r in runs):
        raise ValueError(f"{path} is not a gcl enforce report")
    return runs


def _key(run: dict, r: dict) -> tuple:
    s = r["scenario"]
    # A surface is told apart by its id (m01, m01c): stage, mode and role are shared by many. A config
    # check by its kind, since its id depends on what the adapter declares.
    which = s["config"]["check"] if s.get("config") else (s["id"] if s.get("surface") else "")
    return (run.get("judge_latency_s"), s["stage"], s["mode"], which,
            s.get("role") or "", s["lang"], s.get("attack") or "")


def _index(runs: list[dict], path) -> dict:
    out: dict = {}
    for run in runs:
        for r in run["results"]:
            k = _key(run, r)
            if k in out:
                raise ValueError(f"{path}: two scenarios share {k}; they cannot be matched safely")
            out[k] = r
    return out


def _name(k: tuple) -> str:
    lat, *rest = k
    name = "/".join(str(x) for x in rest if x)
    return f"{name} @{lat:g}s" if lat is not None else name


def classify(x: dict, y: dict) -> str | None:
    """How one scenario moved between two results: regressions | fixes | changed |
    unverified_changes, or None when nothing moved. `gcl compare` and `gcl upgrade-check` share this,
    so the two commands can never disagree about what a regression is."""
    if x["policy"] == y["policy"] and x["observed"] == y["observed"]:
        return None
    if x["policy"] == "n/a" and y["policy"] == "violated":
        return "regressions"  # newly carried and unscanned: a new leak
    if "n/a" in (x["policy"], y["policy"]):
        return "changed"  # carried or not is a change of the gateway; violated -> n/a too
    if "unverified" in (x["policy"], y["policy"]):
        return "unverified_changes"
    if x["policy"] == "held" and y["policy"] == "violated":
        return "regressions"
    if x["policy"] == "violated" and y["policy"] == "held":
        return "fixes"
    return "changed"


def compare(old_path: Path, new_path: Path) -> dict:
    return compare_runs(_runs(old_path), _runs(new_path), old_path, new_path)


def compare_runs(old: list[dict], new: list[dict], old_path="old", new_path="new",
                 same_profile: bool = True) -> dict:
    """The comparison on loaded runs. `same_profile=False` lets two profiles of one integration
    be compared (an upgrade check may switch the profile on one side to simulate a break)."""
    ids = {(r["integration"]["integration"], r["integration"]["profile"] if same_profile else "") for r in old + new}
    if len(ids) != 1:
        raise ValueError("the two reports are for different integrations or profiles")
    a, b = _index(old, old_path), _index(new, new_path)
    lat_a = sorted({x.get("judge_latency_s") for x in old}, key=str)
    lat_b = sorted({x.get("judge_latency_s") for x in new}, key=str)
    out = {"old": {"versions": old[0]["integration"].get("versions"),
                   "run_id": [(x.get("receipt") or {}).get("run_id") for x in old], "latencies": lat_a},
           "new": {"versions": new[0]["integration"].get("versions"),
                   "run_id": [(x.get("receipt") or {}).get("run_id") for x in new], "latencies": lat_b},
           "regressions": [], "fixes": [], "changed": [], "unverified_changes": [], "only_old": [], "only_new": []}
    for k in sorted(set(a) | set(b), key=str):
        name = _name(k)
        if k not in b:
            out["only_old"].append(name)
            continue
        if k not in a:
            out["only_new"].append(name)
            continue
        x, y = a[k], b[k]
        cat = classify(x, y)
        if cat:
            out[cat].append({"scenario": name, "old": f"{x['observed']}/{x['policy']}",
                             "new": f"{y['observed']}/{y['policy']}"})
    return out


def render(d: dict) -> str:
    lines = [f"old: {d['old']['versions']} (run {d['old']['run_id']})",
             f"new: {d['new']['versions']} (run {d['new']['run_id']})"]
    for title, key in (("REGRESSIONS (held -> violated)", "regressions"), ("fixes (violated -> held)", "fixes"),
                       ("other changes", "changed"), ("unverified in one of the runs", "unverified_changes")):
        if d[key]:
            lines.append(f"{title}:")
            lines += [f"  {r['scenario']}: {r['old']} -> {r['new']}" for r in d[key]]
    for title, key in (("only in old", "only_old"), ("only in new", "only_new")):
        if d[key]:
            lines.append(f"{title}: {', '.join(d[key])}")
    if len(lines) == 2:
        lines.append("no change")
    return "\n".join(lines)
