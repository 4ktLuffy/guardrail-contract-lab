"""`gcl compare`: what changed between two enforce reports — typically the same
integration before and after an upgrade.

Scenarios are matched by what they test (stage, guard behaviour, role, language), not by
id. A result that held before and is violated now is a regression; violated → held is a
fix; anything that became or stopped being unverified is listed separately, because it
says the run, not the integration, changed.
"""

from __future__ import annotations

import json
from pathlib import Path


def _run(path: Path) -> dict:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    run = doc.get("enforce") or doc
    if "results" not in run:
        raise ValueError(f"{path} is not a gcl enforce report")
    return run


def _key(r: dict) -> tuple:
    s = r["scenario"]
    return (s["stage"], s["mode"], s.get("role") or "", s["lang"])


def compare(old_path: Path, new_path: Path) -> dict:
    old, new = _run(old_path), _run(new_path)
    if (old["integration"]["integration"], old["integration"]["profile"]) != \
            (new["integration"]["integration"], new["integration"]["profile"]):
        raise ValueError("the two reports are for different integrations or profiles")
    a = {_key(r): r for r in old["results"]}
    b = {_key(r): r for r in new["results"]}
    out = {"old": {"versions": old["integration"].get("versions"), "run_id": (old.get("receipt") or {}).get("run_id")},
           "new": {"versions": new["integration"].get("versions"), "run_id": (new.get("receipt") or {}).get("run_id")},
           "regressions": [], "fixes": [], "changed": [], "unverified_changes": [], "only_old": [], "only_new": []}
    for k in sorted(set(a) | set(b)):
        name = "/".join(x for x in k if x)
        if k not in b:
            out["only_old"].append(name)
            continue
        if k not in a:
            out["only_new"].append(name)
            continue
        x, y = a[k], b[k]
        row = {"scenario": name, "old": f"{x['observed']}/{x['policy']}", "new": f"{y['observed']}/{y['policy']}"}
        if x["policy"] == y["policy"] and x["observed"] == y["observed"]:
            continue
        if "unverified" in (x["policy"], y["policy"]):
            out["unverified_changes"].append(row)
        elif x["policy"] == "held" and y["policy"] == "violated":
            out["regressions"].append(row)
        elif x["policy"] == "violated" and y["policy"] == "held":
            out["fixes"].append(row)
        else:
            out["changed"].append(row)
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
