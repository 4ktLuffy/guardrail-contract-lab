"""`gcl table`: integration × guard behaviour, per version, from stored runs.

Private by default: a table built from your runs contains every result, including
fail-opens no maintainer has been told about yet. With `public=True`, a violation is shown
only if a finding in the ledger covers it and has been marked disclosed
(`gcl findings disclose`); any other violation is printed as "withheld". Holds,
unverified and documented choices are shown either way.
"""

from __future__ import annotations

import json
from pathlib import Path

LEAKS = ("passed", "altered", "blocked after send", "failed after send", "tool executed", "retained",
         "passed unscanned", "passed despite block")  # the last two: an MCP surface (--extra mcp)


def _runs(runs_dir: Path):
    for rep in sorted(Path(runs_dir).rglob("report.json")):
        try:
            doc = json.loads(rep.read_text(encoding="utf-8"))
        except ValueError:
            continue
        for run in doc.get("enforce_by_latency") or ([doc["enforce"]] if "enforce" in doc else []):
            yield rep, run


def _cell(r: dict) -> str:
    if r["policy"] == "n/a":
        return "not carried"
    if r["policy"] == "unverified":
        return "unverified"
    if r["policy"] == "held":
        return "holds"
    if r["observed"] not in LEAKS:  # a contract mismatch where nothing leaked
        return f"{r['observed']} (expected {r['policy_expect']})"
    txt = "FAILS OPEN" if r["documented"] != "conforms" else "fails open (documented)"
    if r["evidence"].get("confidence") == "guessed":
        txt += " (guessed stand-in)"
    return txt


def _ident(run: dict, r: dict) -> tuple:
    """Everything that makes a cell a different result: a disclosure covers exactly one."""
    from .findings import _key

    k = _key(run, r)
    return tuple(sorted(k.items(), key=lambda kv: kv[0]))


def build(runs_dir: Path, ledger: dict | None = None, public: bool = False) -> dict:
    # A disclosure covers the finding's own scenario (full identity) on the versions its
    # runs were made on; a contradicted or retracted finding covers nothing.
    disclosed = {}
    for f in (ledger or {}).get("findings", []):
        if f.get("disclosed") and f["status"] not in ("retracted", "contradicted"):
            key = tuple(sorted(f["key"].items(), key=lambda kv: kv[0]))
            vers = {json.dumps(ev.get("versions"), sort_keys=True) for ev in f.get("runs", [])}
            disclosed.setdefault(key, set()).update(vers)
    cols: list[str] = []
    rows: dict[str, dict] = {}
    withheld = 0
    for _, run in _runs(runs_dir):
        i = run["integration"]
        vers = ", ".join(f"{k} {v}" for k, v in (i.get("versions") or {}).items() if v and k != "python")
        lat = run.get("judge_latency_s")
        name = f"{i['integration']} ({i['profile']}) {vers}" + (f" @{lat:g}s" if lat is not None else "")
        row = rows.setdefault(name, {})
        surfaces: list[str] = []
        for r in run["results"]:
            s = r["scenario"]
            if s.get("control") or s.get("attack"):
                continue
            if s["mode"] == "surface":
                if s["role"]:
                    continue  # the carry control: its result is the attack's "not carried"
                # MCP surfaces share one compact column: "holds" counts, then each failing id.
                covered = json.dumps(i.get("versions"), sort_keys=True) in disclosed.get(_ident(run, r), set())
                if public and r["policy"] == "violated" and not covered:
                    withheld += 1
                    surfaces.append("withheld")
                else:
                    surfaces.append(s["surface"]["id"] + ("" if r["policy"] == "held" else
                                                          ":" + _cell(r).replace(" (documented)", "")))
                continue
            col = f"{s['stage']} {s['mode']}" + (" (stream)" if s.get("stream") else "") + \
                (" (history)" if s.get("history") else "")
            if col not in cols:
                cols.append(col)
            cell = _cell(r)
            covered = json.dumps(i.get("versions"), sort_keys=True) in disclosed.get(_ident(run, r), set())
            if public and r["policy"] == "violated" and not covered:
                cell, withheld = "withheld", withheld + 1
            prev = row.get(col)
            if prev and prev != cell:  # two runs of the same version disagree: say so
                cell = f"{prev} / {cell}"
            row[col] = cell
        if surfaces:
            n_held = sum(1 for x in surfaces if ":" not in x and x != "withheld")
            cell = f"{n_held}/{len(surfaces)} hold" + "".join(f"; {x}" for x in surfaces if ":" in x or x == "withheld")
            if "mcp surfaces" not in cols:
                cols.append("mcp surfaces")
            row["mcp surfaces"] = f"{row['mcp surfaces']} / {cell}" if row.get("mcp surfaces") not in (None, cell) \
                else cell
    return {"columns": cols, "rows": rows, "public": public, "withheld": withheld}


def render(t: dict) -> str:
    head = ("Guardrail failure contract — " + ("public (disclosed results only)" if t["public"] else
            "PRIVATE: contains results not yet disclosed to maintainers — do not publish"))
    lines = [head, "", "| Integration | " + " | ".join(t["columns"]) + " |",
             "|---|" + "---|" * len(t["columns"])]
    for name, row in t["rows"].items():
        lines.append(f"| {name} | " + " | ".join(row.get(c, "") for c in t["columns"]) + " |")
    if t["public"] and t["withheld"]:
        lines.append("")
        lines.append(f"{t['withheld']} result(s) withheld until disclosed.")
    return "\n".join(lines)
