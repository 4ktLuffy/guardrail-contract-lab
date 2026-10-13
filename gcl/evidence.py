"""Compliance evidence pack: stored gcl reports in, a hashed, honest mapping to framework provisions out.

`gcl evidence-pack REPORT.json ... --out DIR` writes

  pack.json       the machine-readable pack: what was run, counts per check family, the
                  provision-by-family coverage matrix, the mapping with a reason per row,
                  what was considered and not mapped, application dates with sources
  pack.html       the same, for a person (no scripts, opens from disk)
  inputs/         a copy of every input report, so the hashes can be checked from the pack
  manifest.json   SHA-256 of every input and every output file, each report's run receipt
                  (run id, gcl commit, uncommitted files, integration versions)
  manifest.hmac   only with --sign-key: HMAC-SHA256 over manifest.json

What the pack will not do, by construction:

  * Turn a missing or unclear result into a good one. A matrix cell is "held" only if every
    result in it held; one violation makes it "violated", else one unverified result makes it
    "unverified". A provision a family is mapped to but no input report covers is "not tested".
    The counts are always printed next to the word.
  * Claim a signature. An HMAC proves that whoever made the file held the key and that the
    manifest is unchanged since; it does not say who that was. Without --sign-key nothing is
    called signed.
  * Claim compliance. The mapping is gcl's reading (see gcl/frameworks.py) and the pack says so on
    its first line.

Standard library only: hashlib, hmac, json, html.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import json
from pathlib import Path

from . import __version__
from . import frameworks as FW
from .enforce import receipt as _rc
from .report import html as _H

PACK_VERSION = 1
POLICIES = ("held", "violated", "unverified", "n/a")
# Worst first: a cell shows the worst state it contains and always prints the counts beside it.
SEVERITY = ("violated", "unverified", "held", "n/a")
STATUS_WORDS = {
    "held": "held",
    "violated": "violated",
    "unverified": "unverified",
    "n/a": "not applicable",
    "not tested": "not tested",
}
CONTROL_ROLES = ("open", "close", "lang", "observe", "control")
FAULT_MODES = set(FW.S.FAULT_MODES)
HMAC_STATEMENT = (
    "HMAC-SHA256 over manifest.json. It proves the manifest is unchanged since it was made by someone who held "
    "this key, and it proves that only to someone who also holds the key. It does not identify who that was and "
    "is not a digital signature in the legal sense."
)
SIGNING_NONE = (
    "not signed: no --sign-key was given. The SHA-256 hashes show files are unchanged from the manifest, "
    "not who wrote it."
)


class PackError(ValueError):
    pass


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with Path(p).open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------- reading reports
def kind_of(doc: dict) -> str:
    for k in ("enforce", "coverage", "probe", "check"):
        if isinstance(doc.get(k), dict):
            return k
    return "unknown"


def norm_policy(p) -> str:
    """Anything that is not exactly held / violated / n/a is unverified. Never promoted."""
    return p if p in ("held", "violated", "n/a") else "unverified"


def classify(result: dict) -> str:
    """Check family of one enforce result, or "control" for the tester's own bracketing controls."""
    s = result.get("scenario") or {}
    if s.get("control") or s.get("role") in CONTROL_ROLES:
        return "control"
    if s.get("surface"):
        return "mcp_surfaces"
    if (s.get("config") or {}).get("check"):
        return "config_applied"
    if s.get("attack"):
        return "attack_corpus"
    if s.get("stream") or s.get("history") or s.get("mode") == "history_block":
        return "stream_history"
    if s.get("mode") in FAULT_MODES:
        return "fail_closed"
    return "verdict_controls"


def _skey(result: dict) -> tuple:
    s = result["scenario"]
    return (
        s.get("id"),
        s.get("stage"),
        s.get("mode"),
        (s.get("surface") or {}).get("id") or "",
        (s.get("config") or {}).get("check") or "",
        s.get("attack") or "",
    )


def runs_of(doc: dict) -> list[dict]:
    """The run itself, then any other latency runs of a sweep (the primary run is one of them)."""
    base = doc.get("enforce")
    out = [base] if isinstance(base, dict) else []
    seen = {(base or {}).get("receipt", {}).get("run_id")}
    for r in doc.get("enforce_by_latency") or []:
        rid = (r.get("receipt") or {}).get("run_id")
        if rid not in seen:
            seen.add(rid)
            out.append(r)
    return out


def receipt_of(run: dict) -> dict:
    rc = run.get("receipt") or {}
    g = rc.get("gcl") or {}
    i = run.get("integration") or {}
    return {
        "run_id": rc.get("run_id"),
        "gcl": {
            "version": g.get("version"),
            "commit": g.get("commit"),
            "dirty_files": g.get("dirty_files"),
            "source_sha256": g.get("source_sha256"),
        },
        "spec_sha256": rc.get("spec_sha256"),
        "timeout_s": rc.get("timeout_s"),
        "problems": rc.get("problems") or [],
        "integration": {
            "name": i.get("integration"),
            "profile": i.get("profile"),
            "versions": i.get("versions"),
            "judge_latency_s": run.get("judge_latency_s"),
        },
        "has_receipt": bool(rc.get("run_id")),
    }


def items_of(doc: dict, idx: int) -> list[dict]:
    """Every result in a report as {family, policy, id, report}. Only the primary run feeds the
    check families; the latency family is built across the sweep's runs."""
    out: list[dict] = []
    k = kind_of(doc)
    if k == "enforce":
        run = doc["enforce"]
        for r in run.get("results") or []:
            out.append(
                {
                    "family": classify(r),
                    "policy": norm_policy(r.get("policy")),
                    "id": (r.get("scenario") or {}).get("id"),
                    "report": idx,
                }
            )
        sweep = [x for x in doc.get("enforce_by_latency") or [] if x.get("results")]
        if len({x.get("judge_latency_s") for x in sweep}) >= 2:
            table: dict[tuple, list[str]] = {}
            for x in sweep:
                for r in x["results"]:
                    if classify(r) != "control":
                        table.setdefault(_skey(r), []).append(norm_policy(r.get("policy")))
            for key, pols in table.items():
                worst = next(p for p in SEVERITY if p in pols)
                out.append(
                    {
                        "family": "latency_race",
                        "policy": worst,
                        "id": key[0],
                        "report": idx,
                        "unstable": len(set(pols)) > 1,
                    }
                )
    elif k == "coverage":
        # gcl coverage records recall, not a pass/fail verdict: no threshold is stored in the report,
        # so every language is "unverified" here with its numbers, and is never shown as held.
        for lg, r in ((doc["coverage"].get("by_lang")) or {}).items():
            if r.get("attacks"):
                out.append(
                    {
                        "family": "coverage_recall",
                        "policy": "unverified",
                        "id": lg,
                        "report": idx,
                        "recall_pct": r.get("recall_pct"),
                        "attacks": r.get("attacks"),
                        "fp_pct": r.get("all_benign_fp_pct"),
                    }
                )
    elif k == "probe":
        for s in doc["probe"].get("scenarios") or []:
            out.append(
                {"family": "scanner_probe", "policy": norm_policy(s.get("verdict")), "id": s.get("name"), "report": idx}
            )
    return out


def tally(items: list[dict]) -> dict:
    fams: dict[str, dict] = {}
    for it in items:
        f = fams.setdefault(
            it["family"], {"held": 0, "violated": 0, "unverified": 0, "n/a": 0, "total": 0, "by_report": {}}
        )
        f[it["policy"]] += 1
        f["total"] += 1
        br = f["by_report"].setdefault(
            it["report"],
            {"held": 0, "violated": 0, "unverified": 0, "n/a": 0, "violated_ids": [], "unverified_ids": []},
        )
        br[it["policy"]] += 1
        if it["policy"] in ("violated", "unverified") and len(br[it["policy"] + "_ids"]) < 40:
            br[it["policy"] + "_ids"].append(it["id"])
    for f in fams.values():
        f["by_report"] = [{"report": k, **v} for k, v in sorted(f["by_report"].items())]
    return fams


def status_of(counts: dict | None) -> str:
    """The worst state present; "not tested" when no input covers the family at all. Pure function of the counts."""
    if not counts or not counts.get("total"):
        return "not tested"
    for s in SEVERITY:
        if counts.get(s):
            return s
    return "not tested"


def matrix(fams: dict) -> dict:
    cols = list(FW.FAMILIES)
    by_prov: dict[str, dict[str, dict]] = {}
    for m in FW.MAPPING:
        by_prov.setdefault(m["provision"], {})[m["family"]] = m
    rows = []
    for pid in FW.VERIFIED:
        if pid not in by_prov:
            continue
        v = FW.VERIFIED[pid]
        cells = {}
        for fam in cols:
            m = by_prov[pid].get(fam)
            if m is None:
                cells[fam] = None
                continue
            c = fams.get(fam)
            counts = {k: (c or {}).get(k, 0) for k in ("held", "violated", "unverified", "n/a", "total")}
            cells[fam] = {"status": status_of(c), "strength": m["strength"], "why": m["why"], "counts": counts}
        rows.append(
            {
                "provision": pid,
                "framework": v["framework"],
                "title": v["title"],
                "url": v["url"],
                "provisional": FW.is_provisional(pid),
                "cells": cells,
            }
        )
    return {"columns": [{"id": f, **FW.FAMILIES[f]} for f in cols], "rows": rows}


def repeat_runs(docs: list[dict]) -> dict:
    """Group enforce runs by integration and profile; compare the policy outcome of each scenario across runs."""
    groups: dict[tuple, list[dict]] = {}
    for idx, doc in enumerate(docs):
        if kind_of(doc) != "enforce":
            continue
        for run in runs_of(doc):
            i = run.get("integration") or {}
            rid = (run.get("receipt") or {}).get("run_id") or f"report{idx}"
            groups.setdefault((i.get("integration"), i.get("profile"), run.get("judge_latency_s")), []).append(
                {
                    "run_id": rid,
                    "report": idx,
                    "versions": i.get("versions"),
                    "outcomes": {
                        _skey(r): norm_policy(r.get("policy"))
                        for r in run.get("results") or []
                        if classify(r) != "control"
                    },
                }
            )
    out = []
    for (name, profile, lat), runs in groups.items():
        uniq = {r["run_id"]: r for r in runs}
        runs = list(uniq.values())
        if len(runs) < 2:
            continue
        keys = set().union(*(r["outcomes"] for r in runs))
        changed = []
        for k in sorted(keys, key=str):
            vals = [r["outcomes"].get(k, "absent") for r in runs]
            if len(set(vals)) > 1:
                changed.append(
                    {
                        "scenario": k[0],
                        "stage": k[1],
                        "mode": k[2],
                        "policy_by_run": dict(zip([r["run_id"] for r in runs], vals, strict=False)),
                    }
                )
        out.append(
            {
                "integration": name,
                "profile": profile,
                "judge_latency_s": lat,
                "runs": [r["run_id"] for r in runs],
                "versions_differ": len({json.dumps(r["versions"], sort_keys=True) for r in runs}) > 1,
                "scenarios_compared": len(keys),
                "scenarios_changed": len(changed),
                "changed": changed[:50],
            }
        )
    return {
        "groups": out,
        "status": (
            "not tested: no integration/profile appears in more than one run in these inputs"
            if not out
            else f"{len(out)} integration/profile group(s) with repeat runs"
        ),
    }


# --------------------------------------------------------------------------- building the pack
def build(reports: list[Path], out: Path, sign_key: Path | None = None) -> dict:
    """Write the pack into `out`; returns {"pack": ..., "manifest": ..., "files": [...]}."""
    if not reports:
        raise PackError("give at least one report")
    key = None
    if sign_key is not None:
        key = Path(sign_key).read_bytes()
        if not key:
            raise PackError(f"{sign_key} is empty: an empty key proves nothing")
    docs, entries = [], []
    out = Path(out)
    (out / "inputs").mkdir(parents=True, exist_ok=True)
    seen_names: set[str] = set()
    for idx, p in enumerate(reports):
        p = Path(p)
        try:
            raw = p.read_bytes()
            doc = json.loads(raw.decode("utf-8"))
        except (OSError, ValueError) as e:
            raise PackError(f"cannot read {p} as a gcl report: {e}") from None
        if not isinstance(doc, dict) or kind_of(doc) == "unknown":
            raise PackError(f"{p} is not a gcl enforce, coverage, probe or check report")
        name = f"{idx + 1:02d}-{p.parent.name or 'report'}-{p.name}".replace(" ", "_")
        while name in seen_names:
            name = "x" + name
        seen_names.add(name)
        (out / "inputs" / name).write_bytes(raw)
        docs.append(doc)
        k = kind_of(doc)
        entry = {
            "index": idx,
            "path_as_given": str(p),
            "copied_as": f"inputs/{name}",
            "sha256": sha256_bytes(raw),
            "bytes": len(raw),
            "kind": k,
            "command": doc.get("command"),
            "generated_at": doc.get("generated_at"),
            "gcl_version": doc.get("version"),
        }
        if k == "enforce":
            entry["receipts"] = [receipt_of(r) for r in runs_of(doc)]
        else:
            entry["receipts"] = []
            entry["receipt_note"] = (
                f"a {k} report carries no run receipt: no run id, commit or install integrity record"
            )
        entries.append(entry)

    items = [it for idx, d in enumerate(docs) for it in items_of(d, idx)]
    fams = tally(items)
    mx = matrix(fams)
    controls = fams.pop("control", None)
    per_report = []
    for idx in range(len(docs)):
        ft = tally([it for it in items if it["report"] == idx and it["family"] != "control"])
        per_report.append(
            {
                "index": idx,
                "kind": entries[idx]["kind"],
                "families": {
                    f: {**{k: v for k, v in c.items() if k != "by_report"}, "status": status_of(c)}
                    for f, c in ft.items()
                },
            }
        )
    cells = [c for r in mx["rows"] for c in r["cells"].values() if c]
    totals = {s: sum(f[s] for f in fams.values()) for s in ("held", "violated", "unverified", "n/a", "total")}
    cell_summary = {s: sum(1 for c in cells if c["status"] == s) for s in (*SEVERITY, "not tested")}
    warnings = []
    for e in entries:
        for rc in e.get("receipts") or []:
            if not rc["has_receipt"]:
                warnings.append(f"{e['path_as_given']}: an enforce run without a receipt")
            for pr in rc["problems"]:
                warnings.append(f"{e['path_as_given']} (run {rc['run_id']}): {pr}")
        if e["kind"] == "check":
            warnings.append(
                f"{e['path_as_given']}: a static `gcl check` report has no mapping to these provisions; "
                "it is recorded in the manifest and contributes no matrix cell"
            )
    pack = {
        "pack": "gcl compliance evidence pack",
        "pack_version": PACK_VERSION,
        "generated_at": _now(),
        "gcl_version": __version__,
        "disclaimer": FW.DISCLAIMER,
        "frameworks": FW.FRAMEWORKS,
        "iso_42001": FW.ISO_42001,
        "strength_legend": {
            "direct": "the provision (or action) asks for the property this check measures; for a risk list, "
            "the observed outcome is the listed risk",
            "supporting": "relevant context; does not by itself show the provision is met",
        },
        "state_legend": {
            "held": "every result in the cell held",
            "violated": "at least one result violated its expectation",
            "unverified": "at least one result could not be judged (and none violated); never counted as held",
            "not tested": "mapped, but no input report contains a result for this check family",
            "not applicable": "every result was n/a (the integration does not carry that surface)",
        },
        "inputs": [
            {k: e[k] for k in ("index", "copied_as", "sha256", "kind", "command", "generated_at")} for e in entries
        ],
        "families": [
            {
                "id": f,
                **FW.FAMILIES[f],
                "counts": {k: v for k, v in (fams.get(f) or {}).items() if k != "by_report"}
                or {"held": 0, "violated": 0, "unverified": 0, "n/a": 0, "total": 0},
                "status": status_of(fams.get(f)),
                "by_report": (fams.get(f) or {}).get("by_report", []),
            }
            for f in FW.FAMILIES
        ],
        "controls": {
            "note": "the tester's own bracketing controls; they gate other results and are not matrix cells",
            **{k: v for k, v in (controls or {"total": 0}).items() if k != "by_report"},
        },
        "totals": totals,
        "per_report": per_report,
        "cell_summary": cell_summary,
        "matrix": mx,
        "mapping": FW.MAPPING,
        "documentation_provisions": FW.DOCUMENTATION,
        "repeat_runs": repeat_runs(docs),
        "considered_not_mapped": [
            {"provision": p, "title": FW.VERIFIED[p]["title"], "why": w} for p, w in FW.NOT_MAPPED
        ]
        + FW.not_mapped_owasp()
        + [
            {
                "provision": "ISO/IEC 42001:2023 Annex A",
                "title": "all controls",
                "why": FW.ISO_42001["status"] + ". " + FW.ISO_42001["detail"],
            }
        ],
        "dates": FW.DATES,
        "sources": {
            p: {
                "title": v["title"],
                "framework": v["framework"],
                "url": v["url"],
                **({"note": v["note"]} if "note" in v else {}),
            }
            for p, v in FW.VERIFIED.items()
        },
        "sources_read_on": FW.SOURCES_READ,
        "warnings": warnings,
    }
    pack_bytes = (json.dumps(pack, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    html_bytes = render_html(pack).encode("utf-8")
    (out / "pack.json").write_bytes(pack_bytes)
    (out / "pack.html").write_bytes(html_bytes)
    manifest = {
        "manifest": "gcl evidence pack manifest",
        "pack_version": PACK_VERSION,
        "generated_at": pack["generated_at"],
        "gcl": _rc.gcl_source(),
        "inputs": entries,
        "outputs": [
            {"path": "pack.json", "sha256": sha256_bytes(pack_bytes), "bytes": len(pack_bytes)},
            {"path": "pack.html", "sha256": sha256_bytes(html_bytes), "bytes": len(html_bytes)},
        ],
        "not_hashed_here": ["manifest.json (it is the thing being described)", "manifest.hmac (it signs the manifest)"],
        "signing": {
            "signed": key is not None,
            "statement": HMAC_STATEMENT if key is not None else SIGNING_NONE,
            **(
                {"algorithm": "HMAC-SHA256", "file": "manifest.hmac", "covers": "manifest.json"}
                if key is not None
                else {}
            ),
        },
    }
    mbytes = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    (out / "manifest.json").write_bytes(mbytes)
    files = ["pack.json", "pack.html", "manifest.json"] + [e["copied_as"] for e in entries]
    if key is not None:
        (out / "manifest.hmac").write_text(
            json.dumps(
                {
                    "algorithm": "HMAC-SHA256",
                    "covers": "manifest.json",
                    "digest": hmac.new(key, mbytes, hashlib.sha256).hexdigest(),
                    "statement": HMAC_STATEMENT,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        files.append("manifest.hmac")
    return {"pack": pack, "manifest": manifest, "files": files}


def verify(directory: Path, sign_key: Path | None = None) -> dict:
    """Re-hash every file the manifest lists; check the HMAC if a key is given. Returns
    {"ok": bool, "problems": [...], "signature": "verified" | "failed" | "not checked" | "absent"}."""
    d = Path(directory)
    problems: list[str] = []
    try:
        mbytes = (d / "manifest.json").read_bytes()
        manifest = json.loads(mbytes)
    except (OSError, ValueError) as e:
        return {"ok": False, "problems": [f"manifest.json unreadable: {e}"], "signature": "not checked", "checked": 0}
    listed = [(e["copied_as"], e["sha256"]) for e in manifest.get("inputs") or []] + [
        (o["path"], o["sha256"]) for o in manifest.get("outputs") or []
    ]
    for rel, want in listed:
        p = d / rel
        if not p.is_file():
            problems.append(f"{rel}: missing")
        elif sha256_file(p) != want:
            problems.append(f"{rel}: content differs from the manifest")
    known = {r for r, _ in listed} | {"manifest.json", "manifest.hmac"}
    for p in sorted(d.rglob("*")):
        if p.is_file() and str(p.relative_to(d)) not in known:
            problems.append(f"{p.relative_to(d)}: not listed in the manifest")
    sig = "not checked"
    hm = d / "manifest.hmac"
    if sign_key is not None:
        if not hm.is_file():
            sig = "absent"
            problems.append("manifest.hmac is missing but a key was given: the pack is not signed")
        else:
            try:
                want = json.loads(hm.read_text(encoding="utf-8"))["digest"]
            except (OSError, ValueError, KeyError):
                want = ""
            got = hmac.new(Path(sign_key).read_bytes(), mbytes, hashlib.sha256).hexdigest()
            if hmac.compare_digest(got, str(want)):
                sig = "verified"
            else:
                sig = "failed"
                problems.append("HMAC does not match: the manifest changed, or this is not the key it was made with")
    elif hm.is_file():
        sig = "not checked"
    return {"ok": not problems, "problems": problems, "signature": sig, "checked": len(listed)}


# --------------------------------------------------------------------------- HTML
e = _H.e
EXTRA_CSS = """
.disc{border:2px solid var(--warn);border-radius:10px;padding:12px 16px;margin:14px 0;background:var(--card)}
.st-held{color:var(--ok);font-weight:600}.st-violated{color:var(--err);font-weight:700}
.st-unverified{color:var(--warn);font-weight:700}.st-nt{color:var(--mute);font-style:italic}
.st-na{color:var(--mute)}.cellb{font-size:12px;color:var(--mute);display:block;font-variant-numeric:tabular-nums}
.matrix td{min-width:92px}.sm{font-size:13px}.mono{font:12px ui-monospace,Menlo,monospace;word-break:break-all}
"""
_CLS = {
    "held": "st-held",
    "violated": "st-violated",
    "unverified": "st-unverified",
    "not tested": "st-nt",
    "n/a": "st-na",
}


def _cell(c: dict | None) -> str:
    if c is None:
        return '<td class="st-na" title="not mapped">&ndash;</td>'
    n = c["counts"]
    tag = "D" if c["strength"] == "direct" else "S"
    parts = [f"{n[k]} {k}" for k in ("held", "violated", "unverified", "n/a") if n[k]]
    return (
        f'<td title="{e(c["strength"] + ": " + c["why"])}"><span '
        f'class="{_CLS[c["status"]]}">{e(STATUS_WORDS[c["status"]])}</span>'
        f'<span class="cellb">{e(tag)} &middot; {e(", ".join(parts) or "no results")}</span></td>'
    )


def render_html(p: dict) -> str:
    o = [
        (
            "<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport "
            "content='width=device-width,initial-scale=1'>"
            "<title>gcl compliance evidence pack</title><style>"
        ),
        _H.CSS,
        EXTRA_CSS,
        "</style></head><body><main>",
        "<h1>gcl compliance evidence pack</h1>",
        (
            f"<p class=sub>generated {e(p['generated_at'])} &middot; gcl {e(p['gcl_version'])} &middot; sources read "
            f"{e(p['sources_read_on'])}</p>"
        ),
        f"<div class=disc><b>Read this first.</b> {e(p['disclaimer'])}</div>",
    ]
    t, cs = p["totals"], p["cell_summary"]
    o.append(
        "<div class=hero>"
        + "".join(
            f"<div><b>{n}</b><span>{e(lab)}</span></div>"
            for n, lab in (
                (len(p["inputs"]), "input reports"),
                (t["total"], "results mapped"),
                (t["violated"], "violated"),
                (t["unverified"], "unverified (never counted as held)"),
                (cs["not tested"], "matrix cells not tested"),
            )
        )
        + "</div>"
    )
    for w in p["warnings"]:
        o.append(f"<div class=banner>{e(w)}</div>")
    o.append(
        "<h2>Coverage matrix</h2><p class=lead>Rows are provisions, columns are the kinds of check gcl ran. A cell "
        "shows the worst "
        "state in it, with counts. D = direct, S = supporting (hover for the reason). &ndash; = gcl does not map that "
        "pair. "
        "<b>not tested</b> = mapped but no input report covers it.</p>"
    )
    m = p["matrix"]
    o.append(
        "<div class=scroll><table class=matrix><tr><th>Provision</th>"
        + "".join(f"<th>{e(c['label'])}</th>" for c in m["columns"])
        + "</tr>"
    )
    last = None
    for r in m["rows"]:
        if r["framework"] != last:
            last = r["framework"]
            o.append(f"<tr><th colspan={len(m['columns']) + 1}>{e(last)}</th></tr>")
        prov = " (provisional)" if r["provisional"] else ""
        o.append(
            f"<tr><td>{e(r['provision'])}{e(prov)}<br><span class=cellb>{e(r['title'])}</span></td>"
            + "".join(_cell(r["cells"][c["id"]]) for c in m["columns"])
            + "</tr>"
        )
    o.append("</table></div>")
    o.append(
        "<h2>Check families</h2><table><tr><th>Family</th><th>What it "
        "is</th><th>State</th><th>held</th><th>violated</th><th>unverified</th><th>n/a</th></tr>"
    )
    for f in p["families"]:
        c = f["counts"]
        o.append(
            f"<tr><td>{e(f['label'])}</td><td class=sm>{e(f['what'])}</td><td "
            f"class='{_CLS[f['status']]}'>{e(STATUS_WORDS[f['status']])}</td>"
            f"<td>{c['held']}</td><td>{c['violated']}</td><td>{c['unverified']}</td><td>{c['n/a']}</td></tr>"
        )
    o.append("</table>")
    o.append(
        "<h2>By input report</h2><table><tr><th>#</th><th>Kind</th>"
        + "".join(f"<th>{e(f['label'])}</th>" for f in p["families"])
        + "</tr>"
    )
    for pr in p["per_report"]:
        o.append(
            f"<tr><td>{pr['index'] + 1}</td><td>{e(pr['kind'])}</td>"
            + "".join(
                (
                    f"<td><span class='{_CLS[c['status']]}'>{e(STATUS_WORDS[c['status']])}</span><span class=cellb>"
                    f"{c['held']} held, {c['violated']} violated, "
                    f"{c['unverified']} unverified, {c['n/a']} n/a</span></td>"
                )
                if (c := pr["families"].get(f["id"]))
                else "<td class=st-nt>not tested</td>"
                for f in p["families"]
            )
            + "</tr>"
        )
    o.append("</table>")
    bad = [(f, b) for f in p["families"] for b in f["by_report"] if b["violated_ids"] or b["unverified_ids"]]
    if bad:
        o.append(
            "<h3>Violated and unverified "
            "results</h3><table><tr><th>Family</th><th>Report</th><th>Violated</th><th>Unverified</th></tr>"
        )
        for f, b in bad:
            o.append(
                f"<tr><td>{e(f['label'])}</td><td>#{b['report'] + 1}</td><td "
                f"class=mono>{e(', '.join(map(str, b['violated_ids'])))}</td>"
                f"<td class=mono>{e(', '.join(map(str, b['unverified_ids'])))}</td></tr>"
            )
        o.append("</table>")
    o.append(
        "<h2>Mapping and reasons</h2><table><tr><th>Check family</th><th>Provision</th><th>Strength</th><th>Why this "
        "is evidence</th></tr>"
    )
    for mp in p["mapping"]:
        v = p["sources"][mp["provision"]]
        o.append(
            f"<tr><td>{e(FW.FAMILIES[mp['family']]['label'])}</td><td>{e(mp['provision'])}<br><span "
            f"class=cellb>{e(v['title'])}</span></td>"
            f"<td>{e(mp['strength'])}</td><td class=sm>{e(mp['why'])}</td></tr>"
        )
    o.append(
        "</table><h2>Records, not matrix cells</h2><table><tr><th>Provision</th><th>Strength</th><th>Why</th></tr>"
    )
    for d in p["documentation_provisions"]:
        o.append(f"<tr><td>{e(d['provision'])}</td><td>{e(d['strength'])}</td><td class=sm>{e(d['why'])}</td></tr>")
    o.append("</table>")
    rr = p["repeat_runs"]
    o.append(f"<h3>Repeat runs</h3><p>{e(rr['status'])}</p>")
    for g in rr["groups"]:
        o.append(
            f"<p class=sm>{e(g['integration'])} / {e(g['profile'])}: runs {e(', '.join(g['runs']))}; "
            f"{g['scenarios_changed']} of {g['scenarios_compared']} scenarios changed outcome"
            f"{'; installed versions differ' if g['versions_differ'] else ''}.</p>"
        )
    o.append("<h2>Considered, not mapped</h2><table><tr><th>Provision</th><th>Why not</th></tr>")
    for n in p["considered_not_mapped"]:
        o.append(
            f"<tr><td>{e(n['provision'])}<br><span class=cellb>{e(n['title'])}</span></td><td "
            f"class=sm>{e(n['why'])}</td></tr>"
        )
    d = p["dates"]
    o.append(f"<h2>Dates</h2><p class=lead>{e(d['note'])}</p><table><tr><th>What</th><th>Date</th><th>Source</th></tr>")
    for it in d["items"]:
        o.append(
            f"<tr><td class=sm>{e(it['what'])}</td><td>{e(it['date'])}</td><td class=mono>{e(it['source'])}</td></tr>"
        )
    o.append(
        f"</table><p class=sm>{e(d['omnibus_scope'])}</p><ul>"
        + "".join(f"<li>{e(x)}</li>" for x in d["not_read"])
        + "</ul>"
    )
    o.append(
        f"<p class=sm><b>Harmonised standards.</b> {e(d['standards'])} <span "
        f"class=mono>{e(d['standards_source'])}</span></p>"
    )
    o.append(
        "<h2>Frameworks</h2><table><tr><th>Framework</th><th>Status</th></tr>"
        + "".join(f"<tr><td>{e(f['name'])}</td><td class=sm>{e(f['status'])}</td></tr>" for f in p["frameworks"])
        + "</table>"
    )
    o.append(f"<p class=sm>{e(p['iso_42001']['detail'])}</p>")
    o.append(
        "<h2>Inputs</h2><table><tr><th>#</th><th>Kind</th><th>Command</th><th>SHA-256</th></tr>"
        + "".join(
            f"<tr><td>{i['index'] + 1}</td><td>{e(i['kind'])}</td><td>{e(i['command'])}</td><td "
            f"class=mono>{e(i['sha256'])}</td></tr>"
            for i in p["inputs"]
        )
        + "</table><p class=sm>Run receipts, output hashes and the optional HMAC are in manifest.json. "
        "Check them with <code>gcl evidence-verify DIR</code>.</p>"
    )
    o.append(
        "<h2>Primary sources used</h2><table><tr><th>Id</th><th>Title</th><th>URL</th></tr>"
        + "".join(
            f"<tr><td>{e(k)}</td><td "
            f"class=sm>{e(v['title'])}{' &mdash; ' + e(v['note']) if v.get('note') else ''}</td><td "
            f"class=mono>{e(v['url'])}</td></tr>"
            for k, v in p["sources"].items()
        )
        + "</table>"
    )
    o.append(
        "<footer>Technical test evidence only. No conformity assessment, no legal advice.</footer></main></body></html>"
    )
    return "".join(o)
