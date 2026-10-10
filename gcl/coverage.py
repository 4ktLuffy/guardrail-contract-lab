"""`gcl coverage`: how much of each language does the guardrail actually catch?

One aggregate recall number hides the failure that matters: a detector can look
fine overall and catch nothing in Arabic. So everything is split by language, with
a Wilson 95% interval (the samples per language are small — say so, don't hide it),
false positives on plain benign text and on hard negatives (benign text that uses
the trigger words), and an intent × language grid.

The detector is either a rule file run in one or more engines (flagged = any rule
matches), or any guardrail wrapped as a subprocess adapter speaking JSONL.
"""

from __future__ import annotations

import json
import math
import shlex
from dataclasses import dataclass
from pathlib import Path

import yaml

from .engines import get_engine, rule_flags
from .rules import load_rules

LANG_NAMES = {"en": "English", "es": "Spanish", "fr": "French", "de": "German", "it": "Italian",
              "pt": "Portuguese", "ru": "Russian", "he": "Hebrew", "ar": "Arabic", "zh": "Chinese",
              "am": "Amharic", "sw": "Swahili", "ar-Latn": "Arabizi", "mix": "code-switched",
              "hi": "Hindi", "fa": "Persian", "tr": "Turkish", "ja": "Japanese", "ko": "Korean"}


def lang_name(code: str | None) -> str:
    return LANG_NAMES.get(code or "", code or "?")


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def pct(x: float) -> float:
    return round(100 * x, 1)


@dataclass
class Detector:
    label: str
    flags: list[bool | None]  # per case: True caught, False missed, None no answer
    complete: bool = True
    note: str = ""
    per_rule: dict | None = None  # rule id -> per-case hits (rule-file detectors only)


def detect_with_rules(rules_path: str, engine_name: str, texts: list[str],
                      flags: str | None = None, deadline_s: float = 3.0,
                      loader_drops_broken: bool = False) -> Detector:
    """Flagged = any rule matches. A rule that does not compile or hangs makes the run
    incomplete — unless `loader_drops_broken`, which measures what a loader that skips
    such rules (the common try/catch) really catches."""
    rs = load_rules(rules_path)
    eng = get_engine(engine_name)
    if not eng.available:
        return Detector(f"{rules_path} @ {engine_name}", [None] * len(texts), complete=False,
                        note=f"{engine_name} runtime not found")
    res = eng.run([r.pattern for r in rs.rules], texts, flags, deadline_s,
                  pattern_flags=[rule_flags(engine_name, r.flags) for r in rs.rules])
    dropped = [r.id for r, x in zip(rs.rules, res, strict=True) if not x.compiled]
    # Flagged by a rule that ran: True. Otherwise, if some rule did not run (and we are
    # not simulating a loader that drops it), we do not know: that rule might have
    # fired. Only a full run turns "nothing fired" into a measured False.
    unknown_if_silent = bool(dropped or rs.skipped) and not loader_drops_broken
    out = [True if any(r.matched(j) for r in res) else (None if unknown_if_silent else False)
           for j in range(len(texts))]
    note = ""
    if dropped:
        shown = ", ".join(dropped[:5]) + (f" +{len(dropped) - 5} more" if len(dropped) > 5 else "")
        note = (f"{len(dropped)} of {len(rs.rules)} rules did not run in {engine_name} "
                f"(compile error or hang): {shown}")
        if loader_drops_broken:
            note += " — measured as a loader that skips them would run"
    if rs.skipped:
        note = "; ".join(filter(None, [note, f"{len(rs.skipped)} rule entries could not be read"]))
    v = eng.meta.get("version", "")
    det = Detector(f"{Path(rules_path).name} @ {engine_name} {v}".strip(), out, note=note,
                   complete=(not dropped or loader_drops_broken) and not rs.skipped)
    det.per_rule = {r.id: [x.matched(j) or False for j in range(len(texts))]
                    for r, x in zip(rs.rules, res, strict=True) if x.compiled}
    return det


def load_adapter(path: str | Path) -> dict:
    p = Path(path)
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    if isinstance(data.get("argv"), str):
        data["argv"] = shlex.split(data["argv"])
    data["_dir"] = str(p.parent.resolve())
    return data


def detect_with_adapter(adapter: dict, cases: list[dict], timeout_s: float = 120.0) -> Detector:
    """Adapter protocol: we write one {"id","text"} JSON line per case on stdin; the
    adapter writes one {"id","flagged": bool} line per case on stdout. A missing or
    unparseable answer is recorded as *no answer*, never as "not flagged"."""
    from .proc import run_supervised

    payload = "".join(json.dumps({"id": c["id"], "text": c["text"]}, ensure_ascii=False) + "\n"
                      for c in cases)
    run = run_supervised(adapter["argv"], payload, timeout_s=timeout_s, cwd=adapter["_dir"])
    name = adapter.get("name", "adapter")
    if run.error or run.returncode is None:
        why = run.error or f"did not finish within {timeout_s:.0f}s (process group killed)"
        return Detector(name, [None] * len(cases), complete=False, note=f"adapter failed: {why}")
    wanted = {c["id"] for c in cases}
    answers: dict = {}
    problems = {"unparseable": 0, "not a boolean": 0, "unknown id": 0, "duplicate": 0}
    for line in run.output.splitlines():
        if not line.strip():
            continue
        try:
            m = json.loads(line)
            cid, val = m["id"], m["flagged"]
            hash(cid)
        except (ValueError, KeyError, TypeError):
            problems["unparseable"] += 1
            continue
        if not isinstance(val, bool):  # "false" is a non-empty string, i.e. True: refuse
            problems["not a boolean"] += 1
            continue
        if cid not in wanted:
            problems["unknown id"] += 1
            continue
        if cid in answers:
            problems["duplicate"] += 1
            answers[cid] = None  # contradictory or repeated: no trustworthy answer
            continue
        answers[cid] = val
    flags = [answers.get(c["id"]) for c in cases]
    missing = sum(f is None for f in flags)
    notes = [f"{missing} of {len(cases)} cases have no valid answer"] if missing else []
    notes += [f"{n} {k}" for k, n in problems.items() if n]
    if run.returncode != 0:
        notes.append(f"adapter exited with status {run.returncode}")
    if run.truncated:
        notes.append("adapter output exceeded the size cap and was cut")
    return Detector(name, flags, note="; ".join(notes),
                    complete=not missing and not any(problems.values())
                    and run.returncode == 0 and not run.truncated)


def summarize(cases: list[dict], det: Detector) -> dict:
    langs: list[str] = []
    for c in cases:
        lg = c.get("lang", "?")
        if lg not in langs:
            langs.append(lg)

    def rate(vals):
        known = [v for v in vals if v is not None]
        return sum(known), len(known), len(vals) - len(known)

    by_lang = {}
    for lg in langs:
        rows = [(c, f) for c, f in zip(cases, det.flags, strict=True) if c.get("lang", "?") == lg]
        att = [f for c, f in rows if c.get("label") == 1]
        ben = [f for c, f in rows if c.get("label") == 0 and c.get("kind") != "hard_negative"]
        hn = [f for c, f in rows if c.get("label") == 0 and c.get("kind") == "hard_negative"]
        k, n, miss = rate(att)
        bk, bn, _ = rate(ben)
        hk, hnn, _ = rate(hn)
        lo, hi = wilson(k, n)
        by_lang[lg] = {
            "attacks": n, "caught": k, "unanswered": miss + (len(ben) - bn) + (len(hn) - hnn),
            "recall": (k / n) if n else None,
            "recall_pct": pct(k / n) if n else None,
            "ci_low_pct": pct(lo) if n else None, "ci_high_pct": pct(hi) if n else None,
            "benign": bn, "flagged_benign": bk,
            "fp_pct": pct(bk / bn) if bn else None,
            "hn": hnn, "hn_flagged": hk,
            "hn_fp_pct": pct(hk / hnn) if hnn else None,
            "all_benign_fp_pct": pct((bk + hk) / (bn + hnn)) if (bn + hnn) else None,
        }
    ak, an, amiss = rate([f for c, f in zip(cases, det.flags, strict=True) if c.get("label") == 1])
    bk, bn, bmiss = rate([f for c, f in zip(cases, det.flags, strict=True) if c.get("label") == 0])
    scored = {lg: r for lg, r in by_lang.items() if r["attacks"] and r["recall"] is not None}
    worst = min(scored, key=lambda lg: (scored[lg]["recall"], lg)) if scored else None
    matrix: dict[str, dict] = {}
    for c, f in zip(cases, det.flags, strict=True):
        if c.get("label") == 1 and c.get("intent"):
            # [caught, answered, unknown]
            cell = matrix.setdefault(c["intent"], {}).setdefault(c.get("lang", "?"), [0, 0, 0])
            if f is None:
                cell[2] += 1
            else:
                cell[0] += int(f)
                cell[1] += 1
    drivers = _drivers(cases, det, langs)
    return {
        "drivers": drivers,
        "detector": det.label,
        "complete": det.complete,
        "note": det.note,
        "aggregate": {
            "attacks": an, "caught": ak, "unanswered": amiss + bmiss,
            "recall_pct": pct(ak / an) if an else None,
            "benign": bn, "flagged_benign": bk,
            "fp_pct": pct(bk / bn) if bn else None,
        },
        "worst": {"lang": worst, "recall_pct": scored[worst]["recall_pct"] if worst else None},
        "by_lang": by_lang,
        "matrix": matrix,
    }


def _drivers(cases: list[dict], det: Detector, langs: list[str]) -> list[str]:
    """Warn when one rule is a language's whole story — e.g. 'recall 100%' that is a
    single character-class rule firing on every line of that script."""
    if not det.per_rule:
        return []
    notes = []
    for lg in langs:
        att = [j for j, c in enumerate(cases) if c.get("lang") == lg and c.get("label") == 1]
        ben = [j for j, c in enumerate(cases) if c.get("lang") == lg and c.get("label") == 0]
        caught = [j for j in att if det.flags[j] is True]
        if len(caught) < 3:
            continue
        sole = [rid for rid, hits in det.per_rule.items() if all(hits[j] for j in caught)]
        if len(sole) == 1:
            rid = sole[0]
            fp = sum(det.per_rule[rid][j] for j in ben)
            notes.append(f"{lg}: all {len(caught)} catches come from one rule ({rid})"
                         + (f", which also flags {fp}/{len(ben)} benign {lg} texts" if fp else ""))
    return notes
