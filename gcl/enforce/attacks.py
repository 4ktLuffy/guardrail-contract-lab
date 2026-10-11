"""Attack mode inputs: real attack texts, a real detector's decisions about them, and a
benign text per language for the language controls.

Attacks are JSON-lines cases (the `gcl coverage` format; rows with label 1). The detector
is a `gcl coverage` adapter manifest: a command that reads {"id","text"} lines and writes
{"id","flagged"} lines — wrap Prompt Guard, LlamaFirewall, a vendor API, or anything else
that way. A case the detector gave no valid answer for is dropped and listed, never
treated as "not flagged".
"""

from __future__ import annotations

from pathlib import Path

from ..coverage import detect_with_adapter, load_adapter
from ..rules import load_cases

BUNDLED = Path(__file__).resolve().parent.parent / "data" / "cases.multilingual.jsonl"


def _round_robin(cases: list[dict], limit: int) -> list[dict]:
    """Up to `limit` cases, taken one language at a time, so a small sample still spans
    scripts."""
    by_lang: dict[str, list[dict]] = {}
    for c in cases:
        by_lang.setdefault(str(c.get("lang") or "en"), []).append(c)
    out: list[dict] = []
    while len(out) < limit and any(by_lang.values()):
        for lang in list(by_lang):
            if by_lang[lang] and len(out) < limit:
                out.append(by_lang[lang].pop(0))
    return out


def prepare(attacks_file: Path, detector_file: Path, faults: list[str], limit: int) -> dict:
    rows = load_cases(attacks_file)
    ids = [str(c["id"]) for c in rows]
    if any(not i.strip() for i in ids) or len(set(ids)) != len(ids):
        raise ValueError("case ids must be non-empty and distinct as text (1 and \"1\" are the same case)")
    if len(set(faults)) != len(faults):
        raise ValueError("each fault once")
    attacks = [dict(c, id=str(c["id"])) for c in _round_robin([c for c in rows if c.get("label") == 1], limit)]
    if not attacks:
        raise ValueError(f"{attacks_file} has no attack rows (label 1)")
    manifest = load_adapter(detector_file)
    det = detect_with_adapter(manifest, attacks)
    flagged = {c["id"]: f for c, f in zip(attacks, det.flags, strict=True) if f is not None}
    dropped = [str(c["id"]) for c, f in zip(attacks, det.flags, strict=True) if f is None]
    kept = [c for c in attacks if c["id"] in flagged]
    if not kept:
        raise ValueError(f"the detector answered none of the attacks ({det.note})")
    benign: dict[str, str] = {}
    for src in (rows, load_cases(BUNDLED)):
        for c in src:
            lang = str(c.get("lang") or "en")
            if c.get("label") == 0 and c.get("kind") != "hard_negative" and lang not in benign:
                benign[lang] = c["text"]
    return {"cases": kept, "flagged": flagged, "faults": faults, "benign": benign, "dropped": dropped,
            "detector": {"name": det.label, "manifest": str(detector_file), "note": det.note,
                         "complete": det.complete}}
