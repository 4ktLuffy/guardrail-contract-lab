"""`coverage_matrix` (G10): which cells were calibrated and judged. Never a percentage.

Rows are forbidden effects, columns are the sources/channels a trigger arrived through, each cell is
exactly one of: calibrated+held, calibrated+violated, uncalibrated, unobserved, unstable. A cell no
trial ever filled is "unobserved" -- not "held": a channel gcl did not exercise says nothing about
that channel. If several trials disagree about a cell, it is "unstable"; the nicer one is not shown.
There is deliberately no total, ratio or score, so the output cannot be quoted as "N% safe".
"""

from __future__ import annotations

from .runner import CELLS


def coverage_matrix(results: list[dict]) -> dict:
    """`results`: Result dicts (or whole trial reports' "results" lists, flattened) of mode "breach".
    Only the verdict results count, not the controls. Returns {"rows", "cols", "cells"} where
    cells[effect][source] is one of CELLS."""
    seen: dict[tuple[str, str], set[str]] = {}
    rows: list[str] = []
    cols: list[str] = []
    for r in results:
        if r.get("scenario", {}).get("mode") != "breach" or r["scenario"].get("control"):
            continue
        ev = r.get("evidence", {})
        effect, source, cell = ev.get("forbidden_effect"), ev.get("source"), ev.get("cell")
        if not (effect and source and cell in CELLS):
            continue
        if effect not in rows:
            rows.append(effect)
        if source not in cols:
            cols.append(source)
        seen.setdefault((effect, source), set()).add(cell)
    cells = {e: {s: "unobserved" for s in cols} for e in rows}
    for (e, s), got in seen.items():
        cells[e][s] = next(iter(got)) if len(got) == 1 else "unstable"
    return {"rows": rows, "cols": cols, "cells": cells}
