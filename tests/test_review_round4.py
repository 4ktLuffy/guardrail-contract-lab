"""Regressions for the fourth independent review: each test is one reproduced failure."""

import sys
import time

import pytest

from gcl.check import Finding, run_check
from gcl.rules import load_cases, load_rules

from .conftest import ROOT, needs_node
from .test_review_round3 import BUNDLED, _agree, _fix


@needs_node
@pytest.mark.parametrize("pat,probes,positive", [
    (r"\bsecret\d", ["secret１", "secret1", "Ɦsecret1"], "a secret1"),  # ٣ is out of Latin scope
    (r"\bidiot\b", ["ıdıot", "İDİOT", "idiot", "ıdiot x"], "an idiot"),
    (r"\bask\b", ["aſK", "aSk", "aſk"], "ask"),
    (r"[a-z]+key", ["ıkey", "Kkey", "xkey"], "xkey"),
    (r"x\s+y", ["x\x1cy", "x\x85y", "x﻿y", "x y"], "x y"),
])
def test_rewrite_is_exact_for_digits_spaces_and_case_partners(tmp_path, pat, probes, positive):
    new, summary = _fix(tmp_path, pat, ["python", "node"], {"python": "IM", "node": "im"},
                        [*BUNDLED, positive])
    assert summary["rewritten"], summary["rejected"]
    for eng in ("python", "node"):
        assert not _agree(new, pat, probes, eng, {"python": "IM", "node": "im"}), (pat, eng)


@needs_node
def test_line_split_requires_the_terminator_to_be_the_cause(tmp_path):
    p = tmp_path / "r.yaml"
    p.write_text("rules:\n  - {id: s, pattern: '\\bsecret\\b'}\n", encoding="utf-8")
    res = run_check(load_rules(p), ["python", "node"], cases=[{"id": "c", "text": "Жsecret\r"}],
                    deadline_s=1.0, redos=False)
    kinds = {f.kind for f in res.findings}
    assert "match_split" in kinds and "line_split" not in kinds


def test_duplicate_ids_of_mixed_types_are_reported_not_crashed(tmp_path):
    c = tmp_path / "c.jsonl"
    c.write_text('{"id": 1, "text": "a"}\n{"id": 1, "text": "b"}\n{"id": "a", "text": "c"}\n'
                 '{"id": "a", "text": "d"}\n')
    with pytest.raises(ValueError, match="duplicate case ids"):
        load_cases(c)


def test_empty_witness_survives_serialization():
    d = Finding("match_split", "error", "r", "t", "d", witness="", original="x").to_dict()
    assert d["witness"] == ""


def test_detached_helper_holding_the_pipe_does_not_hang_cleanup(tmp_path):
    from gcl.proc import run_supervised

    helper = tmp_path / "helper.py"
    helper.write_text("import time\ntime.sleep(60)\n")
    parent = tmp_path / "parent.py"
    parent.write_text("import subprocess, sys\n"
                      f"subprocess.Popen([sys.executable, {str(helper)!r}], start_new_session=True)\n"
                      "print('parent done')\n")
    t = time.perf_counter()
    r = run_supervised([sys.executable, str(parent)], "", timeout_s=1.0)
    assert time.perf_counter() - t < 6.0
    assert "parent done" in r.output


def test_root_is_importable():
    assert ROOT.exists()
