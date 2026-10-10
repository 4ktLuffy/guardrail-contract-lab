"""Regressions for the third independent review: each test is one reproduced failure."""

import re
import sys
import time

import pytest

from gcl.check import _ddmin
from gcl.engines import get_engine
from gcl.fix import run_fix
from gcl.rules import load_cases, load_rules

from .conftest import ROOT, needs_node

BUNDLED = [c["text"] for c in load_cases(ROOT / "gcl" / "data" / "cases.multilingual.jsonl")]


def _fix(tmp_path, pattern, engines, flags, texts):
    src = tmp_path / "r.yaml"
    src.write_text("rules:\n  - id: r\n    pattern: '" + pattern.replace("'", "''") + "'\n", encoding="utf-8")
    out = tmp_path / "o.yaml"
    summary = run_fix(src, out, engines, flags, texts)
    return load_rules(out).rules[0].pattern, summary


def _agree(new, old, texts, engine, flags):
    """Rewritten rule in `engine` vs original under Python, on each text."""
    pyf = 0
    for ch in flags.get("python", "IM"):
        pyf |= {"I": re.I, "M": re.M, "S": re.S, "A": re.A}.get(ch, 0)
    got = get_engine(engine).run([new], texts, flags.get(engine))[0]
    return [(t, got.matched(j), bool(re.search(old, t, pyf))) for j, t in enumerate(texts)
            if got.matched(j) != bool(re.search(old, t, pyf))]


def test_latin_scope_covers_whole_script_by_name(tmp_path):
    new, _ = _fix(tmp_path, r"\bsecret\b", ["python"], {"python": "IM"}, [*BUNDLED, "a secret here"])
    assert not _agree(new, r"\bsecret\b", ["Ɦsecret", "secretǅ", "ꝏsecret", "ﬀsecret"], "python",
                      {"python": "IM"})


@needs_node
def test_python_ascii_mode_reaches_construction_for_node_only_targets(tmp_path):
    pat = r"\Acode\w+(?=Z)|foo"
    new, _ = _fix(tmp_path, pat, ["node"], {"python": "A", "node": ""}, ["codexZ", "foo"])
    assert not _agree(new, pat, ["codeéZ", "codexZ", "code_Z"], "node", {"python": "A", "node": ""})


@needs_node
def test_optional_quantifier_keeps_the_full_boundary(tmp_path):
    pat = r"\b(?:a{,2}!(?=Z))|foo"
    new, _ = _fix(tmp_path, pat, ["python", "node"], {"python": "IM", "node": "im"},
                  [*BUNDLED, "aa!Z", "foo"])
    assert new != pat and "{0,2}" in new  # {,2} is literal text in JavaScript: rewritten
    for eng in ("python", "node"):
        assert not _agree(new, pat, ["!Z", "x!Z", "aa!Z", " a!Z"], eng, {"python": "IM", "node": "im"})


@needs_node
def test_dot_and_anchors_follow_python_line_semantics(tmp_path):
    for pat, probes in [(r"\Acode.+", ["code\rX", "code X", "code\nX", "codeX"]),
                        (r"^ignore", ["x\rignore", "x\nignore", "x ignore", "ignore"]),
                        (r"end$", ["end\rx", "end\nx", "end", "end "])]:
        new, summary = _fix(tmp_path, pat, ["python", "node"], {"python": "IM", "node": "im"},
                            BUNDLED + probes)
        assert summary["rewritten"], pat
        assert not _agree(new, pat, probes, "node", {"python": "IM", "node": "im"}), pat


def test_cleanup_is_bounded_when_a_grandchild_holds_the_pipe(tmp_path):
    from gcl.proc import run_supervised

    child = tmp_path / "child.py"
    child.write_text("import time\ntime.sleep(60)\n")
    parent = tmp_path / "parent.py"
    parent.write_text(f"import subprocess, sys\nsubprocess.Popen([sys.executable, {str(child)!r}])\n"
                      "print('parent done')\n")
    t = time.perf_counter()
    r = run_supervised([sys.executable, str(parent)], "", timeout_s=1.0)
    assert time.perf_counter() - t < 6.0
    assert "parent done" in r.output


def test_tail_cap_is_exact():
    from gcl.proc import run_supervised

    r = run_supervised([sys.executable, "-c", "import sys; sys.stdout.write('ab' * 50000 + 'END')"],
                       "", timeout_s=20, max_bytes=10_000, keep="tail")
    assert len(r.output) == 10_000 and r.output.endswith("END") and r.truncated


@pytest.mark.parametrize("line", ['{"id": [], "text": "x"}', '{"id": "a", "text": 5}', '[1, 2]'])
def test_malformed_cases_are_located_errors(tmp_path, line):
    p = tmp_path / "c.jsonl"
    p.write_text(line + "\n")
    with pytest.raises(ValueError, match=":1:"):
        load_cases(p)


def test_ddmin_can_reach_the_empty_witness():
    assert _ddmin("a", lambda cands: [True] * len(cands)) == ""
