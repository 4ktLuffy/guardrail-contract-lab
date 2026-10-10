"""Regressions for the fifth independent review: each test is one reproduced failure."""

import pytest

from gcl.fix import fix_rule
from gcl.rules import Rule

from .conftest import needs_node
from .test_review_round3 import BUNDLED, _agree, _fix


@needs_node
@pytest.mark.parametrize("pat,probes,positive", [
    (r"\bå\b", ["Å", "å", "Å", " å "], "a å b"),
    (r"\bω\b", ["Ω", "ω", "Ω", " ω "], "x ω y"),
    (r"\b(?:foo|bar|baz|quux|\x69)\b", ["ı", "İ", "i", "I", "foo"], "foo"),
    (r"\bstrasse\b", ["STRAſſE", "straſſe", "strasse"], "strasse"),
    (r"[^a-z]x", ["ıx", "Kx", "Ax", "1x"], "1x"),
])
def test_case_equivalents_beyond_ascii(tmp_path, pat, probes, positive):
    new, summary = _fix(tmp_path, pat, ["python", "node"], {"python": "IM", "node": "im"},
                        [*BUNDLED, positive])
    assert summary["rewritten"], summary["rejected"]
    for eng in ("python", "node"):
        assert not _agree(new, pat, probes, eng, {"python": "IM", "node": "im"}), (pat, eng)


def test_scoped_dotall_is_refused_and_left_unchanged():
    r = fix_rule(Rule("r", r"\b(?s:a.b)\b"), {"python": "IM", "node": "im"})
    assert r.fixed == r.original
    assert any("scoped modifiers other than i" in n for n in r.not_fixed)


@needs_node
@pytest.mark.parametrize("pat,probes,positive", [
    (r"\B\Wx\b", ["é.x", "É.x", "a.x", "..x", ".x"], "..x"),
    (r"\b(?:a|)\Bk\W", ["K.", "aK.", "ak.", "k."], "ak."),
    (r"\b(?:a|)\Bs\W", ["aſ.", "as.", "s."], "as."),
])
def test_not_a_boundary_is_rewritten_too(tmp_path, pat, probes, positive):
    new, summary = _fix(tmp_path, pat, ["python", "node"], {"python": "IM", "node": "im"},
                        [*BUNDLED, positive])
    assert summary["rewritten"], summary["rejected"]
    assert "\\B" not in new  # no native \B left behind a rewritten \b
    for eng in ("python", "node"):
        assert not _agree(new, pat, probes, eng, {"python": "IM", "node": "im"}), (pat, eng)


@needs_node
def test_not_a_boundary_never_matches_empty_input_like_python(tmp_path):
    from gcl.engines import get_engine
    from gcl.fix import fix_rule

    new = fix_rule(Rule("r", r"\B"), {"python": "IM", "node": "im"}).fixed
    for eng in ("python", "node"):
        res = get_engine(eng).run([new], ["", " ", "ab", "a"], "im" if eng == "node" else "IM")[0]
        assert [res.matched(j) for j in range(4)] == [False, True, True, False], eng
