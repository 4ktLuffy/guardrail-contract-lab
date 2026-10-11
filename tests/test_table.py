"""Compatibility table: private by default; a public table never shows an undisclosed
fail-open."""

import sys
from pathlib import Path

import pytest

from gcl import findings as F
from gcl.table import build, render

from .test_tester_findings import _report


@pytest.fixture(scope="module")
def runs(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("table")
    return {"dir": tmp, "naive": _report(tmp, "naive"), "strict": _report(tmp, "strict", "strict")}


def test_private_table_shows_everything_and_says_it_is_private(runs):
    t = build(runs["dir"])
    text = render(t)
    assert "PRIVATE" in text and "FAILS OPEN" in text and "holds" in text
    assert any(c == "input error" for c in t["columns"])


def test_a_public_table_withholds_undisclosed_violations(runs):
    doc = F.load(Path("/x"))
    t = build(runs["dir"], doc, public=True)
    assert "FAILS OPEN" not in render(t) and t["withheld"] >= 1
    fid = F.add(doc, runs["naive"], "i04", "error passes")["id"]
    assert build(runs["dir"], doc, public=True)["withheld"] == t["withheld"]   # recorded, not disclosed
    F.disclose(doc, fid, "https://example.org/issues/1")
    shown = build(runs["dir"], doc, public=True)
    assert shown["withheld"] == t["withheld"] - 1 and "FAILS OPEN" in render(shown)
    assert F.check(doc) == []


def test_cli_public_needs_a_ledger(runs):
    from typer.testing import CliRunner

    from gcl.cli import app

    assert CliRunner().invoke(app, ["table", str(runs["dir"]), "--public"]).exit_code == 2
    assert CliRunner().invoke(app, ["table", str(runs["dir"])]).exit_code == 0
    assert sys.executable
