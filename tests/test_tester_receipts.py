"""The tester's own mistakes, stage 1: every run carries a receipt (run id, gcl source,
the integration's install and its integrity, the docs version), answers from another
run are not evidence, and cut evidence is never judged clean."""

import base64
import hashlib
import json
import re
import sys
from pathlib import Path

from gcl.enforce import receipt as rc
from gcl.enforce.adapters import ReferenceGateway
from gcl.enforce.contracts import _foreign_ids, _judge, _owner_ids, run_contracts, write_bundles

from .test_enforce import _by, _Fake
from .test_review_round9 import _A, _controls, _r


def test_every_sentinel_carries_the_run_id_and_the_receipt_names_the_source(tmp_path):
    run = run_contracts(ReferenceGateway(sys.executable, tmp_path, "strict"), 15, only={"none"})
    rid = run["receipt"]["run_id"]
    assert re.fullmatch(r"[0-9a-f]{6}", rid)
    for r in run["results"]:
        if r["scenario"]["stage"] == "input" and r["evidence"]["model_events"]:
            body = json.dumps(r["evidence"]["model_events"], ensure_ascii=False)
            assert f"GCL-U-{r['scenario']['id']}-{rid}" in body
    g = run["receipt"]["gcl"]
    assert g["commit"] and re.fullmatch(r"[0-9a-f]{64}", g["source_sha256"])
    assert run["integration"]["install"]["executable"]


def test_another_runs_marker_is_foreign_and_not_evidence():
    assert _owner_ids("x GCL-U-i05-abc123 y", "abc123") == {"i05"}
    assert _owner_ids("x GCL-U-i05-def456 y", "abc123") == set()
    assert _foreign_ids("x GCL-U-i05-def456 y", "abc123") == {"i05"}
    assert _owner_ids("tool GCL-T-i05", "abc123") == set()  # no run id: not this run's
    assert _foreign_ids("tool GCL-T-i05", "abc123") == {"i05"}
    r = _r("input", "error", "stopped", False, other_run_events=1)
    _judge([*_controls(), r], _A())
    assert r.policy == "unverified"


def test_a_cached_reply_without_a_model_call_is_not_a_hold(tmp_path):
    cache: dict = {}

    def caching(g, m):
        text = m[0]["content"].rsplit(" GCL-U-", 1)[0]
        v = g.scan("input", [m[0]["content"]]) or {}
        if v.get("action") == "BLOCKED":
            return 400, {"error": "blocked"}
        if v.get("action") != "NONE":             # guard failed: serve from cache, no model call
            if text in cache:
                return 200, {"choices": [{"message": {"content": cache[text]}}]}
            return 400, {"error": "scanner"}
        reply = g.forward(m)
        cache[text] = reply
        return 200, {"choices": [{"message": {"content": reply}}]}

    run = run_contracts(_Fake(tmp_path, caching), 5, settle_s=0.3)
    hits = [r for r in run["results"] if r["evidence"].get("reply_without_provider_call")]
    assert hits, "no scenario was served from the cache: the test does not exercise the check"
    for r in hits:
        assert r["policy"] == "unverified", (r["scenario"]["id"], r["observed"])
    assert _by(run, "input", "block")["policy"] == "held"


def test_a_truncated_client_body_is_never_judged_clean(tmp_path):
    r = _r("input", "error", "stopped", False, client_body_truncated=True)
    leak = _r("input", "timeout", "passed", False, client_body_truncated=True)
    _judge([*_controls(), r, leak], _A())
    assert r.policy == "unverified" and leak.policy == "violated"
    d = r.to_dict()
    d["evidence"]["attempts"] = []
    run = {"results": [d], "integration": {"integration": "x", "profile": "p"}, "timeout_s": 1,
           "receipt": {"run_id": "abc123"}}
    (bundle,) = write_bundles(run, tmp_path)
    f = json.loads((bundle / "finding.json").read_text())
    assert f["truncated"] is True and f["receipt"]["run_id"] == "abc123"


def test_a_locally_patched_install_is_flagged(tmp_path):
    site = tmp_path / "site"
    pkg = site / "gclfake"
    pkg.mkdir(parents=True)
    src = b"VALUE = 1\n"
    (pkg / "__init__.py").write_bytes(src)
    di = site / "gclfake-1.0.dist-info"
    di.mkdir()
    (di / "METADATA").write_text("Metadata-Version: 2.1\nName: gclfake\nVersion: 1.0\n")
    digest = base64.urlsafe_b64encode(hashlib.sha256(src).digest()).rstrip(b"=").decode()
    (di / "RECORD").write_text(f"gclfake/__init__.py,sha256={digest},{len(src)}\n"
                               "gclfake-1.0.dist-info/RECORD,,\n")
    env = {"PYTHONPATH": str(site), "PATH": "/usr/bin:/bin"}
    clean = rc.probe_versions(sys.executable, ["gclfake"], tmp_path, env)
    assert clean["gclfake"] == "1.0" and clean["dists"]["gclfake"]["files_checked"] == 1
    assert rc.integrity_problems(clean) == []
    (pkg / "__init__.py").write_bytes(b"VALUE = 2  # patched\n")
    patched = rc.probe_versions(sys.executable, ["gclfake"], tmp_path, env)
    assert patched["dists"]["gclfake"]["files_modified"] == 1
    assert "locally patched" in rc.integrity_problems(patched)[0]


def test_docs_read_for_another_version_are_flagged():
    src = {"read_for": "litellm 1.104.2 (docs page read 2026-10-10)"}
    assert rc.docs_version_problems(src, {"python": "3.13.1", "litellm": "1.104.2"}) == []
    assert rc.docs_version_problems(src, {"litellm": "1.110.0"}) == [
        "docs were read for litellm 1.104.2, installed is 1.110.0"]


def test_source_hash_sees_any_edit(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    before = rc.source_hash(tmp_path)
    (tmp_path / "new_driver.py").write_text("")       # untracked, new
    assert rc.source_hash(tmp_path) != before


def test_cli_refuses_to_mix_runs_in_one_out_folder(tmp_path):
    from typer.testing import CliRunner

    from gcl.cli import app

    out = tmp_path / "out"
    out.mkdir()
    (out / "report.json").write_text("{}")
    res = CliRunner(env={"COLUMNS": "200", "NO_COLOR": "1", "TERM": "dumb"}).invoke(
        app, ["enforce", "reference", "--python", sys.executable, "--profile", "strict", "--out", str(out)])
    assert res.exit_code == 2 and "not empty" in re.sub(r"\x1b\[[0-9;]*m|[│╭╮╰╯─\s]+", " ", res.output)
    assert Path(out / "report.json").read_text() == "{}"
