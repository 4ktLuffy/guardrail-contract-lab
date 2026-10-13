"""The compliance evidence pack: mapping integrity, honest matrix cells, hashes and HMAC, end to end."""

import copy
import json
import subprocess
import sys

import pytest
from typer.testing import CliRunner

from gcl import evidence as E
from gcl import frameworks as FW
from gcl import standards as S
from gcl.cli import app

# --------------------------------------------------------------------------- mapping integrity


def test_every_mapped_id_is_in_the_verified_list_with_a_source():
    ids = {m["provision"] for m in FW.MAPPING} | {d["provision"] for d in FW.DOCUMENTATION}
    ids |= {p for p, _ in FW.NOT_MAPPED}
    assert ids <= set(FW.VERIFIED)
    for pid, v in FW.VERIFIED.items():
        assert v["url"].startswith("https://"), pid
        assert v["title"] and v["framework"] and v["asks"]


def test_mapping_rows_have_a_reason_a_strength_and_a_known_family():
    for m in FW.MAPPING + FW.DOCUMENTATION:
        assert m["strength"] in ("direct", "supporting")
        assert len(m["why"]) > 25
        assert "\n" not in m["why"]
        if "family" in m:
            assert m["family"] in FW.FAMILIES
    pairs = [(m["family"], m["provision"]) for m in FW.MAPPING]
    assert len(pairs) == len(set(pairs))


def test_nothing_points_at_iso_annex_a():
    assert not [k for k in FW.VERIFIED if "ISO" in k.upper() or "42001" in k]
    assert not [m for m in FW.MAPPING if "ISO" in m["provision"].upper() or "42001" in m["provision"]]
    assert FW.ISO_42001["status"] == "not mapped: control text not read (paid standard)"
    assert any("42001" in f["name"] and f["status"].startswith("not mapped") for f in FW.FRAMEWORKS)


def test_owasp_ids_agree_with_standards_py():
    emitted = {i for fam in FW.FAMILIES for i in FW.owasp_ids(fam)}
    assert set(S.TITLES) <= emitted, "standards.py can tag an id that no family maps"
    assert emitted <= set(S.TITLES)
    for pid, title in S.TITLES.items():
        assert pid in FW.VERIFIED
        assert FW.VERIFIED[pid]["title"] == title or FW.TITLE_ALIASES.get(pid) == title
    assert all(FW.is_provisional(i) for i in FW.VERIFIED if i.startswith("MCP"))
    assert all("Beta" in FW.VERIFIED[i]["note"] for i in FW.VERIFIED if i.startswith("MCP"))


def test_gpai_caveat_and_dates_are_present():
    row = next(m for m in FW.MAPPING if m["provision"] == "AIA:Art55(1)(a)")
    assert row["strength"] == "supporting" and "GPAI" in row["why"] + FW.VERIFIED["AIA:Art55(1)(a)"]["note"]
    d = FW.DATES
    assert any(i["date"] == "2 August 2026" for i in d["items"])
    assert all(i["source"].startswith("https://publications.europa.eu/") for i in d["items"])
    assert any("2026-09-29" in x and "NOT READ" in x for x in d["not_read"])
    assert "No harmonised standard was found cited" in d["standards"]


# --------------------------------------------------------------------------- cells never improve a result


def test_status_never_turns_unverified_or_missing_into_something_better():
    z = {"held": 0, "violated": 0, "unverified": 0, "n/a": 0, "total": 0}
    assert E.status_of(None) == "not tested"
    assert E.status_of(z) == "not tested"
    assert E.status_of({**z, "held": 9, "unverified": 1, "total": 10}) == "unverified"
    assert E.status_of({**z, "held": 9, "unverified": 1, "violated": 1, "total": 11}) == "violated"
    assert E.status_of({**z, "held": 3, "n/a": 2, "total": 5}) == "held"
    assert E.status_of({**z, "n/a": 2, "total": 2}) == "n/a"
    assert (
        E.norm_policy("held") == "held" and E.norm_policy("") == "unverified" and E.norm_policy("pass") == "unverified"
    )


def _res(sid, stage, mode, policy, **sc):
    return {
        "scenario": {"id": sid, "stage": stage, "mode": mode, "control": False, "role": "", "lang": "en", **sc},
        "observed": "stopped",
        "policy": policy,
    }


def _enforce(results, run_id="aaaaaa", profile="strict", lat=None, dirty=()):
    run = {
        "integration": {"integration": "reference", "profile": profile, "versions": {"python": "3.13"}},
        "receipt": {
            "run_id": run_id,
            "gcl": {"version": "0.4.0", "commit": "c0ffee", "dirty_files": list(dirty), "source_sha256": "ab" * 32},
            "spec_sha256": None,
            "timeout_s": 15.0,
            "problems": ["gcl has %d uncommitted or untracked file(s)" % len(dirty)] if dirty else [],
        },
        "results": results,
    }
    if lat is not None:
        run["judge_latency_s"] = lat
    return run


def _doc(run, **more):
    return {
        "tool": "guardrail-contract-lab",
        "version": "0.4.0",
        "command": "enforce",
        "generated_at": "t",
        "enforce": run,
        **more,
    }


def _write(tmp_path, name, doc):
    p = tmp_path / name
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


def test_classify():
    assert E.classify({"scenario": {"control": True, "role": "open", "mode": "allow"}}) == "control"
    assert E.classify(_res("m01", "output", "surface", "held", surface={"id": "m01"})) == "mcp_surfaces"
    assert (
        E.classify(_res("k01", "input", "config", "held", config={"check": "load_failure:missing"})) == "config_applied"
    )
    assert E.classify(_res("i04", "input", "error", "held")) == "fail_closed"
    assert E.classify(_res("i02", "input", "block", "held")) == "verdict_controls"
    assert E.classify(_res("o30", "output", "block", "held", stream=True)) == "stream_history"
    assert E.classify(_res("i31", "input", "history_block", "held")) == "stream_history"
    assert E.classify(_res("a01", "input", "block", "held", attack="a-1")) == "attack_corpus"


def test_matrix_keeps_unverified_and_not_tested(tmp_path):
    results = [
        _res("i01", "input", "block", "held"),
        _res("i02", "input", "allow", "unverified"),
        _res("i04", "input", "error", "held"),
        _res("i05", "input", "timeout", "held"),
        _res("m01", "output", "surface", "n/a", surface={"id": "m01"}),
    ]
    out = tmp_path / "pack"
    res = E.build([_write(tmp_path, "r.json", _doc(_enforce(results)))], out)
    pack = res["pack"]
    fam = {f["id"]: f for f in pack["families"]}
    assert fam["verdict_controls"]["status"] == "unverified"
    assert fam["verdict_controls"]["counts"]["unverified"] == 1 and fam["verdict_controls"]["counts"]["held"] == 1
    assert fam["fail_closed"]["status"] == "held"
    assert fam["mcp_surfaces"]["status"] == "n/a"
    for f in ("attack_corpus", "stream_history", "config_applied", "coverage_recall", "scanner_probe", "latency_race"):
        assert fam[f]["status"] == "not tested" and fam[f]["counts"]["total"] == 0
    rows = {r["provision"]: r for r in pack["matrix"]["rows"]}
    assert rows["AIA:Art15(5)"]["cells"]["verdict_controls"]["status"] == "unverified"
    assert rows["AIA:Art15(5)"]["cells"]["attack_corpus"]["status"] == "not tested"
    assert rows["AIA:Art15(4)"]["cells"]["fail_closed"]["status"] == "held"
    assert rows["AIA:Art15(4)"]["cells"]["verdict_controls"] is None  # not mapped stays unmapped
    assert pack["cell_summary"]["unverified"] > 0 and pack["cell_summary"]["not tested"] > 0
    assert "Read this first" in (out / "pack.html").read_text() and "not tested" in (out / "pack.html").read_text()
    assert pack["disclaimer"].startswith("This is technical test evidence")


def test_coverage_report_is_never_shown_as_held(tmp_path):
    doc = {
        "command": "coverage",
        "version": "0.4.0",
        "coverage": {
            "by_lang": {
                "en": {"attacks": 12, "recall_pct": 100.0, "all_benign_fp_pct": 0.0},
                "de": {"attacks": 12, "recall_pct": 25.0, "all_benign_fp_pct": 0.0},
                "xx": {"attacks": 0},
            }
        },
    }
    pack = E.build([_write(tmp_path, "c.json", doc)], tmp_path / "p")["pack"]
    f = next(x for x in pack["families"] if x["id"] == "coverage_recall")
    assert f["counts"] == {"held": 0, "violated": 0, "unverified": 2, "n/a": 0, "total": 2}
    assert f["status"] == "unverified"
    assert pack["inputs"][0]["kind"] == "coverage"
    assert "no run receipt" in json.loads((tmp_path / "p" / "manifest.json").read_text())["inputs"][0]["receipt_note"]


def test_probe_report_and_latency_and_repeat_runs(tmp_path):
    probe = {
        "command": "probe",
        "version": "0.4.0",
        "probe": {"scenarios": [{"name": "timeout", "verdict": "held"}, {"name": "error", "verdict": "violated"}]},
    }
    r1 = _enforce([_res("i01", "input", "block", "held"), _res("i04", "input", "error", "held")], "111111", lat=0.0)
    r2 = _enforce([_res("i01", "input", "block", "held"), _res("i04", "input", "error", "violated")], "222222", lat=1.0)
    sweep = _doc(r2, enforce_by_latency=[r1, r2])
    other = _doc(
        _enforce([_res("i01", "input", "block", "held"), _res("i04", "input", "error", "held")], "333333", lat=1.0)
    )
    pack = E.build(
        [_write(tmp_path, "p.json", probe), _write(tmp_path, "s.json", sweep), _write(tmp_path, "o.json", other)],
        tmp_path / "pk",
    )["pack"]
    fam = {f["id"]: f for f in pack["families"]}
    assert fam["scanner_probe"]["counts"]["violated"] == 1 and fam["scanner_probe"]["counts"]["held"] == 1
    assert fam["latency_race"]["counts"] == {"held": 1, "violated": 1, "unverified": 0, "n/a": 0, "total": 2}
    g = pack["repeat_runs"]["groups"]
    assert len(g) == 1 and g[0]["scenarios_changed"] == 1 and g[0]["runs"] == ["222222", "333333"]
    mf = json.loads((tmp_path / "pk" / "manifest.json").read_text())
    assert {rc["run_id"] for rc in mf["inputs"][1]["receipts"]} == {"111111", "222222"}


def test_dirty_tree_and_missing_receipt_are_warned(tmp_path):
    dirty = _doc(_enforce([_res("i01", "input", "block", "held")], dirty=("gcl/x.py",)))
    bare = _doc({"integration": {}, "results": [_res("i01", "input", "block", "held")]})
    pack = E.build([_write(tmp_path, "d.json", dirty), _write(tmp_path, "b.json", bare)], tmp_path / "w")["pack"]
    assert any("uncommitted" in w for w in pack["warnings"]) and any("without a receipt" in w for w in pack["warnings"])


def test_bad_inputs_are_refused(tmp_path):
    with pytest.raises(E.PackError):
        E.build([], tmp_path / "o")
    (tmp_path / "x.json").write_text("not json")
    with pytest.raises(E.PackError):
        E.build([tmp_path / "x.json"], tmp_path / "o")
    with pytest.raises(E.PackError):
        E.build([_write(tmp_path, "y.json", {"hello": 1})], tmp_path / "o")
    key = tmp_path / "empty.key"
    key.write_bytes(b"")
    with pytest.raises(E.PackError):
        E.build([_write(tmp_path, "z.json", _doc(_enforce([])))], tmp_path / "o", key)


# --------------------------------------------------------------------------- manifest and HMAC


@pytest.fixture
def small_pack(tmp_path):
    rep = _write(tmp_path, "r.json", _doc(_enforce([_res("i01", "input", "block", "held")])))
    key = tmp_path / "k.bin"
    key.write_bytes(b"correct horse")
    out = tmp_path / "pack"
    E.build([rep], out, key)
    return rep, key, out


def test_manifest_hashes_inputs_and_outputs(small_pack):
    rep, _, out = small_pack
    mf = json.loads((out / "manifest.json").read_text())
    assert mf["inputs"][0]["sha256"] == E.sha256_file(rep)
    assert {o["path"] for o in mf["outputs"]} == {"pack.json", "pack.html"}
    for o in mf["outputs"]:
        assert E.sha256_file(out / o["path"]) == o["sha256"]
    assert mf["inputs"][0]["receipts"][0]["run_id"] == "aaaaaa"
    assert mf["inputs"][0]["receipts"][0]["gcl"]["commit"] == "c0ffee"
    assert E.verify(out)["ok"]


def test_tampered_input_or_output_or_extra_file_is_detected(small_pack):
    _, _, out = small_pack
    copy_in = next((out / "inputs").iterdir())
    original = copy_in.read_bytes()
    copy_in.write_bytes(original.replace(b'"held"', b'"violated"'))
    r = E.verify(out)
    assert not r["ok"] and any("differs" in p for p in r["problems"])
    copy_in.write_bytes(original)
    assert E.verify(out)["ok"]
    (out / "pack.json").write_text((out / "pack.json").read_text().replace("technical", "magical"))
    assert not E.verify(out)["ok"]
    (out / "pack.json").unlink()
    assert any("missing" in p for p in E.verify(out)["problems"])
    (out / "extra.txt").write_text("x")
    assert any("not listed" in p for p in E.verify(out)["problems"])


def test_hmac_verifies_fails_with_wrong_key_and_on_changed_manifest(small_pack, tmp_path):
    _, key, out = small_pack
    assert E.verify(out, key) == {"ok": True, "problems": [], "signature": "verified", "checked": 3}
    wrong = tmp_path / "wrong.bin"
    wrong.write_bytes(b"wrong")
    r = E.verify(out, wrong)
    assert r["signature"] == "failed" and not r["ok"]
    mf = (out / "manifest.json").read_text()
    (out / "manifest.json").write_text(mf.replace("gcl enforce", "gcl enforcX") if "gcl enforce" in mf else mf + " ")
    assert E.verify(out, key)["signature"] == "failed"


def test_unsigned_pack_claims_nothing_and_key_check_fails(tmp_path):
    rep = _write(tmp_path, "r.json", _doc(_enforce([_res("i01", "input", "block", "held")])))
    out = tmp_path / "u"
    E.build([rep], out)
    mf = json.loads((out / "manifest.json").read_text())
    assert mf["signing"]["signed"] is False and mf["signing"]["statement"].startswith("not signed")
    assert not (out / "manifest.hmac").exists()
    key = tmp_path / "k"
    key.write_bytes(b"k")
    r = E.verify(out, key)
    assert not r["ok"] and r["signature"] == "absent"


def test_signed_statement_says_integrity_not_identity(small_pack):
    _, _, out = small_pack
    mf = json.loads((out / "manifest.json").read_text())
    assert "does not identify who" in mf["signing"]["statement"]
    h = json.loads((out / "manifest.hmac").read_text())
    assert h["algorithm"] == "HMAC-SHA256" and len(h["digest"]) == 64


# --------------------------------------------------------------------------- end to end on real runs


def _run(args):
    return subprocess.Popen(
        [sys.executable, "-c", "from gcl.cli import app; app()", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


@pytest.fixture(scope="module")
def real(tmp_path_factory):
    base = tmp_path_factory.mktemp("real")
    jobs = {
        "strict": ["enforce", "reference", "--python", sys.executable, "--profile", "strict", "--extra", "config"],
        "naive": ["enforce", "reference", "--python", sys.executable, "--profile", "naive", "--extra", "config"],
        "mcp": ["enforce", "reference-mcp", "--python", sys.executable, "--profile", "strict", "--extra", "mcp"],
    }
    procs = {k: _run([*a, "--out", str(base / k), "--allow-incomplete", "--fail-on", "never"]) for k, a in jobs.items()}
    for k, p in procs.items():
        out, _ = p.communicate(timeout=300)
        assert (base / k / "report.json").exists(), out[-800:]
    reports = {k: base / k / "report.json" for k in jobs}
    key = base / "key.bin"
    key.write_bytes(b"e2e-key")
    pack_dir = base / "pack"
    res = E.build(list(reports.values()), pack_dir, key)
    return {"base": base, "reports": reports, "key": key, "dir": pack_dir, "res": res}


def test_e2e_matrix_reflects_strict_and_naive(real):
    pack = real["res"]["pack"]
    assert [i["kind"] for i in pack["inputs"]] == ["enforce"] * 3
    per = {p["index"]: p["families"] for p in pack["per_report"]}
    strict, naive, mcp = per[0], per[1], per[2]
    assert strict["fail_closed"]["violated"] == 0 and strict["fail_closed"]["status"] == "held"
    assert naive["fail_closed"]["violated"] > 0 and naive["fail_closed"]["status"] == "violated"
    assert strict["config_applied"]["status"] == "held" and naive["config_applied"]["status"] == "violated"
    assert "mcp_surfaces" in mcp and mcp["mcp_surfaces"]["total"] > 0 and "mcp_surfaces" not in strict
    fam = {f["id"]: f for f in pack["families"]}
    assert fam["attack_corpus"]["status"] == "not tested" and fam["coverage_recall"]["status"] == "not tested"
    assert (
        fam["fail_closed"]["status"] == "violated"
    )  # worst state wins across inputs; per-report table keeps the split
    rows = {r["provision"]: r for r in pack["matrix"]["rows"]}
    assert rows["AIA:Art15(4)"]["cells"]["fail_closed"]["strength"] == "direct"
    assert rows["AIA:Art15(4)"]["cells"]["fail_closed"]["counts"]["violated"] == naive["fail_closed"]["violated"]
    assert rows["N600:MS-2.7-007"]["cells"]["attack_corpus"]["status"] == "not tested"
    assert sum(pack["totals"][k] for k in ("held", "violated", "unverified", "n/a")) == pack["totals"]["total"]


def test_e2e_every_owasp_tag_in_the_reports_is_in_the_mapping(real):
    mapped = {(m["family"], m["provision"]) for m in FW.MAPPING}
    seen = 0
    for path in real["reports"].values():
        for r in json.loads(path.read_text())["enforce"]["results"]:
            fam = E.classify(r)
            for oid in r["evidence"].get("owasp") or []:
                seen += 1
                assert (fam, oid) in mapped, (fam, oid)
    assert seen > 0


def test_e2e_manifest_receipts_and_hashes(real):
    d = real["dir"]
    mf = json.loads((d / "manifest.json").read_text())
    for entry, path in zip(mf["inputs"], real["reports"].values(), strict=True):
        assert entry["sha256"] == E.sha256_file(path)
        rc = entry["receipts"][0]
        assert rc["run_id"] and rc["gcl"]["source_sha256"] and "dirty_files" in rc["gcl"]
        assert rc["integration"]["name"] in ("reference", "reference-mcp")
    assert E.verify(d, real["key"])["ok"]
    assert (d / "pack.html").read_text().count("<script") == 0


def test_e2e_cli_pack_and_verify_and_tamper(real, tmp_path):
    runner = CliRunner()
    key = real["key"]
    out = tmp_path / "cli"
    r = runner.invoke(
        app, ["evidence-pack", *map(str, real["reports"].values()), "--out", str(out), "--sign-key", str(key)]
    )
    assert r.exit_code == 0, r.output
    assert "not a conformity assessment" in r.output and "not tested" in r.output
    ok = runner.invoke(app, ["evidence-verify", str(out), "--sign-key", str(key)])
    assert ok.exit_code == 0 and "signature: verified" in ok.output
    victim = next((out / "inputs").iterdir())
    victim.write_bytes(victim.read_bytes() + b" ")
    bad = runner.invoke(app, ["evidence-verify", str(out)])
    assert bad.exit_code == 1 and "NOT OK" in bad.output
    nope = runner.invoke(app, ["evidence-pack", str(tmp_path / "missing.json"), "--out", str(out)])
    assert nope.exit_code != 0


def test_e2e_deep_copy_of_pack_json_is_stable_json(real):
    p = json.loads((real["dir"] / "pack.json").read_text())
    assert copy.deepcopy(p) == p
    assert p["iso_42001"]["status"].startswith("not mapped")
    assert any("2026-09-29" in x for x in p["dates"]["not_read"])
