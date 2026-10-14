"""Command line: `gcl check | coverage | probe | fix | demo`.

Exit codes are for CI: 0 clean, 1 findings at or above --fail-on, 2 the run was
incomplete (a requested engine or adapter was missing) — never reported as a pass.
"""

from __future__ import annotations

from pathlib import Path

import typer

from . import report as R
from .report.terminal import render_check
from .rules import load_cases, load_rules

app = typer.Typer(add_completion=False, no_args_is_help=True,
                  help="Check whether a guardrail does what its config says.")

DATA = Path(__file__).parent / "data"
BUNDLED_CASES = DATA / "cases.multilingual.jsonl"
BUNDLED_HARDNEG = DATA / "hardneg.multilingual.jsonl"
LEVELS = {"note": 0, "warning": 1, "error": 2}


@app.callback()
def _root():
    """Check whether a guardrail does what its config says."""


def _engines(spec: str) -> list[str]:
    from .engines import ENGINES

    names = [e.strip() for e in spec.split(",") if e.strip()]
    unknown = [n for n in names if n not in ENGINES]
    if unknown or not names:
        raise typer.BadParameter(f"unknown engine(s) {', '.join(unknown) or '(none)'}; "
                                 f"choose from {', '.join(ENGINES)}", param_hint="--engines")
    return names


def _formats(spec: str) -> list[str]:
    return [f.strip() for f in spec.split(",") if f.strip()]


def _flags(py_flags: str | None, js_flags: str | None) -> dict:
    from .engines import validate_flags

    out = {}
    for name, val, hint in (("python", py_flags, "--py-flags"), ("node", js_flags, "--js-flags")):
        if val is None:
            continue
        try:
            validate_flags(name, val)
        except ValueError as e:
            raise typer.BadParameter(str(e), param_hint=hint) from None
        out[name] = val
    return out


def _load_rules_or_exit(path: Path):
    import yaml

    try:
        rs = load_rules(path)
    except (yaml.YAMLError, ValueError) as e:
        typer.echo(f"error: cannot read {path}: {e}", err=True)
        raise typer.Exit(2) from None
    if not rs.rules:
        typer.echo(f"error: no rules found in {path} "
                   "(expected {category: [{pattern: …}]} or a list of rules)", err=True)
        raise typer.Exit(2)
    return rs


def _say(msg: str) -> None:
    typer.echo(f"[gcl] {msg}", err=True)


def _exit(findings_levels: list[str], complete: bool, fail_on: str) -> int:
    if not complete:
        return 2
    if fail_on == "never":
        return 0
    floor = LEVELS[fail_on]
    return 1 if any(LEVELS.get(lv, 0) >= floor for lv in findings_levels) else 0


def _write_outputs(doc: dict, out: Path | None, formats: list[str], html_fn=None, sarif=None):
    if not out:
        return
    out.mkdir(parents=True, exist_ok=True)
    if "json" in formats:
        R.write_json(doc, out / "report.json")
    if "sarif" in formats and sarif is not None:
        R.write_json(sarif, out / "report.sarif")
    if "html" in formats and html_fn is not None:
        (out / "report.html").write_text(html_fn(doc), encoding="utf-8")


@app.command()
def check(
    rules: Path = typer.Argument(..., exists=True, help="Rule file (YAML or JSON)."),
    engines: str = typer.Option("python,node", help="Engines that load these rules."),
    cases: Path | None = typer.Option(None, exists=True, help="Extra JSONL cases to run."),
    benign: bool = typer.Option(True, help="Also run the bundled benign texts (12 languages)."),
    py_flags: str | None = typer.Option(None, help="Python re flags the loader uses (default IM)."),
    js_flags: str | None = typer.Option(None, help="JS RegExp flags the loader uses (default im)."),
    deadline: float = typer.Option(3.0, help="Seconds per rule before it counts as hung."),
    slow_ms: float = typer.Option(250.0, help="Report rules slower than this on long input."),
    max_len: int | None = typer.Option(None, help="Time rules at this input length (use your "
                                       "loader's input cap, e.g. 50000). Default 8000."),
    redos: bool = typer.Option(True, help="Time every rule on adversarial long inputs."),
    out: Path | None = typer.Option(None, help="Directory for report.json/.html/.sarif."),
    format: str = typer.Option("json,html,sarif", help="Files to write into --out."),
    fail_on: str = typer.Option("error", help="error | warning | note | never"),
    quiet: bool = typer.Option(False, help="Only print the summary block."),
):
    """Does every rule compile and match the same in every engine that loads it?"""
    from .check import run_check
    from .report.html import render_html
    from .report.sarif import to_sarif

    names = _engines(engines)
    fl = _flags(py_flags, js_flags)
    if max_len is not None and max_len < 400:
        raise typer.BadParameter("must be at least 400", param_hint="--max-len")
    rs = _load_rules_or_exit(rules)
    case_list = load_cases(cases) if cases else None
    ben = [c for c in load_cases(BUNDLED_CASES) if c.get("label") == 0] if benign else None
    res = run_check(rs, names, case_list, ben, fl, deadline, slow_ms, redos=redos,
                    progress=None if quiet else _say, max_len=max_len)
    sec = R.check_section(res)
    doc = R.envelope("check", {"rules": str(rules), "cases": str(cases) if cases else None,
                               "engines": names})
    doc["check"] = sec
    text = render_check(sec)
    typer.echo(text.split("\n\n")[0] + "\n" + text.split("\n\n")[1] if quiet else text)
    _write_outputs(doc, out, _formats(format), render_html, to_sarif(sec))
    if out:
        typer.echo(f"\nReports: {out}/")
    raise typer.Exit(_exit([f.level for f in res.findings], res.complete, fail_on))


@app.command()
def coverage(
    rules: Path | None = typer.Option(None, exists=True, help="Rule file to evaluate."),
    adapter: Path | None = typer.Option(None, exists=True, help="Adapter manifest (YAML)."),
    cases: Path = typer.Option(BUNDLED_CASES, exists=True, help="JSONL cases (default: bundled)."),
    engines: str = typer.Option("python", help="With --rules: engine(s); first is primary."),
    out: Path | None = typer.Option(None, help="Directory for report.json/.html."),
    format: str = typer.Option("json,html", help="Files to write into --out."),
    min_recall: float | None = typer.Option(None, help="Fail if any language is below this %."),
    max_fp: float | None = typer.Option(None, help="Fail if any language's false-positive rate "
                                        "(plain benign + hard negatives) is above this %."),
    max_fpr: float | None = typer.Option(
        None, help="Fail if the overall false-positive rate (a fraction, 0.05 = 5%) is above this."),
    max_fpr_lang: float | None = typer.Option(
        None, help="Fail if any language's false-positive rate (a fraction, 0.05 = 5%) is above this."),
    hard_negatives: bool = typer.Option(
        False, "--hard-negatives", help="Add gcl's per-language hard-negative set (benign text that "
        "looks risky; 12 per language, authored for gcl, not native-reviewed) to the cases."),
    loader_drops_broken: bool = typer.Option(
        False, help="Measure as a loader that silently skips rules it cannot compile "
                    "(otherwise such rules make the run incomplete)."),
):
    """Per-language recall and false-positive rate, with intervals and a CI gate."""
    from .coverage import (
        detect_with_adapter,
        detect_with_rules,
        evaluate_gate,
        load_adapter,
        summarize,
    )
    from .report.html import render_html
    from .report.terminal import render_coverage

    if bool(rules) == bool(adapter):
        raise typer.BadParameter("give exactly one of --rules or --adapter")
    for opt, v in (("--max-fpr", max_fpr), ("--max-fpr-lang", max_fpr_lang)):
        if v is not None and not 0 <= v <= 1:
            raise typer.BadParameter(f"{opt} is a fraction between 0 and 1 (0.05 = 5%), got {v}")
    case_list = load_cases(cases)
    if hard_negatives:
        have = {c["id"] for c in case_list}
        case_list += [c for c in load_cases(BUNDLED_HARDNEG) if c["id"] not in have]
    texts = [c["text"] for c in case_list]
    if rules:
        _load_rules_or_exit(rules)
        dets = [detect_with_rules(str(rules), e, texts, loader_drops_broken=loader_drops_broken)
                for e in _engines(engines)]
    else:
        dets = [detect_with_adapter(load_adapter(adapter), case_list)]
    secs = [summarize(case_list, d) for d in dets]
    for s in secs:
        label = "bundled: cases.multilingual.jsonl" if cases == BUNDLED_CASES else str(cases)
        if hard_negatives:
            label += " + bundled: hardneg.multilingual.jsonl"
        s["cases"] = {"path": label, "n": len(case_list)}
        s["fixtures_note"] = _fixture_note(case_list)
    sec = secs[0]
    if len(secs) > 1:
        sec["compare"] = [{"detector": s["detector"], "note": s["note"], "aggregate": s["aggregate"],
                           "by_lang": {lg: r["recall_pct"] for lg, r in s["by_lang"].items()}}
                          for s in secs]
    doc = R.envelope("coverage", {"rules": str(rules) if rules else None,
                                  "adapter": str(adapter) if adapter else None,
                                  "cases": "bundled" if cases == BUNDLED_CASES else str(cases)})
    caps = [x for x in (max_fpr_lang, None if max_fp is None else max_fp / 100) if x is not None]
    lang_cap = min(caps) if caps else None  # --max-fp (percent, older spelling) = --max-fpr-lang
    gates = [evaluate_gate(s, min_recall, max_fpr, lang_cap) for s in secs]
    if any(v is not None for v in (min_recall, max_fpr, lang_cap)):
        sec["gate"] = gates[0]
    doc["coverage"] = sec
    typer.echo(render_coverage(sec))
    _write_outputs(doc, out, _formats(format), render_html)
    complete = all(d.complete for d in dets)
    bad = ["error" for g in gates for _ in g["breaches"]]
    raise typer.Exit(_exit(bad, complete, "error"))


@app.command()
def probe(
    adapter: Path = typer.Argument(..., exists=True, help="Probe manifest (YAML)."),
    contract: Path | None = typer.Option(None, exists=True, help="Failure contract (YAML)."),
    faults: str = typer.Option("timeout,error,malformed,empty,wrong_schema,refused",
                                help="Faults to inject into the scanner."),
    out: Path | None = typer.Option(None, help="Directory for report.json/.html."),
    format: str = typer.Option("json,html", help="Files to write into --out."),
):
    """When the scanner fails, does the protected action still run?"""
    from .probe import load_contract, load_manifest, probe_section, run_probe
    from .report.html import render_html
    from .report.terminal import render_probe

    m = load_manifest(adapter)
    con = load_contract(contract)
    scenarios = run_probe(m, con, _formats(faults), progress=_say)
    sec = probe_section(str(adapter), str(contract) if contract else None, scenarios)
    sec["name"] = m.get("name", "")
    doc = R.envelope("probe", {"adapter": str(adapter), "contract": str(contract) if contract else None})
    doc["probe"] = sec
    typer.echo(render_probe(sec))
    _write_outputs(doc, out, _formats(format), render_html)
    levels = ["error" for s in scenarios if s.verdict == "violated"]
    complete = not any(s.verdict == "unverified" for s in scenarios)
    raise typer.Exit(_exit(levels, complete, "error"))


@app.command()
def fix(
    rules: Path = typer.Argument(..., exists=True, help="Rule file to make portable."),
    output: Path | None = typer.Option(None, "--output", "-o",
                                       help="Where to write (default: <name>.portable<ext>)."),
    engines: str = typer.Option("python,node", help="Engines the fixed file must work in."),
    py_flags: str | None = typer.Option(None, help="Python re flags the loader uses (default IM)."),
    js_flags: str | None = typer.Option(None, help="JS RegExp flags the loader uses (default im)."),
    scripts: str = typer.Option("", help="Extra scripts the rewrite must be exact for "
                                "(e.g. cyrillic,arabic). Default: the scripts each rule uses, plus Latin."),
):
    """Rewrite rules so every engine reads them as Python does; verify before writing."""
    from .fix import SCRIPTS, run_fix
    from .report.terminal import render_fix

    names = _engines(engines)
    _flags(py_flags, js_flags)
    _load_rules_or_exit(rules)
    # An explicit empty string means "no flags", not "use the default".
    flags = {"python": py_flags if py_flags is not None else "IM",
             "node": js_flags if js_flags is not None else "im"}
    extra = [x.strip() for x in scripts.split(",") if x.strip()]
    bad = [x for x in extra if x not in SCRIPTS]
    if bad:
        raise typer.BadParameter(f"unknown script(s) {bad}; choose from {', '.join(SCRIPTS)}",
                                 param_hint="--scripts")
    out = output or rules.with_name(rules.stem + ".portable" + rules.suffix)
    bundled = [c["text"] for c in load_cases(BUNDLED_CASES)]
    summary = run_fix(rules, out, names, flags, bundled, extra)
    if summary.get("error"):
        typer.echo(f"{summary['error']}. Nothing written.")
        raise typer.Exit(2)
    typer.echo(render_fix(summary))


@app.command()
def demo(
    out: Path = typer.Option(Path("demo-out"), help="Directory for the demo report."),
    open_report: bool = typer.Option(False, "--open", help="Open the HTML report when done."),
):
    """Run the whole argument on bundled fixtures; write one HTML report."""
    import time

    from .demo import run_demo

    t0 = time.perf_counter()
    doc = run_demo(out, say=lambda m: typer.echo(f"  {m}"))
    typer.echo("")
    for h in doc["hero"]:
        typer.echo(f"  {h['value']:>14}  {h['label']}")
    typer.echo(f"\nReport: {out / 'report.html'}   ({time.perf_counter() - t0:.0f} s)")
    if open_report:
        import webbrowser

        webbrowser.open((out / "report.html").resolve().as_uri())


def _make_adapter(cls, integration: str, where, profile: str, spec: Path | None):
    """One adapter instance in a fresh work directory; the vendor adapters need their --spec."""
    import tempfile

    workdir = Path(tempfile.mkdtemp(prefix="gcl-enforce-"))
    if integration in ("litellm-vendor", "nemo-vendor"):
        if spec is None:
            raise typer.BadParameter(f"{integration} needs --spec FILE", param_hint="--spec")
        import json

        return cls(str(where), workdir, profile, spec=json.loads(spec.read_text()))
    return cls(str(where), workdir, profile)


@app.command()
def enforce(
    integration: str = typer.Argument(..., help="litellm | nemo"),
    python: Path | None = typer.Option(None, exists=True, help="Python of an environment where the "
                                       "integration is installed (it runs there, not in gcl's env)."),
    env: Path | None = typer.Option(None, exists=True, file_okay=False,
                                    help="For Node integrations: the directory holding its node_modules."),
    profile: str = typer.Option("default", help="Integration profile, e.g. litellm: default | fail_open."),
    timeout: float | None = typer.Option(None, help="Client deadline per scenario, seconds "
                                         "(default: the integration's own, e.g. 45)."),
    out: Path | None = typer.Option(None, help="Directory for report.json/.html and repro bundles."),
    format: str = typer.Option("json,html", help="Files to write into --out."),
    fail_on: str = typer.Option("policy", help="policy (any strict-policy violation) | "
                                "documented (only deviations from the integration's docs) | never"),
    allow_incomplete: bool = typer.Option(False, help="Exit 0 even if some scenarios could not be "
                                          "judged (default: exit 2, the run is incomplete)."),
    scenario: list[str] = typer.Option([], help="Run only this scenario id (repeatable); the "
                                       "controls always run. Repro bundles print the command."),
    spec: Path | None = typer.Option(None, exists=True, dir_okay=False,
                                     help="For litellm-vendor: a vendor spec JSON (guardrail type, params, "
                                          "the vendor's request path and allow/block bodies)."),

    judge_latency: str = typer.Option("", help="Comma-separated guard latencies in seconds (e.g. "
                                      "0,0.2,1): run the whole contract once per latency and report "
                                      "results that change with timing as unstable."),
    extra: str = typer.Option("", help="Opt-in blind spots, comma-separated: stream (output checks on "
                              "streamed answers), history (the attack in an earlier turn), retry (a "
                              "blocked request sent twice), mcp (MCP gateways: the baseline plus 34 more "
                              "places a message can carry text, each run with a benign control and an attack), "
                              "config (is the configured policy the one that runs: a policy that fails to load, "
                              "a live edit, a scoped policy), routes (the same guard on every route to the same "
                              "action: chat, /v1/messages, /v1/responses, /v1/completions, streaming; for MCP a "
                              "batch, resources, prompts, a hidden tool)."),
    mcp_protocol: str = typer.Option("2025-03-26", "--mcp-protocol", help="With --extra mcp: the MCP "
                                     "protocol version the client asks for (2025-03-26, 2025-06-18, 2025-11-25). "
                                     "A surface the negotiated version does not have is not run (n/a)."),
    attacks: Path | None = typer.Option(None, exists=True, dir_okay=False,
                                        help="Attack mode: JSON-lines attack cases (rows with label 1). Each is "
                                             "sent with a real detector's verdict and under each fault."),
    detector: Path | None = typer.Option(None, exists=True, dir_okay=False,
                                         help="Attack mode: a coverage adapter manifest for the real detector."),
    attack_faults: str = typer.Option("error,timeout", help="Attack mode: faults to send each attack under."),
    attack_limit: int = typer.Option(8, help="Attack mode: at most this many attacks (spread over languages)."),
    attack_plan_file: Path | None = typer.Option(None, "--attack-plan", exists=True, dir_okay=False,
                                                 help="Attack mode from a frozen plan (attacks and the detector's "
                                                      "verdicts) written by an earlier run: replays exactly that."),
    sarif_anchor: str | None = typer.Option(None, help="With --format sarif: a repository file to attach "
                                            "results to (code scanning needs one; default: the spec)."),
    force: bool = typer.Option(False, help="Write into a non-empty --out folder (default: refuse, so "
                               "reports and repro bundles of different runs never mix)."),
    attest: bool = typer.Option(False, "--attest", help="Mutation control: re-run the opening controls twice "
                                "with the stand-in forced to always-allow and always-block. If the outcome does "
                                "not follow, the adapter does not reach the integration's own control (a stub or "
                                "a mock): every result becomes unverified and the run exits 2, whatever --fail-on "
                                "says. It only demotes. Costs two more integration starts."),
):
    """Does a real guardrail integration enforce what its scanner decides?"""
    from .enforce.adapters import ADAPTERS
    from .enforce.contracts import run_contracts, write_bundles
    from .report.html import render_html
    from .report.terminal import render_enforce

    if fail_on not in ("policy", "documented", "never"):
        raise typer.BadParameter("choose policy, documented or never", param_hint="--fail-on")
    if integration not in ADAPTERS:
        raise typer.BadParameter(f"choose from {', '.join(ADAPTERS)}", param_hint="integration")
    cls = ADAPTERS[integration]
    if profile not in cls.documented:
        raise typer.BadParameter(f"{integration} profiles: {', '.join(cls.documented)}",
                                 param_hint="--profile")
    if out and out.exists() and any(out.iterdir()) and not force:
        raise typer.BadParameter(f"{out} is not empty; use a new folder or --force", param_hint="--out")
    where = env if cls.runtime == "node" else python
    if where is None:
        flag = "--env" if cls.runtime == "node" else "--python"
        raise typer.BadParameter(f"{integration} needs {flag}", param_hint=flag)
    adapter = _make_adapter(cls, integration, where, profile, spec)
    try:
        lats = [float(x) for x in judge_latency.split(",") if x.strip()]
    except ValueError:
        raise typer.BadParameter("numbers in seconds, comma-separated", param_hint="--judge-latency") from None
    if len(set(lats)) != len(lats) or any(x < 0 for x in lats):
        raise typer.BadParameter("each latency once, none negative", param_hint="--judge-latency")
    from .enforce.contracts import EXTRAS

    extras = tuple(x.strip() for x in extra.split(",") if x.strip())
    if any(x not in EXTRAS for x in extras):
        raise typer.BadParameter(f"choose from {', '.join(EXTRAS)}", param_hint="--extra")
    from .enforce.mcp_surfaces import PROTOCOL, PROTOCOLS

    if mcp_protocol not in PROTOCOLS:
        raise typer.BadParameter(f"choose from {', '.join(PROTOCOLS)}", param_hint="--mcp-protocol")
    if mcp_protocol != PROTOCOL and not {"mcp", "routes"} & set(extras):
        raise typer.BadParameter("it only applies with --extra mcp (or routes, on an MCP gateway)",
                                 param_hint="--mcp-protocol")
    if "routes" in extras and not (cls.routes or cls.mcp_transport):
        route_names = ", ".join(n for n, a in ADAPTERS.items() if a.routes or a.mcp_transport)
        raise typer.BadParameter(f"{integration} declares no routes; route parity runs on: {route_names}",
                                 param_hint="--extra")
    if "mcp" in extras and not cls.mcp_transport:
        mcp_names = ", ".join(n for n, a in ADAPTERS.items() if a.mcp_transport)
        raise typer.BadParameter(f"{integration} is not an MCP gateway; mcp surfaces run on: {mcp_names}",
                                 param_hint="--extra")
    if "config" in extras and not cls.config_checks:
        config_names = ", ".join(n for n, a in ADAPTERS.items() if a.config_checks)
        raise typer.BadParameter(f"{integration} cannot start with a given policy; config checks run on: "
                                 f"{config_names}", param_hint="--extra")
    attack_plan = None
    if attack_plan_file:
        import json

        if attacks or detector:
            raise typer.BadParameter("--attack-plan replaces --attacks and --detector", param_hint="--attack-plan")
        attack_plan = json.loads(attack_plan_file.read_text(encoding="utf-8"))
    elif attacks or detector:
        if not (attacks and detector):
            raise typer.BadParameter("attack mode needs both --attacks and --detector", param_hint="--attacks")
        from .enforce.attacks import prepare
        from .enforce.servers import FAULTS

        afaults = [f.strip() for f in attack_faults.split(",") if f.strip()]
        if any(f not in FAULTS for f in afaults):
            raise typer.BadParameter(f"choose from {', '.join(FAULTS)}", param_hint="--attack-faults")
        try:
            attack_plan = prepare(attacks, detector, afaults, attack_limit)
        except ValueError as e:
            typer.echo(f"error: {e}", err=True)
            raise typer.Exit(2) from None
    if attest and lats:
        raise typer.BadParameter("run the mutation control once, on its own run (not per latency)",
                                 param_hint="--attest")
    try:
        if lats and attack_plan:
            raise typer.BadParameter("use --judge-latency or attack mode, not both", param_hint="--judge-latency")
        if attack_plan:
            run = run_contracts(adapter, timeout or adapter.default_timeout_s, progress=_say,
                                only=set(scenario) or None, attacks=attack_plan, attest=attest)
        elif lats:
            from .enforce.contracts import latency_sweep

            sweep = latency_sweep(adapter, lats, timeout or adapter.default_timeout_s, progress=_say,
                                  only=set(scenario) or None, extra=extras, mcp_protocol=mcp_protocol)
            slowest = max(range(len(lats)), key=lambda k: lats[k])  # where races show
            run = sweep["runs"][slowest]
            run["latency_sweep"] = {k: v for k, v in sweep.items() if k != "runs"}
            run["latency_sweep"]["summaries"] = [r["summary"] for r in sweep["runs"]]
        else:
            run = run_contracts(adapter, timeout or adapter.default_timeout_s, progress=_say,
                                only=set(scenario) or None, extra=extras, mcp_protocol=mcp_protocol,
                                attest=attest)
    except (RuntimeError, OSError) as e:  # OSError: URLError and friends from an adapter that failed to start
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(2) from None
    doc = R.envelope("enforce", {"integration": integration, "profile": profile})
    doc["enforce"] = run
    if lats:  # every latency's full run is part of the record, not only the one shown
        doc["enforce_by_latency"] = sweep["runs"]
    if out:  # the evidence is written before anything is rendered: a display bug cannot lose it
        import json
        import shlex

        _write_outputs(doc, out, _formats(format), render_html)
        if "sarif" in _formats(format):
            from .report.sarif import enforce_sarif

            R.write_json(enforce_sarif(sweep["runs"] if lats else run,
                                       sarif_anchor or (str(spec) if spec else f"{integration}.gcl")),
                         out / "report.sarif")
        flag = "--env" if cls.runtime == "node" else "--python"
        extra_spec = f" --spec {shlex.quote(str(spec.resolve()))}" if spec else ""
        replay = (f"gcl enforce {shlex.quote(integration)} {flag} {shlex.quote(str(Path(str(where)).resolve()))} "
                  f"--profile {shlex.quote(profile)}{extra_spec} --timeout {run['timeout_s']:g}"
                  + (f" --extra {','.join(extras)}" if extras else "")
                  + (f" --mcp-protocol {mcp_protocol}" if mcp_protocol != PROTOCOL else ""))
        if attack_plan:  # the plan is frozen next to the report; a replay sends exactly it
            frozen = out / "attack-plan.json"
            frozen.write_text(json.dumps(attack_plan, ensure_ascii=False, indent=2), encoding="utf-8")
            replay += f" --attack-plan {shlex.quote(str(frozen.resolve()))}"
        if lats:
            bundles = [b for r in sweep["runs"] for b in write_bundles(
                r, out / f"latency-{r['judge_latency_s']:g}", f"{replay} --judge-latency {r['judge_latency_s']:g}")]
        else:
            bundles = write_bundles(run, out, replay)
    typer.echo(render_enforce(run))
    if out:
        typer.echo(f"\nReports: {out}/" + (f"  ({len(bundles)} repro bundle(s) in {out}/repro/)" if bundles else ""))
    if (run.get("mutation_control") or {}).get("state") == "failed":
        # Not a finding and not an incomplete run to wave through: the adapter is not trusted.
        raise typer.Exit(2)
    sw = run.get("latency_sweep")
    if sw:
        codes = [_enforce_exit(sm, fail_on, allow_incomplete) for sm in sw["summaries"]]
        code = 1 if 1 in codes else (2 if 2 in codes or sw["unstable"] else 0)
        raise typer.Exit(0 if fail_on == "never" else code)
    raise typer.Exit(_enforce_exit(run["summary"], fail_on, allow_incomplete))


@app.command()
def replay(
    bundle: Path = typer.Argument(..., help="A repro bundle: the directory `enforce --out` wrote under "
                                  "repro/, or a zip of it."),
    python: Path | None = typer.Option(None, "--python", "--env", help="Python (or, for Node integrations, "
                                       "the install directory) to run the integration in, instead of the one "
                                       "the bundle recorded."),
    allow_drift: bool = typer.Option(False, "--allow-version-drift", help="Run even if the integration's "
                                     "version or the control file changed since the bundle was written (the "
                                     "result is then 'does it still happen here', noted as such)."),
    attest: bool = typer.Option(False, "--attest", help="Also run the mutation control on the replay."),
    out: Path | None = typer.Option(None, help="Write the replay record (JSON) here."),
):
    """Re-run one stored finding, offline, from its bundle. Exit 0 reproduced, 1 not reproduced,
    2 unverified (damaged or unsealed bundle, missing integration, a pin changed, controls broke)."""
    from .enforce.replay import replay as do_replay

    res = do_replay(bundle, python=str(python) if python else None, allow_drift=allow_drift, attest=attest,
                    progress=_say)
    sc = res.get("scenario") or {}
    typer.echo(f"Replay of {sc.get('id', '?')} {sc.get('stage', '')} {sc.get('mode', '')} "
               f"from {bundle}: {res['status'].upper()}")
    typer.echo(f"  {res['reason']}")
    if res.get("stored"):
        typer.echo(f"  stored   {res['stored']['observed']} / policy {res['stored']['policy']} / "
                   f"docs {res['stored']['documented']}")
    if res.get("replayed"):
        typer.echo(f"  replayed {res['replayed']['observed']} / policy {res['replayed']['policy']} / "
                   f"docs {res['replayed']['documented']}")
    for ch in res["checks"]:
        typer.echo(f"  {'ok  ' if ch['ok'] else 'FAIL'} {ch['check']}: {ch['detail']}")
    for n in res["notes"]:
        typer.echo(f"  note: {n}")
    typer.echo(f"  ({res['elapsed_s']} s)")
    if out:
        R.write_json(res, out)
    raise typer.Exit({"reproduced": 0, "not reproduced": 1}.get(res["status"], 2))


def _enforce_exit(s: dict, fail_on: str, allow_incomplete: bool) -> int:
    """1: a violation of the chosen kind. 2: nothing wrong found, but some scenarios
    could not be judged (an incomplete run is not a pass). 0 otherwise."""
    if fail_on == "never":
        return 0
    bad = s["policy_violated"] if fail_on == "policy" else s["documented_deviates"]
    if bad:
        return 1
    if s["unverified"] and (not allow_incomplete or s["unverified"] == s["scenarios"]):
        return 2
    return 0


def _fixture_note(cases: list[dict]) -> str:
    reviewed = sum(1 for c in cases if c.get("native_reviewed"))
    if reviewed == len(cases):
        return ""
    return (f"{len(cases) - reviewed} of {len(cases)} cases are machine-written and not "
            "native-reviewed; per-language samples are small, so read the intervals.")


# --------------------------------------------------------------------------- agent actions
actions_app = typer.Typer(no_args_is_help=True, help="Agent actions: approval / read-only / "
                          "allowlist controls, proven from an executor's own receipt, never from "
                          "a reply's text (see gcl/enforce/ledger.py).")
app.add_typer(actions_app, name="actions")


@actions_app.command()
def dbhub(
    install: Path = typer.Option(..., exists=True, file_okay=False, help="The directory `npm pack` / "
                                 "`npm install` unpacked @bytebase/dbhub into (holding dist/index.js "
                                 "and, for its production dependencies, node_modules)."),
    node: str = typer.Option("node", help="The node binary (needs node:sqlite, i.e. Node >=22.5)."),
    db: Path = typer.Option(..., help="The throwaway SQLite file to probe (seeded once if it does "
                            "not exist yet; never deleted or touched for real afterwards)."),
    workdir: Path = typer.Option(..., file_okay=False, help="Where this run writes its own dbhub.toml."),
    timeout: float = typer.Option(30.0, help="Seconds per probe."),
    out: Path | None = typer.Option(None, help="Directory for report.json/.sarif."),
    format: str = typer.Option("json", help="Files to write into --out: json, sarif."),
    fail_on: str = typer.Option("policy", help="policy (any violation) | never"),
    allow_incomplete: bool = typer.Option(False, help="Exit 0 even if the controls did not hold "
                                          "(default: exit 2)."),
):
    """dbhub's read-only flag on execute_sql: a benign PRAGMA-assignment write that the
    leading-keyword classifier misses (CVE-2026-61788 / GHSA-mwwr-p57h-56pf). Vulnerable
    builds (<= 0.22.5) go red; 0.22.6 goes green -- see README "Agent actions"."""
    from .enforce.actions import run_action_target
    from .enforce.dbhub_target import DbhubTarget, seed_db

    if fail_on not in ("policy", "never"):
        raise typer.BadParameter("choose policy or never", param_hint="--fail-on")
    if out and out.exists() and any(out.iterdir()):
        raise typer.BadParameter(f"{out} is not empty; use a new folder", param_hint="--out")
    seed_db(db)
    target = DbhubTarget(node, install, db, workdir)
    run = run_action_target(target, timeout, say=_say)
    doc = R.envelope("actions", {"target": "dbhub", "install": str(install), "db": str(db)})
    # Filed under "enforce" too (not only "actions"): `gcl findings add` and other tools
    # that read a report by that key work on this report unchanged -- same Result shape,
    # same receipt shape, just a different run mode (see enforce/actions.py's docstring).
    doc["actions"] = doc["enforce"] = run
    if out:
        _write_outputs(doc, out, _formats(format))
        if "sarif" in _formats(format):
            from .report.sarif import enforce_sarif

            R.write_json(enforce_sarif(run, str(workdir / "dbhub.toml")), out / "report.sarif")
    for r in run["results"]:
        s = r["scenario"]
        pk = {"held": "ok", "violated": "error", "unverified": "warning"}[r["policy"]]
        typer.echo(f"  {s['id']}  {r['policy']:<10} {s['mode']:<9} observed {r['observed']}"
                  + (f"  [{pk}]" if pk != "ok" else ""))
        for n in r["notes"]:
            typer.echo(f"             {n}")
    sm = run["summary"]
    typer.echo(f"\n{sm['held']} held, {sm['violated']} violated, {sm['unverified']} unverified of "
              f"{sm['checks']}.")
    if out:
        typer.echo(f"Report: {out}/")
    raise typer.Exit(_enforce_exit(sm, fail_on, allow_incomplete))


def main():  # pragma: no cover
    app()




# --------------------------------------------------------------------------- findings
findings_app = typer.Typer(no_args_is_help=True, help="A findings ledger that only holds what runs can back.")
app.add_typer(findings_app, name="findings")


def _ledger_do(ledger: Path, fn, *args, write: bool = True):
    from . import findings as F

    try:
        for w in F.guard_location(ledger):
            typer.echo(f"warning: {w}", err=True)
        doc = F.load(ledger)
        out = fn(doc, *args)
    except (F.LedgerError, OSError, ValueError) as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(2) from None
    if write:
        F.save(ledger, doc)
    return doc, out


@findings_app.command("add")
def findings_add(ledger: Path = typer.Argument(..., help="The ledger file (JSON), kept privately."),
                 report: Path = typer.Option(..., exists=True, dir_okay=False, help="A gcl enforce report.json."),
                 scenario: str = typer.Option(..., help="Scenario id in that report."),
                 title: str = typer.Option(..., help="One line: what is wrong."),
                 latency: float | None = typer.Option(None, help="With a latency sweep report: which run.")):
    """Create a finding from a scenario of a stored run (status: proposed)."""
    from . import findings as F

    _, f = _ledger_do(ledger, lambda d: F.add(d, report, scenario, title, latency))
    typer.echo(f"{f['id']} proposed{' (rests on a guessed stand-in)' if f['guessed'] else ''}")


@findings_app.command("repeat")
def findings_repeat(ledger: Path, fid: str,
                    report: Path = typer.Option(..., exists=True, dir_okay=False)):
    """Add a separate run of the same scenario (proposed → repeated, or contradicted)."""
    from . import findings as F

    _, f = _ledger_do(ledger, lambda d: F.repeat(d, fid, report))
    typer.echo(f"{f['id']} {f['status']}")


@findings_app.command("confirm")
def findings_confirm(ledger: Path, fid: str,
                     repro: Path = typer.Option(..., exists=True, dir_okay=False, help="The hand reproduction."),
                     answer_source: str = typer.Option(..., help="recorded | live-vendor | vendor-docs"),
                     note: str = typer.Option(..., help="What the reproduction showed.")):
    """Attach an independent hand reproduction (repeated → confirmed)."""
    from . import findings as F

    _, f = _ledger_do(ledger, lambda d: F.confirm(d, fid, repro, answer_source, note))
    typer.echo(f"{f['id']} {f['status']}")


@findings_app.command("retract")
def findings_retract(ledger: Path, fid: str, reason: str = typer.Option(...)):
    """Withdraw a finding; the record and its history stay."""
    from . import findings as F

    _, f = _ledger_do(ledger, lambda d: F.retract(d, fid, reason))
    typer.echo(f"{f['id']} retracted")


@findings_app.command("check")
def findings_check(ledger: Path,
                   runs: Path | None = typer.Option(None, exists=True, file_okay=False,
                                                    help="A folder of newer reports to check against.")):
    """Re-validate every finding against its reports and newer runs. Exit 1 on any problem."""
    from . import findings as F

    _, problems = _ledger_do(ledger, lambda d: F.check(d, runs), write=False)
    for p in problems:
        typer.echo(f"{p['id']}: {p['problem']}")
    typer.echo(f"{len(problems)} problem(s)")
    raise typer.Exit(1 if problems else 0)


@findings_app.command("render")
def findings_render(ledger: Path):
    """Print the ledger as a Markdown table."""
    from . import findings as F

    _, table = _ledger_do(ledger, F.render, write=False)
    typer.echo(table)


@findings_app.command("set")
def findings_set(ledger: Path, fid: str,
                 field: str = typer.Option(..., help="default_config | trigger"),
                 value: str = typer.Option(..., help="default_config: yes|no; trigger: attacker | guard down | "
                                           "guard answers oddly | operator misconfiguration"),
                 reason: str = typer.Option(...)):
    """Set a rating input only a person can know, with the reason."""
    from . import findings as F

    v = {"yes": True, "no": False}.get(value, value) if field == "default_config" else value
    _, f = _ledger_do(ledger, lambda d: F.set_field(d, fid, field, v, reason))
    typer.echo(f"{f['id']} severity {f['severity']['score']} ({f['severity']['why']})")


@findings_app.command("override")
def findings_override(ledger: Path, fid: str, score: int = typer.Option(...), reason: str = typer.Option(...)):
    """Record a person's own rating next to the computed one."""
    from . import findings as F

    _, f = _ledger_do(ledger, lambda d: F.override(d, fid, score, reason))
    typer.echo(f"{f['id']} computed {f['severity']['score']}, overridden {score}")


# --------------------------------------------------------------------------- record
record_app = typer.Typer(no_args_is_help=True, help="Capture real vendor replies for stand-in specs.")
app.add_typer(record_app, name="record")


@record_app.command("serve")
def record_serve(upstream: str = typer.Option(..., help="The real vendor's base URL."),
                 out: Path = typer.Option(..., help="JSON-lines file to append exchanges to."),
                 port: int = typer.Option(8899, help="Local port; point the integration here.")):
    """Forward everything to the vendor and record each exchange (no request headers,
    secret-looking fields redacted). Stop with Ctrl-C."""
    import time

    from .record import RecordingProxy

    with RecordingProxy(upstream, out, port=port) as p:
        typer.echo(f"recording {upstream} at {p.url} into {out} (Ctrl-C to stop)")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            typer.echo(f"\n{p.count} exchange(s) recorded")


@record_app.command("to-spec")
def record_to_spec(records: Path = typer.Argument(..., exists=True, dir_okay=False),
                   spec: Path = typer.Option(..., exists=True, dir_okay=False, help="The vendor spec to extend."),
                   allow: int = typer.Option(..., help="Record number of a real allow answer."),
                   block: int = typer.Option(..., help="Record number of a real block answer."),
                   out: Path = typer.Option(..., help="Where to write the spec with recorded replies.")):
    """Put a recorded allow and block answer into a vendor spec ("recorded" block)."""
    import json

    from .record import load, to_spec

    try:
        new = to_spec(load(records), json.loads(spec.read_text()), allow, block)
    except ValueError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(2) from None
    out.write_text(json.dumps(new, ensure_ascii=False, indent=2))
    shape = new["recorded"]["request_shape"]
    typer.echo(f"wrote {out}: recorded allow #{allow}, block #{block}, request shape {shape}")


@app.command()
def compare(old: Path = typer.Argument(..., exists=True, dir_okay=False, help="Earlier report.json."),
            new: Path = typer.Argument(..., exists=True, dir_okay=False, help="Later report.json."),
            json_out: Path | None = typer.Option(None, "--json", help="Also write the comparison as JSON.")):
    """What changed between two enforce reports (e.g. before and after an upgrade).
    Exit 1 if anything that held is now violated."""
    import json

    from .compare import compare as cmp
    from .compare import render

    try:
        d = cmp(old, new)
    except ValueError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(2) from None
    typer.echo(render(d))
    if json_out:
        json_out.write_text(json.dumps(d, ensure_ascii=False, indent=2))
    raise typer.Exit(1 if d["regressions"] else 0)


@app.command("upgrade-check")
def upgrade_check(
    integration: str = typer.Argument(..., help="Any `gcl enforce` integration."),
    before: Path = typer.Option(..., exists=True, help="The install you run today: its Python (Node "
                                "integrations: the directory holding its node_modules)."),
    after: Path = typer.Option(..., exists=True, help="The install you are about to move to."),
    profile: str = typer.Option("default", help="Integration profile, used on both sides."),
    before_profile: str | None = typer.Option(None, help="Profile for the before side only (default: --profile)."),
    after_profile: str | None = typer.Option(None, help="Profile for the after side only (default: --profile). "
                                             "Differing profiles simulate an upgrade that changed behaviour."),
    timeout: float | None = typer.Option(None, help="Client deadline per scenario, seconds."),
    out: Path | None = typer.Option(None, help="Directory for before/, after/ (full enforce reports) and "
                                    "upgrade-check.json."),
    scenario: list[str] = typer.Option([], help="Run only this scenario id (repeatable); controls always run."),
    spec: Path | None = typer.Option(None, exists=True, dir_okay=False, help="For the vendor adapters."),
    extra: str = typer.Option("", help="Opt-in blind spots, as for `gcl enforce` (stream, history, retry, "
                              "mcp, config)."),
    mcp_protocol: str = typer.Option("2025-03-26", "--mcp-protocol", help="With --extra mcp."),
    force: bool = typer.Option(False, help="Write into a non-empty --out folder."),
):
    """Run the same enforce plan against two installs and report what the upgrade changed.
    Exit 1 on a regression (held -> violated or unverified, or a guard no longer consulted), 2 if the
    comparison could not be made, 0 otherwise."""
    import json

    from .enforce.adapters import ADAPTERS
    from .enforce.contracts import EXTRAS, run_contracts
    from .enforce.mcp_surfaces import PROTOCOL, PROTOCOLS
    from .report.html import render_html
    from .upgrade import render
    from .upgrade import upgrade_check as judge

    if integration not in ADAPTERS:
        raise typer.BadParameter(f"choose from {', '.join(ADAPTERS)}", param_hint="integration")
    cls = ADAPTERS[integration]
    profiles = {"before": before_profile or profile, "after": after_profile or profile}
    for side, p in profiles.items():
        if p not in cls.documented:
            raise typer.BadParameter(f"{integration} profiles: {', '.join(cls.documented)}",
                                     param_hint=f"--{side}-profile")
    if out and out.exists() and any(out.iterdir()) and not force:
        raise typer.BadParameter(f"{out} is not empty; use a new folder or --force", param_hint="--out")
    extras = tuple(x.strip() for x in extra.split(",") if x.strip())
    if any(x not in EXTRAS for x in extras):
        raise typer.BadParameter(f"choose from {', '.join(EXTRAS)}", param_hint="--extra")
    if mcp_protocol not in PROTOCOLS:
        raise typer.BadParameter(f"choose from {', '.join(PROTOCOLS)}", param_hint="--mcp-protocol")
    if "mcp" in extras and not cls.mcp_transport:
        raise typer.BadParameter(f"{integration} is not an MCP gateway", param_hint="--extra")
    if "config" in extras and not cls.config_checks:
        raise typer.BadParameter(f"{integration} cannot start with a given policy", param_hint="--extra")
    docs: dict[str, dict] = {}
    # One side after the other, never together: the stand-ins and the integrations use free ports and the
    # timing of a scenario must not depend on what the other install is doing. Each side gets its OWN
    # run id: a cache that outlives one install must not be able to answer the other install's
    # requests (sentinels carry the run id). The plan, and so every scenario id, is the same.
    for side, where in (("before", before), ("after", after)):
        adapter = _make_adapter(cls, integration, where, profiles[side], spec)
        _say(f"upgrade-check: {side} ({where}, profile {profiles[side]})")
        try:
            run = run_contracts(adapter, timeout or adapter.default_timeout_s, progress=_say,
                                only=set(scenario) or None, extra=extras, mcp_protocol=mcp_protocol)
        except (RuntimeError, OSError, ValueError) as e:
            typer.echo(f"error: {side}: {e}", err=True)
            raise typer.Exit(2) from None
        doc = R.envelope("enforce", {"integration": integration, "profile": profiles[side]})
        doc["enforce"] = run
        docs[side] = doc
        if out:
            _write_outputs(doc, out / side, ["json", "html"], render_html)
    try:
        d = judge(docs["before"]["enforce"], docs["after"]["enforce"])
    except ValueError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(2) from None
    d["options"] = {"integration": integration, "extra": list(extras), "scenario": list(scenario),
                    "mcp_protocol": mcp_protocol if mcp_protocol != PROTOCOL or "mcp" in extras else None}
    typer.echo(render(d))
    if out:
        (out / "upgrade-check.json").write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")
        typer.echo(f"\nReports: {out}/")
    raise typer.Exit(d["exit_code"])


@findings_app.command("disclose")
def findings_disclose(ledger: Path, fid: str, where: str = typer.Option(..., help="Issue URL, advisory, or a "
                                                                          "dated reference to the report.")):
    """Mark a finding disclosed to its maintainers; only those appear in a public table."""
    from . import findings as F

    _, f = _ledger_do(ledger, lambda d: F.disclose(d, fid, where))
    typer.echo(f"{f['id']} disclosed ({where})")


@app.command()
def table(runs: Path = typer.Argument(..., exists=True, file_okay=False, help="Folder of enforce reports."),
          ledger: Path | None = typer.Option(None, exists=True, dir_okay=False, help="Findings ledger."),
          public: bool = typer.Option(False, help="Show only violations of disclosed findings; withhold the rest."),
          out: Path | None = typer.Option(None, help="Write the Markdown table here.")):
    """Integration × guard behaviour × version, from stored runs. Private unless --public."""
    import json

    from .table import build, render

    if public and ledger is None:
        raise typer.BadParameter("a public table needs --ledger (to know what was disclosed)", param_hint="--public")
    doc = json.loads(ledger.read_text()) if ledger else None
    text = render(build(runs, doc, public))
    if out:
        out.write_text(text + "\n", encoding="utf-8")
    typer.echo(text)


@app.command("evidence-pack")
def evidence_pack(
    reports: list[Path] = typer.Argument(..., exists=True, dir_okay=False,
                                         help="gcl report.json files (enforce, coverage, probe)."),
    out: Path = typer.Option(..., help="Directory for pack.json, pack.html, manifest.json and copies of the inputs."),
    sign_key: Path | None = typer.Option(None, "--sign-key", exists=True, dir_okay=False,
                                         help="File holding an HMAC key. Adds manifest.hmac: proves integrity "
                                              "to whoever holds the key, not who made the pack."),
):
    """Map stored run reports to framework provisions, with hashes and an honest coverage matrix.

    Technical test evidence only: not a conformity assessment, not legal advice."""
    from . import evidence as E

    try:
        res = E.build(reports, out, sign_key)
    except E.PackError as e:
        typer.echo(f"error: {e}", err=True)
        raise typer.Exit(2) from None
    p = res["pack"]
    c = p["cell_summary"]
    typer.echo(E.FW.DISCLAIMER)
    typer.echo(f"\n{len(reports)} report(s); {p['totals']['total']} results mapped: {p['totals']['held']} held, "
               f"{p['totals']['violated']} violated, {p['totals']['unverified']} unverified, {p['totals']['n/a']} n/a")
    typer.echo(f"matrix cells: {c['held']} held, {c['violated']} violated, {c['unverified']} unverified, "
               f"{c['not tested']} not tested, {c['n/a']} not applicable")
    for w in p["warnings"]:
        typer.echo(f"warning: {w}")
    typer.echo("signing: " + res["manifest"]["signing"]["statement"])
    typer.echo(f"\nPack: {out}/  ({', '.join(res['files'][:3])} ...)")


@app.command("evidence-verify")
def evidence_verify(
    pack_dir: Path = typer.Argument(..., exists=True, file_okay=False,
                                    help="A directory written by `gcl evidence-pack`."),
    sign_key: Path | None = typer.Option(None, "--sign-key", exists=True, dir_okay=False,
                                         help="HMAC key file to check manifest.hmac with."),
):
    """Re-hash every file in the manifest and check the HMAC. Exit 1 on any difference."""
    from . import evidence as E

    r = E.verify(pack_dir, sign_key)
    typer.echo(f"{r['checked']} file(s) checked; signature: {r['signature']}")
    for pr in r["problems"]:
        typer.echo(f"PROBLEM: {pr}")
    typer.echo("OK: every listed file matches the manifest" if r["ok"] else "NOT OK")
    raise typer.Exit(0 if r["ok"] else 1)


# Last, so every command above is registered when run as `python -m gcl.cli`.
if __name__ == "__main__":  # pragma: no cover
    app()
