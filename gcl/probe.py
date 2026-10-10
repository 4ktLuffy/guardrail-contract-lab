"""`gcl probe`: when the guardrail's scanner fails, does the protected action still run?

A detection rule that never fires and a scanner that crashes look the same from
outside unless you watch the action itself. So the drill does:

  * swap the system's scanner for a stand-in (via an env var the system already
    reads — a URL for HTTP scanners, a command line for subprocess scanners);
  * run the system on a request whose protected action leaves a *receipt* (a file
    the action writes when, and only when, it really executes);
  * two controls first: scanner says "malicious" (must block) and "clean" (must
    allow). If the clean control leaves no receipt, the drill cannot see the action
    and every fault result is "unverified" — never "held";
  * then each fault: timeout, error, malformed, empty, wrong schema, refused.
    The contract says what each should do (default: block, i.e. fail closed).
"""

from __future__ import annotations

import json
import os
import shlex
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import yaml

from .faults import MODES, FaultServer

FAULTS = ["timeout", "error", "malformed", "empty", "wrong_schema", "refused"]


@dataclass
class Scenario:
    name: str
    fault: str
    expect: str           # block | allow
    observed: str = ""    # blocked | executed | no-answer
    verdict: str = ""     # held | violated | unverified
    evidence: str = ""

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def load_manifest(path: str | Path) -> dict:
    p = Path(path)
    m = yaml.safe_load(p.read_text(encoding="utf-8"))
    if isinstance(m.get("argv"), str):
        m["argv"] = shlex.split(m["argv"])
    m["_dir"] = str(p.parent.resolve())
    sc = m.setdefault("scanner", {})
    sc.setdefault("mode", "http")
    sc.setdefault("clean_response", {"flagged": False})
    sc.setdefault("flag_response", {"flagged": True})
    m.setdefault("receipt_env", "GCL_RECEIPT")
    m.setdefault("timeout_s", 30.0)
    m.setdefault("request", {"text": "Please summarise the attached report."})
    return m


def load_contract(path: str | Path | None) -> dict:
    """Contract: what each fault must lead to. Default is fail-closed everywhere."""
    c = {"default": "block", "faults": {}}
    if path:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        c["default"] = data.get("default", "block")
        c["faults"] = data.get("faults", {}) or {}
    for k, v in [*c["faults"].items(), ("default", c["default"])]:
        if v not in ("block", "allow"):
            raise ValueError(f"contract: {k} must be 'block' or 'allow', not {v!r}")
    return c


def _run_system(argv, stdin: str, env: dict, cwd: str, timeout_s: float):
    """Returns (returncode or None if killed, output tail). See gcl.proc."""
    from .proc import run_supervised

    r = run_supervised(argv, stdin, timeout_s=timeout_s, cwd=cwd, env=env,
                       max_bytes=64 * 1024, keep="tail", merge_stderr=True)
    if r.error:
        raise FileNotFoundError(r.error)
    return r.returncode, r.output


def _run_once(m: dict, mode: str) -> tuple[bool, bool, str]:
    """Run the system once with the scanner in `mode`.
    Returns (executed, finished, evidence): whether the receipt was written, whether the
    system exited by itself (False = the harness had to kill it, or it never started)."""
    sc = m["scanner"]
    with tempfile.TemporaryDirectory(prefix="gcl-probe-") as tmp:
        receipt = Path(tmp) / "receipt"
        env = dict(os.environ)
        env[m["receipt_env"]] = str(receipt)
        server = None
        try:
            if sc["mode"] == "http":
                server = FaultServer(mode, sc["clean_response"], sc["flag_response"]).__enter__()
                env[sc["env"]] = server.url
            elif sc["mode"] == "command":
                if mode == "refused":
                    env[sc["env"]] = str(Path(tmp) / "no-such-scanner")
                else:
                    env[sc["env"]] = shlex.join([
                        sys.executable, "-m", "gcl.faults", mode,
                        json.dumps(sc["clean_response"]), json.dumps(sc["flag_response"])])
                    # The stand-in must import gcl wherever the system runs it from.
                    here = str(Path(__file__).resolve().parent.parent)
                    env["PYTHONPATH"] = here + os.pathsep + env.get("PYTHONPATH", "")
            else:
                raise ValueError(f"scanner.mode must be http or command, not {sc['mode']!r}")
            try:
                code, out = _run_system(m["argv"], json.dumps(m["request"]), env, m["_dir"],
                                        float(m["timeout_s"]))
            except (FileNotFoundError, PermissionError) as e:
                return False, False, f"could not start the system: {e}"
            finished = code is not None
            status = f"exit {code}" if finished else \
                f"system did not finish within {m['timeout_s']}s (process group killed)"
            tail = out.strip().splitlines()
            if tail:
                status += f"; last output: {tail[-1][:160]}"
            executed = receipt.exists()
            seen = f"; scanner contacted {server.requests}x" if server and mode != "refused" else ""
            return executed, finished, (f"receipt {'written' if executed else 'absent'}; "
                                        f"{status}{seen}")
        finally:
            if server:
                server.__exit__(None, None, None)


def _verdict(expect: str, executed: bool, finished: bool, observable: bool) -> tuple[str, str]:
    """(observed, verdict). A receipt proves the action ran even if the system was killed
    later; no receipt from a killed system proves nothing."""
    if executed:
        return "executed", ("held" if expect == "allow" else "violated") if observable else "unverified"
    if not finished:
        return "no answer", "unverified"
    if not observable:
        return "blocked", "unverified"
    return "blocked", "held" if expect == "block" else "violated"


def run_probe(manifest: dict, contract: dict, faults: list[str] | None = None,
              progress=None) -> list[Scenario]:
    say = progress or (lambda *_: None)
    faults = faults or FAULTS
    out: list[Scenario] = []

    say("control: scanner says malicious")
    ex, fin, ev = _run_once(manifest, "flag")
    obs, ver = _verdict("block", ex, fin, True)
    out.append(Scenario("control: malicious verdict", "flag", "block", obs, ver, ev))
    say("control: scanner says clean")
    ex, fin, ev = _run_once(manifest, "clean")
    obs, ver = _verdict("allow", ex, fin, True)
    if ver == "violated":  # clean verdict but no receipt: the action is not observable
        ver = "unverified"
        ev += ("; the protected action never ran, so a fault cannot be told apart from a "
               "block — fault results are unverified")
    ctl_allow = Scenario("control: clean verdict", "clean", "allow", obs, ver, ev)
    out.append(ctl_allow)
    observable = ctl_allow.verdict == "held"

    for f in faults:
        if f not in MODES:
            raise ValueError(f"unknown fault {f!r}; choose from {', '.join(FAULTS)}")
        expect = contract["faults"].get(f, contract["default"])
        say(f"fault: {f}")
        ex, fin, ev = _run_once(manifest, f)
        obs, ver = _verdict(expect, ex, fin, observable)
        out.append(Scenario(f"scanner {f}", f"{f}: {MODES[f]}", expect, obs, ver, ev))
    return out


def probe_section(manifest_path: str, contract_path: str | None, scenarios: list[Scenario]) -> dict:
    return {
        "adapter": manifest_path,
        "contract": contract_path or "default: every fault must block (fail closed)",
        "summary": {
            "scenarios": len(scenarios),
            "violations": sum(s.verdict == "violated" for s in scenarios),
            "unverified": sum(s.verdict == "unverified" for s in scenarios),
            "held": sum(s.verdict == "held" for s in scenarios),
        },
        "scenarios": [s.to_dict() for s in scenarios],
    }
