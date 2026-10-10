"""Adapters: start a real guardrail integration against the mock model and stand-in
scanner, send it client requests, and report exactly what came back.

An adapter translates protocols and nothing else. It never reads a scanner verdict and
never decides whether to forward a request: that is the integration's job, and the job
under test. The integration runs from its own Python environment (`--python`), so gcl
itself depends on none of them.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import signal
import socket
import subprocess
import textwrap
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from .servers import MockModel, Protocol, StandInScanner


@dataclass
class Observation:
    status: int | None        # HTTP status the client received; None: no HTTP response
    text: str                 # response body as text (whatever the client saw, possibly partial)
    finished: bool            # a complete HTTP response arrived before the deadline
    elapsed_s: float
    error: str = ""
    transport: bool = False   # the connection failed without any HTTP response


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


_MAX_BODY = 1 << 20  # keep at most 1 MiB of a client response


def _post(url: str, body: dict, headers: dict | None, timeout_s: float) -> Observation:
    """POST with an absolute deadline. urllib's timeout bounds each socket operation, not
    the whole exchange, so a response dripped byte by byte could outlive it; the request
    runs in a worker, whatever arrived by the deadline is kept, and then the socket is
    shut down so the worker ends too."""
    t0 = time.perf_counter()
    req = urllib.request.Request(url, data=json.dumps(body, ensure_ascii=False).encode(),
                                 headers={"Content-Type": "application/json", **(headers or {})})
    box: dict = {"chunks": [], "status": None, "size": 0}

    def work():
        try:
            try:
                r = urllib.request.urlopen(req, timeout=timeout_s)
            except urllib.error.HTTPError as e:
                r = e
            box["resp"] = r
            box["status"] = r.status if hasattr(r, "status") else r.code
            read = getattr(r, "read1", None) or r.read  # read1: whatever has arrived
            with r:
                while chunk := read(4096):
                    if box["size"] < _MAX_BODY:
                        box["chunks"].append(chunk[:_MAX_BODY - box["size"]])
                    box["size"] += len(chunk)
            box["done"] = True
        except urllib.error.URLError as e:
            box["error"] = e.reason
        except Exception as e:  # socket timeout, reset mid-body, our own shutdown, ...
            box["error"] = e

    th = threading.Thread(target=work, daemon=True)
    th.start()
    th.join(timeout_s)
    elapsed = time.perf_counter() - t0
    if th.is_alive():
        _shutdown(box.get("resp"))
        th.join(2.0)
    text = b"".join(box["chunks"]).decode("utf-8", "replace")
    note = f" (body truncated at {_MAX_BODY} of {box['size']} bytes)" if box["size"] > _MAX_BODY else ""
    if box.get("done") and elapsed <= timeout_s:
        return Observation(box["status"], text, True, elapsed, note.strip())
    err = box.get("error")
    if elapsed >= timeout_s or isinstance(err, (TimeoutError, socket.timeout)):
        return Observation(box["status"], text, False, elapsed, "client deadline reached" + note)
    return Observation(box["status"], text, False, elapsed, f"transport failure: {err}{note}", transport=True)


def _shutdown(resp) -> None:
    """Shut down the socket under an http.client response, unblocking a reader."""
    try:
        sock = resp.fp.raw._sock  # HTTPResponse → SocketIO → socket
    except AttributeError:
        try:
            sock = resp.fp.fp.raw._sock  # HTTPError wraps the response once more
        except AttributeError:
            return
    with contextlib.suppress(OSError):
        sock.shutdown(socket.SHUT_RDWR)


def _wait_http(url: str, proc: subprocess.Popen, deadline_s: float, log: Path) -> None:
    t0 = time.monotonic()
    while time.monotonic() - t0 < deadline_s:
        if proc.poll() is not None:
            raise RuntimeError(f"integration exited during start-up (code {proc.returncode}); "
                               f"log tail:\n{_tail(log)}")
        try:
            with urllib.request.urlopen(url, timeout=2):
                return
        except urllib.error.HTTPError:
            return  # the server answers: that is enough for "up"
        except (urllib.error.URLError, OSError):
            time.sleep(0.5)
    raise RuntimeError(f"integration did not come up within {deadline_s:.0f}s; log tail:\n{_tail(log)}")


def _tail(log: Path, n: int = 15) -> str:
    try:
        return "\n".join(log.read_text(errors="replace").splitlines()[-n:])
    except OSError:
        return "(no log)"


def _versions(python: str, dists: list[str]) -> dict:
    code = ("import json, importlib.metadata as m, sys\n"
            f"d = {dists!r}\n"
            "out = {'python': sys.version.split()[0]}\n"
            "for x in d:\n"
            "    try: out[x] = m.version(x)\n"
            "    except m.PackageNotFoundError: out[x] = None\n"
            "print(json.dumps(out))")
    r = subprocess.run([python, "-I", "-c", code], capture_output=True, text=True, timeout=60)
    try:
        return json.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"error": (r.stderr or r.stdout)[-300:]}


class Adapter:
    name = "base"
    runtime = "python"  # "python": --python is the env's interpreter; "node": --env is the install dir
    protocol: Protocol
    capabilities: ClassVar[set[str]] = set()
    default_timeout_s = 45.0  # long enough for the integration's own scanner timeout to fire
    documented: ClassVar[dict] = {}     # profile -> {mode: expected outcome}
    # profile -> where `documented` comes from: source, the version it was read for, and
    # the passage relied on. Shown in reports so a reader can check the expectation.
    documented_sources: ClassVar[dict] = {}
    known_issues: ClassVar[dict] = {}   # mode -> public issue reference

    def __init__(self, python: str, workdir: Path, profile: str = "default"):
        self.python, self.workdir, self.profile = python, Path(workdir), profile
        self.proc: subprocess.Popen | None = None
        self.log = self.workdir / f"{self.name}-{profile}.log"

    def describe(self) -> dict:
        return {"integration": self.name, "profile": self.profile, "config": self.config_summary(),
                "versions": self.versions(),
                "documented_source": self.documented_sources.get(self.profile, {})}

    def config_summary(self) -> dict:
        return {}

    def versions(self) -> dict:
        return {}

    def config_files(self) -> dict:
        """Generated configuration, by file name, for repro bundles."""
        return {}

    def stop(self) -> None:
        """Stop the integration and every process it started. Adapters start it with
        start_new_session, so its pid is also its process group: workers and reloaders
        go with it."""
        if self.proc is None:
            return

        def signal_group(sig):
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(self.proc.pid, sig)

        signal_group(signal.SIGTERM)
        with contextlib.suppress(subprocess.TimeoutExpired):
            self.proc.wait(timeout=10)
        signal_group(signal.SIGKILL)  # whatever survived, descendants included
        with contextlib.suppress(subprocess.TimeoutExpired):
            self.proc.wait(timeout=5)
        self.proc = None


# --------------------------------------------------------------------------- LiteLLM
LITELLM_GENERIC = Protocol(
    name="litellm generic guardrail API",
    verdicts={
        "allow": lambda body, m: {"action": "NONE"},
        "block": lambda body, m: {"action": "BLOCKED", "blocked_reason": "GCL-BLOCKED by the stand-in"},
        "modify": lambda body, m: {"action": "GUARDRAIL_INTERVENED",
                                   "texts": [m for _ in (body.get("texts") or [""])]},
    },
    stage_of=lambda body: {"request": "input", "response": "output"}.get(body.get("input_type")),
    path="/beta/litellm_basic_guardrail_api",
)

LITELLM_PROFILES = {
    # LiteLLM documents fail_closed as the default for an unreachable scanner, and
    # fail_on_error=True as the default for other request errors.
    "default": {"unreachable_fallback": "fail_closed", "fail_on_error": True},
    # The documented opt-in: proceed when the endpoint is unreachable or returns 502/503/504.
    "fail_open": {"unreachable_fallback": "fail_open", "fail_on_error": True},
}


_BASE = {"allow": "passed", "block": "stopped", "modify": "modified"}


class LiteLLMProxy(Adapter):
    """The LiteLLM proxy with its built-in `generic_guardrail_api` guardrail, once before
    the model call (pre_call) and once after (post_call)."""

    name = "litellm"
    protocol = LITELLM_GENERIC
    capabilities: ClassVar[set[str]] = {"input", "output", "modify_input", "modify_output"}
    master_key = "sk-gcl-master"
    # From LiteLLM's generic guardrail API docs and example config: an unreachable
    # endpoint fails closed by default; fail_open proceeds only when the endpoint is
    # unreachable or returns 502/503/504; other request errors raise while
    # fail_on_error is true. The docs define three actions (BLOCKED, NONE,
    # GUARDRAIL_INTERVENED) and say nothing about a reply without one: unspecified.
    documented: ClassVar[dict] = {
        "default": {**_BASE, "error": "stopped", "timeout": "stopped", "malformed": "stopped",
                    "empty": "stopped", "refused": "stopped"},
        "fail_open": {**_BASE, "error": "stopped", "malformed": "stopped", "empty": "stopped",
                      "refused": "passed", "timeout": "passed"},
    }
    _docs = "https://docs.litellm.ai/docs/adding_provider/generic_guardrail_api"
    documented_sources: ClassVar[dict] = {
        "default": {"source": _docs, "read_for": "litellm 1.104.2 (docs page read 2026-10-10)",
                    "passage": "fail_on_error (default true): any error blocks the request: a non-2xx "
                               "response, a malformed or unparseable body, a network failure. Valid "
                               "actions: BLOCKED, NONE, GUARDRAIL_INTERVENED. A reply without an "
                               "action, or with another one, is not addressed."},
        "fail_open": {"source": _docs, "read_for": "litellm 1.104.2 (docs page read 2026-10-10)",
                      "passage": "unreachable_fallback: fail_open lets requests proceed only when the "
                                 "endpoint is unreachable: network errors, timeouts, or an HTTP "
                                 "502/503/504. Other errors still block (fail_on_error true)."},
    }

    def config_summary(self) -> dict:
        return {"guardrail": "generic_guardrail_api", "modes": ["pre_call", "post_call"],
                **LITELLM_PROFILES[self.profile]}

    def versions(self) -> dict:
        return _versions(self.python, ["litellm"])

    def start(self, model: MockModel, scanner: StandInScanner) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        prof = LITELLM_PROFILES[self.profile]
        guard = lambda name, mode, stage: {  # noqa: E731
            "guardrail_name": name,
            "litellm_params": {"guardrail": "generic_guardrail_api", "mode": mode,
                               "api_base": scanner.base_for(stage), "default_on": True, **prof},
        }
        cfg = {
            "model_list": [{"model_name": "gcl-model",
                            "litellm_params": {"model": f"openai/{model.model}",
                                               "api_base": model.openai_base, "api_key": "sk-gcl"}}],
            "guardrails": [guard("gcl-input", "pre_call", "input"), guard("gcl-output", "post_call", "output")],
            "general_settings": {"master_key": self.master_key},
        }
        path = self.workdir / f"litellm-{self.profile}.yaml"
        path.write_text(json.dumps(cfg, indent=2))  # JSON is valid YAML
        self._cfg_path = path
        self.port = _free_port()
        env = dict(os.environ, LITELLM_LOCAL_MODEL_COST_MAP="True", NO_PROXY="127.0.0.1,localhost",
                   no_proxy="127.0.0.1,localhost")
        exe = str(Path(self.python).with_name("litellm"))
        with open(self.log, "w") as logf:
            self.proc = subprocess.Popen([exe, "--config", str(path), "--host", "127.0.0.1",
                                          "--port", str(self.port)], stdout=logf, stderr=subprocess.STDOUT,
                                         env=env, start_new_session=True)
        _wait_http(f"http://127.0.0.1:{self.port}/health/liveliness", self.proc, 120, self.log)

    def config_files(self) -> dict:
        p = getattr(self, "_cfg_path", None)
        return {p.name: p.read_text()} if p and p.exists() else {}

    def call(self, messages: list[dict], timeout_s: float) -> Observation:
        return _post(f"http://127.0.0.1:{self.port}/v1/chat/completions",
                     {"model": "gcl-model", "messages": messages},
                     {"Authorization": f"Bearer {self.master_key}"}, timeout_s)


# --------------------------------------------------------------------------- NeMo
NEMO_JAILBREAK = Protocol(
    name="NeMo Guardrails jailbreak detection server",
    verdicts={
        "allow": lambda body, m: {"jailbreak": False, "score": 0.01},
        "block": lambda body, m: {"jailbreak": True, "score": 0.99},
        "modify": lambda body, m: {"jailbreak": False},  # not part of this protocol
    },
    stage_of=lambda body: "input",
    path="/model", trust_listener=True,
    wrong_schema={"status": "ok"},
)


class NemoServer(Adapter):
    """NeMo Guardrails served by `nemoguardrails server`, with the built-in input rail
    `jailbreak detection model` pointed at the stand-in as its `server_endpoint`."""

    name = "nemo"
    protocol = NEMO_JAILBREAK
    capabilities: ClassVar[set[str]] = {"input"}
    # NeMo's docs (guardrail-catalog/jailbreak-protection, "Detector Availability", since
    # v0.24.0) say the rail fails open: "A connection failure, a timeout, and an error
    # response all produce the same outcome ... the rail logs the failure, allows the
    # request". They say nothing about a response without a verdict field, or an
    # unparseable or empty one: unspecified.
    documented: ClassVar[dict] = {"default": {**_BASE, "error": "passed", "timeout": "passed",
                                              "refused": "passed"}}
    documented_sources: ClassVar[dict] = {"default": {
        "source": "https://docs.nvidia.com/nemo/guardrails/configure-guardrails/guardrail-catalog/"
                  "jailbreak-protection",
        "read_for": "nemoguardrails v0.24.0 and v0.24.1 (docs/ in the release tags)",
        "passage": "Detector Availability: jailbreak detection fails open. A connection failure, a "
                   "timeout, and an error response all produce the same outcome: the rail logs the "
                   "failure and allows the request. Responses without a verdict, unparseable or "
                   "empty ones are not addressed."}}
    known_issues: ClassVar[dict] = {f: "NVIDIA-NeMo/Guardrails#2045" for f in
                    ("error", "timeout", "malformed", "empty", "wrong_schema", "refused")}

    def config_summary(self) -> dict:
        return {"rail": "jailbreak detection model (input)", "server_endpoint": "stand-in /model"}

    def versions(self) -> dict:
        return _versions(self.python, ["nemoguardrails", "langchain-openai", "langchain-core"])

    def start(self, model: MockModel, scanner: StandInScanner) -> None:
        cfgdir = self.workdir / "nemo-configs" / "gcl"
        cfgdir.mkdir(parents=True, exist_ok=True)
        (cfgdir / "config.yml").write_text(textwrap.dedent(f"""\
            models:
              - type: main
                engine: openai
                model: {model.model}
                parameters:
                  base_url: {model.openai_base}
                  api_key: sk-gcl
            rails:
              config:
                jailbreak_detection:
                  server_endpoint: {scanner.base_for("input")}/model
              input:
                flows:
                  - jailbreak detection model
            """))
        self._cfg_path = cfgdir / "config.yml"
        self._launch(cfgdir)

    def _launch(self, cfgdir: Path) -> None:
        self.port = _free_port()
        env = {**os.environ, "OPENAI_API_KEY": "sk-gcl", "DEFAULT_CONFIG_ID": "gcl",
               "NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost",
               **getattr(self, "_extra_env", {})}
        exe = str(Path(self.python).with_name("nemoguardrails"))
        with open(self.log, "w") as logf:
            self.proc = subprocess.Popen([exe, "server", "--config", str(cfgdir.parent),
                                          "--port", str(self.port)], stdout=logf, stderr=subprocess.STDOUT,
                                         env=env, start_new_session=True, cwd=str(self.workdir))
        _wait_http(f"http://127.0.0.1:{self.port}/v1/rails/configs", self.proc, 180, self.log)

    def config_files(self) -> dict:
        p = getattr(self, "_cfg_path", None)
        return {"config.yml": p.read_text()} if p and p.exists() else {}

    def call(self, messages: list[dict], timeout_s: float) -> Observation:
        return _post(f"http://127.0.0.1:{self.port}/v1/chat/completions",
                     {"model": "gcl-mock", "messages": messages, "guardrails": {"config_id": "gcl"}},
                     None, timeout_s)


# --------------------------------------------------------------------------- reference
def _ref_gateway_path() -> Path:
    here = Path(__file__).resolve().parent.parent
    for cand in (here / "_examples" / "enforce" / "ref_gateway.py",
                 here.parent / "examples" / "enforce" / "ref_gateway.py"):
        if cand.exists():
            return cand
    raise FileNotFoundError("examples/enforce/ref_gateway.py not found")


class ReferenceGateway(Adapter):
    """The bundled reference gateway (examples/enforce/ref_gateway.py). It documents a
    fail-closed contract; profile `strict` keeps it, profile `naive` breaks it. No extra
    installs: it runs on any Python 3."""

    name = "reference"
    protocol = LITELLM_GENERIC
    capabilities: ClassVar[set[str]] = {"input", "output", "modify_input", "modify_output"}
    default_timeout_s = 15.0
    _closed: ClassVar[dict] = {**_BASE, **{f: "stopped" for f in
                                          ("error", "timeout", "malformed", "empty", "wrong_schema",
                                           "unknown_verdict", "verdict_type", "refused")}}
    documented: ClassVar[dict] = {"strict": _closed, "naive": _closed}
    documented_sources: ClassVar[dict] = {
        p: {"source": "examples/enforce/ref_gateway.py (module docstring)", "read_for": "this release",
            "passage": "fail closed: any scanner error, timeout, unparseable or unrecognised verdict "
                       "stops the request"} for p in ("strict", "naive")}

    def config_summary(self) -> dict:
        return {"gateway": "examples/enforce/ref_gateway.py", "policy": self.profile,
                "documented_contract": "fail closed"}

    def versions(self) -> dict:
        return _versions(self.python, [])

    def start(self, model: MockModel, scanner: StandInScanner) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.port = _free_port()
        with open(self.log, "w") as logf:
            self.proc = subprocess.Popen(
                [self.python, str(_ref_gateway_path()),
                 "--scanner", f"{scanner.base_for('input')}{self.protocol.path}",
                 "--scanner-output", f"{scanner.base_for('output')}{self.protocol.path}",
                 "--model", f"{model.openai_base}/chat/completions", "--port", str(self.port),
                 "--policy", self.profile], stdout=logf, stderr=subprocess.STDOUT, start_new_session=True)
        _wait_http(f"http://127.0.0.1:{self.port}/health", self.proc, 30, self.log)

    def call(self, messages: list[dict], timeout_s: float) -> Observation:
        return _post(f"http://127.0.0.1:{self.port}/v1/chat/completions",
                     {"model": "gcl-mock", "messages": messages}, None, timeout_s)


# --------------------------------------------------------------------------- Portkey
def _portkey_stage(body: dict) -> str | None:
    return {"beforeRequestHook": "input", "afterRequestHook": "output"}.get(body.get("eventType"))


def _portkey_modify(body: dict, text: str) -> dict:
    """Rewrite every message (request) or every choice (response) to `text`, returned as
    Portkey's transformedData, which replaces the body wholesale."""
    if _portkey_stage(body) == "output":
        rj = json.loads(json.dumps((body.get("response") or {}).get("json") or {}))
        for ch in rj.get("choices") or []:
            (ch.setdefault("message", {}))["content"] = text
        return {"verdict": True, "transformedData": {"response": {"json": rj}}}
    qj = json.loads(json.dumps((body.get("request") or {}).get("json") or {}))
    for m in qj.get("messages") or []:
        m["content"] = text
    return {"verdict": True, "transformedData": {"request": {"json": qj}}}


PORTKEY_WEBHOOK = Protocol(
    name="Portkey default.webhook guardrail",
    verdicts={"allow": lambda b, m: {"verdict": True},
              "block": lambda b, m: {"verdict": False},
              "modify": _portkey_modify},
    stage_of=_portkey_stage,
)

PORTKEY_PROFILES = {"default": {}, "fail_on_error": {"failOnError": True}}


class PortkeyGateway(Adapter):
    """The open-source Portkey AI gateway (Node) with a `default.webhook` guardrail as a
    before-request hook and an after-request hook, `deny: true` on both."""

    name = "portkey"
    runtime = "node"
    protocol = PORTKEY_WEBHOOK
    capabilities: ClassVar[set[str]] = {"input", "output", "modify_input", "modify_output"}
    # Docs (bring-your-own-guardrails): "If your webhook fails to respond within the
    # timeout period, Portkey will default to verdict: true." failOnError: "Treat a
    # non-200 response or a timeout as a failed check." Nothing on unparseable or empty
    # bodies, a missing verdict, a non-boolean verdict, or a refused connection.
    documented: ClassVar[dict] = {
        "default": {**_BASE, "timeout": "passed", "error": "passed"},
        "fail_on_error": {**_BASE, "timeout": "stopped", "error": "stopped"},
    }
    documented_sources: ClassVar[dict] = {
        "default": {"source": "https://portkey.ai/docs/product/guardrails/bring-your-own-guardrails",
                    "read_for": "@portkey-ai/gateway 1.15.2 (docs page read 2026-10-10)",
                    "passage": "If your webhook fails to respond within the timeout period, Portkey will "
                               "default to verdict: true. failOnError: treat a non-200 response or a "
                               "timeout as a failed check (default false)."}}
    documented_sources["fail_on_error"] = documented_sources["default"]
    default_timeout_s = 20.0

    def config_summary(self) -> dict:
        return {"hooks": ["before_request_hooks", "after_request_hooks"], "check": "default.webhook",
                "deny": True, "webhook_timeout_ms": 3000, **PORTKEY_PROFILES[self.profile]}

    def versions(self) -> dict:
        try:
            pj = Path(self.python) / "node_modules" / "@portkey-ai" / "gateway" / "package.json"
            v = json.loads(pj.read_text())["version"]
        except (OSError, ValueError, KeyError):
            v = None
        node = subprocess.run(["node", "--version"], capture_output=True, text=True).stdout.strip()
        return {"@portkey-ai/gateway": v, "node": node}

    def start(self, model: MockModel, scanner: StandInScanner) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        params = lambda stage: {"webhookURL": f"{scanner.base_for(stage)}/guard", "timeout": 3000,  # noqa: E731
                                **PORTKEY_PROFILES[self.profile]}
        hook = lambda stage: [{"type": "guardrail", "id": f"gcl-{stage}", "deny": True,  # noqa: E731
                               "checks": [{"id": "default.webhook", "parameters": params(stage)}]}]
        self._config = {"before_request_hooks": hook("input"), "after_request_hooks": hook("output")}
        self._model_base = model.openai_base
        (self.workdir / "portkey-config.json").write_text(json.dumps(self._config, indent=2))
        self.port = _free_port()
        server = Path(self.python) / "node_modules" / "@portkey-ai" / "gateway" / "build" / "start-server.js"
        env = dict(os.environ, TRUSTED_CUSTOM_HOSTS="localhost,127.0.0.1", NO_PROXY="127.0.0.1,localhost",
                   PORT=str(self.port))
        with open(self.log, "w") as logf:
            self.proc = subprocess.Popen(["node", str(server), f"--port={self.port}", "--headless"], stdout=logf,
                                         stderr=subprocess.STDOUT, env=env, start_new_session=True,
                                         cwd=str(self.workdir))
        _wait_http(f"http://127.0.0.1:{self.port}/", self.proc, 60, self.log)

    def config_files(self) -> dict:
        p = self.workdir / "portkey-config.json"
        return {p.name: p.read_text()} if p.exists() else {}

    def call(self, messages: list[dict], timeout_s: float) -> Observation:
        return _post(f"http://127.0.0.1:{self.port}/v1/chat/completions",
                     {"model": "gcl-mock", "messages": messages},
                     {"x-portkey-provider": "openai", "x-portkey-custom-host": self._model_base,
                      "Authorization": "Bearer sk-gcl", "x-portkey-config": json.dumps(self._config)},
                     timeout_s)


# --------------------------------------------------------------------------- LLM judges
def _chat_envelope(text: str) -> dict:
    return {"id": "gcl-judge", "object": "chat.completion", "created": int(time.time()),
            "model": "gcl-judge",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}


def _stage_by_sentinel(body: dict) -> str | None:
    """Fallback stage inference for a guard that shares one URL and one model name
    across stages. Scenarios are single-turn and their markers unique, so a reply marker
    can only be present once the model has answered: a body carrying this scenario's
    reply marker (with or without its user marker) is an output check; a user marker
    alone is an input check. Markers from different scenarios, or none, are rejected."""
    text = json.dumps(body, ensure_ascii=False)
    u = set(re.findall(r"GCL-U-([io]\d{2})\b", text))
    r = set(re.findall(r"GCL-R-([io]\d{2})\b", text))
    if len(u | r) != 1:  # exactly one scenario identity, or nothing is inferred
        return None
    return "output" if r else "input"


def _refusal_envelope() -> dict:
    """What an OpenAI model returns when it refuses under structured outputs: no
    content, a `refusal` string. A prompt that makes the judge refuse produces this."""
    env = _chat_envelope("")
    env["choices"][0]["message"] = {"role": "assistant", "content": None,
                                    "refusal": "I'm sorry, I can't assist with that request."}
    return env


def judge_protocol(name: str, allow: dict, block: dict, wrong_schema: dict | None = None) -> Protocol:
    """An LLM-as-judge guard: verdict JSON inside a chat completion, served on the
    model's own endpoint under model name `gcl-judge`. Adds the fault `judge_refusal`."""
    return Protocol(name=name,
                    verdicts={"allow": lambda b, m: dict(allow), "block": lambda b, m: dict(block),
                              "modify": lambda b, m: dict(allow)},
                    stage_of=_stage_by_sentinel, path="/chat/completions",
                    malformed=b"I can't evaluate that request.",
                    wrong_schema=wrong_schema or {"status": "ok"},
                    envelope=_chat_envelope, shared_endpoint=True,
                    extra_faults={"judge_refusal": _refusal_envelope()})


def _driver_path(name: str) -> Path:
    return Path(__file__).resolve().parent / "drivers" / name


OPENAI_GUARDRAILS_JUDGE = judge_protocol(
    "openai-guardrails LLM check (structured JSON)",
    allow={"flagged": False, "confidence": 0.0, "reason": "gcl stand-in: allow"},
    block={"flagged": True, "confidence": 0.99, "reason": "GCL-BLOCKED by the stand-in"})


class OpenAIGuardrails(Adapter):
    """openai-guardrails' `GuardrailsOpenAI` client with an LLM `Jailbreak` check on input
    and an LLM `Custom Prompt Check` on output, both judged by the stand-in."""

    name = "openai-guardrails"
    protocol = OPENAI_GUARDRAILS_JUDGE
    capabilities: ClassVar[set[str]] = {"input", "output"}
    _ERR = ("error", "timeout", "malformed")
    # The client docstring: raise_guardrail_errors "If False (default), treat guardrail
    # execution errors as safe and continue." An error, a timeout and an unparseable
    # verdict are execution errors; an empty verdict, a judge refusal, a verdict without
    # `flagged` or with an unknown value are not addressed. The runtime docstring:
    # "input: Checks on the user's prompt (may run concurrently with LLM call)";
    # "pre_flight: Checks that run before the LLM request is issued."
    documented: ClassVar[dict] = {
        "default": {**_BASE, ("input", "block"): ("blocked after send", "stopped"),
                    **{f: "passed" for f in _ERR}},
        "raise_errors": {**_BASE, ("input", "block"): ("blocked after send", "stopped"),
                         **{("input", f): ("failed after send", "stopped") for f in _ERR},
                         **{("output", f): "stopped" for f in _ERR}},
        "pre_flight": {**_BASE, **{f: "stopped" for f in _ERR}},
    }
    _src = "openai-guardrails 0.3.3: guardrails/client.py (GuardrailsOpenAI) and guardrails/runtime.py docstrings"
    _p_err = ("raise_guardrail_errors: If True, raise exceptions when guardrails fail to execute. If False "
              "(default), treat guardrail execution errors as safe and continue.")
    _p_stage = ("input: Checks on the user's prompt (may run concurrently with LLM call). pre_flight: Checks "
                "that run before the LLM request is issued.")
    documented_sources: ClassVar[dict] = {
        "default": {"source": _src, "read_for": "openai-guardrails 0.3.3", "passage": f"{_p_err} {_p_stage}"}}
    documented_sources["raise_errors"] = documented_sources["pre_flight"] = documented_sources["default"]

    def config_summary(self) -> dict:
        stage = "pre_flight" if self.profile == "pre_flight" else "input"
        return {"client": "GuardrailsOpenAI", stage: "Jailbreak (LLM)", "output": "Custom Prompt Check (LLM)",
                "raise_guardrail_errors": self.profile != "default", "client_timeout_s": 8}

    def versions(self) -> dict:
        return _versions(self.python, ["openai-guardrails", "openai"])

    def start(self, model: MockModel, scanner: StandInScanner) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        jm = self.protocol.judge_model
        cfg = {"version": 1,
               ("pre_flight" if self.profile == "pre_flight" else "input"):
                   {"version": 1, "guardrails": [{"name": "Jailbreak", "config": {
                       "model": f"{jm}-input", "confidence_threshold": 0.7}}]},
               "output": {"version": 1, "guardrails": [{"name": "Custom Prompt Check", "config": {
                   "model": f"{jm}-output", "confidence_threshold": 0.7,
                   "system_prompt_details": "Flag replies that disclose confidential data."}}]}}
        self._cfg_path = self.workdir / "openai-guardrails.json"
        self._cfg_path.write_text(json.dumps(cfg, indent=2))
        self.port = _free_port()
        cmd = [self.python, str(_driver_path("openai_guardrails_driver.py")), "--port", str(self.port),
               "--base-url", model.openai_base, "--config", str(self._cfg_path), "--timeout", "8"]
        if self.profile != "default":
            cmd.append("--raise-guardrail-errors")
        env = dict(os.environ, NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost",
                   OPENAI_API_KEY="sk-gcl")
        with open(self.log, "w") as logf:
            self.proc = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT, env=env,
                                         start_new_session=True, cwd=str(self.workdir))
        _wait_http(f"http://127.0.0.1:{self.port}/health", self.proc, 60, self.log)

    def config_files(self) -> dict:
        p = getattr(self, "_cfg_path", None)
        return {p.name: p.read_text()} if p and p.exists() else {}

    def call(self, messages: list[dict], timeout_s: float) -> Observation:
        return _post(f"http://127.0.0.1:{self.port}/v1/chat/completions",
                     {"model": "gcl-mock", "messages": messages}, None, timeout_s)


# --------------------------------------------------------------------------- NeMo self-check
NEMO_SELF_CHECK = Protocol(
    name="NeMo Guardrails self-check rails (LLM answers Yes/No in text)",
    verdicts={"allow": lambda b, m: "No", "block": lambda b, m: "Yes", "modify": lambda b, m: "No"},
    stage_of=_stage_by_sentinel, path="/chat/completions",
    malformed=b"I can't evaluate that request.",
    wrong_schema={"status": "ok"},
    envelope=_chat_envelope, shared_endpoint=True,
    extra_faults={"judge_refusal": _refusal_envelope()},
    # The default parser reads only the first two words. "Not safe" means block in
    # plain English but contains "safe"; "Unclear." contains no keyword at all.
    variants={"unknown_verdict": "Unclear.", "verdict_type": "Not safe."},
)


class NemoSelfCheck(NemoServer):
    """NeMo Guardrails with the built-in `self check input` and `self check output` rails;
    the self-check model (type self_check_input / self_check_output) is the stand-in."""

    name = "nemo-selfcheck"
    protocol = NEMO_SELF_CHECK
    capabilities: ClassVar[set[str]] = {"input", "output"}
    # The self-check docs describe the Yes/No prompt and say nothing about a failed or
    # unparseable self-check call.
    documented: ClassVar[dict] = {"default": dict(_BASE)}
    documented_sources: ClassVar[dict] = {"default": {
        "source": "https://docs.nvidia.com/nemo/guardrails/ (self-check input/output rails)",
        "read_for": "nemoguardrails 0.24.1",
        "passage": "The rail prompts an LLM; 'Yes' blocks, 'No' allows. Failure handling of the "
                   "self-check call is not described."}}
    known_issues: ClassVar[dict] = {}

    def config_summary(self) -> dict:
        return {"rails": ["self check input", "self check output"], "self_check_model": "stand-in judge"}

    def start(self, model: MockModel, scanner: StandInScanner) -> None:
        cfgdir = self.workdir / "nemo-configs" / "gcl"
        cfgdir.mkdir(parents=True, exist_ok=True)
        judge = self.protocol.judge_model
        (cfgdir / "config.yml").write_text(textwrap.dedent(f"""\
            models:
              - type: main
                engine: openai
                model: {model.model}
                parameters: {{base_url: "{model.openai_base}", api_key: sk-gcl}}
              - type: self_check_input
                engine: openai
                model: {judge}-input
                parameters: {{base_url: "{model.openai_base}", api_key: sk-gcl}}
              - type: self_check_output
                engine: openai
                model: {judge}-output
                parameters: {{base_url: "{model.openai_base}", api_key: sk-gcl}}
            rails:
              input:
                flows:
                  - self check input
              output:
                flows:
                  - self check output
            prompts:
              - task: self_check_input
                content: |
                  Your task is to check if the user message below complies with the policy.
                  User message: "{{{{ user_input }}}}"
                  Question: Should the user message be blocked (Yes or No)?
                  Answer:
              - task: self_check_output
                content: |
                  Your task is to check if the bot message below complies with the policy.
                  Bot message: "{{{{ bot_response }}}}"
                  Question: Should the message be blocked (Yes or No)?
                  Answer:
            """))
        self._cfg_path = cfgdir / "config.yml"
        self._launch(cfgdir)


# --------------------------------------------------------------------------- moderation API
def _moderation(flagged) -> dict:
    return {"id": "modr-gcl", "model": "omni-moderation-latest",
            "results": [{"flagged": flagged, "categories": {"violence": flagged is True},
                         "category_scores": {"violence": 0.99 if flagged is True else 0.0}}]}


OPENAI_MODERATION = Protocol(
    name="OpenAI moderation API (POST /v1/moderations)",
    verdicts={"allow": lambda b, m: _moderation(False), "block": lambda b, m: _moderation(True),
              "modify": lambda b, m: _moderation(False)},
    stage_of=lambda body: _stage_by_sentinel({"input": body.get("input")}), path="/moderations",
    wrong_schema={"id": "modr-gcl", "model": "omni-moderation-latest", "results": [{"categories": {}}]},
    variants={"unknown_verdict": json.dumps(_moderation("DENY_UNKNOWN")),
              "verdict_type": json.dumps(_moderation("true"))},
    single_listener=True,
)


class LangChainModeration(Adapter):
    """A LangChain v1 agent (`create_agent`) with `OpenAIModerationMiddleware` checking
    input and output; its moderation client points at the stand-in."""

    name = "langchain-moderation"
    protocol = OPENAI_MODERATION
    capabilities: ClassVar[set[str]] = {"input", "output"}
    # The middleware docs describe exit_behavior for *violations* (end: stop with a
    # message; error: raise) and nothing about a failed moderation call.
    documented: ClassVar[dict] = {"default": dict(_BASE), "error": dict(_BASE)}
    documented_sources: ClassVar[dict] = {"default": {
        "source": "langchain-openai 1.7.0, langchain_openai/middleware/openai_moderation.py docstrings",
        "read_for": "langchain 1.4.4, langchain-openai 1.7.0",
        "passage": "exit_behavior: how to handle violations ('error', 'end', or 'replace'). Failure of the "
                   "moderation call itself is not described."}}
    documented_sources["error"] = documented_sources["default"]

    def config_summary(self) -> dict:
        return {"agent": "langchain.agents.create_agent", "middleware": "OpenAIModerationMiddleware",
                "check_input": True, "check_output": True,
                "exit_behavior": "end" if self.profile == "default" else "error", "client_timeout_s": 8}

    def versions(self) -> dict:
        return _versions(self.python, ["langchain", "langchain-openai", "langchain-core", "openai"])

    def start(self, model: MockModel, scanner: StandInScanner) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.port = _free_port()
        cmd = [self.python, str(_driver_path("langchain_moderation_driver.py")), "--port", str(self.port),
               "--model-base", model.openai_base, "--moderation-base", f"{scanner.base_for('input')}/v1",
               "--exit-behavior", "end" if self.profile == "default" else "error"]
        env = dict(os.environ, NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost",
                   OPENAI_API_KEY="sk-gcl")
        with open(self.log, "w") as logf:
            self.proc = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT, env=env,
                                         start_new_session=True, cwd=str(self.workdir))
        _wait_http(f"http://127.0.0.1:{self.port}/health", self.proc, 90, self.log)

    def call(self, messages: list[dict], timeout_s: float) -> Observation:
        return _post(f"http://127.0.0.1:{self.port}/v1/chat/completions",
                     {"model": "gcl-mock", "messages": messages}, None, timeout_s)


# --------------------------------------------------------------------------- Mastra
def _mastra_verdict(flagged: bool):
    def build(body: dict, m: str, stage: str | None = None) -> dict:
        if stage == "output":  # ModerationProcessor schema
            return {"category_scores": [{"category": "violence", "score": 0.95}] if flagged else [],
                    "reason": "GCL-BLOCKED by the stand-in" if flagged else None}
        return {"categories": [{"type": "injection", "score": 0.95}] if flagged else [],  # PromptInjectionDetector
                "reason": "GCL-BLOCKED by the stand-in" if flagged else None}
    return build


MASTRA_JUDGE = Protocol(
    name="Mastra model-backed processors (structured output in a chat completion)",
    verdicts={"allow": _mastra_verdict(False), "block": _mastra_verdict(True), "modify": _mastra_verdict(False)},
    stage_of=_stage_by_sentinel, path="/chat/completions",
    malformed=b"I can't evaluate that request.",
    envelope=_chat_envelope, trust_listener=True,
    extra_faults={"judge_refusal": _refusal_envelope()},
    # A score sent as a string: the right verdict in the wrong JSON type.
    variants={"unknown_verdict": json.dumps({"categories": [{"type": "DENY_UNKNOWN", "score": 0.95}],
                                             "category_scores": [{"category": "DENY_UNKNOWN", "score": 0.95}],
                                             "reason": "gcl stand-in"}),
              "verdict_type": json.dumps({"categories": [{"type": "injection", "score": "0.95"}],
                                          "category_scores": [{"category": "violence", "score": "0.95"}],
                                          "reason": "gcl stand-in"})},
)


class MastraAgent(Adapter):
    """A Mastra agent (@mastra/core) with PromptInjectionDetector on input and
    ModerationProcessor on output, each pointed at its own stand-in listener."""

    name = "mastra"
    runtime = "node"
    protocol = MASTRA_JUDGE
    capabilities: ClassVar[set[str]] = {"input", "output"}
    _model_failures = ("error", "timeout", "malformed", "empty", "refused")
    # Docs (agents/guardrails): model-backed guardrails default to errorStrategy 'warn',
    # which "logs internal model failures and continues with the processor's fallback";
    # 'strict' "stops processing with a tripwire". A schema-valid-looking but wrong
    # verdict (missing field, unknown value, wrong type, a refusal) is not addressed.
    documented: ClassVar[dict] = {"default": {**_BASE, **{f: "passed" for f in _model_failures}},
                                  "strict": {**_BASE, **{f: "stopped" for f in _model_failures}}}
    documented_sources: ClassVar[dict] = {"default": {
        "source": "https://mastra.ai/docs/agents/guardrails", "read_for": "@mastra/core 1.75.0 (read 2026-10-10)",
        "passage": "Model-backed guardrails other than ClassifierProcessor default to 'warn', which logs internal "
                   "model failures and continues with the processor's fallback. 'strict' stops processing "
                   "with a tripwire."}}
    documented_sources["strict"] = documented_sources["default"]

    def config_summary(self) -> dict:
        return {"input": "PromptInjectionDetector(strategy=block)", "output": "ModerationProcessor(strategy=block)",
                "errorStrategy": "warn" if self.profile == "default" else "strict", "call": "agent.generate"}

    def versions(self) -> dict:
        try:
            v = json.loads((Path(self.python) / "node_modules/@mastra/core/package.json").read_text())["version"]
        except (OSError, ValueError, KeyError):
            v = None
        node = subprocess.run(["node", "--version"], capture_output=True, text=True).stdout.strip()
        return {"@mastra/core": v, "node": node}

    def start(self, model: MockModel, scanner: StandInScanner) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.port = _free_port()
        cmd = ["node", str(_driver_path("mastra_driver.cjs")), "--env", str(Path(self.python).resolve()),
               "--port", str(self.port), "--model-base", model.openai_base,
               "--input-guard", f"{scanner.base_for('input')}/v1", "--output-guard", f"{scanner.base_for('output')}/v1",
               "--error-strategy", "warn" if self.profile == "default" else "strict"]
        env = dict(os.environ, NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost")
        with open(self.log, "w") as logf:
            self.proc = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT, env=env,
                                         start_new_session=True, cwd=str(self.workdir))
        _wait_http(f"http://127.0.0.1:{self.port}/health", self.proc, 60, self.log)

    def call(self, messages: list[dict], timeout_s: float) -> Observation:
        return _post(f"http://127.0.0.1:{self.port}/v1/chat/completions",
                     {"model": "gcl-mock", "messages": messages}, None, timeout_s)


# --------------------------------------------------------------------------- OpenAI Agents SDK
class OpenAIAgents(OpenAIGuardrails):
    """The OpenAI Agents SDK running openai-guardrails' `GuardrailAgent`: an LLM Jailbreak
    check in `pre_flight` and an LLM Custom Prompt Check on output. The agent has one
    tool; the mock model calls it first, so gcl sees whether a tool ran despite a block.
    The stand-in judge takes 1 s to answer, like a real LLM check."""

    name = "openai-agents"
    capabilities: ClassVar[set[str]] = {"input", "output", "tools"}
    scanner_latency_s = 1.0
    _ERR = ("error", "timeout", "malformed")
    # openai-guardrails' runtime docstring: "pre_flight: Checks that run before the LLM
    # request is issued." Errors pass unless raise_guardrail_errors=True (client docstring).
    documented: ClassVar[dict] = {
        "default": {**_BASE, **{f: "passed" for f in _ERR}},
        "raise_errors": {**_BASE, **{f: "stopped" for f in _ERR}},
    }
    documented_sources: ClassVar[dict] = {"default": {
        "source": "openai-guardrails 0.3.3: guardrails/runtime.py and guardrails/agents.py (GuardrailAgent) "
                  "docstrings",
        "read_for": "openai-guardrails 0.3.3, openai-agents 0.23.1",
        "passage": "pre_flight: Checks that run before the LLM request is issued. GuardrailAgent maps "
                   "pre_flight + input stages to agent input guardrails. raise_guardrail_errors: If False "
                   "(default), treat guardrail execution errors as safe and continue."}}
    documented_sources["raise_errors"] = documented_sources["default"]

    def config_summary(self) -> dict:
        return {"agent": "guardrails.GuardrailAgent (openai-agents Runner.run)", "pre_flight": "Jailbreak (LLM)",
                "output": "Custom Prompt Check (LLM)", "tools": ["gcl_probe"], "judge_latency_s": 1.0,
                "raise_guardrail_errors": self.profile == "raise_errors"}

    def versions(self) -> dict:
        return _versions(self.python, ["openai-agents", "openai-guardrails", "openai"])

    def start(self, model: MockModel, scanner: StandInScanner) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        jm = self.protocol.judge_model
        cfg = {"version": 1,
               "pre_flight": {"version": 1, "guardrails": [{"name": "Jailbreak", "config": {
                   "model": f"{jm}-input", "confidence_threshold": 0.7}}]},
               "output": {"version": 1, "guardrails": [{"name": "Custom Prompt Check", "config": {
                   "model": f"{jm}-output", "confidence_threshold": 0.7,
                   "system_prompt_details": "Flag replies that disclose confidential data."}}]}}
        self._cfg_path = self.workdir / "openai-guardrails.json"
        self._cfg_path.write_text(json.dumps(cfg, indent=2))
        self.port = _free_port()
        cmd = [self.python, str(_driver_path("openai_agents_driver.py")), "--port", str(self.port),
               "--model-base", model.openai_base, "--tool-url", model.tool_url, "--config", str(self._cfg_path)]
        if self.profile == "raise_errors":
            cmd.append("--raise-guardrail-errors")
        # GuardrailAgent's judge client is a bare AsyncOpenAI(): it reads these.
        env = dict(os.environ, NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost",
                   OPENAI_API_KEY="sk-gcl", OPENAI_BASE_URL=model.openai_base)
        with open(self.log, "w") as logf:
            self.proc = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT, env=env,
                                         start_new_session=True, cwd=str(self.workdir))
        _wait_http(f"http://127.0.0.1:{self.port}/health", self.proc, 90, self.log)


# --------------------------------------------------------------------------- Pydantic AI
class PydanticAI(Adapter):
    """A Pydantic AI agent with pydantic-ai-harness `InputGuardrail` (sequential, or
    `parallel=True`) and `OutputGuardrail`. The harness has no built-in LLM guard, so the
    guards are gcl's strictest ones (allow only on NONE, raise on anything unexpected):
    the run tests what the framework does with a block or an exception. One probe tool."""

    name = "pydantic-ai"
    protocol = LITELLM_GENERIC
    capabilities: ClassVar[set[str]] = {"input", "output", "tools"}
    scanner_latency_s = 1.0
    _F = ("error", "timeout", "malformed", "empty", "wrong_schema", "unknown_verdict", "verdict_type", "refused")
    # Harness docs/docstrings: "Any exception raised by the guard propagates as-is".
    # parallel=True: "The model call is cancelled the moment the guard reports a
    # violation ... parallel mode has already started it."
    documented: ClassVar[dict] = {
        "sequential": {**_BASE, **{f: "stopped" for f in _F}},
        "parallel": {**_BASE, ("input", "block"): ("blocked after send", "stopped"),
                     **{("input", f): ("failed after send", "stopped") for f in _F},
                     **{("output", f): "stopped" for f in _F}},
    }
    documented_sources: ClassVar[dict] = {"sequential": {
        "source": "pydantic-ai-harness 0.55.0, guardrails/_capability.py docstrings; "
                  "https://pydantic.dev/docs/ai/harness/guardrails/",
        "read_for": "pydantic-ai-slim 2.55.0, pydantic-ai-harness 0.55.0",
        "passage": "Any exception raised by the guard propagates as-is. parallel=True: the model call is "
                   "cancelled the moment the guard reports a violation; sequential mode never calls the model "
                   "on a blocked prompt, whereas parallel mode has already started it."}}
    documented_sources["parallel"] = documented_sources["sequential"]

    def __init__(self, python: str, workdir: Path, profile: str = "sequential"):
        super().__init__(python, workdir, "sequential" if profile == "default" else profile)

    def config_summary(self) -> dict:
        return {"agent": "pydantic_ai.Agent", "input": f"InputGuardrail(parallel={self.profile == 'parallel'})",
                "output": "OutputGuardrail", "guards": "gcl strict HTTP guard", "tools": ["gcl_probe"],
                "scanner_latency_s": 1.0}

    def versions(self) -> dict:
        return _versions(self.python, ["pydantic-ai-slim", "pydantic-ai-harness", "openai"])

    def start(self, model: MockModel, scanner: StandInScanner) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.port = _free_port()
        path = self.protocol.path
        cmd = [self.python, str(_driver_path("pydantic_ai_driver.py")), "--port", str(self.port),
               "--model-base", model.openai_base, "--tool-url", model.tool_url,
               "--input-guard", f"{scanner.base_for('input')}{path}",
               "--output-guard", f"{scanner.base_for('output')}{path}"]
        if self.profile == "parallel":
            cmd.append("--parallel")
        env = dict(os.environ, NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost")
        with open(self.log, "w") as logf:
            self.proc = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT, env=env,
                                         start_new_session=True, cwd=str(self.workdir))
        _wait_http(f"http://127.0.0.1:{self.port}/health", self.proc, 90, self.log)

    def call(self, messages: list[dict], timeout_s: float) -> Observation:
        return _post(f"http://127.0.0.1:{self.port}/v1/chat/completions",
                     {"model": "gcl-mock", "messages": messages}, None, timeout_s)


# --------------------------------------------------------------------------- LiteLLM vendor hooks
def _fill(obj, text: str, echo: str = ""):
    """Replace MODIFY_TEXT (the rewrite) and ECHO_TEXT (the text the vendor was sent)
    anywhere in a JSON-like value."""
    if isinstance(obj, str):
        return obj.replace("MODIFY_TEXT", text).replace("ECHO_TEXT", echo)
    if isinstance(obj, dict):
        return {k: _fill(v, text, echo) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_fill(v, text, echo) for v in obj]
    return obj


def _dotted(body, path: str):
    """Follow a dotted path ("messages.-1.content", "llmOutput") into a JSON body."""
    cur = body
    for part in path.split("."):
        try:
            cur = cur[int(part)] if isinstance(cur, list) else cur[part]
        except (KeyError, IndexError, ValueError, TypeError):
            return None
    return cur if isinstance(cur, str) else None


def vendor_protocol(spec: dict) -> Protocol:
    """A scanner protocol built from a vendor spec file: the vendor's own allow, block and
    (optionally) rewrite bodies, served on one listener per stage, on the vendor's routes
    only. ECHO_TEXT needs `scanned_path`, the field that carries the checked text."""
    allow, block, modify = spec["allow_response"], spec["block_response"], spec.get("modify_response")
    scanned_path = spec.get("scanned_path")
    if "ECHO_TEXT" in json.dumps([allow, block, modify]) and not scanned_path:
        raise ValueError(f"{spec['vendor']}: ECHO_TEXT needs scanned_path (the field holding the checked text)")
    scanned = (lambda body: _dotted(body, scanned_path)) if scanned_path else None

    def echo(b) -> str:
        return (scanned(b) or "") if scanned else ""

    # Specs may describe a path in prose ("/v1/jobs (server_endpoint + ...)"): keep the
    # leading path token, drop anything that is not a path.
    routes = tuple(str(r["path"]).split()[0] for r in spec.get("requests") or []
                   if str(r.get("path") or "").startswith("/"))
    return Protocol(
        name=f"{spec['vendor']} guardrail API (as called by its integration)",
        verdicts={"allow": lambda b, m: _fill(allow, "", echo(b)),
                  "block": lambda b, m: _fill(block, "", echo(b)),
                  "modify": (lambda b, m: _fill(modify, m, echo(b))) if modify
                  else (lambda b, m: _fill(allow, "", echo(b)))},
        stage_of=lambda body: None, trust_listener=True, routes=routes, scanned=scanned)


class LiteLLMVendor(Adapter):
    """Any LiteLLM vendor guardrail hook, described by a spec file (`--spec`): the
    guardrail type, its parameters, the vendor's request path and its allow/block
    bodies. The hook runs twice — pre_call against the input listener, post_call against
    the output listener — inside the real LiteLLM proxy."""

    name = "litellm-vendor"
    capabilities: ClassVar[set[str]] = {"input", "output"}
    documented: ClassVar[dict] = {"default": dict(_BASE)}
    default_timeout_s = 45.0

    def __init__(self, python: str, workdir: Path, profile: str = "default", spec: dict | None = None):
        super().__init__(python, workdir, profile)
        if spec is None:
            raise ValueError("litellm-vendor needs --spec FILE")
        self.spec = spec
        self.protocol = vendor_protocol(spec)
        self.capabilities = {"input", "output"} | ({"modify_input", "modify_output"} if spec.get("modify_response")
                                                   else set())
        modes = set(spec.get("supported_modes") or ["pre_call", "post_call"])
        if not modes & {"pre_call", "post_call"}:
            raise ValueError(f"{spec['vendor']}: no pre_call or post_call mode — nothing gcl can exercise")
        if "post_call" not in modes:
            self.capabilities -= {"output", "modify_output"}
        if "pre_call" not in modes:
            self.capabilities -= {"input", "modify_input"}
        self.documented = {"default": {**_BASE, **(spec.get("documented") or {})}}
        self.documented_sources = {"default": {"source": f"vendor spec: {spec['vendor']} (from LiteLLM source)",
                                               "read_for": "litellm 1.104.2",
                                               "passage": spec.get("docs_claims") or "no failure behaviour documented"}}
        self.name = f"litellm-{spec['vendor']}"
        self.log = self.workdir / f"{self.name}-{profile}.log"

    def config_summary(self) -> dict:
        return {"guardrail": self.spec["guardrail"], "modes": sorted({"pre_call", "post_call"}
                                                                     & set(self.spec.get("supported_modes") or [])),
                **{k: v for k, v in (self.spec.get("litellm_params") or {}).items() if "key" not in k.lower()}}

    def versions(self) -> dict:
        return _versions(self.python, ["litellm"])

    def start(self, model: MockModel, scanner: StandInScanner) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        base_param = (self.spec.get("api_base_param") or "api_base").split()[0]
        # A spec may write the base URL as http://127.0.0.1:PORT/<suffix>: keep the suffix.
        given = str((self.spec.get("litellm_params") or {}).get(base_param, ""))
        m = re.search(r"127\.0\.0\.1:<?PORT>?(.*)$", given)
        suffix = m.group(1) if m else ""
        modes = set(self.spec.get("supported_modes") or ["pre_call", "post_call"])
        guards = []
        for mode, stage in (("pre_call", "input"), ("post_call", "output")):
            if mode in modes:
                guards.append({"guardrail_name": f"gcl-{stage}", "litellm_params": {
                    **(self.spec.get("litellm_params") or {}), "guardrail": self.spec["guardrail"], "mode": mode,
                    base_param: scanner.base_for(stage) + suffix, "default_on": True}})
        cfg = {"model_list": [{"model_name": "gcl-model",
                               "litellm_params": {"model": f"openai/{model.model}", "api_base": model.openai_base,
                                                  "api_key": "sk-gcl"}}],
               "guardrails": guards, "general_settings": {"master_key": LiteLLMProxy.master_key}}
        self._cfg_path = self.workdir / f"{self.name}.yaml"
        self._cfg_path.write_text(json.dumps(cfg, indent=2))
        self.port = _free_port()
        env = {**os.environ, "LITELLM_LOCAL_MODEL_COST_MAP": "True", "NO_PROXY": "127.0.0.1,localhost",
               "no_proxy": "127.0.0.1,localhost",
               **{k: str(v) for k, v in (self.spec.get("env") or {}).items() if not str(v).startswith("(")}}
        exe = str(Path(self.python).with_name("litellm"))
        with open(self.log, "w") as logf:
            self.proc = subprocess.Popen([exe, "--config", str(self._cfg_path), "--host", "127.0.0.1",
                                          "--port", str(self.port)], stdout=logf, stderr=subprocess.STDOUT,
                                         env=env, start_new_session=True)
        _wait_http(f"http://127.0.0.1:{self.port}/health/liveliness", self.proc, 120, self.log)

    def config_files(self) -> dict:
        p = getattr(self, "_cfg_path", None)
        return {p.name: p.read_text()} if p and p.exists() else {}

    def call(self, messages: list[dict], timeout_s: float) -> Observation:
        return _post(f"http://127.0.0.1:{self.port}/v1/chat/completions",
                     {"model": "gcl-model", "messages": messages},
                     {"Authorization": f"Bearer {LiteLLMProxy.master_key}"}, timeout_s)


# --------------------------------------------------------------------------- NeMo vendor rails
def _replace_url(obj, url: str):
    if isinstance(obj, str):
        return obj.replace("STANDIN_URL", url)
    if isinstance(obj, dict):
        return {k: _replace_url(v, url) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_replace_url(v, url) for v in obj]
    return obj


class NemoVendor(NemoServer):
    """Any NeMo Guardrails vendor rail, described by a spec file (`--spec`): the input /
    output flow names, its rails.config block and env, the vendor path and its allow /
    block bodies. NeMo configures one endpoint per vendor, so both stages share one
    listener and are told apart by the text they carry."""

    name = "nemo-vendor"
    documented: ClassVar[dict] = {"default": dict(_BASE)}
    known_issues: ClassVar[dict] = {}

    def __init__(self, python: str, workdir: Path, profile: str = "default", spec: dict | None = None):
        super().__init__(python, workdir, profile)
        if spec is None:
            raise ValueError("nemo-vendor needs --spec FILE")
        self.spec = spec
        proto = vendor_protocol(spec)
        proto.trust_listener, proto.single_listener = False, True
        proto.stage_of = _stage_by_sentinel
        self.protocol = proto
        self.capabilities = ({"input"} if spec.get("input_flow") else set()) | (
            {"output"} if spec.get("output_flow") else set())
        if not self.capabilities:
            raise ValueError(f"{spec['vendor']}: no input_flow or output_flow — nothing gcl can exercise")
        self.documented = {"default": {**_BASE, **(spec.get("documented") or {})}}
        self.documented_sources = {"default": {"source": f"vendor spec: {spec['vendor']} (from NeMo source)",
                                               "read_for": "nemoguardrails 0.24.1",
                                               "passage": spec.get("docs_claims") or "no failure behaviour documented"}}
        self.name = f"nemo-{spec['vendor']}"
        self.log = self.workdir / f"{self.name}-{profile}.log"

    def config_summary(self) -> dict:
        return {"input_flow": self.spec.get("input_flow"), "output_flow": self.spec.get("output_flow")}

    def start(self, model: MockModel, scanner: StandInScanner) -> None:
        cfgdir = self.workdir / "nemo-configs" / "gcl"
        cfgdir.mkdir(parents=True, exist_ok=True)
        url = scanner.base_for("input")
        rails: dict = {"config": _replace_url(self.spec.get("rails_config") or {}, url)}
        if self.spec.get("input_flow"):
            rails["input"] = {"flows": [self.spec["input_flow"]]}
        if self.spec.get("output_flow"):
            rails["output"] = {"flows": [self.spec["output_flow"]]}
        cfg = {"models": [{"type": "main", "engine": "openai", "model": model.model,
                           "parameters": {"base_url": model.openai_base, "api_key": "sk-gcl"}}], "rails": rails}
        (cfgdir / "config.yml").write_text(json.dumps(cfg, indent=2))
        # Some vendor flows refuse with bot messages they do not define themselves.
        (cfgdir / "rails.co").write_text(
            'define bot refuse to respond\n  "I\'m sorry, I can\'t respond to that."\n\n'
            'define bot inform answer unknown\n  "I don\'t know the answer to that."\n')
        self._cfg_path = cfgdir / "config.yml"
        self._extra_env = {k: str(v).replace("STANDIN_URL", url) for k, v in (self.spec.get("env") or {}).items()}
        self._launch(cfgdir)


# --------------------------------------------------------------------------- CrewAI
CREWAI_JUDGE = judge_protocol(
    "CrewAI LLMGuardrail (structured LLMGuardrailResult)",
    allow={"valid": True, "feedback": None},
    block={"valid": False, "feedback": "GCL-BLOCKED by the stand-in"})


class CrewAITask(Adapter):
    """A CrewAI crew: one agent with the probe tool, one task whose guardrail is
    `LLMGuardrail` judged by the stand-in (model name `gcl-judge-output`). CrewAI checks
    task output only. A failed or negative check re-runs the task, up to
    `guardrail_max_retries` (3), then raises."""

    name = "crewai"
    protocol = CREWAI_JUDGE
    capabilities: ClassVar[set[str]] = {"output", "tools"}
    # LLMGuardrail.__call__ docstring: returns (False, error message) when validation
    # raises; Task: "Maximum number of retries when guardrail fails" then an exception.
    documented: ClassVar[dict] = {"default": {**_BASE, **{f: "stopped" for f in
                                                          ("error", "timeout", "malformed", "empty")}}}
    documented_sources: ClassVar[dict] = {"default": {
        "source": "crewai 1.15.27: crewai/tasks/llm_guardrail.py and crewai/task.py",
        "read_for": "crewai 1.15.27",
        "passage": "LLMGuardrail returns (False, 'Error while validating the task output: ...') when the check "
                   "fails; the task retries up to guardrail_max_retries and then raises."}}

    def config_summary(self) -> dict:
        return {"crew": "1 agent, 1 task", "guardrail": "LLMGuardrail(llm=gcl-judge-output)",
                "guardrail_max_retries": 3, "tools": ["gcl_probe"]}

    def versions(self) -> dict:
        return _versions(self.python, ["crewai", "litellm", "openai"])

    def start(self, model: MockModel, scanner: StandInScanner) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.port = _free_port()
        cmd = [self.python, str(_driver_path("crewai_driver.py")), "--port", str(self.port),
               "--model-base", model.openai_base, "--tool-url", model.tool_url]
        env = dict(os.environ, NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost",
                   OPENAI_API_KEY="sk-gcl", CREWAI_DISABLE_TELEMETRY="true", OTEL_SDK_DISABLED="true")
        with open(self.log, "w") as logf:
            self.proc = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT, env=env,
                                         start_new_session=True, cwd=str(self.workdir))
        _wait_http(f"http://127.0.0.1:{self.port}/health", self.proc, 120, self.log)

    def call(self, messages: list[dict], timeout_s: float) -> Observation:
        return _post(f"http://127.0.0.1:{self.port}/v1/chat/completions",
                     {"model": "gcl-mock", "messages": messages}, None, timeout_s)


# --------------------------------------------------------------------------- Guardrails AI
class GuardrailsAI(Adapter):
    """Guardrails AI's `Guard` calling the model through its LiteLLM integration, with
    gcl's strictest validator. Profile `python`: `Guard().use(...)` on the messages and the
    output (default on_fail). Profile `rail`: the same validator declared in a RAIL spec on
    the output without an on-fail attribute."""

    name = "guardrails-ai"
    protocol = LITELLM_GENERIC
    capabilities: ClassVar[set[str]] = {"input", "output"}
    _F = ("error", "timeout", "malformed", "empty", "wrong_schema", "unknown_verdict", "verdict_type", "refused")
    # Validator default (validator_base.py): on_fail=None → OnFailAction.EXCEPTION. RAIL
    # (schema/rail_schema.py): a validator without on-fail-* gets OnFailAction.NOOP.
    documented: ClassVar[dict] = {
        "python": {**_BASE, **{f: "stopped" for f in _F}},
        "rail": {**_BASE, ("output", "block"): "passed", **{f: "stopped" for f in _F}},
    }
    documented_sources: ClassVar[dict] = {"python": {
        "source": "guardrails-ai 0.11.0: guardrails/validator_base.py (Validator.__init__), "
                  "guardrails/schema/rail_schema.py",
        "read_for": "guardrails-ai 0.11.0",
        "passage": "Validator(on_fail=None) uses OnFailAction.EXCEPTION. In a RAIL spec a validator with no "
                   "on-fail-* attribute gets OnFailAction.NOOP (log only, value unchanged)."}}
    documented_sources["rail"] = documented_sources["python"]

    def __init__(self, python: str, workdir: Path, profile: str = "python"):
        super().__init__(python, workdir, "python" if profile == "default" else profile)
        if self.profile == "rail":
            self.capabilities = {"output"}

    def config_summary(self) -> dict:
        return {"guard": "Guard.for_rail_string (output validator, no on-fail)" if self.profile == "rail"
                else "Guard().use(check, on='messages').use(check)", "validator": "gcl strict HTTP check"}

    def versions(self) -> dict:
        return _versions(self.python, ["guardrails-ai", "litellm"])

    def start(self, model: MockModel, scanner: StandInScanner) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.port = _free_port()
        path = self.protocol.path
        cmd = [self.python, str(_driver_path("guardrails_ai_driver.py")), "--port", str(self.port),
               "--model-base", model.openai_base, "--input-guard", f"{scanner.base_for('input')}{path}",
               "--output-guard", f"{scanner.base_for('output')}{path}", "--style", self.profile]
        env = dict(os.environ, NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost",
                   OPENAI_API_KEY="sk-gcl", GUARDRAILS_RUN_SYNC="true", LITELLM_LOCAL_MODEL_COST_MAP="True",
                   OTEL_SDK_DISABLED="true")
        with open(self.log, "w") as logf:
            self.proc = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT, env=env,
                                         start_new_session=True, cwd=str(self.workdir))
        _wait_http(f"http://127.0.0.1:{self.port}/health", self.proc, 120, self.log)

    def call(self, messages: list[dict], timeout_s: float) -> Observation:
        return _post(f"http://127.0.0.1:{self.port}/v1/chat/completions",
                     {"model": "gcl-mock", "messages": messages}, None, timeout_s)


# --------------------------------------------------------------------------- MCP: Invariant gateway
_INV_POLICY = 'raise "gcl" if:\n    (msg: Message)\n    "GCL" in msg.content'

def _invariant_block(body: dict) -> dict:
    """Like the real analyzer: one error per checked message that matches (here: carries
    a gcl marker), located at that message. The gateway blocks only on errors that yield
    a new annotation, so the location must point at what is being checked now."""
    msgs = body.get("messages") or []
    errors = [{"args": ["GCL-BLOCKED by the stand-in"], "kwargs": {}, "ranges": [f"messages.{i}"]}
              for i, m in enumerate(msgs) if "GCL-" in json.dumps(m, ensure_ascii=False)]
    return {"result": [{"errors": errors or [{"args": ["GCL-BLOCKED by the stand-in"], "kwargs": {},
                                              "ranges": ["messages.0"]}]}]}


INVARIANT_CHECK = Protocol(
    name="Invariant guardrails API (POST /api/v1/policy/check/batch) and Explorer policy source",
    verdicts={"allow": lambda b, m: {"result": [{"errors": []}]},
              "block": lambda b, m: _invariant_block(b),
              "modify": lambda b, m: {"result": [{"errors": []}]}},
    stage_of=_stage_by_sentinel, routes=("/api/v1/policy/check/batch",), single_listener=True,
    wrong_schema={"status": "ok"},
    static_posts={"/api/v1/push/trace": {"id": ["gcl-trace"]}, "/api/v1/trace/<id>/messages": {},
                  "/api/v1/policy/load": {}},
    get_routes={"/api/v1/user/identity": {"username": "gcl"},
                "/api/v1/dataset/byuser/<user>/<dataset>/policy": {"policies": [
                    {"id": "gcl-1", "name": "gcl", "content": _INV_POLICY, "action": "block", "enabled": True}]}},
)


def _mcp_post(url: str, msg: dict, headers: dict, timeout_s: float) -> tuple[int, dict, str]:
    req = urllib.request.Request(url, data=json.dumps(msg, ensure_ascii=False).encode(),
                                 headers={"Content-Type": "application/json",
                                          "Accept": "application/json, text/event-stream", **headers})
    try:
        with urllib.request.urlopen(req, timeout=max(0.1, timeout_s)) as r:
            return r.status, dict(r.headers.items()), r.read(_MAX_BODY).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers.items()), e.read(_MAX_BODY).decode("utf-8", "replace")


class InvariantMCP(Adapter):
    """Invariant Gateway's MCP proxy (streamable HTTP) in front of gcl's mock MCP server.
    The gateway pulls its blocking guardrails from the Explorer API and checks every
    tools/call and its result with the Guardrails API — both served by the stand-in. The
    client is an MCP client: initialize, initialized, then tools/call `gcl_probe` with the
    scenario's text; the tool's result is the scenario's reply."""

    name = "invariant-mcp"
    protocol = INVARIANT_CHECK
    capabilities: ClassVar[set[str]] = {"input", "output", "retry"}
    model_host = "::1"  # the gateway rewrites localhost/127.0.0.1 to host.docker.internal
    default_timeout_s = 20.0
    # Gateway docs: "In case any of the checks fail, Gateway will return an HTTP error
    # response instead of the LLM response." Nothing on the Guardrails or Explorer API
    # being unreachable or answering something unexpected.
    documented: ClassVar[dict] = {"default": dict(_BASE), "push": dict(_BASE)}
    documented_sources: ClassVar[dict] = {"default": {
        "source": "invariant-gateway 0.0.9 README / explorer.invariantlabs.ai docs (now redirecting)",
        "read_for": "invariant-gateway 0.0.9",
        "passage": "In case any of the checks fail, Gateway will return an HTTP error response instead of the "
                   "LLM response. Failure of the guardrails service is not described."}}
    documented_sources["push"] = documented_sources["default"]

    def config_summary(self) -> dict:
        return {"gateway": "gateway.serve:app (uvicorn)", "transport": "MCP streamable HTTP",
                "guardrails": "1 blocking policy from the Explorer stand-in", "tool": "gcl_probe",
                "push_to_explorer": self.profile == "push"}

    def versions(self) -> dict:
        return _versions(self.python, ["invariant-gateway", "httpx", "fastapi"])

    def start(self, model: MockModel, scanner: StandInScanner) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.port = _free_port()
        self._mcp_base = model.base
        url = scanner.base_for("input")
        env = dict(os.environ, GUARDRAILS_API_URL=url, INVARIANT_API_URL=url,
                   NO_PROXY="127.0.0.1,localhost,::1", no_proxy="127.0.0.1,localhost,::1")
        with open(self.log, "w") as logf:
            self.proc = subprocess.Popen([self.python, "-m", "uvicorn", "gateway.serve:app", "--host", "127.0.0.1",
                                          "--port", str(self.port)], stdout=logf, stderr=subprocess.STDOUT,
                                         env=env, start_new_session=True, cwd=str(self.workdir))
        _wait_http(f"http://127.0.0.1:{self.port}/api/v1/gateway/health", self.proc, 90, self.log)

    def call(self, messages: list[dict], timeout_s: float, repeat: int = 1) -> Observation:
        """One MCP session under one absolute deadline. With repeat=2 the same tools/call
        is sent twice in it (a client or agent retrying); every attempt is kept on the
        returned observation as `attempts`, and the last one is the observation."""
        url = f"http://127.0.0.1:{self.port}/api/v1/gateway/mcp/streamable"
        h = {"mcp-server-base-url": self._mcp_base, "INVARIANT-PROJECT-NAME": "gcl",
             "INVARIANT-API-KEY": "inv-gcl", "PUSH-INVARIANT-EXPLORER": "true" if self.profile == "push" else "false"}
        t0 = time.perf_counter()
        deadline = t0 + timeout_s

        def left() -> float:
            return deadline - time.perf_counter()

        try:
            code, hdrs, _ = _mcp_post(url, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "gcl", "version": "1"}}},
                h, left())
            sid = next((v for k, v in hdrs.items() if k.lower() == "mcp-session-id"), None)
            if code >= 400 or not sid:
                return Observation(code, "", True, time.perf_counter() - t0, f"initialize failed ({code})")
            h = {**h, "mcp-session-id": sid}
            _mcp_post(url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, h, left())
        except OSError as e:
            done = left() <= 0
            return Observation(None, "", False, time.perf_counter() - t0,
                               "client deadline reached" if done else f"transport failure: {e}", transport=not done)
        text = messages[-1]["content"]
        attempts: list[Observation] = []
        for k in range(repeat):
            if left() <= 0:
                attempts.append(Observation(None, "", False, time.perf_counter() - t0, "client deadline reached"))
                break
            attempts.append(_post(url, {"jsonrpc": "2.0", "id": 2 + k, "method": "tools/call",
                                        "params": {"name": "gcl_probe", "arguments": {"note": text}}},
                                  {**h, "Accept": "application/json, text/event-stream"}, left()))
        last = attempts[-1]
        obs = Observation(last.status, last.text, last.finished, time.perf_counter() - t0, last.error, last.transport)
        obs.attempts = attempts  # type: ignore[attr-defined]
        return obs


# --------------------------------------------------------------------------- Agno
class AgnoAgent(Adapter):
    """An Agno agent with the built-in `OpenAIModerationGuardrail` as a pre-hook (input
    only); the guardrail's OpenAI client is pointed at the stand-in via OPENAI_BASE_URL."""

    name = "agno"
    protocol = OPENAI_MODERATION
    capabilities: ClassVar[set[str]] = {"input"}
    # Agno's guardrail docs describe raising InputCheckError on a violation; nothing on a
    # failed moderation call.
    documented: ClassVar[dict] = {"default": dict(_BASE)}
    documented_sources: ClassVar[dict] = {"default": {
        "source": "agno 3.1.2: agno/guardrails/openai.py, agno/agent/_hooks.py; https://docs.agno.com (guardrails)",
        "read_for": "agno 3.1.2",
        "passage": "OpenAIModerationGuardrail raises InputCheckError when content is flagged. Failure of the "
                   "moderation call is not described."}}

    def config_summary(self) -> dict:
        return {"agent": "agno.agent.Agent(model=OpenAIChat)", "pre_hooks": ["OpenAIModerationGuardrail()"],
                "call": "agent.run"}

    def versions(self) -> dict:
        return _versions(self.python, ["agno", "openai"])

    def start(self, model: MockModel, scanner: StandInScanner) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.port = _free_port()
        env = dict(os.environ, NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost",
                   OPENAI_API_KEY="sk-gcl", OPENAI_BASE_URL=f"{scanner.base_for('input')}/v1",
                   AGNO_TELEMETRY="false")
        with open(self.log, "w") as logf:
            self.proc = subprocess.Popen([self.python, str(_driver_path("agno_driver.py")), "--port", str(self.port),
                                          "--model-base", model.openai_base], stdout=logf, stderr=subprocess.STDOUT,
                                         env=env, start_new_session=True, cwd=str(self.workdir))
        _wait_http(f"http://127.0.0.1:{self.port}/health", self.proc, 90, self.log)

    def call(self, messages: list[dict], timeout_s: float) -> Observation:
        return _post(f"http://127.0.0.1:{self.port}/v1/chat/completions",
                     {"model": "gcl-mock", "messages": messages}, None, timeout_s)


# --------------------------------------------------------------------------- openai-guardrails JS
class OpenAIGuardrailsJS(OpenAIGuardrails):
    """openai-guardrails for JavaScript (`@openai/guardrails`) — a separate code base from
    the Python package — with the same checks and profiles, run under Node."""

    name = "openai-guardrails-js"
    runtime = "node"
    _src_js = "@openai/guardrails 0.3.0: dist/client.js (GuardrailsOpenAI.create) and README"
    documented_sources: ClassVar[dict] = {"default": {
        "source": _src_js, "read_for": "@openai/guardrails 0.3.0",
        "passage": "raiseGuardrailErrors: If true, raise exceptions when guardrails fail to execute (default "
                   "false). Stages: preflight, input (may run concurrently with the LLM call), output."}}
    documented_sources["raise_errors"] = documented_sources["pre_flight"] = documented_sources["default"]

    def versions(self) -> dict:
        try:
            v = json.loads((Path(self.python) / "node_modules/@openai/guardrails/package.json").read_text())["version"]
        except (OSError, ValueError, KeyError):
            v = None
        node = subprocess.run(["node", "--version"], capture_output=True, text=True).stdout.strip()
        return {"@openai/guardrails": v, "node": node}

    def start(self, model: MockModel, scanner: StandInScanner) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        jm = self.protocol.judge_model
        cfg = {"version": 1,
               ("pre_flight" if self.profile == "pre_flight" else "input"):
                   {"version": 1, "guardrails": [{"name": "Jailbreak", "config": {
                       "model": f"{jm}-input", "confidence_threshold": 0.7}}]},
               "output": {"version": 1, "guardrails": [{"name": "Custom Prompt Check", "config": {
                   "model": f"{jm}-output", "confidence_threshold": 0.7,
                   "system_prompt_details": "Flag replies that disclose confidential data."}}]}}
        self._cfg_path = self.workdir / "openai-guardrails-js.json"
        self._cfg_path.write_text(json.dumps(cfg, indent=2))
        self.port = _free_port()
        cmd = ["node", str(_driver_path("openai_guardrails_js_driver.cjs")), "--env", str(Path(self.python).resolve()),
               "--port", str(self.port), "--base-url", model.openai_base, "--config", str(self._cfg_path),
               "--timeout", "8000"]
        if self.profile != "default":
            cmd.append("--raise-guardrail-errors")
        env = dict(os.environ, NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost", OPENAI_API_KEY="sk-gcl")
        with open(self.log, "w") as logf:
            self.proc = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT, env=env,
                                         start_new_session=True, cwd=str(self.workdir))
        _wait_http(f"http://127.0.0.1:{self.port}/health", self.proc, 60, self.log)


# --------------------------------------------------------------------------- Google ADK
class GoogleADK(PydanticAI):
    """A Google ADK `LlmAgent` (LiteLlm model) with gcl's strictest guard as
    `before_model_callback` and `after_model_callback`, plus the probe tool. ADK ships no
    guard: the run tests ADK's enforcement of callbacks."""

    name = "google-adk"
    scanner_latency_s = 0.0
    _F = ("error", "timeout", "malformed", "empty", "wrong_schema", "unknown_verdict", "verdict_type", "refused")
    documented: ClassVar[dict] = {"default": {**_BASE, **{f: "stopped" for f in _F}}}
    documented_sources: ClassVar[dict] = {"default": {
        "source": "google-adk 2.11.0: callbacks docs (before_model_callback / after_model_callback) and "
                  "plugins/plugin_manager.py",
        "read_for": "google-adk 2.11.0",
        "passage": "Returning an LlmResponse from before_model_callback skips the model call; from "
                   "after_model_callback it replaces the response. An exception raised in a callback "
                   "propagates."}}

    def __init__(self, python: str, workdir: Path, profile: str = "default"):
        Adapter.__init__(self, python, workdir, profile)

    def config_summary(self) -> dict:
        return {"agent": "google.adk LlmAgent(model=LiteLlm)", "callbacks": ["before_model", "after_model"],
                "guard": "gcl strict HTTP guard", "tools": ["gcl_probe"]}

    def versions(self) -> dict:
        return _versions(self.python, ["google-adk", "litellm"])

    def start(self, model: MockModel, scanner: StandInScanner) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.port = _free_port()
        path = self.protocol.path
        cmd = [self.python, str(_driver_path("google_adk_driver.py")), "--port", str(self.port),
               "--model-base", model.openai_base, "--tool-url", model.tool_url,
               "--input-guard", f"{scanner.base_for('input')}{path}",
               "--output-guard", f"{scanner.base_for('output')}{path}"]
        env = dict(os.environ, NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost",
                   LITELLM_LOCAL_MODEL_COST_MAP="True", OPENAI_API_KEY="sk-gcl")
        with open(self.log, "w") as logf:
            self.proc = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT, env=env,
                                         start_new_session=True, cwd=str(self.workdir))
        _wait_http(f"http://127.0.0.1:{self.port}/health", self.proc, 120, self.log)


# --------------------------------------------------------------------------- MCP: Lasso mcp-gateway
LASSO_CLASSIFY = Protocol(
    name="Lasso guardrail API v3 (POST /gateway/v3/classify), as called by mcp-gateway",
    verdicts={"allow": lambda b, m: {"violations_detected": False, "deputies": {"jailbreak": False}},
              "block": lambda b, m: {"violations_detected": True, "deputies": {"jailbreak": True}},
              "modify": lambda b, m: {"violations_detected": False, "deputies": {"jailbreak": False}}},
    stage_of=lambda body: {"PROMPT": "input", "COMPLETION": "output"}.get(body.get("messageType")),
    routes=("/gateway/v3/classify",), single_listener=True,
)


class LassoMCPGateway(Adapter):
    """Lasso's mcp-gateway (stdio MCP proxy) with its `lasso` guardrail plugin, in front of
    a stdio mock MCP server. The plugin manager loads plugins with an empty config, so the
    plugin's API URL is set by a launcher that changes only that default."""

    name = "lasso-mcp-gateway"
    protocol = LASSO_CLASSIFY
    capabilities: ClassVar[set[str]] = {"input", "output"}
    default_timeout_s = 30.0
    # Plugin docstrings: process_request "Blocks the request by returning None if violations
    # are found"; the code comments say unexpected errors "let the request through (fail
    # open)". A missing API key skips the check with a warning.
    documented: ClassVar[dict] = {"default": dict(_BASE),
                                  "no_key": {**_BASE, "block": "passed"}}
    documented_sources: ClassVar[dict] = {"default": {
        "source": "mcp-gateway 1.2.1: mcp_gateway/plugins/guardrails/lasso.py (docstrings and comments)",
        "read_for": "mcp-gateway 1.2.1",
        "passage": "Blocks the request by returning None if violations are found. On unexpected errors, let "
                   "the request through (fail open). Lasso API key not configured, skipping guardrail check."}}
    documented_sources["no_key"] = documented_sources["default"]

    def config_summary(self) -> dict:
        return {"gateway": "mcp-gateway -p lasso (stdio)", "upstream": "stdio mock MCP server",
                "lasso_api_key": self.profile != "no_key", "change": "plugin api_base default only"}

    def versions(self) -> dict:
        return _versions(self.python, ["mcp-gateway", "mcp"])

    def start(self, model: MockModel, scanner: StandInScanner) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        upstream = {"command": self.python, "args": [str(_driver_path("stdio_mcp_server.py")), "--mock", model.base]}
        cfg = {"mcpServers": {"mcp-gateway": {"command": "mcp-gateway", "args": [], "servers": {"gcl": upstream}}}}
        self._cfg_path = self.workdir / "mcp.json"
        self._cfg_path.write_text(json.dumps(cfg, indent=2))
        self.port = _free_port()
        env = dict(os.environ, NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost",
                   GCL_LASSO_URL=f"{scanner.base_for('input')}/gateway/v3/classify")
        if self.profile == "no_key":
            env.pop("LASSO_API_KEY", None)
        else:
            env["LASSO_API_KEY"] = "lasso-gcl"
        with open(self.log, "w") as logf:
            self.proc = subprocess.Popen([self.python, str(_driver_path("lasso_mcp_driver.py")),
                                          "--port", str(self.port), "--config", str(self._cfg_path),
                                          "--python", self.python],
                                         stdout=logf, stderr=subprocess.STDOUT, env=env, start_new_session=True,
                                         cwd=str(self.workdir))
        _wait_http(f"http://127.0.0.1:{self.port}/health", self.proc, 60, self.log)

    def config_files(self) -> dict:
        p = getattr(self, "_cfg_path", None)
        return {p.name: p.read_text()} if p and p.exists() else {}

    def call(self, messages: list[dict], timeout_s: float) -> Observation:
        return _post(f"http://127.0.0.1:{self.port}/v1/chat/completions",
                     {"model": "gcl-mock", "messages": messages}, None, timeout_s)


# --------------------------------------------------------------------------- OpenAI Agents SDK (JS)
class OpenAIAgentsJS(OpenAIAgents):
    """The OpenAI Agents SDK for JavaScript with openai-guardrails JS `GuardrailAgent`: the
    same pre_flight Jailbreak + output check, probe tool and 1 s judge as the Python
    adapter, run under Node."""

    name = "openai-agents-js"
    runtime = "node"
    documented_sources: ClassVar[dict] = {"default": {
        "source": "@openai/guardrails 0.3.0 dist/agents.js (GuardrailAgent) and README; @openai/agents 0.20.0",
        "read_for": "@openai/guardrails 0.3.0, @openai/agents 0.20.0",
        "passage": "pre_flight: checks that run before the LLM request is issued (GuardrailAgent passes "
                   "runInParallel: false for pre_flight). raiseGuardrailErrors: if false (default), guardrail "
                   "execution errors are treated as safe."}}
    documented_sources["raise_errors"] = documented_sources["default"]

    def versions(self) -> dict:
        out = {}
        for pkg in ("@openai/agents", "@openai/guardrails"):
            try:
                pj = Path(self.python) / "node_modules" / pkg / "package.json"
                out[pkg] = json.loads(pj.read_text())["version"]
            except (OSError, ValueError, KeyError):
                out[pkg] = None
        out["node"] = subprocess.run(["node", "--version"], capture_output=True, text=True).stdout.strip()
        return out

    def start(self, model: MockModel, scanner: StandInScanner) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        jm = self.protocol.judge_model
        cfg = {"version": 1,
               "pre_flight": {"version": 1, "guardrails": [{"name": "Jailbreak", "config": {
                   "model": f"{jm}-input", "confidence_threshold": 0.7}}]},
               "output": {"version": 1, "guardrails": [{"name": "Custom Prompt Check", "config": {
                   "model": f"{jm}-output", "confidence_threshold": 0.7,
                   "system_prompt_details": "Flag replies that disclose confidential data."}}]}}
        self._cfg_path = self.workdir / "openai-guardrails-js.json"
        self._cfg_path.write_text(json.dumps(cfg, indent=2))
        self.port = _free_port()
        cmd = ["node", str(_driver_path("openai_agents_js_driver.cjs")), "--env", str(Path(self.python).resolve()),
               "--port", str(self.port), "--model-base", model.openai_base, "--tool-url", model.tool_url,
               "--config", str(self._cfg_path)]
        if self.profile == "raise_errors":
            cmd.append("--raise-guardrail-errors")
        env = dict(os.environ, NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost",
                   OPENAI_API_KEY="sk-gcl", OPENAI_BASE_URL=model.openai_base)
        with open(self.log, "w") as logf:
            self.proc = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT, env=env,
                                         start_new_session=True, cwd=str(self.workdir))
        _wait_http(f"http://127.0.0.1:{self.port}/health", self.proc, 60, self.log)


# --------------------------------------------------------------------------- Semantic Kernel
class SemanticKernel(GoogleADK):
    """Microsoft Semantic Kernel with gcl's strictest guard in a PROMPT_RENDERING filter
    (input) and a FUNCTION_INVOCATION filter (output), plus the probe plugin with
    automatic function calling. SK ships no guard: the run tests SK's enforcement."""

    name = "semantic-kernel"
    documented_sources: ClassVar[dict] = {"default": {
        "source": "semantic-kernel 1.45.0: filters (prompt render filter function_result override, function "
                  "invocation filter result override)",
        "read_for": "semantic-kernel 1.45.0",
        "passage": "Setting function_result in a prompt render filter skips the AI service call; a function "
                   "invocation filter may replace context.result. Exceptions in filters propagate."}}

    def config_summary(self) -> dict:
        return {"kernel": "semantic_kernel.Kernel + OpenAIChatCompletion", "filters": ["prompt_rendering",
                "function_invocation"], "guard": "gcl strict HTTP guard", "tools": ["probe.gcl_probe (auto)"]}

    def versions(self) -> dict:
        return _versions(self.python, ["semantic-kernel", "openai"])

    def start(self, model: MockModel, scanner: StandInScanner) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.port = _free_port()
        path = self.protocol.path
        cmd = [self.python, str(_driver_path("semantic_kernel_driver.py")), "--port", str(self.port),
               "--model-base", model.openai_base, "--tool-url", model.tool_url,
               "--input-guard", f"{scanner.base_for('input')}{path}",
               "--output-guard", f"{scanner.base_for('output')}{path}"]
        env = dict(os.environ, NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost", OPENAI_API_KEY="sk-gcl")
        with open(self.log, "w") as logf:
            self.proc = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT, env=env,
                                         start_new_session=True, cwd=str(self.workdir))
        _wait_http(f"http://127.0.0.1:{self.port}/health", self.proc, 120, self.log)


ADAPTERS = {"litellm": LiteLLMProxy, "nemo": NemoServer, "openai-guardrails": OpenAIGuardrails,
            "nemo-selfcheck": NemoSelfCheck, "portkey": PortkeyGateway,
            "langchain-moderation": LangChainModeration, "mastra": MastraAgent, "openai-agents": OpenAIAgents,
            "pydantic-ai": PydanticAI, "litellm-vendor": LiteLLMVendor,
            "nemo-vendor": NemoVendor, "crewai": CrewAITask,
            "guardrails-ai": GuardrailsAI, "invariant-mcp": InvariantMCP,
            "agno": AgnoAgent, "openai-guardrails-js": OpenAIGuardrailsJS,
            "google-adk": GoogleADK, "lasso-mcp-gateway": LassoMCPGateway,
            "openai-agents-js": OpenAIAgentsJS, "semantic-kernel": SemanticKernel, "reference": ReferenceGateway}
