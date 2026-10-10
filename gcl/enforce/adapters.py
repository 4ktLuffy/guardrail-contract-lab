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
        "block": lambda body, m: {"action": "BLOCKED", "blocked_reason": "gcl stand-in: blocked"},
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
        env = dict(os.environ, OPENAI_API_KEY="sk-gcl", DEFAULT_CONFIG_ID="gcl",
                   NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost")
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
    across stages: output if the body carries a reply marker and no user marker, input
    for the reverse, None (rejected, never counted) when it carries both or neither."""
    text = json.dumps(body, ensure_ascii=False)
    u, r = "GCL-U-" in text, "GCL-R-" in text
    return "output" if r and not u else "input" if u and not r else None


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
    block={"flagged": True, "confidence": 0.99, "reason": "gcl stand-in: block"})


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
        "default": {**_BASE, ("input", "block"): "blocked after send",
                    **{f: "passed" for f in _ERR}},
        "raise_errors": {**_BASE, ("input", "block"): "blocked after send",
                         **{("input", f): "blocked after send" for f in _ERR},
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
                    "reason": "gcl stand-in" if flagged else None}
        return {"categories": [{"type": "injection", "score": 0.95}] if flagged else [],  # PromptInjectionDetector
                "reason": "gcl stand-in" if flagged else None}
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


ADAPTERS = {"litellm": LiteLLMProxy, "nemo": NemoServer, "openai-guardrails": OpenAIGuardrails,
            "nemo-selfcheck": NemoSelfCheck, "portkey": PortkeyGateway,
            "langchain-moderation": LangChainModeration, "mastra": MastraAgent, "openai-agents": OpenAIAgents,
            "reference": ReferenceGateway}
