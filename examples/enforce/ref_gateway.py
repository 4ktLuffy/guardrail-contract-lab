"""A tiny reference LLM gateway with a guardrail, for `gcl enforce` (standard library only).

It speaks the same scanner protocol as LiteLLM's generic guardrail API: before the model
call it POSTs {"texts": [...], "input_type": "request"} to the scanner, after it
{"texts": [...], "input_type": "response"}; the scanner answers {"action": "NONE" |
"BLOCKED" | "GUARDRAIL_INTERVENED", "texts": [...]}.

Its documented contract: fail closed — any scanner error, timeout, unparseable or
unrecognised verdict stops the request. `--policy strict` keeps that promise.
`--policy naive` breaks it the way real integrations do: errors and unknown verdicts
are treated as "allow". Use it to see `gcl enforce` catch the difference.

    python ref_gateway.py --scanner URL [--scanner-output URL] --model URL --port N \
        --policy strict|naive
    python ref_gateway.py --policy-file PATH [--scanner-output URL] --model URL --port N \
        --policy strict|naive

With `--policy-file` the guards come from a policy file instead of one `--scanner` URL
(`gcl enforce reference --extra config` tests this part):

    {"guards": [{"name": "g1", "type": "http", "scanner": "http://127.0.0.1:9/x", "scope": "*"}]}

Its documented contract, "the configured policy is the one that runs":
  - the input (pre-model) guards are the policy's guards whose `scope` is "*" or equals the
    request body's `model`; a request must pass every matching guard (a scoped guard never
    applies to another model). The output stage still uses --scanner-output, if given;
  - the file is re-read whenever its modification time changes, checked on every request, so
    an edit takes effect on the next request, without a restart;
  - a policy file that is missing, cannot be parsed, or has a structure it does not know (no
    `guards` list, a guard without a string `scanner` or `scope`, a guard `type` other than
    "http") makes the gateway refuse to start (exit code 2, the reason on stderr); if the file
    becomes broken while running, every request is refused (fail closed, 503) until it is fixed.
So, for a client: a policy that cannot load is refused at start or every request is stopped; a
guard added or pointed at a blocking scanner by an edit stops the next request; one pointed at an
allowing scanner lets the next request pass; a scoped guard stops requests to its scope and
never touches the other scope.
`--policy strict` keeps that contract. `--policy naive` breaks it the way real issues do: a
missing or malformed file starts the gateway with no guards (everything allowed); the file is
read once at startup, so edits are ignored (LiteLLM #40201); a scoped guard (scope other than
"*") never matches anything (LiteLLM #41680: a scoped attachment matched nothing); a guard of an
unknown type is skipped.

Routes (`gcl enforce reference --extra routes` tests that the same guard stands on every way in):
POST /v1/chat/completions (OpenAI chat; `"stream": true` answers as an event stream),
/v1/messages (the Anthropic message shape), /v1/completions (legacy `prompt`) and /v1/responses
(`input`). Any other path is 404. `--policy strict` guards all of them the same way: every message
text (system, content blocks, prompt, input) before the model call, the reply after. `--policy
naive` guards /v1/chat/completions only and forwards the others unscanned, in both directions:
the shape of LiteLLM #40583 (/v1/messages skipped the guardrails).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def post(url: str, body: dict, timeout: float) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body, ensure_ascii=False).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


ROUTES = {"/v1/chat/completions": "chat", "/v1/messages": "messages", "/v1/completions": "completions",
          "/v1/responses": "responses"}


class PolicyError(Exception):
    """The policy file cannot be used: missing, unparseable or of a structure not known."""


def parse_policy(text: str, skip_unknown: bool = False) -> list[dict]:
    """The guards of a policy file's text. Raises PolicyError for anything not understood: an
    unknown structure is never read as "no guards". With `skip_unknown` (naive) a guard of an
    unknown type is left out instead."""
    try:
        doc = json.loads(text)
    except ValueError as e:
        raise PolicyError(f"not valid JSON: {e}") from None
    guards = doc.get("guards") if isinstance(doc, dict) else None
    if not isinstance(guards, list):
        raise PolicyError('no "guards" list')
    for g in guards:
        if not (isinstance(g, dict) and isinstance(g.get("scanner"), str) and isinstance(g.get("scope"), str)):
            raise PolicyError(f"a guard needs a string scanner and scope: {g!r}")
        if g.get("type", "http") != "http" and not skip_unknown:
            raise PolicyError(f"unknown guard type {g.get('type')!r} (only \"http\")")
    return [g for g in guards if g.get("type", "http") == "http"]


class Policy:
    """The policy file as the gateway sees it. Strict: re-read when the modification time
    changes, broken means refuse. Naive: read once, broken means no guards."""

    def __init__(self, path: str, mode: str):
        self.path, self.mode = path, mode
        self.guards: list[dict] = []
        self.error = ""
        self._stamp = None
        self._lock = threading.Lock()
        self._load()   # a strict gateway with a broken file is stopped by the caller (self.error)

    def _load(self) -> None:
        try:
            self._stamp = os.stat(self.path).st_mtime_ns
            with open(self.path, encoding="utf-8") as f:
                text = f.read()
            self.guards, self.error = parse_policy(text, self.mode == "naive"), ""
        except (OSError, PolicyError) as e:
            self.guards, self.error = [], f"{type(e).__name__}: {e}"
        if self.mode == "naive":  # carries on without the policy it could not read
            self.error = ""

    def current(self) -> list[dict] | None:
        """The guards that apply now, or None if the policy is unusable (strict only)."""
        if self.mode == "strict":
            with self._lock:
                try:
                    stamp = os.stat(self.path).st_mtime_ns
                except OSError:
                    stamp = None
                if stamp != self._stamp or stamp is None:
                    self._load()
                return None if self.error else self.guards
        return self.guards

    def matching(self, model: str) -> list[dict] | None:
        guards = self.current()
        if guards is None:
            return None
        if self.mode == "naive":
            return [g for g in guards if g["scope"] == "*"]
        return [g for g in guards if g["scope"] in ("*", model)]


def check(args, texts: list[str], stage: str, url: str | None = None):
    """Return ("allow" | "block", texts). Strict: anything unexpected blocks."""
    url = url or (args.scanner_output if stage == "response" and args.scanner_output else args.scanner)
    try:
        verdict = post(url, {"texts": texts, "input_type": stage}, timeout=3)
    except Exception:
        return ("allow", texts) if args.policy == "naive" else ("block", texts)
    action = verdict.get("action") if isinstance(verdict, dict) else None
    if action == "BLOCKED":
        return "block", texts
    if action == "GUARDRAIL_INTERVENED":
        new = verdict.get("texts")
        # A rewrite must replace every text, one for one, with a string; anything else
        # would forward some original text unscanned.
        if isinstance(new, list) and len(new) == len(texts) and all(isinstance(t, str) for t in new):
            return "allow", new
        return ("allow", texts) if args.policy == "naive" else ("block", texts)
    if action == "NONE" or args.policy == "naive":
        return "allow", texts
    return "block", texts


def exit_with_parent() -> None:
    """Exit when the process that started this gateway is gone (it was killed, so it never stopped
    us). Harmless in a terminal: a gateway run by hand has a shell as parent that outlives it."""
    parent = os.getppid()

    def watch() -> None:
        while True:
            time.sleep(1)
            if os.getppid() != parent:
                os._exit(0)

    threading.Thread(target=watch, daemon=True).start()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scanner", default="", help="scanner URL (not with --policy-file)")
    ap.add_argument("--policy-file", default="", help="JSON policy file: the guards and their scopes")
    ap.add_argument("--scanner-output", default="", help="scanner URL for replies (default: --scanner)")
    ap.add_argument("--model", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--policy", choices=["strict", "naive"], required=True)
    args = ap.parse_args()
    if bool(args.scanner) == bool(args.policy_file):
        ap.error("give exactly one of --scanner and --policy-file")
    policy = Policy(args.policy_file, args.policy) if args.policy_file else None
    if policy is not None and policy.error:  # strict: refuse to start with a policy it cannot load
        print(f"ref_gateway: cannot load the policy file: {policy.error}", file=sys.stderr)
        sys.exit(2)

    def input_check(texts: list[str], model: str):
        """The request-side verdict: the one --scanner, or every guard the policy has for `model`."""
        if policy is None:
            return check(args, texts, "request")
        guards = policy.matching(model)
        if guards is None:  # the policy became unusable while running: fail closed
            return "refuse", texts
        for g in guards:
            decision, texts = check(args, texts, "request", g["scanner"])
            if decision == "block":
                return decision, texts
        return "allow", texts

    def output_check(texts: list[str]):
        if policy is not None and not args.scanner_output:
            return "allow", texts
        return check(args, texts, "response")

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, code: int, obj: dict) -> None:
            b = json.dumps(obj, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            self._json(200, {"status": "ok"})

        @staticmethod
        def _chat_messages(route: str, body: dict) -> list[dict]:
            """The request as chat messages (what the model is called with); texts keep their order."""
            def blocks(c):
                if isinstance(c, str):
                    return c
                return " ".join(b.get("text", "") for b in c if isinstance(b, dict)) if isinstance(c, list) else ""
            if route == "chat":
                return body.get("messages", [])
            if route == "messages":
                sys_ = body.get("system")
                head = [{"role": "system", "content": blocks(sys_)}] if sys_ else []
                return head + [{"role": m.get("role", "user"), "content": blocks(m.get("content", ""))}
                               for m in body.get("messages", []) if isinstance(m, dict)]
            if route == "completions":
                p = body.get("prompt", "")
                return [{"role": "user", "content": " ".join(p) if isinstance(p, list) else str(p)}]
            inp = body.get("input", "")
            if isinstance(inp, str):
                return [{"role": "user", "content": inp}]
            return [{"role": m.get("role", "user"), "content": blocks(m.get("content", ""))}
                    for m in inp if isinstance(m, dict)]

        @staticmethod
        def _shape(route: str, reply: dict, text: str, model: str) -> dict:
            if route == "chat":
                reply["choices"][0]["message"]["content"] = text
                return reply
            if route == "messages":
                return {"id": "gcl-1", "type": "message", "role": "assistant", "model": model,
                        "content": [{"type": "text", "text": text}], "stop_reason": "end_turn",
                        "usage": {"input_tokens": 1, "output_tokens": 1}}
            if route == "completions":
                return {"id": "gcl-1", "object": "text_completion", "model": model,
                        "choices": [{"index": 0, "text": text, "finish_reason": "stop"}]}
            return {"id": "gcl-1", "object": "response", "model": model, "status": "completed",
                    "output": [{"type": "message", "role": "assistant",
                                "content": [{"type": "output_text", "text": text}]}]}

        def _sse(self, text: str) -> None:
            chunk = {"id": "gcl-1", "object": "chat.completion.chunk",
                     "choices": [{"index": 0, "delta": {"content": text}, "finish_reason": None}]}
            end = {"id": "gcl-1", "object": "chat.completion.chunk",
                   "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            self.wfile.write(f"data: {json.dumps(chunk, ensure_ascii=False)}\n\ndata: {json.dumps(end)}\n\n"
                             "data: [DONE]\n\n".encode())

        def do_POST(self):
            route = ROUTES.get(self.path.split("?")[0].rstrip("/"))
            if route is None:
                self._json(404, {"error": {"message": "no such route"}})
                return
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
            messages = self._chat_messages(route, body)
            # Strict guards every route; naive only guards chat completions (LiteLLM #40583).
            guarded = args.policy == "strict" or route == "chat"
            texts = [m.get("content", "") for m in messages]
            if guarded:
                decision, texts = input_check(texts, str(body.get("model", "")))
                if decision == "refuse":
                    self._json(503, {"error": {"message": "policy unusable: refused"}})
                    return
                if decision == "block":
                    self._json(400, {"error": {"message": "blocked by guardrail"}})
                    return
            for m, t in zip(messages, texts, strict=True):
                m["content"] = t
            try:
                reply = post(args.model, {"model": body.get("model", "m"), "messages": messages}, timeout=10)
            except urllib.error.URLError:
                self._json(502, {"error": {"message": "model unavailable"}})
                return
            content = reply["choices"][0]["message"]["content"]
            if guarded:
                decision, out = output_check([content])
                if decision == "block":
                    self._json(400, {"error": {"message": "blocked by guardrail"}})
                    return
                content = out[0]
            if route == "chat" and body.get("stream"):
                self._sse(content)
                return
            self._json(200, self._shape(route, reply, content, str(body.get("model", "m"))))

    exit_with_parent()
    ThreadingHTTPServer(("127.0.0.1", args.port), H).serve_forever()


if __name__ == "__main__":
    main()
