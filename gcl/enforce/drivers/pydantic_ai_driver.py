"""Driver for Pydantic AI agents with pydantic-ai-harness guardrails.

    python pydantic_ai_driver.py --port N --model-base URL --tool-url URL
        --input-guard URL --output-guard URL [--parallel]

The harness ships no LLM guard: a guard is a callable you write. This driver's guards
are the strictest reasonable ones — POST the text to the scanner (gcl's standard scanner
protocol), allow only on "NONE", block with the scanner's reason on "BLOCKED", raise on
anything else — so the run tests what the *framework* does with a block or an exception:
`InputGuardrail` (sequential or parallel=True) and `OutputGuardrail`, as documented. The
agent has one tool, `gcl_probe`, that POSTs its argument to gcl's tool observer.
"""
import argparse
import asyncio
import json
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.openai import OpenAIProvider
from pydantic_ai_harness import GuardrailResult, InputGuardrail, OutputGuardrail
from pydantic_ai_harness.guardrails._exceptions import InputBlocked, OutputBlocked


def _post(url: str, obj: dict) -> dict:
    req = urllib.request.Request(url, data=json.dumps(obj, ensure_ascii=False).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=8) as r:
        return json.loads(r.read())


def strict_guard(url: str, stage: str):
    # Async, like any real network guard: a blocking call here would stall the event loop
    # and make parallel mode look sequential.
    async def guard(text) -> GuardrailResult:
        v = await asyncio.to_thread(_post, url, {"texts": [str(text)], "input_type": stage})
        action = v.get("action") if isinstance(v, dict) else None
        if action == "NONE":
            return GuardrailResult.allow()
        if action == "BLOCKED":
            return GuardrailResult.block(str(v.get("blocked_reason") or "blocked"))
        raise RuntimeError(f"unrecognised scanner verdict: {v!r}")
    return guard


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--model-base", required=True)
    ap.add_argument("--tool-url", required=True)
    ap.add_argument("--input-guard", required=True)
    ap.add_argument("--output-guard", required=True)
    ap.add_argument("--parallel", action="store_true")
    args = ap.parse_args()
    model = OpenAIChatModel("gcl-mock", provider=OpenAIProvider(base_url=args.model_base, api_key="sk-gcl"))
    agent = Agent(model, instructions="You are a helpful assistant.", capabilities=[
        InputGuardrail(guard=strict_guard(args.input_guard, "request"), parallel=args.parallel),
        OutputGuardrail(guard=strict_guard(args.output_guard, "response"))])

    @agent.tool_plain
    def gcl_probe(note: str) -> str:
        """Record that a tool ran (gcl test probe)."""
        _post(args.tool_url, {"note": note})
        return "recorded"

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _json(self, code: int, obj: dict) -> None:
            b = json.dumps(obj, ensure_ascii=False, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            self._json(200, {"status": "ok"})

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
            prompt = (body.get("messages") or [{}])[-1].get("content", "")
            try:
                r = asyncio.run(agent.run(prompt))
            except (InputBlocked, OutputBlocked) as e:
                self._json(400, {"error": {"type": type(e).__name__, "message": str(e), "detail": repr(e),
                                           "attrs": {k: repr(v) for k, v in vars(e).items()}}})
                return
            except Exception as e:  # guard exceptions and anything else
                code = 500
                self._json(code, {"error": {"type": type(e).__name__, "message": str(e), "detail": repr(e),
                                           "attrs": {k: repr(v) for k, v in vars(e).items()}}})
                return
            self._json(200, {"choices": [{"index": 0, "message": {"role": "assistant", "content": str(r.output)}}],
                             "library_return": [repr(m) for m in r.all_messages()]})

    ThreadingHTTPServer(("127.0.0.1", args.port), H).serve_forever()


if __name__ == "__main__":
    main()
