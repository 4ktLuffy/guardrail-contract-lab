"""Driver for the OpenAI Agents SDK with openai-guardrails' `GuardrailAgent`.

    python openai_agents_driver.py --port N --model-base URL --tool-url URL --config FILE
        [--raise-guardrail-errors]

Builds the agent as openai-guardrails documents it: `GuardrailAgent(config=..., name=...,
instructions=..., tools=[...])`, run with `Runner.run`. The agent has one tool,
`gcl_probe`, whose only effect is to POST its argument to gcl's tool observer — so gcl
can see whether a tool ran. The chat-completions model class is used so the mock model
can answer. `InputGuardrailTripwireTriggered` / `OutputGuardrailTripwireTriggered` are how
a block surfaces (400); other exceptions are 500.
"""
import argparse
import asyncio
import json
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from agents import (
    InputGuardrailTripwireTriggered,
    OpenAIChatCompletionsModel,
    OutputGuardrailTripwireTriggered,
    Runner,
    function_tool,
    set_tracing_disabled,
)
from guardrails import GuardrailAgent
from openai import AsyncOpenAI


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--model-base", required=True)
    ap.add_argument("--tool-url", required=True)
    ap.add_argument("--config", required=True)
    ap.add_argument("--raise-guardrail-errors", action="store_true")
    args = ap.parse_args()
    set_tracing_disabled(True)

    @function_tool
    def gcl_probe(note: str) -> str:
        """Record that a tool ran (gcl test probe)."""
        req = urllib.request.Request(args.tool_url, data=json.dumps({"note": note}).encode(),
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5).read()
        return "recorded"

    model = OpenAIChatCompletionsModel(model="gcl-mock",
                                       openai_client=AsyncOpenAI(base_url=args.model_base, api_key="sk-gcl"))
    agent = GuardrailAgent(config=Path(args.config), name="gcl", instructions="You are a helpful assistant.",
                           model=model, tools=[gcl_probe], raise_guardrail_errors=args.raise_guardrail_errors)

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
            try:
                r = asyncio.run(Runner.run(agent, body.get("messages", [])))
            except (InputGuardrailTripwireTriggered, OutputGuardrailTripwireTriggered) as e:
                self._json(400, {"error": {"type": type(e).__name__, "message": str(e), "detail": repr(e)},
                                 "library_return": {"exception_attrs": {k: repr(v) for k, v in vars(e).items()}}})
                return
            except Exception as e:
                self._json(500, {"error": {"type": type(e).__name__, "message": str(e), "detail": repr(e)},
                                 "library_return": {"exception_attrs": {k: repr(v) for k, v in vars(e).items()}}})
                return
            answer = {"role": "assistant", "content": str(r.final_output)}
            self._json(200, {"choices": [{"index": 0, "message": answer}],
                             "library_return": [repr(i) for i in r.new_items]})

    ThreadingHTTPServer(("127.0.0.1", args.port), H).serve_forever()


if __name__ == "__main__":
    main()
