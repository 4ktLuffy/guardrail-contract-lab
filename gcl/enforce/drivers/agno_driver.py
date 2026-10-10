"""Driver for Agno agents with the built-in `OpenAIModerationGuardrail` as a pre-hook.

    python agno_driver.py --port N --model-base URL

`Agent(model=OpenAIChat(...), pre_hooks=[OpenAIModerationGuardrail()])`, run with
`agent.run(...)`, as Agno's guardrail docs show. The guardrail builds its own OpenAI
client, so the moderation endpoint comes from OPENAI_BASE_URL (set by the adapter).
`InputCheckError` is how a block surfaces (400); other exceptions are 500.
"""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from agno.agent import Agent
from agno.exceptions import InputCheckError
from agno.guardrails import OpenAIModerationGuardrail
from agno.models.openai import OpenAIChat


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--model-base", required=True)
    args = ap.parse_args()
    agent = Agent(model=OpenAIChat(id="gcl-mock", base_url=args.model_base, api_key="sk-gcl"),
                  pre_hooks=[OpenAIModerationGuardrail()], telemetry=False)

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
                r = agent.run(prompt)
            except InputCheckError as e:
                self._json(400, {"error": {"type": "InputCheckError", "message": str(e), "detail": repr(e)},
                                 "library_return": {"exception_attrs": {k: repr(v) for k, v in vars(e).items()}}})
                return
            except Exception as e:
                self._json(500, {"error": {"type": type(e).__name__, "message": str(e), "detail": repr(e)},
                                 "library_return": {"exception_attrs": {k: repr(v) for k, v in vars(e).items()}}})
                return
            self._json(200, {"choices": [{"index": 0, "message": {"role": "assistant", "content": r.content}}],
                             "library_return": {"status": str(getattr(r, "status", ""))}})

    ThreadingHTTPServer(("127.0.0.1", args.port), H).serve_forever()


if __name__ == "__main__":
    main()
