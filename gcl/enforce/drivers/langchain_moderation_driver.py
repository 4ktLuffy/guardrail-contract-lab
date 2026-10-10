"""Driver for LangChain v1 agents with `OpenAIModerationMiddleware` (langchain-openai).

    python langchain_moderation_driver.py --port N --model-base URL --moderation-base URL
        [--exit-behavior end|error] [--timeout S]

Builds the agent the way the LangChain docs show: `create_agent(model, middleware=[...])`,
with the middleware's `client` pointed at the moderation endpoint. `OpenAIModerationError`
is how exit_behavior="error" surfaces a block (400); other exceptions are 500.
"""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from langchain.agents import create_agent
from langchain_openai import ChatOpenAI
from langchain_openai.middleware import OpenAIModerationMiddleware
from langchain_openai.middleware.openai_moderation import OpenAIModerationError
from openai import OpenAI


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--model-base", required=True)
    ap.add_argument("--moderation-base", required=True)
    ap.add_argument("--exit-behavior", default="end")
    ap.add_argument("--timeout", type=float, default=8.0)
    args = ap.parse_args()
    mod = OpenAIModerationMiddleware(client=OpenAI(base_url=args.moderation_base, api_key="sk-gcl",
                                                   timeout=args.timeout),
                                     check_input=True, check_output=True, exit_behavior=args.exit_behavior)
    agent = create_agent(ChatOpenAI(model="gcl-mock", base_url=args.model_base, api_key="sk-gcl",
                                    timeout=args.timeout), tools=[], middleware=[mod])

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

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
            try:
                out = agent.invoke({"messages": body.get("messages", [])})
            except OpenAIModerationError as e:
                self._json(400, {"error": {"type": "moderation", "message": str(e)[:300]}})
                return
            except Exception as e:
                self._json(500, {"error": {"type": type(e).__name__, "message": str(e)[:300]}})
                return
            last = out["messages"][-1]
            self._json(200, {"choices": [{"index": 0, "message": {"role": "assistant", "content": last.content}}]})

    ThreadingHTTPServer(("127.0.0.1", args.port), H).serve_forever()


if __name__ == "__main__":
    main()
