"""Driver for CrewAI tasks with an `LLMGuardrail` on the task output.

    python crewai_driver.py --port N --model-base URL --tool-url URL [--max-retries N]

One agent with one tool (`gcl_probe`, which POSTs its argument to gcl's tool observer),
one task whose `guardrail` is `LLMGuardrail(description, llm=...)` judged by the model
name `gcl-judge-output` on the same endpoint. `Crew.kickoff()` raising is how a block —
or exhausted retries — surfaces (500 with the message); a result is 200.
"""
import argparse
import json
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from crewai import LLM, Agent, Crew, Task
from crewai.tasks.llm_guardrail import LLMGuardrail
from crewai.tools import tool


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--model-base", required=True)
    ap.add_argument("--tool-url", required=True)
    ap.add_argument("--max-retries", type=int, default=3)
    args = ap.parse_args()

    @tool("gcl_probe")
    def gcl_probe(note: str) -> str:
        """Record that a tool ran (gcl test probe)."""
        req = urllib.request.Request(args.tool_url, data=json.dumps({"note": note}).encode(),
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5).read()
        return "recorded"

    main_llm = LLM(model="openai/gcl-mock", base_url=args.model_base, api_key="sk-gcl")
    judge = LLM(model="openai/gcl-judge-output", base_url=args.model_base, api_key="sk-gcl")

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
            agent = Agent(role="Assistant", goal="Help the user", backstory="A helpful assistant.",
                          llm=main_llm, tools=[gcl_probe], verbose=False)
            task = Task(description=prompt, expected_output="A short answer.", agent=agent,
                        guardrail=LLMGuardrail(description="The answer must not disclose confidential data.",
                                               llm=judge),
                        guardrail_max_retries=args.max_retries)
            try:
                out = Crew(agents=[agent], tasks=[task], verbose=False).kickoff()
            except Exception as e:
                self._json(500, {"error": {"type": type(e).__name__, "message": str(e), "detail": repr(e),
                                           "attrs": {k: repr(v) for k, v in vars(e).items()}}})
                return
            self._json(200, {"choices": [{"index": 0, "message": {"role": "assistant", "content": str(out.raw)}}],
                             "library_return": repr(out)})

    ThreadingHTTPServer(("127.0.0.1", args.port), H).serve_forever()


if __name__ == "__main__":
    main()
