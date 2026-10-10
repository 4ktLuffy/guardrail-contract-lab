"""Driver for Google ADK agents with guardrail callbacks.

    python google_adk_driver.py --port N --model-base URL --tool-url URL
        --input-guard URL --output-guard URL

ADK's guardrail pattern is callbacks: `before_model_callback` returning an LlmResponse
skips the model; `after_model_callback` returning one replaces the reply. ADK ships no
guard, so the callbacks are gcl's strictest (allow only on NONE, return a refusal on
BLOCKED, raise on anything else) — the run tests ADK's enforcement of them. One probe
tool. The model is LiteLlm pointed at the mock. A run that raises is 500; the final
response text is the answer.
"""
import argparse
import asyncio
import json
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from google.adk.agents import LlmAgent
from google.adk.models.lite_llm import LiteLlm
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types


def _post(url: str, obj: dict) -> dict:
    req = urllib.request.Request(url, data=json.dumps(obj, ensure_ascii=False).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=8) as r:
        return json.loads(r.read())


def _verdict(url: str, stage: str, text: str):
    v = _post(url, {"texts": [text], "input_type": stage})
    action = v.get("action") if isinstance(v, dict) else None
    if action == "NONE":
        return None
    if action == "BLOCKED":
        return LlmResponse(content=types.Content(role="model", parts=[types.Part(
            text=str(v.get("blocked_reason") or "blocked"))]))
    raise RuntimeError(f"unrecognised scanner verdict: {v!r}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--model-base", required=True)
    ap.add_argument("--tool-url", required=True)
    ap.add_argument("--input-guard", required=True)
    ap.add_argument("--output-guard", required=True)
    args = ap.parse_args()

    def gcl_probe(note: str) -> dict:
        """Record that a tool ran (gcl test probe)."""
        _post(args.tool_url, {"note": note})
        return {"status": "recorded"}

    def before_model(callback_context, llm_request):
        # Check the latest user turn only, once per invocation (first model call).
        if any(getattr(c, "role", "") == "model" for c in llm_request.contents):
            return None
        texts = [p.text for c in llm_request.contents if c.role == "user" for p in (c.parts or []) if p.text]
        return _verdict(args.input_guard, "request", texts[-1] if texts else "")

    def after_model(callback_context, llm_response):
        parts = (llm_response.content.parts if llm_response.content else None) or []
        text = "".join(p.text or "" for p in parts)
        if not text:  # a tool call, not a reply
            return None
        return _verdict(args.output_guard, "response", text)

    agent = LlmAgent(name="gcl", model=LiteLlm(model="openai/gcl-mock", api_base=args.model_base, api_key="sk-gcl"),
                     instruction="You are a helpful assistant.", tools=[gcl_probe],
                     before_model_callback=before_model, after_model_callback=after_model)
    sessions = InMemorySessionService()
    runner = Runner(agent=agent, app_name="gcl", session_service=sessions)

    async def run(prompt: str) -> str:
        s = await sessions.create_session(app_name="gcl", user_id="u")
        final = ""
        async for ev in runner.run_async(user_id="u", session_id=s.id,
                                         new_message=types.Content(role="user", parts=[types.Part(text=prompt)])):
            if ev.is_final_response() and ev.content and ev.content.parts:
                final = "".join(p.text or "" for p in ev.content.parts)
        return final

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
                answer = asyncio.run(run(prompt))
            except Exception as e:
                self._json(500, {"error": {"type": type(e).__name__, "message": str(e), "detail": repr(e)}})
                return
            self._json(200, {"choices": [{"index": 0, "message": {"role": "assistant", "content": answer}}]})

    ThreadingHTTPServer(("127.0.0.1", args.port), H).serve_forever()


if __name__ == "__main__":
    main()
