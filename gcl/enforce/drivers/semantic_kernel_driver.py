"""Driver for Microsoft Semantic Kernel with guardrail filters.

    python semantic_kernel_driver.py --port N --model-base URL --tool-url URL
        --input-guard URL --output-guard URL

Semantic Kernel's documented guardrail mechanism is filters: a PROMPT_RENDERING filter
that sets `context.function_result` skips the AI call; a FUNCTION_INVOCATION filter can
replace `context.result`. SK ships no guard, so the filters use gcl's strictest guard
(allow only on NONE, a refusal on BLOCKED, raise on anything else) — the run tests SK's
enforcement. One plugin function, gcl_probe, with automatic function calling. A run that
raises is 500; the result's text is the answer.
"""
import argparse
import asyncio
import json
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from openai import AsyncOpenAI
from semantic_kernel import Kernel
from semantic_kernel.connectors.ai.function_choice_behavior import FunctionChoiceBehavior
from semantic_kernel.connectors.ai.open_ai import OpenAIChatCompletion, OpenAIChatPromptExecutionSettings
from semantic_kernel.filters import FilterTypes
from semantic_kernel.functions import KernelArguments, kernel_function
from semantic_kernel.functions.function_result import FunctionResult


def _post(url: str, obj: dict) -> dict:
    req = urllib.request.Request(url, data=json.dumps(obj, ensure_ascii=False).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=8) as r:
        return json.loads(r.read())


def _verdict(url: str, stage: str, text: str) -> str | None:
    """None to allow; the refusal text to block; raise on anything unexpected."""
    v = _post(url, {"texts": [text], "input_type": stage})
    action = v.get("action") if isinstance(v, dict) else None
    if action == "NONE":
        return None
    if action == "BLOCKED":
        return str(v.get("blocked_reason") or "blocked")
    raise RuntimeError(f"unrecognised scanner verdict: {v!r}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--model-base", required=True)
    ap.add_argument("--tool-url", required=True)
    ap.add_argument("--input-guard", required=True)
    ap.add_argument("--output-guard", required=True)
    args = ap.parse_args()

    class Probe:
        @kernel_function(name="gcl_probe", description="Record that a tool ran (gcl test probe).")
        def gcl_probe(self, note: str) -> str:
            _post(args.tool_url, {"note": note})
            return "recorded"

    kernel = Kernel()
    kernel.add_service(OpenAIChatCompletion(ai_model_id="gcl-mock", service_id="chat",
                                            async_client=AsyncOpenAI(base_url=args.model_base, api_key="sk-gcl")))
    kernel.add_plugin(Probe(), plugin_name="probe")

    @kernel.filter(FilterTypes.PROMPT_RENDERING)
    async def input_guard(context, next):
        await next(context)
        refusal = await asyncio.to_thread(_verdict, args.input_guard, "request", context.rendered_prompt or "")
        if refusal is not None:
            context.function_result = FunctionResult(function=context.function.metadata, value=refusal)

    @kernel.filter(FilterTypes.FUNCTION_INVOCATION)
    async def output_guard(context, next):
        await next(context)
        if context.function.plugin_name == "probe" or context.result is None:
            return
        text = str(context.result.value if not isinstance(context.result.value, list)
                   else "".join(str(v) for v in context.result.value))
        refusal = await asyncio.to_thread(_verdict, args.output_guard, "response", text)
        if refusal is not None:
            context.result = FunctionResult(function=context.function.metadata, value=refusal)

    settings = OpenAIChatPromptExecutionSettings(service_id="chat",
                                                 function_choice_behavior=FunctionChoiceBehavior.Auto())

    async def run(text: str) -> str:
        r = await kernel.invoke_prompt("{{$input}}", arguments=KernelArguments(settings=settings, input=text))
        return str(r)

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
            text = (body.get("messages") or [{}])[-1].get("content", "")
            try:
                answer = asyncio.run(run(text))
            except Exception as e:
                self._json(500, {"error": {"type": type(e).__name__, "message": str(e), "detail": repr(e)}})
                return
            self._json(200, {"choices": [{"index": 0, "message": {"role": "assistant", "content": answer}}]})

    ThreadingHTTPServer(("127.0.0.1", args.port), H).serve_forever()


if __name__ == "__main__":
    main()
