"""Driver for Meta LlamaFirewall with its LLM-judged PII check (PIICheckScanner).

    python llamafirewall_driver.py --port N --model-base URL --judge-base URL

LlamaFirewall is a library that returns a ScanResult; the caller enforces it. This driver
does what its README shows: scan the user message, refuse (HTTP 400) when the decision is
BLOCK, otherwise send the request to the model. The scanner is the library's own, pointed
at gcl's judge through the documented `register_llamafirewall_scanner` hook; its failure
handling is the library's. The ScanResult is passed back as `library_return`.
"""

import argparse
import json
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from llamafirewall import LlamaFirewall, Role, ScanDecision, UserMessage, register_llamafirewall_scanner
from llamafirewall.scanners.experimental.piicheck_scanner import PIICheckScanner

ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, required=True)
ap.add_argument("--model-base", required=True)
ap.add_argument("--judge-base", required=True)
args = ap.parse_args()


@register_llamafirewall_scanner("gcl_pii_check")
class GclPIICheck(PIICheckScanner):
    def __init__(self):
        super().__init__(model_name="gcl-judge", api_base_url=args.judge_base, api_key_env_var="GCL_JUDGE_KEY")


firewall = LlamaFirewall(scanners={Role.USER: ["gcl_pii_check"]})


def model_call(messages):
    req = urllib.request.Request(args.model_base + "/chat/completions",
                                 data=json.dumps({"model": "gcl-mock", "messages": messages}).encode(),
                                 headers={"Content-Type": "application/json", "Authorization": "Bearer sk-gcl"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        b = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        self._send(200, {"status": "ok"})

    def do_POST(self):
        scan = None
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
            messages = body.get("messages") or []
            user = next(m["content"] for m in reversed(messages) if m.get("role") == "user")
            result = firewall.scan(UserMessage(content=user))
            scan = {"decision": str(result.decision), "reason": result.reason, "score": result.score,
                    "status": str(result.status)}
            if result.decision == ScanDecision.BLOCK:
                return self._send(400, {"error": {"type": "blocked", "message": result.reason}, "library_return": scan})
            reply = model_call(messages)
            reply["library_return"] = scan
            self._send(200, reply)
        except Exception as e:
            # The library's decision, if it made one, stays in the evidence (e.g. ALLOW with
            # status ERROR before a provider failure).
            self._send(500, {"error": {"type": type(e).__name__, "message": str(e)}, "library_return": scan})


ThreadingHTTPServer(("127.0.0.1", args.port), H).serve_forever()
