"""A minimal coverage adapter: reads {"id","text"} JSON lines on stdin, writes
{"id","flagged"} lines. Stands in for any guardrail you can call from a script —
a local model, an HTTP API, a vendor SDK."""
import json
import sys

KEYWORDS = ("ignore all previous", "system prompt", "do not tell the user", "api key")

for line in sys.stdin:
    case = json.loads(line)
    text = case["text"].lower()
    print(json.dumps({"id": case["id"], "flagged": any(k in text for k in KEYWORDS)}))
