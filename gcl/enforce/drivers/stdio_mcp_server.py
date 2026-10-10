"""A minimal MCP server over stdio (newline-delimited JSON-RPC), standard library only.

    python stdio_mcp_server.py --mock URL

One tool, `gcl_probe(note)`. Each tools/call is forwarded as a JSON-RPC tools/call to
gcl's mock model at URL/mcp, which records it (the provider boundary) and returns the
scenario's reply; that reply is the tool's result.
"""
import json
import sys
import urllib.request


def main() -> None:
    mock = sys.argv[sys.argv.index("--mock") + 1].rstrip("/")
    for line in sys.stdin:
        if not line.strip():
            continue
        msg = json.loads(line)
        mid, method = msg.get("id"), msg.get("method")
        if mid is None:
            continue  # notification
        if method == "initialize":
            result = {"protocolVersion": (msg.get("params") or {}).get("protocolVersion", "2025-03-26"),
                      "capabilities": {"tools": {}}, "serverInfo": {"name": "gcl-stdio", "version": "1"}}
        elif method == "tools/list":
            result = {"tools": [{"name": "gcl_probe", "description": "Record a note.",
                                 "inputSchema": {"type": "object", "properties": {"note": {"type": "string"}},
                                                 "required": ["note"]}}]}
        elif method == "tools/call":
            req = urllib.request.Request(mock + "/mcp", data=json.dumps(
                {"jsonrpc": "2.0", "id": mid, "method": "tools/call", "params": msg.get("params") or {}}).encode(),
                headers={"Content-Type": "application/json", "X-GCL-Transport": "stdio"})
            with urllib.request.urlopen(req, timeout=10) as r:
                result = json.loads(r.read())["result"]
        else:
            result = {}
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": mid, "result": result}) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
