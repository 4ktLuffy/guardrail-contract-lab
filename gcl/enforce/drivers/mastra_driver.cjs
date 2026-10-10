// Driver for Mastra agents with model-backed guardrail processors (@mastra/core).
//
//   node mastra_driver.cjs --env DIR --port N --model-base URL --input-guard URL
//        --output-guard URL [--error-strategy warn|strict]
//
// Builds the agent the way the Mastra guardrails docs show: PromptInjectionDetector as
// an input processor, ModerationProcessor as an output processor, each with its own
// model object { id, url, apiKey }. A result carrying `tripwire` is how a block surfaces
// (400); a thrown error is 500. Mastra is loaded from --env, not from gcl.
const http = require("node:http");
const path = require("node:path");
const { createRequire } = require("node:module");

const arg = (k, d) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : d; };
const envRequire = createRequire(path.join(path.resolve(arg("--env")), "package.json"));
const { Agent } = envRequire("@mastra/core/agent");
const { PromptInjectionDetector, ModerationProcessor } = envRequire("@mastra/core/processors");

const errorStrategy = arg("--error-strategy", "warn");
const guard = (url) => ({ id: "custom/gcl-judge", url, apiKey: "sk-gcl" });
const agent = new Agent({
  name: "gcl", instructions: "You are a helpful assistant.",
  model: { id: "custom/gcl-mock", url: arg("--model-base"), apiKey: "sk-gcl" },
  inputProcessors: [new PromptInjectionDetector({ model: guard(arg("--input-guard")), strategy: "block", errorStrategy })],
  outputProcessors: [new ModerationProcessor({ model: guard(arg("--output-guard")), strategy: "block", errorStrategy })],
});

const send = (res, code, obj) => {
  const b = Buffer.from(JSON.stringify(obj));
  res.writeHead(code, { "Content-Type": "application/json", "Content-Length": b.length });
  res.end(b);
};
http.createServer((req, res) => {
  if (req.method !== "POST") return send(res, 200, { status: "ok" });
  let raw = "";
  req.on("data", (c) => (raw += c));
  req.on("end", async () => {
    try {
      const body = JSON.parse(raw || "{}");
      const r = await agent.generate(body.messages || []);
      const full = { text: r.text, tripwire: r.tripwire, response: r.response && r.response.messages };
      if (r.tripwire) return send(res, 400, { error: { type: "tripwire", message: String(r.tripwire.reason || r.tripwire) }, library_return: full });
      send(res, 200, { choices: [{ index: 0, message: { role: "assistant", content: r.text } }], library_return: full });
    } catch (e) {
      send(res, 500, { error: { type: e && e.name, message: String(e && e.message), stack: String(e && e.stack) } });
    }
  });
}).listen(Number(arg("--port")), "127.0.0.1");
