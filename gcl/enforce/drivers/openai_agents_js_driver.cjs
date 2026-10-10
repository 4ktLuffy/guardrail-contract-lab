// Driver for the OpenAI Agents SDK for JavaScript with openai-guardrails JS GuardrailAgent.
//
//   node openai_agents_js_driver.cjs --env DIR --port N --model-base URL --tool-url URL
//        --config FILE [--raise-guardrail-errors]
//
// `GuardrailAgent.create(config, name, instructions, {model, tools}, raise)` and `run(agent,
// input)` as the packages document. One tool, gcl_probe, whose only effect is a POST to
// gcl's tool observer. The guardrail LLM is a bare `new OpenAI()`, so it reads
// OPENAI_BASE_URL (set by the adapter). Tripwire errors are 400, other errors 500.
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const { createRequire } = require("node:module");

const arg = (k, d) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : d; };
const envRequire = createRequire(path.join(path.resolve(arg("--env")), "package.json"));
const agents = envRequire("@openai/agents");
const { GuardrailAgent } = envRequire("@openai/guardrails");
const OpenAIMod = envRequire("openai");
const OpenAI = OpenAIMod.OpenAI || OpenAIMod.default || OpenAIMod;

const send = (res, code, obj) => {
  const b = Buffer.from(JSON.stringify(obj));
  res.writeHead(code, { "Content-Type": "application/json", "Content-Length": b.length });
  res.end(b);
};

(async () => {
  agents.setTracingDisabled(true);
  const probe = agents.tool({
    name: "gcl_probe", description: "Record that a tool ran (gcl test probe).", strict: true,
    parameters: { type: "object", properties: { note: { type: "string" } }, required: ["note"], additionalProperties: false },
    execute: async ({ note }) => {
      await fetch(arg("--tool-url"), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ note }) });
      return "recorded";
    },
  });
  const model = new agents.OpenAIChatCompletionsModel(new OpenAI({ baseURL: arg("--model-base"), apiKey: "sk-gcl" }), "gcl-mock");
  const config = JSON.parse(fs.readFileSync(arg("--config"), "utf8"));
  const agent = await GuardrailAgent.create(config, "gcl", "You are a helpful assistant.", { model, tools: [probe] },
                                            process.argv.includes("--raise-guardrail-errors"));
  http.createServer((req, res) => {
    if (req.method !== "POST") return send(res, 200, { status: "ok" });
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", async () => {
      try {
        const body = JSON.parse(raw || "{}");
        const msgs = body.messages || [];
        const r = await agents.run(agent, msgs.length ? msgs[msgs.length - 1].content : "");
        send(res, 200, { choices: [{ index: 0, message: { role: "assistant", content: String(r.finalOutput) } }] });
      } catch (e) {
        const blocked = e instanceof agents.InputGuardrailTripwireTriggered || e instanceof agents.OutputGuardrailTripwireTriggered;
        // The library's own message is what it hands the caller; it is reported as returned
        // data, not as the answer, so a message that embeds content is "retained".
        send(res, blocked ? 400 : 500, { error: { type: e && e.name, message: blocked ? "tripwire" : "error" },
                                         library_return: { exception_message: String(e && e.message) } });
      }
    });
  }).listen(Number(arg("--port")), "127.0.0.1");
})();
