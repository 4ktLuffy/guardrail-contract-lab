// Driver for openai-guardrails JS (@openai/guardrails).
//
//   node openai_guardrails_js_driver.cjs --env DIR --port N --base-url URL --config FILE
//        [--raise-guardrail-errors] [--timeout MS]
//
// Uses `GuardrailsOpenAI.create(config, clientOptions, raiseGuardrailErrors)` and
// `client.chat.completions.create(...)` as the README shows; `GuardrailTripwireTriggered`
// is how a block surfaces (400), other errors are 500. Loaded from --env, not from gcl.
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const { createRequire } = require("node:module");

const arg = (k, d) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : d; };
const envRequire = createRequire(path.join(path.resolve(arg("--env")), "package.json"));
const { GuardrailsOpenAI, GuardrailTripwireTriggered } = envRequire("@openai/guardrails");

const send = (res, code, obj) => {
  const b = Buffer.from(JSON.stringify(obj));
  res.writeHead(code, { "Content-Type": "application/json", "Content-Length": b.length });
  res.end(b);
};

(async () => {
  const config = JSON.parse(fs.readFileSync(arg("--config"), "utf8"));
  const client = await GuardrailsOpenAI.create(
    config,
    { baseURL: arg("--base-url"), apiKey: "sk-gcl", timeout: Number(arg("--timeout", "8000")) },
    process.argv.includes("--raise-guardrail-errors"),
  );
  http.createServer((req, res) => {
    if (req.method !== "POST") return send(res, 200, { status: "ok" });
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", async () => {
      try {
        const body = JSON.parse(raw || "{}");
        const r = await client.chat.completions.create({ model: "gcl-mock", messages: body.messages || [] });
        send(res, 200, { choices: [{ index: 0, message: { role: "assistant", content: r.choices[0].message.content } }],
                         library_return: r.guardrail_results || null });
      } catch (e) {
        const blocked = e instanceof GuardrailTripwireTriggered;
        send(res, blocked ? 400 : 500, { error: { type: e && e.name, message: String(e && e.message) },
                                         library_return: { exception_attrs: Object.fromEntries(Object.entries(e || {}).map(([k, v]) => [k, String(v)])) } });
      }
    });
  }).listen(Number(arg("--port")), "127.0.0.1");
})();
