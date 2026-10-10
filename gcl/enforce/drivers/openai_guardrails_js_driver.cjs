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

// Everything the library hands back, serialised recursively (cycles cut, size capped),
// so nested state or result objects are visible to the judge, not "[object Object]".
const safe = (v) => {
  const seen = new WeakSet();
  try {
    const s = JSON.stringify(v, (k, x) => {
      if (typeof x === "object" && x !== null) { if (seen.has(x)) return "[cycle]"; seen.add(x); }
      if (typeof x === "bigint") return String(x);
      return x;
    });
    return s === undefined ? null : JSON.parse(s.length > 500000 ? JSON.stringify(s.slice(0, 500000)) : s);
  } catch (err) { return String(v); }
};

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
                         library_return: safe({ guardrail_results: r.guardrail_results, choices: r.choices }) });
      } catch (e) {
        const blocked = e instanceof GuardrailTripwireTriggered;
        send(res, blocked ? 400 : 500, { error: { type: e && e.name, message: blocked ? "tripwire" : "error" },
                                         library_return: { exception_message: String(e && e.message), exception_attrs: safe(Object.assign({}, e)) } });
      }
    });
  }).listen(Number(arg("--port")), "127.0.0.1");
})();
