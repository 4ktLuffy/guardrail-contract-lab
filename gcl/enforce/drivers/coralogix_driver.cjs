// Driver for Coralogix (formerly Aporia) guardrails on a LangChain chat model
// (@coralogix/guardrails-langchain).
//
//   node coralogix_driver.cjs --env DIR --port N --model-base URL --guard-base URL
//
// Builds the model the way the package README shows: a ChatOpenAI pointed at gcl's mock
// model, wrapped with withGuardrails({projectId, apiKey, baseUrl}). The wrapper does all
// the enforcing; this driver only serves invoke() (and stream(), as server-sent events)
// over HTTP. A blocked prompt or reply comes back from the library as an ordinary message
// carrying its override text (200); a thrown error is 500. The package and LangChain are
// loaded from --env, not from gcl.
const http = require("node:http");
const path = require("node:path");
const { createRequire } = require("node:module");
const { pathToFileURL } = require("node:url");

const arg = (k, d) => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : d; };
const envRequire = createRequire(path.join(path.resolve(arg("--env")), "package.json"));
const load = (name) => import(pathToFileURL(envRequire.resolve(name)).href);

const send = (res, code, obj) => {
  const b = Buffer.from(JSON.stringify(obj));
  res.writeHead(code, { "Content-Type": "application/json", "Content-Length": b.length });
  res.end(b);
};

(async () => {
  const { withGuardrails } = await load("@coralogix/guardrails-langchain");
  const { ChatOpenAI } = await load("@langchain/openai");
  const model = withGuardrails(
    new ChatOpenAI({ model: "gcl-mock", apiKey: "sk-gcl", configuration: { baseURL: arg("--model-base") } }),
    { projectId: "gcl-project", apiKey: "gcl-key", baseUrl: arg("--guard-base") });
  const text = (c) => (typeof c === "string" ? c : JSON.stringify(c));

  http.createServer((req, res) => {
    if (req.method !== "POST") return send(res, 200, { status: "ok" });
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", async () => {
      let body;
      try { body = JSON.parse(raw || "{}"); } catch (e) { return send(res, 400, { error: "bad json" }); }
      const messages = (body.messages || []).map((m) => [m.role === "assistant" ? "ai" : m.role, m.content]);
      if (body.stream) {
        res.writeHead(200, { "Content-Type": "text/event-stream" });
        // Every chunk the library yielded, whole, is sent last as its own event
        // (`library_return`): the delta text is what a client shows, the chunks are
        // everything the library handed its caller.
        const returned = [];
        const keep = (c) => returned.push({ content: c.content, additional_kwargs: c.additional_kwargs,
                                            response_metadata: c.response_metadata });
        try {
          for await (const chunk of await model.stream(messages)) {
            keep(chunk);
            res.write(`data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: text(chunk.content) } }] })}\n\n`);
          }
          res.write(`data: ${JSON.stringify({ library_return: returned })}\n\n`);
          res.end("data: [DONE]\n\n");
        } catch (e) {
          res.write(`data: ${JSON.stringify({ library_return: returned })}\n\n`);
          res.end(`data: ${JSON.stringify({ error: { type: e && e.name, message: String(e && e.message) } })}\n\n`);
        }
        return;
      }
      try {
        const r = await model.invoke(messages);
        send(res, 200, { choices: [{ index: 0, message: { role: "assistant", content: text(r.content) } }],
                         library_return: { content: r.content, additional_kwargs: r.additional_kwargs,
                                           response_metadata: r.response_metadata } });
      } catch (e) {
        send(res, 500, { error: { type: e && e.name, message: String(e && e.message), stack: String(e && e.stack) } });
      }
    });
  }).listen(Number(arg("--port")), "127.0.0.1");
})().catch((e) => { console.error(e); process.exit(1); });
