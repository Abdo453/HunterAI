#!/usr/bin/env node
/**
 * $0 OpenAI-compatible Mock LLM HTTP server for deterministic Playwright E2E tests.
 * Supports `/v1/models`, `/v1/chat/completions` (streaming SSE & JSON), `/v1/embeddings`, and `/health`.
 */

import http from "node:http";

const DEFAULT_PORT = Number.parseInt(process.env.MOCK_LLM_PORT || "4109", 10);
const DEFAULT_HOST = process.env.MOCK_LLM_HOST || "127.0.0.1";

function buildReplyForPrompt(messages) {
  const last = Array.isArray(messages) ? messages[messages.length - 1] : null;
  const content = typeof last?.content === "string" ? last.content.toLowerCase() : "";
  if (content.includes("approval") || content.includes("nuclei")) {
    return "Queued Nuclei verification check against the scoped asset. Review and approve the proposed command to run.";
  }
  if (content.includes("idor") || content.includes("finding")) {
    return "Confirmed IDOR hypothesis on `/api/orders/1002`: cross-tenant invoice payload returned HTTP 200 without ownership enforcement.";
  }
  return "ARTEX-Pro Mock Copilot analyzed the active engagement telemetry and confirmed zero policy violations.";
}

export function createMockLlmServer() {
  return http.createServer((req, res) => {
    const url = new URL(req.url || "/", `http://${req.headers.host || "127.0.0.1"}`);

    if (req.method === "GET" && url.pathname === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok", mode: "mock-llm" }));
      return;
    }

    if (req.method === "GET" && url.pathname === "/v1/models") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          object: "list",
          data: [
            { id: "mock-sentinel-7b", object: "model", owned_by: "hunterai-mock" },
            { id: "mock-reasoning-14b", object: "model", owned_by: "hunterai-mock" },
          ],
        })
      );
      return;
    }

    if (req.method === "POST" && url.pathname === "/v1/embeddings") {
      let body = "";
      req.on("data", (chunk) => {
        body += chunk;
      });
      req.on("end", () => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            object: "list",
            data: [{ object: "embedding", index: 0, embedding: [0.1, 0.2, 0.3, 0.4] }],
            model: "mock-embed",
            usage: { prompt_tokens: Math.max(1, Math.floor(body.length / 4)), total_tokens: Math.max(1, Math.floor(body.length / 4)) },
          })
        );
      });
      return;
    }

    if (req.method === "POST" && url.pathname === "/v1/chat/completions") {
      let body = "";
      req.on("data", (chunk) => {
        body += chunk;
      });
      req.on("end", () => {
        let parsed = {};
        try {
          parsed = JSON.parse(body || "{}");
        } catch {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: { message: "Invalid JSON body" } }));
          return;
        }

        const model = String(parsed.model || "mock-sentinel-7b");
        const reply = buildReplyForPrompt(parsed.messages);
        const created = Math.floor(Date.now() / 1000);

        if (parsed.stream) {
          res.writeHead(200, {
            "Content-Type": "text/event-stream; charset=utf-8",
            "Cache-Control": "no-cache",
            Connection: "keep-alive",
          });
          const tokens = reply.split(" ");
          let idx = 0;
          const timer = setInterval(() => {
            if (idx < tokens.length) {
              const piece = (idx === 0 ? "" : " ") + tokens[idx];
              idx += 1;
              res.write(
                `data: ${JSON.stringify({
                  id: `chatcmpl-mock-${created}`,
                  object: "chat.completion.chunk",
                  created,
                  model,
                  choices: [{ index: 0, delta: { content: piece }, finish_reason: null }],
                })}\n\n`
              );
            } else {
              clearInterval(timer);
              res.write(
                `data: ${JSON.stringify({
                  id: `chatcmpl-mock-${created}`,
                  object: "chat.completion.chunk",
                  created,
                  model,
                  choices: [{ index: 0, delta: {}, finish_reason: "stop" }],
                })}\n\n`
              );
              res.write("data: [DONE]\n\n");
              res.end();
            }
          }, 15);
          req.on("close", () => clearInterval(timer));
          return;
        }

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            id: `chatcmpl-mock-${created}`,
            object: "chat.completion",
            created,
            model,
            choices: [
              {
                index: 0,
                message: { role: "assistant", content: reply },
                finish_reason: "stop",
              },
            ],
            usage: { prompt_tokens: 24, completion_tokens: 20, total_tokens: 44 },
          })
        );
      });
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: { message: `Not found: ${url.pathname}` } }));
  });
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith("server.mjs")) {
  const server = createMockLlmServer();
  server.listen(DEFAULT_PORT, DEFAULT_HOST, () => {
    console.log(`[mock-llm] Listening on http://${DEFAULT_HOST}:${DEFAULT_PORT}`);
  });
}
