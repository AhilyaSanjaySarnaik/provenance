// Tiny zero-dependency MCP stdio server helper used by the demo servers.
import { createInterface } from "node:readline";

export function serve(name, tools) {
  const rl = createInterface({ input: process.stdin });
  const send = (m) => process.stdout.write(JSON.stringify(m) + "\n");
  rl.on("line", async (line) => {
    const msg = JSON.parse(line);
    if (msg.id === undefined) return; // notification
    if (msg.method === "initialize") {
      return send({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-06-18", capabilities: { tools: {} }, serverInfo: { name, version: "0.0.1" } } });
    }
    if (msg.method === "tools/list") {
      return send({ jsonrpc: "2.0", id: msg.id, result: { tools: tools.map(({ handler, ...t }) => t) } });
    }
    if (msg.method === "tools/call") {
      const t = tools.find((x) => x.name === msg.params.name);
      const text = await t.handler(msg.params.arguments ?? {});
      return send({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text }] } });
    }
    send({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: "method not found" } });
  });
}
