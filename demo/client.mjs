// Minimal MCP client that drives a server over stdio. Used by the demo and tests.
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";

export function connect(cmd, args, env = process.env) {
  const child = spawn(cmd, args, { stdio: ["pipe", "pipe", "pipe"], env });
  const waiters = new Map();
  let nextId = 1;
  let stderr = "";
  child.stderr.on("data", (d) => (stderr += d));
  createInterface({ input: child.stdout }).on("line", (line) => {
    const msg = JSON.parse(line);
    waiters.get(msg.id)?.(msg);
    waiters.delete(msg.id);
  });
  const request = (method, params = {}) =>
    new Promise((resolve) => {
      const id = nextId++;
      waiters.set(id, resolve);
      child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });
  return {
    async init() {
      await request("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "demo", version: "0" } });
      child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
      return (await request("tools/list")).result.tools;
    },
    call: (name, args) => request("tools/call", { name, arguments: args }).then((m) => m.result),
    close: () => { child.stdin.end(); child.kill(); },
    get stderr() { return stderr; },
  };
}
