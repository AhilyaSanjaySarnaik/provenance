/**
 * `provenance scan`: find every MCP / agent config on this machine and in this repo,
 * and flag the setups attackers are actively abusing.
 */
import { existsSync, readFileSync, statSync } from "node:fs";
import { homedir, platform } from "node:os";
import { join, resolve } from "node:path";

export type Severity = "high" | "medium" | "low" | "info";

export interface Finding {
  severity: Severity;
  file: string;
  server?: string;
  rule: string;
  message: string;
  fix?: string;
}

interface ServerCfg {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  type?: string;
  headers?: Record<string, string>;
}

export function candidateConfigs(cwd = process.cwd()): { path: string; scope: "user" | "project" }[] {
  const h = homedir();
  const appData = process.env.APPDATA ?? join(h, "AppData", "Roaming");
  const user = [
    join(h, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
    join(h, ".config", "Claude", "claude_desktop_config.json"),
    join(appData, "Claude", "claude_desktop_config.json"),
    join(h, ".claude.json"),
    join(h, ".claude", "settings.json"),
    join(h, ".cursor", "mcp.json"),
    join(h, ".codeium", "windsurf", "mcp_config.json"),
    join(h, ".gemini", "settings.json"),
    join(h, ".codex", "config.toml"),
    join(h, "Library", "Application Support", "Code", "User", "mcp.json"),
    join(h, ".config", "Code", "User", "mcp.json"),
    join(appData, "Code", "User", "mcp.json"),
  ];
  const project = [".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".gemini/settings.json", ".claude/settings.json"]
    .map((p) => resolve(cwd, p));
  return [
    ...user.map((path) => ({ path, scope: "user" as const })),
    ...project.map((path) => ({ path, scope: "project" as const })),
  ].filter((c, i, a) => a.findIndex((x) => x.path === c.path) === i && existsSync(c.path));
}

/** Collect servers from the various shapes different clients use. */
function serversFrom(json: any): Record<string, ServerCfg> {
  const out: Record<string, ServerCfg> = {};
  const add = (obj: any, prefix = "") => {
    if (obj && typeof obj === "object") for (const [k, v] of Object.entries(obj)) out[prefix + k] = v as ServerCfg;
  };
  add(json?.mcpServers);
  add(json?.servers); // VS Code
  add(json?.mcp?.servers);
  if (json?.projects && typeof json.projects === "object") {
    for (const [proj, cfg] of Object.entries<any>(json.projects)) add(cfg?.mcpServers, `${proj.split(/[\\/]/).pop()}:`);
  }
  return out;
}

function tomlServers(text: string): Record<string, ServerCfg> {
  // Minimal parse of [mcp_servers.NAME] tables in Codex config.toml.
  const out: Record<string, ServerCfg> = {};
  const re = /^\[mcp_servers\.([^\]]+)\]\s*$([\s\S]*?)(?=^\[|$(?![\s\S]))/gm;
  for (const m of text.matchAll(re)) {
    const body = m[2];
    const cmd = body.match(/^command\s*=\s*"([^"]*)"/m)?.[1];
    const args = body.match(/^args\s*=\s*\[([^\]]*)\]/m)?.[1]?.match(/"([^"]*)"/g)?.map((s) => s.slice(1, -1));
    const env: Record<string, string> = {};
    for (const e of body.matchAll(/^\s*([A-Z0-9_]+)\s*=\s*"([^"]*)"/gm)) env[e[1]] = e[2];
    out[m[1]] = { command: cmd, args, env };
  }
  return out;
}

const SECRET_VALUE = [
  /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}/, /\bgh[pousr]_[A-Za-z0-9]{30,}/, /\bgithub_pat_[A-Za-z0-9_]{40,}/,
  /\bAKIA[0-9A-Z]{16}\b/, /\bxox[baprs]-[A-Za-z0-9-]{10,}/, /\bAIza[0-9A-Za-z_-]{35}\b/,
  /\bglpat-[A-Za-z0-9_-]{20,}/, /\bnpm_[A-Za-z0-9]{36}\b/, /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
];
const SECRET_NAME = /(token|secret|password|passwd|api[_-]?key|private[_-]?key|credential|auth)/i;
const LAUNCHERS = new Set(["npx", "npx.cmd", "bunx", "pnpm", "uvx", "pipx", "dlx", "yarn"]);
const SHELLS = /^(bash|sh|zsh|cmd(\.exe)?|powershell(\.exe)?|pwsh)$/i;

export function auditServer(file: string, scope: "user" | "project", name: string, s: ServerCfg, fileMode?: number): Finding[] {
  const f: Finding[] = [];
  const push = (severity: Severity, rule: string, message: string, fix?: string) => f.push({ severity, file, server: name, rule, message, fix });
  const cmd = (s.command ?? "").split(/[\\/]/).pop() ?? "";
  const args = s.args ?? [];
  const all = [s.command ?? "", ...args, ...Object.values(s.env ?? {}), ...Object.values(s.headers ?? {}), s.url ?? ""].join(" ");

  // 1. Plaintext secrets
  const leaked = SECRET_VALUE.some((r) => r.test(all));
  const namedSecrets = Object.entries({ ...(s.env ?? {}), ...(s.headers ?? {}) })
    .filter(([k, v]) => SECRET_NAME.test(k) && v && !/^\$\{?[A-Z_]+\}?$/.test(v) && !v.startsWith("${env:") && v.length >= 8);
  if (leaked || namedSecrets.length) {
    const readable = fileMode !== undefined && (fileMode & 0o044) !== 0;
    push(readable || scope === "project" ? "high" : "medium", "plaintext-secret",
      `Credential stored in plaintext${namedSecrets.length ? ` (${namedSecrets.map(([k]) => k).join(", ")})` : ""}. Infostealers now target AI tool configs directly.`
        + (scope === "project" ? " This file lives in a repo and may be committed." : "")
        + (readable ? " File is readable by other users." : ""),
      "Reference an environment variable or OS keychain instead, and rotate the exposed key.");
  }

  // 2. Unpinned package launchers: whoever controls the latest version runs code on your machine.
  if (LAUNCHERS.has(cmd)) {
    const pkg = args.find((a) => !a.startsWith("-") && !["exec", "dlx", "run", "x"].includes(a));
    if (pkg && !/@[\d^~<>=]/.test(pkg.replace(/^@[^/]+\//, "")) && !/==|@\d/.test(pkg)) {
      push("medium", "unpinned-package", `Runs "${pkg}" at whatever version is latest on every launch. A single compromised release (npm/PyPI worms hit 1,000+ packages this year) executes with your privileges.`,
        `Pin an exact version, e.g. "${pkg}@1.2.3".`);
    }
  }

  // 3. Shell as the server command
  if (SHELLS.test(cmd) && args.some((a) => /^-c$|^\/c$|-Command/i.test(a))) {
    push("medium", "shell-wrapper", "Server is launched through a shell one-liner; easy to hide extra commands here.", "Call the server binary directly.");
  }

  // 4. Remote servers
  if (s.url) {
    if (/^http:\/\//i.test(s.url) && !/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])/i.test(s.url)) {
      push("high", "cleartext-remote", `Remote MCP server over unencrypted HTTP: ${s.url}`, "Use https://.");
    } else {
      push("info", "remote-server", `Remote MCP server ${s.url}: tool definitions can change server-side at any time.`, "Pin tool definitions with `provenance wrap` or review on change.");
    }
  }

  // 5. Broad filesystem reach
  if (/filesystem|file-?system|fs-server/i.test(all)) {
    const roots = args.filter((a) => a.startsWith("/") || /^[A-Z]:\\/i.test(a) || a.startsWith("~"));
    if (roots.some((r) => ["/", "~", homedir(), "C:\\", "/Users", "/home"].includes(r.replace(/[\\/]+$/, "") || "/"))) {
      push("high", "broad-filesystem", `Filesystem server can reach ${roots.join(", ")}, including SSH keys, cloud creds and other agents' configs.`,
        "Scope it to the project directory only.");
    }
  }

  // 6. Project-scoped configs execute when you open a repo
  if (scope === "project" && s.command) {
    push("medium", "repo-defined-server", `Repository config launches a local command (${s.command}). Cloning and opening an untrusted repo can run this.`,
      "Only approve project MCP servers from repos you trust; review this file in PRs.");
  }

  // 7. Not guarded
  if (s.command && !/provenance/.test(all)) {
    push("info", "unguarded", "Not wrapped by provenance: tool calls are not taint-checked or audited.",
      `"command": "npx", "args": ["-y", "agent-provenance", "wrap", "--name", "${name}", "--", ${[s.command, ...args].map((a) => JSON.stringify(a)).join(", ")}]`);
  }
  return f;
}

export function scan(cwd = process.cwd()): { files: string[]; servers: number; findings: Finding[] } {
  const findings: Finding[] = [];
  const files: string[] = [];
  let servers = 0;
  for (const { path, scope } of candidateConfigs(cwd)) {
    let text: string;
    try { text = readFileSync(path, "utf8"); } catch { continue; }
    files.push(path);
    const mode = platform() === "win32" ? undefined : statSync(path).mode;
    let srv: Record<string, ServerCfg> = {};
    if (path.endsWith(".toml")) srv = tomlServers(text);
    else {
      try { srv = serversFrom(JSON.parse(text)); } catch { findings.push({ severity: "low", file: path, rule: "parse-error", message: "Could not parse config as JSON." }); continue; }
    }
    for (const [name, cfg] of Object.entries(srv)) {
      servers++;
      findings.push(...auditServer(path, scope, name, cfg, mode));
    }
  }
  return { files, servers, findings };
}
