#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { append, readAll, readSince, verifyLedger, publicKeyPem, withLock } from "./ledger.js";
import { runProxy } from "./proxy.js";
import { scan, type Severity } from "./scan.js";
import { writeDefaultPolicy } from "./policy.js";
import { paths } from "./paths.js";

const tty = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code: number) => (s: string) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
const red = c(31), yellow = c(33), green = c(32), dim = c(2), bold = c(1), cyan = c(36);

const HELP = `${bold("provenance")} - intent provenance for AI agents

${bold("Usage")}
  provenance scan [--json]                 Audit MCP/agent configs on this machine and repo
  provenance wrap --name <n> -- <cmd...>   Run an MCP server behind the provenance guard
  provenance log [-n 20] [--json]          Show recent agent actions, blocks and untrusted inputs
  provenance approve <id>                  Allow a blocked call (same tool + same args) to run once more
  provenance verify [--checkpoint <c>]     Check the audit log's hash chain, signatures, and an anchored checkpoint
  provenance checkpoint                    Print <count>:<head-hash> to store somewhere the agent host can't write
  provenance repin <server>                Accept changed tool definitions for a server
  provenance init                          Write an editable policy to ~/.provenance/policy.json
  provenance pubkey                        Print the public key that verifies your receipts
`;

function arg(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

const sevColor: Record<Severity, (s: string) => string> = { high: red, medium: yellow, low: cyan, info: dim };
const sevOrder: Severity[] = ["high", "medium", "low", "info"];

function cmdScan() {
  const r = scan();
  if (process.argv.includes("--json")) {
    console.log(JSON.stringify(r, null, 2));
  } else {
    console.log(bold(`\nprovenance scan`) + dim(`  ${r.files.length} config file(s), ${r.servers} MCP server(s)\n`));
    if (!r.files.length) console.log(dim("  No MCP configs found in the usual places.\n"));
    for (const file of r.files) {
      const fs = r.findings.filter((f) => f.file === file).sort((a, b) => sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity));
      console.log(bold(file));
      if (!fs.length) console.log(green("  ok"));
      for (const f of fs) {
        if (f.severity === "info" && !process.argv.includes("--all")) continue;
        console.log(`  ${sevColor[f.severity](f.severity.toUpperCase().padEnd(6))} ${f.server ? cyan(f.server) + " " : ""}${f.message}`);
        if (f.fix) console.log(dim(`         fix: ${f.fix}`));
      }
      console.log();
    }
    const counts = sevOrder.map((s) => `${r.findings.filter((f) => f.severity === s).length} ${s}`).join(", ");
    console.log(`${bold("Summary:")} ${counts}${process.argv.includes("--all") ? "" : dim("  (use --all to show info)")}\n`);
  }
  process.exitCode = r.findings.some((f) => f.severity === "high") ? 2 : 0;
}

function cmdWrap() {
  const sep = process.argv.indexOf("--");
  if (sep < 0 || !process.argv[sep + 1]) {
    console.error("usage: provenance wrap --name <server-name> -- <command> [args...]");
    process.exit(1);
  }
  const [cmd, ...rest] = process.argv.slice(sep + 1);
  const name = arg("--name") ?? cmd;
  runProxy(name, cmd, rest);
}

function fmtTime(ts: number) {
  return new Date(ts).toISOString().replace("T", " ").slice(0, 19);
}

function cmdLog() {
  const n = Number(arg("-n") ?? 20);
  const entries = readAll().slice(-n);
  if (process.argv.includes("--json")) return console.log(JSON.stringify(entries, null, 2));
  for (const e of entries) {
    const head = `${dim(fmtTime(e.ts))} ${dim(e.id)} ${e.server}${e.tool ? "/" + e.tool : ""}`;
    switch (e.type) {
      case "sink_blocked": {
        console.log(`${red("BLOCK ")} ${head}  ${yellow(String(e.data.reason))}${e.data.notification ? dim(" (notification)") : ""}`);
        for (const m of (e.data.matches as any[]) ?? []) {
          console.log(dim(`         carried ${[...m.indicators, ...(m.copiedPhrases ? [`${m.copiedPhrases} phrases`] : [])].join(", ")} from ${m.sourceServer}/${m.sourceTool}`));
        }
        for (const s of (e.data.injectionSources as any[]) ?? []) console.log(dim(`         injection signals in ${s.tool}: ${s.signals.join(", ")}`));
        break;
      }
      case "sink_allowed": console.log(`${green("ALLOW ")} ${head}${e.data.flagged ? yellow("  (flagged)") : ""}${e.data.reason === "approved" ? cyan("  (human-approved)") : ""}`); break;
      case "source_ingest": {
        const inj = (e.data.injection as string[]) ?? [];
        console.log(`${cyan("INPUT ")} ${head}  ${dim(`${e.data.bytes} bytes untrusted`)}${inj.length ? red(`  injection: ${inj.join(", ")}`) : ""}`);
        break;
      }
      case "approval": console.log(`${cyan("APPRV ")} ${head}  approved ${e.data.blockId}`); break;
      case "tool_drift": console.log(`${red("DRIFT ")} ${head}  tool ${e.data.kind === "added" ? "appeared after pinning" : "definition changed"}`); break;
      case "session_start": console.log(`${dim("START  " + fmtTime(e.ts) + " " + e.server + "  " + e.data.cmd)}`); break;
    }
  }
}

function cmdApprove() {
  const id = process.argv[3];
  const blocked = readAll().find((e) => e.id === id && e.type === "sink_blocked");
  if (!blocked) { console.error(`No blocked call with id ${id}. See: provenance log`); process.exit(1); }
  append({ type: "approval", server: blocked.server, tool: blocked.tool, data: { blockId: id, callHash: blocked.data.callHash, by: process.env.USER ?? "user" } });
  console.log(green(`Approved. The agent can retry ${blocked.server}/${blocked.tool} with the same arguments.`));
}

function cmdVerify() {
  const r = verifyLedger(undefined, arg("--checkpoint"));
  for (const w of r.warnings) console.log(yellow(`warning: ${w}`));
  if (r.ok) {
    console.log(green(`OK: ${r.count} entries, hash chain intact, all signatures valid${arg("--checkpoint") ? ", matches checkpoint" : ""}.`));
    if (!arg("--checkpoint")) console.log(dim("Note: this proves integrity against anyone without your signing key. Anchor `provenance checkpoint` output elsewhere to detect full rewrites."));
  } else { console.log(red(`TAMPERED${r.at !== undefined ? ` at entry ${r.at}` : ""}: ${r.error}`)); process.exitCode = 1; }
}

function cmdCheckpoint() {
  const r = verifyLedger();
  if (!r.ok) { console.log(red(`Ledger does not verify (${r.error}); refusing to checkpoint.`)); process.exitCode = 1; return; }
  if (!r.count) { console.log("Ledger is empty."); return; }
  // Print just the token so it can be piped somewhere the agent host can't write (a git repo, a ticket, a remote log).
  console.log(`${r.count}:${r.head}`);
}

function cmdRepin() {
  const server = process.argv[3];
  if (!server) { console.error("usage: provenance repin <server>"); process.exit(1); }
  withLock(() => {
    if (!existsSync(paths.pins)) return console.log("Nothing pinned yet.");
    const pins = JSON.parse(readFileSync(paths.pins, "utf8"));
    delete pins[server];
    writeFileSync(paths.pins, JSON.stringify(pins, null, 2));
    console.log(`Cleared pins for ${server}; current tool definitions will be pinned on next start.`);
  });
}

const commands: Record<string, () => void> = {
  scan: cmdScan,
  wrap: cmdWrap,
  log: cmdLog,
  approve: cmdApprove,
  verify: cmdVerify,
  checkpoint: cmdCheckpoint,
  repin: cmdRepin,
  init: () => console.log(`Policy written to ${writeDefaultPolicy()}`),
  pubkey: () => process.stdout.write(publicKeyPem()),
  status: () => {
    const recent = readSince(Date.now() - 3600_000);
    console.log(`last hour: ${recent.filter((e) => e.type === "sink_blocked").length} blocked, ${recent.filter((e) => e.type === "sink_allowed").length} allowed, ${recent.filter((e) => e.type === "source_ingest").length} untrusted inputs`);
  },
};

const fn = commands[process.argv[2] ?? ""];
if (!fn) { console.log(HELP); process.exitCode = process.argv[2] ? 1 : 0; }
else fn();
