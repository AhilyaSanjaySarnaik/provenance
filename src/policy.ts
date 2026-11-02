import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { paths } from "./paths.js";

export type Action = "block" | "allow" | "log";

export interface Policy {
  /** Tools whose OUTPUT is untrusted (web pages, email, issues, other agents). Glob patterns on tool name. */
  sources: string[];
  /** Tools whose CALL has side effects worth guarding (send, pay, write, exec, delete). */
  sinks: string[];
  /** What to do when a sink call's arguments contain data that came from an untrusted source. */
  onTainted: Action;
  /** What to do when a sink is called after a source returned content that looks like a prompt injection. */
  onExposedToInjection: Action;
  /** How long (minutes) untrusted content stays "live" in the session for taint purposes. */
  windowMinutes: number;
  /** Indicators you trust even if they also appear in untrusted content, e.g. "email:me@mycompany.com". */
  allowIndicators: string[];
  /** What to do when an MCP server silently changes a tool's description or schema (rug pull). */
  onToolDrift: "block" | "log";
  /** Per-server overrides keyed by server name passed to `provenance wrap --name`. */
  servers?: Record<string, Partial<Pick<Policy, "sources" | "sinks">>>;
}

export const DEFAULT_POLICY: Policy = {
  sources: [
    "fetch*", "*browse*", "*scrape*", "*crawl*", "*web*", "*search*", "*url*", "*page*",
    "*email*", "*mail*", "*inbox*", "*message*", "*slack*", "*discord*",
    "*issue*", "*comment*", "*pull_request*", "*ticket*",
    "read_file", "read_text_file", "*document*", "*pdf*",
  ],
  sinks: [
    "send*", "*post*", "*reply*", "*publish*", "*upload*",
    "*exec*", "*shell*", "*run*", "*command*", "*terminal*", "*eval*",
    "write*", "*edit*", "*delete*", "*remove*", "*move*", "*create*", "*update*", "*push*", "*merge*",
    "*pay*", "*transfer*", "*transaction*", "*invoice*", "*order*", "*purchase*",
    "*http_request*", "*webhook*",
  ],
  onTainted: "block",
  onExposedToInjection: "block",
  windowMinutes: 60,
  allowIndicators: [],
  onToolDrift: "block",
};

export function loadPolicy(): Policy {
  if (!existsSync(paths.policy)) return DEFAULT_POLICY;
  const user = JSON.parse(readFileSync(paths.policy, "utf8")) as Partial<Policy>;
  return { ...DEFAULT_POLICY, ...user };
}

export function writeDefaultPolicy(): string {
  if (!existsSync(paths.policy)) {
    writeFileSync(paths.policy, JSON.stringify(DEFAULT_POLICY, null, 2) + "\n");
  }
  return paths.policy;
}

function globToRegex(glob: string): RegExp {
  const esc = glob.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
  return new RegExp(`^${esc}$`, "i");
}

export function matches(name: string, patterns: string[]): boolean {
  return patterns.some((p) => globToRegex(p).test(name));
}

export function classify(policy: Policy, server: string, tool: string): { source: boolean; sink: boolean } {
  const o = policy.servers?.[server];
  const sources = o?.sources ?? policy.sources;
  const sinks = o?.sinks ?? policy.sinks;
  const sink = matches(tool, sinks);
  // A side-effecting tool (send_email) isn't an untrusted *source* just because its name says "email";
  // only treat sinks as sources when explicitly listed by exact name.
  const source = sink ? sources.some((p) => p.toLowerCase() === tool.toLowerCase()) : matches(tool, sources);
  return { source, sink };
}
