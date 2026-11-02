/**
 * Taint extraction and matching.
 *
 * When untrusted content enters the agent (a web page, an email, an issue comment),
 * we fingerprint it: concrete indicators (URLs, emails, domains, IPs, wallet-like
 * strings, shell commands) plus hashed word shingles for longer copied text.
 *
 * When the agent later tries a side-effecting call, we fingerprint the arguments the
 * same way. Overlap means the action is carrying data that came from an untrusted
 * source - the classic shape of a prompt-injection exfiltration or hijack.
 */
import { sha256 } from "./ledger.js";

export interface Fingerprint {
  indicators: string[];
  shingles: string[]; // truncated sha256 of 6-word windows
}

const RE = {
  url: /\bhttps?:\/\/[^\s"'<>)\]]+/gi,
  email: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
  domain: /\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ai|dev|app|xyz|ru|cn|co|me|sh|site|online|top|info|biz|cloud|tk|link)\b/gi,
  ipv4: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
  wallet: /\b(?:0x[a-fA-F0-9]{40}|bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g,
  iban: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g,
  shell: /(?:curl|wget|bash|sh|powershell|nc|python3?)\s+[^\n]{4,}/gi,
};

// Indicators so common they'd cause false positives.
const IGNORE = new Set(["example.com", "localhost", "127.0.0.1", "0.0.0.0", "github.com", "google.com"]);

function words(text: string): string[] {
  return text.toLowerCase().replace(/[^a-z0-9@._/-]+/g, " ").split(" ").filter((w) => w.length > 1);
}

export function fingerprint(text: string): Fingerprint {
  const ind = new Set<string>();
  for (const [kind, re] of Object.entries(RE)) {
    for (const m of text.match(re) ?? []) {
      const v = m.toLowerCase().replace(/[.,;:]+$/, "");
      if (IGNORE.has(v)) continue;
      if (kind === "domain" && [...ind].some((i) => i.includes(v))) continue;
      ind.add(`${kind}:${v}`);
    }
  }
  const w = words(text);
  const sh = new Set<string>();
  for (let i = 0; i + 6 <= w.length; i++) sh.add(sha256(w.slice(i, i + 6).join(" ")).slice(0, 16));
  return { indicators: [...ind], shingles: [...sh] };
}

export interface TaintMatch {
  sourceEventId: string;
  sourceServer: string;
  sourceTool: string;
  sourceTs: number;
  indicators: string[];
  copiedPhrases: number;
}

export function matchTaint(
  args: Fingerprint,
  sources: { id: string; server: string; tool?: string; ts: number; fp: Fingerprint }[],
  userTrusted: Set<string> = new Set(),
): TaintMatch[] {
  const out: TaintMatch[] = [];
  const argInd = new Set(args.indicators.filter((i) => !userTrusted.has(i)));
  const argSh = new Set(args.shingles);
  for (const s of sources) {
    const ind = s.fp.indicators.filter((i) => argInd.has(i) || (i.startsWith("domain:") && [...argInd].some((a) => a.includes(i.slice(7)))));
    const copied = s.fp.shingles.filter((h) => argSh.has(h)).length;
    if (ind.length || copied >= 2) {
      out.push({ sourceEventId: s.id, sourceServer: s.server, sourceTool: s.tool ?? "?", sourceTs: s.ts, indicators: ind, copiedPhrases: copied });
    }
  }
  return out;
}

/** Heuristic signals that a piece of untrusted content is trying to instruct the agent. */
const INJECTION_PATTERNS: [RegExp, string][] = [
  [/ignore (all |any )?(the )?(previous|prior|above|earlier) (instructions|prompts|messages)/i, "override-instructions"],
  [/disregard (your|all|the) (instructions|rules|guidelines)/i, "override-instructions"],
  [/\b(you are now|from now on,? you|new instructions?:)/i, "role-reassignment"],
  [/\b(system|assistant)\s*(prompt|message)?\s*:/i, "fake-role-marker"],
  [/<\/?(system|instructions?|im_start|im_end)>/i, "fake-role-marker"],
  [/\b(do not|don't|never) (tell|inform|mention|alert|notify) (the )?(user|human|owner)/i, "concealment"],
  [/\b(send|forward|email|post|upload|exfiltrate) (all|the|any|every|this)\b[^.]{0,60}\b(to|at)\b/i, "exfil-directive"],
  [/\b(api[_ -]?key|password|secret|token|credentials?|private key|seed phrase)s?\b[^.]{0,40}\b(send|share|post|include|paste)/i, "credential-request"],
  [/\b(send|share|post|include|paste)\b[^.]{0,40}\b(api[_ -]?key|password|secret|token|credentials?|private key|seed phrase)/i, "credential-request"],
  [/[​-‏⁠-⁤﻿]/, "invisible-characters"],
  [/[\u{E0000}-\u{E007F}]/u, "unicode-tag-smuggling"],
];

export function detectInjection(text: string): string[] {
  const hits = new Set<string>();
  for (const [re, label] of INJECTION_PATTERNS) if (re.test(text)) hits.add(label);
  return [...hits];
}

/** Pull all human-readable text out of an MCP tool result. */
export function resultText(result: unknown): string {
  const parts: string[] = [];
  const r = result as { content?: unknown[]; structuredContent?: unknown };
  for (const c of r?.content ?? []) {
    const item = c as { type?: string; text?: string; resource?: { text?: string } };
    if (item.text) parts.push(item.text);
    if (item.resource?.text) parts.push(item.resource.text);
  }
  if (r?.structuredContent) parts.push(JSON.stringify(r.structuredContent));
  return parts.join("\n");
}
