/**
 * Taint extraction and matching.
 *
 * When untrusted content enters the agent (a web page, an email, an issue comment),
 * we fingerprint it: concrete indicators (URLs, emails, hostnames, IPs, wallet-like
 * strings, shell commands) plus hashed word shingles for longer copied text.
 *
 * When the agent later tries a side-effecting call, we fingerprint the arguments the
 * same way. Overlap means the action is carrying data that came from an untrusted
 * source - the classic shape of a prompt-injection exfiltration or hijack.
 *
 * Both sides are normalised the same way: Unicode NFKC, IDN/punycode -> Unicode,
 * common Cyrillic/Greek homoglyphs -> Latin, and one decoding pass over base64,
 * hex and percent-encoded runs. So "аpple.com" (Cyrillic а), "xn--pple-43d.com"
 * and "YXBwbGUuY29t" all fingerprint like "apple.com".
 */
import { domainToUnicode } from "node:url";
import { sha256 } from "./ledger.js";

export interface Fingerprint {
  indicators: string[];
  shingles: string[]; // truncated sha256 of 6-token windows, stride 1
}

// --- normalisation -----------------------------------------------------------

/** Characters that render (near-)identically to Latin letters. Covers the common IDN-spoofing set. */
const CONFUSABLES: Record<string, string> = {
  // Cyrillic
  "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p", "с": "c",
  "т": "t", "у": "y", "х": "x", "ѕ": "s", "і": "i", "ї": "i", "ј": "j", "һ": "h", "ԁ": "d", "ӏ": "l",
  "ԛ": "q", "ԝ": "w", "ɡ": "g", "ь": "b",
  // Greek
  "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t",
  "υ": "u", "χ": "x", "ω": "w",
  // Latin lookalikes and digits used as letters in domains are deliberately NOT folded (0/o, 1/l):
  // too many legitimate hosts differ only by those.
};

export function skeleton(s: string): string {
  return [...s.normalize("NFKC").toLowerCase()].map((c) => CONFUSABLES[c] ?? c).join("");
}

/** Canonical comparable form of a hostname: punycode decoded, NFKC, homoglyphs folded, no trailing dot. */
export function normHost(host: string): string {
  let h = host.toLowerCase().replace(/\.$/, "");
  if (h.split(".").some((l) => l.startsWith("xn--"))) {
    const u = domainToUnicode(h);
    if (u) h = u;
  }
  return skeleton(h);
}

function printableRatio(s: string): number {
  if (!s.length) return 0;
  let ok = 0;
  for (const ch of s) if (/[\p{L}\p{N}\p{P}\p{Zs}\n\t]/u.test(ch) || /[$+<=>^`|~]/.test(ch)) ok++;
  return ok / [...s].length;
}

/**
 * One decoding pass over encoded-looking runs. Returns decoded strings worth fingerprinting.
 * One pass, not recursive: cheap, and catches the obvious "base64 the secret" bypass.
 */
export function decodedVariants(text: string): string[] {
  const out: string[] = [];
  const consider = (s: string) => { if (s.length >= 4 && printableRatio(s) > 0.9) out.push(s); };

  for (const run of text.match(/[A-Za-z0-9+/_-]{16,}={0,2}/g) ?? []) {
    try {
      const b64 = run.replace(/-/g, "+").replace(/_/g, "/");
      const dec = Buffer.from(b64, "base64").toString("utf8");
      if (!dec.includes("�")) consider(dec);
    } catch {}
  }
  for (const run of text.match(/\b(?:[0-9a-fA-F]{2}){8,}\b/g) ?? []) {
    const dec = Buffer.from(run, "hex").toString("utf8");
    if (!dec.includes("�")) consider(dec);
  }
  if (/%[0-9a-fA-F]{2}/.test(text)) {
    for (const run of text.match(/[^\s"']*%[0-9a-fA-F]{2}[^\s"']*/g) ?? []) {
      try { consider(decodeURIComponent(run)); } catch {}
    }
  }
  return out;
}

// --- extraction --------------------------------------------------------------

const LABEL = "[\\p{L}\\p{N}](?:[\\p{L}\\p{N}-]{0,61}[\\p{L}\\p{N}])?";
const TLD = "(?:[\\p{L}]{2,24}|xn--[a-z0-9-]{2,59})";
const HOST_RE = new RegExp(`(?<![\\p{L}\\p{N}._-])(?:${LABEL}\\.)+${TLD}(?![\\p{L}\\p{N}-])`, "giu");
const RE = {
  url: /\bhttps?:\/\/[^\s"'<>)\]]+/giu,
  email: /(?<![\p{L}\p{N}._%+-])[\p{L}\p{N}._%+-]+@(?:[\p{L}\p{N}-]+\.)+[\p{L}]{2,24}(?![\p{L}\p{N}-])/giu,
  ipv4: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
  wallet: /\b(?:0x[a-fA-F0-9]{40}|bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g,
  iban: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g,
  shell: /\b(?:curl|wget|bash|sh|powershell|nc|python3?)\s+[^\n]{4,}/gi,
};

// File-extension-like "TLDs" that are almost always not hostnames.
const NOT_TLDS = new Set(["js", "ts", "py", "md", "json", "txt", "html", "css", "png", "jpg", "jpeg", "gif", "svg", "pdf", "zip", "gz", "tar", "exe", "dll", "so", "log", "yml", "yaml", "toml", "lock", "sh", "rs", "go", "java", "rb", "php", "c", "h", "cpp", "mjs", "cjs", "tsx", "jsx", "env", "pem", "key", "csv", "xml"]);

// Indicators so common they'd cause false positives.
const IGNORE_HOSTS = new Set(["example.com", "localhost", "github.com", "google.com", "www.google.com", "w3.org", "www.w3.org", "schema.org"]);
const IGNORE = new Set(["ipv4:127.0.0.1", "ipv4:0.0.0.0"]);

/** Tokenise on Unicode letters/numbers. CJK/kana/hangul have no spaces, so each character is a token. */
function tokens(text: string): string[] {
  return skeleton(text)
    .replace(/([\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}])/gu, " $1 ")
    .split(/[^\p{L}\p{N}@._/-]+/u)
    .filter((w) => w.length > 1 || /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}]/u.test(w));
}

function hostOf(kind: string, value: string): string | undefined {
  if (kind === "url") { try { return new URL(value).hostname; } catch { return undefined; } }
  if (kind === "email") return value.slice(value.lastIndexOf("@") + 1);
  return undefined;
}

function extract(text: string, ind: Set<string>) {
  const addHost = (h: string | undefined) => {
    if (!h) return;
    const n = normHost(h);
    const tld = n.slice(n.lastIndexOf(".") + 1);
    if (!n.includes(".") || NOT_TLDS.has(tld) || IGNORE_HOSTS.has(n) || /^[\d.]+$/.test(n)) return;
    ind.add(`host:${n}`);
  };
  for (const [kind, re] of Object.entries(RE)) {
    for (const m of text.match(re) ?? []) {
      const v = (kind === "wallet" || kind === "iban" ? m : m.toLowerCase()).replace(/[.,;:]+$/, "");
      if (IGNORE.has(`${kind}:${v}`)) continue;
      if (kind === "email") ind.add(`email:${skeleton(v.slice(0, v.lastIndexOf("@") + 1))}${normHost(v.slice(v.lastIndexOf("@") + 1))}`);
      else if (kind !== "url") ind.add(`${kind}:${v}`);
      addHost(hostOf(kind, v));
    }
  }
  for (const m of text.match(HOST_RE) ?? []) addHost(m);
}

export function fingerprint(text: string): Fingerprint {
  const variants = [text, ...decodedVariants(text)];
  const ind = new Set<string>();
  const sh = new Set<string>();
  for (const v of variants) {
    extract(v, ind);
    const w = tokens(v);
    for (let i = 0; i + 6 <= w.length; i++) sh.add(sha256(w.slice(i, i + 6).join(" ")).slice(0, 16));
  }
  return { indicators: [...ind], shingles: [...sh] };
}

// --- matching ----------------------------------------------------------------

export interface TaintMatch {
  sourceEventId: string;
  sourceServer: string;
  sourceTool: string;
  sourceTs: number;
  indicators: string[];
  copiedPhrases: number;
}

/** Same host, or one is a subdomain of the other on a label boundary (a.evil.com ~ evil.com, NOT notevil.com). */
export function hostsRelated(a: string, b: string): boolean {
  if (a === b) return true;
  const [long, short] = a.length > b.length ? [a, b] : [b, a];
  return short.includes(".") && long.endsWith("." + short);
}

export function matchTaint(
  args: Fingerprint,
  sources: { id: string; server: string; tool?: string; ts: number; fp: Fingerprint }[],
  userTrusted: Set<string> = new Set(),
): TaintMatch[] {
  const out: TaintMatch[] = [];
  const trustedHosts = [...userTrusted].filter((t) => t.startsWith("host:")).map((t) => normHost(t.slice(5)));
  const isTrustedHost = (h: string) => trustedHosts.some((t) => h === t || h.endsWith("." + t));
  const argInd = args.indicators.filter((i) => !userTrusted.has(i.toLowerCase()));
  const argHosts = argInd.filter((i) => i.startsWith("host:")).map((i) => i.slice(5))
    .filter((h) => !isTrustedHost(h));
  // An email at a trusted host is trusted too ("host:vendor.io" covers help@vendor.io).
  const argExact = new Set(argInd.filter((i) => !i.startsWith("host:") && !(i.startsWith("email:") && isTrustedHost(i.slice(i.lastIndexOf("@") + 1)))));
  const argSh = new Set(args.shingles);
  for (const s of sources) {
    const ind = s.fp.indicators.filter((i) =>
      i.startsWith("host:") ? argHosts.some((h) => hostsRelated(h, i.slice(5))) : argExact.has(i));
    const copied = s.fp.shingles.filter((h) => argSh.has(h)).length;
    if (ind.length || copied >= 2) {
      out.push({ sourceEventId: s.id, sourceServer: s.server, sourceTool: s.tool ?? "?", sourceTs: s.ts, indicators: ind, copiedPhrases: copied });
    }
  }
  return out;
}

// --- injection heuristics ----------------------------------------------------

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
  for (const v of [text, ...decodedVariants(text)]) {
    for (const [re, label] of INJECTION_PATTERNS) if (re.test(v)) hits.add(label);
  }
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
