/**
 * Tamper-evident, signed event ledger.
 *
 * Every event is appended as one JSON line containing:
 *   prev  - hash of the previous entry (hash chain, so deletions/edits are detectable)
 *   hash  - sha256 over the canonical entry body
 *   sig   - Ed25519 signature of `hash` with the local signing key
 *
 * Several proxy processes (one per wrapped MCP server) share one ledger, which is
 * what lets taint flow across servers: content fetched by the web server can be
 * recognised in a call made to the email server.
 */
import {
  createHash, generateKeyPairSync, sign, verify, createPrivateKey, createPublicKey, randomUUID,
} from "node:crypto";
import {
  appendFileSync, existsSync, readFileSync, writeFileSync, openSync, closeSync, unlinkSync, statSync, linkSync,
} from "node:fs";
import { paths } from "./paths.js";

export type EventType =
  | "source_ingest"   // untrusted content entered the agent's context
  | "sink_allowed"    // a side-effecting call went through (this is the "intent receipt")
  | "sink_blocked"    // a side-effecting call was stopped
  | "approval"        // a human approved a previously blocked call
  | "tool_drift"      // an MCP server changed a tool's definition since first seen (rug pull)
  | "session_start";

export interface LedgerEvent {
  id: string;
  ts: number;
  type: EventType;
  server: string;
  tool?: string;
  data: Record<string, unknown>;
}

export interface LedgerEntry extends LedgerEvent {
  prev: string;
  hash: string;
  sig: string;
}

export function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") {
    const keys = Object.keys(v as object).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical((v as any)[k])}`).join(",")}}`;
  }
  return JSON.stringify(v);
}

export function sha256(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

function ensureKeys(): void {
  if (existsSync(paths.key)) return;
  // Several proxies may start at once: write to a temp file, then hard-link into place.
  // link() fails if the key already exists, so exactly one key ever wins.
  const { privateKey } = generateKeyPairSync("ed25519");
  const tmp = `${paths.key}.${process.pid}.tmp`;
  writeFileSync(tmp, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  try { linkSync(tmp, paths.key); } catch { /* another process won */ }
  unlinkSync(tmp);
}

function privateKey() {
  ensureKeys();
  return createPrivateKey(readFileSync(paths.key));
}

export function publicKeyPem(): string {
  const pem = createPublicKey(privateKey()).export({ type: "spki", format: "pem" }).toString();
  if (!existsSync(paths.pubkey)) writeFileSync(paths.pubkey, pem);
  return pem;
}

function withLock<T>(fn: () => T): T {
  const deadline = Date.now() + 5000;
  for (;;) {
    try {
      const fd = openSync(paths.lock, "wx");
      closeSync(fd);
      break;
    } catch {
      // Break stale locks left by a crashed process.
      try { if (Date.now() - statSync(paths.lock).mtimeMs > 10_000) unlinkSync(paths.lock); } catch {}
      if (Date.now() > deadline) throw new Error("provenance: could not acquire ledger lock");
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);
    }
  }
  try { return fn(); } finally { try { unlinkSync(paths.lock); } catch {} }
}

function lastHash(): string {
  if (!existsSync(paths.ledger)) return "genesis";
  const text = readFileSync(paths.ledger, "utf8").trimEnd();
  if (!text) return "genesis";
  const last = text.slice(text.lastIndexOf("\n") + 1);
  return (JSON.parse(last) as LedgerEntry).hash;
}

export function append(ev: Omit<LedgerEvent, "id" | "ts"> & Partial<Pick<LedgerEvent, "id" | "ts">>): LedgerEntry {
  const key = privateKey();
  return withLock(() => {
    const body: LedgerEvent & { prev: string } = {
      id: ev.id ?? randomUUID().slice(0, 8),
      ts: ev.ts ?? Date.now(),
      type: ev.type,
      server: ev.server,
      ...(ev.tool ? { tool: ev.tool } : {}),
      data: ev.data,
      prev: lastHash(),
    };
    const hash = sha256(canonical(body));
    const sig = sign(null, Buffer.from(hash, "hex"), key).toString("base64");
    const entry: LedgerEntry = { ...body, hash, sig };
    appendFileSync(paths.ledger, JSON.stringify(entry) + "\n", { mode: 0o600 });
    return entry;
  });
}

export function readAll(): LedgerEntry[] {
  if (!existsSync(paths.ledger)) return [];
  return readFileSync(paths.ledger, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l) as LedgerEntry);
}

export function readSince(sinceMs: number): LedgerEntry[] {
  return readAll().filter((e) => e.ts >= sinceMs);
}

export interface VerifyResult { ok: boolean; count: number; error?: string; at?: number }

export function verifyLedger(pubPem = publicKeyPem()): VerifyResult {
  const pub = createPublicKey(pubPem);
  const entries = readAll();
  let prev = "genesis";
  for (let i = 0; i < entries.length; i++) {
    const { hash, sig, ...body } = entries[i];
    if (body.prev !== prev) return { ok: false, count: entries.length, at: i, error: "hash chain broken (entry removed, reordered or inserted)" };
    if (sha256(canonical(body)) !== hash) return { ok: false, count: entries.length, at: i, error: "entry contents were modified" };
    if (!verify(null, Buffer.from(hash, "hex"), pub, Buffer.from(sig, "base64"))) {
      return { ok: false, count: entries.length, at: i, error: "signature invalid" };
    }
    prev = hash;
  }
  return { ok: true, count: entries.length };
}
