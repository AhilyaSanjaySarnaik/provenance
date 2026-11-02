/**
 * Tamper-evident, signed event ledger.
 *
 * Every event is appended as one JSON line containing:
 *   prev  - hash of the previous entry (hash chain, so deletions/edits are detectable)
 *   hash  - sha256 over the canonical entry body
 *   sig   - Ed25519 signature of `hash` with the local signing key
 *
 * Several proxy processes (one per wrapped MCP server) share one ledger, which is
 * what lets taint flow across servers.
 *
 * What the chain does and does not prove: see "Threat model" in README. In short, it
 * detects edits made by anything that does NOT hold the signing key. An attacker with
 * write access to ~/.provenance can rewrite the whole chain; `checkpoint` lets you
 * anchor the head hash somewhere they can't reach, which makes that detectable too.
 */
import {
  createHash, generateKeyPairSync, sign, verify, createPrivateKey, createPublicKey, randomUUID,
} from "node:crypto";
import {
  appendFileSync, existsSync, readFileSync, writeFileSync, openSync, closeSync, readSync, fstatSync,
  unlinkSync, statSync, linkSync, renameSync, ftruncateSync,
} from "node:fs";
import { paths } from "./paths.js";

export type EventType =
  | "source_ingest"   // untrusted content entered the agent's context
  | "sink_allowed"    // a side-effecting call went through (this is the "intent receipt")
  | "sink_blocked"    // a side-effecting call was stopped
  | "approval"        // a human approved a previously blocked call
  | "tool_drift"      // an MCP server changed its tools since first seen (rug pull)
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
  /** Bytes of a truncated (crash-interrupted) tail that were discarded before this entry was written. */
  repaired?: number;
}

export function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") {
    const keys = Object.keys(v as object).filter((k) => (v as any)[k] !== undefined).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical((v as any)[k])}`).join(",")}}`;
  }
  return JSON.stringify(v);
}

export function sha256(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

// --- keys --------------------------------------------------------------------

function ensureKeys(): void {
  if (existsSync(paths.key)) return;
  // Several proxies may start at once: write to a temp file, then hard-link into place.
  // link() fails if the key already exists, so exactly one key ever wins.
  const { privateKey } = generateKeyPairSync("ed25519");
  const tmp = `${paths.key}.${process.pid}.${randomUUID()}.tmp`;
  writeFileSync(tmp, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  try { linkSync(tmp, paths.key); } catch { /* another process won */ }
  unlinkSync(tmp);
}

let cachedKey: { path: string; key: ReturnType<typeof createPrivateKey> } | undefined;
function privateKey() {
  ensureKeys();
  if (cachedKey?.path !== paths.key) cachedKey = { path: paths.key, key: createPrivateKey(readFileSync(paths.key)) };
  return cachedKey.key;
}

export function publicKeyPem(): string {
  const pem = createPublicKey(privateKey()).export({ type: "spki", format: "pem" }).toString();
  if (!existsSync(paths.pubkey)) writeFileSync(paths.pubkey, pem);
  return pem;
}

// --- locking -----------------------------------------------------------------

/** A lock older than this whose owner is still alive is assumed wedged and may be broken. */
const LOCK_WEDGED_MS = 5 * 60_000;
const LOCK_TIMEOUT_MS = 10_000;

function sleepSync(ms: number) {
  // Lock hold times are ~1ms (one small append), so contention waits are a few ms.
  // Staying synchronous keeps JSON-RPC message ordering trivially correct.
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function pidAlive(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch (e) { return (e as NodeJS.ErrnoException).code === "EPERM"; }
}

/**
 * Break a stale lock without the classic TOCTOU: we atomically *rename* the lock away,
 * then check that what we took is the same stale lock we inspected. If another process
 * replaced it in between (so we grabbed a live lock), we put it straight back.
 */
function tryBreakStaleLock(): void {
  let content: string;
  let mtime: number;
  try { content = readFileSync(paths.lock, "utf8"); mtime = statSync(paths.lock).mtimeMs; } catch { return; }
  const [pidStr, tsStr] = content.split(":");
  const pid = Number(pidStr), ts = Number(tsStr) || mtime;
  const ownerDead = Number.isInteger(pid) && pid > 0 && !pidAlive(pid);
  const wedged = Date.now() - ts > LOCK_WEDGED_MS;
  if (!ownerDead && !wedged) return;

  const grave = `${paths.lock}.stale.${process.pid}.${randomUUID()}`;
  try { renameSync(paths.lock, grave); } catch { return; } // someone else broke it first
  let taken = "";
  try { taken = readFileSync(grave, "utf8"); } catch {}
  if (taken !== content) {
    // We grabbed a fresh, live lock by mistake. Put it back (link fails if a new lock exists, which is fine).
    try { linkSync(grave, paths.lock); } catch {}
  }
  try { unlinkSync(grave); } catch {}
}

export function withLock<T>(fn: () => T): T {
  const token = `${process.pid}:${Date.now()}:${randomUUID()}`;
  const deadline = Date.now() + LOCK_TIMEOUT_MS;
  for (let attempt = 0; ; attempt++) {
    try {
      writeFileSync(paths.lock, token, { flag: "wx", mode: 0o600 });
      break;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
      if (attempt % 50 === 49) tryBreakStaleLock();
      if (Date.now() > deadline) throw new Error("provenance: could not acquire ledger lock");
      sleepSync(Math.min(1 + attempt, 10));
    }
  }
  try {
    return fn();
  } finally {
    try { if (readFileSync(paths.lock, "utf8") === token) unlinkSync(paths.lock); } catch {}
  }
}

// --- reading -----------------------------------------------------------------

function tryParse(line: string): LedgerEntry | undefined {
  try {
    const e = JSON.parse(line);
    return e && typeof e === "object" && typeof e.hash === "string" ? (e as LedgerEntry) : undefined;
  } catch { return undefined; }
}

/**
 * Walk the ledger backwards from EOF in fixed-size chunks, so recent-window queries
 * cost O(window), not O(ledger). Calls `visit` newest-first; return false to stop.
 * Unparseable lines are skipped (a crash-truncated tail is the expected case).
 */
function scanBackward(visit: (e: LedgerEntry) => boolean): void {
  if (!existsSync(paths.ledger)) return;
  const fd = openSync(paths.ledger, "r");
  try {
    const CHUNK = 64 * 1024;
    let pos = fstatSync(fd).size;
    let carry = Buffer.alloc(0);
    while (pos > 0) {
      const len = Math.min(CHUNK, pos);
      pos -= len;
      const chunk = Buffer.alloc(len);
      readSync(fd, chunk, 0, len, pos);
      let buf = Buffer.concat([chunk, carry]);
      let end = buf.length;
      for (let i = buf.length - 1; i >= 0; i--) {
        if (buf[i] !== 0x0a) continue;
        const line = buf.subarray(i + 1, end).toString("utf8");
        end = i;
        if (line.trim()) { const e = tryParse(line); if (e && !visit(e)) return; }
      }
      carry = buf.subarray(0, end);
    }
    const first = carry.toString("utf8");
    if (first.trim()) { const e = tryParse(first); if (e) visit(e); }
  } finally { closeSync(fd); }
}

export function lastEntry(): LedgerEntry | undefined {
  let last: LedgerEntry | undefined;
  scanBackward((e) => { last = e; return false; });
  return last;
}

/** Entries with ts >= sinceMs, oldest first. Reads only the tail of the file. */
export function readSince(sinceMs: number): LedgerEntry[] {
  const out: LedgerEntry[] = [];
  // Small slack: entries from concurrent writers can be a few ms out of order.
  scanBackward((e) => { if (e.ts >= sinceMs) out.push(e); return e.ts >= sinceMs - 5_000; });
  return out.reverse();
}

export interface ReadResult { entries: LedgerEntry[]; corruptLines: number[]; truncatedTail: boolean }

/** Full forward read, tolerant of bad lines. Used by `log` and `verify`. */
export function readAllDetailed(): ReadResult {
  if (!existsSync(paths.ledger)) return { entries: [], corruptLines: [], truncatedTail: false };
  const text = readFileSync(paths.ledger, "utf8");
  const lines = text.split("\n");
  const endsClean = text.endsWith("\n") || text.length === 0;
  const entries: LedgerEntry[] = [];
  const corruptLines: number[] = [];
  let truncatedTail = false;
  lines.forEach((line, i) => {
    if (!line.trim()) return;
    const e = tryParse(line);
    if (e) entries.push(e);
    else if (i === lines.length - 1 && !endsClean) truncatedTail = true;
    else corruptLines.push(i + 1);
  });
  return { entries, corruptLines, truncatedTail };
}

export function readAll(): LedgerEntry[] {
  return readAllDetailed().entries;
}

// --- writing -----------------------------------------------------------------

/** If a previous writer crashed mid-line, cut the partial line off. Returns bytes removed. Call under lock. */
function repairTruncatedTail(): number {
  if (!existsSync(paths.ledger)) return 0;
  const fd = openSync(paths.ledger, "r+");
  try {
    const size = fstatSync(fd).size;
    if (size === 0) return 0;
    const last = Buffer.alloc(1);
    readSync(fd, last, 0, 1, size - 1);
    if (last[0] === 0x0a) return 0;
    // Find the last newline.
    const CHUNK = 64 * 1024;
    let pos = size;
    while (pos > 0) {
      const len = Math.min(CHUNK, pos);
      pos -= len;
      const buf = Buffer.alloc(len);
      readSync(fd, buf, 0, len, pos);
      const i = buf.lastIndexOf(0x0a);
      if (i >= 0) { ftruncateSync(fd, pos + i + 1); return size - (pos + i + 1); }
    }
    ftruncateSync(fd, 0);
    return size;
  } finally { closeSync(fd); }
}

export function append(ev: Omit<LedgerEvent, "id" | "ts"> & Partial<Pick<LedgerEvent, "id" | "ts">>): LedgerEntry {
  const key = privateKey();
  return withLock(() => {
    const repaired = repairTruncatedTail();
    if (repaired) process.stderr.write(`[provenance] ledger: discarded ${repaired} bytes of a crash-truncated entry\n`);
    const body: Omit<LedgerEntry, "hash" | "sig"> = {
      id: ev.id ?? randomUUID().slice(0, 8),
      ts: ev.ts ?? Date.now(),
      type: ev.type,
      server: ev.server,
      ...(ev.tool ? { tool: ev.tool } : {}),
      data: ev.data,
      prev: lastEntry()?.hash ?? "genesis",
      ...(repaired ? { repaired } : {}),
    };
    const hash = sha256(canonical(body));
    const sig = sign(null, Buffer.from(hash, "hex"), key).toString("base64");
    const entry: LedgerEntry = { ...body, hash, sig } as LedgerEntry;
    appendFileSync(paths.ledger, JSON.stringify(entry) + "\n", { mode: 0o600 });
    return entry;
  });
}

// --- verification ------------------------------------------------------------

export interface VerifyResult {
  ok: boolean;
  count: number;
  error?: string;
  at?: number;
  warnings: string[];
  head?: string;
}

/**
 * Verify signatures and the hash chain.
 * `checkpoint` ("<count>:<hash>", from `provenance checkpoint`) proves the first <count>
 * entries are the same ones you anchored earlier - this is what catches a full rewrite
 * by someone holding the signing key.
 */
export function verifyLedger(pubPem = publicKeyPem(), checkpoint?: string): VerifyResult {
  const pub = createPublicKey(pubPem);
  const { entries, corruptLines, truncatedTail } = readAllDetailed();
  const warnings: string[] = [];
  if (truncatedTail) warnings.push("last line is a crash-truncated partial entry (ignored; repaired on next write)");
  if (corruptLines.length) {
    return { ok: false, count: entries.length, warnings, error: `unparseable line(s) in the middle of the ledger: ${corruptLines.slice(0, 5).join(", ")}` };
  }
  let prev = "genesis";
  for (let i = 0; i < entries.length; i++) {
    const { hash, sig, ...body } = entries[i];
    if (body.prev !== prev) return { ok: false, count: entries.length, at: i, warnings, error: "hash chain broken (entry removed, reordered or inserted)" };
    if (sha256(canonical(body)) !== hash) return { ok: false, count: entries.length, at: i, warnings, error: "entry contents were modified" };
    if (!verify(null, Buffer.from(hash, "hex"), pub, Buffer.from(sig, "base64"))) {
      return { ok: false, count: entries.length, at: i, warnings, error: "signature invalid" };
    }
    prev = hash;
  }
  if (checkpoint) {
    const [nStr, want] = checkpoint.split(":");
    const n = Number(nStr);
    if (!Number.isInteger(n) || n < 1 || !want) return { ok: false, count: entries.length, warnings, error: "malformed checkpoint (expected <count>:<hash>)" };
    if (entries.length < n) return { ok: false, count: entries.length, warnings, error: `ledger has fewer entries (${entries.length}) than the checkpoint (${n}): history was deleted` };
    if (entries[n - 1].hash !== want) return { ok: false, count: entries.length, at: n - 1, warnings, error: "history differs from checkpoint: the ledger was rewritten" };
  }
  return { ok: true, count: entries.length, warnings, head: prev };
}
