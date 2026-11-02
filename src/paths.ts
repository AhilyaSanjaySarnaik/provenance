import { homedir } from "node:os";
import { join } from "node:path";
import { mkdirSync } from "node:fs";

export function home(): string {
  const dir = process.env.PROVENANCE_HOME || join(homedir(), ".provenance");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  return dir;
}

export const paths = {
  get ledger() { return join(home(), "ledger.jsonl"); },
  get key() { return join(home(), "signing-key.pem"); },
  get pubkey() { return join(home(), "signing-key.pub.pem"); },
  get pins() { return join(home(), "pins.json"); },
  get policy() { return join(home(), "policy.json"); },
  get lock() { return join(home(), "ledger.lock"); },
};
