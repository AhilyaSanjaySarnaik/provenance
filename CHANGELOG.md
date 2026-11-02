# Changelog

## 0.1.1: security review fixes

Fixes from an external review of `proxy.ts`, `ledger.ts` and `taint.ts`. Each item has a regression test in `test/review-fixes.test.mjs`.

**Bypasses**
- `tools/call` sent as a JSON-RPC notification (no `id`) skipped every check. Calls are now checked regardless of `id`; blocked notifications are dropped and logged.
- Unparseable client lines that look like a `tools/call` are refused instead of passed through.
- Subdomain matching used substring matching (`acme.com` matched `notacme.com`). It now matches on label boundaries.
- Base64-, hex- and percent-encoded indicators slipped past matching. One decoding pass now runs on both sources and arguments, and injection detection also runs on decoded text.
- Homoglyph and punycode lookalike domains (`аpple.com`, `xn--pple-43d.com`) were treated as distinct hosts. Hosts are now normalised (IDN → Unicode, NFKC, Cyrillic/Greek confusables → Latin).
- Copy detection ignored non-ASCII text. Tokenisation is now Unicode-aware, and CJK is tokenised per character.
- A new tool appearing after first pinning was not treated as a rug pull. It is now held like a changed tool.

**Audit log integrity**
- A crash mid-write left a truncated line that broke `log`, `verify` and every `decide()`. Readers now tolerate it, `verify` warns, and the next write repairs it.
- The stale-lock breaker had a TOCTOU race that could fork the hash chain. Locks now record the owner's PID and are only broken when the owner is dead (or the lock is wedged for more than 5 minutes), via atomic rename-and-verify.
- Pin file writes were not locked, so concurrent proxies could clobber each other. They are now locked and written atomically.
- The tamper-evidence claim was overstated. The README now states the key-holder boundary, and new `checkpoint` / `verify --checkpoint` commands detect full rewrites.

**Robustness and performance**
- Every append and every sink check re-read the whole ledger. Both now read backward from EOF (O(window), not O(file)).
- Untrusted results that failed to scan were silently lost. They are now recorded as unscanned (holding side effects), and the model is told in-band.
- Added a 16 MB line cap per JSON-RPC message, plus TTL and size caps on in-flight request tracking.
- Approvals are now keyed on the full SHA-256 instead of 64 bits.
- Added an `agent-provenance` bin alias.
- The `shell` indicator regex lacked a word boundary (`push the` matched `sh the`).

## 0.1.0

Initial release.
