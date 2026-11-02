# provenance

[![ci](https://github.com/AhilyaSanjaySarnaik/provenance/actions/workflows/ci.yml/badge.svg)](https://github.com/AhilyaSanjaySarnaik/provenance/actions/workflows/ci.yml) [![npm](https://img.shields.io/npm/v/agent-provenance)](https://www.npmjs.com/package/agent-provenance) ![deps](https://img.shields.io/badge/dependencies-0-brightgreen) ![license](https://img.shields.io/badge/license-Apache--2.0-blue)

**Your AI agent just read a web page that told it to email your API keys to a stranger. Did it?**

`provenance` sits between your AI agent and its MCP tools. It remembers what came from untrusted content (web pages, emails, issues, documents) and **blocks any action that carries that content somewhere it shouldn't go**. Every action gets a signed, tamper-evident receipt.

Zero dependencies. One line to install. Works with Claude, Cursor, Windsurf, VS Code, Codex: anything that speaks MCP over stdio.

```
$ npm run demo

3. The hijacked agent tries to follow the hidden instructions:
    [Provenance] Blocked call to "send_email" on server "mail".
    This action carries data that came from untrusted content, not from the user:
      - email security-verify@acme-billing-support.xyz  <- from web/fetch_page (2s ago)
    Agent: do not retry with altered arguments. Tell the user what you were trying to do and why.
    User: if this was really your intent, run:  npx agent-provenance approve 20aa44de
```

Note that the web server and the mail server are **two different MCP servers**. Taint flows across them through a shared local ledger. Per-server guardrails can't see this attack.

---

## 30-second start

**1. See how exposed you are right now**

```bash
npx agent-provenance scan
```

It finds every MCP config on your machine and in the current repo, and flags plaintext tokens (infostealers now target `.claude.json`, `.cursor/mcp.json` and Codex configs), unpinned `npx` packages, filesystem servers with access to `/`, cleartext remote servers, and repo-defined servers that run when you open a project. Exits `2` on high findings, so you can drop it into CI.

**2. Guard a server**

Change this:

```json
"mail": { "command": "npx", "args": ["-y", "some-mail-mcp@1.4.0"] }
```

to this:

```json
"mail": { "command": "npx", "args": ["-y", "agent-provenance", "wrap", "--name", "mail", "--", "npx", "-y", "some-mail-mcp@1.4.0"] }
```

Wrap every server you use. They share one ledger, so taint is tracked across all of them.

**3. Watch it work**

```bash
npx agent-provenance log       # what your agents read, did, and were stopped from doing
npx agent-provenance verify    # prove the log hasn't been edited
```

## How it works

```
 untrusted content                                           side effects
 fetch_page, read_email,  ──►  fingerprint  ──►  ledger  ◄──  send_email, write_file,
 get_issue, read_file          (URLs, emails,    (signed,      run_command, transfer,
                                wallets, IPs,     hash-        post_message ...
                                commands, copied  chained)          │
                                phrases)                            ▼
                                                           args carry untrusted data?  ─► BLOCK + explain
                                                           session saw an injection?   ─► HOLD for human
                                                           otherwise                   ─► ALLOW + signed receipt
```

| Feature | What it does |
|---|---|
| **Cross-server taint tracking** | Fingerprints every untrusted tool result. Sink calls whose arguments contain those indicators or copied phrases are blocked, with the evidence. |
| **Injection exposure hold** | If untrusted content contained injection patterns (override instructions, concealment, credential requests, invisible Unicode, tag smuggling), side effects wait for a human. |
| **Single-use approvals** | `provenance approve <id>` lets exactly that call (same tool, same args) through once. |
| **Rug-pull detection** | Tool definitions are pinned on first sight. If a server silently changes a tool's description or schema, the tool is withheld until you `repin`. |
| **Signed audit trail** | Ed25519-signed, hash-chained JSONL. `verify` detects any edit, deletion or reordering. |
| **Config scanner** | `scan` audits Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, Gemini CLI and Codex configs. |
| **Fails closed** | If the guard itself errors on a tool call, the call is refused, not passed through. |

## Policy

`npx agent-provenance init` writes `~/.provenance/policy.json`:

```jsonc
{
  "sources": ["fetch*", "*email*", "*issue*", "*page*", ...],   // tools whose OUTPUT is untrusted
  "sinks":   ["send*", "*exec*", "write*", "*pay*", ...],        // tools whose CALL has side effects
  "onTainted": "block",              // block | log | allow
  "onExposedToInjection": "block",
  "onToolDrift": "block",
  "windowMinutes": 60,
  "allowIndicators": ["email:me@mycompany.com"],
  "servers": { "github": { "sinks": ["create_issue", "merge_pull_request"] } }
}
```

## Threat model and honest limits

provenance targets the most common real-world agent attack: **indirect prompt injection that turns into a tool call**. It is a strong tripwire, not a proof of safety.

- Taint matching is lexical. An attacker who gets the model to *paraphrase or encode* the data defeats indicator matching. The injection-exposure hold is the backstop for that, which is why it defaults to `block`.
- It sees tool traffic, not your chat. It can't tell that *you* typed an email address that also appears on a page; use `allowIndicators` or approve once.
- It guards stdio MCP servers today. Remote (HTTP) MCP support and a hosted policy/audit plane are on the roadmap.
- Tool classification is by name pattern. Review `sources`/`sinks` for your servers.

Found a bypass? Please open an issue. Bypasses become test cases.

## Roadmap

- [ ] Streamable HTTP / remote MCP proxying
- [ ] **Intent receipts v1**: a signed "user X authorised goal Y" token that downstream APIs and agents can verify ([spec draft](docs/INTENT-RECEIPTS.md))
- [ ] Local dashboard (`provenance ui`)
- [ ] Semantic taint (embedding similarity) for paraphrased exfiltration
- [ ] Team mode: central policy, fleet-wide audit, SIEM export

## Development

```bash
npm install
npm test        # 11 tests incl. end-to-end proxy and tamper detection
npm run demo    # the attack above, live
```

Apache-2.0
