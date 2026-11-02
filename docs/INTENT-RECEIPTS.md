# Intent Receipts (draft v0)

**Problem.** When an AI agent performs an action, such as sending email, moving money, merging code or hiring another agent, the receiving system can verify *which credential* was used, but not *which human asked for it* or *whether untrusted content steered it*. OAuth answers "who is this?" Nothing answers "who wanted this?"

**Proposal.** Every side-effecting agent action carries an *intent receipt*: a small signed token binding the action to an authorised human goal and to the provenance of its inputs.

```jsonc
{
  "v": 0,
  "principal": "user:ahilya@example.com",      // who authorised the goal
  "goal": "sha256:…",                           // hash of the human instruction (content stays private)
  "scope": ["send_email:to=*@mycompany.com"],    // what the goal permits
  "action": { "tool": "send_email", "args": "sha256:…" },
  "inputs": [                                    // provenance of data in the args
    { "source": "user", "trust": "trusted" },
    { "source": "web/fetch_page", "trust": "untrusted", "flowed_into_args": false }
  ],
  "parent": "receipt:…",                         // chain when agent A delegates to agent B
  "issued": 1793634000,
  "sig": "ed25519:…"
}
```

**Verification rules for a receiving API or agent:**

1. The signature is valid and the key belongs to a registered agent runtime.
2. The action falls within `scope`.
3. No `untrusted` input has `flowed_into_args: true` unless a human co-signed it.
4. The `parent` chain is valid back to a human principal (for agent-to-agent delegation).

**What exists today.** `provenance` already produces steps 1 and 3 locally: signed, hash-chained records of every sink call with taint evidence. v1 turns those records into portable tokens that a third party can verify.

**Open questions.** Scope grammar; key distribution (local keys vs. org CA vs. transparency log); privacy of `goal`; how to express "derived from" for summarised content.
