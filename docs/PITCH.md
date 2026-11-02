# Provenance: one-page pitch

**One line.** Provenance proves which human asked for every action an AI agent takes, and stops the ones nobody asked for.

**Problem.** Agents now send email, ship code and move money. Their biggest weakness is that they can't tell your instructions from instructions hidden in the content they read. In 2026 alone there were thousands of CVEs across MCP servers and coding agents, the first MCP vulnerability landed on CISA's KEV list, infostealers began targeting AI tool configs, and ransomware operators were reported running intrusions through MCP tools. Security teams can't answer the auditor's basic question: *who authorised this agent action?*

**Why existing approaches fall short.** Prompt guardrails classify text; they don't follow data. Agent firewalls inspect one call at a time, inside one server. The attack is a *flow*: untrusted content enters through one tool and leaves through another.

**Product.**
1. **Open source (wedge):** `provenance`, a zero-dependency MCP proxy with cross-server taint tracking, injection holds, rug-pull detection, signed audit logs and a config scanner. One-line install.
2. **Standard (moat):** Intent Receipts, a verifiable token binding each agent action to a human-authorised goal and the provenance of its inputs. APIs and other agents can check it.
3. **Commercial (revenue):** a team control plane offering central policy, fleet-wide agent inventory, approval workflows (Slack/Teams), SIEM export and compliance evidence packs.

**Why now.** Agents moved from demos to production in 2026, and agent security became the largest category of cyber seed investment. Most entrants sell top-down. Developers adopt MCP tooling bottom-up, and nobody owns the open-source runtime layer or the provenance standard yet.

**Business model.** Open core. Free local tool → paid team tier (per agent or per seat) → enterprise (SSO, on-prem, audit retention).

**Traction plan (first 90 days).**
- Weeks 0–4: launch on GitHub, Hacker News, r/netsec and X with the live attack demo; target 1,000 stars.
- Weeks 4–8: publish the Intent Receipts spec and get two MCP server maintainers to verify receipts.
- Weeks 8–12: sign 3–5 design partners (teams running coding or ops agents) and add the hosted approval workflow.

**Ask.** Pre-seed to fund 12–18 months: founder plus 2 engineers, focused on remote-MCP support, the hosted control plane and the standard.

**Founder.** *[Your story: why you, what you've built, what you've seen break.]*
