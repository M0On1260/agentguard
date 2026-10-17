# AgentGuard: product view (DRAFT, edit in your own words)

No users yet. Everything below is a hypothesis to validate, not a result.

## 1. User
A small team that ships an AI agent with access to private data (a database, files, email) and has no security specialist.

## 2. Pain
The agent can read sensitive data and call external services. A hidden instruction in a web page, email or document can chain those two abilities into a leak. Published cases: Slack AI (2024), EchoLeak in Microsoft 365 Copilot (2025), GitHub MCP "toxic agent flow" (2025).

## 3. Alternatives
| Alternative | What it covers | Gap for this user |
|---|---|---|
| Do nothing / trust the model | Models often resist obvious injections | No safety net when they don't |
| LLM Guard (text scanner) | Scores text for injection | No view of what the agent *does*; in my test it missed 4/19 reworded pages |
| LLM-judge on every page | Most accurate text check in my test | Roughly 4 to 12 s per page, API cost, rate limits |
| **AgentGuard action rules** | Blocks "read secret, then send to unknown host" regardless of wording | Only covers sequences the policy describes |

## 4. Success metrics (measured on my own 23 attack / 12 normal page set)
- Attacks that cause harm: 0/23 with action rules (19/23 with regex only)
- Normal pages wrongly blocked: 0/12 (judge + action), 3/12 (regex)
- Added latency: action rules negligible; LLM-judge about 4 to 12 s per page
- Time to set up: TODO measure (target: under 10 minutes with `docker compose up`)

## 5. Scope decisions
- **Built:** one attack class (data exfiltration), sequence rules with taint, pluggable text layer, audit log, evaluation harness.
- **Cut:** auth on the gateway, multi-tenant sessions, persistent taint, a real UI beyond the audit dashboard.
- **Why:** a narrow claim I can measure beats a broad claim I can't.

## 6. Validation plan (not done yet)
Ask 3 to 5 people building agents (classmates, hackathon teams) to try the Docker quickstart. Record what broke, what confused them, and what they would change. Only then write "tried by N teams".
