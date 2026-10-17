import re
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel

from .models import Decision, ToolCall
from .session import Session


class RateLimit(BaseModel):
    max_calls: int = 5
    per_seconds: float = 3


class Policy(BaseModel):
    agent: str
    allow_tools: list[str] = []
    deny_tools: list[str] = []
    network_tools: list[str] = []
    egress_allowlist: list[str] = []
    sensitive_tools: list[str] = []
    rate_limit: RateLimit = RateLimit()
    injection_patterns: list[str] = []


def load_policy(path: str) -> Policy:
    with open(path) as f:
        return Policy(**yaml.safe_load(f))


def host_of(arg: str) -> str:
    """'https://a.com/x' -> 'a.com'; 'a.com' -> 'a.com'."""
    url = arg if "://" in arg else f"//{arg}"
    return (urlparse(url).hostname or "").lower()


def evaluate(policy: Policy, session: Session, call: ToolCall, now: float) -> Decision:
    """Pure decision. Does not mutate the session. First matching rule wins."""
    # 1. Rate limit (this call counts, so prior + 1)
    rl = policy.rate_limit
    if session.recent_count(now, rl.per_seconds) + 1 > rl.max_calls:
        return Decision(verdict="block", rule_id="rate-limit",
                        reason=f"more than {rl.max_calls} calls in {rl.per_seconds}s")
    # 2. Deny list, then allow list
    if call.tool in policy.deny_tools:
        return Decision(verdict="block", rule_id="deny-list",
                        reason=f"{call.tool} is explicitly denied for {policy.agent}")
    if call.tool not in policy.allow_tools:
        return Decision(verdict="block", rule_id="not-allowed",
                        reason=f"{call.tool} is not on the allow list")
    # 3. Network tools: sequence rules first, then egress allowlist
    if call.tool in policy.network_tools:
        host = host_of(call.arg)
        if host not in policy.egress_allowlist:
            if "secret" in session.taint:
                return Decision(verdict="block", rule_id="no-exfil",
                                reason="session read a secret, then tried to send to an unknown host")
            if "untrusted" in session.taint:
                return Decision(verdict="block", rule_id="no-send-after-injection",
                                reason="session saw an injected instruction, external send blocked")
            return Decision(verdict="approve", rule_id="egress-unknown-host",
                            reason=f"{host or 'empty host'} is not on the egress allowlist")
    return Decision(verdict="allow", rule_id="default-allow", reason="matches policy")


def scan_output(policy: Policy, text: str) -> Decision:
    for pattern in policy.injection_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return Decision(verdict="block", rule_id="injection-output",
                            reason=f"tool output matched injection pattern: {pattern}")
    return Decision(verdict="allow", rule_id="output-clean", reason="no injection pattern found")
