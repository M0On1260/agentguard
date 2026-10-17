import os
import time

from fastapi import FastAPI

from .audit import AuditLog
from .judge import GeminiJudge
from .models import Decision, ScanRequest, ToolCall
from .policy import evaluate, load_policy, scan_output
from .session import SessionStore

POLICY_PATH = os.getenv("AGENTGUARD_POLICY", "policy.yaml")

app = FastAPI(title="AgentGuard")
policy = load_policy(POLICY_PATH)
sessions = SessionStore()
audit = AuditLog(os.getenv("AGENTGUARD_DB", "audit.db"))
# Optional 2nd text layer. Enable with: $env:AGENTGUARD_JUDGE="gemini"
judge = GeminiJudge(cache_path="judge_cache.json") if os.getenv("AGENTGUARD_JUDGE") == "gemini" else None


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "agent": policy.agent}


@app.post("/tool-call", response_model=Decision)
def tool_call(call: ToolCall) -> Decision:
    session = sessions.get(call.session_id)
    now = time.time()
    decision = evaluate(policy, session, call, now)
    session.record(call.tool, call.arg, decision.verdict, now)
    audit.log(call.session_id, "call", call.tool, call.arg, decision.verdict, decision.rule_id, decision.reason)
    # Taint on read: only if the call was actually allowed
    if decision.verdict == "allow" and call.tool in policy.sensitive_tools:
        session.taint.add("secret")
    return decision


@app.post("/scan-output", response_model=Decision)
def scan(req: ScanRequest) -> Decision:
    decision = scan_output(policy, req.output)
    if decision.verdict == "allow" and judge is not None:
        try:
            decision = judge(req.output)
        except Exception as e:  # fail-open: documented trade-off, logged below
            decision = Decision(verdict="allow", rule_id="judge-unavailable", reason=f"judge error: {type(e).__name__}")
    audit.log(req.session_id, "scan", req.tool, req.output[:80], decision.verdict, decision.rule_id, decision.reason)
    if decision.verdict == "block":
        sessions.get(req.session_id).taint.add("untrusted")
    return decision


@app.get("/session/{session_id}")
def session_info(session_id: str) -> dict:
    s = sessions.get(session_id)
    return {"taint": sorted(s.taint), "calls": len(s.calls)}


@app.get("/audit")
def get_audit(limit: int = 50) -> list[dict]:
    return audit.recent(limit)


@app.get("/stats")
def get_stats() -> dict:
    return audit.stats()
