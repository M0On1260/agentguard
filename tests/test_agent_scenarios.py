import pytest
from fastapi.testclient import TestClient

from agent.scripted_agent import SCENARIOS, run_scenario
from gateway.api import app

gw = TestClient(app)
ATTACKS = [(n, f) for n, f, a in SCENARIOS if a]


@pytest.mark.parametrize("name,fn", ATTACKS)
def test_attack_causes_harm_without_guard(name, fn):
    assert run_scenario(fn).harm() is not None


@pytest.mark.parametrize("name,fn", ATTACKS)
def test_attack_stopped_with_guard(name, fn):
    assert run_scenario(fn, gw).harm() is None


def test_normal_task_not_blocked_by_guard():
    normal = SCENARIOS[0][1]
    env = run_scenario(normal, gw)
    assert env.harm() is None
    assert env.outbox == [("api.company.com", "rows=3")]  # task completed: no false positive


def test_audit_log_records_decisions():
    run_scenario(SCENARIOS[1][1], gw)  # exfil chain
    stats = gw.get("/stats").json()
    assert stats["blocks_by_rule"].get("no-exfil", 0) >= 1
    rows = gw.get("/audit", params={"limit": 5}).json()
    assert rows and {"session_id", "tool", "verdict", "rule_id"} <= rows[0].keys()
