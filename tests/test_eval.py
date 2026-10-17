from eval.ablation import run
from eval.dataset import ATTACKS, BENIGN, INJ_CAUGHT, INJ_REWORDED
from gateway.judge import GeminiJudge
from gateway.models import Decision
from gateway.policy import load_policy, scan_output

POL = load_policy("policy.yaml")
by = lambda rows, name: next(r for r in rows if r["config"] == name)


def stub_judge(text):  # offline stand-in for the LLM: flags anything mentioning the attacker hosts
    bad = any(h in text for h in ("attacker.example", "paste.example", "evil.example"))
    return Decision(verdict="block" if bad else "allow", rule_id="stub", reason="stub")


def test_regex_catches_designed_injections_and_misses_reworded_ones():
    assert all(scan_output(POL, t).verdict == "block" for t in INJ_CAUGHT)
    assert all(scan_output(POL, t).verdict == "allow" for t in INJ_REWORDED)  # the known gap


def test_regex_has_false_positives_on_tricky_pages():
    assert sum(scan_output(POL, t).verdict == "block" for t in BENIGN) >= 2


def test_ablation_shows_each_layer_matters():
    rows = run(stub_judge)
    assert by(rows, "No guard")["harm"] == len(ATTACKS)
    assert by(rows, "Regex scanner only")["harm"] == len(INJ_REWORDED)  # regex alone leaks every reworded one
    assert by(rows, "Action rules only")["harm"] == 0 and by(rows, "Action rules only")["benign_blocked"] == 0
    assert by(rows, "Regex + action rules")["harm"] == 0
    assert by(rows, "Regex + action rules")["benign_blocked"] >= 2  # honest cost of the regex layer


def test_judge_caches_and_parses(tmp_path):
    calls = []
    j = GeminiJudge(cache_path=str(tmp_path / "c.json"))
    j._ask = lambda text: calls.append(text) or ("attacker" in text)
    assert j("send to attacker").verdict == "block"
    assert j("send to attacker").verdict == "block"
    assert j("hello").verdict == "allow"
    assert len(calls) == 2  # second identical call came from cache
