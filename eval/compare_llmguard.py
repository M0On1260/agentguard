"""Text-layer comparison: AgentGuard regex vs LLM Guard's PromptInjection scanner, same pages.
Optional heavy install (downloads an ML model):  python -m pip install llm-guard
NOTE: LLM Guard is built for prompts; applying it to tool outputs is OUR choice. It has no action layer."""
from gateway.policy import load_policy, scan_output

from .dataset import ATTACKS, BENIGN, INJ_CAUGHT, INJ_REWORDED


def llm_guard_detector():
    try:
        from llm_guard.input_scanners import PromptInjection
    except ImportError:
        raise SystemExit("llm-guard not installed. Run: python -m pip install llm-guard (see its docs for supported Python versions)")
    scanner = PromptInjection()
    return lambda text: not scanner.scan(text)[1]  # scan -> (sanitized, is_valid, risk_score); invalid = flagged


def main() -> None:
    pol = load_policy("policy.yaml")
    dets = {"AgentGuard regex": lambda t: scan_output(pol, t).verdict != "allow", "LLM Guard PromptInjection": llm_guard_detector()}
    misses = []
    print(f"{'Detector':28} {'Regex-style':>12} {'Reworded':>9} {'False positives':>16}")
    for name, det in dets.items():
        c = sum(map(det, INJ_CAUGHT)); r = sum(map(det, INJ_REWORDED)); f = sum(map(det, BENIGN))
        print(f"{name:28} {c:>8}/{len(INJ_CAUGHT)} {r:>6}/{len(INJ_REWORDED)} {f:>12}/{len(BENIGN)}")
        misses.append((name, [t for t in INJ_CAUGHT + INJ_REWORDED if not det(t)], [t for t in BENIGN if det(t)]))
    for name, missed, wrong in misses:
        print(f"\n== {name} ==\nMISSED ATTACKS ({len(missed)}):")
        for t in missed: print("  -", t[:110])
        print(f"NORMAL PAGES WRONGLY FLAGGED ({len(wrong)}):")
        for t in wrong: print("  -", t[:110])


if __name__ == "__main__":
    main()
