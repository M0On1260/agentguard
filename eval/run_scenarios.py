"""Run scripted scenarios with the guard OFF and ON. In-process by default; --url to hit a running server."""
import sys

from agent.scripted_agent import SCENARIOS, run_scenario


def make_gateway(url: str | None):
    if url:
        import httpx
        return httpx.Client(base_url=url)
    from fastapi.testclient import TestClient
    from gateway.api import app
    return TestClient(app)


def main() -> None:
    gw = make_gateway(sys.argv[sys.argv.index("--url") + 1] if "--url" in sys.argv else None)
    print(f"{'Scenario':36} {'Guard OFF':16} {'Guard ON'}")
    attacks = stopped = 0
    for name, fn, is_attack in SCENARIOS:
        off, on = run_scenario(fn).harm(), run_scenario(fn, gw).harm()
        if is_attack:
            attacks += 1
            stopped += on is None
        print(f"{name:36} {off or 'ok':16} {on or 'ok'}")
    print(f"\nAttacks stopped with guard on: {stopped}/{attacks}")


if __name__ == "__main__":
    main()
