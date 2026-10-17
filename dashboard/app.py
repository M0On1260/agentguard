"""streamlit run dashboard/app.py   (gateway must be running)"""
import os

import httpx
import pandas as pd
import streamlit as st

URL = os.getenv("AGENTGUARD_URL", "http://127.0.0.1:8000")
st.title("AgentGuard audit")
stats = httpx.get(f"{URL}/stats").json()
c = st.columns(3)
for col, v in zip(c, ["allow", "block", "approve"]):
    col.metric(v, stats["by_verdict"].get(v, 0))
st.subheader("Blocks by rule")
st.bar_chart(pd.Series(stats["blocks_by_rule"], dtype=int))
st.subheader("Recent decisions")
st.dataframe(pd.DataFrame(httpx.get(f"{URL}/audit", params={"limit": 100}).json()))
