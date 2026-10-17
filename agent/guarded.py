from .fake_tools import PRIMARY, Env


def run_tool(env: Env, name: str, args: dict, gw=None, session_id: str = "s") -> str:
    """Run a tool, asking the AgentGuard gateway first. gw=None means no protection."""
    arg = str(args.get(PRIMARY[name], ""))
    if gw is not None:
        d = gw.post("/tool-call", json={"session_id": session_id, "tool": name, "arg": arg}).json()
        if d["verdict"] != "allow":
            return f"BLOCKED by AgentGuard ({d['rule_id']}): {d['reason']}"
    out = getattr(env, name)(**args)
    if gw is not None and name == "fetch_page":
        s = gw.post("/scan-output", json={"session_id": session_id, "tool": name, "output": out}).json()
        if s["verdict"] != "allow":
            return f"BLOCKED OUTPUT by AgentGuard ({s['rule_id']}): {s['reason']}"
    return out
