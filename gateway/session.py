import time
from dataclasses import dataclass, field


@dataclass
class Session:
    calls: list[dict] = field(default_factory=list)
    taint: set[str] = field(default_factory=set)  # e.g. {"secret", "untrusted"}

    def record(self, tool: str, arg: str, verdict: str, now: float | None = None) -> None:
        self.calls.append({"t": now if now is not None else time.time(),
                           "tool": tool, "arg": arg, "verdict": verdict})

    def recent_count(self, now: float, window: float) -> int:
        return sum(1 for c in self.calls if now - c["t"] < window)


class SessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}

    def get(self, session_id: str) -> Session:
        return self._sessions.setdefault(session_id, Session())
