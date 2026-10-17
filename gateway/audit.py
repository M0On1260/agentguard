import sqlite3
import threading
import time


class AuditLog:
    """Append-only SQLite log of every gateway decision."""

    def __init__(self, path: str = "audit.db") -> None:
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        self._db.execute(
            """CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL, session_id TEXT, kind TEXT, tool TEXT,
                arg TEXT, verdict TEXT, rule_id TEXT, reason TEXT)"""
        )
        self._db.commit()

    def log(self, session_id, kind, tool, arg, verdict, rule_id, reason) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO audit (ts,session_id,kind,tool,arg,verdict,rule_id,reason) VALUES (?,?,?,?,?,?,?,?)",
                (time.time(), session_id, kind, tool, str(arg)[:200], verdict, rule_id, reason),
            )
            self._db.commit()

    def recent(self, limit: int = 50) -> list[dict]:
        with self._lock:
            cur = self._db.execute(
                "SELECT ts,session_id,kind,tool,arg,verdict,rule_id,reason FROM audit ORDER BY id DESC LIMIT ?",
                (limit,),
            )
            cols = [c[0] for c in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def stats(self) -> dict:
        with self._lock:
            by_verdict = dict(self._db.execute("SELECT verdict, COUNT(*) FROM audit GROUP BY verdict").fetchall())
            by_rule = dict(self._db.execute(
                "SELECT rule_id, COUNT(*) FROM audit WHERE verdict!='allow' GROUP BY rule_id").fetchall())
        return {"by_verdict": by_verdict, "blocks_by_rule": by_rule}
