"""Bounded, ordered output records. Also runs on the remote SSH host."""

import sqlite3
import time
from contextlib import closing
from pathlib import Path


class OutputRing:
    def __init__(self, path: Path, capacity: int, retention_seconds: int) -> None:
        self.path = path
        self.capacity = capacity
        self.retention_seconds = retention_seconds

    def connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=5)
        db.execute("CREATE TABLE IF NOT EXISTS output (seq INTEGER PRIMARY KEY AUTOINCREMENT, "
                   "stream TEXT NOT NULL, text TEXT NOT NULL, size INTEGER NOT NULL, stamp REAL NOT NULL)")
        return db

    def append(self, stream: str, text: str) -> None:
        if not text:
            return
        with closing(self.connect()) as db, db:
            db.execute("INSERT INTO output(stream, text, size, stamp) VALUES(?, ?, ?, ?)",
                       (stream, text, len(text.encode()), time.time()))
            db.execute("DELETE FROM output WHERE seq IN (SELECT seq FROM "
                       "(SELECT seq, SUM(size) OVER(ORDER BY seq DESC) AS total FROM output) WHERE total > ?)",
                       (self.capacity,))
            self.expire(db)

    def expire(self, db: sqlite3.Connection) -> None:
        db.execute("DELETE FROM output WHERE stamp < ?", (time.time() - self.retention_seconds,))

    def read(self, cursor: int, max_bytes: int) -> dict:
        with closing(self.connect()) as db, db:
            self.expire(db)
            last = db.execute("SELECT seq FROM sqlite_sequence WHERE name='output'").fetchone()
            head = last[0] if last else 0
            first = db.execute("SELECT MIN(seq) FROM output").fetchone()[0] or head + 1
            effective = max(cursor, first - 1)
            entries = []
            used = 0
            for seq, stream, text, size in db.execute(
                "SELECT seq, stream, text, size FROM output WHERE seq > ? ORDER BY seq", (effective,)
            ):
                if used + size > max_bytes or len(entries) >= 256:
                    break
                entries.append({"cursor": seq, "stream": stream, "text": text})
                used += size
            next_cursor = entries[-1]["cursor"] if entries else effective
            return {"entries": entries, "next_cursor": next_cursor,
                    "truncated": cursor < first - 1, "has_more": next_cursor < head}

    def compact_expired(self) -> None:
        with closing(self.connect()) as db:
            with db:
                self.expire(db)
            if db.execute("PRAGMA freelist_count").fetchone()[0]:
                db.execute("VACUUM")
