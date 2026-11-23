"""Bounded, ordered output records. Also runs on the remote SSH host."""

import sqlite3
import time
from contextlib import closing
from collections.abc import Iterator
from pathlib import Path


class OutputRing:
    def __init__(self, path: Path, capacity: int, retention_seconds: int) -> None:
        if capacity < 4:
            raise ValueError("Output ring capacity must fit one UTF-8 character")
        self.path = path
        self.capacity = capacity
        self.retention_seconds = retention_seconds

    def connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=5)
        try:
            page_size = db.execute("PRAGMA page_size").fetchone()[0]
            # Allow space for rows, indexes and fragmentation in addition to payload.
            db.execute(f"PRAGMA max_page_count={max(65536, self.capacity * 4) // page_size}")
            db.execute("CREATE TABLE IF NOT EXISTS output (seq INTEGER PRIMARY KEY AUTOINCREMENT, "
                       "stream TEXT NOT NULL, text TEXT NOT NULL, size INTEGER NOT NULL, stamp REAL NOT NULL)")
        except BaseException:
            db.close()
            raise
        return db

    def append(self, stream: str, text: str) -> None:
        if not text:
            return
        with closing(self.connect()) as db, db:
            self.expire(db)
            stamp = time.time()
            for piece, size in self.chunks(text):
                self.trim(db, self.capacity - size, max(32, self.capacity // 128) - 1)
                db.execute("INSERT INTO output(stream, text, size, stamp) VALUES(?, ?, ?, ?)",
                           (stream, piece, size, stamp))

    def chunks(self, text: str) -> Iterator[tuple[str, int]]:
        limit = min(4096, self.capacity)
        length = len(text.encode())
        if length <= limit:
            yield text, length
            return
        start = 0
        size = 0
        for index, character in enumerate(text):
            length = len(character.encode())
            if size and size + length > limit:
                yield text[start:index], size
                start, size = index, 0
            size += length
        if size:
            yield text[start:], size

    @staticmethod
    def trim(db: sqlite3.Connection, size: int, count: int) -> None:
        db.execute("DELETE FROM output WHERE seq IN (SELECT seq FROM "
                   "(SELECT seq, SUM(size) OVER(ORDER BY seq DESC) AS total, "
                   "ROW_NUMBER() OVER(ORDER BY seq DESC) AS position FROM output) "
                   "WHERE total > ? OR position > ?)", (size, count))

    def expire(self, db: sqlite3.Connection) -> None:
        db.execute("DELETE FROM output WHERE stamp < ?", (time.time() - self.retention_seconds,))

    def read(self, cursor: int, max_bytes: int) -> dict:
        if cursor < 0 or max_bytes <= 0:
            raise ValueError("Invalid output cursor or page size")
        with closing(self.connect()) as db, db:
            self.expire(db)
            last = db.execute("SELECT seq FROM sqlite_sequence WHERE name='output'").fetchone()
            head = last[0] if last else 0
            first = db.execute("SELECT MIN(seq) FROM output").fetchone()[0] or head + 1
            effective = max(min(cursor, head), first - 1)
            entries = []
            used = 0
            truncated = cursor < first - 1 or cursor > head
            next_cursor = effective
            for seq, stream, text, size in db.execute(
                "SELECT seq, stream, text, size FROM output WHERE seq > ? ORDER BY seq", (effective,)
            ):
                if len(entries) >= 256 or (used + size > max_bytes and entries):
                    break
                if size > max_bytes:
                    # Old database rows can exceed the page size. Consume the row explicitly.
                    text = text.encode()[:max_bytes].decode(errors="ignore")
                    size = len(text.encode())
                    truncated = True
                if seq > next_cursor + 1:
                    truncated = True
                entries.append({"cursor": seq, "stream": stream, "text": text})
                used += size
                next_cursor = seq
            else:
                # A tail gap is possible after expiry or after reading a legacy file.
                if next_cursor < head:
                    next_cursor = head
                    truncated = True
            return {"entries": entries, "next_cursor": next_cursor,
                    "truncated": truncated, "has_more": next_cursor < head}

    def compact_expired(self) -> None:
        with closing(self.connect()) as db:
            with db:
                self.expire(db)
            if db.execute("PRAGMA freelist_count").fetchone()[0]:
                db.execute("VACUUM")
