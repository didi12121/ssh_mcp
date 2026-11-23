from concurrent.futures import ThreadPoolExecutor
import os
import sqlite3
import time
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from conftest import OTHER, TOKEN
from persistent_terminal_mcp.executions import Executions
from persistent_terminal_mcp.models import Execution, Session
from persistent_terminal_mcp.ring import OutputRing
from persistent_terminal_mcp.security import Security, private_file
from persistent_terminal_mcp.server import build_app
from persistent_terminal_mcp.storage import Store


def test_output_legacy_oversized_rows_and_gaps(tmp_path):
    ring = OutputRing(tmp_path / "output.db", 16384, 60)
    with ring.connect() as db:
        chunk = "中" * 4000
        db.executemany("INSERT INTO output(stream, text, size, stamp) VALUES (?, ?, ?, ?)", [
            ("stdout", chunk, len(chunk.encode()), time.time()),
            ("stderr", "expired", 7, time.time() - 100),
            ("stdout", "next", 4, time.time()),
            ("stdout", "expired", 7, time.time() - 100),
        ])
    first = ring.read(0, 8192)
    assert first["next_cursor"] == 1 and first["truncated"] and first["has_more"]
    assert len(first["entries"][0]["text"].encode()) <= 8192
    assert set(first["entries"][0]["text"]) == {"中"}
    second = ring.read(first["next_cursor"], 8192)
    assert [row["text"] for row in second["entries"]] == ["next"]
    assert second["next_cursor"] == 4 and second["truncated"] and not second["has_more"]
    ring.append("terminal", "end")
    assert ring.read(10**8, 8192)["next_cursor"] == 5


def test_output_concurrent_writers_disk_budget_and_expiry(tmp_path):
    file = tmp_path / "output.db"
    ring = OutputRing(file, 16384, 3600)
    marker = "🙂" * 2000
    with ThreadPoolExecutor(8) as pool:
        list(pool.map(lambda n: ring.append(f"worker-{n % 8}", marker + str(n)), range(320)))
    result = ring.read(0, 8192)
    assert result["truncated"] and result["has_more"]
    seen = []
    while True:
        seen.extend(item["cursor"] for item in result["entries"])
        assert all("�" not in item["text"] for item in result["entries"])
        assert sum(len(item["text"].encode()) for item in result["entries"]) <= 8192
        if not result["has_more"]:
            break
        result = ring.read(result["next_cursor"], 8192)
    assert seen == sorted(set(seen)) and result["next_cursor"] > 320
    assert file.stat().st_size <= 65536
    high_water = result["next_cursor"]
    with sqlite3.connect(file) as db:
        db.execute("UPDATE output SET stamp=0")
    ring.compact_expired()
    assert not ring.read(0, 8192)["entries"] and file.stat().st_size <= 16384
    ring.append("stdout", "new")
    assert ring.read(high_water, 8192)["next_cursor"] == high_water + 1


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership, modes and symlinks")
def test_secret_file_checks_open_file_permissions(config):
    identity = config.data_dir / "identity"
    identity.chmod(0o644)
    with pytest.raises(PermissionError):
        private_file(identity)
    identity.chmod(0o600)
    shadow = config.data_dir / "shadow"
    shadow.symlink_to(identity)
    with pytest.raises(OSError):
        private_file(shadow)
    assert Security(config).authenticate(TOKEN) is not None
    config.principals_file.chmod(0o644)
    assert Security(config).authenticate(TOKEN) is None


def test_duplicate_headers_host_and_origin_are_rejected(config):
    payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    with TestClient(build_app(config), base_url="http://127.0.0.1:8766") as client:
        ambiguous = client.post("/mcp", json=payload, headers=[
            ("Authorization", "Bearer " + TOKEN),
            ("Authorization", "Bearer " + OTHER),
        ])
        assert ambiguous.status_code == 401
        for name, value in [("Host", "attacker.example"), ("Origin", "https://attacker.example")]:
            denied = client.post("/mcp", json=payload, headers={
                "Authorization": "Bearer " + TOKEN, "Accept": "application/json, text/event-stream", name: value,
            })
            assert denied.status_code in {403, 421}


async def test_confirmed_exit_cannot_be_overwritten_by_stale_failure(config):
    store = Store(config)
    await store.start()
    executions = Executions(SimpleNamespace(store=store, settings=config, remote=None))
    try:
        async with store.transaction.begin() as db:
            db.add(Session(session_id="s", owner_id="first", workspace_id="default", profile_id="p",
                           profile_version=1, snapshot={}, name="test", status="READY", backend="exec"))
        async with store.transaction.begin() as db:
            db.add(Execution(execution_id="e", session_id="s", mode="detached", status="RUNNING"))
        confirmed = await store.execution("s", "e")
        delayed = await store.execution("s", "e")
        await executions.state(confirmed, "COMPLETED", 17)
        await executions.state(delayed, "UNKNOWN")
        assert (delayed.status, delayed.exit_code) == ("COMPLETED", 17)
    finally:
        await store.engine.dispose()
