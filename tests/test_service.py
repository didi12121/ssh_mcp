from concurrent.futures import ThreadPoolExecutor
from socketserver import BaseRequestHandler, TCPServer
from threading import Event, Thread

import pytest
from starlette.testclient import TestClient

from persistent_terminal_mcp.models import ProfileInput
from persistent_terminal_mcp.ring import OutputRing
from persistent_terminal_mcp.server import build_app
from conftest import OTHER, TOKEN, call, profile


def test_health_and_authentication(config):
    with TestClient(build_app(config), base_url="http://127.0.0.1") as client:
        assert client.get("/health").json()["ok"]
        assert client.post("/mcp", json={}).status_code == 401
        assert client.post("/mcp", json={}, headers={"Authorization": "Bearer " + "x" * 40}).status_code == 401
        assert client.post("/mcp", json={}, headers={
            "Authorization": "Bearer " + TOKEN, "Host": "untrusted.test",
        }).status_code == 421
        response = client.post("/mcp", headers={
            "Authorization": "Bearer " + TOKEN, "Accept": "application/json, text/event-stream",
        }, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        tools = response.json()["result"]["tools"]
        assert len(tools) == 16
        assert all(tool["description"] and tool["inputSchema"] for tool in tools)


def test_profile_crud_isolation_and_persistence(config):
    with TestClient(build_app(config), base_url="http://127.0.0.1") as client:
        first = profile(client, name="Sandbox One", tags=["demo", "demo"])
        second = profile(client, name="Sandbox Two", host="localhost")
        assert first["tags"] == ["demo"]
        assert second["profile_id"] != first["profile_id"]
        assert "PRIVATE KEY" not in str(first)
        assert str(config.data_dir) not in str(first)
        assert call(client, "connection_list", OTHER)["total"] == 0
        assert call(client, "connection_get", OTHER, profile_id=first["profile_id"])["code"] == "PROFILE_NOT_FOUND"
        search = call(client, "connection_list", name="BOX", host="127", tag="demo", limit=1)
        assert [item["profile_id"] for item in search["profiles"]] == [first["profile_id"]]
        assert call(client, "connection_list", limit=1, page=2)["profiles"][0]["profile_id"] == second["profile_id"]
        assert call(client, "connection_update", profile_id=first["profile_id"], changes={"name": "Renamed"})["version"] == 2
        assert call(client, "connection_delete", profile_id=second["profile_id"])["deleted"]
    with TestClient(build_app(config), base_url="http://127.0.0.1") as client:
        stored = call(client, "connection_get", profile_id=first["profile_id"])
        assert stored["name"] == "Renamed"
        assert stored["version"] == 2
        assert call(client, "connection_list")["total"] == 1


def test_profile_rejects_unapproved_targets_and_credentials(config):
    with TestClient(build_app(config), base_url="http://127.0.0.1") as client:
        assert profile(client, host="example.org")["code"] == "TARGET_FORBIDDEN"
        assert profile(client, credential_ref="ungranted")["code"] == "CREDENTIAL_FORBIDDEN"
        assert profile(client, username="root;whoami")["code"] == "INVALID_INPUT"
        assert profile(client, auth_type="agent", credential_ref=None)["code"] == "CREDENTIAL_FORBIDDEN"


@pytest.mark.parametrize("host", ["-proxy", "example.org;id", "user@server", "https://server", "a..b"])
def test_rejects_invalid_ssh_host(host):
    with pytest.raises(ValueError):
        ProfileInput(name="test", host=host, username="operator", auth_type="agent")


def test_output_order_cursor_retention_and_utf8(tmp_path):
    ring = OutputRing(tmp_path / "ring.db", 16384, 3600)
    first = "测试" * 500
    ring.append("stdout", first)
    ring.append("stderr", "error")
    data = ring.read(0, 8192)
    assert [(row["stream"], row["text"]) for row in data["entries"]] == [("stdout", first), ("stderr", "error")]
    assert not ring.read(data["next_cursor"], 8192)["entries"]
    with ThreadPoolExecutor(2) as pool:
        list(pool.map(lambda _: ring.append("stdout", "z" * 3000), range(10)))
    data = ring.read(0, 8192)
    assert data["truncated"] and data["has_more"]
    page = ring.read(data["next_cursor"], 8192)
    assert all(entry["cursor"] > data["next_cursor"] for entry in page["entries"])
    expired = OutputRing(ring.path, 16384, -1).read(0, 8192)
    assert expired["truncated"] and not expired["entries"]


def test_ssh_handshake_deadline(config):
    release = Event()

    class Silent(BaseRequestHandler):
        def handle(self):
            release.wait(3)

    with TCPServer(("127.0.0.1", 0), Silent) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        config.connect_timeout = 0.25
        config.known_hosts.write_text("")
        try:
            with TestClient(build_app(config), base_url="http://127.0.0.1") as client:
                created = profile(client, port=server.server_address[1])
                assert call(client, "connection_test", profile_id=created["profile_id"])["code"] == "SSH_TIMEOUT"
        finally:
            release.set()
            server.shutdown()
            thread.join(timeout=2)
