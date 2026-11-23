from concurrent.futures import ThreadPoolExecutor
from socketserver import BaseRequestHandler, TCPServer
from threading import Event, Thread

import pytest
from starlette.testclient import TestClient

from persistent_terminal_mcp.models import ProfileInput
from persistent_terminal_mcp.ring import OutputRing
from persistent_terminal_mcp.server import build_app
from conftest import OTHER, TOKEN, call, profile, put_secret


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


def test_web_admin_shares_agent_profiles_and_validates_credentials(config):
    token = "a" * 64
    headers = {"Authorization": "Bearer " + token}
    config.web_admin_token_file = config.data_dir / "admin-token"
    put_secret(config.web_admin_token_file, token.encode())
    config.managed_keys_dir = config.data_dir / "managed"
    key = config.managed_keys_dir / "web_backup" / "identity"
    key.parent.mkdir(parents=True)
    put_secret(key, (config.data_dir / "identity").read_bytes())
    url = "/admin/connections"
    data = {"name": "Dashboard", "host": "127.0.0.1", "username": "fixture",
            "auth_type": "key", "credential_ref": "managed_web_backup"}
    app = build_app(config)
    with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 51000)) as client:
        assert client.get(url).status_code == 403
        assert client.get(url, headers={"Authorization": "Bearer " + TOKEN}).status_code == 403
        assert client.get(url, headers={**headers, "Origin": "http://evil.example"}).status_code == 403
        assert client.get(url, headers={**headers, "Host": "other.example"}).status_code == 403
        assert client.post("/mcp", headers=headers, json={}).status_code == 401
        created = client.post(url, headers=headers, json=data)
        assert created.status_code == 201, created.text
        dashboard_id = created.json()["profile_id"]
        assert client.get(url, headers=headers).json()["profiles"][0]["profile_id"] == dashboard_id
        assert call(client, "connection_list")["total"] == 0
        assert client.post(url + "?owner=first", headers=headers, json=data).json()["code"] == "CREDENTIAL_FORBIDDEN"
        shared = client.post(url + "?owner=first", headers=headers, json={**data, "credential_ref": "fixture"})
        assert shared.status_code == 201
        shared_id = shared.json()["profile_id"]
        assert call(client, "connection_get", profile_id=shared_id)["name"] == "Dashboard"
        patched = client.patch(url + "/" + shared_id + "?owner=first", headers=headers, json={"name": "Shared"})
        assert patched.json()["version"] == 2
        assert call(client, "connection_get", profile_id=shared_id)["name"] == "Shared"
        assert client.delete(url + "/" + shared_id + "?owner=first", headers=headers).json()["deleted"]
        assert client.delete(url + "/" + dashboard_id, headers=headers).json()["deleted"]
    with TestClient(build_app(config), base_url="http://127.0.0.1", client=("192.0.2.10", 51000)) as client:
        assert client.get(url, headers=headers).status_code == 403
