from concurrent.futures import ThreadPoolExecutor
from socketserver import BaseRequestHandler, TCPServer
from threading import Event, Thread

import pytest
from starlette.testclient import TestClient

from persistent_terminal_mcp.models import ProfileInput
from persistent_terminal_mcp.ring import OutputRing
from persistent_terminal_mcp.server import build_app
from conftest import OTHER, TOKEN, ADMIN_HEADERS, admin_request, call, global_profile, profile, put_secret


def test_health_and_authentication(config):
    with TestClient(build_app(config), base_url="http://127.0.0.1", client=("127.0.0.1", 51000)) as client:
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
        assert len(tools) == 11
        assert all(tool["description"] and tool["inputSchema"] for tool in tools)
        assert not any({"host", "port", "username", "credential_ref"} & tool["inputSchema"].get("properties", {}).keys()
                       for tool in tools)


def test_global_profiles_are_admin_owned_and_client_sees_only_aliases(config):
    with TestClient(build_app(config), base_url="http://127.0.0.1", client=("127.0.0.1", 51000)) as client:
        first = profile(client, name="Sandbox One", tags=["demo", "demo"])
        second = global_profile(client, name="Sandbox Two", host="localhost")
        assert first["tags"] == ["demo"] and "owner_id" not in first
        assert admin_request(client, "GET", "connections").json()["total"] == 2
        assert call(client, "connection_list", OTHER)["total"] == 0
        assert call(client, "terminal_create", profile_id=second["profile_id"])["code"] == "PROFILE_NOT_FOUND"
        search = call(client, "connection_list", name="BOX", tag="demo", limit=1)
        assert search["connections"] == [{"profile_id": first["profile_id"], "name": "Sandbox One",
                                            "description": None, "tags": ["demo"]}]
        assert call(client, "connection_list", page=2, limit=1)["connections"] == []
        for operation in ["create", "get", "update", "delete", "test"]:
            result = call(client, "connection_" + operation, profile_id=first["profile_id"])
            assert result["is_error"] and "fixture" not in result["message"]
        assert admin_request(client, "PATCH", "connections/" + first["profile_id"], {"name": "Renamed"}).json()["version"] == 2
        assert admin_request(client, "DELETE", "connections/" + second["profile_id"]).json()["deleted"]
    with TestClient(build_app(config), base_url="http://127.0.0.1", client=("127.0.0.1", 51000)) as client:
        assert call(client, "connection_list")["connections"][0]["name"] == "Renamed"
        assert admin_request(client, "GET", "connections").json()["total"] == 1


def test_admin_profile_verifies_credential_and_form_fields(config):
    base = {"name": "Profile", "host": "example.org", "username": "fixture", "credential_ref": "fixture"}
    with TestClient(build_app(config), base_url="http://127.0.0.1", client=("127.0.0.1", 51000)) as client:
        assert admin_request(client, "POST", "connections", {**base, "credential_ref": "missing"}).json()["code"] == "CREDENTIAL_UNAVAILABLE"
        assert admin_request(client, "POST", "connections", {**base, "username": "root;whoami"}).status_code == 400
        assert admin_request(client, "POST", "connections", {**base, "auth_type": "agent",
                             "credential_ref": None}).json()["code"] == "CREDENTIAL_UNAVAILABLE"


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
            with TestClient(build_app(config), base_url="http://127.0.0.1", client=("127.0.0.1", 51000)) as client:
                created = profile(client, port=server.server_address[1])
                assert admin_request(client, "POST", "connections/" + created["profile_id"] + "/test").json()["code"] == "SSH_TIMEOUT"
        finally:
            release.set()
            server.shutdown()
            thread.join(timeout=2)


def test_managed_keys_are_global_and_references_block_removal(config):
    config.managed_keys_dir = config.data_dir / "managed"
    key = config.managed_keys_dir / "web_backup" / "identity"
    key.parent.mkdir(parents=True)
    put_secret(key, (config.data_dir / "identity").read_bytes())
    (key.parent / "key.json").write_text("{}")
    with TestClient(build_app(config), base_url="http://127.0.0.1", client=("127.0.0.1", 51000)) as client:
        assert client.get("/admin/connections").status_code == 403
        assert client.get("/admin/keys", headers={"Authorization": "Bearer " + TOKEN}).status_code == 403
        row = global_profile(client, credential_ref="managed_web_backup")
        refs = admin_request(client, "GET", "keys").json()["references"]
        assert refs["web_backup"][0]["profile_id"] == row["profile_id"]
        vault = {"vault": str(config.managed_keys_dir)}
        assert admin_request(client, "POST", "keys/web_backup/delete", vault).status_code == 409
        assert key.exists()
        assert admin_request(client, "DELETE", "connections/" + row["profile_id"]).status_code == 200
        assert admin_request(client, "POST", "keys/web_backup/delete", vault).status_code == 200
        assert not key.exists()
