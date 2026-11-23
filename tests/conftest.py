import hashlib
import json
from pathlib import Path

import asyncssh
import pytest

from persistent_terminal_mcp.config import Settings

TOKEN = "fixture-a-" + "a" * 40
OTHER = "fixture-b-" + "b" * 40
LIMITED = "fixture-c-" + "c" * 40
ADMIN = "8" * 64
ADMIN_HEADERS = {"Authorization": "Bearer " + ADMIN}


def put_secret(path: Path, value: bytes) -> None:
    path.write_bytes(value)
    path.chmod(0o600)


@pytest.fixture
def config(tmp_path: Path) -> Settings:
    tmp_path.chmod(0o700)
    key = asyncssh.generate_private_key("ssh-ed25519")
    put_secret(tmp_path / "identity", key.export_private_key())
    put_secret(tmp_path / "identity.pub", key.export_public_key())
    put_secret(tmp_path / "admin-token", ADMIN.encode())
    principal = {"targets": ["127.0.0.1", "localhost"], "credentials": ["fixture"], "shell": True}
    put_secret(tmp_path / "principals.json", json.dumps([
        {**principal, "owner_id": "first", "token_sha256": hashlib.sha256(TOKEN.encode()).hexdigest()},
        {**principal, "owner_id": "second", "token_sha256": hashlib.sha256(OTHER.encode()).hexdigest()},
        {**principal, "owner_id": "limited", "token_sha256": hashlib.sha256(LIMITED.encode()).hexdigest(),
         "shell": False, "commands": {"uptime": ["uptime"]}},
    ]).encode())
    put_secret(tmp_path / "credentials.json", json.dumps({
        "fixture": {"file": str(tmp_path / "identity"), "kind": "key"}
    }).encode())
    return Settings(data_dir=tmp_path, principals_file=tmp_path / "principals.json",
                    credentials_file=tmp_path / "credentials.json", known_hosts=tmp_path / "known_hosts",
                    web_admin_token_file=tmp_path / "admin-token", connect_timeout=2, execution_timeout=10)


def call(client, tool_name: str, token: str = TOKEN, **params) -> dict:
    response = client.post("/mcp", headers={
        "Authorization": f"Bearer {token}", "Accept": "application/json, text/event-stream",
    }, json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool_name, "arguments": params}})
    assert response.status_code == 200, response.text
    assert "result" in response.json(), response.text
    result = response.json()["result"]
    if "structuredContent" not in result and result.get("isError"):
        return {"is_error": True, "message": str(result["content"])}
    assert "structuredContent" in result, result
    return {**result["structuredContent"], "is_error": result.get("isError", False)}


def profile(client, token: str = TOKEN, **changes) -> dict:
    row = global_profile(client, **changes)
    owner = {TOKEN: "first", OTHER: "second", LIMITED: "limited"}[token]
    listing = admin_request(client, "GET", f"tokens?owner={owner}").json()
    legacy = next(item for item in listing["tokens"] if item["legacy"])
    update = admin_request(client, "PATCH", f"tokens/{legacy['token_id']}/permissions", {
        "allowed_profile_ids": [*legacy["allowed_profile_ids"], row["profile_id"]],
    })
    assert update.status_code == 200, update.text
    return row


def admin_request(client, method, path, body=None, **headers):
    return client.request(method, "/admin/" + path, json=body, headers={**ADMIN_HEADERS, **headers})


def global_profile(client, **changes) -> dict:
    result = admin_request(client, "POST", "connections", {
        "name": "sandbox", "host": "127.0.0.1", "username": "fixture", "credential_ref": "fixture", **changes,
    })
    assert result.status_code == 201, result.text
    return result.json()
