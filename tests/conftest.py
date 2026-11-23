import hashlib
import json
from pathlib import Path

import asyncssh
import pytest

from persistent_terminal_mcp.config import Settings

TOKEN = "fixture-a-" + "a" * 40
OTHER = "fixture-b-" + "b" * 40
LIMITED = "fixture-c-" + "c" * 40


def put_secret(path: Path, value: bytes) -> None:
    path.write_bytes(value)
    path.chmod(0o600)


@pytest.fixture
def config(tmp_path: Path) -> Settings:
    tmp_path.chmod(0o700)
    key = asyncssh.generate_private_key("ssh-ed25519")
    put_secret(tmp_path / "identity", key.export_private_key())
    put_secret(tmp_path / "identity.pub", key.export_public_key())
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
                    connect_timeout=2, execution_timeout=10)


def call(client, tool_name: str, token: str = TOKEN, **params) -> dict:
    response = client.post("/mcp", headers={
        "Authorization": f"Bearer {token}", "Accept": "application/json, text/event-stream",
    }, json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool_name, "arguments": params}})
    assert response.status_code == 200, response.text
    assert "result" in response.json(), response.text
    result = response.json()["result"]
    assert "structuredContent" in result, result
    return {**result["structuredContent"], "is_error": result.get("isError", False)}


def profile(client, token: str = TOKEN, **changes) -> dict:
    return call(client, "connection_create", token, **{
        "name": "sandbox", "host": "127.0.0.1", "username": "fixture", "credential_ref": "fixture", **changes,
    })
