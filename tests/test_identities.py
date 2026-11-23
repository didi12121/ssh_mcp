from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
import json
import logging
import re
import sqlite3
from uuid import uuid4

import pytest
from sqlalchemy.exc import SQLAlchemyError
from starlette.testclient import TestClient

from conftest import OTHER, TOKEN, call, put_secret
from persistent_terminal_mcp.identity_store import Identities
from persistent_terminal_mcp.server import build_app

ADMIN = "8" * 64
ADMIN_HEADERS = {"Authorization": "Bearer " + ADMIN}
MCP_REQUEST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}


def admin_app(config, *, ip="127.0.0.1"):
    if config.web_admin_token_file is None:
        config.web_admin_token_file = config.data_dir / "admin-token"
        put_secret(config.web_admin_token_file, ADMIN.encode())
    return TestClient(build_app(config), base_url="http://127.0.0.1", client=(ip, 51000))


def admin_request(client, method, path, body=None, **headers):
    return client.request(method, "/admin/" + path, json=body, headers={**ADMIN_HEADERS, **headers})


def mcp_status(client, token):
    return client.post("/mcp", json=MCP_REQUEST, headers={
        "Authorization": "Bearer " + token, "Accept": "application/json, text/event-stream",
    }).status_code


def create_agent(client, owner_id="automation", **overrides):
    result = admin_request(client, "POST", "agents", {"owner_id": owner_id, "name": owner_id, **overrides})
    assert result.status_code == 201, result.text
    return result.json()


def issue_token(client, owner_id="automation", **overrides):
    result = admin_request(client, "POST", "tokens", {"owner_id": owner_id, "name": "Desktop", **overrides})
    assert result.status_code == 201, result.text
    assert result.headers["Cache-Control"] == "no-store"
    return result.json()


def test_agent_policy_crud_enable_and_targets(config):
    with admin_app(config) as client:
        created = create_agent(client)
        assert created["targets"] == [] and created["credentials"] == []
        assert not created["shell"] and not created["custom_commands"] and not created["ssh_agent"]
        duplicate = admin_request(client, "POST", "agents", {"owner_id": "automation", "name": "duplicate"})
        assert duplicate.status_code == 409
        granted = admin_request(client, "PATCH", "agents/automation", {
            "targets": ["LOCALHOST"], "credentials": ["fixture"], "workspaces": ["ops"], "shell": True,
            "custom_commands": True, "commands": {"disk": ["df", "-h"]},
        }).json()
        assert granted["targets"] == ["localhost"] and granted["workspaces"] == ["ops"]
        assert granted["credentials"] == ["fixture"] and granted["commands"] == {"disk": ["df", "-h"]}
        assert granted["shell"] and granted["custom_commands"]
        assert admin_request(client, "PATCH", "agents/automation", {"owner_id": "other"}).status_code == 400
        assert admin_request(client, "PATCH", "agents/automation", {"targets": ["ssh://not-a-host"]}).status_code == 400
        assert admin_request(client, "GET", "agents?search=autom&catalog=1").json()["credentials"] == [
            {"ref": "fixture", "kind": "key"}
        ]
        first, second = issue_token(client), issue_token(client)
        for enabled in (False, True):
            assert admin_request(client, "PATCH", "agents/automation", {"enabled": enabled}).json()["enabled"] is enabled
            assert mcp_status(client, first["token"]) == mcp_status(client, second["token"]) == (200 if enabled else 401)


def test_token_create_rotation_revocation_filter_and_logs(config, caplog):
    with admin_app(config) as client:
        caplog.set_level(logging.INFO)
        first = issue_token(client, "first")
        other = issue_token(client, "first", expires_at=None)
        assert other["expires_at"] is None and first["expires_at"] is not None
        assert re.fullmatch(r"ptmcp_[a-f0-9]{32}_[A-Za-z0-9_-]{43}", first["token"])
        assert mcp_status(client, first["token"]) == 200
        assert mcp_status(client, first["token"][:-1] + "!") == 401
        listing = admin_request(client, "GET", "tokens?owner=first&status=ACTIVE")
        assert listing.headers["Cache-Control"] == "no-store"
        first_row = next(token for token in listing.json()["tokens"] if token["token_id"] == first["token_id"])
        assert first_row["last_used_at"]
        assert "token_hash" not in listing.text and first["token"] not in listing.text
        assert mcp_status(client, first["token"]) == 200
        assert admin_request(client, "GET", "tokens/" + first["token_id"]).json()["last_used_at"] == first_row["last_used_at"]
        rotate = admin_request(client, "POST", f"tokens/{first['token_id']}/rotate").json()
        assert rotate["replaces"] == first["token_id"] and rotate["owner_id"] == "first"
        assert mcp_status(client, first["token"]) == 401 and mcp_status(client, rotate["token"]) == 200
        assert mcp_status(client, other["token"]) == 200
        path = f"tokens/{rotate['token_id']}"
        revoked = admin_request(client, "POST", path + "/revoke", {"reason": "unused"}).json()
        assert revoked["status"] == "REVOKED" and mcp_status(client, rotate["token"]) == 401
        repeat = admin_request(client, "POST", path + "/revoke", {"reason": "manual"}).json()
        assert repeat["revoked_at"] == revoked["revoked_at"] and repeat["revoked_reason"] == "unused"
        assert admin_request(client, "DELETE", path).json()["deleted"]
        assert admin_request(client, "DELETE", path).json()["deleted"]
        assert admin_request(client, "GET", path).status_code == 404
        for secret in (first["token"], rotate["token"], other["token"], ADMIN):
            assert secret not in caplog.text
        assert {"token_create", "token_rotate", "token_revoke", "token_delete"}.issubset({
            record.action_fields["action"] for record in caplog.records
            if record.getMessage() == "identity_admin_action"
        })


def test_expired_tokens_filter_and_reject(config):
    with admin_app(config) as client:
        created = issue_token(client, "first")
        with sqlite3.connect(config.data_dir / "terminal.db") as db:
            db.execute("UPDATE access_tokens SET expires_at=? WHERE token_id=?", (
                (datetime.now(UTC) - timedelta(days=1)).isoformat(), created["token_id"],
            ))
        assert mcp_status(client, created["token"]) == 401
        result = admin_request(client, "GET", "tokens?status=EXPIRED").json()
        assert [(item["token_id"], item["status"]) for item in result["tokens"]] == [(created["token_id"], "EXPIRED")]
        rejected = admin_request(client, "POST", "tokens", {
            "owner_id": "first", "name": "expired", "expires_at": "2000-01-01T00:00:00Z",
        })
        assert rejected.status_code == 422
        invalid = admin_request(client, "POST", "tokens", {
            "owner_id": "first", "name": "expired", "expires_at": "2027-01-01T00:00:00",
        })
        assert invalid.status_code == 400


def test_rotation_transaction_rolls_back_if_issue_fails(config, monkeypatch):
    with admin_app(config) as client:
        original = issue_token(client, "first")
        issue = Identities.issue

        async def fail_after_insert(*args):
            await issue(*args)
            raise SQLAlchemyError("synthetic secret must never be returned")

        monkeypatch.setattr(Identities, "issue", staticmethod(fail_after_insert))
        result = admin_request(client, "POST", f"tokens/{original['token_id']}/rotate")
        assert result.status_code == 503 and "synthetic secret" not in result.text
        assert mcp_status(client, original["token"]) == 200
        listing = admin_request(client, "GET", "tokens?owner=first").json()["tokens"]
        assert {item["token_id"] for item in listing} == {original["token_id"],
            next(item["token_id"] for item in listing if item["legacy"])}


def test_token_idempotency_rate_limit_and_digest_constraint(config):
    config.admin_token_mutations_per_minute = 3
    with admin_app(config) as client:
        request_id = str(uuid4())

        def send(_):
            return admin_request(client, "POST", "tokens", {"owner_id": "first", "name": "duplicate"},
                                 **{"Idempotency-Key": request_id})

        with ThreadPoolExecutor(2) as pool:
            results = list(pool.map(send, range(2)))
        assert sorted(result.status_code for result in results) == [201, 409]
        assert "token" not in next(result.json() for result in results if result.status_code == 409)
        assert send(0).status_code == 409
        blocked = send(0)
        assert blocked.status_code == 429 and 1 <= int(blocked.headers["Retry-After"]) <= 60
        with sqlite3.connect(config.data_dir / "terminal.db") as db, pytest.raises(sqlite3.IntegrityError):
            db.execute("UPDATE access_tokens SET token_hash=(SELECT token_hash FROM access_tokens LIMIT 1)")


def test_admin_mcp_credentials_origin_host_and_body_separation(config):
    with admin_app(config) as client:
        assert mcp_status(client, ADMIN) == 401
        assert client.get("/admin/agents", headers={"Authorization": "Bearer " + TOKEN}).status_code == 403
        assert client.get("/admin/tokens?token=" + ADMIN).status_code == 403
        assert admin_request(client, "GET", "tokens", Origin="http://fake.test").status_code == 403
        assert admin_request(client, "GET", "agents", Host="fake.test").status_code == 403
        assert admin_request(client, "POST", "tokens", {"name": "x" * 5000}).status_code == 413
        assert call(client, "connection_list", OTHER)["total"] == 0
    with admin_app(config, ip="192.0.2.45") as client:
        assert admin_request(client, "GET", "tokens").status_code == 403


def test_migrated_identity_cannot_use_same_value_as_admin_credential(config):
    import hashlib

    records = json.loads(config.principals_file.read_text())
    records[0]["token_sha256"] = hashlib.sha256(ADMIN.encode()).hexdigest()
    put_secret(config.principals_file, json.dumps(records).encode())
    with admin_app(config) as client:
        assert mcp_status(client, ADMIN) == 401
        assert admin_request(client, "GET", "agents").status_code == 403
