import hashlib
import json
import sqlite3

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

from conftest import LIMITED, OTHER, TOKEN, call, put_secret
from test_identities import admin_app, admin_request, mcp_status
from persistent_terminal_mcp import migrations
from persistent_terminal_mcp.main import preflight
from persistent_terminal_mcp.identity_models import AccessToken, AgentIdentity
from persistent_terminal_mcp.models import Active, Execution, Profile, Session, now
from persistent_terminal_mcp.storage import Store

PROFILE_ID = "a" * 32
SESSION_ID = "b" * 32
EXECUTION_ID = "c" * 32


def version_one(config):
    engine = create_engine(f"sqlite:///{(config.data_dir / 'terminal.db').as_posix()}")
    with engine.begin() as db:
        db.execute(text("CREATE TABLE schema_versions (version INTEGER PRIMARY KEY)"))
        db.execute(text("INSERT INTO schema_versions VALUES (1)"))
        for table in (Profile, Session, Active, Execution):
            table.__table__.create(db)
        data = {"name": "Existing target", "host": "127.0.0.1", "username": "fixture", "port": 22,
                "auth_type": "key", "credential_ref": "fixture", "tags": []}
        db.execute(Profile.__table__.insert().values(profile_id=PROFILE_ID, owner_id="first", configuration=data))
        db.execute(Session.__table__.insert().values(
            session_id=SESSION_ID, owner_id="first", workspace_id="default", profile_id=PROFILE_ID,
            profile_version=1, snapshot=data, name="Original", status="DISCONNECTED", backend="exec",
        ))
        db.execute(Execution.__table__.insert().values(
            execution_id=EXECUTION_ID, session_id=SESSION_ID, mode="detached", status="COMPLETED", exit_code=7,
        ))
        db.execute(Active.__table__.insert().values(owner_id="first", workspace_id="default", session_id=SESSION_ID))
        for table, column in (("profiles", "enabled"), ("profiles", "access_version"), ("profiles", "deleted_at"),
                              ("sessions", "profile_access_version")):
            db.execute(text(f"ALTER TABLE {table} DROP COLUMN {column}"))
    engine.dispose()


def test_v1_migration_preserves_owner_and_never_reimports_revoked_token(config):
    version_one(config)
    with admin_app(config) as client:
        assert mcp_status(client, TOKEN) == 200
        assert call(client, "connection_list")["connections"][0]["profile_id"] == PROFILE_ID
        assert call(client, "terminal_list")["terminals"][0]["session_id"] == SESSION_ID
        assert call(client, "terminal_status", session_id=SESSION_ID, execution_id=EXECUTION_ID)["exit_code"] == 7
        limited = admin_request(client, "GET", "tokens?owner=limited").json()["tokens"][0]
        assert not limited["shell"] and not limited["custom_commands"] and limited["commands"] == {"uptime": ["uptime"]}
        imported = admin_request(client, "GET", "tokens?owner=first").json()["tokens"][0]
        assert imported["legacy"] and imported["expires_at"] is None and imported["custom_commands"]
        assert admin_request(client, "POST", f"tokens/{imported['token_id']}/revoke").status_code == 200
        assert admin_request(client, "PATCH", f"tokens/{limited['token_id']}/permissions",
                             {"commands": {"disk": ["df", "-h"]}}).status_code == 200
    [backup] = list((config.data_dir / "migration-backups").glob("*/terminal-v1.db"))
    with sqlite3.connect(backup) as db:
        assert db.execute("SELECT MAX(version) FROM schema_versions").fetchone() == (1,)
    assert backup.with_name("principals.json").read_bytes() == config.principals_file.read_bytes()
    put_secret(config.principals_file, b"old file is no longer an authentication source")
    with admin_app(config) as client:
        assert mcp_status(client, TOKEN) == 401 and mcp_status(client, LIMITED) == 200
        assert admin_request(client, "GET", "tokens?owner=limited").json()["tokens"][0]["commands"] == {"disk": ["df", "-h"]}
        assert admin_request(client, "GET", "tokens").json()["total"] == 3
    assert len(list((config.data_dir / "migration-backups").glob("*/terminal-v1.db"))) == 1


def test_conflicting_legacy_records_fail_closed(config):
    version_one(config)
    rows = json.loads(config.principals_file.read_text())
    rows.append({**rows[0], "token_sha256": "1" * 64, "shell": False})
    put_secret(config.principals_file, json.dumps(rows).encode())
    with pytest.raises(RuntimeError, match="Conflicting permissions"):
        with admin_app(config):
            pytest.fail("Conflicting policies must not be merged")
    with sqlite3.connect(config.data_dir / "terminal.db") as db:
        assert db.execute("SELECT MAX(version) FROM schema_versions").fetchone() == (1,)


async def test_failed_schema_upgrade_rolls_back_ddl_and_existing_rows(config, monkeypatch):
    version_one(config)
    rows = migrations.legacy_rows

    def broken_import(records):
        agents, tokens = rows(records)
        tokens[0]["owner_id"] = "missing"
        return agents, tokens

    monkeypatch.setattr(migrations, "legacy_rows", broken_import)
    store = Store(config)
    try:
        with pytest.raises(IntegrityError):
            await store.start()
    finally:
        await store.engine.dispose()
    with sqlite3.connect(config.data_dir / "terminal.db") as db:
        assert db.execute("SELECT MAX(version) FROM schema_versions").fetchone() == (1,)
        assert not db.execute("SELECT name FROM sqlite_master WHERE name IN ('agent_identities','access_tokens')").fetchall()
        assert db.execute("SELECT owner_id FROM profiles").fetchone() == ("first",)
        assert db.execute("SELECT exit_code FROM executions").fetchone() == (7,)


def test_unrecognized_schema_is_not_accepted(config):
    version_one(config)
    with sqlite3.connect(config.data_dir / "terminal.db") as db:
        db.execute("INSERT INTO schema_versions VALUES (9)")
    with pytest.raises(RuntimeError, match="Unsupported terminal database schema"):
        with admin_app(config):
            pytest.fail("A future schema must not be used")


async def test_preflight_blocks_update_with_live_foreground_execution(config):
    version_one(config)
    with sqlite3.connect(config.data_dir / "terminal.db") as db:
        db.execute("UPDATE executions SET mode='foreground', status='RUNNING'")
    with pytest.raises(SystemExit, match="1 active foreground"):
        await preflight(config)
    with sqlite3.connect(config.data_dir / "terminal.db") as db:
        assert db.execute("SELECT MAX(version) FROM schema_versions").fetchone() == (1,)


def version_two(config):
    version_one(config)
    engine = create_engine(f"sqlite:///{(config.data_dir / 'terminal.db').as_posix()}")
    _, records = migrations.read_legacy(config.principals_file)
    agents, tokens = migrations.legacy_rows(records)
    with engine.begin() as db:
        for table in (AgentIdentity, AccessToken):
            table.__table__.create(db)
        db.execute(AgentIdentity.__table__.insert(), agents)
        db.execute(AccessToken.__table__.insert(), tokens)
        db.execute(text("ALTER TABLE access_tokens DROP COLUMN permissions_json"))
        db.execute(text("INSERT INTO schema_versions VALUES (2)"))
    engine.dispose()


def test_v2_migration_never_expands_old_owner_or_credential_scope(config):
    version_two(config)
    across, wrong_key, stale_session, malformed = "d" * 32, "e" * 32, "f" * 32, "2" * 32
    generated_id = "1" * 32
    generated = f"ptmcp_{generated_id}_" + "x" * 43
    with sqlite3.connect(config.data_dir / "terminal.db") as db:
        db.execute("INSERT INTO profiles(profile_id,owner_id,version,configuration,created_at,updated_at) "
                   "SELECT ?,'second',version,configuration,created_at,updated_at FROM profiles WHERE profile_id=?",
                   (across, PROFILE_ID))
        db.execute("INSERT INTO profiles(profile_id,owner_id,version,configuration,created_at,updated_at) "
                   "SELECT ?,owner_id,version,json_set(configuration,'$.credential_ref','outside'),created_at,updated_at "
                   "FROM profiles WHERE profile_id=?", (wrong_key, PROFILE_ID))
        db.execute("INSERT INTO sessions (session_id, owner_id, workspace_id, profile_id, profile_version, snapshot, name,"
                   "status, backend, created_at, last_active_at) SELECT ?, owner_id, workspace_id, profile_id, profile_version,"
                   "json_set(snapshot, '$.port', 2222), name, status, backend, created_at, last_active_at FROM sessions",
                   (stale_session,))
        db.execute("UPDATE access_tokens SET revoked_at=? WHERE owner_id='second'", (now(),))
        db.execute("INSERT INTO profiles(profile_id,owner_id,version,configuration,created_at,updated_at) "
                   "SELECT ?,'limited',version,configuration,created_at,updated_at FROM profiles WHERE profile_id=?",
                   (malformed, PROFILE_ID))
        db.execute("UPDATE agent_identities SET permissions_json=json_set(permissions_json,'$.credentials','fixture') "
                   "WHERE owner_id='limited'")
        db.execute("INSERT INTO access_tokens(token_id,owner_id,name,token_hash,created_at,created_by,legacy) "
                   "VALUES (?,'first','Existing generated token',?,?,'fixture',0)",
                   (generated_id, hashlib.sha256(generated.encode()).hexdigest(), now()))
    put_secret(config.principals_file, b"old file must not be parsed when migrating v2")
    with admin_app(config) as client:
        assert mcp_status(client, OTHER) == 401
        assert [row["profile_id"] for row in call(client, "connection_list", generated)["connections"]] == [PROFILE_ID]
        assert [row["profile_id"] for row in call(client, "connection_list")["connections"]] == [PROFILE_ID]
        assert call(client, "connection_list", LIMITED)["connections"] == []
        assert admin_request(client, "GET", "connections").json()["total"] == 4
        assert [row["session_id"] for row in call(client, "terminal_list")["terminals"]] == [SESSION_ID]
        assert call(client, "terminal_status", session_id=stale_session)["code"] == "SESSION_NOT_FOUND"
    report = next((config.data_dir / "migration-backups").glob("*/report.json"))
    details = json.loads(report.read_text())
    assert details["from_schema"] == 2 and details["resources"] == {
        "profiles": 4, "sessions": 2, "executions": 1, "access_tokens": 4,
    }
    assert {entry.get("profile_id") for entry in details["denied"]}.issuperset({wrong_key, PROFILE_ID, malformed})
    assert any(item["reason"] == "legacy_policy_invalid" for item in details["denied"])
