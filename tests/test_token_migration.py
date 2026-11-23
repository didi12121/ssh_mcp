import json
import sqlite3

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

from conftest import LIMITED, TOKEN, call, put_secret
from test_identities import admin_app, admin_request, mcp_status
from persistent_terminal_mcp import migrations
from persistent_terminal_mcp.main import preflight
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
    engine.dispose()


def test_v1_migration_preserves_owner_and_never_reimports_revoked_token(config):
    version_one(config)
    with admin_app(config) as client:
        assert mcp_status(client, TOKEN) == 200
        assert call(client, "connection_get", profile_id=PROFILE_ID)["owner_id"] == "first"
        assert call(client, "terminal_list")["terminals"][0]["session_id"] == SESSION_ID
        assert call(client, "terminal_status", session_id=SESSION_ID, execution_id=EXECUTION_ID)["exit_code"] == 7
        limited = admin_request(client, "GET", "agents/limited").json()
        assert not limited["shell"] and not limited["custom_commands"] and limited["commands"] == {"uptime": ["uptime"]}
        assert admin_request(client, "GET", "agents/first").json()["custom_commands"]
        imported = admin_request(client, "GET", "tokens?owner=first").json()["tokens"][0]
        assert imported["legacy"] and imported["expires_at"] is None
        assert admin_request(client, "POST", f"tokens/{imported['token_id']}/revoke").status_code == 200
        assert admin_request(client, "PATCH", "agents/limited", {"name": "Updated name"}).status_code == 200
    [backup] = list((config.data_dir / "migration-backups").glob("*/terminal-v1.db"))
    with sqlite3.connect(backup) as db:
        assert db.execute("SELECT MAX(version) FROM schema_versions").fetchone() == (1,)
    assert backup.with_name("principals.json").read_bytes() == config.principals_file.read_bytes()
    put_secret(config.principals_file, b"old file is no longer an authentication source")
    with admin_app(config) as client:
        assert mcp_status(client, TOKEN) == 401 and mcp_status(client, LIMITED) == 200
        assert admin_request(client, "GET", "agents/limited").json()["name"] == "Updated name"
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
        db.execute("INSERT INTO schema_versions VALUES (3)")
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
