import asyncio
import logging
import os
from pathlib import Path
import sqlite3
from uuid import uuid4

from pydantic import TypeAdapter, ValidationError
from sqlalchemy import inspect, select, text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from .config import LegacyPrincipal, Settings
from .identity_models import AccessToken, AgentIdentity
from .models import Active, Execution, Profile, Session, now
from .security import private_file

SCHEMA_VERSION = 2
legacy_schema = TypeAdapter(list[LegacyPrincipal])
logger = logging.getLogger("terminal.audit")


def sqlite_backup(source: Path, target: Path) -> None:
    fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    src = dst = None
    try:
        src = sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True)
        dst = sqlite3.connect(target)
        src.backup(dst)
        if dst.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise RuntimeError("SQLite migration backup failed its integrity check")
    finally:
        if src:
            src.close()
        if dst:
            dst.close()


def read_legacy(file: Path) -> tuple[bytes | None, list[LegacyPrincipal]]:
    try:
        content = private_file(file)
    except FileNotFoundError:
        return None, []
    try:
        return content, legacy_schema.validate_json(content)
    except ValidationError:
        raise RuntimeError("Invalid legacy Agent configuration; no credentials were imported") from None


def legacy_rows(records: list[LegacyPrincipal]) -> tuple[list[dict], list[dict]]:
    agents: dict[str, dict] = {}
    hashes: set[str] = set()
    tokens = []
    timestamp = now()
    for principal in records:
        permissions = principal.model_dump(mode="json", exclude={"owner_id", "token_sha256"})
        for field in ("credentials", "workspaces"):
            permissions[field] = sorted(permissions[field])
        permissions["custom_commands"] = principal.shell
        entry = agents.get(principal.owner_id)
        if entry and entry["permissions_json"] != permissions:
            raise RuntimeError("Conflicting permissions for a legacy Agent ID; resolve the conflict before migrating")
        if principal.token_sha256 in hashes:
            raise RuntimeError("Duplicate legacy token digest; resolve the conflict before migrating")
        hashes.add(principal.token_sha256)
        agents.setdefault(principal.owner_id, {
            "owner_id": principal.owner_id, "name": principal.owner_id, "enabled": True,
            "permissions_json": permissions, "created_at": timestamp, "updated_at": timestamp,
        })
        tokens.append({
            "token_id": uuid4().hex, "owner_id": principal.owner_id, "token_hash": principal.token_sha256,
            "name": "Legacy Token", "created_at": timestamp, "expires_at": None,
            "created_by": "legacy_migration", "legacy": True,
        })
    return list(agents.values()), tokens


async def schema_version(connection: AsyncConnection) -> int | None:
    tables = await connection.run_sync(lambda db: set(inspect(db).get_table_names()))
    if "schema_versions" not in tables:
        if tables.intersection({"profiles", "sessions", "active_sessions", "executions",
                                "agent_identities", "access_tokens"}):
            raise RuntimeError("Unversioned terminal database contains objects; restore a versioned backup")
        return None
    value = (await connection.execute(text("SELECT MAX(version) FROM schema_versions"))).scalar_one()
    if value not in {1, SCHEMA_VERSION}:
        raise RuntimeError("Unsupported terminal database schema")
    if value == SCHEMA_VERSION and not {"agent_identities", "access_tokens"}.issubset(tables):
        raise RuntimeError("Terminal identity schema is incomplete")
    return value


async def upgrade(engine: AsyncEngine, settings: Settings) -> None:
    if engine.dialect.name != "sqlite":
        raise RuntimeError("Token migration currently requires SQLite")
    async with engine.connect() as db:
        await db.execute(text("PRAGMA journal_mode=WAL"))
        await db.commit()
        # SQLite does not otherwise guarantee that DDL participates in a transaction.
        await db.execute(text("BEGIN IMMEDIATE"))
        version = await schema_version(db)
        if version == SCHEMA_VERSION:
            await db.commit()
            return
        raw, records = await asyncio.to_thread(read_legacy, settings.principals_file)
        agents, tokens = legacy_rows(records)
        if version == 1 or raw is not None:
            directory = settings.data_dir / "migration-backups" / uuid4().hex
            directory.mkdir(parents=True, mode=0o700)
            if version == 1 and engine.url.database not in {None, "", ":memory:"}:
                await asyncio.to_thread(sqlite_backup, Path(engine.url.database), directory / "terminal-v1.db")
            if raw is not None:
                fd = os.open(directory / "principals.json", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(fd, "wb") as file:
                    file.write(raw)
                    file.flush()
                    os.fsync(file.fileno())
        if version is None:
            await db.execute(text("CREATE TABLE schema_versions (version INTEGER PRIMARY KEY)"))
            for table in (Profile, Session, Active, Execution):
                await db.run_sync(table.__table__.create)
        else:
            tables = await db.run_sync(lambda connection: set(inspect(connection).get_table_names()))
            if not {"profiles", "sessions", "active_sessions", "executions"}.issubset(tables):
                raise RuntimeError("Incomplete version 1 database")
        for table in (AgentIdentity, AccessToken):
            await db.run_sync(table.__table__.create)
        if agents:
            await db.execute(AgentIdentity.__table__.insert(), agents)
            await db.execute(AccessToken.__table__.insert(), tokens)
        # Compare imported digests without logging them. Foreign keys cover token ownership.
        imported = (await db.execute(select(AccessToken.owner_id, AccessToken.token_hash))).all()
        if set(imported) != {(row["owner_id"], row["token_hash"]) for row in tokens} or (
            await db.execute(text("PRAGMA foreign_key_check"))
        ).first() is not None:
            raise RuntimeError("Agent migration failed its integrity check")
        await db.execute(text("INSERT INTO schema_versions VALUES (:v)"), {"v": SCHEMA_VERSION})
        await db.commit()
        logger.info("agent_identity_migration", extra={"action_fields": {
            "schema": SCHEMA_VERSION, "agents_imported": len(agents), "tokens_imported": len(tokens),
        }})
