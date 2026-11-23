from sqlalchemy import event, select, text, update
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from .config import Settings
from .errors import ToolError
from .models import Base, Execution, Profile, Session


class Store:
    def __init__(self, settings: Settings) -> None:
        self.engine = create_async_engine(settings.db_url)
        self.transaction = async_sessionmaker(self.engine, expire_on_commit=False)
        if self.engine.dialect.name == "sqlite":
            @event.listens_for(self.engine.sync_engine, "connect")
            def sqlite_options(connection, _record) -> None:
                cursor = connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA busy_timeout=5000")
                cursor.close()

    async def start(self, reset_runtime: bool = True) -> None:
        async with self.engine.begin() as connection:
            if self.engine.dialect.name == "sqlite":
                await connection.execute(text("PRAGMA journal_mode=WAL"))
            await connection.execute(text(
                "CREATE TABLE IF NOT EXISTS schema_versions (version INTEGER PRIMARY KEY)"
            ))
            result = await connection.execute(text("SELECT MAX(version) FROM schema_versions"))
            version = result.scalar_one()
            if version is None:
                await connection.run_sync(Base.metadata.create_all)
                await connection.execute(text("INSERT INTO schema_versions VALUES (1)"))
            elif version != 1:
                raise RuntimeError("Unsupported terminal database schema")
        if not reset_runtime:
            return
        async with self.transaction.begin() as db:
            await db.execute(update(Session).where(
                Session.status.in_(["CREATING", "READY", "BUSY", "RECONNECTING"])
            ).values(status="DISCONNECTED"))
            await db.execute(update(Execution).where(
                Execution.mode == "foreground", Execution.status.in_(["PENDING", "RUNNING"])
            ).values(status="UNKNOWN"))

    async def profile(self, owner: str, profile_id: str) -> Profile:
        async with self.transaction() as db:
            row = await db.scalar(select(Profile).where(Profile.profile_id == profile_id, Profile.owner_id == owner))
        if row is None:
            raise ToolError("PROFILE_NOT_FOUND", "Connection profile not found.")
        return row

    async def session(self, owner: str, session_id: str) -> Session:
        async with self.transaction() as db:
            row = await db.scalar(select(Session).where(Session.session_id == session_id, Session.owner_id == owner))
        if row is None:
            raise ToolError("SESSION_NOT_FOUND", "Terminal session not found.")
        return row

    async def execution(self, session_id: str, execution_id: str) -> Execution:
        async with self.transaction() as db:
            row = await db.scalar(select(Execution).where(
                Execution.execution_id == execution_id, Execution.session_id == session_id
            ))
        if row is None:
            raise ToolError("EXECUTION_NOT_FOUND", "Execution not found in this terminal.")
        return row
