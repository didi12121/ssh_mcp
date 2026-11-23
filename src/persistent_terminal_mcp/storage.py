from contextlib import asynccontextmanager
from sqlalchemy import event, select, text, update
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from .config import Settings
from .errors import ToolError
from .migrations import upgrade
from .models import Execution, Profile, Session


class Store:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.engine = create_async_engine(settings.db_url, hide_parameters=True)
        self.transaction = async_sessionmaker(self.engine, expire_on_commit=False)
        if self.engine.dialect.name == "sqlite":
            @event.listens_for(self.engine.sync_engine, "connect")
            def sqlite_options(connection, _record) -> None:
                cursor = connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA busy_timeout=5000")
                cursor.close()

    async def start(self, reset_runtime: bool = True) -> None:
        await upgrade(self.engine, self.settings)
        if not reset_runtime:
            return
        async with self.transaction.begin() as db:
            await db.execute(update(Session).where(
                Session.status.in_(["CREATING", "READY", "BUSY", "RECONNECTING"])
            ).values(status="DISCONNECTED"))
            await db.execute(update(Execution).where(
                Execution.mode == "foreground", Execution.status.in_(["PENDING", "RUNNING"])
            ).values(status="UNKNOWN"))

    @asynccontextmanager
    async def write(self):
        async with self.transaction.begin() as db:
            await db.execute(text("BEGIN IMMEDIATE"))
            yield db

    async def profile(self, profile_id: str) -> Profile:
        async with self.transaction() as db:
            row = await db.get(Profile, profile_id)
        if row is None or row.deleted_at:
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
