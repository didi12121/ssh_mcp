import asyncio
import codecs
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from collections.abc import Awaitable, Callable
from uuid import uuid4

import asyncssh
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import SQLAlchemyError

from .backends import Remote
from .config import Principal, Settings
from .errors import ToolError
from .models import Active, Execution, Profile, ProfileInput, Session, now
from .ring import OutputRing
from .security import Security, audit
from .ssh import SSHConnection, SSHConnectionManager
from .storage import Store

logger = logging.getLogger("terminal.sessions")

@dataclass
class Runtime:
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    ssh: SSHConnection | None = None
    shell: asyncssh.SSHClientProcess[bytes] | None = None
    reader: asyncio.Task | None = None
    monitor: asyncio.Task | None = None
    attempts: int = 0
    last_error: str | None = None
    touched: float = field(default_factory=time.monotonic)

    @property
    def connected(self) -> bool:
        return self.ssh is not None and not self.ssh.connection.is_closed()

    @property
    def shell_alive(self) -> bool:
        return (self.shell is not None and self.reader is not None and not self.reader.done()
                and not self.shell.stdout.at_eof())

    async def close_shell(self) -> None:
        if self.shell:
            self.shell.close()
        if self.reader:
            self.reader.cancel()
            await asyncio.gather(self.reader, return_exceptions=True)
        self.shell = None
        self.reader = None

    async def disconnect(self) -> None:
        if self.monitor:
            self.monitor.cancel()
            await asyncio.gather(self.monitor, return_exceptions=True)
            self.monitor = None
        await self.close_shell()
        ssh, self.ssh = self.ssh, None
        if ssh:
            await ssh.close()


class Sessions:
    def __init__(
        self, settings: Settings, store: Store, security: Security, ssh: SSHConnectionManager, mutations: asyncio.Lock,
    ) -> None:
        self.settings = settings
        self.store = store
        self.security = security
        self.ssh = ssh
        self.remote = Remote(settings)
        self.mutations = mutations
        self.runtimes: dict[str, Runtime] = {}
        self.sweeper: asyncio.Task | None = None
        self.cleanup_foreground: Callable[[str], Awaitable[None]] | None = None

    def ring(self, resource: str) -> OutputRing:
        return OutputRing(self.settings.data_dir / f"{resource}.db", self.settings.output_max_bytes,
                          86400 * self.settings.output_retention_days)

    def runtime(self, session_id: str) -> Runtime:
        return self.runtimes.setdefault(session_id, Runtime())

    async def set_status(self, row: Session, status: str, **fields: object) -> None:
        async with self.store.transaction.begin() as db:
            await db.execute(update(Session).where(Session.session_id == row.session_id)
                             .values(status=status, last_active_at=now(), **fields))

    async def sweep(self) -> None:
        while True:
            await asyncio.sleep(min(60, self.settings.idle_timeout))
            for session_id, runtime in list(self.runtimes.items()):
                if runtime.lock.locked() or runtime.ssh is None:
                    continue
                if runtime.connected and time.monotonic() - runtime.touched < self.settings.idle_timeout:
                    continue
                try:
                    async with runtime.lock:
                        await self.sweep_runtime(session_id, runtime)
                except (SQLAlchemyError, OSError, asyncssh.Error):
                    logger.warning("Idle SSH cleanup could not complete")
            expiry = time.time() - 86400 * self.settings.output_retention_days
            for file in self.settings.data_dir.glob("*.db"):
                try:
                    if file.stem.startswith(("e_", "t_")) and file.stat().st_mtime < expiry:
                        await asyncio.to_thread(self.ring(file.stem).compact_expired)
                except (OSError, sqlite3.Error):
                    logger.warning("Output storage cleanup could not complete")

    async def sweep_runtime(self, session_id: str, runtime: Runtime) -> None:
        if runtime.connected:
            if time.monotonic() - runtime.touched < self.settings.idle_timeout:
                return
            async with self.store.transaction() as db:
                foreground = await db.scalar(select(Execution.execution_id).where(
                    Execution.session_id == session_id, Execution.mode == "foreground",
                    Execution.status.in_(["PENDING", "RUNNING"])).limit(1))
            if foreground:
                return
        await runtime.disconnect()
        if self.cleanup_foreground:
            await self.cleanup_foreground(session_id)
        async with self.store.transaction.begin() as db:
            await db.execute(update(Session).where(
                Session.session_id == session_id, Session.status.in_(["READY", "BUSY", "RECONNECTING"]),
            ).values(status="DISCONNECTED"))

    async def watch_disconnect(self, session_id: str, runtime: Runtime, ssh: SSHConnection) -> None:
        await ssh.connection.wait_closed()
        async with runtime.lock:
            if runtime.ssh is not ssh:
                return
            runtime.last_error = "SSH_DISCONNECTED"
            await runtime.close_shell()
            if self.cleanup_foreground:
                await self.cleanup_foreground(session_id)
            async with self.store.transaction.begin() as db:
                await db.execute(update(Session).where(
                    Session.session_id == session_id, Session.status.in_(["READY", "BUSY", "RECONNECTING"]),
                ).values(status="DISCONNECTED"))

    async def shutdown(self) -> None:
        if self.sweeper:
            self.sweeper.cancel()
            await asyncio.gather(self.sweeper, return_exceptions=True)
        await asyncio.gather(*(runtime.disconnect() for runtime in self.runtimes.values()), return_exceptions=True)

    async def owned(self, agent: Principal, session_id: str | None, workspace_id: str = "default") -> Session:
        if session_id is None:
            self.security.workspace(agent, workspace_id)
            async with self.store.transaction() as db:
                current = await db.get(Active, (agent.owner_id, workspace_id))
            if current is None:
                raise ToolError("NO_ACTIVE_TERMINAL", "No active terminal in this workspace.")
            session_id = current.session_id
        row = await self.store.session(agent.owner_id, session_id)
        self.security.workspace(agent, row.workspace_id)
        self.security.credential(agent, ProfileInput.model_validate(row.snapshot))
        return row

    async def create(
        self, agent: Principal, profile_id: str, name: str, workspace_id: str,
    ) -> dict:
        self.security.workspace(agent, workspace_id)
        async with self.mutations, self.store.transaction.begin() as db:
            profile = await self.store.profile(agent.owner_id, profile_id)
            self.security.credential(agent, ProfileInput.model_validate(profile.configuration))
            row = await db.scalar(select(Session).where(
                Session.owner_id == agent.owner_id, Session.workspace_id == workspace_id,
                Session.profile_id == profile_id, Session.profile_version == profile.version,
                Session.name == name, Session.status != "CLOSED",
            ).order_by(Session.created_at.desc()).limit(1))
            reused = row is not None
            if row is None:
                count = await db.scalar(select(func.count()).select_from(Session).where(
                    Session.owner_id == agent.owner_id, Session.status != "CLOSED"))
                if count is not None and count >= self.settings.max_sessions_per_agent:
                    raise ToolError("SESSION_LIMIT", "Terminal limit reached. Close a terminal first.")
                row = Session(
                    session_id=uuid4().hex, owner_id=agent.owner_id, workspace_id=workspace_id,
                    profile_id=profile_id, profile_version=profile.version, snapshot=profile.configuration,
                    name=name, status="CREATING", backend="pending",
                )
                db.add(row)
        await self.connect(agent, row)
        row = await self.owned(agent, row.session_id)
        await self.activate(agent, row, connect=False)
        audit("terminal_create", agent, session_id=row.session_id, profile_id=profile_id)
        return {**self.describe(row), "reused": reused}

    async def activate(self, agent: Principal, row: Session, connect: bool = True) -> dict:
        if connect:
            await self.connect(agent, row)
        async with self.mutations, self.store.transaction.begin() as db:
            current = await db.get(Session, row.session_id)
            if not current or current.status not in {"READY", "BUSY"}:
                raise ToolError("TERMINAL_UNAVAILABLE", "This terminal cannot be activated.")
            await db.merge(Active(owner_id=agent.owner_id, workspace_id=row.workspace_id, session_id=row.session_id))
        return {"session_id": row.session_id, "workspace_id": row.workspace_id, "active": True}

    async def connect(self, agent: Principal, row: Session, *, for_close: bool = False) -> Runtime:
        runtime = self.runtime(row.session_id)
        async with runtime.lock:
            return await self.connect_locked(agent, row, runtime, for_close=for_close)

    async def connect_locked(
        self, agent: Principal, row: Session, runtime: Runtime, *, for_close: bool = False,
    ) -> Runtime:
        row = await self.owned(agent, row.session_id)
        if row.status == "CLOSED":
            raise ToolError("TERMINAL_CLOSED", "This terminal has been closed.")
        if row.backend == "tmux_lost" and not for_close:
            raise ToolError("TMUX_SESSION_LOST", "The original remote tmux session no longer exists.")
        if row.backend in {"tmux", "tmux_pending", "pty"} and not agent.shell and not for_close:
            raise ToolError("SHELL_FORBIDDEN", "This terminal requires interactive shell authorization.")
        runtime.touched = time.monotonic()
        if runtime.connected and (runtime.shell_alive or row.backend == "exec" or for_close):
            async with self.store.transaction.begin() as db:
                await db.execute(update(Session).where(Session.session_id == row.session_id).values(last_active_at=now()))
            return runtime
        initial = row.backend in {"pending", "tmux_pending"}
        if not initial and row.backend == "pty" and not for_close:
            await self.set_status(row, "ERROR")
            raise ToolError("SHELL_LOST", "The plain PTY shell exited or disconnected and cannot be recovered.")
        if not initial and not self.settings.recovery_enabled and not for_close:
            raise ToolError("RECOVERY_DISABLED", "Terminal recovery is disabled.")
        opened = not runtime.connected
        if opened:
            await runtime.disconnect()
        else:
            await runtime.close_shell()
        if not for_close:
            await self.set_status(row, "CREATING" if initial else "RECONNECTING")
        runtime.last_error = None
        try:
            if opened:
                for attempt in range(self.settings.reconnect_attempts):
                    runtime.attempts += 1
                    try:
                        runtime.ssh = await self.ssh.connect(agent, ProfileInput.model_validate(row.snapshot))
                        runtime.monitor = asyncio.create_task(
                            self.watch_disconnect(row.session_id, runtime, runtime.ssh)
                        )
                        break
                    except ToolError as error:
                        if error.code not in {"SSH_UNAVAILABLE", "SSH_TIMEOUT", "DNS_FAILED"} or attempt + 1 == self.settings.reconnect_attempts:
                            raise
                        await asyncio.sleep(min(0.25 * (2 ** attempt), 4))
            assert runtime.ssh is not None
            ssh = runtime.ssh.connection
            if for_close:
                return runtime
            backend = row.backend
            tmux_name = row.tmux_session_name
            if backend == "pending":
                if not agent.shell:
                    backend = "exec"
                elif await self.remote.runnable(ssh):
                    backend = "tmux_pending"
                    tmux_name = "t_" + row.session_id
                    # Record the intended remote name before the side effect. Never silently replace a lost shell.
                    await self.set_status(row, "CREATING", backend=backend, tmux_session_name=tmux_name)
                elif self.settings.allow_pty_fallback:
                    backend = "pty"
                else:
                    raise ToolError("TMUX_UNAVAILABLE", "SSH host needs tmux and Python 3, or an explicitly enabled PTY fallback.")
            if backend in {"tmux_pending", "tmux"}:
                assert tmux_name is not None
                await self.remote.prepare_tmux(ssh, tmux_name, pending=backend == "tmux_pending")
                backend = "tmux"
            if backend in {"tmux", "pty"}:
                runtime.shell = await self.remote.attach(ssh, tmux_name)
                runtime.reader = asyncio.create_task(self.consume_shell(runtime.shell, row.session_id, backend))
            await self.set_status(row, "READY", backend=backend, tmux_session_name=tmux_name)
            async with self.store.transaction.begin() as db:
                profile = await db.get(Profile, row.profile_id)
                if profile and profile.version == row.profile_version:
                    profile.last_connected_at = now()
            return runtime
        except (Exception, asyncio.CancelledError) as error:
            if opened:
                await runtime.disconnect()
            else:
                await runtime.close_shell()
            runtime.last_error = error.code if isinstance(error, ToolError) else "TERMINAL_UNAVAILABLE"
            if row.backend == "tmux" and runtime.last_error == "TMUX_SESSION_LOST":
                await self.set_status(row, "ERROR", backend="tmux_lost")
            else:
                await self.set_status(row, "ERROR")
            raise

    async def consume_shell(
        self, shell: asyncssh.SSHClientProcess[bytes], session_id: str, backend: str,
    ) -> None:
        ring = self.ring("t_" + session_id)
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        while chunk := await shell.stdout.read(2048):
            if backend == "pty":
                await asyncio.to_thread(ring.append, "terminal", decoder.decode(chunk))
        if backend == "pty":
            await asyncio.to_thread(ring.append, "terminal", decoder.decode(b"", final=True))

    async def send(self, agent: Principal, row: Session, data: str) -> dict:
        self.security.shell(agent)
        runtime = self.runtimes.setdefault(row.session_id, Runtime())
        async with runtime.lock:
            await self.connect_locked(agent, row, runtime)
            if not runtime.shell:
                raise ToolError("SHELL_UNAVAILABLE", "This terminal has no interactive shell.")
            try:
                payload = data.encode("utf-8")
                runtime.shell.stdin.write(payload)
                async with asyncio.timeout(5):
                    await runtime.shell.stdin.drain()
            except (asyncssh.Error, OSError, TimeoutError):
                raise ToolError("INPUT_UNKNOWN", "Input delivery is uncertain. Inspect the terminal before retrying.") from None
        audit("terminal_send", agent, session_id=row.session_id)
        return {"session_id": row.session_id, "input_bytes": len(payload)}

    async def resize(self, agent: Principal, row: Session, columns: int, lines: int) -> dict:
        self.security.shell(agent)
        runtime = self.runtimes.setdefault(row.session_id, Runtime())
        async with runtime.lock:
            await self.connect_locked(agent, row, runtime)
            if not runtime.shell:
                raise ToolError("SHELL_UNAVAILABLE", "This terminal has no interactive shell.")
            runtime.shell.change_terminal_size(columns, lines)
        return {"session_id": row.session_id, "columns": columns, "lines": lines}

    async def close(self, agent: Principal, row: Session, preserve: bool) -> dict:
        runtime = self.runtimes.setdefault(row.session_id, Runtime())
        async with runtime.lock:
            row = await self.owned(agent, row.session_id)
            if row.status == "CLOSED":
                return {"session_id": row.session_id, "status": "CLOSED"}
            async with self.store.transaction() as db:
                detached = (await db.scalars(select(Execution).where(
                    Execution.session_id == row.session_id, Execution.mode == "detached",
                    Execution.status.in_(["PENDING", "RUNNING", "UNKNOWN"]),
                ))).all()
            if not preserve and (row.tmux_session_name or detached):
                await self.connect_locked(agent, row, runtime, for_close=True)
                assert runtime.ssh is not None
                ssh = runtime.ssh.connection
                for item in detached:
                    remote = await self.remote.request(ssh, "status", "e_" + item.execution_id)
                    if remote["status"] == "RUNNING" or (
                        remote["status"] == "UNKNOWN" and await self.remote.exists(ssh, "e_" + item.execution_id)
                    ):
                        raise ToolError("EXECUTION_ACTIVE", "Signal the detached task before destroying this terminal.")
                if row.tmux_session_name:
                    await self.remote.kill_tmux(ssh, row.tmux_session_name)
            await runtime.disconnect()
            if self.cleanup_foreground:
                await self.cleanup_foreground(row.session_id)
            if preserve:
                state = "DISCONNECTED" if row.backend != "pty" else "CLOSED"
            else:
                state = "CLOSED"
            await self.set_status(row, state)
            async with self.store.transaction.begin() as db:
                await db.execute(delete(Active).where(Active.session_id == row.session_id))
                await db.execute(update(Execution).where(
                    Execution.session_id == row.session_id, Execution.mode == "foreground",
                    Execution.status.in_(["RUNNING", "PENDING"]),
                ).values(status="UNKNOWN", updated_at=now()))
        audit("terminal_close", agent, session_id=row.session_id)
        return {"session_id": row.session_id, "status": state, "preserve_remote": preserve,
                "foreground_notice": "Closing SSH may terminate foreground processes."}

    def describe(self, row: Session) -> dict:
        runtime = self.runtimes.get(row.session_id)
        connected = runtime is not None and runtime.connected
        shell_alive = runtime is not None and runtime.shell_alive and connected
        state = row.status
        if state in {"READY", "BUSY"} and (not connected or (row.backend in {"tmux", "pty"} and not shell_alive)):
            state = "DISCONNECTED"
        return {
            "session_id": row.session_id, "profile_id": row.profile_id, "profile_version": row.profile_version,
            "workspace_id": row.workspace_id, "name": row.name, "server_name": row.snapshot["name"],
            "status": state, "last_active_at": row.last_active_at, "backend": row.backend,
            "ssh_connected": connected, "interactive_shell_alive": shell_alive,
            "recoverable": row.backend == "tmux" and state != "CLOSED" and self.settings.recovery_enabled,
            "connection_attempts": runtime.attempts if runtime else 0,
            "last_error": runtime.last_error if runtime else None,
        }

    async def list(self, agent: Principal, profile_id: str, workspace_id: str, status: str, name: str) -> dict:
        async with self.store.transaction() as db:
            rows = (await db.scalars(select(Session).where(Session.owner_id == agent.owner_id)
                                     .order_by(Session.last_active_at.desc()))).all()
            active = (await db.scalars(select(Active.session_id).where(Active.owner_id == agent.owner_id))).all()
        results = []
        for row in rows:
            if row.workspace_id not in agent.workspaces or (profile_id and row.profile_id != profile_id):
                continue
            if (workspace_id and row.workspace_id != workspace_id) or name.casefold() not in row.name.casefold():
                continue
            item = self.describe(row)
            if not status or status.upper() == item["status"]:
                results.append({**item, "active": row.session_id in active})
        return {"terminals": results}
