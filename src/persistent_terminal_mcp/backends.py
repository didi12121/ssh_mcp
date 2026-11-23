import asyncio
from dataclasses import dataclass
import json
from importlib.resources import files
from shlex import join

import asyncssh

from .config import Settings
from .errors import ToolError


@dataclass(frozen=True)
class RemoteResult:
    exit_status: int | None
    stdout: str


class Remote:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        package = files(__package__)
        # The same bounded output format is used locally and on remote hosts without installing a package.
        self.source = (
            (package / "ring.py").read_text() + "\n"
            + (package / "remote_worker.py").read_text().replace("from .ring import OutputRing", "")
        )

    async def call(self, ssh: asyncssh.SSHClientConnection, command: str, timeout: float = 10) -> RemoteResult:
        try:
            async with asyncio.timeout(timeout), ssh.create_process(
                command, encoding=None, stderr=asyncssh.DEVNULL,
            ) as process:
                process.stdin.write_eof()
                output = bytearray()
                while chunk := await process.stdout.read(8192):
                    output.extend(chunk)
                    if len(output) > 1_048_576:
                        raise ToolError("REMOTE_OUTPUT_LIMIT", "The remote helper exceeded its output limit.")
                await process.wait_closed()
                return RemoteResult(process.exit_status, output.decode("utf-8", errors="replace"))
        except (asyncssh.Error, OSError, TimeoutError):
            raise ToolError("REMOTE_UNAVAILABLE", "The remote terminal operation did not complete.") from None

    def helper(self, operation: str, resource: str, *args: str) -> str:
        return join(["python3", "-c", self.source, operation, resource, str(self.settings.output_max_bytes),
                     str(self.settings.output_retention_days * 86400), *args])

    @staticmethod
    def tmux(*args: str) -> str:
        return join(["tmux", "-L", "persistent-terminal-mcp", "-f", "/dev/null", *args])

    async def runnable(self, ssh: asyncssh.SSHClientConnection) -> bool:
        result = await self.call(ssh, "command -v tmux >/dev/null && command -v python3 >/dev/null")
        return result.exit_status == 0

    async def exists(self, ssh: asyncssh.SSHClientConnection, name: str) -> bool:
        return (await self.call(ssh, self.tmux("has-session", "-t", "=" + name))).exit_status == 0

    async def create_tmux(self, ssh: asyncssh.SSHClientConnection, name: str) -> None:
        command = self.tmux("new-session", "-d", "-s", name, "-x", "120", "-y", "32")
        pipe = self.tmux("pipe-pane", "-o", "-t", name + ":0.0", self.helper("pipe", name))
        result = await self.call(ssh, command + " && " + pipe)
        if result.exit_status != 0:
            await self.kill_tmux(ssh, name)
            raise ToolError("TERMINAL_START_FAILED", "Remote tmux terminal could not be initialized.")

    async def attach(self, ssh: asyncssh.SSHClientConnection, name: str | None) -> asyncssh.SSHClientProcess[bytes]:
        try:
            async with asyncio.timeout(10):
                return await ssh.create_process(
                    self.tmux("attach-session", "-t", "=" + name) if name else None,
                    term_type="xterm-256color", term_size=(120, 32), encoding=None,
                )
        except (asyncssh.Error, OSError, TimeoutError):
            raise ToolError("TERMINAL_ATTACH_FAILED", "Could not open a remote PTY.") from None

    async def kill_tmux(self, ssh: asyncssh.SSHClientConnection, name: str) -> None:
        if await self.exists(ssh, name):
            result = await self.call(ssh, self.tmux("kill-session", "-t", "=" + name))
            if result.exit_status != 0 and await self.exists(ssh, name):
                raise ToolError("TERMINAL_CLOSE_FAILED", "Remote tmux could not be closed.")

    async def request(self, ssh: asyncssh.SSHClientConnection, operation: str, name: str, *args: str):
        result = await self.call(ssh, self.helper(operation, name, *args))
        if result.exit_status != 0:
            raise ToolError("REMOTE_STATE_UNAVAILABLE", "Remote task or output metadata could not be read.")
        try:
            return json.loads(result.stdout)
        except ValueError:
            raise ToolError("REMOTE_STATE_UNAVAILABLE", "Remote helper did not return valid metadata.") from None

    async def detach(
        self, ssh: asyncssh.SSHClientConnection, name: str, command: str, cwd: str | None,
    ) -> None:
        if not await self.runnable(ssh):
            raise ToolError("DETACHED_UNAVAILABLE", "Detached execution requires tmux and Python 3 on the SSH host.")
        payload = json.dumps({"command": command, "cwd": cwd, "timeout": self.settings.execution_timeout})
        start = self.tmux("new-session", "-d", "-s", name, self.helper("execute", name, payload))
        result = await self.call(ssh, start)
        if result.exit_status != 0:
            raise ToolError("DETACHED_START_FAILED", "The detached task could not be started.")
