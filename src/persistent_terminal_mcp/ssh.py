import asyncio
from contextlib import AsyncExitStack
import socket
from dataclasses import dataclass
from typing import Any

import asyncssh

from .config import Settings
from .errors import ToolError
from .models import ProfileInput
from .security import Security


@dataclass
class SSHConnection:
    connection: asyncssh.SSHClientConnection
    resources: AsyncExitStack

    async def close(self) -> None:
        try:
            async with asyncio.timeout(3):
                await self.resources.aclose()
        except (asyncssh.Error, OSError, TimeoutError):
            self.connection.abort()


class SSHConnectionManager:
    def __init__(self, settings: Settings, security: Security) -> None:
        self.settings = settings
        self.security = security

    async def connect(self, profile: ProfileInput) -> SSHConnection:
        credential = self.security.credential(profile)
        resources = AsyncExitStack()
        try:
            options: dict[str, Any]
            async with asyncio.timeout(self.settings.connect_timeout):
                if credential is None:
                    ssh_agent = await asyncssh.connect_agent(self.settings.ssh_agent_path)
                    await resources.enter_async_context(ssh_agent)
                    identities = await ssh_agent.get_keys()
                    if not identities:
                        raise ToolError("CREDENTIAL_UNAVAILABLE", "The configured SSH agent has no keys.")
                    options = {"client_keys": identities}
                else:
                    options = self.security.ssh_options(credential)
                connection = await resources.enter_async_context(asyncssh.connect(
                    profile.host, profile.port, username=profile.username,
                    known_hosts=str(self.settings.known_hosts.resolve()),
                    config=None, agent_forwarding=False, agent_path=None,
                    kbdint_auth=False, preferred_auth=["password"] if profile.auth_type == "password" else ["publickey"],
                    keepalive_interval=self.settings.keepalive_interval, keepalive_count_max=3,
                    **options,
                ))
            return SSHConnection(connection, resources)
        except BaseException as error:
            await resources.aclose()
            if isinstance(error, (asyncio.CancelledError, ToolError)):
                raise
            if isinstance(error, asyncssh.HostKeyNotVerifiable):
                failure = ToolError("HOST_KEY_UNVERIFIED", "SSH host key is unknown or changed. Verify and provision known_hosts.")
            elif isinstance(error, asyncssh.PermissionDenied):
                failure = ToolError("SSH_AUTH_FAILED", "SSH authentication was rejected.")
            elif isinstance(error, socket.gaierror):
                failure = ToolError("DNS_FAILED", "The SSH hostname could not be resolved.")
            elif isinstance(error, TimeoutError):
                failure = ToolError("SSH_TIMEOUT", "The SSH handshake or authentication timed out.")
            elif isinstance(error, (OSError, asyncssh.Error)):
                failure = ToolError("SSH_UNAVAILABLE", "The SSH endpoint or trusted host key file is unavailable.")
            else:
                raise
            raise failure from None
