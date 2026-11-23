import logging
import os
import stat
from pathlib import Path
from typing import Any

import asyncssh
from cryptography.fernet import Fernet
from pydantic import TypeAdapter

from .config import Credential, Identifier, Principal, Settings
from .errors import ToolError
from .models import ProfileInput

credentials_schema = TypeAdapter(dict[Identifier, Credential])
credential_id = TypeAdapter(Identifier)
MANAGED_PREFIX = "managed_"
audit_log = logging.getLogger("terminal.audit")


def private_file(file: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(file, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or (os.name == "posix" and (
            info.st_uid != os.getuid() or info.st_mode & 0o077
        )):
            raise PermissionError("Secret file must be owned by the service user and inaccessible to other users")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            return handle.read()
    finally:
        os.close(fd)


class Security:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def credential_catalog(self) -> dict[str, Credential]:
        try:
            return credentials_schema.validate_json(private_file(self.settings.credentials_file))
        except FileNotFoundError:
            return {}

    def managed_key(self, reference: str) -> Credential | None:
        directory = self.settings.managed_keys_dir
        if directory is None or not reference.startswith(MANAGED_PREFIX):
            return None
        try:
            key_id = credential_id.validate_python(reference.removeprefix(MANAGED_PREFIX))
        except ValueError:
            return None
        key = directory / key_id / "identity"
        if key.is_file():
            return Credential(kind="key", file=key)
        return None

    def visible_credentials(self) -> dict[str, str]:
        result = {ref: item.kind for ref, item in self.credential_catalog().items()}
        directory = self.settings.managed_keys_dir
        if directory and directory.is_dir():
            for item in directory.iterdir():
                ref = MANAGED_PREFIX + item.name
                if self.managed_key(ref):
                    result.setdefault(ref, "key")
        return result

    def credential(self, principal: Principal, profile: ProfileInput) -> Credential | None:
        if profile.host not in principal.targets:
            raise ToolError("TARGET_FORBIDDEN", "This SSH host is outside the principal's allowed targets.")
        if profile.auth_type == "agent":
            if not principal.ssh_agent or not self.settings.ssh_agent_path:
                raise ToolError("CREDENTIAL_FORBIDDEN", "SSH agent authentication is unavailable for this principal.")
            return None
        if profile.credential_ref not in principal.credentials:
            raise ToolError("CREDENTIAL_FORBIDDEN", "Credential reference is unavailable for this principal.")
        try:
            assert profile.credential_ref is not None
            catalog = self.credential_catalog()
            credential = catalog.get(profile.credential_ref) or self.managed_key(profile.credential_ref)
            if credential is None:
                raise KeyError(profile.credential_ref)
            if (profile.auth_type == "password") != (credential.kind == "password"):
                raise ValueError("credential kind mismatch")
            return credential
        except (OSError, ValueError, KeyError):
            raise ToolError("CREDENTIAL_UNAVAILABLE", "The configured credential is unavailable.") from None

    def ssh_options(self, credential: Credential) -> dict[str, Any]:
        try:
            data = private_file(credential.file)
            if credential.kind != "key":
                if self.settings.master_key_file is None:
                    raise ValueError("missing encryption key")
                data = Fernet(private_file(self.settings.master_key_file).strip()).decrypt(data.strip())
            if credential.kind == "password":
                return {"password": data.decode("utf-8"), "client_keys": None}
            return {"client_keys": [asyncssh.import_private_key(data)]}
        except Exception:
            raise ToolError("CREDENTIAL_UNAVAILABLE", "The configured SSH secret could not be loaded.") from None

    @staticmethod
    def workspace(principal: Principal, workspace_id: str) -> None:
        if workspace_id not in principal.workspaces:
            raise ToolError("WORKSPACE_FORBIDDEN", "This workspace is not assigned to the principal.")

    @staticmethod
    def shell(principal: Principal) -> None:
        if not principal.shell:
            raise ToolError("SHELL_FORBIDDEN", "Interactive shell access requires explicit authorization.")

    @staticmethod
    def command(principal: Principal, command: str | None, operation: str | None, cwd: str | None) -> str:
        from shlex import join

        if operation is not None:
            argv = principal.commands.get(operation)
            if not argv or command is not None or (cwd is not None and not principal.custom_commands):
                raise ToolError("COMMAND_FORBIDDEN", "Use a configured operation without a custom command or directory.")
            return join(argv)
        if not principal.custom_commands:
            raise ToolError("COMMAND_FORBIDDEN", "This principal may execute configured operations only.")
        if not command or not command.strip() or "\0" in command:
            raise ToolError("INVALID_COMMAND", "Supply a nonempty shell command.")
        return command


def audit(action: str, principal: Principal, *, result: str = "ok", **ids: str) -> None:
    audit_log.info("terminal_action", extra={"action_fields": {
        "action": action, "owner_id": principal.owner_id, "result": result, **ids,
    }})
