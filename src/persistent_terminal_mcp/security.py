import hashlib
import hmac
import logging
import os
from pathlib import Path
from typing import Any

import asyncssh
from cryptography.fernet import Fernet
from pydantic import TypeAdapter

from .config import Credential, Identifier, Principal, Settings
from .errors import ToolError
from .models import ProfileInput

principals_schema = TypeAdapter(list[Principal])
credentials_schema = TypeAdapter(dict[Identifier, Credential])
audit_log = logging.getLogger("terminal.audit")


def private_file(file: Path) -> bytes:
    info = file.stat()
    if not file.is_file() or (os.name == "posix" and (info.st_uid != os.getuid() or info.st_mode & 0o077)):
        raise PermissionError("Secret file must be owned by the service user and inaccessible to other users")
    return file.read_bytes()


class Security:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def authenticate(self, token: str) -> Principal | None:
        if len(token) < 32 or len(token) > 256:
            return None
        try:
            principals = principals_schema.validate_json(private_file(self.settings.principals_file))
        except (ValueError, OSError):
            return None
        digest = hashlib.sha256(token.encode()).hexdigest()
        matches = [principal for principal in principals if hmac.compare_digest(digest, principal.token_sha256)]
        return matches[0] if len(matches) == 1 else None

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
            credentials = credentials_schema.validate_json(private_file(self.settings.credentials_file))
            credential = credentials[profile.credential_ref]
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
            if not argv or command is not None or (cwd is not None and not principal.shell):
                raise ToolError("COMMAND_FORBIDDEN", "Use a configured operation without a custom command or directory.")
            return join(argv)
        if not principal.shell:
            raise ToolError("COMMAND_FORBIDDEN", "This principal may execute configured operations only.")
        if not command or not command.strip() or "\0" in command:
            raise ToolError("INVALID_COMMAND", "Supply a nonempty shell command.")
        return command


def audit(action: str, principal: Principal, *, result: str = "ok", **ids: str) -> None:
    audit_log.info("terminal_action", extra={"action_fields": {
        "action": action, "owner_id": principal.owner_id, "result": result, **ids,
    }})
