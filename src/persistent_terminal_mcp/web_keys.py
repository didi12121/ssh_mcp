import asyncio
from pathlib import Path
import shutil
import tempfile

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, ValidationError
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from starlette.requests import Request
from starlette.responses import JSONResponse

from .errors import ToolError
from .identity_store import admin_audit
from .models import Profile, Session
from .security import MANAGED_PREFIX, Security, credential_id
from .web_admin import WebAdmin, admin_response, read_model


class KeyRemoval(BaseModel):
    model_config = ConfigDict(extra="forbid")
    vault: Path


async def references(db, security: Security, vault: Path) -> dict[str, list[dict]]:
    catalog = security.credential_catalog()

    def key_id(configuration: dict) -> str | None:
        reference = configuration.get("credential_ref")
        if not reference:
            return None
        if reference in catalog:
            try:
                parts = catalog[reference].file.resolve().relative_to(vault).parts
            except ValueError:
                return None
            return parts[0] if len(parts) == 2 and parts[1] == "identity" else None
        return reference.removeprefix(MANAGED_PREFIX) if reference.startswith(MANAGED_PREFIX) else None

    result: dict[str, list[dict]] = {}
    profiles = (await db.scalars(select(Profile).where(Profile.deleted_at.is_(None)))).all()
    for profile in profiles:
        name = key_id(profile.configuration)
        if name:
            result.setdefault(name, []).append({"profile_id": profile.profile_id, "name": profile.configuration["name"]})
    sessions = (await db.scalars(select(Session).where(Session.status != "CLOSED"))).all()
    for session in sessions:
        name = key_id(session.snapshot)
        if name:
            result.setdefault(name, []).append({"session_id": session.session_id, "name": session.name})
    return result


def remove_directory(vault: Path, key_id: str) -> None:
    entry = vault / key_id
    if entry.is_symlink() or not entry.is_dir():
        raise ToolError("KEY_NOT_FOUND", "SSH key not found.")
    if not (entry / "key.json").is_file():
        raise ToolError("KEY_NOT_FOUND", "SSH key metadata not found.")
    retired = Path(tempfile.mkdtemp(prefix=".remove-", dir=vault))
    try:
        entry.rename(retired / "entry")
    finally:
        shutil.rmtree(retired)


def register_key_routes(mcp: FastMCP, admin: WebAdmin, security: Security) -> None:
    store = admin.identities.store

    @mcp.custom_route("/admin/keys", methods=["GET"])
    @mcp.custom_route("/admin/keys/{key_id}/delete", methods=["POST"])
    async def keys(request: Request) -> JSONResponse:
        try:
            if not await admin.authorize(request):
                return admin_response({"code": "ADMIN_FORBIDDEN", "error": "Administrator authorization is required."}, 403)
            directory = security.settings.managed_keys_dir
            if directory is None:
                raise ToolError("KEY_VAULT_UNAVAILABLE", "Managed SSH key storage is not configured.")
            vault = directory.resolve()
            if request.method == "GET":
                async with store.transaction() as db:
                    return admin_response({"vault": str(vault), "references": await references(db, security, vault)})
            key_id = credential_id.validate_python(request.path_params["key_id"])
            data = await read_model(request, KeyRemoval, 8192)
            if data.vault.resolve() != vault:
                raise ToolError("KEY_VAULT_UNAVAILABLE", "The configured key stores do not match.")
            # Profile writes use the same SQLite write lock, so validation and removal cannot race.
            async with store.write() as db:
                if (await references(db, security, vault)).get(key_id):
                    raise ToolError("KEY_IN_USE", "This key is referenced by an SSH connection or open terminal.")
                await asyncio.to_thread(remove_directory, vault, key_id)
            admin_audit("key_delete", key_id=key_id)
            return admin_response({"deleted": True})
        except ToolError as failure:
            status = {"KEY_NOT_FOUND": 404, "KEY_IN_USE": 409, "KEY_VAULT_UNAVAILABLE": 503}.get(failure.code, 400)
            return admin_response({"code": failure.code, "error": str(failure)}, status)
        except (ValidationError, ValueError):
            return admin_response({"code": "INVALID_INPUT", "error": "Invalid key request."}, 400)
        except (OSError, SQLAlchemyError):
            return admin_response({"code": "ADMIN_UNAVAILABLE", "error": "Key storage is unavailable."}, 503)
