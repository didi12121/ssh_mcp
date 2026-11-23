import asyncio
import time
from uuid import uuid4

from sqlalchemy import delete, select

from .backends import Remote
from .config import Principal
from .errors import ToolError
from .identity_models import TokenProfileGrant
from .identity_store import admin_audit
from .models import Profile, ProfileInput, ProfilePatch, Session, now, profile_binding
from .security import Security
from .ssh import SSHConnectionManager
from .storage import Store


def profile_info(row: Profile) -> dict:
    return {
        **row.configuration, "profile_id": row.profile_id, "enabled": row.enabled,
        "version": row.version, "created_at": row.created_at, "updated_at": row.updated_at,
        "last_connected_at": row.last_connected_at,
    }


def connection_alias(row: Profile) -> dict:
    data = row.configuration
    return {"profile_id": row.profile_id, "name": data["name"],
            "description": data.get("description"), "tags": data.get("tags", [])}


def usable(profile: Profile | None, agent: Principal, session: Session | None = None) -> bool:
    return bool(
        profile and profile.enabled and not profile.deleted_at
        and agent.profile_grants.get(profile.profile_id) == profile.access_version
        and (session is None or session.profile_access_version == profile.access_version)
    )


class Profiles:
    def __init__(self, store: Store, security: Security, ssh: SSHConnectionManager, mutations: asyncio.Lock) -> None:
        self.store = store
        self.security = security
        self.ssh = ssh
        self.remote = Remote(ssh.settings)
        self.mutations = mutations

    async def create(self, data: ProfileInput) -> dict:
        async with self.store.write() as db:
            self.security.credential(data)
            row = Profile(profile_id=uuid4().hex, enabled=data.enabled,
                          configuration=data.model_dump(exclude={"enabled"}))
            db.add(row)
        admin_audit("connection_create", profile_id=row.profile_id)
        return profile_info(row)

    async def list(self, name: str, host: str, tag: str, page: int, limit: int) -> dict:
        async with self.store.transaction() as db:
            rows = (await db.scalars(select(Profile).where(Profile.deleted_at.is_(None))
                                     .order_by(Profile.created_at, Profile.profile_id))).all()
        matches = [
            profile_info(row) for row in rows
            if name.casefold() in row.configuration["name"].casefold()
            and host.casefold() in row.configuration["host"].casefold()
            and (not tag or tag in row.configuration.get("tags", []))
        ]
        start = (page - 1) * limit
        return {"profiles": matches[start:start + limit], "total": len(matches), "page": page, "limit": limit}

    async def discover(self, agent: Principal, name: str, tag: str, page: int, limit: int) -> dict:
        async with self.store.transaction() as db:
            rows = (await db.scalars(select(Profile).where(Profile.profile_id.in_(agent.profile_grants))
                                     .order_by(Profile.created_at, Profile.profile_id))).all() if agent.profile_grants else []
        matches = [
            connection_alias(row) for row in rows if usable(row, agent)
            and name.casefold() in row.configuration["name"].casefold()
            and (not tag or tag in row.configuration.get("tags", []))
        ]
        start = (page - 1) * limit
        return {"connections": matches[start:start + limit], "total": len(matches), "page": page}

    async def edit(self, profile_id: str, patch: ProfilePatch) -> dict:
        async with self.mutations, self.store.write() as db:
            row = await db.get(Profile, profile_id)
            if row is None or row.deleted_at:
                raise ToolError("PROFILE_NOT_FOUND", "Connection profile not found.")
            data = ProfileInput.model_validate({**row.configuration, "enabled": row.enabled,
                                                **patch.model_dump(exclude_unset=True)})
            changed = profile_binding(data.model_dump()) != profile_binding(row.configuration)
            if changed or data.enabled:
                self.security.credential(data)
            row.configuration = data.model_dump(exclude={"enabled"})
            row.enabled = data.enabled
            row.version += 1
            row.updated_at = now()
            if changed:
                row.access_version += 1
                await db.execute(delete(TokenProfileGrant).where(TokenProfileGrant.profile_id == profile_id))
            linked = (await db.scalars(select(Session.session_id).where(
                Session.profile_id == profile_id, Session.status != "CLOSED"))).all()
        admin_audit("connection_rebind" if changed else "connection_update", profile_id=profile_id)
        return {**profile_info(row), "session_ids": list(linked), "grants_invalidated": changed}

    async def delete(self, profile_id: str) -> dict:
        async with self.mutations, self.store.write() as db:
            row = await db.get(Profile, profile_id)
            if row is None or row.deleted_at:
                raise ToolError("PROFILE_NOT_FOUND", "Connection profile not found.")
            linked = await db.scalar(select(Session.session_id).where(
                Session.profile_id == profile_id, Session.status != "CLOSED").limit(1))
            if linked:
                raise ToolError("PROFILE_IN_USE", "Close the associated terminals first.")
            row.enabled = False
            row.deleted_at = now()
            await db.execute(delete(TokenProfileGrant).where(TokenProfileGrant.profile_id == profile_id))
        admin_audit("connection_delete", profile_id=profile_id)
        return {"profile_id": profile_id, "deleted": True}

    async def test(self, profile_id: str) -> dict:
        row = await self.store.profile(profile_id)
        start = time.monotonic()
        ssh = await self.ssh.connect(ProfileInput.model_validate(row.configuration))
        try:
            latency = round((time.monotonic() - start) * 1000)
            capability = await self.remote.call(ssh.connection, "command -v tmux >/dev/null 2>&1", timeout=5)
            async with self.store.transaction.begin() as db:
                current = await db.get(Profile, profile_id)
                if current and current.version == row.version:
                    current.last_connected_at = now()
        finally:
            await ssh.close()
        admin_audit("connection_test", profile_id=profile_id)
        return {"profile_id": profile_id, "reachable": True, "authenticated": True,
                "tmux_available": capability.exit_status == 0, "latency_ms": latency}
