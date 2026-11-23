import asyncio
import time
from uuid import uuid4

from sqlalchemy import select

from .backends import Remote
from .config import Principal
from .errors import ToolError
from .models import Profile, ProfileInput, ProfilePatch, Session, now
from .security import Security, audit
from .ssh import SSHConnectionManager
from .storage import Store


def profile_info(row: Profile) -> dict:
    return {
        **row.configuration, "profile_id": row.profile_id, "owner_id": row.owner_id,
        "version": row.version, "created_at": row.created_at, "updated_at": row.updated_at,
        "last_connected_at": row.last_connected_at,
    }


class Profiles:
    def __init__(self, store: Store, security: Security, ssh: SSHConnectionManager, mutations: asyncio.Lock) -> None:
        self.store = store
        self.security = security
        self.ssh = ssh
        self.remote = Remote(ssh.settings)
        self.mutations = mutations

    async def create(self, agent: Principal, data: ProfileInput) -> dict:
        self.security.credential(agent, data)
        row = Profile(profile_id=uuid4().hex, owner_id=agent.owner_id, configuration=data.model_dump())
        async with self.store.transaction.begin() as db:
            db.add(row)
        audit("connection_create", agent, profile_id=row.profile_id)
        return profile_info(row)

    async def list(self, agent: Principal, name: str, host: str, tag: str, page: int, limit: int) -> dict:
        async with self.store.transaction() as db:
            rows = (await db.scalars(select(Profile).where(Profile.owner_id == agent.owner_id)
                                     .order_by(Profile.created_at, Profile.profile_id))).all()
        matches = [
            profile_info(row) for row in rows
            if name.casefold() in row.configuration["name"].casefold()
            and host.casefold() in row.configuration["host"].casefold()
            and (not tag or tag in row.configuration["tags"])
        ]
        start = (page - 1) * limit
        return {"profiles": matches[start:start + limit], "total": len(matches), "page": page}

    async def edit(self, agent: Principal, profile_id: str, patch: ProfilePatch) -> dict:
        async with self.mutations, self.store.transaction.begin() as db:
            row = await self.store.profile(agent.owner_id, profile_id)
            data = ProfileInput.model_validate({**row.configuration, **patch.model_dump(exclude_unset=True)})
            self.security.credential(agent, data)
            row.configuration = data.model_dump()
            row.version += 1
            row.updated_at = now()
            await db.merge(row)
            linked = (await db.scalars(select(Session.session_id).where(
                Session.profile_id == profile_id, Session.status != "CLOSED"))).all()
        audit("connection_update", agent, profile_id=profile_id)
        return {**profile_info(row), "unchanged_session_ids": list(linked)}

    async def delete(self, agent: Principal, profile_id: str) -> dict:
        async with self.mutations, self.store.transaction.begin() as db:
            row = await self.store.profile(agent.owner_id, profile_id)
            linked = await db.scalar(select(Session.session_id).where(
                Session.profile_id == profile_id, Session.status != "CLOSED").limit(1))
            if linked:
                raise ToolError("PROFILE_IN_USE", "Close or destroy the associated terminals first.")
            await db.delete(row)
        audit("connection_delete", agent, profile_id=profile_id)
        return {"profile_id": profile_id, "deleted": True}

    async def test(self, agent: Principal, profile_id: str) -> dict:
        row = await self.store.profile(agent.owner_id, profile_id)
        start = time.monotonic()
        ssh = await self.ssh.connect(agent, ProfileInput.model_validate(row.configuration))
        try:
            latency = round((time.monotonic() - start) * 1000)
            capability = await self.remote.call(ssh.connection, "command -v tmux >/dev/null 2>&1", timeout=5)
            async with self.store.transaction.begin() as db:
                current = await db.get(Profile, profile_id)
                if current and current.version == row.version:
                    current.last_connected_at = now()
        finally:
            await ssh.close()
        audit("connection_test", agent, profile_id=profile_id)
        return {"profile_id": profile_id, "reachable": True, "authenticated": True,
                "tmux_available": capability.exit_status == 0, "latency_ms": latency}
