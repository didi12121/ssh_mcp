from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import logging
import re
import secrets
from uuid import uuid4

from sqlalchemy import func, or_, select, text, update
from sqlalchemy.exc import SQLAlchemyError

from .config import Principal
from .errors import ToolError
from .identity_models import AccessToken, AgentIdentity, AgentInput, AgentPatch, TokenInput
from .storage import Store
from .security import private_file

audit = logging.getLogger("terminal.audit")
generated_pattern = re.compile(r"ptmcp_[a-f0-9]{32}_[A-Za-z0-9_-]{43}")


def timestamp(value: datetime | None = None) -> str:
    return (value or datetime.now(UTC)).isoformat(timespec="microseconds")


def state(row: AccessToken, at: str) -> str:
    if row.revoked_at or row.deleted_at:
        return "REVOKED"
    return "EXPIRED" if row.expires_at and row.expires_at <= at else "ACTIVE"


def token_info(row: AccessToken, at: str) -> dict:
    return {
        "token_id": row.token_id, "owner_id": row.owner_id, "name": row.name,
        "status": state(row, at), "created_at": row.created_at, "expires_at": row.expires_at,
        "last_used_at": row.last_used_at, "revoked_at": row.revoked_at, "revoked_reason": row.revoked_reason,
        "created_by": row.created_by, "legacy": row.legacy,
    }


def agent_info(row: AgentIdentity, count: int, activity: str | None) -> dict:
    return {
        **row.permissions_json, "owner_id": row.owner_id, "name": row.name, "description": row.description,
        "enabled": row.enabled, "token_count": count, "last_used_at": activity,
        "created_at": row.created_at, "updated_at": row.updated_at,
    }


def admin_audit(action: str, owner_id: str, token_id: str | None = None) -> None:
    audit.info("identity_admin_action", extra={"action_fields": {
        "actor": "web_admin", "action": action, "owner_id": owner_id, **({"token_id": token_id} if token_id else {}),
    }})


class Identities:
    def __init__(self, store: Store) -> None:
        self.store = store
        self.settings = store.settings

    @asynccontextmanager
    async def write(self):
        async with self.store.transaction.begin() as db:
            await db.execute(text("BEGIN IMMEDIATE"))
            yield db

    async def authenticate(self, token: str) -> Principal | None:
        if not 32 <= len(token) <= 256:
            return None
        if self.settings.web_admin_token_file and re.fullmatch(r"[a-f0-9]{64}", token):
            try:
                if hmac.compare_digest(private_file(self.settings.web_admin_token_file).strip(), token.encode()):
                    return None
            except OSError:
                return None
        digest = hashlib.sha256(token.encode()).hexdigest()
        instant = datetime.now(UTC)
        at = timestamp(instant)
        async with self.store.transaction() as db:
            record = (await db.execute(
                select(AccessToken, AgentIdentity).join(AgentIdentity, AccessToken.owner_id == AgentIdentity.owner_id)
                .where(AccessToken.token_hash == digest)
            )).one_or_none()
        expected = record[0].token_hash if record else "0" * 64
        matches = hmac.compare_digest(digest, expected)
        if not record or not matches:
            return None
        key, agent = record
        if not agent.enabled or state(key, at) != "ACTIVE":
            return None
        if not key.legacy and not generated_pattern.fullmatch(token):
            return None
        cutoff = timestamp(instant - timedelta(seconds=self.settings.token_usage_interval_seconds))
        if key.last_used_at is None or key.last_used_at <= cutoff:
            try:
                async with self.store.transaction.begin() as db:
                    await db.execute(update(AccessToken).where(
                        AccessToken.token_id == key.token_id,
                        AccessToken.revoked_at.is_(None), AccessToken.deleted_at.is_(None),
                        or_(AccessToken.last_used_at.is_(None), AccessToken.last_used_at <= cutoff),
                    ).values(last_used_at=at))
            except SQLAlchemyError:
                audit.warning("token_usage_update_failed")
        return agent.principal()

    async def principals(self) -> dict[str, Principal]:
        async with self.store.transaction() as db:
            rows = (await db.scalars(select(AgentIdentity))).all()
        return {row.owner_id: row.principal() for row in rows}

    async def registered(self, token: str) -> bool:
        digest = hashlib.sha256(token.encode()).hexdigest()
        async with self.store.transaction() as db:
            return await db.scalar(select(AccessToken.token_id).where(AccessToken.token_hash == digest)) is not None

    @staticmethod
    def agent_stats():
        return select(
            AgentIdentity, func.count(AccessToken.token_id).filter(AccessToken.deleted_at.is_(None)),
            func.max(AccessToken.last_used_at),
        ).outerjoin(AccessToken, AccessToken.owner_id == AgentIdentity.owner_id).group_by(AgentIdentity.owner_id)

    async def agents(self, page: int, limit: int, search: str) -> dict:
        match = or_(AgentIdentity.owner_id.icontains(search, autoescape=True),
                    AgentIdentity.name.icontains(search, autoescape=True))
        async with self.store.transaction() as db:
            total = await db.scalar(select(func.count()).select_from(AgentIdentity).where(match))
            rows = (await db.execute(self.agent_stats().where(match).order_by(AgentIdentity.owner_id)
                                     .offset((page - 1) * limit).limit(limit))).all()
        return {"agents": [agent_info(*row) for row in rows], "page": page, "limit": limit, "total": total}

    async def agent(self, owner_id: str) -> dict:
        async with self.store.transaction() as db:
            row = (await db.execute(self.agent_stats().where(AgentIdentity.owner_id == owner_id))).one_or_none()
        if row is None:
            raise ToolError("AGENT_NOT_FOUND", "Agent does not exist.")
        return agent_info(*row)

    async def create_agent(self, data: AgentInput) -> dict:
        at = timestamp()
        async with self.write() as db:
            if await db.get(AgentIdentity, data.owner_id):
                raise ToolError("AGENT_EXISTS", "The Agent ID is already in use.")
            row = AgentIdentity(owner_id=data.owner_id, name=data.name, description=data.description,
                                enabled=data.enabled, permissions_json=data.permissions(), created_at=at, updated_at=at)
            db.add(row)
        admin_audit("agent_create", row.owner_id)
        return agent_info(row, 0, None)

    async def update_agent(self, owner_id: str, data: AgentPatch) -> dict:
        changes = data.model_dump(exclude_unset=True)
        async with self.write() as db:
            row = await db.get(AgentIdentity, owner_id)
            if row is None:
                raise ToolError("AGENT_NOT_FOUND", "Agent does not exist.")
            fields = {"owner_id": owner_id, "name": row.name, "description": row.description, "enabled": row.enabled}
            # Validate only changed fields; preserve the exact legacy host grants for unrelated edits.
            validated = AgentInput.model_validate({**fields, **changes})
            permissions = validated.permissions()
            row.permissions_json = {**row.permissions_json, **{key: permissions[key] for key in changes.keys() & permissions.keys()}}
            row.name, row.description, row.enabled = validated.name, validated.description, validated.enabled
            row.updated_at = timestamp()
        admin_audit("agent_update", owner_id)
        return await self.agent(owner_id)

    async def tokens(self, owner_id: str | None, status: str | None, page: int, limit: int) -> dict:
        at = timestamp()
        filters = [AccessToken.deleted_at.is_(None)]
        if owner_id:
            filters.append(AccessToken.owner_id == owner_id)
        if status == "REVOKED":
            filters.append(AccessToken.revoked_at.is_not(None))
        elif status == "EXPIRED":
            filters.extend((AccessToken.revoked_at.is_(None), AccessToken.expires_at <= at))
        elif status == "ACTIVE":
            filters.extend((AccessToken.revoked_at.is_(None), or_(
                AccessToken.expires_at.is_(None), AccessToken.expires_at > at,
            )))
        async with self.store.transaction() as db:
            count = await db.scalar(select(func.count()).select_from(AccessToken).where(*filters))
            rows = (await db.execute(select(AccessToken, AgentIdentity.enabled, AgentIdentity.name)
                                     .join(AgentIdentity, AccessToken.owner_id == AgentIdentity.owner_id)
                                     .where(*filters).order_by(AccessToken.created_at.desc(), AccessToken.token_id)
                                     .offset((page - 1) * limit).limit(limit))).all()
        return {"tokens": [{**token_info(row, at), "owner_enabled": enabled, "owner_name": name}
                           for row, enabled, name in rows], "page": page, "limit": limit, "total": count,
                "default_days": self.settings.token_default_days}

    async def token(self, token_id: str) -> dict:
        async with self.store.transaction() as db:
            row = await db.get(AccessToken, token_id)
        if row is None or row.deleted_at:
            raise ToolError("TOKEN_NOT_FOUND", "Token does not exist.")
        return token_info(row, timestamp())

    @staticmethod
    async def check_request(db, request_id: str | None) -> None:
        if request_id and await db.scalar(select(AccessToken.token_id).where(AccessToken.issue_request_id == request_id)):
            raise ToolError("TOKEN_ALREADY_ISSUED", "This request already issued a token. The secret cannot be displayed again.")

    @staticmethod
    async def issue(db, owner_id: str, name: str, at: str, expiry: str | None, request_id: str | None):
        token_id = uuid4().hex
        secret = f"ptmcp_{token_id}_{secrets.token_urlsafe(32)}"
        row = AccessToken(token_id=token_id, owner_id=owner_id, name=name,
                          token_hash=hashlib.sha256(secret.encode()).hexdigest(), created_at=at, expires_at=expiry,
                          created_by="web_admin", legacy=False, issue_request_id=request_id)
        db.add(row)
        await db.flush()
        return row, secret

    async def create_token(self, data: TokenInput, request_id: str | None) -> dict:
        instant = datetime.now(UTC)
        expiry = (data.expires_at if "expires_at" in data.model_fields_set
                  else instant + timedelta(days=self.settings.token_default_days))
        if expiry is not None and expiry <= instant:
            raise ToolError("INVALID_EXPIRY", "Expiration must be in the future.")
        at = timestamp(instant)
        async with self.write() as db:
            await self.check_request(db, request_id)
            if await db.get(AgentIdentity, data.owner_id) is None:
                raise ToolError("AGENT_NOT_FOUND", "Agent does not exist.")
            row, secret = await self.issue(db, data.owner_id, data.name, at, timestamp(expiry) if expiry else None, request_id)
        admin_audit("token_create", row.owner_id, row.token_id)
        return {**token_info(row, at), "token": secret}

    async def rotate(self, token_id: str, request_id: str | None) -> dict:
        at = timestamp()
        async with self.write() as db:
            await self.check_request(db, request_id)
            old = await db.get(AccessToken, token_id)
            if old is None or old.deleted_at:
                raise ToolError("TOKEN_NOT_FOUND", "Token does not exist.")
            if state(old, at) != "ACTIVE":
                raise ToolError("TOKEN_INACTIVE", "Only an active token can be rotated.")
            row, secret = await self.issue(db, old.owner_id, old.name, at, old.expires_at, request_id)
            old.revoked_at, old.revoked_reason = at, "rotated"
        admin_audit("token_rotate", row.owner_id, row.token_id)
        return {**token_info(row, at), "token": secret, "replaces": token_id}

    async def revoke(self, token_id: str, reason: str, delete: bool = False) -> dict:
        at = timestamp()
        async with self.write() as db:
            row = await db.get(AccessToken, token_id)
            if row is None or (row.deleted_at and not delete):
                raise ToolError("TOKEN_NOT_FOUND", "Token does not exist.")
            if row.revoked_at is None:
                row.revoked_at, row.revoked_reason = at, reason
            if delete and row.deleted_at is None:
                row.deleted_at = at
        admin_audit("token_delete" if delete else "token_revoke", row.owner_id, row.token_id)
        return {**token_info(row, at), "deleted": bool(row.deleted_at)}
