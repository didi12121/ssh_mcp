from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import logging
import re
import secrets
from uuid import uuid4

from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.exc import SQLAlchemyError

from .config import Principal
from .errors import ToolError
from .identity_models import AccessToken, AgentIdentity, TokenInput, TokenPermissionPatch, TokenPermissions, TokenProfileGrant, TokenRotation
from .models import Profile
from .security import private_file
from .storage import Store

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
        "created_by": row.created_by, "legacy": row.legacy, **row.permissions_json,
    }


def admin_audit(action: str, **fields: str) -> None:
    audit.info("identity_admin_action", extra={"action_fields": {"actor": "web_admin", "action": action, **fields}})


class Identities:
    def __init__(self, store: Store) -> None:
        self.store = store
        self.settings = store.settings

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
                select(AccessToken, AgentIdentity, TokenProfileGrant.profile_id, TokenProfileGrant.profile_access_version)
                .join(AgentIdentity, AccessToken.owner_id == AgentIdentity.owner_id)
                .outerjoin(TokenProfileGrant, TokenProfileGrant.token_id == AccessToken.token_id)
                .where(AccessToken.token_hash == digest)
            )).all()
        expected = record[0][0].token_hash if record else "0" * 64
        if not hmac.compare_digest(digest, expected) or not record:
            return None
        key, owner, _, _ = record[0]
        if not owner.enabled or state(key, at) != "ACTIVE":
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
        return Principal(owner_id=owner.owner_id, token_id=key.token_id, **key.permissions_json,
                         profile_grants={profile_id: version for _, _, profile_id, version in record if profile_id})

    async def registered(self, token: str) -> bool:
        digest = hashlib.sha256(token.encode()).hexdigest()
        async with self.store.transaction() as db:
            return await db.scalar(select(AccessToken.token_id).where(AccessToken.token_hash == digest)) is not None

    @staticmethod
    async def grant_map(db, token_id: str) -> dict[str, int]:
        rows = (await db.execute(select(TokenProfileGrant.profile_id, TokenProfileGrant.profile_access_version)
                                 .where(TokenProfileGrant.token_id == token_id))).all()
        return dict(rows)

    @staticmethod
    async def replace_grants(db, token_id: str, profile_ids: set[str], retain_existing: bool = False) -> None:
        retained = await Identities.grant_map(db, token_id) if retain_existing else {}
        grants = (await db.execute(select(Profile.profile_id, Profile.access_version).where(
            Profile.profile_id.in_(profile_ids), or_(Profile.enabled.is_(True), Profile.profile_id.in_(retained)),
            Profile.deleted_at.is_(None),
        ))).all() if profile_ids else []
        if len(grants) != len(profile_ids):
            raise ToolError("INVALID_PROFILE_GRANT", "Select existing, enabled SSH connections.")
        await db.execute(delete(TokenProfileGrant).where(TokenProfileGrant.token_id == token_id))
        db.add_all([TokenProfileGrant(token_id=token_id, profile_id=profile_id, profile_access_version=version)
                    for profile_id, version in grants])

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
            rows = (await db.execute(select(AccessToken, AgentIdentity.enabled)
                                     .join(AgentIdentity, AccessToken.owner_id == AgentIdentity.owner_id)
                                     .where(*filters).order_by(AccessToken.created_at.desc(), AccessToken.token_id)
                                     .offset((page - 1) * limit).limit(limit))).all()
            token_ids = [row.token_id for row, _ in rows]
            grants = (await db.execute(select(TokenProfileGrant.token_id, Profile.profile_id, Profile.configuration, Profile.enabled)
                                       .join(Profile, TokenProfileGrant.profile_id == Profile.profile_id)
                                       .where(TokenProfileGrant.token_id.in_(token_ids)))).all()
        items: dict[str, list] = {}
        for token_id, profile_id, profile, enabled in grants:
            items.setdefault(token_id, []).append({"profile_id": profile_id, "name": profile["name"], "enabled": enabled})
        return {"tokens": [{
            **token_info(row, at), "owner_enabled": enabled,
            "profiles": items.get(row.token_id, []),
            "allowed_profile_ids": [item["profile_id"] for item in items.get(row.token_id, [])],
        } for row, enabled in rows], "page": page, "limit": limit, "total": count,
            "default_days": self.settings.token_default_days}

    async def token(self, token_id: str) -> dict:
        async with self.store.transaction() as db:
            row = await db.get(AccessToken, token_id)
            if row is None or row.deleted_at:
                raise ToolError("TOKEN_NOT_FOUND", "Token does not exist.")
            grants = await self.grant_map(db, token_id)
        return {**token_info(row, timestamp()), "allowed_profile_ids": sorted(grants)}

    @staticmethod
    async def check_request(db, request_id: str | None) -> None:
        if request_id and await db.scalar(select(AccessToken.token_id).where(AccessToken.issue_request_id == request_id)):
            raise ToolError("TOKEN_ALREADY_ISSUED", "This request already issued a token. The secret cannot be displayed again.")

    @staticmethod
    async def issue(db, owner_id: str, name: str, at: str, expiry: str | None, request_id: str | None,
                    permissions: dict):
        token_id = uuid4().hex
        secret = f"ptmcp_{token_id}_{secrets.token_urlsafe(32)}"
        row = AccessToken(token_id=token_id, owner_id=owner_id, name=name,
                          token_hash=hashlib.sha256(secret.encode()).hexdigest(), created_at=at, expires_at=expiry,
                          created_by="web_admin", legacy=False, issue_request_id=request_id, permissions_json=permissions)
        db.add(row)
        await db.flush()
        return row, secret

    async def create_token(self, data: TokenInput, request_id: str | None) -> dict:
        instant = datetime.now(UTC)
        if "expires_at" in data.model_fields_set and data.expires_in_days is not None:
            raise ToolError("INVALID_EXPIRY", "Choose one expiration option.")
        expiry = (data.expires_at if "expires_at" in data.model_fields_set
                  else instant + timedelta(days=data.expires_in_days or self.settings.token_default_days))
        if expiry is not None and expiry <= instant:
            raise ToolError("INVALID_EXPIRY", "Expiration must be in the future.")
        at = timestamp(instant)
        async with self.store.write() as db:
            await self.check_request(db, request_id)
            if data.attach_to_token_id:
                existing = await db.get(AccessToken, data.attach_to_token_id)
                if existing is None or existing.deleted_at:
                    raise ToolError("TOKEN_NOT_FOUND", "Token does not exist.")
                owner_id = existing.owner_id
            else:
                owner_id = "owner_" + uuid4().hex
                db.add(AgentIdentity(owner_id=owner_id, name=data.name, enabled=True,
                                     permissions_json={}, created_at=at, updated_at=at))
                await db.flush()
            row, secret = await self.issue(db, owner_id, data.name, at, timestamp(expiry) if expiry else None,
                                           request_id, data.permissions())
            await self.replace_grants(db, row.token_id, data.allowed_profile_ids)
        admin_audit("token_create", owner_id=row.owner_id, token_id=row.token_id)
        return {**token_info(row, at), "allowed_profile_ids": sorted(data.allowed_profile_ids), "token": secret}

    async def update_permissions(self, token_id: str, data: TokenPermissionPatch) -> dict:
        changes = data.model_dump(exclude_unset=True)
        async with self.store.write() as db:
            row = await db.get(AccessToken, token_id)
            if row is None or row.deleted_at:
                raise ToolError("TOKEN_NOT_FOUND", "Token does not exist.")
            if state(row, timestamp()) != "ACTIVE":
                raise ToolError("TOKEN_INACTIVE", "Only an active token can be changed.")
            permissions = TokenPermissions.model_validate({**row.permissions_json, **changes})
            row.permissions_json = permissions.permissions()
            if "allowed_profile_ids" in changes:
                await self.replace_grants(db, row.token_id, permissions.allowed_profile_ids, retain_existing=True)
            grants = await self.grant_map(db, row.token_id)
        admin_audit("token_permissions_update", owner_id=row.owner_id, token_id=row.token_id)
        return {**token_info(row, timestamp()), "allowed_profile_ids": sorted(grants)}

    async def rotate(self, token_id: str, request_id: str | None, renewal: TokenRotation) -> dict:
        at = timestamp()
        async with self.store.write() as db:
            await self.check_request(db, request_id)
            old = await db.get(AccessToken, token_id)
            if old is None or old.deleted_at:
                raise ToolError("TOKEN_NOT_FOUND", "Token does not exist.")
            if state(old, at) != "ACTIVE":
                raise ToolError("TOKEN_INACTIVE", "Only an active token can be rotated.")
            expiry = old.expires_at
            if "expires_at" in renewal.model_fields_set:
                expiry = timestamp(renewal.expires_at) if renewal.expires_at else None
                if expiry and expiry <= at:
                    raise ToolError("INVALID_EXPIRY", "Expiration must be in the future.")
            row, secret = await self.issue(db, old.owner_id, old.name, at, expiry, request_id, old.permissions_json)
            grants = await self.grant_map(db, old.token_id)
            db.add_all([TokenProfileGrant(token_id=row.token_id, profile_id=profile_id, profile_access_version=version)
                        for profile_id, version in grants.items()])
            old.revoked_at, old.revoked_reason = at, "rotated"
        admin_audit("token_rotate", owner_id=row.owner_id, token_id=row.token_id, replaces=token_id)
        return {**token_info(row, at), "token": secret, "replaces": token_id, "allowed_profile_ids": sorted(grants)}

    async def revoke(self, token_id: str, reason: str, delete_record: bool = False) -> dict:
        at = timestamp()
        async with self.store.write() as db:
            row = await db.get(AccessToken, token_id)
            if row is None or (row.deleted_at and not delete_record):
                raise ToolError("TOKEN_NOT_FOUND", "Token does not exist.")
            if row.revoked_at is None:
                row.revoked_at, row.revoked_reason = at, reason
            if delete_record and row.deleted_at is None:
                row.deleted_at = at
        admin_audit("token_delete" if delete_record else "token_revoke", owner_id=row.owner_id, token_id=row.token_id)
        return {**token_info(row, at), "deleted": bool(row.deleted_at)}
