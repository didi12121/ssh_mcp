from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, AwareDatetime, BaseModel, ConfigDict, Field, StringConstraints, field_validator
from sqlalchemy import CheckConstraint, ForeignKey, Index, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from .config import Identifier
from .models import Base

Label = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100)]
Arg = Annotated[str, StringConstraints(max_length=1024)]
Argv = Annotated[list[Arg], Field(min_length=1, max_length=32)]
TOKEN_STATES = ("ACTIVE", "REVOKED", "EXPIRED")
ProfileId = Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{32}$")]


class TokenPermissions(BaseModel):
    model_config = ConfigDict(extra="forbid")
    allowed_profile_ids: set[ProfileId] = Field(default_factory=set, max_length=512)
    shell: bool = False
    custom_commands: bool = False
    workspaces: set[Identifier] = Field(default_factory=lambda: {"default"}, max_length=128)
    commands: dict[Identifier, Argv] = Field(default_factory=dict, max_length=128)

    @field_validator("commands")
    @classmethod
    def allowed_argv(cls, commands: dict[str, list[str]]) -> dict[str, list[str]]:
        for argv in commands.values():
            if not argv[0].strip() or any("\0" in arg for arg in argv):
                raise ValueError("Commands need a valid executable followed by arguments")
        return commands

    def permissions(self) -> dict:
        data = self.model_dump(mode="json", include={"shell", "custom_commands", "commands", "workspaces"})
        data["workspaces"] = sorted(data["workspaces"])
        return data


class TokenPermissionPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    allowed_profile_ids: set[ProfileId] | None = None
    workspaces: set[Identifier] | None = None
    shell: bool | None = None
    custom_commands: bool | None = None
    commands: dict[Identifier, Argv] | None = None


def utc(value: datetime) -> datetime:
    return value.astimezone(UTC)


class TokenInput(TokenPermissions):
    name: Label
    attach_to_token_id: ProfileId | None = None
    expires_at: Annotated[AwareDatetime, AfterValidator(utc)] | None = None
    expires_in_days: Annotated[int, Field(ge=1, le=3650)] | None = None


class TokenRotation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expires_at: Annotated[AwareDatetime, AfterValidator(utc)] | None = None


class TokenRevocation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: Literal["manual", "compromised", "unused"] = "manual"


class AgentIdentity(Base):
    __tablename__ = "agent_identities"
    owner_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str]
    description: Mapped[str | None]
    enabled: Mapped[bool]
    permissions_json: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[str]
    updated_at: Mapped[str]

class AccessToken(Base):
    __tablename__ = "access_tokens"
    __table_args__ = (
        Index("ix_access_tokens_owner_created", "owner_id", "created_at", "token_id"),
        CheckConstraint("length(token_hash) = 64", name="ck_access_tokens_hash_length"),
    )
    token_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    owner_id: Mapped[str] = mapped_column(ForeignKey("agent_identities.owner_id", ondelete="RESTRICT"))
    name: Mapped[str]
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[str]
    expires_at: Mapped[str | None]
    last_used_at: Mapped[str | None]
    revoked_at: Mapped[str | None]
    revoked_reason: Mapped[str | None]
    deleted_at: Mapped[str | None]
    created_by: Mapped[str]
    legacy: Mapped[bool]
    issue_request_id: Mapped[str | None] = mapped_column(String(36), unique=True)
    permissions_json: Mapped[dict] = mapped_column(JSON, default=dict, server_default="{}")


class TokenProfileGrant(Base):
    __tablename__ = "token_profile_grants"
    token_id: Mapped[str] = mapped_column(ForeignKey("access_tokens.token_id", ondelete="CASCADE"), primary_key=True)
    profile_id: Mapped[str] = mapped_column(ForeignKey("profiles.profile_id", ondelete="RESTRICT"), primary_key=True, index=True)
    profile_access_version: Mapped[int]
