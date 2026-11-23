from datetime import UTC, datetime
from ipaddress import ip_address
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import ForeignKey, JSON, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from .config import CredentialRef, Port


def now() -> str:
    return datetime.now(UTC).isoformat()


class ProfileInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=500)
    host: str = Field(min_length=1, max_length=253)
    port: Port = 22
    username: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9._-]{0,63}$")
    auth_type: Literal["key", "agent", "password"] = "key"
    credential_ref: CredentialRef | None = None
    tags: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("host")
    @classmethod
    def valid_host(cls, value: str) -> str:
        try:
            return str(ip_address(value))
        except ValueError:
            labels = value.rstrip(".").split(".")
            if not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", item) for item in labels):
                raise ValueError("invalid SSH hostname") from None
            return value.lower().rstrip(".")

    @field_validator("tags")
    @classmethod
    def valid_tags(cls, values: list[str]) -> list[str]:
        if any(not value.strip() or len(value) > 64 for value in values):
            raise ValueError("tags must be 1 to 64 characters")
        return list(dict.fromkeys(value.strip() for value in values))

    @model_validator(mode="after")
    def credential_required(self) -> "ProfileInput":
        if (self.auth_type == "agent") == bool(self.credential_ref):
            raise ValueError("agent auth requires no credential, key and password auth require a reference")
        return self


class ProfilePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = None
    description: str | None = None
    host: str | None = None
    port: Port | None = None
    username: str | None = None
    auth_type: Literal["key", "agent", "password"] | None = None
    credential_ref: CredentialRef | None = None
    tags: list[str] | None = None


class Base(DeclarativeBase):
    pass


class Profile(Base):
    __tablename__ = "profiles"
    profile_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    owner_id: Mapped[str] = mapped_column(index=True)
    version: Mapped[int] = mapped_column(default=1)
    configuration: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[str] = mapped_column(default=now)
    updated_at: Mapped[str] = mapped_column(default=now)
    last_connected_at: Mapped[str | None]


class Session(Base):
    __tablename__ = "sessions"
    session_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    owner_id: Mapped[str] = mapped_column(index=True)
    workspace_id: Mapped[str]
    profile_id: Mapped[str] = mapped_column(index=True)
    profile_version: Mapped[int]
    snapshot: Mapped[dict] = mapped_column(JSON)
    name: Mapped[str]
    status: Mapped[str]
    backend: Mapped[str]
    tmux_session_name: Mapped[str | None]
    created_at: Mapped[str] = mapped_column(default=now)
    last_active_at: Mapped[str] = mapped_column(default=now)


class Active(Base):
    __tablename__ = "active_sessions"
    owner_id: Mapped[str] = mapped_column(primary_key=True)
    workspace_id: Mapped[str] = mapped_column(primary_key=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.session_id"))


class Execution(Base):
    __tablename__ = "executions"
    execution_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.session_id"), index=True)
    mode: Mapped[str]
    status: Mapped[str]
    exit_code: Mapped[int | None]
    ended_by: Mapped[str | None]
    created_at: Mapped[str] = mapped_column(default=now)
    updated_at: Mapped[str] = mapped_column(default=now)
