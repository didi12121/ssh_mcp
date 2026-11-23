from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, Field, StringConstraints
from pydantic_settings import BaseSettings, SettingsConfigDict

Identifier = Annotated[str, StringConstraints(pattern=r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")]
CredentialRef = Annotated[str, StringConstraints(pattern=r"^[A-Za-z][A-Za-z0-9_-]{0,79}$")]
Port = Annotated[int, Field(ge=1, le=65535)]
Digest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class Principal(BaseModel):
    owner_id: Identifier
    targets: list[str] = Field(default_factory=list)  # Exact hostnames/IP addresses.
    credentials: set[CredentialRef] = Field(default_factory=set)
    workspaces: set[Identifier] = Field(default_factory=lambda: {"default"})
    shell: bool = False
    custom_commands: bool = False
    commands: dict[Identifier, list[str]] = Field(default_factory=dict)
    ssh_agent: bool = False


class LegacyPrincipal(BaseModel):
    owner_id: Identifier
    token_sha256: Digest
    targets: list[str] = Field(min_length=1)
    credentials: set[CredentialRef] = Field(default_factory=set)
    workspaces: set[Identifier] = Field(default_factory=lambda: {"default"})
    shell: bool = False
    commands: dict[Identifier, list[str]] = Field(default_factory=dict)
    ssh_agent: bool = False

class Credential(BaseModel):
    kind: Literal["key", "password", "encrypted_key"]
    file: Path


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PTMCP_", env_file=".env", extra="ignore")

    host: str = "127.0.0.1"
    port: Port = 8766
    allowed_hosts: list[str] = Field(default_factory=list)
    data_dir: Path = Path(".data/terminal")
    database_url: str | None = None
    known_hosts: Path = Path(".data/known_hosts")
    principals_file: Path = Path(".data/terminal/principals.json")
    credentials_file: Path = Path(".data/terminal/credentials.json")
    master_key_file: Path | None = None
    web_admin_token_file: Path | None = None
    managed_keys_dir: Path | None = None
    ssh_agent_path: str | None = None
    token_default_days: int = Field(default=90, ge=1, le=3650)
    token_usage_interval_seconds: int = Field(default=60, ge=1, le=3600)
    admin_token_mutations_per_minute: int = Field(default=30, ge=1, le=600)
    connect_timeout: float = Field(default=15, gt=0, le=60)
    keepalive_interval: int = Field(default=30, ge=1)
    idle_timeout: int = Field(default=3600, ge=1)
    reconnect_attempts: int = Field(default=3, ge=1, le=6)
    recovery_enabled: bool = True
    allow_pty_fallback: bool = False
    max_sessions_per_agent: int = Field(default=20, ge=1)
    max_executions_per_session: int = Field(default=10, ge=1, le=50)
    execution_timeout: int = Field(default=3600, ge=1)
    output_max_bytes: int = Field(default=10_485_760, ge=16384)
    output_retention_days: int = Field(default=7, ge=1)
    log_level: str = "INFO"

    @property
    def db_url(self) -> str:
        return self.database_url or f"sqlite+aiosqlite:///{(self.data_dir / 'terminal.db').resolve().as_posix()}"
