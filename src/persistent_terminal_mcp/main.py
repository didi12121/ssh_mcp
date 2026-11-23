import argparse
import asyncio
from contextlib import asynccontextmanager
from getpass import getpass
import hashlib
import json
import logging
import os
from pathlib import Path
import secrets
from datetime import UTC, datetime

from cryptography.fernet import Fernet
import uvicorn

from .config import Settings
from .server import build_app
from .storage import Store


class JsonLog(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps({
            "timestamp": datetime.now(UTC).isoformat(), "level": record.levelname, "logger": record.name,
            "message": record.getMessage(), **getattr(record, "action_fields", {}),
        }, ensure_ascii=False)


def create_secret(file: Path, value: bytes) -> None:
    with os.fdopen(os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as target:
        target.write(value + b"\n")


async def migrate(settings: Settings) -> None:
    settings.data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    store = Store(settings)
    try:
        await store.start(reset_runtime=False)
    finally:
        await store.engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(prog="terminal-mcp")
    commands = parser.add_subparsers(dest="action")
    commands.add_parser("serve")
    commands.add_parser("migrate")
    commands.add_parser("token")
    master = commands.add_parser("master-key")
    master.add_argument("file", type=Path)
    encrypt = commands.add_parser("encrypt")
    encrypt.add_argument("master_key", type=Path)
    encrypt.add_argument("file", type=Path)
    encrypt.add_argument("--key-file", type=Path)
    args = parser.parse_args()
    if args.action == "token":
        value = secrets.token_urlsafe(32)
        print(json.dumps({"token": value, "token_sha256": hashlib.sha256(value.encode()).hexdigest()}))
        return
    if args.action == "master-key":
        create_secret(args.file, Fernet.generate_key())
        return
    if args.action == "encrypt":
        from .security import private_file

        raw = private_file(args.key_file) if args.key_file else getpass("SSH password: ").encode()
        create_secret(args.file, Fernet(private_file(args.master_key).strip()).encrypt(raw))
        return
    settings = Settings()
    if os.name == "posix":
        os.umask(0o077)
    if args.action == "migrate":
        asyncio.run(migrate(settings))
        return
    handler = logging.StreamHandler()
    handler.setFormatter(JsonLog())
    logging.basicConfig(handlers=[handler], level=settings.log_level, force=True)
    uvicorn.run(build_app(settings), host=settings.host, port=settings.port, workers=1,
                proxy_headers=False, log_config=None, access_log=False)


if __name__ == "__main__":
    main()
