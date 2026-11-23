"""Remote helper source executed through AsyncSSH with generated resource IDs."""

import asyncio
import codecs
import json
import os
import re
import signal
import sys
from pathlib import Path

from .ring import OutputRing


def state(folder: Path, **values: object) -> None:
    temporary = folder / "state.tmp"
    temporary.write_text(json.dumps(values), encoding="utf-8")
    temporary.replace(folder / "state.json")


def status(folder: Path) -> dict:
    try:
        return json.loads((folder / "state.json").read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"status": "UNKNOWN", "exit_code": None}


async def capture(reader: asyncio.StreamReader, ring: OutputRing, stream: str) -> None:
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    while chunk := await reader.read(2048):
        await asyncio.to_thread(ring.append, stream, decoder.decode(chunk))
    await asyncio.to_thread(ring.append, stream, decoder.decode(b"", final=True))


async def run_job(folder: Path, ring: OutputRing, payload: dict) -> None:
    os.chdir(folder)
    controlling_signal = None
    process = None
    server = None
    try:
        process = await asyncio.create_subprocess_exec(
            "/bin/sh", "-c", payload["command"],
            cwd=payload["cwd"] or Path.home(), start_new_session=True,
            stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )

        async def control(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            nonlocal controlling_signal
            try:
                value = (await asyncio.wait_for(reader.readline(), 2)).decode().strip()
                if value in {"SIGINT", "SIGTERM", "SIGKILL"} and process.returncode is None:
                    os.killpg(process.pid, getattr(signal, value))
                    controlling_signal = value
                    writer.write(b"ok\n")
                else:
                    writer.write(b"unavailable\n")
                await writer.drain()
            except (OSError, TimeoutError, ValueError):
                pass
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_unix_server(control, "control.sock")
        state(folder, status="RUNNING", exit_code=None)
        assert process.stdout is not None and process.stderr is not None
        try:
            async with asyncio.timeout(payload["timeout"]), asyncio.TaskGroup() as tasks:
                tasks.create_task(capture(process.stdout, ring, "stdout"))
                tasks.create_task(capture(process.stderr, ring, "stderr"))
                await process.wait()
        except TimeoutError:
            controlling_signal = "timeout"
            if process.returncode is None:
                os.killpg(process.pid, signal.SIGKILL)
                try:
                    await asyncio.wait_for(process.wait(), 5)
                except TimeoutError:
                    pass
        code = process.returncode
        final = "TIMED_OUT" if controlling_signal == "timeout" else (
            "CANCELLED" if code is not None and code < 0 and controlling_signal else "COMPLETED"
        )
        state(folder, status=final, exit_code=code if code is not None and code >= 0 else None,
              ended_by=controlling_signal)
    except Exception:
        if process is not None and process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            await process.wait()
        state(folder, status="FAILED", exit_code=None)
    finally:
        if server:
            server.close()
            await server.wait_closed()
            (folder / "control.sock").unlink(missing_ok=True)


async def signal_job(folder: Path, name: str) -> bool:
    os.chdir(folder)
    try:
        reader, writer = await asyncio.open_unix_connection("control.sock")
    except OSError:
        return False
    try:
        writer.write((name + "\n").encode())
        await writer.drain()
        return (await asyncio.wait_for(reader.readline(), 3)) == b"ok\n"
    finally:
        writer.close()
        await writer.wait_closed()


def remote_main() -> None:
    operation, resource, size, ttl, *arguments = sys.argv[1:]
    if not re.fullmatch(r"(?:t|e)_[a-f0-9]{32}", resource):
        raise ValueError("Invalid resource")
    os.umask(0o077)
    folder = Path.home() / ".local/state/persistent-terminal-mcp" / resource
    if operation in {"pipe", "execute"}:
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not folder.exists():
        print(json.dumps({"status": "UNKNOWN", "exit_code": None}) if operation == "status" else "null")
        return
    ring = OutputRing(folder / "output.db", int(size), int(ttl))
    if operation == "execute":
        asyncio.run(run_job(folder, ring, json.loads(arguments[0])))
    elif operation == "pipe":
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        while chunk := os.read(0, 2048):
            ring.append("terminal", decoder.decode(chunk))
        ring.append("terminal", decoder.decode(b"", final=True))
    elif operation == "status":
        print(json.dumps(status(folder)))
    elif operation == "read":
        print(json.dumps(ring.read(int(arguments[0]), int(arguments[1]))))
    elif operation == "signal":
        print(json.dumps(asyncio.run(signal_job(folder, arguments[0]))))


if __name__ == "__main__":
    remote_main()
