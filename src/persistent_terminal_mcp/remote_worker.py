"""Remote helper source executed through AsyncSSH with generated resource IDs."""

import asyncio
import codecs
import json
import os
import re
import signal
import sqlite3
import sys
import time
from pathlib import Path

from .ring import OutputRing

LINUX_JOB_START = """
import ctypes, os, signal, sys
parent = int(sys.argv[1])
if ctypes.CDLL(None).prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
    sys.exit(125)
os.execv("/bin/sh", ["/bin/sh", "-c", sys.argv[2]])
"""


def state(folder: Path, **values: object) -> None:
    temporary = folder / "state.tmp"
    with temporary.open("w", encoding="utf-8") as file:
        json.dump(values, file)
        file.flush()
        os.fsync(file.fileno())
    temporary.replace(folder / "state.json")
    directory = os.open(folder, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def status(folder: Path) -> dict:
    try:
        record = json.loads((folder / "state.json").read_text(encoding="utf-8"))
        kind = record.get("status") if isinstance(record, dict) else None
        if kind == "COMPLETED" and type(record.get("exit_code")) is int and record["exit_code"] >= 0:
            return record
        if kind in {"RUNNING", "FAILED", "CANCELLED", "TIMED_OUT"} and record.get("exit_code") is None:
            return record
    except (OSError, ValueError):
        pass
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
        argv = ["/bin/sh", "-c", payload["command"]]
        if sys.platform.startswith("linux"):
            argv = [sys.executable, "-c", LINUX_JOB_START, str(os.getpid()), payload["command"]]
        process = await asyncio.create_subprocess_exec(
            *argv,
            cwd=payload["cwd"] or Path.home(), start_new_session=True,
            stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )

        async def control(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            nonlocal controlling_signal
            try:
                value = (await asyncio.wait_for(reader.readline(), 2)).decode().strip()
                if value == "ping":
                    writer.write(b"ok\n")
                elif value in {"SIGINT", "SIGTERM", "SIGKILL"} and process.returncode is None:
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
        state(folder, status="RUNNING", exit_code=None, worker_pid=os.getpid(), process_pid=process.pid)
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
        if controlling_signal == "timeout":
            final = "TIMED_OUT"
        elif code is not None and code >= 0:
            final = "COMPLETED"
        elif controlling_signal and code == -getattr(signal, controlling_signal):
            final = "CANCELLED"
        else:
            final = "FAILED"
        state(folder, status=final, exit_code=code if final == "COMPLETED" else None, ended_by=controlling_signal)
    except Exception:
        if process is not None and process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(process.wait(), 5)
            except TimeoutError:
                pass
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
    except (OSError, TimeoutError):
        return False
    finally:
        writer.close()
        await writer.wait_closed()


def remote_main() -> None:
    operation, resource, size, ttl, *arguments = sys.argv[1:]
    if not re.fullmatch(r"(?:t|e)_[a-f0-9]{32}", resource):
        raise ValueError("Invalid resource")
    os.umask(0o077)
    folder = Path.home() / ".local/state/persistent-terminal-mcp" / resource
    if operation == "execute":
        # Claim the ID before running user code. An existing claim is never replayed.
        folder.mkdir(mode=0o700, parents=True, exist_ok=False)
    elif operation == "pipe":
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
        result = status(folder)
        if result["status"] == "RUNNING" and not asyncio.run(signal_job(folder, "ping")):
            # Fetch once more in case the worker published its exit while the socket was closing.
            result = status(folder)
            if result["status"] == "RUNNING":
                result = {"status": "UNKNOWN", "exit_code": None}
        print(json.dumps(result))
    elif operation == "read":
        try:
            if ring.path.stat().st_mtime < time.time() - ring.retention_seconds:
                ring.compact_expired()
        except (OSError, sqlite3.Error):
            pass
        print(json.dumps(ring.read(int(arguments[0]), int(arguments[1]))))
    elif operation == "signal":
        allowed = arguments[0] in {"SIGINT", "SIGTERM", "SIGKILL"}
        print(json.dumps(allowed and asyncio.run(signal_job(folder, arguments[0]))))


if __name__ == "__main__":
    remote_main()
