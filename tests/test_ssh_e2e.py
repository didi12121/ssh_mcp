from concurrent.futures import ThreadPoolExecutor
import json
import os
import sqlite3
import subprocess
import sys
import time

import asyncssh
import httpx
import pytest
from starlette.testclient import TestClient

from conftest import LIMITED, OTHER, TOKEN, admin_request, call, global_profile, profile, put_secret
from test_identities import admin_app, issue_token, mcp_status
from test_token_migration import version_two, SESSION_ID, PROFILE_ID, EXECUTION_ID
from persistent_terminal_mcp.server import build_app
from persistent_terminal_mcp.backends import Remote
from persistent_terminal_mcp.errors import ToolError
from persistent_terminal_mcp.ssh import SSHConnectionManager


def docker(*args: str) -> str:
    return subprocess.run(["docker", *args], capture_output=True, check=True, text=True, timeout=30).stdout.strip()


def until(check, timeout: float = 8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(0.1)
    raise AssertionError("Condition did not converge in time")


@pytest.fixture
def sshd(config):
    image = os.environ.get("PTMCP_TEST_SSH_IMAGE")
    if not image:
        pytest.skip("Set PTMCP_TEST_SSH_IMAGE to run the real OpenSSH/tmux tests")
    public = (config.data_dir / "identity.pub").read_text().strip()
    container = docker("run", "--rm", "-d", "-p", "127.0.0.1::22", "-e", f"TEST_SSH_PUBLIC_KEY={public}", image)
    try:
        port = int(docker("port", container, "22/tcp").rsplit(":", 1)[1])

        def host_key():
            try:
                return docker("exec", container, "cat", "/etc/ssh/ssh_host_ed25519_key.pub")
            except subprocess.CalledProcessError:
                return ""

        key = until(host_key)
        put_secret(config.known_hosts, f"[127.0.0.1]:{port} {key}\n".encode())
        yield container, port
    finally:
        docker("stop", "-t", "2", container)


def output(client, session: str, execution: str | None = None, token: str = TOKEN) -> str:
    result = call(client, "terminal_read", token, session_id=session, execution_id=execution)
    assert not result["is_error"], result
    return "".join(entry["text"] for entry in result["entries"])


def finished(client, session: str, execution: str, token: str = TOKEN) -> dict:
    result = call(client, "terminal_status", token, session_id=session, execution_id=execution)
    assert not result["is_error"], result
    if result["status"] in {"PENDING", "RUNNING"}:
        return {}
    return result


def test_real_tmux_channels_restart_and_detached(config, sshd):
    container, port = sshd
    with TestClient(build_app(config), base_url="http://127.0.0.1", client=("127.0.0.1", 51000)) as client:
        config_id = profile(client, port=port)["profile_id"]
        tested = admin_request(client, "POST", f"connections/{config_id}/test").json()
        assert tested["authenticated"] and tested["tmux_available"]
        created = call(client, "terminal_create", profile_id=config_id, name="persistent")
        assert not created["is_error"], created
        session = created["session_id"]
        assert call(client, "terminal_create", profile_id=config_id, name="persistent")["reused"]
        assert admin_request(client, "DELETE", f"connections/{config_id}").json()["code"] == "PROFILE_IN_USE"
        assert call(client, "terminal_send", session_id=session, input="cd /tmp\nexport PERSISTENT_MARKER=retained\n")["input_bytes"]
        call(client, "terminal_send", session_id=session,
             input="printf '%s:%s\\n' \"$(pwd)\" \"$PERSISTENT_MARKER\"\n")
        until(lambda: "/tmp:retained" in output(client, session))
        assert call(client, "terminal_resize", session_id=session, columns=100, lines=30)["columns"] == 100
        call(client, "terminal_send", session_id=session, input="sleep 30\n")
        assert not call(client, "terminal_signal", session_id=session, signal="CTRL_C")["is_error"]
        call(client, "terminal_send", session_id=session, input="echo survived-interruption\n")
        until(lambda: output(client, session).count("survived-interruption") >= 2)
        long_task = call(client, "terminal_exec", session_id=session, command="sleep 2; printf slow", yield_time_ms=30)
        assert long_task["status"] in {"PENDING", "RUNNING"}
        independent = call(client, "terminal_exec", session_id=session, cwd="/",
                           command="pwd; printf '测试'; printf 'err' >&2; exit 7", yield_time_ms=1500)
        assert independent["status"] == "COMPLETED" and independent["exit_code"] == 7, independent
        assert independent["stdout"] == "/\n测试" and independent["stderr"] == "err"
        assert call(client, "terminal_read", session_id=session, execution_id=independent["execution_id"],
                    cursor=independent["next_cursor"])["entries"] == []
        assert call(client, "terminal_list", OTHER)["terminals"] == []
        assert call(client, "terminal_read", OTHER, session_id=session,
                    execution_id=independent["execution_id"])["code"] == "SESSION_NOT_FOUND"
        assert until(lambda: finished(client, session, long_task["execution_id"]))["exit_code"] == 0
        assert output(client, session, long_task["execution_id"]) == "slow"
        handed_off = call(client, "terminal_exec", session_id=session,
                          command="printf start; sleep 4; printf end; exit 9", execution_mode="detached",
                          yield_time_ms=100)
        assert handed_off["status"] in {"PENDING", "RUNNING"}, handed_off
        until(lambda: call(client, "terminal_status", session_id=session,
                           execution_id=handed_off["execution_id"])["status"] == "RUNNING")
        unconfirmed = call(client, "terminal_exec", session_id=session,
                           command="echo once >> /tmp/foreground-count; sleep 9", yield_time_ms=120)
        assert unconfirmed["status"] == "RUNNING"
        edited = admin_request(client, "PATCH", f"connections/{config_id}", {"name": "New label"}).json()
        assert edited["session_ids"] == [session]
        logs = subprocess.run(["docker", "logs", container], capture_output=True, check=True, text=True).stderr
        assert logs.count("Accepted publickey for fixture") == 2  # One probe and one managed login.
    with TestClient(build_app(config), base_url="http://127.0.0.1", client=("127.0.0.1", 51000)) as client:
        assert call(client, "terminal_list")["terminals"][0]["status"] == "DISCONNECTED"
        call(client, "terminal_send", session_id=session,
             input="printf '%s:%s\\n' \"$(pwd)\" \"$PERSISTENT_MARKER\"\n")
        until(lambda: output(client, session).count("/tmp:retained") >= 2)
        recovered = until(lambda: finished(client, session, handed_off["execution_id"]))
        assert recovered["exit_code"] == 9, recovered
        assert output(client, session, handed_off["execution_id"]) == "startend"
        assert finished(client, session, unconfirmed["execution_id"])["status"] == "UNKNOWN"
        count = call(client, "terminal_exec", session_id=session, command="cat /tmp/foreground-count")
        assert count["stdout"] == "once\n"
        assert call(client, "terminal_close", session_id=session, preserve_remote=True)["status"] == "DISCONNECTED"
        with ThreadPoolExecutor(2) as pool:
            active = list(pool.map(lambda _: call(client, "terminal_activate", session_id=session), range(2)))
        assert all(item.get("active") for item in active)
        logs = subprocess.run(["docker", "logs", container], capture_output=True, check=True, text=True).stderr
        assert logs.count("Accepted publickey for fixture") == 4  # One recovery per disconnect.
        assert call(client, "terminal_close", session_id=session, preserve_remote=False)["status"] == "CLOSED"
        assert admin_request(client, "DELETE", f"connections/{config_id}").json()["deleted"]


def test_real_failures_and_restricted_access(config, sshd):
    container, port = sshd
    pinned = config.known_hosts.read_bytes()
    identity = config.data_dir / "identity"
    original = identity.read_bytes()
    wrong = asyncssh.generate_private_key("ssh-ed25519")
    with TestClient(build_app(config), base_url="http://127.0.0.1", client=("127.0.0.1", 51000)) as client:
        profile_id = profile(client, LIMITED, port=port)["profile_id"]
        put_secret(config.known_hosts, f"[127.0.0.1]:{port} ".encode() + wrong.export_public_key())
        assert admin_request(client, "POST", f"connections/{profile_id}/test").json()["code"] == "HOST_KEY_UNVERIFIED"
        put_secret(config.known_hosts, pinned)
        put_secret(identity, wrong.export_private_key())
        assert admin_request(client, "POST", f"connections/{profile_id}/test").json()["code"] == "SSH_AUTH_FAILED"
        put_secret(identity, original)
        result = call(client, "terminal_create", LIMITED, profile_id=profile_id)
        assert result["backend"] == "exec", result
        session = result["session_id"]
        assert call(client, "terminal_send", LIMITED, session_id=session, input="pwd\n")["code"] == "SHELL_FORBIDDEN"
        assert call(client, "terminal_exec", LIMITED, session_id=session, command="uptime")["code"] == "COMMAND_FORBIDDEN"
        allowed = call(client, "terminal_exec", LIMITED, session_id=session, operation="uptime")
        assert allowed["status"] == "COMPLETED" and allowed["exit_code"] == 0
        assert call(client, "terminal_exec", LIMITED, session_id=session,
                    operation="uptime", cwd="/")["code"] == "COMMAND_FORBIDDEN"
        full = profile(client, port=port)["profile_id"]
        session = call(client, "terminal_create", profile_id=full)["session_id"]
        task = call(client, "terminal_exec", session_id=session, command="sleep 8", execution_mode="detached")
        assert task["status"] == "RUNNING", task
        signal = call(client, "terminal_signal", session_id=session, execution_id=task["execution_id"], signal="SIGTERM")
        assert signal["signal_requested"] == "SIGTERM", signal
        assert until(lambda: finished(client, session, task["execution_id"]))["status"] == "CANCELLED"
        docker("exec", container, "su", "fixture", "-c",
               f"tmux -L persistent-terminal-mcp kill-session -t t_{session}")
        assert call(client, "terminal_status", session_id=session, reconnect=True)["code"] == "TMUX_SESSION_LOST"


def test_pty_fallback_deadlines_and_output_limits(config, sshd):
    container, port = sshd
    docker("exec", container, "mv", "/usr/bin/tmux", "/usr/bin/tmux.disabled")
    config.allow_pty_fallback = True
    config.execution_timeout = 2
    config.output_max_bytes = 16384
    config.max_executions_per_session = 1
    with TestClient(build_app(config), base_url="http://127.0.0.1", client=("127.0.0.1", 51000)) as client:
        profile_id = profile(client, port=port)["profile_id"]
        assert not admin_request(client, "POST", f"connections/{profile_id}/test").json()["tmux_available"]
        result = call(client, "terminal_create", profile_id=profile_id)
        assert result["backend"] == "pty" and not result["recoverable"], result
        session = result["session_id"]
        assert call(client, "terminal_send", input="echo fallback-output\n")["input_bytes"]
        until(lambda: output(client, session).count("fallback-output") >= 2)
        long_task = call(client, "terminal_exec", command="sleep 30", yield_time_ms=20)
        assert call(client, "terminal_exec", command="printf nope")["code"] == "EXECUTION_LIMIT"
        assert until(lambda: finished(client, session, long_task["execution_id"]))["status"] == "TIMED_OUT"
        response = call(client, "terminal_exec",
                        command="python3 -c 'print(\"中\" * 22000)'", yield_time_ms=1500)
        assert response["status"] == "COMPLETED", response
        page = call(client, "terminal_read", execution_id=response["execution_id"])
        assert page["truncated"] and sum(len(entry["text"].encode()) for entry in page["entries"]) <= 16384
        assert not any("�" in entry["text"] for entry in page["entries"])
        assert call(client, "terminal_close", session_id=session, preserve_remote=True)["status"] == "CLOSED"
        assert call(client, "terminal_status", session_id=session, reconnect=True)["code"] == "TERMINAL_CLOSED"
        legacy = admin_request(client, "GET", "tokens?owner=first").json()["tokens"][0]
        admin_request(client, "PATCH", f"tokens/{legacy['token_id']}/permissions", {"shell": False})
        assert call(client, "terminal_read", session_id=session)["code"] == "SHELL_FORBIDDEN"


def test_web_connection_probe_uses_real_ssh(config, sshd):
    _, port = sshd
    token = "f" * 64
    config.web_admin_token_file = config.data_dir / "admin-token"
    put_secret(config.web_admin_token_file, token.encode())
    headers = {"Authorization": "Bearer " + token}
    with TestClient(build_app(config), base_url="http://127.0.0.1", client=("127.0.0.1", 51001)) as client:
        created = client.post("/admin/connections", headers=headers, json={
            "name": "SSH probe", "host": "127.0.0.1", "port": port,
            "username": "fixture", "credential_ref": "fixture",
        })
        assert created.status_code == 201
        url = "/admin/connections/" + created.json()["profile_id"]
        probe = client.post(url + "/test", headers=headers)
        assert probe.status_code == 200 and probe.json()["tmux_available"]
        assert client.delete(url, headers=headers).status_code == 200


@pytest.mark.parametrize("remote_exists", [False, True])
def test_restart_recovers_only_unfinished_tmux_initialization(config, sshd, remote_exists):
    container, port = sshd
    address = config.data_dir / "crash-test-port"
    settings = config.data_dir / "crash-test-settings.json"
    settings.write_text(config.model_dump_json())
    crash_service = """
import os
from pathlib import Path
import socket
import sys
import uvicorn
from persistent_terminal_mcp.backends import Remote
from persistent_terminal_mcp.config import Settings
from persistent_terminal_mcp.server import build_app

async def crash(self, ssh, name, *, pending):
    assert pending
    if sys.argv[3] == "True":
        assert (await self.call(ssh, self.tmux("new-session", "-d", "-s", name))).exit_status == 0
    os._exit(77)

Remote.prepare_tmux = crash
settings = Settings.model_validate_json(Path(sys.argv[1]).read_text())
with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    Path(sys.argv[2]).write_text(str(listener.getsockname()[1]))
    uvicorn.Server(uvicorn.Config(build_app(settings), log_level="warning")).run(sockets=[listener])
"""
    with subprocess.Popen([sys.executable, "-c", crash_service, str(settings),
                           str(address), str(remote_exists)]) as process:
        try:
            listen_port = until(lambda: address.read_text() if address.exists() else "")
            with httpx.Client(base_url=f"http://127.0.0.1:{listen_port}", timeout=5) as client:
                def healthy():
                    try:
                        return client.get("/health").is_success
                    except httpx.TransportError:
                        return False

                until(healthy)
                profile_id = profile(client, port=port)["profile_id"]
                with pytest.raises(httpx.TransportError):
                    call(client, "terminal_create", profile_id=profile_id)
            assert process.wait(timeout=5) == 77
        finally:
            if process.poll() is None:
                process.kill()
    with sqlite3.connect(config.data_dir / "terminal.db") as db:
        session_id, backend, status = db.execute("SELECT session_id, backend, status FROM sessions").fetchone()
    assert (backend, status) == ("tmux_pending", "CREATING")
    if remote_exists:
        docker("exec", "-u", "fixture", container, "tmux", "-L", "persistent-terminal-mcp",
               "send-keys", "-t", "t_" + session_id, "export BEFORE_CRASH=preserved", "Enter")
    with TestClient(build_app(config), base_url="http://127.0.0.1", client=("127.0.0.1", 51000)) as client:
        result = call(client, "terminal_create", profile_id=profile_id)
        assert result["status"] == "READY" and result["session_id"] == session_id and result["reused"]
        call(client, "terminal_send", session_id=session_id,
             input="printf 'restored:%s\\n' \"$BEFORE_CRASH\"\n")
        expected = "restored:preserved" if remote_exists else "restored:\r\n"
        until(lambda: expected in output(client, session_id))
        docker("exec", "-u", "fixture", container, "tmux", "-L", "persistent-terminal-mcp",
               "kill-session", "-t", "t_" + session_id)
        until(lambda: not call(client, "terminal_status", session_id=session_id)["interactive_shell_alive"])
        assert call(client, "terminal_status", session_id=session_id, reconnect=True)["code"] == "TMUX_SESSION_LOST"
        assert call(client, "terminal_create", profile_id=profile_id)["code"] == "TMUX_SESSION_LOST"
        assert not call(client, "terminal_status", session_id=session_id)["recoverable"]
    with TestClient(build_app(config), base_url="http://127.0.0.1", client=("127.0.0.1", 51000)) as client:
        assert not call(client, "terminal_status", session_id=session_id)["recoverable"]
        assert call(client, "terminal_close", session_id=session_id, preserve_remote=False)["status"] == "CLOSED"


def test_transport_abort_is_detected_and_parallel_recovery_is_single(config, sshd, monkeypatch):
    _, port = sshd
    connections = []
    original = SSHConnectionManager.connect

    async def capture(self, data):
        ssh = await original(self, data)
        connections.append(ssh.connection)
        return ssh

    monkeypatch.setattr(SSHConnectionManager, "connect", capture)
    with TestClient(build_app(config), base_url="http://127.0.0.1", client=("127.0.0.1", 51000)) as client:
        profile_id = profile(client, port=port)["profile_id"]
        row = call(client, "terminal_create", profile_id=profile_id)
        session_id = row["session_id"]
        work = call(client, "terminal_exec", session_id=session_id, command="sleep 20", yield_time_ms=100)
        assert work["status"] == "RUNNING"
        assert client.portal is not None
        client.portal.call(connections[0].abort)
        until(lambda: call(client, "terminal_status", session_id=session_id)["status"] == "DISCONNECTED")
        assert not call(client, "terminal_status", session_id=session_id)["ssh_connected"]
        assert until(lambda: finished(client, session_id, work["execution_id"]))["status"] == "UNKNOWN"
        assert len(connections) == 1
        with ThreadPoolExecutor(5) as pool:
            states = list(pool.map(lambda _: call(client, "terminal_activate", session_id=session_id), range(5)))
        assert all(state.get("active") for state in states)
        assert len(connections) == 2


def wait_for_worker(client, session, item):
    execution = item["execution_id"]
    until(lambda: call(client, "terminal_status", session_id=session, execution_id=execution)["status"] == "RUNNING")
    return execution


@pytest.mark.parametrize("fault", ["worker_kill", "tmux_lost", "write_failure", "process_kill"])
def test_detached_faults_never_claim_success(config, sshd, fault):
    container, port = sshd
    with TestClient(build_app(config), base_url="http://127.0.0.1", client=("127.0.0.1", 51000)) as client:
        session = call(client, "terminal_create", profile_id=profile(client, port=port)["profile_id"])["session_id"]
        created = call(client, "terminal_exec", session_id=session, execution_mode="detached",
                       command="echo once >> /tmp/fault-count; exec sleep 9", yield_time_ms=10)
        execution = wait_for_worker(client, session, created)
        folder = "/home/fixture/.local/state/persistent-terminal-mcp/e_" + execution
        state = json.loads(docker("exec", container, "cat", folder + "/state.json"))
        until(lambda: docker("exec", container, "sh", "-c", "test -s /tmp/fault-count && echo started || true"))
        if fault in {"worker_kill", "process_kill"}:
            pid = str(state["worker_pid" if fault == "worker_kill" else "process_pid"])
            docker("exec", "-u", "fixture", container, "kill", "-KILL", pid)
        elif fault == "tmux_lost":
            docker("exec", "-u", "fixture", container, "tmux", "-L", "persistent-terminal-mcp",
                   "kill-session", "-t", "e_" + execution)
        else:
            docker("exec", "-u", "fixture", container, "mkdir", folder + "/state.tmp")
            assert call(client, "terminal_signal", session_id=session, execution_id=execution,
                        signal="SIGKILL")["signal_requested"] == "SIGKILL"
        result = until(lambda: finished(client, session, execution))
        assert result["status"] == ("FAILED" if fault == "process_kill" else "UNKNOWN"), result
        assert result["exit_code"] is None
        assert docker("exec", container, "cat", "/tmp/fault-count").splitlines() == ["once"]
        assert call(client, "terminal_status", session_id=session)["interactive_shell_alive"]


def test_detached_transport_loss_after_launch_does_not_replay(config, sshd, monkeypatch):
    container, port = sshd
    original = Remote.detach

    async def interrupt(self, ssh, name, command, cwd):
        await original(self, ssh, name, command, cwd)
        ssh.abort()
        raise ToolError("REMOTE_UNAVAILABLE", "Injected loss of the launch response.")

    monkeypatch.setattr(Remote, "detach", interrupt)
    with TestClient(build_app(config), base_url="http://127.0.0.1", client=("127.0.0.1", 51000)) as client:
        session = call(client, "terminal_create", profile_id=profile(client, port=port)["profile_id"])["session_id"]
        submitted = call(client, "terminal_exec", session_id=session, execution_mode="detached",
                         command="echo once >> /tmp/launch-count; sleep 1; exit 11")
        assert submitted["status"] == "UNKNOWN" and submitted["exit_code"] is None
        execution = submitted["execution_id"]

        def recovered():
            result = call(client, "terminal_status", session_id=session, execution_id=execution)
            return result if result["status"] == "COMPLETED" else None

        assert until(recovered)["exit_code"] == 11
        assert docker("exec", container, "cat", "/tmp/launch-count").splitlines() == ["once"]


def test_approval_and_close_do_not_affect_other_sessions(config, sshd):
    _, port = sshd
    observed = []

    async def approve(principal, session_id, command):
        observed.append((principal.owner_id, session_id, command))
        return command not in {"denied", "denied\n", "\x03"}

    config.idle_timeout = 1
    with TestClient(build_app(config, approve=approve), base_url="http://127.0.0.1", client=("127.0.0.1", 51000)) as client:
        profile_id = profile(client, port=port)["profile_id"]
        one = call(client, "terminal_create", profile_id=profile_id, name="one")["session_id"]
        two = call(client, "terminal_create", profile_id=profile_id, name="two")["session_id"]
        limited = profile(client, LIMITED, port=port)["profile_id"]
        restricted = call(client, "terminal_create", LIMITED, profile_id=limited)["session_id"]
        assert call(client, "terminal_send", LIMITED, session_id=restricted, input="denied\n")["code"] == "SHELL_FORBIDDEN"
        assert not observed
        assert call(client, "terminal_exec", OTHER, session_id=one, command="denied")["code"] == "SESSION_NOT_FOUND"
        assert not observed
        assert call(client, "terminal_exec", session_id=one, command="denied")["code"] == "APPROVAL_REQUIRED"
        assert call(client, "terminal_send", session_id=one, input="denied\n")["code"] == "APPROVAL_REQUIRED"
        assert call(client, "terminal_signal", session_id=one, signal="CTRL_C")["code"] == "APPROVAL_REQUIRED"
        first = call(client, "terminal_exec", session_id=one, command="sleep 8", yield_time_ms=100)
        second = call(client, "terminal_exec", session_id=two, command="sleep 3; echo alive", yield_time_ms=100)
        assert call(client, "terminal_signal", session_id=one, execution_id=second["execution_id"],
                    signal="SIGKILL")["code"] == "EXECUTION_NOT_FOUND"
        assert call(client, "terminal_close", session_id=one, preserve_remote=True)["status"] == "DISCONNECTED"
        assert until(lambda: finished(client, one, first["execution_id"]))["status"] == "UNKNOWN"
        until(lambda: not call(client, "terminal_status", LIMITED, session_id=restricted)["ssh_connected"])
        assert call(client, "terminal_status", session_id=two, execution_id=second["execution_id"])["status"] in {
            "RUNNING", "COMPLETED",
        }
        assert until(lambda: finished(client, two, second["execution_id"]))["exit_code"] == 0
        assert output(client, two, second["execution_id"]).strip() == "alive"


def test_profile_revoke_regrant_rotation_and_shared_owner_sessions(config, sshd):
    _, port = sshd
    with admin_app(config) as client:
        prod = global_profile(client, port=port, name="Production")["profile_id"]
        nas = global_profile(client, port=port, name="NAS")["profile_id"]
        first = issue_token(client, allowed_profile_ids=[prod, nas], shell=True, custom_commands=True,
                            workspaces=["ops"], commands={"uptime": ["uptime"]})
        attached = issue_token(client, attach_to_token_id=first["token_id"], allowed_profile_ids=[nas],
                               shell=True, custom_commands=True, workspaces=["ops"])
        independent = issue_token(client, allowed_profile_ids=[prod], shell=True, workspaces=["ops"])
        first_secret, attached_secret = first["token"], attached["token"]
        created = call(client, "terminal_create", first_secret, profile_id=prod, workspace_id="ops")
        session = created["session_id"]
        assert call(client, "terminal_send", first_secret, session_id=session, input="export OWNER_SCOPE=retained\n")["input_bytes"]
        for wrong in (attached_secret, independent["token"]):
            assert call(client, "terminal_status", wrong, session_id=session)["code"] == "SESSION_NOT_FOUND"
        for tool, extra in (("terminal_activate", {}), ("terminal_read", {}), ("terminal_signal", {"signal": "CTRL_C"}),
                            ("terminal_close", {}), ("terminal_exec", {"command": "pwd"})):
            assert call(client, tool, attached_secret, session_id=session, **extra)["code"] == "SESSION_NOT_FOUND"
        job = call(client, "terminal_exec", first_secret, session_id=session, execution_mode="detached",
                   command="printf begin; sleep 2; printf end; exit 6", yield_time_ms=25)
        execution = job["execution_id"]
        scope = f"tokens/{first['token_id']}/permissions"
        assert admin_request(client, "PATCH", scope, {"allowed_profile_ids": [nas]}).status_code == 200
        assert call(client, "terminal_list", first_secret)["terminals"] == []
        assert call(client, "terminal_exec", first_secret, session_id=session, command="pwd")["code"] == "SESSION_NOT_FOUND"
        assert call(client, "terminal_read", first_secret, session_id=session, execution_id=execution)["code"] == "SESSION_NOT_FOUND"
        assert admin_request(client, "PATCH", scope, {"allowed_profile_ids": [prod, nas]}).status_code == 200
        new = admin_request(client, "POST", f"tokens/{first['token_id']}/rotate").json()
        assert new["owner_id"] == first["owner_id"] and set(new["allowed_profile_ids"]) == {prod, nas}
        assert mcp_status(client, first_secret) == 401 and mcp_status(client, new["token"]) == 200
        token = new["token"]
        assert call(client, "terminal_list", token)["terminals"][0]["session_id"] == session
        echo = call(client, "terminal_send", token, session_id=session,
                    input="printf 'confirmation:%s\\n' \"$OWNER_SCOPE\"\n")
        assert not echo["is_error"], echo
        until(lambda: "confirmation:retained" in output(client, session, token=token))
        assert until(lambda: finished(client, session, execution, token))["exit_code"] == 6
        assert output(client, session, execution, token) == "beginend"
        permissions = f"tokens/{new['token_id']}/permissions"
        assert admin_request(client, "PATCH", permissions, {"shell": False, "custom_commands": False}).status_code == 200
        assert call(client, "terminal_send", token, session_id=session, input="pwd\n")["code"] == "SHELL_FORBIDDEN"
        assert call(client, "terminal_exec", token, session_id=session, command="pwd")["code"] == "COMMAND_FORBIDDEN"
        assert call(client, "terminal_exec", token, session_id=session, operation="uptime")["exit_code"] == 0
        assert admin_request(client, "PATCH", permissions, {"workspaces": []}).status_code == 200
        assert call(client, "terminal_status", token, session_id=session)["code"] == "SESSION_NOT_FOUND"
        assert admin_request(client, "PATCH", permissions, {"workspaces": ["ops"]}).status_code == 200
        assert admin_request(client, "PATCH", f"connections/{prod}", {"enabled": False}).status_code == 200
        assert call(client, "terminal_status", token, session_id=session)["code"] == "SESSION_NOT_FOUND"
        assert admin_request(client, "PATCH", f"connections/{prod}", {"enabled": True}).status_code == 200
        assert call(client, "terminal_status", token, session_id=session)["session_id"] == session
        assert admin_request(client, "PATCH", f"connections/{prod}", {"port": 1}).json()["grants_invalidated"]
        assert admin_request(client, "PATCH", permissions, {"allowed_profile_ids": [prod, nas]}).status_code == 200
        assert call(client, "terminal_status", token, session_id=session)["code"] == "SESSION_NOT_FOUND"
        closed = admin_request(client, "POST", f"connections/{prod}/sessions/{session}/close")
        assert closed.status_code == 200 and closed.json()["status"] == "CLOSED"


def test_real_legacy_tmux_is_reattached_after_v2_database_migration(config, sshd):
    container, port = sshd
    version_two(config)
    name = "t_" + SESSION_ID
    with sqlite3.connect(config.data_dir / "terminal.db") as db:
        db.execute("UPDATE profiles SET configuration=json_set(configuration,'$.port',?) WHERE profile_id=?",
                   (port, PROFILE_ID))
        db.execute("UPDATE sessions SET backend='tmux', tmux_session_name=?, snapshot=json_set(snapshot, '$.port', ?) "
                   "WHERE session_id=?", (name, port, SESSION_ID))
    docker("exec", "-u", "fixture", container, "tmux", "-L", "persistent-terminal-mcp", "new-session", "-d", "-s", name)
    docker("exec", "-u", "fixture", container, "tmux", "-L", "persistent-terminal-mcp",
           "send-keys", "-t", name, "export MIGRATED_TMUX=untouched", "Enter")
    with admin_app(config) as client:
        assert call(client, "connection_list")["connections"][0]["profile_id"] == PROFILE_ID
        assert call(client, "terminal_list")["terminals"][0]["session_id"] == SESSION_ID
        assert call(client, "terminal_status", session_id=SESSION_ID, execution_id=EXECUTION_ID)["exit_code"] == 7
        call(client, "terminal_send", session_id=SESSION_ID, input="printf 'legacy-result:%s\\n' \"$MIGRATED_TMUX\"\n")
        until(lambda: "legacy-result:untouched" in output(client, SESSION_ID))
