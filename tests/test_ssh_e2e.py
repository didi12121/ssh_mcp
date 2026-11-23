from concurrent.futures import ThreadPoolExecutor
import os
import subprocess
import time

import asyncssh
import pytest
from starlette.testclient import TestClient

from conftest import LIMITED, OTHER, TOKEN, call, profile, put_secret
from persistent_terminal_mcp.server import build_app


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
    with TestClient(build_app(config), base_url="http://127.0.0.1") as client:
        config_id = profile(client, port=port)["profile_id"]
        tested = call(client, "connection_test", profile_id=config_id)
        assert tested["authenticated"] and tested["tmux_available"]
        created = call(client, "terminal_create", profile_id=config_id, name="persistent")
        assert not created["is_error"], created
        session = created["session_id"]
        assert call(client, "terminal_create", profile_id=config_id, name="persistent")["reused"]
        assert call(client, "connection_delete", profile_id=config_id)["code"] == "PROFILE_IN_USE"
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
        edited = call(client, "connection_update", profile_id=config_id, changes={"port": 1})
        assert edited["unchanged_session_ids"] == [session]
        logs = subprocess.run(["docker", "logs", container], capture_output=True, check=True, text=True).stderr
        assert logs.count("Accepted publickey for fixture") == 2  # One probe and one managed login.
    with TestClient(build_app(config), base_url="http://127.0.0.1") as client:
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
        assert call(client, "connection_delete", profile_id=config_id)["deleted"]


def test_real_failures_and_restricted_access(config, sshd):
    container, port = sshd
    pinned = config.known_hosts.read_bytes()
    identity = config.data_dir / "identity"
    original = identity.read_bytes()
    wrong = asyncssh.generate_private_key("ssh-ed25519")
    with TestClient(build_app(config), base_url="http://127.0.0.1") as client:
        profile_id = profile(client, LIMITED, port=port)["profile_id"]
        put_secret(config.known_hosts, f"[127.0.0.1]:{port} ".encode() + wrong.export_public_key())
        assert call(client, "connection_test", LIMITED, profile_id=profile_id)["code"] == "HOST_KEY_UNVERIFIED"
        put_secret(config.known_hosts, pinned)
        put_secret(identity, wrong.export_private_key())
        assert call(client, "connection_test", LIMITED, profile_id=profile_id)["code"] == "SSH_AUTH_FAILED"
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
    with TestClient(build_app(config), base_url="http://127.0.0.1") as client:
        profile_id = profile(client, port=port)["profile_id"]
        assert not call(client, "connection_test", profile_id=profile_id)["tmux_available"]
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
