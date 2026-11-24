import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import os from "node:os";
import path from "node:path";
import { setTimeout as wait } from "node:timers/promises";
import { createAdminApp } from "../dist/admin.js";

const python = process.env.PTMCP_TEST_PYTHON;
const chrome = process.env.PTMCP_TEST_CHROME;
if (!python || !chrome) throw new Error("Set PTMCP_TEST_PYTHON and PTMCP_TEST_CHROME to run the browser test.");
const temporary = await mkdtemp(path.join(os.tmpdir(), "ssh-mcp-identity-browser-"));
const admin = randomBytes(32).toString("hex");
const tokenFile = path.join(temporary, "admin-token");
const portFile = path.join(temporary, "port");
const profile = path.join(temporary, "chrome");
await writeFile(tokenFile, admin, { mode: 0o600 });
await writeFile(path.join(temporary, "credentials.json"), JSON.stringify({
  fixture: { kind: "key", file: path.join(temporary, "fixture-key") },
}), { mode: 0o600 });
const script = `
import socket, sys
from pathlib import Path
import uvicorn
from persistent_terminal_mcp.config import Settings
from persistent_terminal_mcp.server import build_app
root = Path(sys.argv[1])
settings = Settings(data_dir=root, principals_file=root / "legacy.json",
                    credentials_file=root / "credentials.json", web_admin_token_file=root / "admin-token")
with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    (root / "port").write_text(str(listener.getsockname()[1]))
    uvicorn.Server(uvicorn.Config(build_app(settings), log_level="warning")).run(sockets=[listener])
`;
const terminal = spawn(python, ["-c", script, temporary], { windowsHide: true, stdio: "ignore" });
let browser;
let server;
let socket;

async function until(check) {
  for (let index = 0; index < 100; index++) {
    const result = await check().catch(() => false);
    if (result) return result;
    await wait(100);
  }
  throw new Error("Browser integration condition timed out");
}

try {
  const port = Number(await until(() => readFile(portFile, "utf8")));
  const terminalOrigin = "http://127.0.0.1:" + port;
  await until(async () => (await fetch(terminalOrigin + "/health")).ok);
  server = createServer(createAdminApp({
    admin: { port: 0, terminalAdminPort: port, tokenFile },
    keys: { directory: path.join(temporary, "keys"), sshKeygenExecutable: "ssh-keygen" },
    hosts: {},
  }));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const origin = "http://127.0.0.1:" + server.address().port;
  browser = spawn(chrome, ["--headless=new", "--remote-debugging-port=0", "--no-first-run",
    "--disable-gpu", "--user-data-dir=" + profile, origin], { windowsHide: true, stdio: "ignore" });
  const devtools = await until(() => readFile(path.join(profile, "DevToolsActivePort"), "utf8"));
  const targets = await (await fetch("http://127.0.0.1:" + devtools.split("\n")[0] + "/json/list")).json();
  socket = new WebSocket(targets.find((target) => target.type === "page").webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", reject, { once: true });
  });
  let sequence = 0;
  const call = (method, params) => new Promise((resolve, reject) => {
    const id = ++sequence;
    const listener = (event) => {
      const result = JSON.parse(event.data);
      if (result.id !== id) return;
      socket.removeEventListener("message", listener);
      if (result.error) reject(new Error("Chrome command failed"));
      else resolve(result.result);
    };
    socket.addEventListener("message", listener);
    socket.send(JSON.stringify({ id, method, params }));
  });
  async function evaluate(expression) {
    const result = await call("Runtime.evaluate", { expression, returnByValue: true, userGesture: true });
    if (result.exceptionDetails) throw new Error("Browser script failed");
    return result.result.value;
  }
  const click = (id) => evaluate(`document.getElementById(${JSON.stringify(id)}).click()`);
  const fill = (id, value) => evaluate(`document.getElementById(${JSON.stringify(id)}).value=${JSON.stringify(value)}`);
  const secretValue = () => evaluate("document.querySelector('#token-secret').value");
  const listText = () => evaluate("document.querySelector('#token-list').textContent");
  const mcp = (token, method, params = {}) => fetch(terminalOrigin + "/mcp", {
    method: "POST",
    headers: { Authorization: "Bearer " + token, Accept: "application/json, text/event-stream",
      "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });

  await until(() => evaluate("document.readyState === 'complete' && Boolean(document.getElementById('token'))"));
  await fill("token", admin);
  await evaluate("document.querySelector('#login button').click()");
  await until(() => evaluate("!document.getElementById('sections').hidden"));
  assert.equal(await evaluate("document.querySelector('#sections').children.length"), 3);
  await click("nav-connections");
  await until(() => evaluate("!document.getElementById('connection-form').hidden"));
  await evaluate("document.querySelector('#connection-tmux-help summary').click()");
  assert.equal(await evaluate("document.querySelector('#connection-tmux-help').open"), true);
  assert.ok((await evaluate("document.querySelector('#connection-tmux-help').innerText")).includes("sudo apt install tmux python3"));
  await fill("connection-name", "Browser profile");
  await fill("connection-host", "example.internal");
  await fill("connection-user", "fixture");
  await fill("connection-credential", "fixture");
  await click("connections-save");
  await until(() => evaluate("document.querySelector('#connection-list').textContent.includes('Browser profile')"));
  await click("nav-tokens");
  await until(() => evaluate("!document.getElementById('tokens-empty').hidden"));
  await click("token-create");
  await fill("token-name", "Browser token");
  await evaluate("document.querySelector('#token-profile-options input').click()");
  await click("token-submit");
  const first = await until(secretValue);
  assert.ok(first.startsWith("ptmcp_"));
  await call("Browser.grantPermissions", { origin, permissions: ["clipboardReadWrite", "clipboardSanitizedWrite"] });
  await click("token-copy");
  await until(() => evaluate("document.getElementById('token-dialog-status').textContent.includes('已复制')"));
  await click("token-close");
  assert.equal((await secretValue()).length, 0);
  assert.ok(!(await listText()).includes(first));
  assert.equal(await evaluate("localStorage.length + sessionStorage.length"), 0);
  const init = await mcp(first, "initialize", { protocolVersion: "2025-03-26", capabilities: {},
    clientInfo: { name: "browser-test", version: "1" } });
  assert.equal(init.status, 200);
  assert.ok((await init.json()).result.serverInfo);
  const tools = await (await mcp(first, "tools/list")).json();
  assert.equal(tools.result.tools.length, 11);
  const connections = await (await mcp(first, "tools/call", { name: "connection_list", arguments: {} })).json();
  assert.equal(connections.result.structuredContent.connections[0].name, "Browser profile");
  assert.ok(!Object.hasOwn(connections.result.structuredContent.connections[0], "host"));
  const openPermissions = () => evaluate("[...document.querySelectorAll('#token-list button')].find(x=>x.textContent==='编辑权限').click()");
  const listed = async () => (await (await mcp(first, "tools/call", { name: "connection_list", arguments: {} })).json()).result.structuredContent.total;
  await openPermissions();
  await evaluate("document.querySelector('#token-profile-options input').click()");
  await click("token-submit");
  await until(async () => await listed() === 0);
  await until(() => evaluate("!document.getElementById('token-dialog').open"));
  await openPermissions();
  await evaluate("document.querySelector('#token-profile-options input').click()");
  await click("token-submit");
  await until(async () => await listed() === 1);
  await until(() => evaluate("!document.getElementById('token-dialog').open"));
  await evaluate("window.confirm=()=>true");
  await evaluate("[...document.querySelectorAll('#token-list button')].find(x=>x.textContent==='轮换').click()");
  await click("token-submit");
  const second = await until(secretValue);
  assert.ok(second !== first);
  assert.equal((await mcp(first, "tools/list")).status, 401);
  assert.equal((await mcp(second, "tools/list")).status, 200);
  await click("token-close");
  assert.equal((await secretValue()).length, 0);
  await until(() => evaluate("Boolean([...document.querySelectorAll('#token-list button')].find(x=>x.textContent==='撤销'))"));
  await evaluate("[...document.querySelectorAll('#token-list button')].find(x=>x.textContent==='撤销').click()");
  await until(async () => (await mcp(second, "tools/list")).status === 401);
  assert.ok(!(await listText()).includes(second));
  console.log("Browser integration passed: global connection, one-time Token, opaque discovery, rotation and revocation.");
} finally {
  socket?.close();
  for (const processHandle of [browser, terminal]) {
    if (processHandle?.exitCode === null) {
      processHandle.kill();
      await Promise.race([once(processHandle, "exit"), wait(2000)]);
    }
  }
  server?.closeAllConnections();
  server?.close();
  await rm(temporary, { recursive: true, force: true, maxRetries: 4 }).catch(() => undefined);
}
