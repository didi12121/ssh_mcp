import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { loadConfig, renderOperation } from "../src/config.js";

async function writeConfig(source: string): Promise<string> {
  const directory = await mkdtemp(path.join(os.tmpdir(), "ssh-mcp-config-"));
  const file = path.join(directory, "config.yaml");
  await writeFile(file, source, "utf8");
  return file;
}

const base = `
version: 1
ssh:
  knownHostsFile: known_hosts
hosts:
  demo:
    address: example.com
    user: observer
    operations: [service_status]
operations:
  service_status:
    description: Read a service status
    command: [systemctl, status, "{service}", --no-pager]
    readOnly: true
    parameters:
      service:
        pattern: "[A-Za-z0-9_.@-]{1,64}"
`;

test("loads a valid config and resolves security-sensitive paths", async () => {
  const file = await writeConfig(base);
  const config = await loadConfig(file);
  assert.equal(config.hosts.demo?.port, 22);
  assert.equal(config.ssh.knownHostsFile, path.join(path.dirname(file), "known_hosts"));
  assert.equal(config.audit.file, path.join(path.dirname(file), ".data", "audit.jsonl"));
});

test("rejects partial placeholders that could create shell syntax", async () => {
  const file = await writeConfig(base.replace('"{service}"', '"--unit={service}"'));
  await assert.rejects(() => loadConfig(file), /complete command arguments/);
});

test("rejects relative private-key paths", async () => {
  const file = await writeConfig(base.replace("    operations: [service_status]", "    identityFile: ./id_ed25519\n    operations: [service_status]"));
  await assert.rejects(() => loadConfig(file), /identityFile must be an absolute path/);
});

test("validates operation parameters before rendering", async () => {
  const config = await loadConfig(await writeConfig(base));
  const operation = config.operations.service_status!;
  assert.deepEqual(renderOperation(operation, { service: "nginx.service" }), ["systemctl", "status", "nginx.service", "--no-pager"]);
  assert.throws(() => renderOperation(operation, { service: "nginx; rm -rf /" }), /allowed pattern/);
  assert.throws(() => renderOperation(operation, {}), /missing required/);
  assert.throws(() => renderOperation(operation, { service: "nginx", extra: "x" }), /unknown parameter/);
});
