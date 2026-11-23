import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const mockSsh = path.join(projectRoot, "test", "fixtures", "mock-ssh.mjs");
const serverEntry = path.join(projectRoot, "dist", "index.js");

function textPayload(result: Awaited<ReturnType<Client["callTool"]>>): Record<string, unknown> {
  const first = result.content[0];
  assert.equal(first?.type, "text");
  if (!first || first.type !== "text") throw new Error("missing text result");
  return JSON.parse(first.text) as Record<string, unknown>;
}

test("STDIO server exposes only policy-constrained tools and executes a configured operation", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "ssh-mcp-protocol-"));
  const configPath = path.join(directory, "config.yaml");
  const auditPath = path.join(directory, "audit.jsonl");
  const yaml = `
version: 1
ssh:
  executable: ${JSON.stringify(process.execPath)}
  executableArgs: [${JSON.stringify(mockSsh)}]
  sshAddExecutable: ssh-add
  knownHostsFile: known_hosts
  connectTimeoutSeconds: 2
  commandTimeoutSeconds: 2
  maxOutputBytes: 8192
audit:
  file: audit.jsonl
hosts:
  demo:
    address: example.com
    user: observer
    operations: [service_status]
operations:
  service_status:
    description: Read service status
    command: [systemctl, status, "{service}", --no-pager]
    readOnly: true
    parameters:
      service:
        pattern: "[A-Za-z0-9_.@-]{1,64}"
`;
  await writeFile(configPath, yaml, "utf8");

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [serverEntry],
    cwd: projectRoot,
    env: { SSH_MCP_CONFIG: configPath },
    stderr: "pipe",
  });
  const client = new Client({ name: "local-ssh-mcp-test", version: "1.0.0" });
  await client.connect(transport);
  try {
    const tools = await client.listTools();
    assert.deepEqual(tools.tools.map((tool) => tool.name).sort(), [
      "list_agent_keys", "list_hosts", "list_operations", "run_operation", "test_connection",
    ]);

    const hosts = textPayload(await client.callTool({ name: "list_hosts", arguments: {} }));
    assert.equal((hosts.hosts as Array<{ id: string }>)[0]?.id, "demo");
    assert.deepEqual(Object.keys((hosts.hosts as object[])[0]!).sort(), ["description", "id", "tags"]);

    const operation = await client.callTool({
      name: "run_operation",
      arguments: { host_id: "demo", operation_id: "service_status", parameters: { service: "nginx.service" } },
    });
    assert.notEqual(operation.isError, true);
    const payload = textPayload(operation);
    assert.equal(payload.ok, true);
    assert.match(String(payload.stdout), /'systemctl' 'status' 'nginx\.service' '--no-pager'/);

    const rejected = await client.callTool({
      name: "run_operation",
      arguments: { host_id: "demo", operation_id: "service_status", parameters: { service: "nginx;id" } },
    });
    assert.equal(rejected.isError, true);

    const audit = await readFile(auditPath, "utf8");
    assert.match(audit, /"operationId":"service_status"/);
    assert.doesNotMatch(audit, /nginx\.service/);
  } finally {
    await client.close();
  }
});
