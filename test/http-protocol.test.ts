import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { loadConfig } from "../src/config.js";
import { createHttpMcpApp } from "../src/http.js";
import { createAccessToken } from "../src/tokens.js";

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const mockSsh = path.join(projectRoot, "test", "fixtures", "mock-ssh.mjs");

test("intranet HTTP MCP requires a bearer token and applies token scopes", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "ssh-mcp-http-"));
  const configPath = path.join(directory, "config.yaml");
  await writeFile(configPath, `
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
http:
  host: 127.0.0.1
  port: 8787
  allowedHosts: [127.0.0.1]
  tokenStoreFile: tokens.json
  maxRequestsPerMinute: 100
  sessionIdleMinutes: 5
  maxSessions: 10
hosts:
  demo:
    address: example.com
    user: observer
    operations: [uptime, disk]
operations:
  uptime:
    description: Read uptime
    command: [uptime]
    readOnly: true
  disk:
    description: Read disk usage
    command: [df, -h]
    readOnly: true
`, "utf8");
  const config = await loadConfig(configPath);
  const { token } = await createAccessToken(config.http!.tokenStoreFile, "http_test", {
    hosts: ["demo"], operations: ["uptime"],
  });
  const instance = createHttpMcpApp(config);
  const httpServer = createServer(instance.app);
  await new Promise<void>((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
  const address = httpServer.address();
  if (!address || typeof address === "string") throw new Error("test server has no TCP address");
  const url = new URL(`http://127.0.0.1:${address.port}/mcp`);

  try {
    const unauthorized = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    assert.equal(unauthorized.status, 401);

    const transport = new StreamableHTTPClientTransport(url, {
      requestInit: { headers: { Authorization: `Bearer ${token}` } },
    });
    const client = new Client({ name: "http-test-client", version: "1.0.0" });
    await client.connect(transport);
    try {
      const tools = await client.listTools();
      assert.equal(tools.tools.some((tool) => tool.name === "list_agent_keys"), false);
      const operations = await client.callTool({ name: "list_operations", arguments: { host_id: "demo" } });
      const content = operations.content[0];
      if (!content || content.type !== "text") throw new Error("missing tool output");
      const parsed = JSON.parse(content.text) as { operations: Array<{ id: string }> };
      assert.deepEqual(parsed.operations.map((operation) => operation.id), ["uptime"]);
      const result = await client.callTool({ name: "run_operation", arguments: { host_id: "demo", operation_id: "uptime" } });
      assert.notEqual(result.isError, true);
    } finally {
      await client.close();
    }
  } finally {
    await instance.close();
    await new Promise<void>((resolve, reject) => httpServer.close((error) => error ? reject(error) : resolve()));
  }
});
