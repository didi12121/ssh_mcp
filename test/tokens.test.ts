import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import type { Config } from "../src/config.js";
import { authenticateToken, createAccessToken, filterConfigForToken, loadTokenStore, revokeAccessToken } from "../src/tokens.js";

test("stores only token hashes and supports immediate revocation", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "ssh-mcp-tokens-"));
  const file = path.join(directory, "tokens.json");
  const created = await createAccessToken(file, "codex", { hosts: ["demo"], operations: ["uptime"] });
  assert.match(created.token, /^ssh_mcp_[A-Za-z0-9_-]+$/);
  const store = await loadTokenStore(file);
  assert.equal(store.tokens[0]?.hash.includes(created.token), false);
  assert.equal((await authenticateToken(file, created.token))?.name, "codex");
  assert.equal(await authenticateToken(file, "ssh_mcp_wrong_wrong_wrong_wrong"), undefined);
  await revokeAccessToken(file, "codex");
  assert.equal(await authenticateToken(file, created.token), undefined);
});

test("filters hosts and operations to token scopes", async () => {
  const operation = { description: "read", command: ["uptime"], readOnly: true as const, parameters: {} };
  const config = {
    version: 1 as const,
    ssh: { executable: "ssh", executableArgs: [], sshAddExecutable: "ssh-add", knownHostsFile: "known_hosts", connectTimeoutSeconds: 5, commandTimeoutSeconds: 10, maxOutputBytes: 4096 },
    audit: { file: "audit.jsonl" },
    hosts: {
      one: { address: "one.local", port: 22, user: "observer", description: "", tags: [], enabled: true, operations: ["uptime", "disk"] },
      two: { address: "two.local", port: 22, user: "observer", description: "", tags: [], enabled: true, operations: ["uptime"] },
    },
    operations: { uptime: operation, disk: { ...operation, command: ["df", "-h"] } },
  } satisfies Config;
  const token = {
    id: "00000000-0000-4000-8000-000000000000",
    name: "limited",
    hash: "0".repeat(64),
    createdAt: new Date().toISOString(),
    enabled: true,
    hosts: ["one"],
    operations: ["uptime"],
    allowAgentKeyListing: false,
  };
  const filtered = filterConfigForToken(config, token);
  assert.deepEqual(Object.keys(filtered.hosts), ["one"]);
  assert.deepEqual(filtered.hosts.one?.operations, ["uptime"]);
  assert.deepEqual(Object.keys(filtered.operations), ["uptime"]);
});
