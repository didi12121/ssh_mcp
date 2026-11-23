import assert from "node:assert/strict";
import test from "node:test";
import type { Config, Host } from "../src/config.js";
import { buildSshInvocation, quotePosixArgument } from "../src/ssh.js";

const config = {
  version: 1,
  ssh: {
    executable: "ssh",
    executableArgs: [],
    sshAddExecutable: "ssh-add",
    knownHostsFile: "C:\\keys\\known_hosts",
    connectTimeoutSeconds: 10,
    commandTimeoutSeconds: 30,
    maxOutputBytes: 65536,
  },
  audit: { file: "audit.jsonl" },
  hosts: {},
  operations: {},
} satisfies Config;

const host = {
  address: "192.0.2.10",
  port: 2222,
  user: "observer",
  description: "",
  tags: [],
  enabled: true,
  identityFile: "C:\\keys\\id_ed25519",
  operations: ["status"],
} satisfies Host;

test("POSIX quoting treats shell metacharacters as data", () => {
  assert.equal(quotePosixArgument("a'b;$(touch /tmp/x)"), `'a'"'"'b;$(touch /tmp/x)'`);
  assert.throws(() => quotePosixArgument("one\ntwo"), /line breaks/);
});

test("SSH invocation enforces strict non-interactive options", () => {
  const invocation = buildSshInvocation(config, host, ["systemctl", "status", "nginx.service"]);
  assert.equal(invocation.executable, "ssh");
  assert.ok(invocation.args.includes("StrictHostKeyChecking=yes"));
  assert.ok(invocation.args.includes("BatchMode=yes"));
  assert.ok(invocation.args.includes("ClearAllForwardings=yes"));
  assert.ok(invocation.args.includes("ForwardAgent=no"));
  assert.ok(invocation.args.includes("IdentitiesOnly=yes"));
  assert.equal(invocation.args.at(-2), "observer@192.0.2.10");
  assert.equal(invocation.args.at(-1), "'systemctl' 'status' 'nginx.service'");
});
