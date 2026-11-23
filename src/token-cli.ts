#!/usr/bin/env node
import path from "node:path";
import { loadConfig } from "./config.js";
import { createAccessToken, loadTokenStore, revokeAccessToken } from "./tokens.js";

function valuesAfter(args: string[], flag: string): string[] {
  return args.flatMap((value, index) => value === flag && args[index + 1] ? [args[index + 1]!] : []);
}

function usage(): never {
  throw new Error([
    "Usage:",
    "  token-cli create <name> [--host <host-id>] [--operation <operation-id>] [--allow-agent-keys]",
    "  token-cli list",
    "  token-cli revoke <name-or-id>",
  ].join("\n"));
}

async function main(): Promise<void> {
  const [command, subject, ...args] = process.argv.slice(2);
  const config = await loadConfig(process.env.SSH_MCP_CONFIG ?? path.resolve("config.yaml"));
  if (!config.http) throw new Error("config.yaml must contain an http section");
  const file = config.http.tokenStoreFile;

  if (command === "create") {
    if (!subject) usage();
    const hosts = valuesAfter(args, "--host");
    const operations = valuesAfter(args, "--operation");
    for (const host of hosts) if (!config.hosts[host]) throw new Error(`unknown configured host '${host}'`);
    for (const operation of operations) if (!config.operations[operation]) throw new Error(`unknown configured operation '${operation}'`);
    const { token, record } = await createAccessToken(file, subject, {
      ...(hosts.length ? { hosts } : {}),
      ...(operations.length ? { operations } : {}),
      allowAgentKeyListing: args.includes("--allow-agent-keys"),
    });
    console.log(`Token created: ${record.name} (${record.id})`);
    console.log("Copy this token now; it is never stored in plaintext:");
    console.log(token);
    return;
  }
  if (command === "list") {
    const store = await loadTokenStore(file);
    console.table(store.tokens.map(({ hash: _hash, ...record }) => record));
    return;
  }
  if (command === "revoke") {
    if (!subject) usage();
    const record = await revokeAccessToken(file, subject);
    console.log(`Token revoked: ${record.name} (${record.id})`);
    return;
  }
  usage();
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
