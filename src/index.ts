#!/usr/bin/env node
import path from "node:path";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadConfig } from "./config.js";
import { createServer } from "./server.js";

async function main(): Promise<void> {
  const configPath = process.env.SSH_MCP_CONFIG ?? path.resolve("config.yaml");
  const config = await loadConfig(configPath);
  const server = createServer(config);
  await server.connect(new StdioServerTransport());
  console.error(`local-ssh-mcp started with ${Object.values(config.hosts).filter((host) => host.enabled).length} enabled host(s)`);
}

main().catch((error) => {
  console.error(`local-ssh-mcp failed to start: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
});
