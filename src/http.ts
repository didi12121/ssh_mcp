#!/usr/bin/env node
import { randomUUID } from "node:crypto";
import { createServer as createHttpServer, type Server as NodeHttpServer } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import type { Express, NextFunction, Request, Response } from "express";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { Config } from "./config.js";
import { loadConfig } from "./config.js";
import { createServer } from "./server.js";
import { authenticateToken, filterConfigForToken, type TokenRecord } from "./tokens.js";
import { startAdminServer } from "./admin.js";

interface AuthenticatedRequest extends Request {
  mcpToken?: TokenRecord;
}

interface Session {
  transport: StreamableHTTPServerTransport;
  server: McpServer;
  tokenId: string;
  lastSeen: number;
}

function getSessionId(req: Request): string | undefined {
  const value = req.headers["mcp-session-id"];
  return typeof value === "string" ? value : undefined;
}

function rpcError(res: Response, status: number, message: string): void {
  res.status(status).json({ jsonrpc: "2.0", error: { code: -32000, message }, id: null });
}

export function createHttpMcpApp(config: Config): { app: Express; close: () => Promise<void> } {
  if (!config.http) throw new Error("config.yaml must contain an http section");
  const httpConfig = config.http;
  const app = createMcpExpressApp({ host: httpConfig.host, allowedHosts: httpConfig.allowedHosts });
  const sessions = new Map<string, Session>();
  const rateWindows = new Map<string, { startedAt: number; count: number }>();

  app.disable("x-powered-by");
  app.use((_req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");
    next();
  });
  app.get("/health", (_req, res) => res.json({ ok: true, service: "local-ssh-mcp" }));

  const authenticate = async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    const match = /^Bearer ([A-Za-z0-9_-]{20,})$/u.exec(req.header("authorization") ?? "");
    if (!match?.[1]) {
      res.setHeader("WWW-Authenticate", "Bearer");
      res.status(401).json({ error: "missing or invalid bearer token" });
      return;
    }
    try {
      const token = await authenticateToken(httpConfig.tokenStoreFile, match[1]);
      if (!token) {
        res.setHeader("WWW-Authenticate", "Bearer");
        res.status(401).json({ error: "invalid or revoked bearer token" });
        return;
      }
      req.mcpToken = token;
      next();
    } catch {
      res.status(503).json({ error: "token store unavailable" });
    }
  };

  const rateLimit = (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    const token = req.mcpToken!;
    const now = Date.now();
    const current = rateWindows.get(token.id);
    if (!current || now - current.startedAt >= 60_000) {
      rateWindows.set(token.id, { startedAt: now, count: 1 });
      next();
      return;
    }
    current.count += 1;
    if (current.count > httpConfig.maxRequestsPerMinute) {
      res.setHeader("Retry-After", String(Math.max(1, Math.ceil((60_000 - (now - current.startedAt)) / 1000))));
      res.status(429).json({ error: "rate limit exceeded" });
      return;
    }
    next();
  };

  app.use("/mcp", authenticate, rateLimit);

  app.post("/mcp", async (req: AuthenticatedRequest, res) => {
    const token = req.mcpToken!;
    const sessionId = getSessionId(req);
    try {
      if (sessionId) {
        const session = sessions.get(sessionId);
        if (!session) return rpcError(res, 404, "unknown or expired MCP session");
        if (session.tokenId !== token.id) return rpcError(res, 403, "token does not own this MCP session");
        session.lastSeen = Date.now();
        await session.transport.handleRequest(req, res, req.body);
        return;
      }
      if (!isInitializeRequest(req.body)) return rpcError(res, 400, "initial request must be MCP initialize");
      if (sessions.size >= httpConfig.maxSessions) return rpcError(res, 503, "maximum MCP sessions reached");

      const scopedConfig = filterConfigForToken(config, token);
      const mcpServer = createServer(scopedConfig, {
        enableAgentKeyListing: token.allowAgentKeyListing,
        auditActor: `${token.name}:${token.id}`,
      });
      let transport: StreamableHTTPServerTransport;
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (newSessionId) => {
          sessions.set(newSessionId, { transport, server: mcpServer, tokenId: token.id, lastSeen: Date.now() });
        },
      });
      transport.onclose = () => {
        if (transport.sessionId) sessions.delete(transport.sessionId);
      };
      // SDK 1.30's Node wrapper and base Transport differ only in optional-property typing.
      await mcpServer.connect(transport as unknown as Transport);
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      console.error(`MCP request failed: ${error instanceof Error ? error.message : String(error)}`);
      if (!res.headersSent) rpcError(res, 500, "internal MCP server error");
    }
  });

  const handleExistingSession = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    const sessionId = getSessionId(req);
    const session = sessionId ? sessions.get(sessionId) : undefined;
    if (!session) return rpcError(res, 404, "unknown or expired MCP session");
    if (session.tokenId !== req.mcpToken!.id) return rpcError(res, 403, "token does not own this MCP session");
    session.lastSeen = Date.now();
    try {
      await session.transport.handleRequest(req, res);
    } catch (error) {
      console.error(`MCP session request failed: ${error instanceof Error ? error.message : String(error)}`);
      if (!res.headersSent) rpcError(res, 500, "internal MCP server error");
    }
  };

  app.get("/mcp", handleExistingSession);
  app.delete("/mcp", handleExistingSession);

  const sweep = setInterval(() => {
    const oldestAllowed = Date.now() - httpConfig.sessionIdleMinutes * 60_000;
    for (const [id, session] of sessions) {
      if (session.lastSeen < oldestAllowed) {
        sessions.delete(id);
        void session.transport.close().catch(() => undefined);
      }
    }
  }, 60_000);
  sweep.unref();

  return {
    app,
    close: async () => {
      clearInterval(sweep);
      const active = [...sessions.values()];
      sessions.clear();
      await Promise.allSettled(active.map((session) => session.transport.close()));
    },
  };
}

export async function startHttpMcpServer(config: Config): Promise<{ httpServer: NodeHttpServer; close: () => Promise<void> }> {
  if (!config.http) throw new Error("config.yaml must contain an http section");
  const closeAdmin = config.admin ? await startAdminServer(config) : undefined;
  const instance = createHttpMcpApp(config);
  const httpServer = createHttpServer(instance.app);
  try {
    await new Promise<void>((resolve, reject) => {
      httpServer.once("error", reject);
      httpServer.listen(config.http!.port, config.http!.host, () => {
        httpServer.off("error", reject);
        resolve();
      });
    });
  } catch (error) {
    await instance.close();
    await closeAdmin?.();
    throw error;
  }
  return {
    httpServer,
    close: async () => {
      await instance.close();
      await Promise.all([
        closeAdmin?.(),
        new Promise<void>((resolve, reject) => httpServer.close((error) => error ? reject(error) : resolve())),
      ]);
    },
  };
}

async function main(): Promise<void> {
  const config = await loadConfig(process.env.SSH_MCP_CONFIG ?? path.resolve("config.yaml"));
  if (!config.http) throw new Error("config.yaml must contain an http section");
  const running = await startHttpMcpServer(config);
  console.error(`local-ssh-mcp listening on http://${config.http.host}:${config.http.port}/mcp`);
  if (config.admin) console.error(`Key administration listening on http://127.0.0.1:${config.admin.port}/`);
  if (config.admin?.lan) {
    const { address, subnet, port = config.admin.port } = config.admin.lan;
    console.error(`LAN administration listening on https://${address}:${port}/ for ${subnet}`);
  }
  const shutdown = async (): Promise<void> => {
    await running.close();
    process.exit(0);
  };
  process.once("SIGINT", () => void shutdown());
  process.once("SIGTERM", () => void shutdown());
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
  main().catch((error) => {
    console.error(`local-ssh-mcp HTTP failed to start: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  });
}
