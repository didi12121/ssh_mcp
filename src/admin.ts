import { timingSafeEqual } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import express, { type ErrorRequestHandler } from "express";
import type { Config } from "./config.js";
import { generateKey, importKey, KeyError, keyGenerationInput, keyId, keyInput, listKeys, readKey, removeKey } from "./keys.js";
import { buildKeyInstallCommand, keyTarget } from "./key-install.js";

const tokenPattern = /^[a-f0-9]{64}$/u;
const assets = new URL("../admin/", import.meta.url);

async function readToken(file: string): Promise<string> {
  const entry = await stat(file);
  if (!entry.isFile() || (process.getuid && (entry.uid !== process.getuid() || (entry.mode & 0o077) !== 0))) {
    throw new Error("admin token file must be owned by the service user with mode 0600");
  }
  const token = (await readFile(file, "utf8")).trim();
  if (!tokenPattern.test(token)) throw new Error("admin token must contain 64 lowercase hex characters");
  return token;
}

export function createAdminApp(config: Config) {
  const admin = config.admin!;
  const keys = config.keys!;
  const app = express();
  app.disable("x-powered-by");
  app.use((req, res, next) => {
    const host = req.headers.host ?? "";
    if (!/^(?:127\.0\.0\.1|localhost)(?::[0-9]{1,5})?$/u.test(host)) {
      res.status(403).end();
      return;
    }
    if (req.headers.origin && req.headers.origin !== `http://${host}`) {
      res.status(403).end();
      return;
    }
    res.set({
      "Cache-Control": "no-store",
      "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff",
    });
    next();
  });
  app.get("/", (_req, res) => res.sendFile(fileURLToPath(new URL("index.html", assets))));
  app.get("/admin.css", (_req, res) => res.sendFile(fileURLToPath(new URL("admin.css", assets))));
  app.get("/admin.js", (_req, res) => res.sendFile(fileURLToPath(new URL("admin.js", assets))));
  app.get("/connections.js", (_req, res) => res.sendFile(fileURLToPath(new URL("connections.js", assets))));

  app.use("/api", async (req, res, next) => {
    const supplied = req.header("authorization")?.match(/^Bearer ([a-f0-9]{64})$/u)?.[1];
    if (supplied) {
      const expected = await readToken(admin.tokenFile);
      if (timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(supplied, "hex"))) {
        next();
        return;
      }
    }
    res.status(401).json({ error: "Invalid administrator token." });
  });
  app.get("/api/keys", async (_req, res) => {
    const items = await listKeys(keys);
    const keyHosts = Object.entries(config.hosts);
    res.json({
      keys: items.map((item) => ({
        ...item,
        hosts: keyHosts.filter(([, host]) => host.identityKey === item.id).map(([id]) => id),
      })),
      targets: keyHosts.filter(([, host]) => host.enabled)
        .map(([id, { address, port, user }]) => ({ id, address, port, user })),
    });
  });
  app.post("/api/keys", express.json({ limit: "96kb", inflate: false }), async (req, res) => {
    const input = keyInput.safeParse(req.body);
    if (!input.success) {
      res.status(400).json({ error: "Invalid key ID, label, type or key content." });
      return;
    }
    res.status(201).json(await importKey(keys, input.data));
  });
  const smallJson = express.json({ limit: "4kb", inflate: false });
  app.use("/api/connections", smallJson, async (req, res) => {
    if (!admin.terminalAdminPort) {
      res.status(503).json({ error: "尚未配置终端服务的管理接口。" });
      return;
    }
    const endpoint = req.path === "/" ? "" : req.path;
    const allowed = endpoint === ""
      ? ["GET", "POST"].includes(req.method)
      : /^\/[a-f0-9]{32}$/u.test(endpoint)
        ? ["PATCH", "DELETE"].includes(req.method)
        : /^\/[a-f0-9]{32}\/test$/u.test(endpoint) && req.method === "POST";
    if (!allowed) {
      res.status(404).json({ error: "未知的连接管理请求。" });
      return;
    }
    const url = new URL(`http://127.0.0.1:${admin.terminalAdminPort}/admin/connections${endpoint}`);
    for (const field of ["owner", "page"]) {
      if (typeof req.query[field] === "string") url.searchParams.set(field, req.query[field]);
    }
    try {
      const response = await fetch(url, {
        method: req.method,
        headers: { Authorization: req.header("authorization")!, "Content-Type": "application/json" },
        ...(req.body === undefined ? {} : { body: JSON.stringify(req.body) }),
        redirect: "error",
        signal: AbortSignal.timeout(75000),
      });
      res.status(response.status).json(await response.json());
    } catch {
      res.status(502).json({ error: "终端服务管理接口暂不可用。" });
    }
  });
  app.post("/api/keys/generate", smallJson, async (req, res) => {
    const input = keyGenerationInput.safeParse(req.body);
    if (!input.success) throw new KeyError(400, "Invalid key ID, label or algorithm.");
    res.status(201).json(await generateKey(keys, input.data));
  });
  app.post("/api/keys/:id/install-command", smallJson, async (req, res) => {
    const id = keyId.safeParse(req.params.id);
    const target = keyTarget.safeParse(req.body);
    if (!id.success || !target.success) throw new KeyError(400, "Invalid key ID or SSH destination.");
    const key = await readKey(keys, id.data);
    res.json({ command: buildKeyInstallCommand(key, target.data) });
  });
  app.delete("/api/keys/:id", async (req, res) => {
    const id = keyId.safeParse(req.params.id);
    if (!id.success) throw new KeyError(400, "Invalid key ID.");
    await removeKey(config, id.data);
    res.status(204).end();
  });
  const handleError: ErrorRequestHandler = (error: unknown, _req, res, next) => {
    if (res.headersSent) return next(error);
    const status = error instanceof KeyError ? error.status : Number((error as { status?: number }).status) || 500;
    const message = error instanceof KeyError ? error.message
      : status < 500 ? "Invalid request." : "Key management service unavailable.";
    res.status(status).json({ error: message });
  };
  app.use(handleError);
  return app;
}

export async function startAdminServer(config: Config): Promise<() => Promise<void>> {
  await readToken(config.admin!.tokenFile);
  const server = createServer(createAdminApp(config));
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.admin!.port, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  return () => new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}
