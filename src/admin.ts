import { timingSafeEqual, X509Certificate } from "node:crypto";
import { readFile, realpath, stat } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { BlockList } from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import express, { type ErrorRequestHandler } from "express";
import type { Config } from "./config.js";
import { generateKey, importKey, KeyError, keyGenerationInput, keyId, keyInput, listKeys, readKey, removeKey } from "./keys.js";
import { buildKeyInstallCommand, keyTarget } from "./key-install.js";

const tokenPattern = /^[a-f0-9]{64}$/u;
const assets = new URL("../admin/", import.meta.url);
const terminalAdminRoutes = {
  connections: {
    methods: ["GET", "POST"],
    records: /^\/[a-f0-9]{32}$/u,
    recordMethods: ["GET", "PATCH", "DELETE"],
    actions: /^\/[a-f0-9]{32}\/test$/u,
    query: ["page"],
  },
  tokens: {
    methods: ["GET", "POST"],
    records: /^\/[a-f0-9]{32}$/u,
    recordMethods: ["GET", "DELETE"],
    actions: /^\/[a-f0-9]{32}\/(?:rotate|revoke)$/u,
    query: ["owner", "status", "page", "limit", "catalog"],
  },
};

async function readSecret(file: string, label: string): Promise<Buffer> {
  const entry = await stat(file);
  if (!entry.isFile() || (process.getuid && (entry.uid !== process.getuid() || (entry.mode & 0o077) !== 0))) {
    throw new Error(`${label} must be owned by the service user with mode 0600`);
  }
  return readFile(file);
}

async function readToken(file: string): Promise<string> {
  const token = (await readSecret(file, "admin token file")).toString("utf8").trim();
  if (!tokenPattern.test(token)) throw new Error("admin token must contain 64 lowercase hex characters");
  return token;
}

export function createAdminApp(config: Config, lan?: { authority: string; clients: BlockList }) {
  const admin = config.admin!;
  const keys = config.keys!;
  const app = express();
  app.disable("x-powered-by");
  app.use((req, res, next) => {
    const hosts = req.headersDistinct.host;
    const host = hosts?.length === 1 ? hosts[0]! : "";
    const allowed = lan
      ? host === lan.authority && lan.clients.check(req.socket.remoteAddress ?? "", "ipv4")
      : /^(?:127\.0\.0\.1|localhost)(?::[0-9]{1,5})?$/u.test(host);
    if (!allowed) {
      res.status(403).end();
      return;
    }
    const origins = req.headersDistinct.origin;
    if (origins && (origins.length !== 1 || origins[0] !== `${lan ? "https" : "http"}://${host}`)) {
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
  app.get("/identity.js", (_req, res) => res.sendFile(fileURLToPath(new URL("identity.js", assets))));

  app.use("/api", async (req, res, next) => {
    const headers = req.headersDistinct.authorization;
    const supplied = headers?.length === 1 ? headers[0]?.match(/^Bearer ([a-f0-9]{64})$/u)?.[1] : undefined;
    if (supplied) {
      const expected = await readToken(admin.tokenFile);
      if (timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(supplied, "hex"))) {
        next();
        return;
      }
    }
    res.status(401).json({ error: "Invalid administrator token." });
  });
  app.get("/api/keys", async (req, res) => {
    const items = await listKeys(keys);
    const keyHosts = Object.entries(config.hosts);
    let references: Record<string, Array<{ name: string }>> = {};
    let referencesAvailable = !admin.terminalAdminPort;
    if (admin.terminalAdminPort && items.length) {
      try {
        const response = await fetch(`http://127.0.0.1:${admin.terminalAdminPort}/admin/keys`, {
          headers: { Authorization: req.header("authorization")! },
          redirect: "error", signal: AbortSignal.timeout(5000),
        });
        if (response.ok) {
          const data = await response.json() as { vault: string; references: typeof references };
          referencesAvailable = path.resolve(data.vault) === await realpath(keys.directory);
          if (referencesAvailable) references = data.references;
        }
      } catch {
        // Browsing the key store can continue while the terminal service is recovering.
      }
    }
    res.json({
      referencesAvailable,
      keys: items.map((item) => ({
        ...item,
        hosts: keyHosts.filter(([, host]) => host.identityKey === item.id ||
          host.identityFile === path.join(keys.directory, item.id, "identity")).map(([id]) => id),
        references: Object.hasOwn(references, item.id) ? references[item.id] : [],
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
  for (const [resource, rules] of Object.entries(terminalAdminRoutes)) {
    app.use(`/api/${resource}`, express.json({ limit: "40kb", inflate: false }), async (req, res) => {
      if (!admin.terminalAdminPort) {
        res.status(503).json({ error: "尚未配置终端服务的管理接口。" });
        return;
      }
      const endpoint = req.path === "/" ? "" : req.path;
      const allowed = endpoint === ""
        ? rules.methods.includes(req.method)
        : rules.records.test(endpoint)
          ? rules.recordMethods.includes(req.method)
          : (rules.actions.test(endpoint) && req.method === "POST")
            || (resource === "tokens" && req.method === "PATCH" && /^\/[a-f0-9]{32}\/permissions$/u.test(endpoint))
            || (resource === "connections" && req.method === "GET" && /^\/[a-f0-9]{32}\/sessions$/u.test(endpoint))
            || (resource === "connections" && req.method === "POST" &&
              /^\/[a-f0-9]{32}\/sessions\/[a-f0-9]{32}\/close$/u.test(endpoint));
      if (!allowed) {
        res.status(404).json({ error: "未知的连接管理请求。" });
        return;
      }
      const url = new URL(`http://127.0.0.1:${admin.terminalAdminPort}/admin/${resource}${endpoint}`);
      for (const field of rules.query) {
        if (typeof req.query[field] === "string") url.searchParams.set(field, req.query[field]);
      }
      try {
        const requestId = resource === "tokens" ? req.header("idempotency-key") : undefined;
        const response = await fetch(url, {
          method: req.method,
          headers: {
            Authorization: req.header("authorization")!,
            "Content-Type": "application/json",
            ...(requestId ? { "Idempotency-Key": requestId } : {}),
          },
          ...(req.body === undefined ? {} : { body: JSON.stringify(req.body) }),
          redirect: "error",
          signal: AbortSignal.timeout(75000),
        });
        const retryAfter = response.headers.get("retry-after");
        if (retryAfter) res.setHeader("Retry-After", retryAfter);
        res.status(response.status).json(await response.json());
      } catch {
        res.status(502).json({ error: "终端服务管理接口暂不可用。" });
      }
    });
  }
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
    if (!admin.terminalAdminPort) {
      await removeKey(config, id.data);
      res.status(204).end();
      return;
    }
    if (Object.values(config.hosts).some((host) => host.identityKey === id.data ||
      host.identityFile === path.join(keys.directory, id.data, "identity"))) {
      res.status(409).json({ error: "密钥仍被旧版 SSH 主机配置引用。" });
      return;
    }
    try {
      const response = await fetch(`http://127.0.0.1:${admin.terminalAdminPort}/admin/keys/${id.data}/delete`, {
        method: "POST", redirect: "error", signal: AbortSignal.timeout(15000),
        headers: { Authorization: req.header("authorization")!, "Content-Type": "application/json" },
        body: JSON.stringify({ vault: keys.directory }),
      });
      if (response.ok) res.status(204).end();
      else res.status(response.status).json(await response.json());
    } catch {
      res.status(502).json({ error: "无法校验密钥引用，稍后再试。" });
    }
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

function listen(server: Server, host: string, port: number): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      resolve();
    });
  });
}

function closeServer(server: Server): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}

export async function startAdminServer(config: Config): Promise<() => Promise<void>> {
  const admin = config.admin!;
  await readToken(admin.tokenFile);
  const local = createServer(createAdminApp(config));
  const lan = admin.lan;
  if (!lan) {
    await listen(local, "127.0.0.1", admin.port);
    return () => closeServer(local);
  }

  const port = lan.port ?? admin.port;
  const authority = port === 443 ? lan.address : `${lan.address}:${port}`;
  const [network, mask] = lan.subnet.split("/") as [string, string];
  const clients = new BlockList();
  clients.addSubnet(network, Number(mask), "ipv4");
  const [cert, key] = await Promise.all([readFile(lan.certFile), readSecret(lan.keyFile, "LAN TLS key file")]);
  if (!new X509Certificate(cert).checkIP(lan.address)) {
    throw new Error("LAN TLS certificate must list the configured IP in its subject alternative names");
  }
  const tls = createHttpsServer({ cert, key, minVersion: "TLSv1.2" }, createAdminApp(config, { authority, clients }));
  await listen(local, "127.0.0.1", admin.port);
  try {
    await listen(tls, lan.address, port);
  } catch (error) {
    await closeServer(local);
    throw error;
  }
  return async () => { await Promise.all([closeServer(local), closeServer(tls)]); };
}
