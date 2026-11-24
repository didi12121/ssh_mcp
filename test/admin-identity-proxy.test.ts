import assert from "node:assert/strict";
import { createServer, get, type Server } from "node:http";
import { BlockList } from "node:net";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createAdminApp } from "../src/admin.js";
import { loadConfig } from "../src/config.js";

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("No HTTP address");
  return address.port;
}

const close = (server: Server) => new Promise<void>((resolve, reject) => {
  server.close((error) => error ? reject(error) : resolve());
});

test("identity proxy authenticates and only forwards allowlisted routes and query fields", async () => {
  const admin = "2".repeat(64);
  const requestId = "aa57b2c9-ff26-40cc-8fb2-7a8e39712120";
  const called: Array<{ url: string | undefined; idempotency: string | string[] | undefined }> = [];
  const upstream = createServer((req, res) => {
    assert.equal(req.headers.authorization, `Bearer ${admin}`);
    called.push({ url: req.url, idempotency: req.headers["idempotency-key"] });
    req.resume();
    res.writeHead(req.method === "POST" ? 429 : 200, { "Content-Type": "application/json", "Retry-After": "7" });
    res.end("{}");
  });
  const temp = await mkdtemp(path.join(os.tmpdir(), "ssh-mcp-admin-identity-"));
  const port = await listen(upstream);
  let server: Server | undefined;
  let lanServer: Server | undefined;
  try {
    await writeFile(path.join(temp, "admin-token"), admin, { mode: 0o600 });
    const config = path.join(temp, "config.yaml");
    await writeFile(config, `
version: 1
ssh: { knownHostsFile: known_hosts }
keys: {}
admin: { tokenFile: admin-token, terminalAdminPort: ${port} }
hosts:
  demo: { address: example.com, user: observer, operations: [uptime] }
operations:
  uptime: { description: Read uptime, command: [uptime], readOnly: true }
`);
    const settings = await loadConfig(config);
    server = createServer(createAdminApp(settings));
    const base = `http://127.0.0.1:${await listen(server)}`;
    const auth = { Authorization: `Bearer ${admin}` };
    assert.equal((await fetch(`${base}/api/tokens`)).status, 401);
    assert.equal((await fetch(`${base}/api/connections`, { headers: { ...auth, Origin: "http://invalid.test" } })).status, 403);
    assert.equal((await fetch(`${base}/api/tokens/00000000000000000000000000000000/other`,
      { headers: auth, method: "POST" })).status, 404);
    const tokens = await fetch(`${base}/api/tokens?catalog=1&token=not-forwarded&target=https://example.com`, { headers: auth });
    assert.equal(tokens.status, 200);
    assert.equal(tokens.headers.get("cache-control"), "no-store");
    const create = await fetch(`${base}/api/tokens`, {
      method: "POST", body: JSON.stringify({ owner_id: "test", name: "client" }),
      headers: { ...auth, "Idempotency-Key": requestId, "Content-Type": "application/json" },
    });
    assert.equal(create.status, 429);
    assert.equal(create.headers.get("retry-after"), "7");
    assert.deepEqual(called, [
      { url: "/admin/tokens?catalog=1", idempotency: undefined },
      { url: "/admin/tokens", idempotency: requestId },
    ]);

    const clients = new BlockList();
    clients.addSubnet("192.168.50.0", 24);
    const authority = "192.168.50.20:8788";
    lanServer = createServer(createAdminApp(settings, { authority, clients }));
    const lanBase = `http://127.0.0.1:${await listen(lanServer)}`;
    const status = (route: string, headers: Record<string, string>) => new Promise<number | undefined>((resolve, reject) => {
      get(lanBase + route, { headers }, (response) => {
        response.resume();
        resolve(response.statusCode);
      }).on("error", reject);
    });
    const host = { Host: authority };
    assert.equal(await status("/", host), 403);
    clients.addAddress("127.0.0.1");
    assert.equal(await status("/", { Host: "untrusted.example" }), 403);
    assert.equal(await status("/", { ...host, Origin: `http://${authority}` }), 403);
    assert.equal(await status("/", { ...host, Origin: `https://${authority}` }), 200);
    assert.equal(await status("/api/keys", host), 401);
  } finally {
    if (lanServer) await close(lanServer);
    if (server) await close(server);
    await close(upstream);
    await rm(temp, { recursive: true, force: true });
  }
});
