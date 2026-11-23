import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import type { Config } from "./config.js";

const tokenRecordSchema = z.object({
  id: z.string().uuid(),
  name: z.string().regex(/^[A-Za-z][A-Za-z0-9_-]{0,63}$/),
  hash: z.string().regex(/^[a-f0-9]{64}$/),
  createdAt: z.string().datetime(),
  enabled: z.boolean(),
  hosts: z.array(z.string()).min(1),
  operations: z.array(z.string()).min(1),
  allowAgentKeyListing: z.boolean().default(false),
}).strict();

const tokenStoreSchema = z.object({
  version: z.literal(1),
  tokens: z.array(tokenRecordSchema),
}).strict();

export type TokenRecord = z.infer<typeof tokenRecordSchema>;
export type TokenStore = z.infer<typeof tokenStoreSchema>;

export interface CreateTokenOptions {
  hosts?: string[];
  operations?: string[];
  allowAgentKeyListing?: boolean;
}

export function hashToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

export async function loadTokenStore(file: string): Promise<TokenStore> {
  try {
    return tokenStoreSchema.parse(JSON.parse(await readFile(file, "utf8")));
  } catch (error) {
    const code = error instanceof Error && "code" in error ? (error as NodeJS.ErrnoException).code : undefined;
    if (code === "ENOENT") return { version: 1, tokens: [] };
    throw error;
  }
}

async function saveTokenStore(file: string, store: TokenStore): Promise<void> {
  await mkdir(path.dirname(file), { recursive: true });
  const temporary = `${file}.${process.pid}.${randomUUID()}.tmp`;
  await writeFile(temporary, `${JSON.stringify(store, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  await rename(temporary, file);
}

export async function createAccessToken(file: string, name: string, options: CreateTokenOptions = {}) {
  if (!/^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(name)) {
    throw new Error("token name must start with a letter and contain only letters, numbers, underscores, or hyphens");
  }
  const store = await loadTokenStore(file);
  if (store.tokens.some((record) => record.name === name && record.enabled)) {
    throw new Error(`an enabled token named '${name}' already exists`);
  }
  const token = `ssh_mcp_${randomBytes(32).toString("base64url")}`;
  const record: TokenRecord = {
    id: randomUUID(),
    name,
    hash: hashToken(token),
    createdAt: new Date().toISOString(),
    enabled: true,
    hosts: options.hosts?.length ? [...new Set(options.hosts)] : ["*"],
    operations: options.operations?.length ? [...new Set(options.operations)] : ["*"],
    allowAgentKeyListing: options.allowAgentKeyListing ?? false,
  };
  store.tokens.push(record);
  await saveTokenStore(file, store);
  return { token, record };
}

export async function revokeAccessToken(file: string, idOrName: string): Promise<TokenRecord> {
  const store = await loadTokenStore(file);
  const record = store.tokens.find((candidate) => candidate.id === idOrName || candidate.name === idOrName);
  if (!record) throw new Error(`token '${idOrName}' was not found`);
  record.enabled = false;
  await saveTokenStore(file, store);
  return record;
}

export async function authenticateToken(file: string, token: string): Promise<TokenRecord | undefined> {
  const actual = Buffer.from(hashToken(token), "hex");
  const store = await loadTokenStore(file);
  let match: TokenRecord | undefined;
  for (const record of store.tokens) {
    const expected = Buffer.from(record.hash, "hex");
    if (expected.length === actual.length && timingSafeEqual(expected, actual) && record.enabled) match = record;
  }
  return match;
}

export function filterConfigForToken(config: Config, token: TokenRecord): Config {
  const allHosts = token.hosts.includes("*");
  const allOperations = token.operations.includes("*");
  const allowedHosts = new Set(token.hosts);
  const allowedOperations = new Set(token.operations);
  const hosts = Object.fromEntries(Object.entries(config.hosts).flatMap(([id, host]) => {
    if (!allHosts && !allowedHosts.has(id)) return [];
    const operations = host.operations.filter((operation) => allOperations || allowedOperations.has(operation));
    return operations.length > 0 ? [[id, { ...host, operations }]] : [];
  }));
  const referencedOperations = new Set(Object.values(hosts).flatMap((host) => host.operations));
  const operations = Object.fromEntries(Object.entries(config.operations).filter(([id]) => referencedOperations.has(id)));
  return { ...config, hosts, operations };
}
