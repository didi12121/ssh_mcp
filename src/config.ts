import { readFile } from "node:fs/promises";
import { BlockList } from "node:net";
import path from "node:path";
import { parseDocument } from "yaml";
import { z } from "zod";

const safeId = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;
const safeHost = /^(?!-)[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$/;
const safeUser = /^(?!-)[A-Za-z_][A-Za-z0-9._-]{0,63}$/;
const placeholder = /^\{([A-Za-z][A-Za-z0-9_]*)\}$/;

const parameterSchema = z.object({
  description: z.string().max(300).default(""),
  pattern: z.string().min(1).max(256),
  required: z.boolean().default(true),
  maxLength: z.number().int().min(1).max(1024).default(128),
}).strict();

const operationSchema = z.object({
  description: z.string().min(1).max(500),
  command: z.array(z.string().min(1).max(1024)).min(1).max(64),
  readOnly: z.literal(true),
  timeoutSeconds: z.number().int().min(1).max(300).optional(),
  parameters: z.record(z.string().regex(safeId), parameterSchema).default({}),
}).strict();

const hostSchema = z.object({
  address: z.string().regex(safeHost, "invalid SSH hostname or IP address"),
  port: z.number().int().min(1).max(65535).default(22),
  user: z.string().regex(safeUser, "invalid SSH username"),
  description: z.string().max(500).default(""),
  tags: z.array(z.string().min(1).max(64)).max(32).default([]),
  enabled: z.boolean().default(true),
  identityFile: z.string().min(1).optional(),
  identityKey: z.string().regex(safeId).optional(),
  operations: z.array(z.string().regex(safeId)).min(1),
}).strict();

const adminLanSchema = z.object({
  address: z.ipv4(),
  subnet: z.cidrv4(),
  port: z.number().int().min(1).max(65535).optional(),
  certFile: z.string().min(1),
  keyFile: z.string().min(1),
}).strict().refine(({ address, subnet }) => {
  const [network, mask] = subnet.split("/") as [string, string];
  const prefix = Number(mask);
  const [first, second = 0] = network.split(".").map(Number);
  const privatePrefix = first === 10 ? 8 : first === 172 && second >= 16 && second <= 31 ? 12
    : first === 192 && second === 168 ? 16 : undefined;
  if (privatePrefix === undefined || prefix < privatePrefix) return false;
  const clients = new BlockList();
  clients.addSubnet(network, prefix, "ipv4");
  return clients.check(address, "ipv4");
}, "LAN admin requires a private IPv4 address within its private client subnet");

const configSchema = z.object({
  version: z.literal(1),
  ssh: z.object({
    executable: z.string().min(1).default("ssh"),
    executableArgs: z.array(z.string()).max(16).default([]),
    sshAddExecutable: z.string().min(1).default("ssh-add"),
    knownHostsFile: z.string().min(1),
    connectTimeoutSeconds: z.number().int().min(1).max(60).default(10),
    commandTimeoutSeconds: z.number().int().min(1).max(300).default(30),
    maxOutputBytes: z.number().int().min(1024).max(4 * 1024 * 1024).default(65536),
  }).strict(),
  audit: z.object({
    file: z.string().min(1).default(".data/audit.jsonl"),
  }).strict().default({ file: ".data/audit.jsonl" }),
  keys: z.object({
    directory: z.string().min(1).default(".data/keys"),
    sshKeygenExecutable: z.string().min(1).default("ssh-keygen"),
  }).strict().optional(),
  admin: z.object({
    port: z.number().int().min(1).max(65535).default(8788),
    tokenFile: z.string().min(1).default(".data/admin-token"),
    terminalAdminPort: z.number().int().min(1).max(65535).optional(),
    lan: adminLanSchema.optional(),
  }).strict().optional(),
  http: z.object({
    host: z.string().min(1).default("127.0.0.1"),
    port: z.number().int().min(1).max(65535).default(8787),
    allowedHosts: z.array(z.string().min(1).max(253)).min(1),
    tokenStoreFile: z.string().min(1).default(".data/tokens.json"),
    maxRequestsPerMinute: z.number().int().min(1).max(6000).default(120),
    sessionIdleMinutes: z.number().int().min(1).max(1440).default(60),
    maxSessions: z.number().int().min(1).max(1000).default(100),
  }).strict().optional(),
  hosts: z.record(z.string().regex(safeId), hostSchema),
  operations: z.record(z.string().regex(safeId), operationSchema),
}).strict();

export type Config = z.infer<typeof configSchema>;
export type Host = Config["hosts"][string];
export type Operation = Config["operations"][string];

function resolveConfiguredPath(value: string, baseDir: string): string {
  return path.isAbsolute(value) ? path.normalize(value) : path.resolve(baseDir, value);
}

function validateReferences(config: Config): void {
  if (Object.keys(config.hosts).length === 0) throw new Error("hosts must contain at least one host");
  if (Object.keys(config.operations).length === 0) throw new Error("operations must contain at least one operation");

  for (const [hostId, host] of Object.entries(config.hosts)) {
    for (const operationId of host.operations) {
      if (!config.operations[operationId]) {
        throw new Error(`host '${hostId}' references unknown operation '${operationId}'`);
      }
    }
  }

  for (const [operationId, operation] of Object.entries(config.operations)) {
    const used = new Set<string>();
    for (const token of operation.command) {
      const match = placeholder.exec(token);
      if (match?.[1]) used.add(match[1]);
      else if (token.includes("{") || token.includes("}")) {
        throw new Error(`operation '${operationId}' must use placeholders as complete command arguments`);
      }
    }
    for (const name of used) {
      if (!operation.parameters[name]) {
        throw new Error(`operation '${operationId}' uses undefined parameter '${name}'`);
      }
    }
    for (const name of Object.keys(operation.parameters)) {
      if (!used.has(name)) throw new Error(`operation '${operationId}' defines unused parameter '${name}'`);
    }
  }
}

export async function loadConfig(configPath: string): Promise<Config> {
  const absoluteConfigPath = path.resolve(configPath);
  const source = await readFile(absoluteConfigPath, "utf8");
  const document = parseDocument(source, { uniqueKeys: true });
  if (document.errors.length > 0) {
    throw new Error(`invalid YAML: ${document.errors.map((error) => error.message).join("; ")}`);
  }
  const config = configSchema.parse(document.toJS());
  const baseDir = path.dirname(absoluteConfigPath);
  config.ssh.knownHostsFile = resolveConfiguredPath(config.ssh.knownHostsFile, baseDir);
  config.audit.file = resolveConfiguredPath(config.audit.file, baseDir);
  if (config.keys) config.keys.directory = resolveConfiguredPath(config.keys.directory, baseDir);
  if (config.admin) {
    if (!config.keys) throw new Error("admin requires a keys section");
    config.admin.tokenFile = resolveConfiguredPath(config.admin.tokenFile, baseDir);
    if (config.admin.lan) {
      config.admin.lan.certFile = resolveConfiguredPath(config.admin.lan.certFile, baseDir);
      config.admin.lan.keyFile = resolveConfiguredPath(config.admin.lan.keyFile, baseDir);
    }
  }
  if (config.http) config.http.tokenStoreFile = resolveConfiguredPath(config.http.tokenStoreFile, baseDir);
  for (const host of Object.values(config.hosts)) {
    if (host.identityKey && (!config.keys || host.identityFile)) {
      throw new Error("identityKey requires a keys section and cannot be combined with identityFile");
    }
    if (host.identityFile) {
      if (!path.isAbsolute(host.identityFile)) throw new Error("identityFile must be an absolute path outside the project configuration");
      host.identityFile = path.normalize(host.identityFile);
    }
  }
  validateReferences(config);
  return config;
}

export function renderOperation(operation: Operation, values: Record<string, string>): string[] {
  const allowedNames = new Set(Object.keys(operation.parameters));
  for (const name of Object.keys(values)) {
    if (!allowedNames.has(name)) throw new Error(`unknown parameter '${name}'`);
  }
  for (const [name, spec] of Object.entries(operation.parameters)) {
    const value = values[name];
    if (value === undefined) {
      if (spec.required) throw new Error(`missing required parameter '${name}'`);
      continue;
    }
    if (value.length > spec.maxLength) throw new Error(`parameter '${name}' is too long`);
    let expression: RegExp;
    try {
      expression = new RegExp(`^(?:${spec.pattern})$`, "u");
    } catch {
      throw new Error(`parameter '${name}' has an invalid configured pattern`);
    }
    if (!expression.test(value)) throw new Error(`parameter '${name}' does not match its allowed pattern`);
  }

  return operation.command.flatMap((token) => {
    const match = placeholder.exec(token);
    if (!match?.[1]) return [token];
    const value = values[match[1]];
    return value === undefined ? [] : [value];
  });
}
