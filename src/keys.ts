import { lstat, mkdir, mkdtemp, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { z } from "zod";
import type { Config } from "./config.js";
import { runProcess } from "./process.js";

export const keyId = z.string().regex(/^[A-Za-z][A-Za-z0-9_-]{0,63}$/u);
export const keyInput = z.object({
  id: keyId,
  label: z.string().trim().max(100).default(""),
  kind: z.enum(["public", "private"]),
  material: z.string().trim().min(1).max(32768),
}).strict();

export const keyGenerationInput = keyInput.pick({ id: true, label: true }).extend({
  algorithm: z.enum(["ed25519", "rsa-3072", "rsa-4096", "ecdsa-p256"]).default("ed25519"),
});

const generationArgs: Record<z.infer<typeof keyGenerationInput>["algorithm"], string[]> = {
  ed25519: ["-t", "ed25519"],
  "rsa-3072": ["-t", "rsa", "-b", "3072"],
  "rsa-4096": ["-t", "rsa", "-b", "4096"],
  "ecdsa-p256": ["-t", "ecdsa", "-b", "256"],
};

const metadata = z.object({
  id: keyId,
  label: z.string(),
  kind: keyInput.shape.kind,
  algorithm: z.string(),
  fingerprint: z.string(),
  publicKey: z.string(),
  importedAt: z.string(),
});

type KeyRecord = z.infer<typeof metadata>;
type KeyConfig = NonNullable<Config["keys"]>;

export class KeyError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

function missing(error: unknown): boolean {
  return (error as NodeJS.ErrnoException).code === "ENOENT";
}

async function prepareDirectory(directory: string): Promise<void> {
  await mkdir(directory, { mode: 0o700, recursive: true });
  const entry = await lstat(directory);
  if (!entry.isDirectory() || (process.getuid && (entry.uid !== process.getuid() || (entry.mode & 0o077) !== 0))) {
    throw new Error("key directory must be owned by the service user with mode 0700");
  }
}

export async function listKeys(config: KeyConfig): Promise<KeyRecord[]> {
  await prepareDirectory(config.directory);
  const entries = await readdir(config.directory, { withFileTypes: true });
  const records = await Promise.all(entries.filter((entry) => entry.isDirectory() && keyId.safeParse(entry.name).success)
    .map(async (entry) => {
      try {
        return await readKey(config, entry.name);
      } catch (error) {
        if (!(error instanceof KeyError) || error.status !== 404) throw error;
        return undefined;
      }
    }));
  return records.flatMap((record) => record ? [record] : []).sort((a, b) => b.importedAt.localeCompare(a.importedAt));
}

export async function readKey(config: KeyConfig, id: string): Promise<KeyRecord> {
  try {
    const content = await readFile(path.join(config.directory, id, "key.json"), "utf8");
    return metadata.parse(JSON.parse(content));
  } catch (error) {
    if (missing(error)) throw new KeyError(404, "Key not found.");
    throw error;
  }
}

function keygen(config: KeyConfig, args: string[], timeoutMs = 5000) {
  return runProcess(config.sshKeygenExecutable, args, { timeoutMs, maxOutputBytes: 32768 });
}

type KeyDetails = Pick<KeyRecord, "id" | "label" | "kind">;

async function saveKey(
  config: KeyConfig,
  data: KeyDetails,
  preparePublicKey: (identity: string) => Promise<string>,
): Promise<KeyRecord> {
  if (data.kind === "private" && process.platform === "win32") {
    throw new KeyError(400, "Private key storage is supported on Linux and other POSIX hosts.");
  }
  await prepareDirectory(config.directory);
  const destination = path.join(config.directory, data.id);
  const existing = await lstat(destination).catch((error) => {
    if (!missing(error)) throw error;
    return undefined;
  });
  if (existing) throw new KeyError(409, "This key ID already exists.");
  const temporary = await mkdtemp(path.join(config.directory, ".key-"));
  try {
    const publicKey = await preparePublicKey(path.join(temporary, "identity"));
    const match = /^((?:ssh-|ecdsa-|sk-)[A-Za-z0-9@._+-]+)[ \t]+([A-Za-z0-9+/]+={0,2})(?:[ \t]+[^\p{Cc}]*)?$/u.exec(publicKey);
    if (!match || /[\r\n]/u.test(publicKey)) {
      throw new KeyError(400, "Expected one OpenSSH public key line.");
    }
    const publicFile = path.join(temporary, "identity.pub");
    await writeFile(publicFile, `${publicKey}\n`, { mode: 0o600 });
    const inspected = await keygen(config, ["-l", "-E", "sha256", "-f", publicFile]);
    const fingerprint = /^\d+\s+(SHA256:[A-Za-z0-9+/]+)/u.exec(inspected.stdout)?.[1];
    if (inspected.exitCode !== 0 || !fingerprint) throw new KeyError(400, "Invalid SSH public key.");
    const record: KeyRecord = {
      id: data.id,
      label: data.label,
      kind: data.kind,
      algorithm: match[1]!,
      fingerprint,
      publicKey,
      importedAt: new Date().toISOString(),
    };
    await writeFile(path.join(temporary, "key.json"), JSON.stringify(record), { mode: 0o600, flag: "wx" });
    try {
      await rename(temporary, destination);
    } catch (error) {
      const existing = await lstat(destination).catch(() => undefined);
      if (existing) throw new KeyError(409, "This key ID already exists.");
      throw error;
    }
    return record;
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

export function importKey(config: KeyConfig, data: z.infer<typeof keyInput>): Promise<KeyRecord> {
  return saveKey(config, data, async (identity) => {
    const material = data.material.replaceAll("\r\n", "\n");
    if (data.kind === "public") return material;
    await writeFile(identity, `${material}\n`, { mode: 0o600, flag: "wx" });
    const derived = await keygen(config, ["-y", "-P", "", "-f", identity]);
    if (derived.exitCode !== 0 || derived.truncated) {
      throw new KeyError(400, "Expected a valid SSH private key without a passphrase.");
    }
    return derived.stdout.trim();
  });
}

export function generateKey(config: KeyConfig, data: z.infer<typeof keyGenerationInput>): Promise<KeyRecord> {
  return saveKey(config, { ...data, kind: "private" }, async (identity) => {
    const generated = await keygen(config, [
      "-q", ...generationArgs[data.algorithm], "-N", "", "-C", data.id, "-f", identity,
    ], 30000);
    if (generated.exitCode !== 0 || generated.timedOut) {
      throw new KeyError(422, "SSH key generation failed.");
    }
    return (await readFile(`${identity}.pub`, "utf8")).trim();
  });
}

export async function removeKey(config: Config, id: string): Promise<void> {
  if (Object.values(config.hosts).some((host) => host.identityKey === id)) {
    throw new KeyError(409, "Remove this key from the host configuration and restart the service first.");
  }
  const directory = config.keys!.directory;
  await prepareDirectory(directory);
  const temporary = await mkdtemp(path.join(directory, ".remove-"));
  try {
    await rename(path.join(directory, id), path.join(temporary, "key"));
  } catch (error) {
    if (missing(error)) throw new KeyError(404, "Key not found.");
    throw error;
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}
