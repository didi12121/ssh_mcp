import { stat } from "node:fs/promises";
import path from "node:path";
import type { Config, Host } from "./config.js";
import { runProcess, type ProcessResult } from "./process.js";

export function quotePosixArgument(value: string): string {
  if (value.includes("\0") || value.includes("\n") || value.includes("\r")) {
    throw new Error("remote command arguments cannot contain NUL or line breaks");
  }
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

export function buildSshInvocation(config: Config, host: Host, command: string[]): { executable: string; args: string[] } {
  if (command.length === 0) throw new Error("remote command cannot be empty");
  const args = [
    ...config.ssh.executableArgs,
    "-F", "none",
    "-T",
    "-o", "BatchMode=yes",
    "-o", "NumberOfPasswordPrompts=0",
    "-o", "PasswordAuthentication=no",
    "-o", "KbdInteractiveAuthentication=no",
    "-o", "StrictHostKeyChecking=yes",
    "-o", `UserKnownHostsFile=${config.ssh.knownHostsFile}`,
    "-o", `ConnectTimeout=${config.ssh.connectTimeoutSeconds}`,
    "-o", "ServerAliveInterval=5",
    "-o", "ServerAliveCountMax=1",
    "-o", "ClearAllForwardings=yes",
    "-o", "ForwardAgent=no",
    "-p", String(host.port),
  ];
  if (host.identityKey) {
    args.push("-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes", "-i",
      path.join(config.keys!.directory, host.identityKey, "identity"));
  } else if (host.identityFile) {
    args.push("-o", "IdentitiesOnly=yes", "-i", host.identityFile);
  }
  args.push("--", `${host.user}@${host.address}`, command.map(quotePosixArgument).join(" "));
  return { executable: config.ssh.executable, args };
}

export async function runSsh(
  config: Config,
  host: Host,
  command: string[],
  timeoutSeconds: number,
  signal?: AbortSignal,
): Promise<ProcessResult> {
  if (host.identityKey) {
    const key = await stat(path.join(config.keys!.directory, host.identityKey, "identity")).catch(() => undefined);
    if (!key?.isFile()) throw new Error("configured managed private key is unavailable");
  }
  const invocation = buildSshInvocation(config, host, command);
  return runProcess(invocation.executable, invocation.args, {
    timeoutMs: timeoutSeconds * 1000,
    maxOutputBytes: config.ssh.maxOutputBytes,
    ...(signal ? { signal } : {}),
  });
}
