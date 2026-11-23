import { isIP } from "node:net";
import { z } from "zod";
import { KeyError } from "./keys.js";

const dnsName = /^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$/u;
export const keyTarget = z.object({
  address: z.string().trim().max(253).refine((value) => isIP(value) !== 0 || dnsName.test(value)),
  user: z.string().trim().regex(/^[A-Za-z_][A-Za-z0-9._-]{0,63}$/u),
  port: z.number().int().min(1).max(65535).default(22),
}).strict();

export function buildKeyInstallCommand(
  key: { id: string; publicKey: string },
  target: z.infer<typeof keyTarget>,
): string {
  const match = /^((?:ssh-|ecdsa-|sk-)[A-Za-z0-9@._+-]+)[ \t]+([A-Za-z0-9+/]+={0,2})(?:[ \t]|$)/u
    .exec(key.publicKey);
  if (!match) throw new KeyError(422, "Expected an OpenSSH public key.");
  const [, algorithm, material] = match;
  // Match key data even if the installed line already has options or a different comment.
  const regexLiteral = (value: string) => value.replace(/[.+]/gu, (char) => `[${char}]`);
  const pattern = `(^|[[:blank:]])${regexLiteral(algorithm!)}[[:blank:]]+${regexLiteral(material!)}([[:space:]]|$)`;
  const authorizedKeys = "~/.ssh/authorized_keys";
  const publicLine = `${algorithm} ${material} ssh-mcp-${key.id}`;
  const remote = [
    "umask 077; mkdir -p ~/.ssh",
    "chmod 700 ~/.ssh",
    `touch ${authorizedKeys}`,
    `chmod 600 ${authorizedKeys}`,
    `(flock -x 9 && (grep -Eq '${pattern}' ${authorizedKeys} || printf '\\n%s\\n' '${publicLine}' >> ${authorizedKeys})) 9>>~/.ssh/.ssh-mcp-install.lock`,
  ].join(" && ");
  return `ssh -p ${target.port} -l ${target.user} -- ${target.address} "${remote}"`;
}
