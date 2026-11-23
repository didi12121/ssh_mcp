import { appendFile, mkdir } from "node:fs/promises";
import path from "node:path";

export interface AuditEvent {
  timestamp: string;
  tool: string;
  actor?: string;
  hostId?: string;
  operationId?: string;
  parameterNames?: string[];
  success: boolean;
  exitCode?: number | null;
  durationMs?: number;
  error?: string;
}

export async function writeAudit(file: string, event: AuditEvent): Promise<void> {
  await mkdir(path.dirname(file), { recursive: true });
  await appendFile(file, `${JSON.stringify(event)}\n`, { encoding: "utf8", mode: 0o600 });
}
