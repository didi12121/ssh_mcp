import { spawn } from "node:child_process";

export interface ProcessResult {
  exitCode: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  aborted: boolean;
  truncated: boolean;
  durationMs: number;
}

export interface ProcessOptions {
  timeoutMs: number;
  maxOutputBytes: number;
  signal?: AbortSignal;
}

export function runProcess(executable: string, args: string[], options: ProcessOptions): Promise<ProcessResult> {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const child = spawn(executable, args, {
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let capturedBytes = 0;
    let truncated = false;
    let timedOut = false;
    let aborted = false;
    let settled = false;

    const capture = (target: Buffer[], chunk: Buffer): void => {
      const remaining = options.maxOutputBytes - capturedBytes;
      if (remaining <= 0) {
        truncated = true;
        return;
      }
      if (chunk.length > remaining) {
        target.push(chunk.subarray(0, remaining));
        capturedBytes += remaining;
        truncated = true;
      } else {
        target.push(chunk);
        capturedBytes += chunk.length;
      }
    };

    child.stdout.on("data", (chunk: Buffer) => capture(stdout, chunk));
    child.stderr.on("data", (chunk: Buffer) => capture(stderr, chunk));

    const stop = (reason: "timeout" | "abort"): void => {
      if (reason === "timeout") timedOut = true;
      else aborted = true;
      child.kill();
    };
    const timer = setTimeout(() => stop("timeout"), options.timeoutMs);
    const onAbort = (): void => stop("abort");
    options.signal?.addEventListener("abort", onAbort, { once: true });

    child.once("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", onAbort);
      reject(error);
    });
    child.once("close", (exitCode) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", onAbort);
      resolve({
        exitCode,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
        timedOut,
        aborted,
        truncated,
        durationMs: Date.now() - started,
      });
    });
  });
}
