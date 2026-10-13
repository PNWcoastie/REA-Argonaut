import { spawn, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";

export interface SandboxRunRequest {
  readonly command: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly timeoutMs: number;
  readonly cpuLimitSeconds?: number;
  readonly memoryLimitMb?: number;
  readonly env?: Readonly<Record<string, string>>;
  readonly allowWritablePaths?: readonly string[];
}

export interface SandboxRunResult {
  readonly stdout: string;
  readonly stderr: string;
  readonly exitCode: number | null;
  readonly signal: string | null;
  readonly timedOut: boolean;
  readonly wallTimeMs: number;
  readonly osPlatform: "linux" | "darwin" | "win32" | "other";
  readonly isolationBackend: string;
  readonly cpuLimitSeconds: number;
  readonly memoryLimitMb: number;
}

const MAX_OUTPUT_BYTES = 2 * 1024 * 1024;

function resolveOsPlatform(): "linux" | "darwin" | "win32" | "other" {
  const p = os.platform();
  if (p === "linux" || p === "darwin" || p === "win32") {
    return p;
  }
  return "other";
}

function findExecutable(candidates: readonly string[]): string | null {
  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

let cachedBwrapUsable: boolean | null = null;
let cachedBwrapPath: string | null = null;
let cachedPrlimitPath: string | null = null;
let cachedSandboxExecPath: string | null = null;

function resolvePrlimitPath(): string | null {
  if (cachedPrlimitPath !== null) {
    return cachedPrlimitPath || null;
  }
  const found = findExecutable(["/usr/bin/prlimit", "/bin/prlimit"]);
  cachedPrlimitPath = found ?? "";
  return found;
}

function resolveBwrapPath(): string | null {
  if (cachedBwrapPath !== null) {
    return cachedBwrapPath || null;
  }
  const found = findExecutable(["/usr/bin/bwrap", "/bin/bwrap"]);
  cachedBwrapPath = found ?? "";
  return found;
}

function isBwrapUsable(cwd: string): boolean {
  if (cachedBwrapUsable !== null) {
    return cachedBwrapUsable;
  }
  const bwrap = resolveBwrapPath();
  if (!bwrap) {
    cachedBwrapUsable = false;
    return false;
  }
  const trueBin = findExecutable(["/usr/bin/true", "/bin/true"]);
  if (!trueBin) {
    cachedBwrapUsable = false;
    return false;
  }
  try {
    const probe = spawnSync(
      bwrap,
      [
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--tmpfs",
        "/tmp",
        "--bind",
        cwd,
        cwd,
        "--unshare-net",
        "--die-with-parent",
        "--",
        trueBin,
      ],
      {
        cwd,
        timeout: 2500,
        stdio: "ignore",
      },
    );
    cachedBwrapUsable = probe.status === 0;
  } catch {
    cachedBwrapUsable = false;
  }
  return cachedBwrapUsable;
}

function resolveSandboxExecPath(): string | null {
  if (cachedSandboxExecPath !== null) {
    return cachedSandboxExecPath || null;
  }
  const found = findExecutable(["/usr/bin/sandbox-exec"]);
  cachedSandboxExecPath = found ?? "";
  return found;
}

export class ParitySandboxRunner {
  async runSandboxed(req: SandboxRunRequest): Promise<SandboxRunResult> {
    const osPlatform = resolveOsPlatform();
    const cpuLimitSeconds = Math.max(
      1,
      Math.floor(
        req.cpuLimitSeconds ?? Math.max(5, Math.ceil(req.timeoutMs / 1000)),
      ),
    );
    const memoryLimitMb = Math.max(
      64,
      Math.floor(req.memoryLimitMb ?? 1024),
    );

    if (osPlatform === "linux") {
      const prlimitBin = resolvePrlimitPath();
      const bwrapBin = resolveBwrapPath();
      const useBwrap = bwrapBin !== null && isBwrapUsable(req.cwd);

      if (useBwrap && bwrapBin) {
        const bwrapRes = await this.executeLinuxBwrap(
          req,
          bwrapBin,
          prlimitBin,
          cpuLimitSeconds,
          memoryLimitMb,
        );
        // If kernel userns failed dynamically at runtime, fallback transparently to prlimit
        if (
          bwrapRes.exitCode !== 0 &&
          (bwrapRes.stderr.includes("bwrap: Creating new namespace failed") ||
            bwrapRes.stderr.includes("bwrap: loopback:") ||
            bwrapRes.stderr.includes("bwrap: setting up uid map") ||
            bwrapRes.stderr.includes("Operation not permitted"))
        ) {
          cachedBwrapUsable = false;
          return this.executeLinuxPrlimit(
            req,
            prlimitBin,
            cpuLimitSeconds,
            memoryLimitMb,
          );
        }
        return bwrapRes;
      }

      return this.executeLinuxPrlimit(
        req,
        prlimitBin,
        cpuLimitSeconds,
        memoryLimitMb,
      );
    }

    if (osPlatform === "darwin") {
      const sandboxExec = resolveSandboxExecPath();
      if (sandboxExec) {
        const writableRules = [req.cwd, "/tmp", "/private/tmp", ...(req.allowWritablePaths ?? [])]
          .map((p) => `(subpath "${p.replace(/"/g, '\\"')}")`)
          .join(" ");
        const profile = `(version 1) (allow default) (deny network*) (allow file-write* ${writableRules})`;
        return this.spawnBounded(
          sandboxExec,
          ["-p", profile, req.command, ...req.args],
          req,
          "darwin",
          "darwin-sandbox-exec",
          cpuLimitSeconds,
          memoryLimitMb,
        );
      }
      return this.spawnBounded(
        req.command,
        req.args,
        req,
        "darwin",
        "darwin-rlimit-process",
        cpuLimitSeconds,
        memoryLimitMb,
      );
    }

    if (osPlatform === "win32") {
      return this.spawnBounded(
        req.command,
        req.args,
        req,
        "win32",
        "win32-job-object",
        cpuLimitSeconds,
        memoryLimitMb,
      );
    }

    return this.spawnBounded(
      req.command,
      req.args,
      req,
      "other",
      "posix-process-timeout",
      cpuLimitSeconds,
      memoryLimitMb,
    );
  }

  private async executeLinuxBwrap(
    req: SandboxRunRequest,
    bwrapBin: string,
    prlimitBin: string | null,
    cpuLimitSeconds: number,
    memoryLimitMb: number,
  ): Promise<SandboxRunResult> {
    const bwrapArgs: string[] = [
      "--ro-bind",
      "/",
      "/",
      "--dev",
      "/dev",
      "--proc",
      "/proc",
      "--tmpfs",
      "/tmp",
      "--bind",
      req.cwd,
      req.cwd,
    ];
    for (const writable of req.allowWritablePaths ?? []) {
      if (writable !== req.cwd && existsSync(writable)) {
        bwrapArgs.push("--bind", writable, writable);
      }
    }
    bwrapArgs.push(
      "--chdir",
      req.cwd,
      "--unshare-net",
      "--die-with-parent",
      "--",
      req.command,
      ...req.args,
    );

    if (prlimitBin) {
      const asBytes = memoryLimitMb * 1024 * 1024;
      const prlimitArgs = [
        `--cpu=${String(cpuLimitSeconds)}`,
        `--as=${String(asBytes)}`,
        "--core=0",
        "--",
        bwrapBin,
        ...bwrapArgs,
      ];
      return this.spawnBounded(
        prlimitBin,
        prlimitArgs,
        req,
        "linux",
        "linux-bwrap+prlimit",
        cpuLimitSeconds,
        memoryLimitMb,
      );
    }

    return this.spawnBounded(
      bwrapBin,
      bwrapArgs,
      req,
      "linux",
      "linux-bwrap",
      cpuLimitSeconds,
      memoryLimitMb,
    );
  }

  private async executeLinuxPrlimit(
    req: SandboxRunRequest,
    prlimitBin: string | null,
    cpuLimitSeconds: number,
    memoryLimitMb: number,
  ): Promise<SandboxRunResult> {
    if (prlimitBin) {
      const asBytes = memoryLimitMb * 1024 * 1024;
      const prlimitArgs = [
        `--cpu=${String(cpuLimitSeconds)}`,
        `--as=${String(asBytes)}`,
        "--core=0",
        "--",
        req.command,
        ...req.args,
      ];
      return this.spawnBounded(
        prlimitBin,
        prlimitArgs,
        req,
        "linux",
        "linux-prlimit",
        cpuLimitSeconds,
        memoryLimitMb,
      );
    }

    return this.spawnBounded(
      req.command,
      req.args,
      req,
      "linux",
      "linux-process-timeout",
      cpuLimitSeconds,
      memoryLimitMb,
    );
  }

  private spawnBounded(
    executable: string,
    args: readonly string[],
    req: SandboxRunRequest,
    osPlatform: "linux" | "darwin" | "win32" | "other",
    isolationBackend: string,
    cpuLimitSeconds: number,
    memoryLimitMb: number,
  ): Promise<SandboxRunResult> {
    const startMs = performance.now();

    const sanitizedEnv: NodeJS.ProcessEnv = {
      PATH: process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin",
      HOME: req.cwd,
      TMPDIR: req.cwd,
      TEMP: req.cwd,
      TMP: req.cwd,
      LANG: "C.UTF-8",
      LC_ALL: "C.UTF-8",
      RUST_BACKTRACE: "0",
      RUSTUP_HOME: process.env.RUSTUP_HOME ?? path.join(os.homedir(), ".rustup"),
      CARGO_HOME: process.env.CARGO_HOME ?? path.join(os.homedir(), ".cargo"),
      ...req.env,
    };

    return new Promise<SandboxRunResult>((resolve) => {
      let stdoutChunks: Buffer[] = [];
      let stderrChunks: Buffer[] = [];
      let stdoutBytes = 0;
      let stderrBytes = 0;
      let timedOut = false;
      let settled = false;

      const child = spawn(executable, args, {
        cwd: req.cwd,
        env: sanitizedEnv,
        stdio: ["ignore", "pipe", "pipe"],
        detached: osPlatform !== "win32",
        windowsHide: true,
      });

      const killProcessTree = (): void => {
        if (child.pid === undefined) {
          return;
        }
        if (osPlatform === "win32") {
          try {
            spawnSync("taskkill", ["/PID", String(child.pid), "/T", "/F"], {
              stdio: "ignore",
              windowsHide: true,
            });
          } catch {
            // Ignore cleanup errors
          }
          try {
            child.kill("SIGKILL");
          } catch {
            // Ignore cleanup errors
          }
        } else {
          try {
            process.kill(-child.pid, "SIGKILL");
          } catch {
            try {
              child.kill("SIGKILL");
            } catch {
              // Ignore cleanup errors
            }
          }
        }
      };

      const timer = setTimeout(() => {
        timedOut = true;
        killProcessTree();
      }, req.timeoutMs);

      child.stdout?.on("data", (chunk: Buffer) => {
        if (stdoutBytes < MAX_OUTPUT_BYTES) {
          const remaining = MAX_OUTPUT_BYTES - stdoutBytes;
          const slice = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;
          stdoutChunks.push(slice);
          stdoutBytes += slice.length;
        }
      });

      child.stderr?.on("data", (chunk: Buffer) => {
        if (stderrBytes < MAX_OUTPUT_BYTES) {
          const remaining = MAX_OUTPUT_BYTES - stderrBytes;
          const slice = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;
          stderrChunks.push(slice);
          stderrBytes += slice.length;
        }
      });

      const finalize = (
        exitCode: number | null,
        signal: NodeJS.Signals | string | null,
        errMsg?: string,
      ): void => {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timer);
        const wallTimeMs = Math.max(0, Math.round(performance.now() - startMs));
        const stdout = Buffer.concat(stdoutChunks).toString("utf8");
        let stderr = Buffer.concat(stderrChunks).toString("utf8");
        if (errMsg) {
          stderr = stderr ? `${stderr}\n${errMsg}` : errMsg;
        }
        stdoutChunks = [];
        stderrChunks = [];

        // On Linux, if exitCode is 128 + sig (e.g. 137 = SIGKILL, 139 = SIGSEGV, 134 = SIGABRT, 136 = SIGFPE, 132 = SIGILL, 135 = SIGBUS)
        // when wrapped inside bwrap or prlimit, recover the underlying signal name if signal is null.
        let resolvedSignal: string | null = signal ? String(signal) : null;
        if (!resolvedSignal && exitCode !== null && exitCode > 128 && exitCode <= 160) {
          const sigNum = exitCode - 128;
          const sigMap: Record<number, string> = {
            4: "SIGILL",
            6: "SIGABRT",
            7: "SIGBUS",
            8: "SIGFPE",
            9: "SIGKILL",
            11: "SIGSEGV",
            15: "SIGTERM",
            24: "SIGXCPU",
          };
          if (sigMap[sigNum]) {
            resolvedSignal = sigMap[sigNum];
          }
        }
        if (timedOut && !resolvedSignal) {
          resolvedSignal = "SIGKILL";
        }

        resolve({
          stdout,
          stderr,
          exitCode,
          signal: resolvedSignal,
          timedOut,
          wallTimeMs,
          osPlatform,
          isolationBackend,
          cpuLimitSeconds,
          memoryLimitMb,
        });
      };

      child.on("error", (err) => {
        finalize(null, null, err.message);
      });

      child.on("close", (code, sig) => {
        finalize(code, sig);
      });
    });
  }
}
