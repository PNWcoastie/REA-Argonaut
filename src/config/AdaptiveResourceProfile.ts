import os from "node:os";

export interface AdaptiveResourceProfile {
  /** Number of logical CPU cores reported by the OS at runtime. */
  readonly logicalCores: number;
  /** Total system RAM in bytes reported by the OS at runtime. */
  readonly totalMemBytes: number;
  /** Optimal worker concurrency scaled dynamically to host CPU cores. */
  readonly workerConcurrency: number;
  /** Maximum JavaScript/AST files analyzed per run, scaled to host memory. */
  readonly maxAnalyzedFiles: number;
  /** Maximum AST semantic nodes retained, scaled to host memory. */
  readonly maxSemanticNodes: number;
  /** Maximum bytes per analyzed source file, scaled to host memory. */
  readonly maxSourceFileBytes: number;
  /** Maximum subgraph nodes extracted in a single batch call. */
  readonly defaultSubgraphMaxNodes: number;
}

/**
 * Compute hardware-adaptive concurrency and memory budgets at runtime.
 * Never hardcodes development-host core counts or single-OS limits.
 */
export const resolveAdaptiveResourceProfile = (): AdaptiveResourceProfile => {
  const logicalCores = Math.max(
    1,
    typeof os.availableParallelism === "function"
      ? os.availableParallelism()
      : os.cpus().length,
  );
  const totalMemBytes = Math.max(512 * 1024 * 1024, os.totalmem());
  const totalMemGiB = totalMemBytes / (1024 * 1024 * 1024);

  const workerConcurrency = Math.max(1, Math.min(logicalCores - 1, 16));
  const memScale = Math.max(1, Math.min(Math.floor(totalMemGiB / 4), 8));

  return Object.freeze({
    logicalCores,
    totalMemBytes,
    workerConcurrency,
    maxAnalyzedFiles: Math.max(1024, 512 * memScale),
    maxSemanticNodes: Math.max(500_000, 250_000 * memScale),
    maxSourceFileBytes: Math.max(4 * 1024 * 1024, 2 * 1024 * 1024 * memScale),
    defaultSubgraphMaxNodes: Math.max(64, 32 * memScale),
  });
};

export const ADAPTIVE_RESOURCE_PROFILE: AdaptiveResourceProfile =
  resolveAdaptiveResourceProfile();
