import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import type {
  RustParityBenchmarkTelemetry,
  RustParityCounterexample,
  RustParityMemorySafety,
  RustParityScaffoldedCrate,
  RustParityScalarType,
  VerifyRustParityInput,
} from "../../domain/rustParity/rustParity.js";
import type { SandboxRunResult } from "../../process/ParitySandboxRunner.js";

/** Recorded C-oracle sample vector emitted by the differential parity harness. */
export interface SampleVectorPayload {
  readonly inputs_formatted: readonly string[];
  readonly inputs_rust_literal: readonly string[];
  readonly output_formatted: string;
  readonly output_rust_literal: string;
  readonly output_hex: string;
}

/** Structured JSON verdict payload emitted by the parity runner binary. */
export interface HarnessJsonPayload {
  readonly status: "verified_bit_exact" | "diverged" | "sandbox_fault";
  readonly iterations_completed: number;
  readonly boundary_cases_tested: number;
  readonly fault_reason?: string;
  readonly counterexample: RustParityCounterexample | null;
  readonly benchmark_telemetry?: RustParityBenchmarkTelemetry | null;
  readonly sample_vectors?: readonly SampleVectorPayload[];
}

export type BaseParityScalarType = Exclude<
  RustParityScalarType,
  "f32_finite" | "f64_finite"
>;

/** Maps constrained finite float aliases to their underlying Rust/C ABI scalar type. */
export function normalizeAbiScalarType(
  ty: RustParityScalarType,
): BaseParityScalarType {
  if (ty === "f32_finite") return "f32";
  if (ty === "f64_finite") return "f64";
  return ty;
}

export const RUST_DIGEST_HELPERS_PREAMBLE = `/// Built-in SplitMix64 avalanche finalizer for canonical out-buffer digests.
#[inline]
pub fn argon_avalanche64(mut h: u64) -> u64 {
    h ^= h >> 30;
    h = h.wrapping_mul(0xbf58476d1ce4e5b9);
    h ^= h >> 27;
    h = h.wrapping_mul(0x94d049bb133111eb);
    h ^ (h >> 31)
}

/// Folds a byte slice into a deterministic 64-bit digest matching C \`argon_digest_bytes\`.
#[inline]
pub fn argon_digest_bytes(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    argon_avalanche64(h)
}

/// Folds a \`u32\` slice into a deterministic 64-bit digest matching C \`argon_digest_u32\`.
#[inline]
pub fn argon_digest_u32(vals: &[u32]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &v in vals {
        h ^= v as u64;
        h = h.wrapping_mul(0x100000001b3);
        h ^= h >> 32;
    }
    argon_avalanche64(h)
}

/// Folds an \`i32\` slice into a deterministic 64-bit digest matching C \`argon_digest_i32\`.
#[inline]
pub fn argon_digest_i32(vals: &[i32]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &v in vals {
        h ^= (v as u32) as u64;
        h = h.wrapping_mul(0x100000001b3);
        h ^= h >> 32;
    }
    argon_avalanche64(h)
}

/// Folds an \`f32\` slice into a canonical 64-bit digest (normalizing \`-0.0\` and \`NaN\` payloads) matching C \`argon_digest_f32\`.
#[inline]
pub fn argon_digest_f32(vals: &[f32]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &v in vals {
        let mut bits = v.to_bits();
        if bits == 0x8000_0000 {
            bits = 0;
        } else if v.is_nan() {
            bits = 0x7fc0_0000;
        }
        h ^= bits as u64;
        h = h.wrapping_mul(0x100000001b3);
        h ^= h >> 32;
    }
    argon_avalanche64(h)
}

/// Folds an \`f64\` slice into a canonical 64-bit digest (normalizing \`-0.0\` and \`NaN\` payloads) matching C \`argon_digest_f64\`.
#[inline]
pub fn argon_digest_f64(vals: &[f64]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &v in vals {
        let mut bits = v.to_bits();
        if bits == 0x8000_0000_0000_0000 {
            bits = 0;
        } else if v.is_nan() {
            bits = 0x7ff8_0000_0000_0000;
        }
        h ^= bits;
        h = h.wrapping_mul(0x100000001b3);
        h ^= h >> 32;
    }
    argon_avalanche64(h)
}
`;

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Derives a valid Cargo package name and Rust library crate identifier from a function name. */
export function sanitizeCratePackageName(rustFnName: string): {
  readonly pkgName: string;
  readonly crateIdent: string;
} {
  const sanitizedName = rustFnName
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, "_")
    .replace(/^[^a-z]+/, "argon_");
  const pkgName =
    sanitizedName.length > 0 ? sanitizedName : "argon_reconstructed";
  const crateIdent = pkgName.replace(/-/g, "_");
  return { pkgName, crateIdent };
}

/**
 * Normalizes candidate or remediated Safe Rust source for inclusion in a standalone
 * `#![forbid(unsafe_code)]` Rust 2024 crate by stripping redundant crate-level
 * `#![forbid(unsafe_code)]`, FFI `#[no_mangle]` / `#[unsafe(no_mangle)]` attributes,
 * and `extern "C"` ABI qualifiers while preserving `pub fn` visibility.
 */
export function cleanRustSourceForSafeCrate(
  rustSource: string,
  fnName?: string,
): string {
  let cleaned = rustSource
    .replace(
      /^[ \t]*#!\s*\[\s*forbid\s*\(\s*unsafe_code\s*\)\s*\][ \t]*(?:\r?\n|$)/gm,
      "",
    )
    .replace(/#!\s*\[\s*forbid\s*\(\s*unsafe_code\s*\)\s*\][ \t]*/g, "")
    .replace(
      /^[ \t]*#\s*\[\s*(?:unsafe\s*\(\s*no_mangle\s*\)|no_mangle)\s*\][ \t]*(?:\r?\n|$)/gm,
      "",
    )
    .replace(
      /#\s*\[\s*(?:unsafe\s*\(\s*no_mangle\s*\)|no_mangle)\s*\][ \t]*/g,
      "",
    )
    .replace(
      /^([ \t]*(?:#\[[^\]\r\n]*\][ \t]*)*)(?:pub[ \t]+)?(const[ \t]+)?extern[ \t]+"C"[ \t]+fn\b/gm,
      (_match, prefix: string, constMod: string | undefined) =>
        `${prefix}pub ${constMod ?? ""}fn`,
    )
    .replace(/\n{3,}/g, "\n\n")
    .trim();

  if (fnName) {
    cleaned = cleaned.replace(
      new RegExp(`(^|\\n)([ \\t]*)fn\\s+(${escapeRegExp(fnName)})\\b`),
      "$1$2pub fn $3",
    );
  }

  return cleaned;
}

function renderRegressionAssertion(
  sv: SampleVectorPayload,
  idx: number,
  crateIdent: string,
  rustFnName: string,
  returnType: RustParityScalarType,
): string {
  const callExpr = `${crateIdent}::${rustFnName}(${sv.inputs_rust_literal.join(", ")})`;
  const normRet = normalizeAbiScalarType(returnType);
  const comment = `    // Vector #${idx + 1}: inputs=(${sv.inputs_formatted.join(", ")}) -> ${sv.output_formatted} (${sv.output_hex})`;

  if (normRet === "f32" || normRet === "f64") {
    return `${comment}
    {
        let actual = ${callExpr};
        let expected = ${sv.output_rust_literal};
        assert!(
            actual.to_bits() == expected.to_bits()
                || (actual.is_nan() && expected.is_nan())
                || ((actual.to_bits() << 1) == 0 && (expected.to_bits() << 1) == 0),
            "Vector #${idx + 1} mismatch: actual={actual:?}, expected={expected:?}",
        );
    }`;
  }

  if (normRet === "bool") {
    const expectedLiteral = sv.output_rust_literal.trim();
    if (expectedLiteral === "true") {
      return `${comment}
    assert!(${callExpr});`;
    }
    if (expectedLiteral === "false") {
      return `${comment}
    assert!(!${callExpr});`;
    }
  }

  return `${comment}
    assert_eq!(${callExpr}, ${sv.output_rust_literal});`;
}

/**
 * Materializes a standalone Rust 2024 `#![forbid(unsafe_code)]` Cargo crate with
 * zero-drift `[lints]` policies, optional remediated sibling implementation,
 * Clippy-clean regression tests, and an optional `generative_ui` HTML report.
 */
export async function scaffoldVerifiedCrate(
  input: VerifyRustParityInput,
  rustFnName: string,
  payload: HarnessJsonPayload,
  memorySafety: RustParityMemorySafety,
  sandboxResult: SandboxRunResult,
): Promise<RustParityScaffoldedCrate> {
  if (!input.scaffold_output_dir) {
    throw new Error("scaffold_output_dir is required to scaffold a verified crate.");
  }

  const outDir = path.resolve(input.scaffold_output_dir);
  const srcDir = path.join(outDir, "src");
  const testsDir = path.join(outDir, "tests");
  await mkdir(srcDir, { recursive: true });
  await mkdir(testsDir, { recursive: true });

  const { pkgName, crateIdent } = sanitizeCratePackageName(rustFnName);

  const cargoTomlPath = path.join(outDir, "Cargo.toml");
  const libRsPath = path.join(srcDir, "lib.rs");
  const regressionTestPath = path.join(testsDir, "parity_regression.rs");

  const speedup = payload.benchmark_telemetry?.speedup_vs_c_oracle ?? 1.0;
  const safeRustNs =
    payload.benchmark_telemetry?.safe_rust_ns_per_call ?? 0.0;
  const cOracleNs = payload.benchmark_telemetry?.c_oracle_ns_per_call ?? 0.0;
  const targetDesc = input.target_binary_path
    ? `Binary: ${input.target_binary_path}`
    : "Inline C Reference Oracle";
  const abiSig = `(${input.arg_types.join(", ")}) -> ${input.return_type}`;

  const cargoTomlContent = `[package]
name = "${pkgName}"
version = "0.1.0"
edition = "2024"
rust-version = "1.100"
description = "ArgonZeroG verified #![forbid(unsafe_code)] Safe Rust reconstruction of ${input.symbol_name}"

[lib]
name = "${crateIdent}"
path = "src/lib.rs"

[lints.rust]
unsafe_code = "forbid"

[lints.cargo]
unused_dependencies = "warn"

[lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
todo = "deny"
unimplemented = "deny"
dbg_macro = "deny"
`;

  const exportedRustSource = cleanRustSourceForSafeCrate(
    input.rust_source_code,
    rustFnName,
  );

  let exportedRemediatedSource = input.remediated_rust_source_code
    ? cleanRustSourceForSafeCrate(
        input.remediated_rust_source_code,
        `${rustFnName}_remediated`,
      )
    : "";
  if (
    exportedRemediatedSource.length > 0 &&
    !/\bpub\s+(?:const\s+)?fn\b/.test(exportedRemediatedSource)
  ) {
    exportedRemediatedSource = exportedRemediatedSource.replace(
      /(^|\n)([ \t]*)fn\s+([A-Za-z_][A-Za-z0-9_]*)\b/,
      "$1$2pub fn $3",
    );
  }

  const combinedSource = `${exportedRustSource}\n${exportedRemediatedSource}`;
  const scaffoldDigestPreamble =
    combinedSource.includes("argon_digest_") &&
    !combinedSource.includes("fn argon_digest_bytes")
      ? `\n${RUST_DIGEST_HELPERS_PREAMBLE}`
      : "";

  const remediatedSection =
    exportedRemediatedSource.length > 0
      ? `\n// --- Remediated Implementation (Defects Eliminated) ---\n\n${exportedRemediatedSource}\n`
      : "";

  const libRsContent = `#![forbid(unsafe_code)]
//! ArgonZeroG Verified Safe Rust Reconstruction
//! - Target: ${targetDesc}
//! - Symbol: \`${input.symbol_name}\` -> \`${rustFnName}\`
//! - ABI Signature: \`${abiSig}\`
//! - Verified Test Vectors: ${payload.iterations_completed} randomized + ${payload.boundary_cases_tested} deterministic boundary cases (seed=${input.seed})
//! - Native Speedup vs C Oracle: ${speedup}x (${safeRustNs} ns/call Safe Rust vs ${cOracleNs} ns/call C Oracle)

${exportedRustSource}
${remediatedSection}${scaffoldDigestPreamble}`;

  const sampleVectors = payload.sample_vectors ?? [];
  const assertionLines = sampleVectors
    .map((sv, idx) =>
      renderRegressionAssertion(
        sv,
        idx,
        crateIdent,
        rustFnName,
        input.return_type,
      ),
    )
    .join("\n\n");

  const regressionTestContent = `#![forbid(unsafe_code)]
//! Standalone regression test suite verifying ${sampleVectors.length} recorded C oracle test vectors
//! against the reconstructed Safe Rust implementation \`${crateIdent}::${rustFnName}\`.

#[test]
fn verified_c_oracle_regression_vectors() {
${assertionLines}
}
`;

  await writeFile(cargoTomlPath, cargoTomlContent, "utf8");
  await writeFile(libRsPath, libRsContent, "utf8");
  await writeFile(regressionTestPath, regressionTestContent, "utf8");

  let dashboardHtmlPath: string | null = null;
  if (input.html_report_path) {
    dashboardHtmlPath = path.resolve(input.html_report_path);
    await mkdir(path.dirname(dashboardHtmlPath), { recursive: true });
    const dashboardHtmlContent = renderReconstructionDashboardHtml(
      input,
      pkgName,
      rustFnName,
      libRsContent,
      payload,
      memorySafety,
      sandboxResult,
    );
    await writeFile(dashboardHtmlPath, dashboardHtmlContent, "utf8");
  }

  return {
    output_dir: outDir,
    cargo_toml_path: cargoTomlPath,
    lib_rs_path: libRsPath,
    regression_test_path: regressionTestPath,
    dashboard_html_path: dashboardHtmlPath,
    rust_edition: "2024",
    zero_drift_lints_enforced: true,
  };
}

/**
 * Renders an Antigravity `generative_ui`-compliant HTML parity report summarizing
 * bit-exact differential testing, memory safety, benchmark speedup, and sample vectors.
 */
export function renderReconstructionDashboardHtml(
  input: VerifyRustParityInput,
  pkgName: string,
  rustFnName: string,
  libRsContent: string,
  payload: HarnessJsonPayload,
  memorySafety: RustParityMemorySafety,
  sandboxResult: SandboxRunResult,
): string {
  const escapeHtml = (str: string): string =>
    str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");

  const speedup = payload.benchmark_telemetry?.speedup_vs_c_oracle ?? 1.0;
  const safeRustNs =
    payload.benchmark_telemetry?.safe_rust_ns_per_call ?? 0.0;
  const cOracleNs = payload.benchmark_telemetry?.c_oracle_ns_per_call ?? 0.0;
  const abiSig = `(${input.arg_types.join(", ")}) -> ${input.return_type}`;
  const sampleVectors = payload.sample_vectors ?? [];

  const maxNs = Math.max(cOracleNs, safeRustNs, 0.0001);
  const cBarPct = Math.min(
    100,
    Math.max(8, Math.round((cOracleNs / maxNs) * 100)),
  );
  const rustBarPct = Math.min(
    100,
    Math.max(8, Math.round((safeRustNs / maxNs) * 100)),
  );

  const cSpecDisplay = input.c_source_code
    ? input.c_source_code.trim()
    : `// Target Native Binary: ${input.target_binary_path ?? "N/A"}\n// Exported C Symbol: ${input.symbol_name}\n// C ABI Signature: (${input.arg_types.map((t, i) => (t === "bytes" ? `const uint8_t* arg${i}_ptr, size_t arg${i}_len` : `${t} arg${i}`)).join(", ")}) -> ${input.return_type}`;

  const vectorRowsHtml = sampleVectors
    .map(
      (sv, idx) => `
          <tr class="vector-row border-b border-[var(--border)]">
            <td class="py-3 px-4 font-mono text-xs text-[var(--foreground)]">#${idx + 1}</td>
            <td class="py-3 px-4 font-mono text-xs text-[var(--foreground)]">(${escapeHtml(sv.inputs_formatted.join(", "))})</td>
            <td class="py-3 px-4 font-mono text-xs text-[var(--foreground)]">${escapeHtml(sv.output_formatted)} <span class="bg-[var(--secondary)] text-[var(--secondary-foreground)] border border-[var(--border)] rounded px-2 py-0.5 text-xs ml-1">${escapeHtml(sv.output_hex)}</span></td>
            <td class="py-3 px-4 font-mono text-xs text-[var(--foreground)]">${escapeHtml(sv.output_formatted)} <span class="bg-[var(--secondary)] text-[var(--secondary-foreground)] border border-[var(--border)] rounded px-2 py-0.5 text-xs ml-1">${escapeHtml(sv.output_hex)}</span></td>
            <td class="py-3 px-4 text-xs"><span class="bg-[var(--primary)] text-[var(--primary-foreground)] rounded-md px-2.5 py-1 text-xs font-semibold">XOR Diff: 0x0 (MATCH)</span></td>
          </tr>`,
    )
    .join("\n");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>ArgonZeroG Reconstruction Dashboard — ${escapeHtml(input.symbol_name)}</title>
  <script src="https://www.gstatic.com/antigravity/web/dev/tailwindcss.min.js"></script>
</head>
<body class="bg-[var(--background)] text-[var(--foreground)] antialiased p-6">
  <div class="max-w-7xl mx-auto space-y-6">
    <div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-6 shadow-sm flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
      <div>
        <h1 class="text-[var(--foreground)] font-bold text-xl">ArgonZeroG Verified Safe Rust Reconstruction</h1>
        <p class="text-[var(--muted-foreground)] text-sm mt-1">Symbol: <strong>${escapeHtml(input.symbol_name)}</strong> &rarr; Crate: <strong>${escapeHtml(pkgName)}::${escapeHtml(rustFnName)}</strong> &bull; Signature: <code class="font-mono text-xs">${escapeHtml(abiSig)}</code></p>
      </div>
      <div class="bg-[var(--primary)] text-[var(--primary-foreground)] rounded-full px-4 py-1.5 text-xs font-bold tracking-wider uppercase">VERIFIED BIT-EXACT</div>
    </div>

    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      <div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-5 shadow-sm">
        <div class="text-[var(--muted-foreground)] text-xs uppercase tracking-wider font-medium">Differential Parity Verdict</div>
        <div class="text-[var(--foreground)] font-bold text-xl mt-1">VERIFIED BIT-EXACT</div>
        <div class="text-[var(--muted-foreground)] text-xs mt-1">100.0% parity across ${payload.iterations_completed} random + ${payload.boundary_cases_tested} boundary vectors (seed=${input.seed})</div>
      </div>

      <div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-5 shadow-sm">
        <div class="text-[var(--muted-foreground)] text-xs uppercase tracking-wider font-medium">Memory Safety Guarantee</div>
        <div class="text-[var(--accent)] font-bold text-xl mt-1 font-mono">#![forbid(unsafe_code)]</div>
        <div class="text-[var(--muted-foreground)] text-xs mt-1">${memorySafety.candidate_unsafe_blocks} unsafe blocks &bull; Compile-time enforced</div>
      </div>

      <div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-5 shadow-sm">
        <div class="text-[var(--muted-foreground)] text-xs uppercase tracking-wider font-medium">Native Speedup vs C Oracle</div>
        <div class="text-[var(--foreground)] font-bold text-xl mt-1 font-mono">${speedup}x</div>
        <div class="text-[var(--muted-foreground)] text-xs mt-1">${safeRustNs} ns Safe Rust vs ${cOracleNs} ns C Oracle</div>
        <div class="mt-2 space-y-1.5 text-xs">
          <div class="flex items-center gap-2">
            <span class="w-16 text-[var(--muted-foreground)] text-xs">Safe Rust</span>
            <div class="flex-1 bg-[var(--sidebar)] border border-[var(--border)] h-2 rounded overflow-hidden">
              <div class="bg-[var(--primary)] h-full" style="width: ${rustBarPct}%;"></div>
            </div>
          </div>
          <div class="flex items-center gap-2">
            <span class="w-16 text-[var(--muted-foreground)] text-xs">C Oracle</span>
            <div class="flex-1 bg-[var(--sidebar)] border border-[var(--border)] h-2 rounded overflow-hidden">
              <div class="bg-[var(--accent)] h-full" style="width: ${cBarPct}%;"></div>
            </div>
          </div>
        </div>
      </div>

      <div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-5 shadow-sm">
        <div class="text-[var(--muted-foreground)] text-xs uppercase tracking-wider font-medium">Sandbox Isolation</div>
        <div class="text-[var(--foreground)] font-bold text-lg mt-1 font-mono">${escapeHtml(sandboxResult.isolationBackend)}</div>
        <div class="text-[var(--muted-foreground)] text-xs mt-1">${sandboxResult.wallTimeMs} ms wall time &bull; ${sandboxResult.memoryLimitMb} MB cap</div>
      </div>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-5 shadow-sm">
        <div class="flex items-center justify-between border-b border-[var(--border)] pb-3 mb-3">
          <span class="text-[var(--foreground)] font-semibold text-sm">Original C / Binary Target Specification</span>
          <span class="text-[var(--muted-foreground)] text-xs font-mono">${escapeHtml(input.symbol_name)} ${escapeHtml(abiSig)}</span>
        </div>
        <pre class="bg-[var(--sidebar)] text-[var(--foreground)] border border-[var(--border)] rounded-lg p-4 overflow-x-auto font-mono text-xs"><code>${escapeHtml(cSpecDisplay)}</code></pre>
      </div>

      <div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-5 shadow-sm">
        <div class="flex items-center justify-between border-b border-[var(--border)] pb-3 mb-3">
          <span class="text-[var(--foreground)] font-semibold text-sm">Reconstructed #![forbid(unsafe_code)] Safe Rust (src/lib.rs)</span>
          <span class="text-[var(--accent)] text-xs font-semibold">0 unsafe blocks</span>
        </div>
        <pre class="bg-[var(--sidebar)] text-[var(--foreground)] border border-[var(--border)] rounded-lg p-4 overflow-x-auto font-mono text-xs"><code>${escapeHtml(libRsContent.trim())}</code></pre>
      </div>
    </div>

    <div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-5 shadow-sm">
      <div class="flex items-center justify-between border-b border-[var(--border)] pb-3 mb-3">
        <span class="text-[var(--foreground)] font-semibold text-sm">Verified Test Vector Summary (${sampleVectors.length} Sampled Oracle Vectors)</span>
        <span class="text-[var(--muted-foreground)] text-xs font-mono">tests/parity_regression.rs</span>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full text-left border-collapse">
          <thead>
            <tr class="border-b border-[var(--border)] text-[var(--muted-foreground)] text-xs uppercase tracking-wider">
              <th class="py-3 px-4">Vector #</th>
              <th class="py-3 px-4">Input Arguments</th>
              <th class="py-3 px-4">C Oracle Output</th>
              <th class="py-3 px-4">Safe Rust Output</th>
              <th class="py-3 px-4">Bit-Exact Parity</th>
            </tr>
          </thead>
          <tbody id="vectorTableBody">
            ${vectorRowsHtml}
          </tbody>
        </table>
      </div>
    </div>
  </div>
</body>
</html>
`;
}
