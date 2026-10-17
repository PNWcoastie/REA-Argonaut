import { z } from "zod";
import type { ProviderIdentity } from "../../application/AnalysisProvider.js";

/** Provider identity committed by the ArgonZeroG closed-loop Rust parity verifier. */
export const RUST_PARITY_PROVIDER_IDENTITY: ProviderIdentity = Object.freeze({
  id: "argon-rust-parity",
  name: "ArgonZeroG Closed-Loop Rust Parity Verifier",
  version: "1.0.0",
});

export const rustParityScalarTypeSchema = z
  .enum([
    "i8",
    "u8",
    "i16",
    "u16",
    "i32",
    "u32",
    "i64",
    "u64",
    "f32",
    "f64",
    "f32_finite",
    "f64_finite",
    "bool",
    "bytes",
  ])
  .describe(
    "Scalar or byte-slice ('bytes': (*const u8, usize) in C ABI <-> &[u8] in Safe Rust; 'f32_finite'/'f64_finite': finite normal/subnormal IEEE-754 floats for DSP/numerical kernels) type for FFI differential property testing.",
  );

export type RustParityScalarType = z.infer<typeof rustParityScalarTypeSchema>;

export const rustParityHarnessModeSchema = z
  .enum(["native-rustc", "cargo-proptest"])
  .default("native-rustc")
  .describe(
    "Execution harness mode: 'native-rustc' (default zero-network fast path using stdlib FFI dlopen + SplitMix64 + binary-search shrinker) or 'cargo-proptest' (Cargo workspace harness).",
  );

export type RustParityHarnessMode = z.infer<typeof rustParityHarnessModeSchema>;

export const verifyRustParityInputSchema = z
  .object({
    target_binary_path: z
      .string()
      .min(1)
      .optional()
      .describe(
        "Optional absolute path to a compiled C/C++ shared library (.so, .dylib, .dll) or object/binary exporting symbol_name.",
      ),
    c_source_code: z
      .string()
      .min(1)
      .optional()
      .describe(
        "Optional C reference source code to compile into a shared library when verifying a decompiled or standalone C function.",
      ),
    symbol_name: z
      .string()
      .min(1)
      .describe(
        "Exported C ABI symbol name to test (e.g., 'compute_packet_crc32c').",
      ),
    rust_source_code: z
      .string()
      .min(1)
      .describe(
        "Candidate safe Rust source code defining pub fn <rust_fn_name>(...) or pub extern \"C\" fn <rust_fn_name>(...).",
      ),
    rust_fn_name: z
      .string()
      .min(1)
      .optional()
      .describe(
        "Rust function identifier in rust_source_code to invoke (defaults to symbol_name).",
      ),
    arg_types: z
      .array(rustParityScalarTypeSchema)
      .min(1)
      .max(16)
      .describe(
        "Ordered list of C ABI parameter types accepted by both the C symbol and Rust function (1 to 16 arguments; 'bytes' passes (*const u8, usize) to C and &[u8] to Rust).",
      ),
    return_type: rustParityScalarTypeSchema.describe(
      "Scalar C ABI return type produced by both the C symbol and Rust function.",
    ),
    iterations: z
      .number()
      .int()
      .min(10)
      .max(1_000_000)
      .default(10_000)
      .describe(
        "Number of randomized FFI property-testing iterations to execute in addition to deterministic boundary cases (default 10000).",
      ),
    seed: z
      .number()
      .int()
      .nonnegative()
      .default(1337420)
      .describe(
        "Deterministic 64-bit PRNG seed for reproducible differential fuzzing.",
      ),
    float_ulp_tolerance: z
      .number()
      .int()
      .nonnegative()
      .max(1024)
      .default(0)
      .describe(
        "Maximum allowed IEEE-754 ULP (Units in the Last Place) distance for f32/f64 return values (default 0 for strict bit-exact equivalence).",
      ),
    timeout_ms: z
      .number()
      .int()
      .min(1000)
      .max(120_000)
      .default(20_000)
      .describe(
        "Hard wall-clock timeout in milliseconds for sandboxed execution (default 20000).",
      ),
    forbid_unsafe: z
      .boolean()
      .default(true)
      .describe(
        "Whether to enforce #![forbid(unsafe_code)] at compile time on the candidate Rust module (default true; set to false only when intentionally testing candidate code that uses unsafe).",
      ),
    scaffold_output_dir: z
      .string()
      .min(1)
      .optional()
      .describe(
        "Optional directory path where a pure standalone verified #![forbid(unsafe_code)] Rust Cargo crate (Cargo.toml, src/lib.rs, tests/parity_regression.rs) will be scaffolded without HTML clutter when status === 'verified_bit_exact'.",
      ),
    html_report_path: z
      .string()
      .min(1)
      .optional()
      .describe(
        "Optional file path to write an Antigravity generative_ui-compliant HTML parity report when status === 'verified_bit_exact'.",
      ),
    harness_mode: rustParityHarnessModeSchema,
  })
  .strict();

export type VerifyRustParityInput = z.infer<typeof verifyRustParityInputSchema>;

export const rustParityCounterexampleSchema = z
  .object({
    failing_iteration: z
      .number()
      .int()
      .nonnegative()
      .describe("0-based index of the first failing test case."),
    original_inputs: z
      .array(z.string())
      .describe(
        "Original failing argument values before counterexample shrinking.",
      ),
    shrunk_inputs: z
      .array(z.string())
      .describe(
        "Minimal failing argument values after binary-search counterexample shrinking.",
      ),
    shrink_steps: z
      .number()
      .int()
      .nonnegative()
      .describe(
        "Number of successful shrinking reductions applied to isolate the minimal counterexample.",
      ),
    c_output: z
      .string()
      .describe("Formatted return value from the C reference symbol."),
    rust_output: z
      .string()
      .describe("Formatted return value from the candidate Rust function."),
    c_output_hex: z
      .string()
      .describe("Raw bit-level hexadecimal representation of the C return value."),
    rust_output_hex: z
      .string()
      .describe(
        "Raw bit-level hexadecimal representation of the Rust return value.",
      ),
    bit_diff_summary: z
      .string()
      .describe(
        "Human- and agent-readable diagnosis of the bit/value divergence (XOR mask, differing bits, or sign/exponent/mantissa mismatch).",
      ),
    ulp_distance: z
      .number()
      .int()
      .nonnegative()
      .nullable()
      .describe(
        "Exact ULP distance for floating-point return types, or null for integer/boolean types.",
      ),
  })
  .strict();

export type RustParityCounterexample = z.infer<
  typeof rustParityCounterexampleSchema
>;

export const rustParityMemorySafetySchema = z
  .object({
    forbid_unsafe_enforced: z
      .boolean()
      .describe(
        "True when #![forbid(unsafe_code)] was enforced at compile time on the candidate Rust module.",
      ),
    candidate_unsafe_blocks: z
      .number()
      .int()
      .nonnegative()
      .describe(
        "Count of unsafe blocks or unsafe fn declarations found in the candidate Rust source (0 for 100% Safe Rust).",
      ),
  })
  .strict();

export type RustParityMemorySafety = z.infer<
  typeof rustParityMemorySafetySchema
>;

export const rustParityBenchmarkTelemetrySchema = z
  .object({
    benchmark_iterations: z
      .number()
      .int()
      .nonnegative()
      .describe("Number of in-process micro-benchmark iterations executed per implementation."),
    c_oracle_total_ns: z
      .number()
      .nonnegative()
      .describe("Total nanoseconds elapsed calling the compiled C symbol across benchmark_iterations."),
    safe_rust_total_ns: z
      .number()
      .nonnegative()
      .describe("Total nanoseconds elapsed calling the candidate Safe Rust function across benchmark_iterations."),
    c_oracle_ns_per_call: z
      .number()
      .nonnegative()
      .describe("Average nanoseconds per call for the C reference symbol."),
    safe_rust_ns_per_call: z
      .number()
      .nonnegative()
      .describe("Average nanoseconds per call for the Safe Rust implementation."),
    speedup_vs_c_oracle: z
      .number()
      .nonnegative()
      .describe("Speedup ratio of Safe Rust vs. C oracle (c_oracle_total_ns / safe_rust_total_ns)."),
  })
  .strict();

export type RustParityBenchmarkTelemetry = z.infer<
  typeof rustParityBenchmarkTelemetrySchema
>;

export const rustParitySandboxTelemetrySchema = z
  .object({
    os_platform: z
      .enum(["linux", "darwin", "win32", "other"])
      .describe("Host operating system platform."),
    isolation_backend: z
      .string()
      .min(1)
      .describe(
        "Active OS sandbox backend (e.g., 'linux-bwrap+prlimit', 'linux-prlimit', 'darwin-sandbox-exec', 'win32-job-object').",
      ),
    cpu_limit_seconds: z
      .number()
      .int()
      .positive()
      .describe("CPU time limit enforced on the sandboxed target process."),
    memory_limit_mb: z
      .number()
      .int()
      .positive()
      .describe("Address-space memory cap in MiB enforced on the sandboxed target process."),
    wall_time_ms: z
      .number()
      .nonnegative()
      .describe("Total wall-clock execution duration in milliseconds."),
    exit_code: z
      .number()
      .int()
      .nullable()
      .describe("Process exit code of the sandboxed harness, or null if killed by signal."),
    signal: z
      .string()
      .nullable()
      .describe("Termination signal name (e.g., 'SIGSEGV', 'SIGKILL') if faulted/killed, else null."),
    timed_out: z
      .boolean()
      .describe("True if the harness exceeded timeout_ms and was terminated."),
    compiler_diagnostics: z
      .string()
      .nullable()
      .describe("Compiler stderr output when status is 'compile_error', else null."),
  })
  .strict();

export type RustParitySandboxTelemetry = z.infer<
  typeof rustParitySandboxTelemetrySchema
>;

export const rustParityScaffoldedCrateSchema = z
  .object({
    output_dir: z
      .string()
      .min(1)
      .describe("Absolute directory path of the scaffolded verified Safe Rust Cargo crate."),
    cargo_toml_path: z
      .string()
      .min(1)
      .describe("Absolute path to Cargo.toml."),
    lib_rs_path: z
      .string()
      .min(1)
      .describe("Absolute path to src/lib.rs."),
    regression_test_path: z
      .string()
      .min(1)
      .describe("Absolute path to tests/parity_regression.rs."),
    dashboard_html_path: z
      .string()
      .min(1)
      .nullable()
      .default(null)
      .describe(
        "Absolute path to the optional Antigravity generative_ui-compliant HTML parity report when html_report_path is provided, or null when omitted.",
      ),
  })
  .strict();

export type RustParityScaffoldedCrate = z.infer<
  typeof rustParityScaffoldedCrateSchema
>;

export const rustParityReportSchema = z
  .object({
    status: z
      .enum([
        "verified_bit_exact",
        "diverged",
        "sandbox_fault",
        "compile_error",
      ])
      .describe("Overall verification verdict."),
    symbol_name: z.string().min(1),
    rust_fn_name: z.string().min(1),
    harness_mode: rustParityHarnessModeSchema,
    arg_types: z.array(rustParityScalarTypeSchema),
    return_type: rustParityScalarTypeSchema,
    iterations_requested: z.number().int().nonnegative(),
    iterations_completed: z.number().int().nonnegative(),
    boundary_cases_tested: z.number().int().nonnegative(),
    seed: z.number().int().nonnegative(),
    float_ulp_tolerance: z.number().int().nonnegative(),
    counterexample: rustParityCounterexampleSchema.nullable(),
    memory_safety: rustParityMemorySafetySchema,
    benchmark_telemetry: rustParityBenchmarkTelemetrySchema.nullable(),
    sandbox_telemetry: rustParitySandboxTelemetrySchema,
    scaffolded_crate: rustParityScaffoldedCrateSchema.nullable().default(null),
  })
  .strict();

export type RustParityReport = z.infer<typeof rustParityReportSchema>;
