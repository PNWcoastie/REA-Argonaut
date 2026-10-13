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
    "bool",
  ])
  .describe("Scalar C ABI type for FFI differential property testing.");

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
      .max(8)
      .describe(
        "Ordered list of scalar C ABI parameter types accepted by both the C symbol and Rust function (1 to 8 arguments).",
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
    sandbox_telemetry: rustParitySandboxTelemetrySchema,
  })
  .strict();

export type RustParityReport = z.infer<typeof rustParityReportSchema>;
