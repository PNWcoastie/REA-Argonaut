import { z } from "incur";
import { resolve } from "node:path";
import { createRustParityService } from "../composition/rustParity.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { rustParityScalarTypeSchema } from "../domain/rustParity/rustParity.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";

/** Register closed-loop Rust FFI differential parity verification CLI command. */
export const registerRustParityCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  const service = createRustParityService();
  cli.command(CLI_COMMANDS.verifyRustParity, {
    aliases: ["verify-parity"],
    description:
      "Compile and execute a sandboxed differential FFI property-testing harness comparing a C symbol against reconstructed Rust",
    args: z.object({
      symbolName: z.string().describe("Exported C ABI symbol name to test"),
      rustSourceCode: z
        .string()
        .describe("Candidate safe Rust source code defining the function"),
    }),
    options: z.object({
      targetBinaryPath: z
        .string()
        .optional()
        .describe("Path to a compiled C/C++ shared library or object"),
      cSourceCode: z
        .string()
        .optional()
        .describe("Inline C reference source code to compile"),
      rustFnName: z
        .string()
        .optional()
        .describe("Rust function identifier (defaults to symbolName)"),
      argTypes: z
        .array(rustParityScalarTypeSchema)
        .default(["u32", "u32"])
        .describe("Ordered list of scalar C ABI parameter types"),
      returnType: rustParityScalarTypeSchema
        .default("u32")
        .describe("Scalar C ABI return type"),
      iterations: z
        .number()
        .int()
        .min(10)
        .max(1_000_000)
        .default(10_000)
        .describe("Number of randomized FFI property-testing iterations"),
      seed: z
        .number()
        .int()
        .nonnegative()
        .default(1337420)
        .describe("Deterministic 64-bit PRNG seed"),
      floatUlpTolerance: z
        .number()
        .int()
        .nonnegative()
        .max(1024)
        .default(0)
        .describe("Maximum allowed IEEE-754 ULP distance for f32/f64"),
      forbidUnsafe: z
        .boolean()
        .default(true)
        .describe(
          "Enforce #![forbid(unsafe_code)] on candidate Rust code (default: true)",
        ),
      timeoutMs: z
        .number()
        .int()
        .min(1000)
        .max(120_000)
        .default(20_000)
        .describe("Hard wall-clock timeout in milliseconds"),
      scaffoldOutputDir: z
        .string()
        .min(1)
        .optional()
        .describe(
          "Optional directory to scaffold a pure standalone verified #![forbid(unsafe_code)] Cargo crate (Cargo.toml, src/lib.rs, tests/parity_regression.rs) without HTML clutter",
        ),
      htmlReport: z
        .string()
        .min(1)
        .optional()
        .describe(
          "Optional file path to write an Antigravity generative_ui-compliant HTML parity report when status === 'verified_bit_exact'",
        ),
      harnessMode: z
        .enum(["native-rustc", "cargo-proptest"])
        .default("native-rustc")
        .describe("Execution harness mode"),
    }),
    run: ({ args, options }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, CLI_COMMANDS.verifyRustParity, async () => {
          const result = await service.verify(
            {
              ...(options.targetBinaryPath === undefined
                ? {}
                : { target_binary_path: resolve(options.targetBinaryPath) }),
              ...(options.cSourceCode === undefined
                ? {}
                : { c_source_code: options.cSourceCode }),
              symbol_name: args.symbolName,
              rust_source_code: args.rustSourceCode,
              ...(options.rustFnName === undefined
                ? {}
                : { rust_fn_name: options.rustFnName }),
              arg_types: options.argTypes,
              return_type: options.returnType,
              iterations: options.iterations,
              seed: options.seed,
              float_ulp_tolerance: options.floatUlpTolerance,
              forbid_unsafe: options.forbidUnsafe,
              timeout_ms: options.timeoutMs,
              ...(options.scaffoldOutputDir === undefined
                ? {}
                : { scaffold_output_dir: options.scaffoldOutputDir }),
              ...(options.htmlReport === undefined
                ? {}
                : { html_report_path: options.htmlReport }),
              harness_mode: options.harnessMode,
            },
            { signal },
          );
          return result.ok ? result.value : projectAnalysisError(result.error);
        }),
      ),
  });
};
