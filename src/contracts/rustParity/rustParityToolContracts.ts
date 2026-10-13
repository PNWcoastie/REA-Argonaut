import {
  rustParityReportSchema,
  verifyRustParityInputSchema,
} from "../../domain/rustParity/rustParity.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Closed-loop FFI differential parity verification for reconstructed Rust functions. */
export const RUST_PARITY_TOOL_CONTRACTS = [
  {
    name: "verify_rust_parity",
    ...toolContractMetadata("verify_rust_parity"),
    kind: "artifact-provider",
    description:
      "Compile and execute a sandboxed differential FFI property-testing harness comparing a C/C++ reference symbol (from a compiled shared library or inline C source code) against a candidate reconstructed Rust function across deterministic boundary cases and SplitMix64 randomized inputs. Automatically shrinks any failing counterexample via binary-search reduction and reports exact bit/ULP divergence and OS sandbox telemetry (bwrap/prlimit on Linux, sandbox-exec on macOS, Job Objects on Windows).",
    inputSchema: verifyRustParityInputSchema,
    outputSchema: evidenceResultOf(rustParityReportSchema),
    examples: [
      {
        title: "Verify bit-exact parity of a reconstructed Rust function against C",
        input: {
          c_source_code:
            "#include <stdint.h>\nuint32_t add_u32(uint32_t a, uint32_t b) { return a + b; }",
          symbol_name: "add_u32",
          rust_source_code:
            "pub fn add_u32(a: u32, b: u32) -> u32 { a.wrapping_add(b) }",
          arg_types: ["u32", "u32"],
          return_type: "u32",
          iterations: 10000,
          seed: 1337420,
          float_ulp_tolerance: 0,
          timeout_ms: 20000,
          harness_mode: "native-rustc",
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
