import {
  inspectRustCppBinaryInputSchema,
  rustCppBinarySchema,
} from "../../domain/rustCpp/rustCppBinary.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Static Rust & C++ metadata is independent of active native-analysis providers and host toolchains. */
export const RUST_CPP_TOOL_CONTRACTS = [
  {
    name: "inspect_rust_cpp_binary",
    ...toolContractMetadata("inspect_rust_cpp_binary"),
    kind: "artifact-provider",
    description:
      "Inspect a local ELF, Mach-O, or PE binary for Rust compiler metadata (rustc version, commit hash, crate dependencies, recovered .rs source files, core::panicking::Location records, and demangled v0/legacy Rust symbols) and C++ RTTI / vtable class layouts (Itanium and MSVC ABI typeinfo, base class hierarchies, virtual method tables, and demangled C++ symbols) in pure TypeScript without executing the target or requiring external toolchains.",
    inputSchema: inspectRustCppBinaryInputSchema,
    outputSchema: evidenceResultOf(rustCppBinarySchema),
    examples: [
      {
        title: "Inspect Rust panic locations and C++ vtables in a native binary",
        input: {
          path: "/artifacts/application",
          max_panic_locations: 500,
          max_symbols: 500,
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
