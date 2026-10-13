import { z } from "zod";
import type { ProviderIdentity } from "../../application/AnalysisProvider.js";

/** Provider identity committed by the pure-TS Rust & C++ binary forensic engine. */
export const RUST_CPP_PROVIDER_IDENTITY: ProviderIdentity = Object.freeze({
  id: "argon-rust-cpp-forensics",
  name: "ArgonZeroG Rust & C++ ABI / Panic / VTable Forensic Inspector",
  version: "1.0.0",
});

export const inspectRustCppBinaryInputSchema = z
  .object({
    path: z
      .string()
      .min(1)
      .describe(
        "Absolute filesystem path to the local ELF, Mach-O, or PE binary to inspect.",
      ),
    max_panic_locations: z
      .number()
      .int()
      .min(1)
      .max(5000)
      .default(500)
      .describe(
        "Maximum number of Rust core::panicking::Location records to return (default 500).",
      ),
    max_symbols: z
      .number()
      .int()
      .min(1)
      .max(5000)
      .default(500)
      .describe(
        "Maximum number of demangled Rust/C++ symbols to return (default 500).",
      ),
  })
  .strict();

export type InspectRustCppBinaryInput = z.infer<
  typeof inspectRustCppBinaryInputSchema
>;

export const rustPanicLocationSchema = z
  .object({
    struct_offset: z
      .number()
      .int()
      .nonnegative()
      .describe("File byte offset of the Location struct in the binary."),
    file: z
      .string()
      .min(1)
      .describe("Recovered UTF-8 .rs source file path referenced by the panic Location."),
    line: z.number().int().positive().describe("1-based source line number."),
    column: z
      .number()
      .int()
      .nonnegative()
      .describe("Source column number."),
  })
  .strict();

export type RustPanicLocation = z.infer<typeof rustPanicLocationSchema>;

export const rustCrateDependencySchema = z
  .object({
    name: z.string().min(1),
    version: z.string().nullable(),
    source_paths: z.array(z.string().min(1)),
  })
  .strict();

export type RustCrateDependency = z.infer<typeof rustCrateDependencySchema>;

export const demangledSymbolRecordSchema = z
  .object({
    address: z.string().min(1),
    mangled: z.string().min(1),
    demangled: z.string().min(1),
    encoding: z.enum(["rust-v0", "rust-legacy", "itanium-cpp", "msvc-cpp"]),
  })
  .strict();

export type DemangledSymbolRecord = z.infer<typeof demangledSymbolRecordSchema>;

export const cppClassRecordSchema = z
  .object({
    class_name: z.string().min(1),
    mangled_typeinfo: z.string().nullable(),
    base_classes: z.array(z.string().min(1)),
    vtable_address: z.string().nullable(),
    virtual_methods: z.array(
      z
        .object({
          slot: z.number().int().nonnegative(),
          address: z.string().min(1),
          symbol: z.string().nullable(),
          demangled: z.string().nullable(),
        })
        .strict(),
    ),
  })
  .strict();

export type CppClassRecord = z.infer<typeof cppClassRecordSchema>;

export const rustCppBinarySchema = z
  .object({
    artifact: z
      .object({
        path: z.string().min(1),
        sha256: z.string().regex(/^[0-9a-f]{64}$/),
        size_bytes: z.number().int().nonnegative(),
      })
      .strict(),
    format: z.enum(["elf", "macho", "pe"]),
    architecture: z.string().min(1),
    bits: z.union([z.literal(32), z.literal(64)]),
    is_stripped: z.boolean(),
    rust: z
      .object({
        detected: z.boolean(),
        rustc_version: z.string().nullable(),
        compiler_commit: z.string().nullable(),
        crates: z.array(rustCrateDependencySchema),
        recovered_source_files: z.array(z.string().min(1)),
        panic_locations: z.array(rustPanicLocationSchema),
        demangled_symbols: z.array(demangledSymbolRecordSchema),
      })
      .strict(),
    cpp: z
      .object({
        detected: z.boolean(),
        abi: z.enum(["itanium", "msvc", "none"]),
        classes: z.array(cppClassRecordSchema),
        demangled_symbols: z.array(demangledSymbolRecordSchema),
      })
      .strict(),
    limitations: z.array(z.string()),
  })
  .strict();

export type RustCppBinaryReport = z.infer<typeof rustCppBinarySchema>;
