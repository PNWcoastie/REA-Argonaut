import { z } from "zod";
import type { ProviderIdentity } from "../../application/AnalysisProvider.js";

/** Provider identity committed by the pure-TS Game Engine & Bytecode Archive Inspector. */
export const ENGINE_ARCHIVE_PROVIDER_IDENTITY: ProviderIdentity = Object.freeze({
  id: "argon-engine-archive-forensics",
  name: "ArgonZeroG Game Engine & Bytecode Archive Inspector",
  version: "1.0.0",
});

export const engineArchiveFormatSchema = z
  .enum(["unity-il2cpp-metadata", "godot-pck", "electron-asar"])
  .describe("Detected game engine metadata, resource pack, or Electron ASAR archive format.");

export type EngineArchiveFormat = z.infer<typeof engineArchiveFormatSchema>;

export const inspectEngineArchiveInputSchema = z
  .object({
    path: z
      .string()
      .min(1)
      .describe(
        "Absolute filesystem path to a Unity IL2CPP global-metadata.dat binary, Godot Engine .pck archive, or Electron .asar archive.",
      ),
    max_types: z
      .number()
      .int()
      .min(1)
      .max(20_000)
      .default(1_000)
      .describe("Maximum number of C# TypeDefinitions to return for IL2CPP metadata (default 1000)."),
    max_methods: z
      .number()
      .int()
      .min(1)
      .max(50_000)
      .default(2_000)
      .describe("Maximum number of C# MethodDefinitions to return for IL2CPP metadata (default 2000)."),
    max_strings: z
      .number()
      .int()
      .min(1)
      .max(20_000)
      .default(1_000)
      .describe("Maximum number of IL2CPP string literals to return (default 1000)."),
    max_files: z
      .number()
      .int()
      .min(1)
      .max(50_000)
      .default(2_000)
      .describe("Maximum number of bundled files to return for Godot .pck or Electron .asar archives (default 2000)."),
    max_entries: z
      .number()
      .int()
      .min(1)
      .max(50_000)
      .optional()
      .describe("Optional alias for max_files: maximum number of archive entries/files to return."),
  })
  .strict();

export type InspectEngineArchiveInput = z.infer<
  typeof inspectEngineArchiveInputSchema
>;

export const il2CppTypeDescriptorSchema = z
  .object({
    type_index: z.number().int().nonnegative(),
    namespace: z.string(),
    name: z.string().min(1),
    full_name: z.string().min(1),
    is_value_type: z.boolean(),
    is_enum: z.boolean(),
    method_count: z.number().int().nonnegative(),
    field_count: z.number().int().nonnegative(),
  })
  .strict();

export type Il2CppTypeDescriptor = z.infer<typeof il2CppTypeDescriptorSchema>;

export const il2CppMethodDescriptorSchema = z
  .object({
    method_index: z.number().int().nonnegative(),
    name: z.string().min(1),
    declaring_type: z.string().min(1),
    parameter_count: z.number().int().nonnegative(),
    token: z.string().describe("Hexadecimal metadata token (e.g., '0x06000001')."),
  })
  .strict();

export type Il2CppMethodDescriptor = z.infer<
  typeof il2CppMethodDescriptorSchema
>;

export const il2CppStringLiteralSchema = z
  .object({
    index: z.number().int().nonnegative(),
    value: z.string(),
  })
  .strict();

export type Il2CppStringLiteral = z.infer<typeof il2CppStringLiteralSchema>;

export const il2CppMetadataSummarySchema = z
  .object({
    metadata_version: z.number().int().positive(),
    images: z.array(z.string()),
    total_types: z.number().int().nonnegative(),
    total_methods: z.number().int().nonnegative(),
    total_string_literals: z.number().int().nonnegative(),
    types: z.array(il2CppTypeDescriptorSchema),
    methods: z.array(il2CppMethodDescriptorSchema),
    string_literals: z.array(il2CppStringLiteralSchema),
  })
  .strict();

export type Il2CppMetadataSummary = z.infer<typeof il2CppMetadataSummarySchema>;

export const godotPackFileEntrySchema = z
  .object({
    path: z.string().min(1).describe("Resource path inside the Godot pack (e.g., 'res://scripts/auth.gd')."),
    offset: z.number().int().nonnegative(),
    size_bytes: z.number().int().nonnegative(),
    md5_hex: z.string().regex(/^[0-9a-f]{32}$/),
    encrypted: z.boolean(),
  })
  .strict();

export type GodotPackFileEntry = z.infer<typeof godotPackFileEntrySchema>;

export const godotPackSummarySchema = z
  .object({
    pack_format_version: z.number().int().nonnegative(),
    engine_version: z.string().min(1),
    flags: z.number().int().nonnegative(),
    file_base_offset: z.number().int().nonnegative(),
    file_count: z.number().int().nonnegative(),
    files: z.array(godotPackFileEntrySchema),
  })
  .strict();

export type GodotPackSummary = z.infer<typeof godotPackSummarySchema>;

export const electronAsarEntrySchema = z
  .object({
    path: z.string().min(1).describe("Virtual path inside the Electron ASAR archive (e.g., 'dist/main.js')."),
    size_bytes: z.number().int().nonnegative(),
    offset: z.number().int().nonnegative().nullable(),
    unpacked: z.boolean(),
    is_executable: z.boolean(),
    integrity_hash: z.string().nullable(),
  })
  .strict();

export type ElectronAsarEntry = z.infer<typeof electronAsarEntrySchema>;

export const electronAsarSummarySchema = z
  .object({
    header_size_bytes: z.number().int().positive(),
    total_files: z.number().int().nonnegative(),
    total_directories: z.number().int().nonnegative(),
    unpacked_files: z.number().int().nonnegative(),
    main_entry_script: z.string().nullable(),
    native_addons: z.array(z.string()),
    files: z.array(electronAsarEntrySchema),
  })
  .strict();

export type ElectronAsarSummary = z.infer<typeof electronAsarSummarySchema>;

export const engineArchiveReportSchema = z
  .object({
    path: z.string().min(1),
    sha256: z.string().regex(/^[0-9a-f]{64}$/),
    size_bytes: z.number().int().nonnegative(),
    archive_format: engineArchiveFormatSchema,
    version: z.string().min(1),
    il2cpp: il2CppMetadataSummarySchema.nullable(),
    godot_pck: godotPackSummarySchema.nullable(),
    asar: electronAsarSummarySchema.nullable().default(null),
  })
  .strict();

export type EngineArchiveReport = z.infer<typeof engineArchiveReportSchema>;
