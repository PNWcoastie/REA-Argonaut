import { z } from "zod";

/** Input schema for the ArgonZeroG whole-subgraph batch extractor (decompile_subgraph). */
export const decompileSubgraphInputSchema = z
  .object({
    document: z
      .string()
      .min(1)
      .nullable()
      .default(null)
      .describe(
        "Optional document name for multi-document providers; defaults to null for the active binary target.",
      ),
    procedure: z
      .string()
      .min(1)
      .optional()
      .describe(
        "Root procedure selector: exact symbol name or 0x-prefixed hexadecimal entry address.",
      ),
    entry: z
      .string()
      .min(1)
      .optional()
      .describe(
        "Alias for procedure: root procedure symbol name or 0x-prefixed hexadecimal entry address.",
      ),
    max_depth: z
      .number()
      .int()
      .min(0)
      .max(10)
      .default(2)
      .describe(
        "Maximum call-graph traversal depth from the root procedure (0..10, default 2).",
      ),
    max_nodes: z
      .number()
      .int()
      .min(1)
      .max(100)
      .default(25)
      .describe(
        "Maximum number of unique procedures to decompile in the subgraph (1..100, default 25).",
      ),
    traversal: z
      .enum(["bfs", "dfs"])
      .default("bfs")
      .describe(
        "Call-graph traversal order: breadth-first ('bfs', default) or depth-first ('dfs').",
      ),
    include_assembly: z
      .boolean()
      .default(true)
      .describe(
        "Whether to include disassembled instruction lines for each node in the subgraph (default true).",
      ),
  })
  .strict();

export type DecompileSubgraphInput = z.infer<
  typeof decompileSubgraphInputSchema
>;

export const subgraphProcedureRefSchema = z
  .object({
    address: z
      .string()
      .min(1)
      .describe("Canonical 0x-prefixed entry address of the procedure."),
    name: z
      .string()
      .min(1)
      .describe("Primary analyzed or synthesized name of the procedure."),
  })
  .strict();

export type SubgraphProcedureRef = z.infer<typeof subgraphProcedureRefSchema>;

export const inferredStructOffsetSchema = z
  .object({
    base: z
      .string()
      .min(1)
      .describe(
        "Base pointer register or variable name (e.g., 'rdi', 'param_1', 'x0', 'rcx').",
      ),
    offset: z
      .number()
      .int()
      .describe("Signed byte displacement from the base pointer."),
    offset_hex: z
      .string()
      .min(1)
      .describe("Hexadecimal representation of the byte offset (e.g., '+0x10')."),
    size: z
      .number()
      .int()
      .nonnegative()
      .describe("Observed memory access size in bytes (1, 2, 4, 8, etc.; 0 if address-only)."),
    access: z
      .enum(["read", "write", "read_write", "address"])
      .describe("Observed access mode across the procedure."),
    field_name: z
      .string()
      .nullable()
      .describe("Recovered composite field name when known, or null."),
  })
  .strict();

export type InferredStructOffset = z.infer<typeof inferredStructOffsetSchema>;

export const latentBinaryHazardCategorySchema = z
  .enum([
    "potential_integer_overflow_to_pointer",
    "unchecked_division",
    "thread_hostile_mutable_global",
    "unsafe_memory_sink",
    "uninitialized_or_stack_hazard",
    "register_writeback_offset_clobber",
    "null_deref_before_check",
    "size_truncation_or_unsigned_underflow",
    "unpopulated_out_param_or_duplicate_call",
  ])
  .describe("Classification of a latent binary bug or undefined-behavior hazard.");

export type LatentBinaryHazardCategory = z.infer<
  typeof latentBinaryHazardCategorySchema
>;

export const latentBinaryHazardSchema = z
  .object({
    category: latentBinaryHazardCategorySchema,
    severity: z
      .enum(["high", "medium", "low"])
      .describe("Estimated severity of the binary hazard during modernization."),
    address: z
      .string()
      .min(1)
      .describe("0x-prefixed instruction or procedure address where the hazard occurs."),
    instruction_or_op: z
      .string()
      .min(1)
      .describe("Disassembled instruction or HighFunction P-Code operation triggering the hazard."),
    description: z
      .string()
      .min(1)
      .describe("Actionable engineering explanation of the latent bug/UB hazard and how to eliminate it in Safe Rust."),
  })
  .strict();

export type LatentBinaryHazard = z.infer<typeof latentBinaryHazardSchema>;

export const stage15LinkageEdgeKindSchema = z.enum([
  "dynsym_export",
  "jni_java_export",
  "jni_onload_register_natives",
  "vtable_dispatch",
  "dlopen_plugin_entry",
  "internal_call_chain",
  "unreferenced_export",
  "unreferenced_internal",
]);

export type Stage15LinkageEdgeKind = z.infer<
  typeof stage15LinkageEdgeKindSchema
>;

export const stage15NodeReachabilitySchema = z
  .object({
    classification: z.enum([
      "class_i_live_wired",
      "class_ii_dead_fossil",
      "class_ii_cloned_inline_suspect",
    ]),
    intra_binary_caller_count: z.number().int().nonnegative(),
    is_exported_global_default: z.boolean(),
    linkage_edges: z.array(stage15LinkageEdgeKindSchema),
    remediation_action: z.string().min(1),
  })
  .strict();

export type Stage15NodeReachability = z.infer<
  typeof stage15NodeReachabilitySchema
>;

export const linkerHygieneSummarySchema = z
  .object({
    defined_dynsym_functions: z.number().int().nonnegative(),
    global_default_functions: z.number().int().nonnegative(),
    global_default_ratio: z.number().nonnegative(),
    weak_functions: z.number().int().nonnegative(),
    intra_binary_plt_stubs: z.number().int().nonnegative(),
    relr_relocations_decoded: z.number().int().nonnegative(),
    jni_registered_methods_recovered: z.number().int().nonnegative(),
    dlopen_targets: z.array(z.string()),
    filtered_cpp_linker_traps: z.number().int().nonnegative(),
    fvisibility_hidden_likely_omitted: z.boolean(),
  })
  .strict();

export type LinkerHygieneSummary = z.infer<typeof linkerHygieneSummarySchema>;

export const subgraphStringRefSchema = z
  .object({
    address: z
      .string()
      .min(1)
      .describe("Address of the referenced string constant."),
    value: z.string().describe("Decoded string literal content."),
  })
  .strict();

export type SubgraphStringRef = z.infer<typeof subgraphStringRefSchema>;

export const subgraphNodeDossierSchema = z
  .object({
    procedure: z
      .object({
        address: z.string().min(1),
        name: z.string().min(1),
        signature: z.string().nullable(),
      })
      .strict(),
    depth: z
      .number()
      .int()
      .nonnegative()
      .describe("Shortest traversal distance from root_procedure."),
    pseudocode: z
      .string()
      .describe("Decompiled C or synthesized structured pseudo-C for this procedure."),
    assembly: z
      .array(z.string())
      .describe("Disassembled instruction lines (empty array if include_assembly is false)."),
    callers: z.array(subgraphProcedureRefSchema),
    callees: z.array(subgraphProcedureRefSchema),
    referenced_strings: z.array(subgraphStringRefSchema),
    inferred_struct_offsets: z.array(inferredStructOffsetSchema),
    latent_hazards: z
      .array(latentBinaryHazardSchema)
      .default([])
      .describe(
        "Static binary bug and undefined-behavior hazards uncovered in this procedure (unchecked division, 32-bit overflow before pointer indexing, mutable globals, unsafe sinks, stack hazards, writeback offset clobbers, pre-check null derefs, size truncation/underflow, and unpopulated out-params/duplicate calls).",
      ),
    stage15_reachability: stage15NodeReachabilitySchema.optional(),
  })
  .strict();

export type SubgraphNodeDossier = z.infer<typeof subgraphNodeDossierSchema>;

export const subgraphEdgeSchema = z
  .object({
    from: z.string().min(1).describe("Caller procedure canonical address."),
    from_name: z.string().min(1).describe("Caller procedure name."),
    to: z.string().min(1).describe("Callee procedure canonical address."),
    to_name: z.string().min(1).describe("Callee procedure name."),
    kind: z.enum(["direct_call", "indirect_call", "cycle_call"]),
  })
  .strict();

export type SubgraphEdge = z.infer<typeof subgraphEdgeSchema>;

export const aggregatedSubgraphStringSchema = z
  .object({
    address: z.string().min(1),
    value: z.string(),
    referenced_by: z.array(z.string().min(1)),
  })
  .strict();

export const nativeSubgraphSchema = z
  .object({
    root_procedure: z
      .object({
        address: z.string().min(1),
        name: z.string().min(1),
        signature: z.string().nullable(),
      })
      .strict(),
    traversal: z.enum(["bfs", "dfs"]),
    max_depth: z.number().int().min(0).max(10),
    max_nodes: z.number().int().min(1).max(100),
    node_count: z.number().int().nonnegative(),
    total_latent_hazards: z
      .number()
      .int()
      .nonnegative()
      .default(0)
      .describe("Total latent binary hazards detected across all nodes in the subgraph."),
    truncated: z.boolean(),
    cycle_edges: z.array(
      z
        .object({
          from: z.string().min(1),
          from_name: z.string().min(1),
          to: z.string().min(1),
          to_name: z.string().min(1),
        })
        .strict(),
    ),
    nodes: z.array(subgraphNodeDossierSchema),
    edges: z.array(subgraphEdgeSchema),
    aggregated_strings: z.array(aggregatedSubgraphStringSchema),
    linker_hygiene: linkerHygieneSummarySchema.optional(),
    limitations: z.array(z.string()),
  })
  .strict();

export type NativeSubgraph = z.infer<typeof nativeSubgraphSchema>;
