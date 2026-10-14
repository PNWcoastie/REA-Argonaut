import { z } from "zod";
import type { ProviderIdentity } from "../../application/AnalysisProvider.js";

/** Provider identity committed by the ArgonZeroG Universal 4-Mount Recon Kit & Blueprint Exporter. */
export const RECON_KIT_PROVIDER_IDENTITY: ProviderIdentity = Object.freeze({
  id: "argon-recon-kit",
  name: "ArgonZeroG Universal 4-Mount Recon Kit & Blueprint Exporter",
  version: "1.0.0",
});

export const reconMountKindSchema = z
  .enum([
    "native-binary",
    "packaged-ui-archive",
    "hardware-firmware-protocol",
    "ai-model-data",
  ])
  .describe(
    "Reverse-engineering domain mount: Mount 1 ('native-binary'), Mount 2 ('packaged-ui-archive'), Mount 3 ('hardware-firmware-protocol'), or Mount 4 ('ai-model-data').",
  );

export type ReconMountKind = z.infer<typeof reconMountKindSchema>;

export const reconMountOverrideSchema = z
  .enum([
    "auto",
    "native-binary",
    "packaged-ui-archive",
    "hardware-firmware-protocol",
    "ai-model-data",
  ])
  .default("auto")
  .describe(
    "Mount selection mode: 'auto' (default, automatically detects all applicable mounts via magic bytes and internal structures) or an explicit mount override.",
  );

export type ReconMountOverride = z.infer<typeof reconMountOverrideSchema>;

export const reconHarnessKindSchema = z
  .enum([
    "verified-safe-rust-port",
    "clean-room-app-ui-rebuild",
    "hardware-hal-protocol-replay",
    "security-hazard-audit",
  ])
  .describe(
    "Selectable engineering harness track: 'verified-safe-rust-port' (Harness 1), 'clean-room-app-ui-rebuild' (Harness 2), 'hardware-hal-protocol-replay' (Harness 3), or 'security-hazard-audit' (Harness 4).",
  );

export type ReconHarnessKind = z.infer<typeof reconHarnessKindSchema>;

export const exportReconKitInputSchema = z
  .object({
    path: z
      .string()
      .min(1)
      .optional()
      .describe(
        "Filesystem path to the target binary, archive, firmware image, capture, or AI model artifact (alias for target_path).",
      ),
    target_path: z
      .string()
      .min(1)
      .optional()
      .describe(
        "Filesystem path to the target binary, archive, firmware image, capture, or AI model artifact.",
      ),
    output_dir: z
      .string()
      .min(1)
      .optional()
      .describe(
        "Optional output directory where recon-kit/, RECON_BLUEPRINT.md, and RECON_EXPLORER.html will be materialized (defaults to <target_dir>/<target_stem>-recon-kit).",
      ),
    mount_override: reconMountOverrideSchema,
    max_subsystems: z
      .number()
      .int()
      .min(1)
      .max(500)
      .default(50)
      .describe(
        "Maximum number of clustered subsystems/components to emit in the blueprint and explorer (default 50).",
      ),
    max_classes: z
      .number()
      .int()
      .min(10)
      .max(5000)
      .default(500)
      .describe(
        "Maximum number of recovered C++/Rust/IL2CPP/.NET classes or types to materialize (default 500).",
      ),
    max_entries: z
      .number()
      .int()
      .min(10)
      .max(5000)
      .default(500)
      .describe(
        "Maximum number of archive entries, functions, tensors, or hardware registers to sample per mount (default 500).",
      ),
    mock_ui_concepts: z
      .boolean()
      .default(false)
      .describe(
        "Opt-in flag (default false): when true and the target contains UI/UX assets, renders an Antigravity generative_ui visual concept mock of the extracted screens/components without any clickable harness buttons.",
      ),
    include_explorer_html: z
      .boolean()
      .default(false)
      .describe(
        "Opt-in alias for mock_ui_concepts (default false): no HTML files are generated unless explicitly requested by the user.",
      ),
  })
  .strict();

export type ExportReconKitInput = z.infer<typeof exportReconKitInputSchema>;

export const reconMaterializedFileSchema = z
  .object({
    relative_path: z
      .string()
      .min(1)
      .describe("Path relative to output_dir (e.g., 'RECON_BLUEPRINT.md' or 'types/recovered_types.rs')."),
    absolute_path: z
      .string()
      .min(1)
      .describe("Absolute filesystem path to the materialized file."),
    mount: reconMountKindSchema,
    category: z
      .string()
      .min(1)
      .describe("Logical artifact category (e.g., 'blueprint', 'explorer-ui', 'rust-types', 'c-header', 'vtable-map', 'pseudocode', 'ui-preview', 'hardware-hal', 'ai-model-card')."),
    size_bytes: z.number().int().nonnegative(),
    description: z.string().min(1),
  })
  .strict();

export type ReconMaterializedFile = z.infer<typeof reconMaterializedFileSchema>;

export const reconSubsystemEntrySchema = z
  .object({
    id: z.string().min(1).describe("Stable slug identifier for the subsystem."),
    name: z
      .string()
      .min(1)
      .describe("Human-readable subsystem name (e.g., 'Core Engine Runtime', '3D Rendering Pipeline', 'State Serialization', 'Electron Renderer UI')."),
    mount: reconMountKindSchema,
    summary: z.string().min(1),
    class_count: z.number().int().nonnegative(),
    function_or_method_count: z.number().int().nonnegative(),
    file_or_resource_count: z.number().int().nonnegative(),
    hazard_count: z.number().int().nonnegative(),
    sample_items: z
      .array(z.string())
      .describe("Representative class names, function symbols, file paths, or register names in this subsystem."),
    kit_relative_paths: z
      .array(z.string())
      .describe("Relative paths inside recon-kit/ containing extracted artifacts for this subsystem."),
    recommended_harnesses: z.array(reconHarnessKindSchema),
  })
  .strict();

export type ReconSubsystemEntry = z.infer<typeof reconSubsystemEntrySchema>;

export const reconUiPreviewItemSchema = z
  .object({
    logical_path: z.string().min(1),
    asset_kind: z.enum([
      "html-view",
      "stylesheet",
      "script-module",
      "svg-or-image",
      "scene-or-prefab",
      "pe-dialog-or-icon",
      "config-manifest",
    ]),
    size_bytes: z.number().int().nonnegative(),
    summary: z.string().min(1),
  })
  .strict();

export type ReconUiPreviewItem = z.infer<typeof reconUiPreviewItemSchema>;

export const reconHardwareRegisterItemSchema = z
  .object({
    name: z.string().min(1),
    address_or_offset: z.string().min(1),
    width_bits: z.number().int().positive(),
    access: z.string().min(1),
    description: z.string().min(1),
  })
  .strict();

export type ReconHardwareRegisterItem = z.infer<
  typeof reconHardwareRegisterItemSchema
>;

export const reconHarnessRecommendationSchema = z
  .object({
    harness_id: reconHarnessKindSchema,
    title: z.string().min(1),
    mount: reconMountKindSchema,
    target_subsystems: z.array(z.string()),
    rationale: z.string().min(1),
    kit_inputs: z
      .array(z.string())
      .describe("Relative file paths inside recon-kit/ that feed directly into this harness."),
    argon_handoff_prompt: z
      .string()
      .min(1)
      .describe("Ready-to-use prompt instructing Antigravity + Gemini 4 Argon to execute this reconstruction/engineering harness from the materialized recon-kit/."),
    verification_command: z
      .string()
      .min(1)
      .describe("Exact CLI or MCP verification command to validate the output of this harness."),
  })
  .strict();

export type ReconHarnessRecommendation = z.infer<
  typeof reconHarnessRecommendationSchema
>;

export const reconSummaryMetricsSchema = z
  .object({
    total_subsystems: z.number().int().nonnegative(),
    total_classes_or_types: z.number().int().nonnegative(),
    total_functions_or_methods: z.number().int().nonnegative(),
    total_files_or_entries: z.number().int().nonnegative(),
    total_hazards: z.number().int().nonnegative(),
    total_materialized_files: z.number().int().nonnegative(),
  })
  .strict();

export type ReconSummaryMetrics = z.infer<typeof reconSummaryMetricsSchema>;

export const reconKitReportSchema = z
  .object({
    target_path: z.string().min(1),
    sha256: z.string().regex(/^[0-9a-f]{64}$/),
    size_bytes: z.number().int().nonnegative(),
    detected_format: z.string().min(1),
    detected_mounts: z.array(reconMountKindSchema).min(1),
    primary_mount: reconMountKindSchema,
    output_dir: z.string().min(1),
    blueprint_path: z.string().min(1),
    explorer_html_path: z.string().nullable(),
    materialized_files: z.array(reconMaterializedFileSchema),
    subsystems: z.array(reconSubsystemEntrySchema),
    ui_preview_items: z.array(reconUiPreviewItemSchema),
    hardware_or_protocol_items: z.array(reconHardwareRegisterItemSchema),
    harnesses: z.array(reconHarnessRecommendationSchema),
    summary_metrics: reconSummaryMetricsSchema,
  })
  .strict();

export type ReconKitReport = z.infer<typeof reconKitReportSchema>;
