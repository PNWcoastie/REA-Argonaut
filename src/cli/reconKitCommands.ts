import { z } from "incur";
import { resolve } from "node:path";
import { createReconKitService } from "../composition/binary.js";
import type { ReconKitService } from "../application/reconKit/ReconKitService.js";
import { logCliCommand } from "../cliLogging.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import { reconMountOverrideSchema } from "../domain/reconKit/reconKit.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";

const EXPORT_RECON_KIT_COMMAND = "export-recon-kit";

/** Register the export-recon-kit CLI command for Universal 4-Mount Recon Kit materialization. */
export const registerReconKitCommands = (
  cli: CliInstance,
  logger: Logger,
  service: ReconKitService = createReconKitService(),
): void => {
  cli.command(EXPORT_RECON_KIT_COMMAND, {
    aliases: ["recon-kit"],
    description:
      "Materialize a Universal 4-Mount Recon Kit (RECON_BLUEPRINT.md, RECON_EXPLORER.html, and typed recon-kit/ artifacts) for any binary, archive, firmware, capture, or AI model",
    args: z.object({
      path: z
        .string()
        .optional()
        .describe(
          "Local target binary, archive, firmware image, capture, or AI model path",
        ),
    }),
    options: z.object({
      path: z
        .string()
        .optional()
        .describe(
          "Filesystem path to the target artifact (alias for --target-path)",
        ),
      targetPath: z
        .string()
        .optional()
        .describe("Filesystem path to the target artifact"),
      outputDir: z
        .string()
        .optional()
        .describe(
          "Optional output directory where recon-kit/, RECON_BLUEPRINT.md, and RECON_EXPLORER.html will be materialized",
        ),
      mountOverride: reconMountOverrideSchema,
      maxSubsystems: z
        .number()
        .int()
        .min(1)
        .max(500)
        .default(50)
        .describe("Maximum number of clustered subsystems/components to emit"),
      maxClasses: z
        .number()
        .int()
        .min(10)
        .max(5000)
        .default(500)
        .describe(
          "Maximum number of recovered C++/Rust/IL2CPP/.NET classes or types to materialize",
        ),
      maxEntries: z
        .number()
        .int()
        .min(10)
        .max(5000)
        .default(500)
        .describe(
          "Maximum number of archive entries, functions, tensors, or hardware registers to sample per mount",
        ),
      mockUiConcepts: z
        .boolean()
        .default(false)
        .describe(
          "Opt-in flag (default false): render an Antigravity generative_ui UI concept mock when UI assets are present",
        ),
      explorerHtml: z
        .boolean()
        .default(false)
        .describe(
          "Opt-in alias for --mock-ui-concepts (default false): do not generate HTML unless explicitly requested",
        ),
    }),
    run: ({ args, options }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, EXPORT_RECON_KIT_COMMAND, async () => {
          const rawTargetPath = options.targetPath ?? options.path ?? args.path;
          const resolvedPath =
            rawTargetPath === undefined ? undefined : resolve(rawTargetPath);
          const resolvedOutputDir =
            options.outputDir === undefined
              ? undefined
              : resolve(options.outputDir);
          const result = await service.exportKit(
            {
              ...(resolvedPath === undefined
                ? {}
                : { path: resolvedPath, target_path: resolvedPath }),
              ...(resolvedOutputDir === undefined
                ? {}
                : { output_dir: resolvedOutputDir }),
              mount_override: options.mountOverride,
              max_subsystems: options.maxSubsystems,
              max_classes: options.maxClasses,
              max_entries: options.maxEntries,
              mock_ui_concepts: options.mockUiConcepts || options.explorerHtml,
              include_explorer_html:
                options.mockUiConcepts || options.explorerHtml,
            },
            { signal },
          );
          return result.ok ? result.value : projectAnalysisError(result.error);
        }),
      ),
  });
};
