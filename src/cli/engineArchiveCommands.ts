import { z } from "incur";
import { resolve } from "node:path";
import { createEngineArchiveService } from "../composition/engineArchive.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";

/** Resolve caller paths and inspect Unity IL2CPP metadata or Godot .pck archives through the shared workflow. */
export const registerEngineArchiveCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  const service = createEngineArchiveService();
  cli.command(CLI_COMMANDS.inspectEngineArchive, {
    description:
      "Inspect a Unity IL2CPP global-metadata.dat binary or Godot Engine .pck archive without target execution",
    args: z.object({
      path: z
        .string()
        .describe("Local Unity global-metadata.dat or Godot .pck file"),
    }),
    options: z.object({
      maxTypes: z
        .number()
        .int()
        .min(1)
        .max(20_000)
        .default(1_000)
        .describe("Maximum number of C# TypeDefinitions to return"),
      maxMethods: z
        .number()
        .int()
        .min(1)
        .max(50_000)
        .default(2_000)
        .describe("Maximum number of C# MethodDefinitions to return"),
      maxStrings: z
        .number()
        .int()
        .min(1)
        .max(20_000)
        .default(1_000)
        .describe("Maximum number of IL2CPP string literals to return"),
      maxFiles: z
        .number()
        .int()
        .min(1)
        .max(50_000)
        .default(2_000)
        .describe("Maximum number of Godot res:// files to return"),
    }),
    run: ({ args, options }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, CLI_COMMANDS.inspectEngineArchive, async () => {
          const result = await service.inspect(
            {
              path: resolve(args.path),
              max_types: options.maxTypes,
              max_methods: options.maxMethods,
              max_strings: options.maxStrings,
              max_files: options.maxFiles,
            },
            { signal },
          );
          return result.ok ? result.value : projectAnalysisError(result.error);
        }),
      ),
  });
};
