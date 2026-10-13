import { z } from "incur";
import { resolve } from "node:path";
import { createAiModelArtifactService } from "../composition/aiModel.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";

/** Resolve caller paths and stream-inspect AI model artifacts through the shared workflow. */
export const registerAiModelCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  const service = createAiModelArtifactService();
  cli.command(CLI_COMMANDS.inspectAiModelArtifact, {
    aliases: ["inspect-ai-model"],
    description:
      "Stream-inspect a local GGUF, SafeTensors, ONNX, or TFLite AI model artifact without loading full weights",
    args: z.object({
      path: z
        .string()
        .describe("Local .gguf, .safetensors, .onnx, or .tflite model file"),
    }),
    options: z.object({
      maxTensors: z
        .number()
        .int()
        .min(1)
        .max(10_000)
        .default(500)
        .describe("Maximum number of tensor descriptors to return"),
      maxMetadataEntries: z
        .number()
        .int()
        .min(1)
        .max(5_000)
        .default(500)
        .describe("Maximum number of metadata key-value entries to return"),
      extractPrompts: z
        .boolean()
        .default(true)
        .describe(
          "Extract embedded Jinja chat templates, system prompts, and control tokens",
        ),
    }),
    run: ({ args, options }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, CLI_COMMANDS.inspectAiModelArtifact, async () => {
          const result = await service.inspect(
            {
              path: resolve(args.path),
              max_tensors: options.maxTensors,
              max_metadata_entries: options.maxMetadataEntries,
              extract_prompts: options.extractPrompts,
            },
            { signal },
          );
          return result.ok ? result.value : projectAnalysisError(result.error);
        }),
      ),
  });
};
