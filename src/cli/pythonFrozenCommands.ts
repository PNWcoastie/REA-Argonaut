import { z } from "incur";
import { resolve } from "node:path";
import { createPythonFrozenBinaryService } from "../composition/pythonFrozen.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";

/** Resolve caller paths and inspect static PyInstaller / .pyc metadata through the shared workflow. */
export const registerPythonFrozenCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  const service = createPythonFrozenBinaryService();
  cli.command(CLI_COMMANDS.inspectPythonFrozenBinary, {
    aliases: ["inspect-python-frozen"],
    description:
      "Inspect a frozen Python executable (PyInstaller CArchive/PYZ) or standalone .pyc bytecode file without target execution",
    args: z.object({
      path: z
        .string()
        .describe("Local PyInstaller executable or .pyc bytecode file"),
    }),
    options: z.object({
      maxTocEntries: z
        .number()
        .int()
        .min(1)
        .max(5000)
        .default(1000)
        .describe("Maximum number of PyInstaller TOC entries"),
      maxCodeObjects: z
        .number()
        .int()
        .min(1)
        .max(1000)
        .default(200)
        .describe("Maximum number of .pyc marshal code objects"),
    }),
    run: ({ args, options }) =>
      withCommandCancellation((signal) =>
        logCliCommand(
          logger,
          CLI_COMMANDS.inspectPythonFrozenBinary,
          async () => {
            const result = await service.inspect(
              {
                path: resolve(args.path),
                max_toc_entries: options.maxTocEntries,
                max_code_objects: options.maxCodeObjects,
              },
              { signal },
            );
            return result.ok
              ? result.value
              : projectAnalysisError(result.error);
          },
        ),
      ),
  });
};
