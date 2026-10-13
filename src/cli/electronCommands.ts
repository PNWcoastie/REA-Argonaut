import { Cli, z } from "incur";

import { logCliCommand } from "../cliLogging.js";
import type { Logger } from "pino";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { javascriptApplicationOptions } from "../cliObservationOptions.js";
import { runCliJavaScriptApplicationAnalysis } from "./javascriptApplicationAnalysis.js";
import { withCommandCancellation } from "./commandCancellation.js";

/** Register static JavaScript/Electron application analysis CLI command. */
export const registerElectronCommands = (
  cli: ReturnType<typeof Cli.create>,
  logger: Logger,
  _environment?: Readonly<Record<string, string | undefined>>,
): void => {
  registerJavaScriptApplicationCommand(cli, logger);
};

const registerJavaScriptApplicationCommand = (
  cli: ReturnType<typeof Cli.create>,
  logger: Logger,
): void => {
  cli.command(CLI_COMMANDS.analyzeJavaScriptApplication, {
    description:
      "Statically reconstruct a local JavaScript/Electron application",
    args: z.object({
      path: z.string().describe("ASAR or extracted application path"),
    }),
    options: javascriptApplicationOptions,
    run: ({ args, options }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, CLI_COMMANDS.analyzeJavaScriptApplication, () =>
          runCliJavaScriptApplicationAnalysis(
            {
              input_path: args.path,
              format: options.artifactFormat,
              integrity_policy: options.integrityPolicy,
              ...(options.maxSemanticNodes === undefined
                ? {}
                : { max_semantic_nodes: options.maxSemanticNodes }),
              ...(options.maxSemanticNodesPerFile === undefined
                ? {}
                : {
                    max_semantic_nodes_per_file:
                      options.maxSemanticNodesPerFile,
                  }),
              ...(options.sourcePath === undefined
                ? {}
                : { source_paths: options.sourcePath }),
              ...(options.maxHeapMb === undefined
                ? {}
                : { max_heap_mb: options.maxHeapMb }),
              ...(options.analysisTimeoutMs === undefined
                ? {}
                : { analysis_timeout_ms: options.analysisTimeoutMs }),
            },
            signal,
          ),
        ),
      ),
  });
};

