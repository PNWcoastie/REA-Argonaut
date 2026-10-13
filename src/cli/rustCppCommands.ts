import { z } from "incur";
import { resolve } from "node:path";
import { createRustCppBinaryService } from "../composition/rustCpp.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";

/** Resolve caller paths and inspect static Rust & C++ metadata through the shared workflow. */
export const registerRustCppCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  const service = createRustCppBinaryService();
  cli.command(CLI_COMMANDS.inspectRustCppBinary, {
    aliases: ["inspect-rust-cpp"],
    description:
      "Inspect embedded Rust panic locations, crate dependencies, C++ RTTI/vtables and demangled symbols without target execution",
    args: z.object({
      path: z.string().describe("Local ELF, PE or Mach-O binary"),
    }),
    options: z.object({
      maxPanicLocations: z
        .number()
        .int()
        .min(1)
        .max(5000)
        .default(500)
        .describe("Maximum number of Rust core::panicking::Location records"),
      maxSymbols: z
        .number()
        .int()
        .min(1)
        .max(5000)
        .default(500)
        .describe("Maximum number of demangled Rust/C++ symbols"),
    }),
    run: ({ args, options }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, CLI_COMMANDS.inspectRustCppBinary, async () => {
          const result = await service.inspect(
            {
              path: resolve(args.path),
              max_panic_locations: options.maxPanicLocations,
              max_symbols: options.maxSymbols,
            },
            { signal },
          );
          return result.ok ? result.value : projectAnalysisError(result.error);
        }),
      ),
  });
};
