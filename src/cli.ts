import { snapshotEnvironment } from "./process/snapshotEnvironment.js";
import { createDirectAnalysis } from "./composition/directAnalysis.js";
import { registerAnalysisViewCommands } from "./cli/analysisViewCommands.js";
import { registerBinaryDiagnosticsCommands } from "./cli/binaryDiagnosticsCommands.js";
import type { FridaInstrumentationPort } from "./application/frida/FridaInstrumentationPort.js";
import { Cli } from "incur";

import { createLogger, parseLogLevel } from "./logger.js";
import { projectAnalysisError } from "./domain/analysisErrorProjection.js";
import { PRODUCT_IDENTITY } from "./identity.js";
import { npxRegistrationCommand } from "./application/ClientRegistrationIdentity.js";
import { registerSetupCommands } from "./cli/setupCommands.js";
import { registerCoreAnalysisCommands } from "./cli/coreAnalysisCommands.js";
import { registerUtilityCommands } from "./cli/utilityCommands.js";
import { registerArtifactCommands } from "./cli/artifactCommands.js";
import { registerEvidenceCommands } from "./cliEvidenceCommands.js";
import { registerProcessCommands } from "./cli/processCommands.js";
import { registerElectronCommands } from "./cli/electronCommands.js";
import { registerApplicationCommands } from "./cli/applicationCommands.js";
import { presentOmittableDefaults } from "./cli/omittableDefaults.js";
import type { CliInstance } from "./cli/types.js";
import {
  streamCliCommandResults,
  type CliResultOutput,
} from "./cli/cliResultOutput.js";

/** Describe CLI settings that are invalid before any command runs, as MCP does. */
export const cliConfigurationError = (
  selectedEnvironment: Readonly<Record<string, string | undefined>>,
): string | undefined => {
  const value = selectedEnvironment.REA_LOG_LEVEL;
  if (value === undefined) return undefined;
  const level = parseLogLevel(value);
  return level.ok ? undefined : projectAnalysisError(level.error).message;
};

/**
 * Build the one-shot Incur CLI without starting Hopper at import time.
 * Analysis commands acquire and close their own sessions; bare `mcp` and
 * `--mcp` are intercepted by the executable dispatcher before this module loads.
 */
export const createCli = (
  selectedEnvironment: Readonly<
    Record<string, string | undefined>
  > = process.env,
  resultOutput?: CliResultOutput,
  _fridaInstrumentation?: FridaInstrumentationPort,
): CliInstance => {
  const environment = snapshotEnvironment(selectedEnvironment);
  const analysis = createDirectAnalysis(environment);
  // The executable reports an invalid level through cliConfigurationError.
  const level =
    environment.REA_LOG_LEVEL === undefined
      ? undefined
      : parseLogLevel(environment.REA_LOG_LEVEL);
  const logger = createLogger(
    "cli",
    level?.ok === true ? level.value : "silent",
  );
  const cli = Cli.create(PRODUCT_IDENTITY.cliBinary, {
    version: PRODUCT_IDENTITY.packageVersion,
    description:
      "Zero-G Reverse Engineering & Verified Rust Reconstruction for Gemini 4 Argon + Antigravity.",
    mcp: {
      command: npxRegistrationCommand().join(" "),
      instructions:
        "Ask what software, artifact, protocol, or behavior the user wants to understand, then choose the available investigation capabilities that can produce evidence.",
    },
    sync: false,
  });

  registerSetupCommands(cli, logger, environment);
  registerCoreAnalysisCommands(cli, logger, analysis.runDirectAnalysis);
  registerUtilityCommands(cli, logger, environment, analysis);
  registerArtifactCommands(cli, logger, analysis.runProviderAnalysis);
  registerBinaryDiagnosticsCommands(cli, logger, environment);
  registerAnalysisViewCommands(cli, logger);
  registerEvidenceCommands(cli, logger);
  registerProcessCommands(cli, logger, environment);
  registerElectronCommands(cli, logger, environment);
  registerApplicationCommands(cli, logger);
  presentOmittableDefaults(cli);
  if (resultOutput !== undefined) streamCliCommandResults(cli, resultOutput);
  return cli;
};

