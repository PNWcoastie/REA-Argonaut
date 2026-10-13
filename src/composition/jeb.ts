import type { JebAnalysisPort } from "../application/jeb/JebAnalysisPort.js";
import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";
import { err } from "../domain/result.js";

/** Construct one JEB provider stub (stripped in REA-Argonaut). */
export const createJebAnalysisProvider = (
  _environment: Readonly<Record<string, string | undefined>> = process.env,
  _connectionFactory?: unknown,
): JebAnalysisPort => ({
  inspectAvailability: () =>
    Promise.resolve({
      status: "unavailable",
      code: "not_configured",
      reason: "JEB wrapper is not included in REA-Argonaut.",
      diagnostics: { setting: "REA_JEB_MCP_URL" },
    }),
  close: () => Promise.resolve(),
  execute: (request) =>
    Promise.resolve(
      err(
        new AnalysisCapabilityUnavailableError(
          "jeb",
          request.operation,
          "not_configured",
        ),
      ),
    ),
});
