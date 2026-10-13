import type { ApktoolResourceAnalysisPort } from "../application/apktool/ApktoolResourceAnalysisPort.js";
import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";
import { err } from "../domain/result.js";

/** Construct one Apktool provider stub (stripped in REA-Argonaut). */
export const createApktoolResourceAnalysisProvider = (
  _environment: Readonly<Record<string, string | undefined>> = process.env,
): ApktoolResourceAnalysisPort => ({
  inspectAvailability: async () => ({
    status: "unavailable",
    code: "not_configured",
    reason: "Apktool wrapper is not included in REA-Argonaut.",
    diagnostics: {},
  }),
  close: async () => {},
  execute: async (request) =>
    err(
      new AnalysisCapabilityUnavailableError(
        "apktool",
        request.operation,
        "not_configured",
      ),
    ),
});
