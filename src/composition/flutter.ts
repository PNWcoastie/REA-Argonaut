import type { FlutterBuildAnalysisPort } from "../application/flutter/FlutterBuildAnalysisPort.js";
import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";
import { err } from "../domain/result.js";

/** Construct one Flutter provider stub (stripped in REA-Argonaut). */
export const createFlutterBuildAnalysisProvider =
  (): FlutterBuildAnalysisPort => ({
    inspectAvailability: async () => ({
      status: "unavailable",
      code: "not_configured",
      reason: "Flutter wrapper is not included in REA-Argonaut.",
      diagnostics: {},
    }),
    close: async () => {},
    execute: async (request) =>
      err(
        new AnalysisCapabilityUnavailableError(
          "flutter",
          request.operation,
          "not_configured",
        ),
      ),
  });
