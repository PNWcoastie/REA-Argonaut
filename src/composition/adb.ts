import type { AdbDeviceAnalysisPort } from "../application/adb/AdbDeviceAnalysisPort.js";
import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";
import { err } from "../domain/result.js";

/** Construct one ADB provider stub (stripped in REA-Argonaut). */
export const createAdbDeviceAnalysisProvider = (
  _environment: Readonly<Record<string, string | undefined>> = process.env,
): AdbDeviceAnalysisPort => ({
  inspectAvailability: async () => ({
    status: "unavailable",
    code: "not_configured",
    reason: "ADB wrapper is not included in REA-Argonaut.",
    diagnostics: {},
  }),
  close: async () => {},
  execute: async (request) =>
    err(
      new AnalysisCapabilityUnavailableError(
        "adb",
        request.operation,
        "not_configured",
      ),
    ),
});
