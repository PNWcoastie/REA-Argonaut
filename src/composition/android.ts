import type { AndroidAnalysisPort } from "../application/android/AndroidAnalysisPort.js";
import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";
import { err } from "../domain/result.js";

/** Construct one APK provider stub (stripped in REA-Argonaut). */
export const createAndroidAnalysisProvider = (
  _environment: Readonly<Record<string, string | undefined>> = process.env,
  _launcher?: unknown,
): AndroidAnalysisPort => ({
  inspectAvailability: async () => ({
    status: "unavailable",
    code: "not_configured",
    reason: "Android/JADX wrapper is not included in REA-Argonaut.",
    diagnostics: {},
  }),
  close: async () => {},
  execute: async (_target, request) =>
    err(
      new AnalysisCapabilityUnavailableError(
        "android",
        request.operation,
        "not_configured",
      ),
    ),
});
