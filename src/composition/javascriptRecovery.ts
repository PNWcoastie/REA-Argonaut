import type { JavaScriptRecoveryPort } from "../application/javascript/JavaScriptRecoveryPort.js";
import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";
import { err } from "../domain/result.js";

/** Construct optional recovery stub (stripped in REA-Argonaut). */
export const createJavaScriptRecoveryProvider = (
  _environment: Readonly<Record<string, string | undefined>> = process.env,
  _launcher?: unknown,
): JavaScriptRecoveryPort => ({
  close: async () => {},
  recover: async () =>
    err(
      new AnalysisCapabilityUnavailableError(
        "javascript-recovery",
        "recover_javascript_sources",
        "not_configured",
      ),
    ),
});
