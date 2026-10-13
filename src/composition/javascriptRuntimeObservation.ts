import type { JavaScriptRuntimeObservationPort } from "../application/javascript/JavaScriptRuntimeObservationPort.js";
import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";
import { err } from "../domain/result.js";

/** Construct a stub JavaScript runtime observation provider (stripped in REA-Argonaut). */
export const createJavaScriptRuntimeObservationProvider =
  (): JavaScriptRuntimeObservationPort => ({
    identity: () => ({
      id: "v8-inspector",
      name: "V8 Inspector Runtime Observation",
      version: "unavailable",
    }),
    listTargets: async () =>
      err(
        new AnalysisCapabilityUnavailableError(
          "v8-inspector-observation",
          "list_javascript_runtime_targets",
          "not_configured",
        ),
      ),
    observe: async () =>
      err(
        new AnalysisCapabilityUnavailableError(
          "v8-inspector-observation",
          "observe_javascript_runtime",
          "not_configured",
        ),
      ),
  });
