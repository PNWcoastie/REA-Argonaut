import { WebRuntimeService } from "../application/WebRuntimeService.js";
import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";
import { err } from "../domain/result.js";

/** Construct the live attribution workflow stub (stripped in REA-Argonaut). */
export const createWebRuntimeService = (): WebRuntimeService =>
  new WebRuntimeService({
    identity: () => ({
      id: "cdp-web-runtime",
      name: "CDP Web Runtime",
      version: "unavailable",
    }),
    observeExecution: async () =>
      err(
        new AnalysisCapabilityUnavailableError(
          "web-runtime",
          "observe_web_execution",
          "not_configured",
        ),
      ),
    inspectEventListeners: async () =>
      err(
        new AnalysisCapabilityUnavailableError(
          "web-runtime",
          "inspect_web_event_listeners",
          "not_configured",
        ),
      ),
  });
