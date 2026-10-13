import type { BrowserScenarioCapturePort } from "../application/BrowserScenarioCapturePort.js";
import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";
import { err } from "../domain/result.js";

/** Construct a stub browser scenario provider (stripped in REA-Argonaut). */
export const createBrowserScenarioProvider = (
  _environment: Readonly<Record<string, string | undefined>>,
): BrowserScenarioCapturePort => ({
  close: async () => {},
  identity: () => ({
    id: "playwright-browser-scenario",
    name: "Playwright Browser Scenario",
    version: "unavailable",
  }),
  captureScenario: async () =>
    err(
      new AnalysisCapabilityUnavailableError(
        "browser-scenario",
        "capture_browser_scenario",
        "not_configured",
      ),
    ),
});
