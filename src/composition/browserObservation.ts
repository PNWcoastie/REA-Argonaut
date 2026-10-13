import type { BrowserObservationPort } from "../application/BrowserObservationPort.js";
import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";
import { err } from "../domain/result.js";

const unavailable = (operation: string) =>
  Promise.resolve(
    err(
      new AnalysisCapabilityUnavailableError(
        "browser-observation",
        operation,
        "not_configured",
      ),
    ),
  );

/** Construct a stub browser observation provider (stripped in REA-Argonaut). */
export const createBrowserObservationProvider = (): BrowserObservationPort => ({
  identity: () => ({
    id: "cdp-browser",
    name: "CDP Browser Observation",
    version: "unavailable",
  }),
  listTargets: () => unavailable("list_browser_targets"),
  inspectPage: () => unavailable("inspect_web_page"),
  analyzeBundle: () => unavailable("analyze_web_bundle"),
  observeSession: () => unavailable("observe_web_session"),
  discoverWebMcpTools: () => unavailable("discover_webmcp_tools"),
  compareCaptures: () => unavailable("compare_web_captures"),
  captureScreenshot: () => unavailable("capture_web_screenshot"),
  compareScreenshots: () => unavailable("compare_web_screenshots"),
});
