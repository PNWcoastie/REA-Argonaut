import type { ElectronActiveObservationPort } from "../application/javascript/ElectronActiveObservationPort.js";
import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";
import { err } from "../domain/result.js";

/** Construct a stub Electron scenario provider (stripped in REA-Argonaut). */
export const createElectronScenarioProvider = (
  _environment: Readonly<Record<string, string | undefined>>,
): ElectronActiveObservationPort => ({
  identity: () => ({
    id: "playwright-electron-active",
    name: "Playwright Electron Active Observation",
    version: "unavailable",
  }),
  capture: async () =>
    err(
      new AnalysisCapabilityUnavailableError(
        "electron-active-observation",
        "capture_electron_scenario",
        "not_configured",
      ),
    ),
});
