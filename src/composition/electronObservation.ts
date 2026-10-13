import type { ElectronObservationPort } from "../application/javascript/ElectronObservationPort.js";
import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";
import { err } from "../domain/result.js";

/** Construct a stub Electron observation provider (stripped in REA-Argonaut). */
export const createElectronObservationProvider =
  (): ElectronObservationPort => ({
    identity: () => ({
      id: "cdp-electron",
      name: "CDP Electron Observation",
      version: "unavailable",
    }),
    listTargets: async () =>
      err(
        new AnalysisCapabilityUnavailableError(
          "electron-observation",
          "list_electron_targets",
          "not_configured",
        ),
      ),
    inspectPage: async () =>
      err(
        new AnalysisCapabilityUnavailableError(
          "electron-observation",
          "inspect_electron_page",
          "not_configured",
        ),
      ),
  });
