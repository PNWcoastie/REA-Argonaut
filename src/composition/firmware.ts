import type { FirmwareAnalysisPort } from "../application/firmware/FirmwareAnalysisPort.js";
import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";
import { err } from "../domain/result.js";

/** Construct one firmware provider stub (stripped in REA-Argonaut). */
export const createFirmwareAnalysisProvider = (
  _environment: Readonly<Record<string, string | undefined>> = process.env,
  _launcher?: unknown,
): FirmwareAnalysisPort => ({
  close: async () => {},
  execute: async (request) =>
    err(
      new AnalysisCapabilityUnavailableError(
        "firmware",
        request.operation,
        "not_configured",
      ),
    ),
});
