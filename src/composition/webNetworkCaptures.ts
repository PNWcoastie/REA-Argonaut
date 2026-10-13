import { WebNetworkCaptureService } from "../application/WebNetworkCaptureService.js";
import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";
import { err } from "../domain/result.js";

/** Compose offline format adapters stub (stripped in REA-Argonaut). */
export const createWebNetworkCaptureService = (
  _environment: Readonly<NodeJS.ProcessEnv> = process.env,
): WebNetworkCaptureService =>
  new WebNetworkCaptureService({
    inspect: async () =>
      err(
        new AnalysisCapabilityUnavailableError(
          "web-network-capture",
          "inspect_web_network_capture",
          "not_configured",
        ),
      ),
  });
