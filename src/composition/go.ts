import { GoBinaryService } from "../application/go/GoBinaryService.js";
import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";
import { err } from "../domain/result.js";

/** Compose bundled offline inspection stub (stripped in REA-Argonaut). */
export const createGoBinaryService = (): GoBinaryService =>
  new GoBinaryService({
    identity: { id: "go-binary", name: "Go Binary Reader", version: "unavailable" },
    inspect: async () =>
      err(
        new AnalysisCapabilityUnavailableError(
          "go-binary",
          "inspect_go_binary",
          "not_configured",
        ),
      ),
  });
