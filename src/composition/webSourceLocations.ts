import { WebSourceLocationService } from "../application/WebSourceLocationService.js";
import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";
import { err } from "../domain/result.js";
import { SourceMapDecoder } from "../javascript/sourceMaps/SourceMapDecoder.js";

/** Compose local source/map analysis without deleted browser assets. */
export const createWebSourceLocationService = (
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
): WebSourceLocationService =>
  new WebSourceLocationService(
    {
      load: async () =>
        err(
          new AnalysisCapabilityUnavailableError(
            "web-source-location",
            "trace_web_source_location",
            "not_configured",
          ),
        ),
    },
    new SourceMapDecoder({ environment }),
  );
