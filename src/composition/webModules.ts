import { WebModuleTraceService } from "../application/WebModuleTraceService.js";
import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";
import { err } from "../domain/result.js";

/** Assemble optional module tracing stub (stripped in REA-Argonaut). */
export const createWebModuleTraceService = (
  _environment: Readonly<Record<string, string | undefined>> = process.env,
): WebModuleTraceService =>
  new WebModuleTraceService(
    {
      load: async () =>
        err(
          new AnalysisCapabilityUnavailableError(
            "web-module-resolution",
            "trace_web_module_imports",
            "not_configured",
          ),
        ),
    },
    {
      close: async () => {},
      resolve: async () =>
        err(
          new AnalysisCapabilityUnavailableError(
            "web-module-resolution",
            "trace_web_module_imports",
            "not_configured",
          ),
        ),
    },
  );
