import { isAbsolute } from "node:path";

import type { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import {
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import type { Evidence } from "../domain/evidence.js";
import { analysisInputErrorFromIssues } from "../domain/inputIssueProjection.js";
import { err, type Result } from "../domain/result.js";
import {
  exportWebScriptsInputSchema,
  type ExportWebScriptsInput,
} from "../domain/webScriptExport.js";
import type { ExecutionOptions } from "./AnalysisProvider.js";

const OPERATION = "export_web_scripts";

/** Export one local capture through the shared CLI/MCP application workflow. */
export const exportWebScripts = async (
  rawInput: unknown,
  resources: ArtifactResourceScope,
  options: ExecutionOptions = {},
): Promise<Result<Evidence, AnalysisError>> => {
  const input = exportWebScriptsInputSchema.safeParse(rawInput);
  return input.success
    ? exportWebScriptsValidated(input.data, resources, options)
    : err(
        analysisInputErrorFromIssues(OPERATION, input.error.issues, rawInput),
      );
};

/** Publish input already parsed by a named adapter contract. */
export const exportWebScriptsValidated = async (
  input: ExportWebScriptsInput,
  _resources: ArtifactResourceScope,
  options: ExecutionOptions = {},
): Promise<Result<Evidence, AnalysisError>> => {
  if (!isAbsolute(input.capture_path) || !isAbsolute(input.output_directory))
    return err(
      new AnalysisInputError(OPERATION, undefined, [
        {
          path: [],
          reason: "invalid_format",
          message:
            "capture_path and output_directory must be absolute filesystem paths on this host.",
        },
      ]),
    );
  options.signal?.throwIfAborted();
  return err(
    new AnalysisCapabilityUnavailableError(
      "web-script-export",
      OPERATION,
      "not_configured",
    ),
  );
};


