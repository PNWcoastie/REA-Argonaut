import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { PythonFrozenBinaryPort } from "../../native/pythonFrozen/PythonFrozenBinaryInspector.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  inspectPythonFrozenBinaryInputSchema,
  pythonFrozenBinarySchema,
} from "../../domain/pythonFrozen/pythonFrozenBinary.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { err, ok, type Result } from "../../domain/result.js";

const OPERATION = "inspect_python_frozen_binary";

/** Shared exact input validation and artifact-bound Evidence for CLI and MCP. */
export class PythonFrozenBinaryService {
  constructor(readonly provider: PythonFrozenBinaryPort) {}

  /** Inspect one explicitly selected frozen Python or .pyc artifact without acquiring a binary session. */
  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = inspectPythonFrozenBinaryInputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(OPERATION, input.error.issues, rawInput, {
          cause: input.error,
        }),
      );
    if (!isAbsolute(input.data.path))
      return err(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: ["path"],
            reason: "invalid_format",
            message: "Expected an absolute filesystem path on this host.",
          },
        ]),
      );
    const inspected = await this.provider.inspect(input.data, options);
    if (!inspected.ok) return inspected;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const report = pythonFrozenBinarySchema.safeParse(inspected.value);
    if (!report.success || report.data.artifact.path !== input.data.path)
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Frozen Python binary inspector returned malformed metadata or changed the selected artifact identity.",
        ),
      );
    const value = report.data;
    return ok(
      createEvidence(
        {
          path: value.artifact.path,
          sha256: value.artifact.sha256,
          format: "file",
        },
        this.provider.identity,
        {
          operation: OPERATION,
          parameters: {
            path: input.data.path,
            max_toc_entries: input.data.max_toc_entries,
            max_code_objects: input.data.max_code_objects,
            ...(input.data.max_entries !== undefined
              ? { max_entries: input.data.max_entries }
              : {}),
            ...(input.data.max_strings !== undefined
              ? { max_strings: input.data.max_strings }
              : {}),
          },
          result: value,
          confidence: "observed",
          limitations: value.limitations,
          locations: [{ kind: "artifact-path", path: value.artifact.path }],
        },
      ),
    );
  }
}
