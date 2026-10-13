import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { EngineArchivePort } from "../../artifacts/engineArchive/EngineArchiveInspector.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  engineArchiveReportSchema,
  inspectEngineArchiveInputSchema,
} from "../../domain/engineArchive/engineArchive.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { err, ok, type Result } from "../../domain/result.js";

const OPERATION = "inspect_engine_archive";

/** Shared exact input validation and artifact-bound Evidence for CLI and MCP. */
export class EngineArchiveService {
  constructor(readonly provider: EngineArchivePort) {}

  /** Inspect one explicitly selected Unity IL2CPP metadata or Godot .pck archive without acquiring a binary session. */
  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = inspectEngineArchiveInputSchema.safeParse(rawInput);
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
    const report = engineArchiveReportSchema.safeParse(inspected.value);
    if (!report.success || report.data.path !== input.data.path)
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Engine archive inspector returned malformed metadata or changed the selected artifact identity.",
        ),
      );
    const value = report.data;
    return ok(
      createEvidence(
        {
          path: value.path,
          sha256: value.sha256,
          format: "file",
        },
        this.provider.identity,
        {
          operation: OPERATION,
          parameters: input.data,
          result: value,
          confidence: "observed",
          limitations: [],
          locations: [{ kind: "artifact-path", path: value.path }],
        },
      ),
    );
  }

  /** Alias matching the tool name for direct service consumers. */
  async inspectEngineArchive(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    return this.inspect(rawInput, options);
  }
}
