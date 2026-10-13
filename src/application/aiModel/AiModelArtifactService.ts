import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { AiModelArtifactPort } from "../../artifacts/aiModel/AiModelArtifactInspector.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  aiModelArtifactReportSchema,
  inspectAiModelArtifactInputSchema,
} from "../../domain/aiModel/aiModelArtifact.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { err, ok, type Result } from "../../domain/result.js";

const OPERATION = "inspect_ai_model_artifact";

/** Shared exact input validation and artifact-bound Evidence for CLI and MCP. */
export class AiModelArtifactService {
  constructor(readonly provider: AiModelArtifactPort) {}

  /** Stream-inspect one explicitly selected AI model artifact without acquiring a binary session. */
  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = inspectAiModelArtifactInputSchema.safeParse(rawInput);
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
    const report = aiModelArtifactReportSchema.safeParse(inspected.value);
    if (!report.success || report.data.path !== input.data.path)
      return err(
        new AnalysisOutputError(
          OPERATION,
          "AI model artifact inspector returned malformed metadata or changed the selected artifact identity.",
        ),
      );
    const value = report.data;
    return ok(
      createEvidence(
        {
          path: value.path,
          sha256: value.sha256_header,
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
  async inspectAiModelArtifact(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    return this.inspect(rawInput, options);
  }
}
