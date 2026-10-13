import { createHash } from "node:crypto";
import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { RustParityPort } from "../../native/rustParity/RustParityVerifier.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  rustParityReportSchema,
  verifyRustParityInputSchema,
} from "../../domain/rustParity/rustParity.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { err, ok, type Result } from "../../domain/result.js";

const OPERATION = "verify_rust_parity";

/** Shared exact input validation and artifact-bound Evidence for CLI and MCP. */
export class RustParityService {
  constructor(readonly provider: RustParityPort) {}

  /** Verify FFI parity between a C reference implementation and candidate Rust source. */
  async verify(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = verifyRustParityInputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(OPERATION, input.error.issues, rawInput, {
          cause: input.error,
        }),
      );
    if (
      input.data.target_binary_path === undefined &&
      input.data.c_source_code === undefined
    )
      return err(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: ["target_binary_path"],
            reason: "missing_argument",
            message:
              "Expected either target_binary_path or c_source_code for C reference comparison.",
          },
        ]),
      );
    if (
      input.data.target_binary_path !== undefined &&
      !isAbsolute(input.data.target_binary_path)
    )
      return err(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: ["target_binary_path"],
            reason: "invalid_format",
            message: "Expected an absolute filesystem path on this host.",
          },
        ]),
      );
    const verified = await this.provider.verify(input.data, options);
    if (!verified.ok) return verified;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const report = rustParityReportSchema.safeParse(verified.value);
    if (!report.success)
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Rust parity verifier returned malformed verification telemetry.",
        ),
      );
    const value = report.data;
    const targetPath =
      input.data.target_binary_path ?? `inline-c:${input.data.symbol_name}`;
    const targetSha256 = createHash("sha256")
      .update(
        `${targetPath}\0${input.data.c_source_code ?? ""}\0${input.data.rust_source_code}`,
      )
      .digest("hex");
    return ok(
      createEvidence(
        {
          path: targetPath,
          sha256: targetSha256,
          format: "file",
        },
        this.provider.identity,
        {
          operation: OPERATION,
          parameters: {
            ...(input.data.target_binary_path !== undefined
              ? { target_binary_path: input.data.target_binary_path }
              : {}),
            ...(input.data.c_source_code !== undefined
              ? { c_source_code: input.data.c_source_code }
              : {}),
            rust_source_code: input.data.rust_source_code,
            symbol_name: input.data.symbol_name,
            arg_types: input.data.arg_types,
            return_type: input.data.return_type,
            ...(input.data.iterations !== undefined
              ? { iterations: input.data.iterations }
              : {}),
            ...(input.data.seed !== undefined ? { seed: input.data.seed } : {}),
          },
          result: value,
          confidence: "observed",
          limitations: [],
          locations: [{ kind: "artifact-path", path: targetPath }],
        },
      ),
    );
  }

  /** Alias matching the tool name for direct service consumers. */
  async verifyRustParity(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    return this.verify(rawInput, options);
  }
}
