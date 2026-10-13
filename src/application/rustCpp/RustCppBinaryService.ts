import { isAbsolute } from "node:path";
import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { RustCppBinaryPort } from "../../native/rustCpp/RustCppBinaryInspector.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { BINARY_ARCHITECTURES } from "../../domain/binaryTargetTypes.js";
import {
  inspectRustCppBinaryInputSchema,
  rustCppBinarySchema,
} from "../../domain/rustCpp/rustCppBinary.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { err, ok, type Result } from "../../domain/result.js";

const OPERATION = "inspect_rust_cpp_binary";

const architectureForSubject = (architecture: string) => {
  switch (architecture) {
    case "386":
    case "i386":
      return "x86";
    case "amd64":
      return "x86_64";
    case "aarch64":
      return "arm64";
    default:
      return BINARY_ARCHITECTURES.find(
        (supported) => supported === architecture,
      );
  }
};

/** Shared exact input validation and artifact-bound Evidence for CLI and MCP. */
export class RustCppBinaryService {
  constructor(readonly provider: RustCppBinaryPort) {}

  /** Inspect one explicitly selected file without acquiring a binary session. */
  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = inspectRustCppBinaryInputSchema.safeParse(rawInput);
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
    const report = rustCppBinarySchema.safeParse(inspected.value);
    if (!report.success || report.data.artifact.path !== input.data.path)
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Rust/C++ binary inspector returned malformed metadata or changed the selected artifact identity.",
        ),
      );
    const value = report.data;
    const architecture = architectureForSubject(value.architecture);
    return ok(
      createEvidence(
        {
          path: value.artifact.path,
          sha256: value.artifact.sha256,
          format: value.format === "macho" ? "mach-o" : value.format,
          ...(architecture === undefined ? {} : { architecture }),
        },
        this.provider.identity,
        {
          operation: OPERATION,
          parameters: input.data,
          result: value,
          confidence: "observed",
          limitations: value.limitations,
          locations: [{ kind: "artifact-path", path: value.artifact.path }],
        },
      ),
    );
  }
}
