import { isAbsolute } from "node:path";
import type {
  ExecutionOptions,
  ProviderIdentity,
} from "../AnalysisProvider.js";
import {
  ReconKitExporter,
  type ReconKitPort,
} from "../../artifacts/reconKit/ReconKitExporter.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  exportReconKitInputSchema,
  RECON_KIT_PROVIDER_IDENTITY,
  reconKitReportSchema,
} from "../../domain/reconKit/reconKit.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { err, ok, type Result } from "../../domain/result.js";

const OPERATION = "export_recon_kit";

/** Shared exact input validation and artifact-bound Evidence for Universal 4-Mount Recon Kit export across CLI and MCP. */
export class ReconKitService {
  constructor(readonly provider: ReconKitPort = new ReconKitExporter()) {}

  /** Materialize a Universal 4-Mount Recon Kit (RECON_BLUEPRINT.md, RECON_EXPLORER.html, and typed recon-kit/ artifacts). */
  async exportKit(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const input = exportReconKitInputSchema.safeParse(rawInput);
    if (!input.success)
      return err(
        analysisInputErrorFromIssues(OPERATION, input.error.issues, rawInput, {
          cause: input.error,
        }),
      );
    const targetPath = input.data.target_path ?? input.data.path;
    if (targetPath === undefined)
      return err(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: ["path"],
            reason: "missing_argument",
            message:
              "Expected either path or target_path to select a target artifact.",
          },
        ]),
      );
    if (!isAbsolute(targetPath))
      return err(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: [
              input.data.target_path !== undefined ? "target_path" : "path",
            ],
            reason: "invalid_format",
            message: "Expected an absolute filesystem path on this host.",
          },
        ]),
      );
    if (
      input.data.output_dir !== undefined &&
      !isAbsolute(input.data.output_dir)
    )
      return err(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: ["output_dir"],
            reason: "invalid_format",
            message: "Expected an absolute filesystem path for output_dir.",
          },
        ]),
      );
    const exported = await this.provider.exportKit(input.data, options);
    if (!exported.ok) return exported;
    if (options?.signal?.aborted)
      return err(new AnalysisCancelledError(OPERATION));
    const report = reconKitReportSchema.safeParse(exported.value);
    if (!report.success)
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Recon Kit exporter returned malformed blueprint metadata.",
        ),
      );
    const value = report.data;
    const providerIdentity: ProviderIdentity =
      "identity" in this.provider && this.provider.identity !== undefined
        ? this.provider.identity
        : RECON_KIT_PROVIDER_IDENTITY;
    return ok(
      createEvidence(
        {
          path: value.target_path,
          sha256: value.sha256,
          format: "file",
        },
        providerIdentity,
        {
          operation: OPERATION,
          parameters: {
            ...(input.data.path !== undefined ? { path: input.data.path } : {}),
            ...(input.data.target_path !== undefined
              ? { target_path: input.data.target_path }
              : {}),
            ...(input.data.output_dir !== undefined
              ? { output_dir: input.data.output_dir }
              : {}),
            mount_override: input.data.mount_override,
            max_subsystems: input.data.max_subsystems,
            max_classes: input.data.max_classes,
            max_entries: input.data.max_entries,
            include_explorer_html: input.data.include_explorer_html,
          },
          result: value,
          confidence: "observed",
          limitations: [],
          locations: [{ kind: "artifact-path", path: value.target_path }],
        },
      ),
    );
  }

  /** Alias matching the tool name for direct service consumers. */
  async exportReconKit(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    return this.exportKit(rawInput, options);
  }
}
