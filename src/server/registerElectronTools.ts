import type { ToolResultDelivery } from "./toolResult.js";
import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import { summarizeRetainedAnalysis } from "../application/analysisView/AnalysisViewService.js";
import type { EvidenceLookup } from "../application/EvidenceInputResolver.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import type { OptionalProviderLoadFailure } from "../application/OptionalObservationProviders.js";
import type { ServerContext } from "@modelcontextprotocol/server";

import type { ElectronActiveObservationPort } from "../application/javascript/ElectronActiveObservationPort.js";
import type { ElectronObservationPort } from "../application/javascript/ElectronObservationPort.js";
import { analyzeJavaScriptApplicationValidated } from "../application/javascript/JavaScriptApplicationService.js";
import type { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import type { ProgressReporter } from "../application/ProgressReporter.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { ToolContract } from "../contracts/toolContractTypes.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import type { Evidence } from "../domain/evidence.js";
import type { Result } from "../domain/result.js";
import type { Logger } from "pino";
import { mcpProgressReporter } from "./mcpProgress.js";
import { logToolExecution } from "./toolLogging.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import { runAdmittedToolOperation } from "./admittedToolOperation.js";

interface ElectronToolRegistration {
  readonly artifactResources: ArtifactResourceScope;
  readonly logger: Logger;
  readonly observationLoadFailure?: OptionalProviderLoadFailure | undefined;
  readonly activeLoadFailure?: OptionalProviderLoadFailure | undefined;
  readonly electron?: ElectronObservationPort | undefined;
  readonly electronActive?: ElectronActiveObservationPort | undefined;
  readonly recordEvidence: EvidenceWriter["recordEvidence"] | undefined;
  readonly evidenceById: EvidenceLookup | undefined;
  readonly withAdmittedAnalysis?: WithAdmittedAnalysis;
}

interface ElectronToolContext {
  readonly signal: AbortSignal;
  readonly progress: ProgressReporter;
}

/** Register static JavaScript/Electron application analysis tool. */
export const registerElectronTools = (
  server: EvidenceMcpServer,
  options: ElectronToolRegistration,
): void => {
  const registration = { ...options, delivery: server.delivery, server };
  const analyzeContract = toolContract("analyze_javascript_application");

  server.registerTool(
    analyzeContract.name,
    toolRegistrationOptions(analyzeContract),
    (input, context) =>
      runElectronTool(
        registration,
        analyzeContract,
        { input, context },
        async ({ detail, ...request }, { signal, progress }) => {
          const analyzed = await analyzeJavaScriptApplicationValidated(
            request,
            options.artifactResources,
            { signal, progress },
          );
          return detail === "summary" && analyzed.ok
            ? summarizeRetainedAnalysis(analyzed.value, options)
            : analyzed;
        },
      ),
  );
};

const runElectronTool = async <Input>(
  options: ElectronToolRegistration & {
    readonly delivery: ToolResultDelivery;
    readonly server: EvidenceMcpServer;
  },
  contract: ToolContract,
  request: {
    readonly input: Input;
    readonly context: ServerContext;
  },
  execute: (
    input: Input,
    context: ElectronToolContext,
  ) => Promise<Result<Evidence, AnalysisError>>,
) => {
  const { input, context } = request;
  return runAdmittedToolOperation(
    options.server,
    options.withAdmittedAnalysis,
    contract.name,
    context.mcpReq.signal,
    async () => {
      const result = await logToolExecution(options.logger, contract.name, () =>
        execute(input, {
          signal: context.mcpReq.signal,
          progress: mcpProgressReporter(context),
        }),
      );
      if (!result.ok) {
        const partial = result.error.partialObservation;
        if (
          partial !== undefined &&
          "evidence_id" in partial &&
          typeof partial.evidence_id === "string"
        ) {
          const recorded = options.recordEvidence?.(partial);
          if (recorded !== undefined)
            return options.delivery.toRecordedPartialErrorToolResult(
              result.error,
              partial.evidence_id,
              recorded,
              contract.returnsTargetContent,
            );
        }
        return options.delivery.toCallToolResult(result, contract);
      }
      const recorded = options.recordEvidence?.(result.value);
      return options.delivery.toEvidenceToolResult(
        result.value,
        contract,
        recorded,
      );
    },
  );
};

