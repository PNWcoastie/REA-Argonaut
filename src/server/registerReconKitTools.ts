import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { ReconKitService } from "../application/reconKit/ReconKitService.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { Logger } from "pino";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import { createEvidenceToolHandler } from "./contractToolHandler.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

/** Bind the export_recon_kit contract to its shared workflow and owning session Evidence ledger. */
export const registerReconKitTools = (
  server: EvidenceMcpServer,
  service: ReconKitService,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  const contract = toolContract("export_recon_kit");
  const handler = createEvidenceToolHandler(
    server,
    (input, options) => service.exportKit(input, options),
    logger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  server.registerTool(
    contract.name,
    toolRegistrationOptions(contract),
    handler(contract),
  );
};
