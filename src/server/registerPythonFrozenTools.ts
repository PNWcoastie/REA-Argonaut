import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { PythonFrozenBinaryService } from "../application/pythonFrozen/PythonFrozenBinaryService.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { Logger } from "pino";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import { createEvidenceToolHandler } from "./contractToolHandler.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

/** Bind the exact Frozen Python & .pyc inspection contract to its shared workflow and owning session Evidence ledger. */
export const registerPythonFrozenTools = (
  server: EvidenceMcpServer,
  service: PythonFrozenBinaryService,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  const contract = toolContract("inspect_python_frozen_binary");
  const handler = createEvidenceToolHandler(
    server,
    (input, options) => service.inspect(input, options),
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
