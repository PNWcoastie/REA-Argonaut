import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { RustParityService } from "../application/rustParity/RustParityService.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { Logger } from "pino";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import { createEvidenceToolHandler } from "./contractToolHandler.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

/** Bind the exact Rust parity verification contract to its shared workflow and owning session Evidence ledger. */
export const registerRustParityTools = (
  server: EvidenceMcpServer,
  service: RustParityService,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  const contract = toolContract("verify_rust_parity");
  const handler = createEvidenceToolHandler(
    server,
    (input, options) => service.verify(input, options),
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
