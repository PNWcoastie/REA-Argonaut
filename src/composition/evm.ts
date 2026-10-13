import { EvmInterfaceService } from "../application/evm/EvmInterfaceService.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { INSPECT_EVM_INTERFACE_CONTRACT } from "../contracts/evm/evmToolContracts.js";
import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";
import { err } from "../domain/result.js";

/** Compose offline interface analysis stub (stripped in REA-Argonaut). */
export const createEvmInterfaceService = (
  _environment: Readonly<NodeJS.ProcessEnv> = process.env,
): EvmInterfaceService =>
  new EvmInterfaceService({
    close: async () => {},
    inspect: async () =>
      err(
        new AnalysisCapabilityUnavailableError(
          "evm-interface",
          "inspect_evm_interface",
          "not_configured",
        ),
      ),
  });

/**
 * Static binding of the existing operation, command and fresh service factory.
 * The host owns injected service identity and its retryable cleanup lifetime.
 * Construction performs no acquisition, target I/O or import-time execution.
 */
export const evmInterfaceModule = {
  contract: INSPECT_EVM_INTERFACE_CONTRACT,
  cliCommand: CLI_COMMANDS.inspectEvmInterface,
  create: createEvmInterfaceService,
} as const;
