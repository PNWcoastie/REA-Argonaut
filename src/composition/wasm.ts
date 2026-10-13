import { WasmArtifactService } from "../application/wasm/WasmArtifactService.js";
import { INSPECT_WASM_ARTIFACT_CONTRACT } from "../contracts/wasm/wasmToolContracts.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";
import { err } from "../domain/result.js";

/** Compose the caller-supplied offline toolchain stub (stripped in REA-Argonaut). */
export const createWasmArtifactService = (
  _environment: Readonly<NodeJS.ProcessEnv> = process.env,
): WasmArtifactService =>
  new WasmArtifactService({
    close: async () => {},
    inspect: async () =>
      err(
        new AnalysisCapabilityUnavailableError(
          "wasm-artifact",
          "inspect_wasm_artifact",
          "not_configured",
        ),
      ),
  });

/**
 * Internal static descriptor for one named domain operation and its lifetime.
 * CLI/MCP share this binding; the service keeps failed resource ownership so
 * close can be retried. Construction performs no acquisition or target I/O.
 */
export const wasmArtifactModule = {
  contract: INSPECT_WASM_ARTIFACT_CONTRACT,
  cliCommand: CLI_COMMANDS.inspectWasmArtifact,
  create(
    environment: Readonly<NodeJS.ProcessEnv>,
    injected?: WasmArtifactService,
  ): Pick<WasmArtifactService, "inspect" | "close"> {
    const service = injected ?? createWasmArtifactService(environment);
    return {
      inspect: service.inspect.bind(service),
      close: service.close.bind(service),
    };
  },
} as const;
