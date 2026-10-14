import { CAPTURE_TOOL_CONTRACTS } from "./captures/captureToolContracts.js";
import { SIGNAL_TOOL_CONTRACTS } from "./signals/signalToolContracts.js";
import { WASM_TOOL_CONTRACTS } from "./wasm/wasmToolContracts.js";
import { EVM_TOOL_CONTRACTS } from "./evm/evmToolContracts.js";
import { GO_TOOL_CONTRACTS } from "./go/goToolContracts.js";
import { RUST_CPP_TOOL_CONTRACTS } from "./rustCpp/rustCppToolContracts.js";
import { PYTHON_FROZEN_TOOL_CONTRACTS } from "./pythonFrozen/pythonFrozenToolContracts.js";
import { RUST_PARITY_TOOL_CONTRACTS } from "./rustParity/rustParityToolContracts.js";
import { AI_MODEL_TOOL_CONTRACTS } from "./aiModel/aiModelToolContracts.js";
import { ENGINE_ARCHIVE_TOOL_CONTRACTS } from "./engineArchive/engineArchiveToolContracts.js";
import {
  exportReconKitInputSchema,
  reconKitReportSchema,
} from "../domain/reconKit/reconKit.js";
import type { ToolContract } from "./toolContractTypes.js";
import { annotationsFromEffects, type ToolEffects } from "./toolEffects.js";
import { evidenceResultOf } from "./toolOutputSchemaPrimitives.js";
import { SQLITE_TOOL_CONTRACTS } from "./sqlite/sqliteToolContracts.js";
import { ANALYSIS_VIEW_TOOL_CONTRACTS } from "./analysisViewToolContracts.js";
import { BINARY_DIAGNOSTICS_TOOL_CONTRACTS } from "./native/binaryDiagnosticsToolContracts.js";
import { NATIVE_TOOL_CONTRACTS } from "./native/nativeToolContracts.js";
import { ARTIFACT_TOOL_CONTRACTS } from "./artifactToolContracts.js";
import { MANAGED_TOOL_CONTRACTS } from "./managed/managedToolContracts.js";
import { FIRMWARE_TOOL_CONTRACTS } from "./firmware/firmwareToolContracts.js";
import { ANDROID_TOOL_CONTRACTS } from "./android/androidToolContracts.js";
import { APKTOOL_TOOL_CONTRACTS } from "./apktool/apktoolToolContracts.js";
import { FLUTTER_TOOL_CONTRACTS } from "./flutter/flutterToolContracts.js";
import { JEB_TOOL_CONTRACTS } from "./jeb/jebToolContracts.js";
import { ADB_TOOL_CONTRACTS } from "./adb/adbToolContracts.js";
import { MANAGED_WORKFLOW_TOOL_CONTRACTS } from "./managed/managedWorkflowToolContracts.js";
import { BROWSER_PROVIDER_TOOL_CONTRACTS } from "./browserProviderToolContracts.js";
import { ELECTRON_TOOL_CONTRACTS } from "./javascript/electronToolContracts.js";
import { JAVASCRIPT_RUNTIME_OBSERVATION_TOOL_CONTRACTS } from "./javascript/javascriptRuntimeObservationToolContracts.js";
import { APPLICATION_TOOL_CONTRACTS } from "./applicationToolContracts.js";
import { WEB_SCRIPT_TOOL_CONTRACTS } from "./webScriptToolContracts.js";
import { WEB_RUNTIME_TOOL_CONTRACTS } from "./webRuntimeToolContracts.js";
import { WEB_NETWORK_CAPTURE_TOOL_CONTRACTS } from "./webNetworkCaptureToolContracts.js";
import { JAVASCRIPT_RECOVERY_TOOL_CONTRACTS } from "./javascript/javascriptRecoveryToolContracts.js";
import { OFFICIAL_TOOL_CONTRACTS } from "./officialToolContracts.js";
import { ENHANCED_TOOL_CONTRACTS } from "./enhancedToolContracts.js";
import { SESSION_TOOL_CONTRACTS } from "./sessionToolContracts.js";
import { FRIDA_TOOL_CONTRACTS } from "./fridaToolContracts.js";

const reconKitEffects: ToolEffects = {
  mutatesTarget: false,
  mutatesSession: true,
  writesFilesystem: true,
  launchesProcess: false,
  accessesNetwork: false,
  changesUiState: false,
  mayDiscardData: false,
  executesForeignCode: false,
  mutatesDevice: false,
  idempotent: true,
};

/** Universal 4-Mount Recon Kit & Blueprint Exporter contract. */
export const RECON_KIT_TOOL_CONTRACTS = [
  {
    name: "export_recon_kit",
    title: "Export Recon Kit",
    effects: reconKitEffects,
    annotations: annotationsFromEffects(reconKitEffects),
    returnsTargetContent: true,
    kind: "artifact-provider",
    description:
      "Materialize an ArgonZeroG Universal 4-Mount Recon Kit (RECON_BLUEPRINT.md, generative_ui RECON_EXPLORER.html interactive workbench, and typed recon-kit/ artifacts) for any native binary (ELF/PE/Mach-O, C++ RTTI/VTables, stripped Rust), packaged UI/game archive (Electron ASAR, Unity IL2CPP, Godot .pck, APK/DEX, Web/SourceMap, PE resources), hardware/firmware/protocol artifact (SVD/DBC/UF2/PCAP/Sigrok), or AI model/data artifact (GGUF/SafeTensors/ONNX/TFLite/SQLite) with ready-to-run Harness 1..4 engineering handoff prompts.",
    inputSchema: exportReconKitInputSchema,
    outputSchema: evidenceResultOf(reconKitReportSchema),
    examples: [
      {
        title:
          "Export a Universal 4-Mount Recon Kit for a target binary or artifact",
        input: {
          path: "/artifacts/target_binary.exe",
          mount_override: "auto",
          max_subsystems: 50,
          max_classes: 500,
          max_entries: 500,
          mock_ui_concepts: false,
          include_explorer_html: false,
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];

/** Complete ordered public inventory used by registration and verification. */
export const TOOL_CONTRACTS = [
  ...OFFICIAL_TOOL_CONTRACTS,
  ...ENHANCED_TOOL_CONTRACTS,
  ...NATIVE_TOOL_CONTRACTS,
  ...BINARY_DIAGNOSTICS_TOOL_CONTRACTS,
  ...ANALYSIS_VIEW_TOOL_CONTRACTS,
  ...ARTIFACT_TOOL_CONTRACTS,
  ...EVM_TOOL_CONTRACTS,
  ...GO_TOOL_CONTRACTS,
  ...RUST_CPP_TOOL_CONTRACTS,
  ...PYTHON_FROZEN_TOOL_CONTRACTS,
  ...RUST_PARITY_TOOL_CONTRACTS,
  ...AI_MODEL_TOOL_CONTRACTS,
  ...ENGINE_ARCHIVE_TOOL_CONTRACTS,
  ...RECON_KIT_TOOL_CONTRACTS,
  ...WASM_TOOL_CONTRACTS,
  ...SQLITE_TOOL_CONTRACTS,
  ...CAPTURE_TOOL_CONTRACTS,
  ...SIGNAL_TOOL_CONTRACTS,
  ...MANAGED_TOOL_CONTRACTS,
  ...ANDROID_TOOL_CONTRACTS,
  ...APKTOOL_TOOL_CONTRACTS,
  ...FLUTTER_TOOL_CONTRACTS,
  ...JEB_TOOL_CONTRACTS,
  ...ADB_TOOL_CONTRACTS,
  ...FIRMWARE_TOOL_CONTRACTS,
  ...MANAGED_WORKFLOW_TOOL_CONTRACTS,
  ...BROWSER_PROVIDER_TOOL_CONTRACTS,
  ...ELECTRON_TOOL_CONTRACTS,
  ...JAVASCRIPT_RUNTIME_OBSERVATION_TOOL_CONTRACTS,
  ...APPLICATION_TOOL_CONTRACTS,
  ...WEB_SCRIPT_TOOL_CONTRACTS,
  ...WEB_RUNTIME_TOOL_CONTRACTS,
  ...WEB_NETWORK_CAPTURE_TOOL_CONTRACTS,
  ...JAVASCRIPT_RECOVERY_TOOL_CONTRACTS,
  ...SESSION_TOOL_CONTRACTS,
  ...FRIDA_TOOL_CONTRACTS,
] as const;

/** Resolve a public contract by name while retaining its exact schema types. */
export const toolContract = <
  Name extends (typeof TOOL_CONTRACTS)[number]["name"],
>(
  name: Name,
): Extract<(typeof TOOL_CONTRACTS)[number], { readonly name: Name }> => {
  const contract = TOOL_CONTRACTS.find(
    (
      candidate,
    ): candidate is Extract<
      (typeof TOOL_CONTRACTS)[number],
      { readonly name: Name }
    > => candidate.name === name,
  );
  if (contract === undefined) throw new Error(`Missing tool contract: ${name}`);
  return contract;
};
