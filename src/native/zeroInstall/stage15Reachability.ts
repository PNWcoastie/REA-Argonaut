import type {
  LatentBinaryHazard,
  LatentBinaryHazardCategory,
  LinkerHygieneSummary,
  Stage15LinkageEdgeKind,
  Stage15NodeReachability,
} from "../../domain/native/nativeSubgraph.js";
import { extractValidDlopenLibraryTargets } from "./elfRelocations.js";
import {
  extractLatentBinaryHazards,
  type HazardModelContext,
  type HazardProcedureRef,
} from "./latentHazards.js";

export interface Stage15ElfLinkerMetrics {
  readonly definedDynsymFunctions: number;
  readonly globalDefaultFunctions: number;
  readonly weakFunctions: number;
  readonly intraBinaryPltStubs: number;
  readonly relrRelocationsDecoded: number;
  readonly jniRegisteredMethodsRecovered: number;
  readonly filteredCppLinkerTraps: number;
  readonly exportedFuncAddresses: ReadonlySet<bigint>;
  readonly jniRegisteredAddresses: ReadonlySet<bigint>;
}

export interface Stage15ProcedureRef extends HazardProcedureRef {
  readonly external: boolean;
  readonly callers: ReadonlySet<bigint>;
  readonly callees: ReadonlySet<bigint>;
}

export interface Stage15ModelView extends HazardModelContext {
  readonly entryPoint: bigint;
  readonly sortedProcedures: readonly Stage15ProcedureRef[];
  readonly symbolsByAddr: ReadonlyMap<
    bigint,
    {
      readonly name: string;
      readonly isFunction: boolean;
      readonly dynamic: boolean;
    }
  >;
  readonly rttiAnnotationsByAddr: ReadonlyMap<bigint, string>;
  readonly strings: readonly { readonly value: string }[];
  readonly elfLinkerMetrics?: Stage15ElfLinkerMetrics;
}

const KNOWN_PLUGIN_FACTORY_PATTERN =
  /^(?:create|init|get|HumanTracking|SRIBEngine|HMI|initializeLib|processEvent|compute_)/iu;

const KNOWN_ROOT_ENTRY_NAMES = new Set([
  "main",
  "_start",
  "DllMain",
  "wmain",
  "WinMain",
]);

/**
 * Classifies a procedure inside a subgraph according to the Stage 1.5
 * Multi-Edge Reachability model (Class I Live Wired vs Class II Dead Fossil
 * or Cloned-Inline Suspect).
 */
export function computeStage15NodeReachability(
  proc: Stage15ProcedureRef,
  model: Stage15ModelView,
  nodeHazards: readonly LatentBinaryHazard[],
  allProcedures: readonly Stage15ProcedureRef[] = model.sortedProcedures,
  activeHazardCategoriesCache?: Map<bigint, Set<LatentBinaryHazardCategory>>,
): Stage15NodeReachability {
  const callerCount = proc.callers.size;
  const sym = model.symbolsByAddr.get(proc.address);
  const metrics = model.elfLinkerMetrics;
  const isExported =
    metrics !== undefined
      ? metrics.exportedFuncAddresses.has(proc.address)
      : !proc.external && !proc.thunk && Boolean(sym?.dynamic);

  const linkageEdges: Stage15LinkageEdgeKind[] = [];
  const isJniJavaExport =
    proc.name.startsWith("Java_") || proc.name === "JNI_OnLoad";
  const isJniRegisterNatives =
    metrics?.jniRegisteredAddresses.has(proc.address) ?? false;
  const isVtableDispatch =
    model.rttiAnnotationsByAddr.has(proc.address) ||
    /__vslot_\d+_/u.test(proc.name);
  const isEntryRoot =
    proc.address === model.entryPoint || KNOWN_ROOT_ENTRY_NAMES.has(proc.name);

  if (isJniJavaExport) {
    linkageEdges.push("jni_java_export");
  }
  if (isJniRegisterNatives) {
    linkageEdges.push("jni_onload_register_natives");
  }
  if (isVtableDispatch) {
    linkageEdges.push("vtable_dispatch");
  }

  const dlopenTargets = extractValidDlopenLibraryTargets(model.strings);
  const isPluginFactoryEntry =
    isExported &&
    !isJniJavaExport &&
    (dlopenTargets.length > 0 || KNOWN_PLUGIN_FACTORY_PATTERN.test(proc.name)) &&
    KNOWN_PLUGIN_FACTORY_PATTERN.test(proc.name);

  if (isPluginFactoryEntry) {
    linkageEdges.push("dlopen_plugin_entry");
  } else if (isExported && !isJniJavaExport) {
    linkageEdges.push("dynsym_export");
  }

  if (callerCount > 0 || isEntryRoot) {
    linkageEdges.push("internal_call_chain");
  }

  const hasLiveEntryEdge =
    callerCount > 0 ||
    isEntryRoot ||
    isJniJavaExport ||
    isJniRegisterNatives ||
    isVtableDispatch ||
    isPluginFactoryEntry;

  if (hasLiveEntryEdge) {
    return {
      classification: "class_i_live_wired",
      intra_binary_caller_count: callerCount,
      is_exported_global_default: isExported,
      linkage_edges: linkageEdges,
      remediation_action:
        nodeHazards.length > 0
          ? "Prioritize Stage 2 #![forbid(unsafe_code)] Safe Rust reconstruction: live wired execution path with active hazards."
          : "Live wired execution path; maintain bounds and ABI invariants during Safe Rust reconstruction.",
    };
  }

  linkageEdges.push(isExported ? "unreferenced_export" : "unreferenced_internal");

  let isClonedInlineSuspect = false;
  if (nodeHazards.length > 0) {
    const nodeCategories = new Set(nodeHazards.map((h) => h.category));
    for (const other of allProcedures) {
      if (other.address === proc.address || other.callers.size === 0) continue;
      let otherCategories = activeHazardCategoriesCache?.get(other.address);
      if (otherCategories === undefined) {
        const otherHazards = extractLatentBinaryHazards(other, model);
        otherCategories = new Set(otherHazards.map((h) => h.category));
        activeHazardCategoriesCache?.set(other.address, otherCategories);
      }
      for (const cat of nodeCategories) {
        if (otherCategories.has(cat)) {
          isClonedInlineSuspect = true;
          break;
        }
      }
      if (isClonedInlineSuspect) break;
    }
  }

  if (isClonedInlineSuspect) {
    return {
      classification: "class_ii_cloned_inline_suspect",
      intra_binary_caller_count: callerCount,
      is_exported_global_default: isExported,
      linkage_edges: linkageEdges,
      remediation_action:
        "Audit active callers or inlined/threaded clones sharing matching hazard classes, then strip this dead fossil via -fvisibility=hidden and -Wl,--gc-sections.",
    };
  }

  return {
    classification: "class_ii_dead_fossil",
    intra_binary_caller_count: callerCount,
    is_exported_global_default: isExported,
    linkage_edges: linkageEdges,
    remediation_action:
      "Compile with -fvisibility=hidden -ffunction-sections and link with -Wl,--gc-sections to strip unreferenced code and prevent Class III zombie activation.",
  };
}

/**
 * Computes binary-wide linker hygiene, symbol-visibility bloat, and Stage 1.5
 * dynamic linkage recovery telemetry for a decompile_subgraph response.
 */
export function computeLinkerHygieneSummary(
  model: Stage15ModelView,
): LinkerHygieneSummary {
  const metrics = model.elfLinkerMetrics;
  const definedDynsym = metrics?.definedDynsymFunctions ?? 0;
  const globalDefault = metrics?.globalDefaultFunctions ?? 0;
  const ratio =
    definedDynsym > 0
      ? Math.round((globalDefault / definedDynsym) * 10_000) / 10_000
      : 0;
  const dlopenTargets = extractValidDlopenLibraryTargets(model.strings);

  return {
    defined_dynsym_functions: definedDynsym,
    global_default_functions: globalDefault,
    global_default_ratio: ratio,
    weak_functions: metrics?.weakFunctions ?? 0,
    intra_binary_plt_stubs: metrics?.intraBinaryPltStubs ?? 0,
    relr_relocations_decoded: metrics?.relrRelocationsDecoded ?? 0,
    jni_registered_methods_recovered:
      metrics?.jniRegisteredMethodsRecovered ?? 0,
    dlopen_targets: dlopenTargets,
    filtered_cpp_linker_traps: metrics?.filteredCppLinkerTraps ?? 0,
    fvisibility_hidden_likely_omitted: definedDynsym >= 10 && ratio > 0.5,
  };
}
