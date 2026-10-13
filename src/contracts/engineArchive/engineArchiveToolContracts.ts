import {
  engineArchiveReportSchema,
  inspectEngineArchiveInputSchema,
} from "../../domain/engineArchive/engineArchive.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Pure-TS inspection for Unity IL2CPP global-metadata.dat and Godot .pck archives. */
export const ENGINE_ARCHIVE_TOOL_CONTRACTS = [
  {
    name: "inspect_engine_archive",
    ...toolContractMetadata("inspect_engine_archive"),
    kind: "artifact-provider",
    description:
      "Inspect a Unity IL2CPP global-metadata.dat binary (versions 24..31) or Godot Engine resource pack (.pck v1/v2/v3) in pure TypeScript without external game-engine toolchains or target execution. Recovers IL2CPP image assemblies, C# TypeDefinitions (namespaces, names, value/enum flags, method/field counts), MethodDefinitions (declaring types, parameter counts, metadata tokens), string literals, and Godot res:// packed file entries (offsets, sizes, MD5 digests, encryption flags).",
    inputSchema: inspectEngineArchiveInputSchema,
    outputSchema: evidenceResultOf(engineArchiveReportSchema),
    examples: [
      {
        title: "Inspect Unity IL2CPP global-metadata.dat or Godot .pck archive",
        input: {
          path: "/artifacts/global-metadata.dat",
          max_types: 1000,
          max_methods: 2000,
          max_strings: 1000,
          max_files: 2000,
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
