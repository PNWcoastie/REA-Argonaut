import {
  inspectPythonFrozenBinaryInputSchema,
  pythonFrozenBinarySchema,
} from "../../domain/pythonFrozen/pythonFrozenBinary.js";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import { evidenceResultOf } from "../toolOutputSchemaPrimitives.js";

/** Static frozen Python & .pyc metadata is independent of active native-analysis providers and host toolchains. */
export const PYTHON_FROZEN_TOOL_CONTRACTS = [
  {
    name: "inspect_python_frozen_binary",
    ...toolContractMetadata("inspect_python_frozen_binary"),
    kind: "artifact-provider",
    description:
      "Inspect a frozen Python executable (PyInstaller CArchive/PKG/PYZ ELF, PE, or Mach-O) or standalone .pyc bytecode file in pure TypeScript without executing target code or requiring a Python runtime. Recovers PyInstaller MEI cookies, Python version, entry scripts, bundled modules, native extensions, CArchive table-of-contents entries, and .pyc marshal code object summaries (names, varnames, string constants, and imported module names).",
    inputSchema: inspectPythonFrozenBinaryInputSchema,
    outputSchema: evidenceResultOf(pythonFrozenBinarySchema),
    examples: [
      {
        title: "Inspect a PyInstaller executable or .pyc bytecode artifact",
        input: {
          path: "/artifacts/frozen_app",
          max_toc_entries: 1000,
          max_code_objects: 200,
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
