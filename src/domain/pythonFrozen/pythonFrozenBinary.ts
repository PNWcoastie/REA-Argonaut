import { z } from "zod";
import type { ProviderIdentity } from "../../application/AnalysisProvider.js";

/** Provider identity committed by the pure-TS Frozen Python & .pyc forensic engine. */
export const PYTHON_FROZEN_PROVIDER_IDENTITY: ProviderIdentity = Object.freeze({
  id: "argon-python-frozen-forensics",
  name: "ArgonZeroG Frozen Python & Bytecode Forensic Inspector",
  version: "1.0.0",
});

export const inspectPythonFrozenBinaryInputSchema = z
  .object({
    path: z
      .string()
      .min(1)
      .describe(
        "Absolute filesystem path to a frozen Python executable (PyInstaller ELF/PE/Mach-O) or standalone .pyc bytecode file.",
      ),
    max_toc_entries: z
      .number()
      .int()
      .min(1)
      .max(5000)
      .default(1000)
      .describe(
        "Maximum number of PyInstaller CArchive/PYZ table-of-contents entries to return (default 1000).",
      ),
    max_code_objects: z
      .number()
      .int()
      .min(1)
      .max(1000)
      .default(200)
      .describe(
        "Maximum number of Python marshal code objects to return when inspecting .pyc bytecode (default 200).",
      ),
  })
  .strict();

export type InspectPythonFrozenBinaryInput = z.infer<
  typeof inspectPythonFrozenBinaryInputSchema
>;

export const pyinstallerTocEntrySchema = z
  .object({
    name: z.string().min(1),
    type_code: z.string().min(1),
    type_description: z.string().min(1),
    data_offset: z.number().int().nonnegative(),
    compressed_size: z.number().int().nonnegative(),
    uncompressed_size: z.number().int().nonnegative(),
    is_compressed: z.boolean(),
  })
  .strict();

export type PyinstallerTocEntry = z.infer<typeof pyinstallerTocEntrySchema>;

export const pycCodeObjectSummarySchema = z
  .object({
    co_name: z.string(),
    co_filename: z.string(),
    co_firstlineno: z.number().int().nonnegative(),
    argcount: z.number().int().nonnegative(),
    names: z.array(z.string()),
    varnames: z.array(z.string()),
    string_constants: z.array(z.string()),
    bytecode_length: z.number().int().nonnegative(),
  })
  .strict();

export type PycCodeObjectSummary = z.infer<typeof pycCodeObjectSummarySchema>;

export const pythonFrozenBinarySchema = z
  .object({
    artifact: z
      .object({
        path: z.string().min(1),
        sha256: z.string().regex(/^[0-9a-f]{64}$/),
        size_bytes: z.number().int().nonnegative(),
      })
      .strict(),
    container_format: z.enum([
      "pyinstaller-executable",
      "pyc-bytecode",
      "none",
    ]),
    pyinstaller: z
      .object({
        detected: z.boolean(),
        cookie_offset: z.number().int().nonnegative().nullable(),
        archive_size: z.number().int().nonnegative().nullable(),
        toc_offset: z.number().int().nonnegative().nullable(),
        toc_length: z.number().int().nonnegative().nullable(),
        python_version: z.string().nullable(),
        pylib_name: z.string().nullable(),
        entry_scripts: z.array(z.string()),
        native_extensions: z.array(z.string()),
        bundled_modules: z.array(z.string()),
        toc_entries: z.array(pyinstallerTocEntrySchema),
        pyz_header: z
          .object({
            offset: z.number().int().nonnegative(),
            python_magic_hex: z.string().min(1),
            toc_offset: z.number().int().nonnegative(),
          })
          .strict()
          .nullable(),
      })
      .strict(),
    pyc: z
      .object({
        detected: z.boolean(),
        magic_number: z.number().int().nonnegative().nullable(),
        magic_hex: z.string().nullable(),
        python_version_estimate: z.string().nullable(),
        pep552_flags: z.number().int().nonnegative().nullable(),
        source_timestamp: z.number().int().nonnegative().nullable(),
        source_size: z.number().int().nonnegative().nullable(),
        imported_names: z.array(z.string()),
        code_objects: z.array(pycCodeObjectSummarySchema),
      })
      .strict(),
    limitations: z.array(z.string()),
  })
  .strict();

export type PythonFrozenBinaryReport = z.infer<typeof pythonFrozenBinarySchema>;
