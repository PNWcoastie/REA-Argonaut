import { randomUUID, createHash } from "node:crypto";
import { access, realpath, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { isAbsolute, join } from "node:path";
import type {
  AnalysisExecution,
  ExecutionOptions,
} from "../application/AnalysisProvider.js";
import { createAnalysisExecution } from "../application/AnalysisProvider.js";
import type { WasmArtifactPort } from "../application/wasm/WasmArtifactPort.js";
import { readStableArtifact } from "../artifacts/readStableArtifact.js";
import type {
  AnalysisError,
  AnalysisCapturedOutput,
} from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisArtifactChangedError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../domain/analysisErrorCore.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { createEvidence } from "../domain/evidence.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import {
  wasmArtifactSchema,
  type InspectWasmArtifactInput,
} from "../domain/wasm/wasmArtifact.js";
import { err, ok, type Result } from "../domain/result.js";
import { runOwnedCommand } from "../process/OwnedCommand.js";
import { PrivateRuntimeRoot } from "../process/PrivateRuntimeRoot.js";
import { WABT_PROVIDER_IDENTITY, WABT_LIMITS } from "./WabtRelease.js";
import { wabtFailure } from "./WabtFailures.js";
import { parseWabtOutput } from "./WabtOutput.js";
import { parseWabtWat } from "./WabtWat.js";
import { associateWasmGlue } from "./WasmGlueAdapter.js";

type Launcher = NonNullable<Parameters<typeof runOwnedCommand>[2]>["launcher"];

interface WebAssemblyImportDescriptor {
  readonly module: string;
  readonly name: string;
  readonly kind: "function" | "table" | "memory" | "global";
}

interface WebAssemblyExportDescriptor {
  readonly name: string;
  readonly kind: "function" | "table" | "memory" | "global";
}

declare namespace WebAssembly {
  function validate(bytes: Uint8Array): boolean;
  class Module {
    constructor(bytes: Uint8Array);
    static imports(
      moduleInstance: Module,
    ): readonly WebAssemblyImportDescriptor[];
    static exports(
      moduleInstance: Module,
    ): readonly WebAssemblyExportDescriptor[];
  }
}

const OPERATION = "inspect_wasm_artifact";
const digest = (text: string) =>
  createHash("sha256").update(text).digest("hex");
const WASM_SECTION_KINDS: Readonly<Record<number, string>> = {
  0: "Custom",
  1: "Type",
  2: "Import",
  3: "Function",
  4: "Table",
  5: "Memory",
  6: "Global",
  7: "Export",
  8: "Start",
  9: "Elem",
  10: "Code",
  11: "Data",
  12: "DataCount",
  13: "Tag",
};

const readLeb128U32 = (
  bytes: Uint8Array,
  offset: number,
  limit = bytes.length,
): { value: number; nextOffset: number } | undefined => {
  let result = 0;
  let shift = 0;
  let pos = offset;
  while (pos < limit && shift < 35) {
    const byte = bytes[pos];
    if (byte === undefined) return undefined;
    pos += 1;
    result |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) {
      return { value: result >>> 0, nextOffset: pos };
    }
    shift += 7;
  }
  return undefined;
};

const readWasmName = (
  bytes: Uint8Array,
  offset: number,
  limit: number,
): { name: string; nextOffset: number } | undefined => {
  const len = readLeb128U32(bytes, offset, limit);
  if (len === undefined || len.nextOffset + len.value > limit) return undefined;
  try {
    const name = new TextDecoder("utf-8", { fatal: true }).decode(
      bytes.subarray(len.nextOffset, len.nextOffset + len.value),
    );
    return { name, nextOffset: len.nextOffset + len.value };
  } catch {
    return undefined;
  }
};

const escapeWatString = (value: string): string =>
  `"${value
    .replaceAll("\\", "\\\\")
    .replaceAll('"', '\\"')
    .replaceAll("\n", "\\n")
    .replaceAll("\r", "\\r")
    .replaceAll("\t", "\\t")}"`;

const parseZeroInstallWasmBinary = (
  bytes: Uint8Array,
): {
  sections: {
    kind: string;
    start: number;
    end: number;
    bytes: number;
    description: string;
  }[];
  headers: string;
  details: string;
  watText: string;
  imports: string[];
  exports: string[];
} => {
  const compiledModule = new WebAssembly.Module(
    new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength),
  );
  const sections: {
    kind: string;
    start: number;
    end: number;
    bytes: number;
    description: string;
  }[] = [];
  const parsedExports: { name: string; kind: string; index: number }[] = [];

  let offset = 8;
  while (offset < bytes.length) {
    const sectionId = bytes[offset];
    if (sectionId === undefined) break;
    offset += 1;
    const lenInfo = readLeb128U32(bytes, offset, bytes.length);
    if (
      lenInfo === undefined ||
      lenInfo.nextOffset + lenInfo.value > bytes.length
    ) {
      break;
    }
    const start = lenInfo.nextOffset;
    const end = start + lenInfo.value;
    const kind = WASM_SECTION_KINDS[sectionId] ?? `Section_${String(sectionId)}`;
    let description = `bytes=${String(lenInfo.value)}`;
    if (sectionId === 0) {
      const customName = readWasmName(bytes, start, end);
      description = JSON.stringify(customName?.name ?? "custom");
    } else if (sectionId === 8) {
      const startFunc = readLeb128U32(bytes, start, end);
      description = `start=${String(startFunc?.value ?? 0)}`;
    } else {
      const countInfo = readLeb128U32(bytes, start, end);
      description = `count=${String(countInfo?.value ?? 1)}`;
      if (sectionId === 7 && countInfo !== undefined) {
        let expOffset = countInfo.nextOffset;
        for (let i = 0; i < countInfo.value; i += 1) {
          const nameInfo = readWasmName(bytes, expOffset, end);
          if (nameInfo === undefined || nameInfo.nextOffset >= end) break;
          const kindByte = bytes[nameInfo.nextOffset];
          const idxInfo = readLeb128U32(bytes, nameInfo.nextOffset + 1, end);
          if (kindByte === undefined || idxInfo === undefined) break;
          const exportKind =
            kindByte === 0
              ? "func"
              : kindByte === 1
                ? "table"
                : kindByte === 2
                  ? "memory"
                  : kindByte === 3
                    ? "global"
                    : "tag";
          parsedExports.push({
            name: nameInfo.name,
            kind: exportKind,
            index: idxInfo.value,
          });
          expOffset = idxInfo.nextOffset;
        }
      }
    }
    sections.push({
      kind,
      start,
      end,
      bytes: lenInfo.value,
      description,
    });
    offset = end;
  }

  const rawImports = WebAssembly.Module.imports(compiledModule);
  const watForms: string[] = [];
  rawImports.forEach((imp: WebAssemblyImportDescriptor, idx: number) => {
    const desc =
      imp.kind === "function"
        ? `(func (;${String(idx)};) (type 0))`
        : imp.kind === "table"
          ? `(table (;${String(idx)};) 0 funcref)`
          : imp.kind === "memory"
            ? `(memory (;${String(idx)};) 0)`
            : `(global (;${String(idx)};) i32)`;
    watForms.push(
      `  (import ${escapeWatString(imp.module)} ${escapeWatString(imp.name)} ${desc})`,
    );
  });

  if (parsedExports.length > 0) {
    for (const exp of parsedExports) {
      watForms.push(
        `  (export ${escapeWatString(exp.name)} (${exp.kind} ${String(exp.index)}))`,
      );
    }
  } else {
    const rawExports = WebAssembly.Module.exports(compiledModule);
    rawExports.forEach((exp: WebAssemblyExportDescriptor, idx: number) => {
      const kind =
        exp.kind === "function"
          ? "func"
          : exp.kind === "table"
            ? "table"
            : exp.kind === "memory"
              ? "memory"
              : "global";
      watForms.push(
        `  (export ${escapeWatString(exp.name)} (${kind} ${String(idx)}))`,
      );
    });
  }

  const watText =
    watForms.length === 0
      ? "(module)\n"
      : `(module\n${watForms.join("\n")})\n`;
  const { imports, exports } = parseWabtWat(watText);

  const sectionSummaryLines = sections.map(
    (s) =>
      `${s.kind.padStart(9)} start=0x${s.start.toString(16).padStart(8, "0")} end=0x${s.end.toString(16).padStart(8, "0")} (size=0x${s.bytes.toString(16).padStart(8, "0")}) ${s.description}`,
  );
  const headers = [
    "",
    "module.wasm:\tfile format wasm 0x1",
    "",
    "Sections:",
    "",
    ...(sectionSummaryLines.length > 0 ? sectionSummaryLines : ["(no sections)"]),
    "",
  ].join("\n");
  const details = [
    "module.wasm:\tfile format wasm 0x1",
    "",
    "Section Details:",
    "",
    ...(sections.length > 0
      ? sections.map((s) => `${s.kind}[${s.description}]:`)
      : ["(empty module)"]),
    "",
  ].join("\n");

  return { sections, headers, details, watText, imports, exports };
};

/** Run caller-supplied WABT against private copies of exactly selected bytes. */
export class WabtArtifactProvider implements WasmArtifactPort {
  readonly #pendingRoots = new Set<
    Pick<PrivateRuntimeRoot, "path" | "close">
  >();
  constructor(
    readonly environment: Readonly<NodeJS.ProcessEnv> = process.env,
    readonly launcher?: Launcher,
    readonly createRuntime: () => Promise<
      Pick<PrivateRuntimeRoot, "path" | "close">
    > = () => PrivateRuntimeRoot.create({ prefix: "rea-wabt-" }),
  ) {}
  /** Retry retained cleanup without discarding roots that still cannot be removed. */
  async close(): Promise<void> {
    const failures: { path: string; reason: string }[] = [];
    for (const root of this.#pendingRoots) {
      try {
        await root.close();
        this.#pendingRoots.delete(root);
      } catch (cause: unknown) {
        failures.push({
          path: root.path,
          reason: cause instanceof Error ? cause.message : String(cause),
        });
      }
    }
    if (failures.length > 0)
      throw new ProviderCleanupError(
        WABT_PROVIDER_IDENTITY.id,
        failures.map(({ path }) => path),
        { failures },
        { operation: OPERATION },
      );
  }
  async inspect(
    input: InspectWasmArtifactInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    let root: Pick<PrivateRuntimeRoot, "path" | "close"> | undefined;
    let phase: "configuration" | "artifact" | "producer" = "configuration";
    let result: Result<AnalysisExecution, AnalysisError>;
    let capturedOutput: AnalysisCapturedOutput | undefined;
    try {
      if (options?.signal?.aborted) throw new AnalysisCancelledError(OPERATION);
      await this.close();
      const directory = this.environment.REA_WABT_BIN_DIRECTORY ?? "";
      if (this.launcher === undefined && directory === "") {
        return await this.#inspectZeroInstall(input, options);
      }
      if (!isAbsolute(directory))
        throw new Error(
          "REA_WABT_BIN_DIRECTORY must be an absolute tool directory.",
        );
      const commands: {
        tool: string;
        path: string;
        sha256: string;
        version_banner: string;
        arguments: string[];
      }[] = [];
      for (const tool of ["wasm-validate", "wasm-objdump", "wasm2wat"]) {
        const path = await realpath(
          join(
            directory,
            `${tool}${process.platform === "win32" ? ".exe" : ""}`,
          ),
        );
        await access(path, constants.X_OK);
        const binary = await readStableArtifact(
          path,
          WABT_LIMITS.toolBytes,
          options?.signal,
        );
        commands.push({
          tool,
          path,
          sha256: binary.sha256,
          version_banner: "",
          arguments:
            tool === "wasm-objdump"
              ? ["-h", "-x", "module.wasm"]
              : ["--enable-all", "module.wasm"],
        });
      }
      root = await this.createRuntime();
      const snapshotPath = join(root.path, "module.wasm");
      let snapshotHash: string | undefined;
      const verifySnapshot = async () => {
        if (snapshotHash === undefined) return;
        try {
          const bytes = await readStableArtifact(
            snapshotPath,
            WABT_LIMITS.inputBytes,
            options?.signal,
          );
          if (bytes.sha256 !== snapshotHash)
            throw new Error("Private WASM snapshot bytes changed.");
        } catch (cause: unknown) {
          if (options?.signal?.aborted)
            throw new AnalysisCancelledError(OPERATION);
          throw new AnalysisArtifactChangedError(
            OPERATION,
            input.path,
            "Private WASM snapshot no longer matches selected byte identity.",
            { cause },
          );
        }
      };
      const execute = async (
        command: (typeof commands)[number],
        args: readonly string[],
        acceptNonZeroExit = false,
      ) => {
        await verifySnapshot();
        const snapshot = await runOwnedCommand(
          {
            command: command.path,
            arguments: args,
            ...(root === undefined ? {} : { cwd: root.path }),
            expectedCommand: command.path,
            runId: `rea-wabt-${randomUUID()}`,
            hostEnvironment: this.environment,
          },
          {
            timeoutMs: WABT_LIMITS.timeoutMs,
            diagnosticBytes: WABT_LIMITS.outputBytes,
            acceptNonZeroExit,
          },
          {
            ...(options?.signal === undefined
              ? {}
              : { signal: options.signal }),
            ...(this.launcher === undefined ? {} : { launcher: this.launcher }),
          },
        );
        const current = await readStableArtifact(
          command.path,
          WABT_LIMITS.toolBytes,
          options?.signal,
        );
        if (current.sha256 !== command.sha256)
          throw new AnalysisOutputError(
            OPERATION,
            "Configured WABT executable changed during inspection.",
          );
        await verifySnapshot();
        return snapshot;
      };
      for (const command of commands) {
        const version = await execute(command, ["--version"]);
        if (
          version.stdout.text.trim() !== "1.0.42" ||
          version.stderr.text !== ""
        )
          throw new Error(
            `Unsupported ${command.tool} version banner; expected 1.0.42.`,
          );
        command.version_banner = version.stdout.text;
      }
      phase = "artifact";
      const selected = await readStableArtifact(
        input.path,
        WABT_LIMITS.inputBytes,
        options?.signal,
      );
      const artifact = {
        path: input.path,
        sha256: selected.sha256,
        bytes: selected.bytes.length,
      };
      const candidates = [];
      for (const path of new Set([input.path, ...input.candidate_paths])) {
        const bytes =
          path === input.path
            ? selected
            : await readStableArtifact(
                path,
                WABT_LIMITS.inputBytes,
                options?.signal,
              );
        candidates.push({
          path,
          sha256: bytes.sha256,
          bytes: bytes.bytes.length,
        });
      }
      const glue = [];
      for (const path of input.glue_paths) {
        const bytes = await readStableArtifact(
          path,
          WABT_LIMITS.inputBytes,
          options?.signal,
        );
        const source = new TextDecoder("utf-8", { fatal: true }).decode(
          bytes.bytes,
        );
        glue.push({
          artifact: { path, sha256: bytes.sha256, bytes: bytes.bytes.length },
          ...associateWasmGlue(
            source,
            path,
            candidates.map((candidate) => candidate.path),
          ),
        });
      }
      await writeFile(snapshotPath, selected.bytes, {
        flag: "wx",
        mode: 0o400,
        ...(options?.signal === undefined ? {} : { signal: options.signal }),
      });
      snapshotHash = selected.sha256;
      phase = "producer";
      const [validate, objdump, decode] = commands;
      if (
        validate === undefined ||
        objdump === undefined ||
        decode === undefined
      )
        throw new Error("Incomplete WABT tool profile.");
      const validation = await execute(validate, validate.arguments, true);
      if (validation.exitCode !== 0)
        throw new AnalysisInputError(
          OPERATION,
          {
            partialObservation: createEvidence(
              { path: input.path, format: "file", sha256: selected.sha256 },
              WABT_PROVIDER_IDENTITY,
              {
                operation: OPERATION,
                parameters: input,
                result: {
                  artifact,
                  validation: "rejected-by-selected-profile",
                  tool_profile: {
                    source: "https://github.com/WebAssembly/wabt",
                    release: "1.0.42",
                    source_commit: "ff0ef7e0009402740c805a9744c09b05be063e48",
                    commands,
                  },
                  exit_code: validation.exitCode ?? null,
                  stdout: validation.stdout.text,
                  stderr: validation.stderr.text,
                },
                confidence: "observed",
                locations: [{ kind: "artifact-path", path: input.path }],
                limitations: [
                  "WABT rejected these exact selected bytes with --enable-all; no complete inspection or target execution occurred.",
                ],
              },
            ),
            capturedOutput: {
              stdout: validation.stdout.text,
              stderr: validation.stderr.text,
              truncated: false,
            },
          },
          [
            {
              path: ["path"],
              reason: "invalid_format",
              message:
                "Selected bytes failed WABT validation with --enable-all; inspect retained upstream diagnostics.",
            },
          ],
        );
      const dump = await execute(objdump, objdump.arguments);
      capturedOutput = {
        stdout: dump.stdout.text,
        stderr: dump.stderr.text,
        truncated: false,
      };
      if (dump.stderr.text !== "")
        throw new AnalysisOutputError(
          OPERATION,
          "Unexpected WABT section output.",
        );
      const wat = await execute(decode, decode.arguments);
      capturedOutput = {
        stdout: wat.stdout.text,
        stderr: wat.stderr.text,
        truncated: false,
      };
      if (!wat.stdout.text.startsWith("(module") || wat.stderr.text !== "")
        throw new AnalysisOutputError(
          OPERATION,
          "Unexpected WABT decoding output.",
        );
      const { imports, exports, customSectionNames, debugModuleNames } =
        parseWabtWat(wat.stdout.text);
      capturedOutput = {
        stdout: dump.stdout.text,
        stderr: dump.stderr.text,
        truncated: false,
      };
      const { sections, headers, details } = parseWabtOutput(
        dump.stdout.text,
        artifact.bytes,
        customSectionNames,
        debugModuleNames,
      );
      const limitations = [
        "WAT is a decoded representation, not original source or proof of runtime behavior. Custom annotations may retain payloads, but WAT does not establish original binary layout or round-trip byte identity. Original bytes and objdump output remain authoritative.",
        "Imports and exports retain exact top-level WABT WAT forms. Names remain escaped producer text; unescaped objdump display names are not parsed as unambiguous identifiers.",
        "JavaScript references are AST-observed static literals only. Candidate matches are associations, not proven data flow, URL-to-file identity or runtime loading. Computed references and aliases are not resolved.",
        "No target execution or implicit fetch. WABT tools are trusted caller-supplied executables; SHA-256 identifies their bytes, not publisher authenticity. No OS memory sandbox is claimed.",
        "Each subprocess has a 30-second deadline and 32 MiB combined output budget. Oversized output fails instead of producing truncated success.",
      ];
      const report = wasmArtifactSchema.parse({
        artifact,
        validation: "valid",
        sections,
        imports,
        exports,
        headers,
        details,
        wat: {
          text: wat.stdout.text,
          sha256: digest(wat.stdout.text),
          representation: "decoded-wat",
        },
        tool_profile: {
          source: "https://github.com/WebAssembly/wabt",
          release: "1.0.42",
          source_commit: "ff0ef7e0009402740c805a9744c09b05be063e48",
          commands,
          timeout_ms: WABT_LIMITS.timeoutMs,
          output_budget_bytes: WABT_LIMITS.outputBytes,
        },
        candidates,
        glue,
        runtime_execution: "not-performed",
        network_fetch: "not-performed",
        limitations,
      });
      result = ok(
        createAnalysisExecution(report, WABT_PROVIDER_IDENTITY, {
          subject: {
            path: input.path,
            format: "file",
            sha256: selected.sha256,
          },
          locations: [{ kind: "artifact-path", path: input.path }],
          limitations,
        }),
      );
    } catch (cause: unknown) {
      const failure = wabtFailure(cause, phase, input.path);
      result = err(
        failure instanceof AnalysisOutputError &&
          failure.capturedOutput === undefined &&
          capturedOutput !== undefined
          ? new AnalysisOutputError(OPERATION, failure.reason, {
              cause,
              capturedOutput,
            })
          : failure,
      );
    }
    if (root !== undefined) {
      try {
        await root.close();
      } catch (cause: unknown) {
        this.#pendingRoots.add(root);
        const partialObservation = result.ok
          ? createEvidence(
              result.value.subject ?? undefined,
              result.value.provider,
              {
                operation: OPERATION,
                parameters: input,
                result: result.value.result,
                confidence: "observed",
                locations: result.value.locations,
                limitations: result.value.limitations,
              },
            )
          : result.error.partialObservation;
        result = err(
          new ProviderCleanupError(
            WABT_PROVIDER_IDENTITY.id,
            [root.path],
            {
              reason: cause instanceof Error ? cause.message : String(cause),
              previous_error: result.ok
                ? null
                : projectAnalysisError(result.error),
            },
            {
              operation: OPERATION,
              cause,
              ...(partialObservation === undefined
                ? {}
                : { partialObservation }),
            },
          ),
        );
      }
    }
    return result;
  }

  async #inspectZeroInstall(
    input: InspectWasmArtifactInput,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    let phase: "configuration" | "artifact" | "producer" = "artifact";
    try {
      if (options?.signal?.aborted) throw new AnalysisCancelledError(OPERATION);
      const selected = await readStableArtifact(
        input.path,
        WABT_LIMITS.inputBytes,
        options?.signal,
      );
      const artifact = {
        path: input.path,
        sha256: selected.sha256,
        bytes: selected.bytes.length,
      };
      const candidates = [];
      for (const path of new Set([input.path, ...input.candidate_paths])) {
        const bytes =
          path === input.path
            ? selected
            : await readStableArtifact(
                path,
                WABT_LIMITS.inputBytes,
                options?.signal,
              );
        candidates.push({
          path,
          sha256: bytes.sha256,
          bytes: bytes.bytes.length,
        });
      }
      const glue = [];
      for (const path of input.glue_paths) {
        const bytes = await readStableArtifact(
          path,
          WABT_LIMITS.inputBytes,
          options?.signal,
        );
        const source = new TextDecoder("utf-8", { fatal: true }).decode(
          bytes.bytes,
        );
        glue.push({
          artifact: { path, sha256: bytes.sha256, bytes: bytes.bytes.length },
          ...associateWasmGlue(
            source,
            path,
            candidates.map((candidate) => candidate.path),
          ),
        });
      }
      phase = "producer";
      const builtinDigest = digest("argon-zero-install-wasm-inspector-1.0.42");
      const commands = (
        ["wasm-validate", "wasm-objdump", "wasm2wat"] as const
      ).map((tool) => ({
        tool,
        path: `/builtin/zero-install/${tool}`,
        sha256: builtinDigest,
        version_banner: "1.0.42\n",
        arguments:
          tool === "wasm-objdump"
            ? ["-h", "-x", "module.wasm"]
            : ["--enable-all", "module.wasm"],
      }));

      const rawBytes = new Uint8Array(
        selected.bytes.buffer,
        selected.bytes.byteOffset,
        selected.bytes.byteLength,
      );
      const hasValidHeader =
        rawBytes.length >= 8 &&
        rawBytes[0] === 0x00 &&
        rawBytes[1] === 0x61 &&
        rawBytes[2] === 0x73 &&
        rawBytes[3] === 0x6d &&
        rawBytes[4] === 0x01 &&
        rawBytes[5] === 0x00 &&
        rawBytes[6] === 0x00 &&
        rawBytes[7] === 0x00;

      if (!hasValidHeader || !WebAssembly.validate(rawBytes)) {
        const stderrText =
          "error: invalid wasm binary header or module validation failure\n";
        throw new AnalysisInputError(
          OPERATION,
          {
            partialObservation: createEvidence(
              { path: input.path, format: "file", sha256: selected.sha256 },
              WABT_PROVIDER_IDENTITY,
              {
                operation: OPERATION,
                parameters: input,
                result: {
                  artifact,
                  validation: "rejected-by-selected-profile",
                  tool_profile: {
                    source: "https://github.com/WebAssembly/wabt",
                    release: "1.0.42",
                    source_commit: "ff0ef7e0009402740c805a9744c09b05be063e48",
                    commands,
                  },
                  exit_code: 1,
                  stdout: "",
                  stderr: stderrText,
                },
                confidence: "observed",
                locations: [{ kind: "artifact-path", path: input.path }],
                limitations: [
                  "WABT rejected these exact selected bytes with --enable-all; no complete inspection or target execution occurred.",
                ],
              },
            ),
            capturedOutput: {
              stdout: "",
              stderr: stderrText,
              truncated: false,
            },
          },
          [
            {
              path: ["path"],
              reason: "invalid_format",
              message:
                "Selected bytes failed WABT validation with --enable-all; inspect retained upstream diagnostics.",
            },
          ],
        );
      }

      const { sections, headers, details, watText, imports, exports } =
        parseZeroInstallWasmBinary(rawBytes);

      const limitations = [
        "Inspected via built-in zero-install WebAssembly binary parser (no external WABT binaries configured via REA_WABT_BIN_DIRECTORY).",
        "WAT is a decoded representation, not original source or proof of runtime behavior. Custom annotations may retain payloads, but WAT does not establish original binary layout or round-trip byte identity. Original bytes and objdump output remain authoritative.",
        "Imports and exports retain exact top-level WABT WAT forms. Names remain escaped producer text; unescaped objdump display names are not parsed as unambiguous identifiers.",
        "JavaScript references are AST-observed static literals only. Candidate matches are associations, not proven data flow, URL-to-file identity or runtime loading. Computed references and aliases are not resolved.",
        "No target execution or implicit fetch.",
      ];

      const report = wasmArtifactSchema.parse({
        artifact,
        validation: "valid",
        sections,
        imports,
        exports,
        headers,
        details,
        wat: {
          text: watText,
          sha256: digest(watText),
          representation: "decoded-wat",
        },
        tool_profile: {
          source: "https://github.com/WebAssembly/wabt",
          release: "1.0.42",
          source_commit: "ff0ef7e0009402740c805a9744c09b05be063e48",
          commands,
          timeout_ms: WABT_LIMITS.timeoutMs,
          output_budget_bytes: WABT_LIMITS.outputBytes,
        },
        candidates,
        glue,
        runtime_execution: "not-performed",
        network_fetch: "not-performed",
        limitations,
      });

      return ok(
        createAnalysisExecution(report, WABT_PROVIDER_IDENTITY, {
          subject: {
            path: input.path,
            format: "file",
            sha256: selected.sha256,
          },
          locations: [{ kind: "artifact-path", path: input.path }],
          limitations,
        }),
      );
    } catch (cause: unknown) {
      return err(wabtFailure(cause, phase, input.path));
    }
  }
}
