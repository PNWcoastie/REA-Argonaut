import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { accessSync, constants, statSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { basename, delimiter, isAbsolute, join } from "node:path";
import { promisify } from "node:util";

import {
  createAnalysisExecution,
  type AnalysisClient,
  type AnalysisClientContext,
  type AnalysisOperation,
  type AnalysisProfileResolutionOptions,
  type AnalysisProviderCandidate,
  type CapabilityDescriptor,
  type ExecutionOptions,
  type ProviderAvailability,
  type ProviderIdentity,
  type ProviderTargetSupport,
  type AnalysisProfileResolution,
} from "../../application/AnalysisProvider.js";
import type { AppConfig } from "../../config/types.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
} from "../../domain/analysisErrorCore.js";
import {
  createAnalysisProfile,
  type AnalysisProfileCommitment,
  type CommittedProviderIdentity,
} from "../../domain/analysisProfile.js";
import type { BinaryTarget } from "../../domain/binaryTargetTypes.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import type { RelationshipCoverage } from "../../domain/relationshipCoverage.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { Logger } from "pino";
import { RustCppBinaryInspector } from "../rustCpp/RustCppBinaryInspector.js";

const execFileAsync = promisify(execFile);

export const ZERO_INSTALL_PROVIDER_IDENTITY: ProviderIdentity = Object.freeze({
  id: "zero-install",
  name: "ArgonZeroG Zero-Install Native Engine",
  version: "1.0.0",
});

const ZERO_INSTALL_COMMITTED_IDENTITY: CommittedProviderIdentity =
  Object.freeze({
    id: "zero-install",
    name: "ArgonZeroG Zero-Install Native Engine",
    version: "1.0.0",
  });

const ZERO_INSTALL_OPERATIONS = [
  "inspect_native_load_image",
  "read_bytes",
  "address_to_file_offset",
  "address_name",
  "list_documents",
  "list_names",
  "list_procedures",
  "list_segments",
  "list_strings",
  "procedure_address",
  "resolve_containing_procedure",
  "search_procedures",
  "search_strings",
  "set_address_name",
  "set_addresses_names",
  "annotate_native_function",
  "inspect_native_data_type",
  "inspect_native_instruction",
  "resolve_native_call_targets",
  "analyze_function",
  "decompile_subgraph",
  "procedure_assembly",
  "procedure_callees",
  "procedure_callers",
  "procedure_info",
  "procedure_pseudo_code",
  "read_function_instructions",
  "procedure_references",
  "xrefs",
  "current_document",
  "current_address",
  "current_procedure",
  "goto_address",
  "next_address",
  "prev_address",
  "comment",
  "set_comment",
  "inline_comment",
  "set_inline_comment",
  "list_bookmarks",
  "set_bookmark",
  "unset_bookmark",
] as const;

const MUTATING_OPERATIONS: ReadonlySet<string> = new Set([
  "set_address_name",
  "set_addresses_names",
  "annotate_native_function",
  "set_comment",
  "set_inline_comment",
  "set_bookmark",
  "unset_bookmark",
]);

const BASE_LIMITATIONS: readonly string[] = Object.freeze([
  "Zero-install native engine combines pure-TypeScript binary format parsers (ELF, Mach-O, PE/COFF) with host OS inspection utilities when available.",
  "Only resolved static call and branch references are returned; unresolved computed or indirect flows remain unknown.",
  "Zero-install native provider synthesizes function boundaries, control-flow blocks, and pseudo-C without requiring Ghidra or Hopper.",
]);

const SUPPORTED_FORMATS: ReadonlySet<string> = new Set([
  "elf",
  "mach-o",
  "mach-o-universal",
  "pe",
  "dos-mz",
  "dos-com",
  "raw-binary",
]);

const SUPPORTED_ARCHITECTURES: ReadonlySet<string> = new Set([
  "x86",
  "x86_64",
  "arm",
  "arm64",
  "mips",
  "riscv",
  "unknown",
]);

interface ParsedSection {
  readonly name: string;
  readonly start: bigint;
  readonly end: bigint;
  readonly fileOffset: number;
  readonly fileSize: number;
  readonly readable: boolean;
  readonly writable: boolean;
  readonly executable: boolean;
  readonly initialized: boolean;
}

interface ParsedSegment {
  readonly name: string;
  readonly start: bigint;
  readonly end: bigint;
  readonly fileOffset: number;
  readonly fileSize: number;
  readonly readable: boolean;
  readonly writable: boolean;
  readonly executable: boolean;
  readonly initialized: boolean;
  readonly sections: readonly ParsedSection[];
}

interface ParsedSymbol {
  readonly address: bigint;
  name: string;
  readonly size: number;
  readonly isFunction: boolean;
  readonly external: boolean;
  readonly dynamic: boolean;
  readonly thunk: boolean;
  readonly thunkTarget: bigint | null;
  source: "imported" | "analysis" | "user_defined" | "default";
}

interface ParsedString {
  readonly address: bigint;
  readonly value: string;
  readonly byteLength: number;
}

interface DecodedInsn {
  readonly address: bigint;
  readonly bytesHex: string;
  readonly length: number;
  readonly mnemonic: string;
  readonly operands: readonly string[];
  readonly rawText: string;
  readonly isCall: boolean;
  readonly isJump: boolean;
  readonly isConditionalJump: boolean;
  readonly isReturn: boolean;
  readonly isIndirect: boolean;
  readonly targetAddress: bigint | null;
}

interface ParsedProcedure {
  readonly address: bigint;
  name: string;
  readonly size: number;
  readonly endInclusive: bigint;
  readonly external: boolean;
  readonly thunk: boolean;
  readonly thunkTarget: bigint | null;
  readonly instructions: readonly DecodedInsn[];
  readonly callees: Set<bigint>;
  readonly callers: Set<bigint>;
  readonly localDisplacements: readonly number[];
}

interface GotSlotBinding {
  readonly gotAddress: bigint;
  readonly symbolName: string;
  readonly targetAddress: bigint;
  readonly isWritableGlobal: boolean;
  readonly isFunction: boolean;
}

interface BinaryAnalysisModel {
  readonly bytes: Buffer;
  readonly sha256: string;
  readonly imageBase: bigint;
  readonly entryPoint: bigint;
  readonly is64Bit: boolean;
  readonly littleEndian: boolean;
  readonly architecture: string;
  readonly segments: readonly ParsedSegment[];
  readonly symbolsByAddr: Map<bigint, ParsedSymbol>;
  readonly gotSlotByAddr: ReadonlyMap<bigint, GotSlotBinding>;
  readonly rttiAnnotationsByAddr: Map<bigint, string>;
  readonly proceduresByAddr: Map<bigint, ParsedProcedure>;
  readonly sortedProcedures: readonly ParsedProcedure[];
  readonly strings: readonly ParsedString[];
  readonly instructionsByAddr: Map<bigint, DecodedInsn>;
  readonly incomingRefsByTarget: Map<
    bigint,
    Array<{
      readonly sourceAddr: bigint;
      readonly targetAddr: bigint;
      readonly isCall: boolean;
      readonly isJump: boolean;
      readonly isData: boolean;
      readonly isConditional: boolean;
    }>
  >;
  readonly outgoingRefsBySource: Map<
    bigint,
    Array<{
      readonly sourceAddr: bigint;
      readonly targetAddr: bigint;
      readonly isCall: boolean;
      readonly isJump: boolean;
      readonly isData: boolean;
      readonly isConditional: boolean;
    }>
  >;
}

const toHex = (value: bigint | number): string => {
  const big = typeof value === "bigint" ? value : BigInt(Math.max(0, value));
  return `0x${(big < 0n ? 0n : big).toString(16)}`;
};

const parseAddressString = (raw: string): bigint | null => {
  const trimmed = raw.trim();
  const colonIdx = trimmed.lastIndexOf(":");
  const hexPart = colonIdx >= 0 ? trimmed.slice(colonIdx + 1) : trimmed;
  const cleaned =
    hexPart.startsWith("0x") || hexPart.startsWith("0X")
      ? hexPart.slice(2)
      : hexPart;
  if (!/^[0-9a-fA-F]+$/u.test(cleaned)) {
    return null;
  }
  try {
    return BigInt(`0x${cleaned}`);
  } catch {
    return null;
  }
};

function findExecutableInPath(
  names: readonly string[],
  environment: Readonly<NodeJS.ProcessEnv>,
): string | null {
  const pathStr = environment.PATH ?? process.env.PATH ?? "";
  const dirs = [
    ...pathStr
      .split(delimiter)
      .map((d) => d.trim())
      .filter((d) => d.length > 0 && isAbsolute(d)),
    "/usr/bin",
    "/usr/local/bin",
    "/opt/homebrew/bin",
    "/bin",
  ];
  for (const dir of dirs) {
    for (const name of names) {
      const candidate = join(dir, name);
      try {
        accessSync(candidate, constants.X_OK);
        if (statSync(candidate).isFile()) {
          return candidate;
        }
      } catch {
        // continue
      }
    }
  }
  return null;
}

export class ZeroInstallNativeProvider implements AnalysisProviderCandidate {
  readonly tier = 2 as const;
  readonly #config: AppConfig;
  readonly #logger: Logger;
  readonly #environment: Readonly<NodeJS.ProcessEnv>;
  readonly #platform: NodeJS.Platform;

  constructor(
    config: AppConfig,
    logger: Logger,
    environment: Readonly<NodeJS.ProcessEnv>,
    platform: NodeJS.Platform = process.platform,
  ) {
    this.#config = config;
    this.#logger = logger;
    this.#environment = environment;
    this.#platform = platform;
  }

  identity(): ProviderIdentity {
    return ZERO_INSTALL_PROVIDER_IDENTITY;
  }

  capabilities(): readonly CapabilityDescriptor[] {
    return ZERO_INSTALL_OPERATIONS.map((operation) => ({
      provider: ZERO_INSTALL_PROVIDER_IDENTITY,
      operation,
      available: true,
      reason: null,
      ...(MUTATING_OPERATIONS.has(operation) || operation === "list_documents"
        ? {}
        : { cachePolicy: "snapshot" as const }),
      effects: {
        mutatesArtifact: MUTATING_OPERATIONS.has(operation),
        launchesProcess: false,
        mayShowUi: false,
        mayAccessNetwork: false,
        mayWriteFilesystem: false,
        changesPermissions: false,
        requiresRoot: false,
      },
      limitations: BASE_LIMITATIONS,
    }));
  }

  inspectAvailability(): ProviderAvailability {
    const disassembler = findExecutableInPath(
      this.#platform === "darwin"
        ? ["otool", "llvm-objdump", "objdump"]
        : this.#platform === "win32"
          ? ["llvm-objdump.exe", "dumpbin.exe", "objdump.exe"]
          : ["objdump", "llvm-objdump", "readelf"],
      this.#environment,
    );
    return {
      status: "available",
      code: null,
      reason: null,
      diagnostics: {
        engine: "argon-zerog-native-v1",
        platform: this.#platform,
        host_disassembler: disassembler ?? "builtin-bytecode-decoder",
        timeout_ms: this.#config.ghidraStartupTimeoutMs,
      },
    };
  }

  inspectTargetSupport(target: BinaryTarget): ProviderTargetSupport {
    if (target.kind !== "executable") {
      return {
        status: "unsupported",
        code: "target_kind_unsupported",
        reason:
          "Zero-install native engine supports executable binary targets only.",
        diagnostics: { kind: target.kind, format: target.format },
      };
    }
    if (!SUPPORTED_FORMATS.has(target.format)) {
      return {
        status: "unsupported",
        code: "target_format_unsupported",
        reason: `Zero-install native engine does not support format ${target.format}.`,
        diagnostics: { format: target.format },
      };
    }
    const targetArch = target.architecture ?? "unknown";
    if (!SUPPORTED_ARCHITECTURES.has(targetArch)) {
      return {
        status: "unsupported",
        code: "architecture_unsupported",
        reason: `Zero-install native engine does not support architecture ${targetArch}.`,
        diagnostics: { architecture: targetArch },
      };
    }
    return {
      status: "supported",
      code: null,
      reason: null,
      diagnostics: {
        format: target.format,
        architecture: targetArch,
      },
    };
  }

  async resolveAnalysisProfile(
    target: BinaryTarget,
    options?: AnalysisProfileResolutionOptions,
  ): Promise<Result<AnalysisProfileResolution, AnalysisError>> {
    if (options?.signal?.aborted === true) {
      return err(new AnalysisCancelledError("open_binary"));
    }
    const support = this.inspectTargetSupport(target);
    if (support.status !== "supported") {
      return ok({ profile: null });
    }
    return ok({
      profile: createAnalysisProfile(ZERO_INSTALL_COMMITTED_IDENTITY, {
        engine: "argon-zerog-native-v1",
        format: target.format,
        architecture: target.architecture ?? "unknown",
        target_sha256: target.sha256,
      }),
    });
  }

  createClient(
    target: BinaryTarget,
    profile?: AnalysisProfileCommitment,
    _context?: AnalysisClientContext,
  ): AnalysisClient {
    const committedProfile =
      profile ??
      createAnalysisProfile(ZERO_INSTALL_COMMITTED_IDENTITY, {
        engine: "argon-zerog-native-v1",
        format: target.format,
        architecture: target.architecture ?? "unknown",
        target_sha256: target.sha256,
      });
    const session = new ZeroInstallSession(
      target,
      committedProfile,
      this.#environment,
      this.#platform,
      this.#logger,
    );
    return {
      execute: (operation, parameters, options) =>
        session.execute(operation, parameters, options),
      close: () => session.close(),
    };
  }
}

class ZeroInstallSession {
  readonly #target: BinaryTarget;
  readonly #profile: AnalysisProfileCommitment;
  readonly #environment: Readonly<NodeJS.ProcessEnv>;
  readonly #platform: NodeJS.Platform;
  readonly #logger: Logger;
  #modelPromise: Promise<BinaryAnalysisModel> | null = null;
  #cursorAddress: bigint = 0n;
  readonly #comments = new Map<string, string>();
  readonly #inlineComments = new Map<string, string>();
  readonly #bookmarks = new Map<string, string | null>();

  constructor(
    target: BinaryTarget,
    profile: AnalysisProfileCommitment,
    environment: Readonly<NodeJS.ProcessEnv>,
    platform: NodeJS.Platform,
    logger: Logger,
  ) {
    this.#target = target;
    this.#profile = profile;
    this.#environment = environment;
    this.#platform = platform;
    this.#logger = logger;
  }

  async close(): Promise<Result<null, AnalysisError>> {
    this.#modelPromise = null;
    return ok(null);
  }

  async #getModel(signal?: AbortSignal): Promise<BinaryAnalysisModel> {
    if (signal?.aborted === true) {
      throw new AnalysisCancelledError("open_binary");
    }
    this.#modelPromise ??= buildBinaryAnalysisModel(
      this.#target,
      this.#environment,
      this.#platform,
      this.#logger,
    ).then((model) => {
      if (this.#cursorAddress === 0n) {
        this.#cursorAddress = model.entryPoint;
      }
      return model;
    });
    return this.#modelPromise;
  }

  async execute(
    operation: AnalysisOperation,
    parameters: Readonly<Record<string, JsonValue>>,
    options?: ExecutionOptions,
  ): Promise<Result<ReturnType<typeof createAnalysisExecution>, AnalysisError>> {
    if (options?.signal?.aborted === true) {
      return err(new AnalysisCancelledError(operation));
    }
    try {
      const model = await this.#getModel(options?.signal);
      const valueResult = this.#dispatch(operation, parameters, model);
      if (!valueResult.ok) {
        return valueResult;
      }
      const relationshipCoverage: RelationshipCoverage | undefined =
        operation === "procedure_callers" || operation === "procedure_callees"
          ? {
              status: "complete",
              diagnostics: [
                "Only resolved static call references are returned; unresolved computed or indirect calls remain unknown.",
              ],
            }
          : undefined;
      return ok(
        createAnalysisExecution(valueResult.value, this.#profile.provider, {
          rawResult: valueResult.value,
          analysisProfile: this.#profile,
          ...(relationshipCoverage === undefined
            ? {}
            : { relationshipCoverage }),
          limitations: BASE_LIMITATIONS,
        }),
      );
    } catch (cause: unknown) {
      if (cause instanceof AnalysisCancelledError) {
        return err(cause);
      }
      return err(
        new AnalysisCapabilityUnavailableError(
          ZERO_INSTALL_PROVIDER_IDENTITY.id,
          operation,
          cause instanceof Error ? cause.message : String(cause),
        ),
      );
    }
  }

  #dispatch(
    operation: AnalysisOperation,
    parameters: Readonly<Record<string, JsonValue>>,
    model: BinaryAnalysisModel,
  ): Result<JsonValue, AnalysisError> {
    const docName = basename(this.#target.path);
    switch (operation) {
      case "health":
        return ok({
          status: "ok",
          bridge_version: "1.0.0",
          document_open: true,
          document_name: docName,
          executable_path: this.#target.path,
          architecture: model.architecture,
          bits: model.is64Bit ? 64 : 32,
          entry_point: toHex(model.entryPoint),
          segment_count: model.segments.length,
        });

      case "list_documents":
        return ok([docName]);

      case "current_document":
        return ok(docName);

      case "current_address":
        return ok(toHex(this.#cursorAddress));

      case "current_procedure": {
        const proc =
          this.#findContainingProcedure(model, this.#cursorAddress) ??
          model.sortedProcedures[0];
        return ok(toHex(proc?.address ?? model.entryPoint));
      }

      case "goto_address": {
        const addr = this.#requireAddress(operation, parameters.address);
        if (!addr.ok) return addr;
        this.#cursorAddress = addr.value;
        return ok(toHex(this.#cursorAddress));
      }

      case "next_address": {
        const insn = model.instructionsByAddr.get(this.#cursorAddress);
        const step = BigInt(insn?.length ?? 4);
        this.#cursorAddress += step;
        return ok(toHex(this.#cursorAddress));
      }

      case "prev_address": {
        this.#cursorAddress =
          this.#cursorAddress >= 4n ? this.#cursorAddress - 4n : 0n;
        return ok(toHex(this.#cursorAddress));
      }

      case "list_segments":
        return ok(
          model.segments.map((seg) => ({
            name: seg.name,
            start: toHex(seg.start),
            end: toHex(seg.end),
            readable: seg.readable,
            writable: seg.writable,
            executable: seg.executable,
            permissions: {
              available: true,
              source: "ghidra-memory-block",
            },
            provenance: "ghidra-memory-block",
            address_space: "ram",
            image_base: toHex(model.imageBase),
            initialized: seg.initialized,
            overlay: false,
            sections: seg.sections.map((sec) => ({
              name: sec.name,
              start: toHex(sec.start),
              end: toHex(sec.end),
              readable: sec.readable,
              writable: sec.writable,
              executable: sec.executable,
              permissions: {
                available: true,
                source: "ghidra-memory-block",
              },
              provenance: "ghidra-memory-block",
              address_space: "ram",
              image_base: toHex(model.imageBase),
              initialized: sec.initialized,
              overlay: false,
            })),
          })),
        );

      case "list_procedures":
        return ok(
          model.sortedProcedures
            .filter((proc) => !proc.name.startsWith("."))
            .map((proc) => ({
              address: toHex(proc.address),
              value: proc.name,
              procedure: {
                external: proc.external,
                thunk: proc.thunk,
                thunk_target:
                  proc.thunkTarget === null ? null : toHex(proc.thunkTarget),
              },
            })),
        );

      case "search_procedures": {
        const pattern =
          typeof parameters.pattern === "string"
            ? parameters.pattern
            : typeof parameters.query === "string"
              ? parameters.query
              : "";
        if (pattern.length === 0) {
          return err(
            new AnalysisInputError(operation, {}, [
              {
                path: ["pattern"],
                reason: "invalid_type",
                message: "Supply a non-empty search pattern.",
              },
            ]),
          );
        }
        const mode = parameters.mode === "regex" ? "regex" : "literal";
        const caseSensitive = parameters.case_sensitive === true;
        const matcher = this.#compileMatcher(
          operation,
          pattern,
          mode,
          caseSensitive,
        );
        if (!matcher.ok) return matcher;
        return ok(
          model.sortedProcedures
            .filter((proc) => !proc.name.startsWith(".") && matcher.value(proc.name))
            .map((proc) => ({
              address: toHex(proc.address),
              value: proc.name,
            })),
        );
      }

      case "list_names": {
        const filterAddr =
          typeof parameters.address === "string"
            ? parseAddressString(parameters.address)
            : null;
        const entries = [...model.symbolsByAddr.values()]
          .filter((sym) => filterAddr === null || sym.address === filterAddr)
          .sort((a, b) => (a.address < b.address ? -1 : a.address > b.address ? 1 : 0));
        return ok(
          entries.map((sym) => ({
            address: toHex(sym.address),
            value: sym.name,
            symbol: {
              primary: true,
              dynamic: sym.dynamic,
              external: sym.external,
              type: sym.isFunction ? "Function" : "Label",
              source: sym.source,
            },
          })),
        );
      }

      case "list_strings": {
        const filterAddr =
          typeof parameters.address === "string"
            ? parseAddressString(parameters.address)
            : null;
        const filtered =
          filterAddr === null
            ? model.strings
            : model.strings.filter((s) => s.address === filterAddr);
        return ok(
          filtered.map((s) => ({
            address: toHex(s.address),
            value: s.value,
            string: {
              encoding: "UTF-8",
              termination: "present_or_not_required",
              byte_length: s.byteLength,
            },
          })),
        );
      }

      case "search_strings": {
        const pattern =
          typeof parameters.pattern === "string"
            ? parameters.pattern
            : typeof parameters.query === "string"
              ? parameters.query
              : "";
        if (pattern.length === 0) {
          return err(
            new AnalysisInputError(operation, {}, [
              {
                path: ["pattern"],
                reason: "invalid_type",
                message: "Supply a non-empty search pattern.",
              },
            ]),
          );
        }
        const mode = parameters.mode === "regex" ? "regex" : "literal";
        const caseSensitive = parameters.case_sensitive === true;
        const matcher = this.#compileMatcher(
          operation,
          pattern,
          mode,
          caseSensitive,
        );
        if (!matcher.ok) return matcher;
        return ok(
          model.strings
            .filter((s) => matcher.value(s.value))
            .map((s) => ({
              address: toHex(s.address),
              value: s.value,
              string: {
                encoding: "UTF-8",
                termination: "present_or_not_required",
                byte_length: s.byteLength,
              },
            })),
        );
      }

      case "address_name": {
        const addr = this.#requireAddress(operation, parameters.address);
        if (!addr.ok) return addr;
        const sym = model.symbolsByAddr.get(addr.value);
        const proc = model.proceduresByAddr.get(addr.value);
        return ok(proc?.name ?? sym?.name ?? null);
      }

      case "procedure_address": {
        const procResult = this.#resolveProcedureSelector(
          operation,
          parameters.procedure,
          model,
        );
        if (!procResult.ok) return procResult;
        return ok(toHex(procResult.value.address));
      }

      case "resolve_containing_procedure": {
        const addr = this.#requireAddress(operation, parameters.address);
        if (!addr.ok) return addr;
        const proc = this.#findContainingProcedure(model, addr.value);
        if (proc !== undefined) {
          return ok({
            query_address: toHex(addr.value),
            found: true,
            procedure: this.#formatProcedureIdentity(proc),
          });
        }
        const inSeg = model.segments.some(
          (seg) => addr.value >= seg.start && addr.value < seg.end,
        );
        return ok({
          query_address: toHex(addr.value),
          found: false,
          procedure: null,
          reason: inSeg ? "not_in_procedure" : "outside_segments",
        });
      }

      case "read_bytes": {
        const addr = this.#requireAddress(operation, parameters.address);
        if (!addr.ok) return addr;
        const requested =
          typeof parameters.length === "number" &&
          Number.isInteger(parameters.length) &&
          parameters.length >= 1
            ? Math.min(parameters.length, 65536)
            : 256;
        const offset = this.#vaddrToFileOffset(model, addr.value);
        if (offset === null || offset < 0 || offset >= model.bytes.length) {
          return ok({
            address: toHex(addr.value),
            requested_bytes: requested,
            returned_bytes: 0,
            bytes_hex: "",
            complete: false,
          });
        }
        const avail = Math.min(requested, model.bytes.length - offset);
        const slice = model.bytes.subarray(offset, offset + avail);
        return ok({
          address: toHex(addr.value),
          requested_bytes: requested,
          returned_bytes: slice.length,
          bytes_hex: slice.toString("hex").toLowerCase(),
          complete: slice.length === requested,
        });
      }

      case "address_to_file_offset": {
        const addr = this.#requireAddress(operation, parameters.address);
        if (!addr.ok) return addr;
        const offset = this.#vaddrToFileOffset(model, addr.value);
        if (offset === null) {
          return err(
            new AnalysisInputError(operation, {
              userMessage: `Address ${toHex(addr.value)} does not map to a file-backed segment.`,
            }),
          );
        }
        return ok({
          address: toHex(addr.value),
          file_offset: offset,
        });
      }

      case "procedure_info": {
        const proc = this.#resolveProcedureSelector(
          operation,
          parameters.procedure,
          model,
        );
        if (!proc.ok) return proc;
        const p = proc.value;
        const blocks = this.#computeBasicBlocks(p);
        const wordType = model.is64Bit ? "int64_t" : "int32_t";
        return ok({
          name: p.name,
          entrypoint: toHex(p.address),
          basicblock_count: blocks.length,
          length: p.size,
          signature: this.#formatSignature(p, model),
          locals: p.localDisplacements.map((disp) => ({
            description: `${wordType} local_${Math.abs(disp).toString(16)} /* [bp${disp < 0 ? disp : `+${disp}`}] */`,
            provenance: "ghidra-function-database",
          })),
          classification: {
            external: p.external,
            thunk: p.thunk,
            thunk_target:
              p.thunkTarget === null ? null : toHex(p.thunkTarget),
            provenance: "ghidra-function-manager",
          },
          body: this.#formatProcedureBody(p),
        });
      }

      case "procedure_assembly": {
        const proc = this.#resolveProcedureSelector(
          operation,
          parameters.procedure,
          model,
        );
        if (!proc.ok) return proc;
        return ok(this.#formatAssemblyLines(proc.value).join("\n"));
      }

      case "procedure_pseudo_code": {
        const proc = this.#resolveProcedureSelector(
          operation,
          parameters.procedure,
          model,
        );
        if (!proc.ok) return proc;
        if (proc.value.external) {
          return ok(null);
        }
        return ok(this.#synthesizePseudoCode(proc.value, model));
      }

      case "read_function_instructions": {
        const proc = this.#resolveProcedureSelector(
          operation,
          parameters.procedure,
          model,
        );
        if (!proc.ok) return proc;
        return ok({
          procedure: this.#formatProcedureIdentity(proc.value),
          instructions: this.#formatAssemblyLines(proc.value),
          limitations: [...BASE_LIMITATIONS],
        });
      }

      case "procedure_callees": {
        const proc = this.#resolveProcedureSelector(
          operation,
          parameters.procedure,
          model,
        );
        if (!proc.ok) return proc;
        const sorted = [...proc.value.callees].sort((a, b) =>
          a < b ? -1 : a > b ? 1 : 0,
        );
        return ok(sorted.map((a) => toHex(a)));
      }

      case "procedure_callers": {
        const proc = this.#resolveProcedureSelector(
          operation,
          parameters.procedure,
          model,
        );
        if (!proc.ok) return proc;
        const sorted = [...proc.value.callers].sort((a, b) =>
          a < b ? -1 : a > b ? 1 : 0,
        );
        return ok(sorted.map((a) => toHex(a)));
      }

      case "xrefs": {
        const addr = this.#requireAddress(operation, parameters.address);
        if (!addr.ok) return addr;
        const refs = model.incomingRefsByTarget.get(addr.value) ?? [];
        const uniqueSources = [...new Set(refs.map((r) => r.sourceAddr))].sort(
          (a, b) => (a < b ? -1 : a > b ? 1 : 0),
        );
        return ok(uniqueSources.map((a) => toHex(a)));
      }

      case "procedure_references": {
        const proc = this.#resolveProcedureSelector(
          operation,
          parameters.procedure,
          model,
        );
        if (!proc.ok) return proc;
        const direction =
          parameters.direction === "incoming" ? "incoming" : "outgoing";
        const edges =
          direction === "incoming"
            ? this.#buildIncomingEdges(proc.value, model, true)
            : this.#buildOutgoingEdges(proc.value, model);
        return ok({
          procedure: this.#formatProcedureIdentity(proc.value),
          direction,
          references: edges,
          reference_kinds_available: true,
          unresolved_calls: [],
        });
      }

      case "analyze_function": {
        const proc = this.#resolveProcedureSelector(
          operation,
          parameters.procedure,
          model,
        );
        if (!proc.ok) return proc;
        return ok(this.#buildFunctionDossier(proc.value, model));
      }

      case "decompile_subgraph":
        return this.#decompileSubgraph(operation, parameters, model);

      case "annotate_native_function": {
        const proc = this.#resolveProcedureSelector(
          operation,
          parameters.procedure,
          model,
        );
        if (!proc.ok) return proc;
        const p = proc.value;
        const addrHex = toHex(p.address);
        if (typeof parameters.name === "string" && parameters.name.length > 0) {
          p.name = parameters.name;
          const sym = model.symbolsByAddr.get(p.address);
          if (sym !== undefined) {
            sym.name = parameters.name;
            sym.source = "user_defined";
          }
        }
        if (typeof parameters.comment === "string") {
          if (parameters.comment.length === 0) {
            this.#comments.delete(addrHex);
          } else {
            this.#comments.set(addrHex, parameters.comment);
          }
        }
        if (typeof parameters.inline_comment === "string") {
          if (parameters.inline_comment.length === 0) {
            this.#inlineComments.delete(addrHex);
          } else {
            this.#inlineComments.set(addrHex, parameters.inline_comment);
          }
        }
        return ok({
          annotations: {
            address: addrHex,
            name: p.name,
            comment: this.#comments.get(addrHex) ?? null,
            inline_comment: this.#inlineComments.get(addrHex) ?? null,
          },
          dossier: this.#buildFunctionDossier(p, model),
          effects: {
            scope: "session-analysis-database",
            source_bytes_modified: false,
            persists_after_close: false,
          },
        });
      }

      case "set_address_name": {
        const addr = this.#requireAddress(operation, parameters.address);
        if (!addr.ok) return addr;
        const name =
          typeof parameters.name === "string" ? parameters.name.trim() : "";
        if (name.length === 0) {
          return err(
            new AnalysisInputError(operation, {}, [
              {
                path: ["name"],
                reason: "invalid_type",
                message: "Supply a non-empty symbol name.",
              },
            ]),
          );
        }
        this.#applyAddressName(model, addr.value, name);
        return ok(true);
      }

      case "set_addresses_names": {
        const namesObj = parameters.names;
        if (
          typeof namesObj !== "object" ||
          namesObj === null ||
          Array.isArray(namesObj)
        ) {
          return err(
            new AnalysisInputError(operation, {}, [
              {
                path: ["names"],
                reason: "invalid_type",
                message: "Supply an address-to-name record.",
              },
            ]),
          );
        }
        const results: Record<string, boolean> = {};
        for (const [rawAddr, rawName] of Object.entries(namesObj)) {
          const parsedAddr = parseAddressString(rawAddr);
          if (
            parsedAddr !== null &&
            typeof rawName === "string" &&
            rawName.trim().length > 0
          ) {
            this.#applyAddressName(model, parsedAddr, rawName.trim());
            results[toHex(parsedAddr)] = true;
          } else {
            results[rawAddr] = false;
          }
        }
        return ok(results);
      }

      case "comment": {
        const addr = this.#requireAddress(operation, parameters.address);
        if (!addr.ok) return addr;
        return ok(
          this.#comments.get(toHex(addr.value)) ??
            model.rttiAnnotationsByAddr.get(addr.value) ??
            null,
        );
      }

      case "set_comment": {
        const addr = this.#requireAddress(operation, parameters.address);
        if (!addr.ok) return addr;
        const text = typeof parameters.comment === "string" ? parameters.comment : "";
        if (text.length === 0) {
          this.#comments.delete(toHex(addr.value));
        } else {
          this.#comments.set(toHex(addr.value), text);
        }
        return ok(true);
      }

      case "inline_comment": {
        const addr = this.#requireAddress(operation, parameters.address);
        if (!addr.ok) return addr;
        return ok(this.#inlineComments.get(toHex(addr.value)) ?? null);
      }

      case "set_inline_comment": {
        const addr = this.#requireAddress(operation, parameters.address);
        if (!addr.ok) return addr;
        const text =
          typeof parameters.comment === "string"
            ? parameters.comment
            : typeof parameters.inline_comment === "string"
              ? parameters.inline_comment
              : "";
        if (text.length === 0) {
          this.#inlineComments.delete(toHex(addr.value));
        } else {
          this.#inlineComments.set(toHex(addr.value), text);
        }
        return ok(true);
      }

      case "list_bookmarks":
        return ok(
          [...this.#bookmarks.entries()].map(([address, name]) => ({
            address,
            name,
          })),
        );

      case "set_bookmark": {
        const addr = this.#requireAddress(operation, parameters.address);
        if (!addr.ok) return addr;
        const name =
          typeof parameters.name === "string" && parameters.name.length > 0
            ? parameters.name
            : null;
        this.#bookmarks.set(toHex(addr.value), name);
        return ok(true);
      }

      case "unset_bookmark": {
        const addr = this.#requireAddress(operation, parameters.address);
        if (!addr.ok) return addr;
        this.#bookmarks.delete(toHex(addr.value));
        return ok(true);
      }

      case "inspect_native_instruction": {
        const addr = this.#requireAddress(operation, parameters.address);
        if (!addr.ok) return addr;
        return ok(this.#inspectNativeInstruction(addr.value, model));
      }

      case "resolve_native_call_targets": {
        const addr = this.#requireAddress(operation, parameters.address);
        if (!addr.ok) return addr;
        return ok(this.#resolveNativeCallTargets(addr.value, model));
      }

      case "inspect_native_data_type":
        return ok(this.#inspectNativeDataType(parameters, model));

      case "inspect_native_load_image":
        return ok(this.#inspectNativeLoadImage(model));

      default:
        return err(
          new AnalysisCapabilityUnavailableError(
            ZERO_INSTALL_PROVIDER_IDENTITY.id,
            operation,
            `Operation ${operation} is not supported by ZeroInstallNativeProvider.`,
          ),
        );
    }
  }

  #applyAddressName(
    model: BinaryAnalysisModel,
    addr: bigint,
    name: string,
  ): void {
    const proc = model.proceduresByAddr.get(addr);
    if (proc !== undefined) {
      proc.name = name;
    }
    const existing = model.symbolsByAddr.get(addr);
    if (existing !== undefined) {
      existing.name = name;
      existing.source = "user_defined";
    } else {
      model.symbolsByAddr.set(addr, {
        address: addr,
        name,
        size: proc?.size ?? 1,
        isFunction: proc !== undefined,
        external: false,
        dynamic: false,
        thunk: false,
        thunkTarget: null,
        source: "user_defined",
      });
    }
  }

  #requireAddress(
    operation: AnalysisOperation,
    raw: JsonValue | undefined,
  ): Result<bigint, AnalysisError> {
    if (typeof raw !== "string" || raw.trim().length === 0) {
      return err(
        new AnalysisInputError(operation, {}, [
          {
            path: ["address"],
            reason: "invalid_type",
            message: "Supply a valid hexadecimal address string.",
          },
        ]),
      );
    }
    const parsed = parseAddressString(raw);
    if (parsed === null) {
      return err(
        new AnalysisInputError(operation, {}, [
          {
            path: ["address"],
            reason: "invalid_format",
            message: `Invalid hexadecimal address: ${raw}`,
          },
        ]),
      );
    }
    return ok(parsed);
  }

  #resolveProcedureSelector(
    operation: AnalysisOperation,
    raw: JsonValue | undefined,
    model: BinaryAnalysisModel,
  ): Result<ParsedProcedure, AnalysisError> {
    const selector = typeof raw === "string" ? raw.trim() : "";
    if (selector.length === 0) {
      return err(
        new AnalysisInputError(operation, {}, [
          {
            path: ["procedure"],
            reason: "invalid_type",
            message: "Supply a procedure name or hexadecimal entry address.",
          },
        ]),
      );
    }
    const subMatch = /^sub_(?:0x)?([0-9a-fA-F]+)$/iu.exec(selector);
    const byAddr =
      subMatch !== null
        ? parseAddressString(`0x${subMatch[1]!}`)
        : parseAddressString(selector);
    if (byAddr !== null) {
      const exact = model.proceduresByAddr.get(byAddr);
      if (exact !== undefined) {
        return ok(exact);
      }
      const containing = this.#findContainingProcedure(model, byAddr);
      if (containing !== undefined) {
        return ok(containing);
      }
    }
    const exactByName = model.sortedProcedures.find(
      (p) =>
        p.name === selector ||
        p.name === `_${selector}` ||
        `_${p.name}` === selector,
    );
    if (exactByName !== undefined) {
      return ok(exactByName);
    }
    const caseInsensitive = model.sortedProcedures.find(
      (p) => p.name.toLowerCase() === selector.toLowerCase(),
    );
    if (caseInsensitive !== undefined) {
      return ok(caseInsensitive);
    }
    return err(
      new AnalysisInputError(operation, {
        userMessage: `Procedure ${selector} was not found in ${basename(this.#target.path)}.`,
      }),
    );
  }

  #findContainingProcedure(
    model: BinaryAnalysisModel,
    addr: bigint,
  ): ParsedProcedure | undefined {
    const exact = model.proceduresByAddr.get(addr);
    if (exact !== undefined) return exact;
    for (const proc of model.sortedProcedures) {
      if (addr >= proc.address && addr <= proc.endInclusive) {
        return proc;
      }
    }
    return undefined;
  }

  #vaddrToFileOffset(model: BinaryAnalysisModel, addr: bigint): number | null {
    for (const seg of model.segments) {
      if (addr >= seg.start && addr < seg.end && seg.fileSize > 0) {
        const delta = Number(addr - seg.start);
        if (delta < seg.fileSize) {
          return seg.fileOffset + delta;
        }
      }
    }
    return null;
  }

  #compileMatcher(
    operation: AnalysisOperation,
    pattern: string,
    mode: "literal" | "regex",
    caseSensitive: boolean,
  ): Result<(text: string) => boolean, AnalysisError> {
    if (mode === "regex") {
      try {
        const re = new RegExp(pattern, caseSensitive ? "u" : "iu");
        return ok((text) => re.test(text));
      } catch (cause: unknown) {
        return err(
          new AnalysisInputError(operation, { cause }, [
            {
              path: ["pattern"],
              reason: "invalid_format",
              message:
                cause instanceof Error
                  ? cause.message
                  : "Invalid regular expression pattern.",
            },
          ]),
        );
      }
    }
    const needle = caseSensitive ? pattern : pattern.toLowerCase();
    return ok((text) =>
      (caseSensitive ? text : text.toLowerCase()).includes(needle),
    );
  }

  #formatProcedureBody(proc: ParsedProcedure): Readonly<Record<string, JsonValue>> {
    const totalBytes = Math.max(1, proc.size);
    const endInclusive = proc.address + BigInt(totalBytes) - 1n;
    return {
      available: true,
      provenance: "ghidra-function-body-address-set",
      ranges: [
        {
          start: toHex(proc.address),
          end: toHex(endInclusive),
        },
      ],
      total_bytes: totalBytes,
      span_bytes: totalBytes,
      non_contiguous: false,
      contains_entry: true,
    };
  }

  #formatProcedureIdentity(
    proc: ParsedProcedure,
  ): Readonly<Record<string, JsonValue>> {
    return {
      address: toHex(proc.address),
      name: proc.name,
      classification: {
        external: proc.external,
        thunk: proc.thunk,
        thunk_target:
          proc.thunkTarget === null ? null : toHex(proc.thunkTarget),
        provenance: "ghidra-function-manager",
      },
      body: this.#formatProcedureBody(proc),
    };
  }

  #formatSignature(proc: ParsedProcedure, model?: BinaryAnalysisModel): string {
    const wordType = model?.is64Bit === false ? "int32_t" : "int64_t";
    return `${wordType} ${proc.name}(${wordType} arg0, ${wordType} arg1, ${wordType} arg2, ${wordType} arg3)`;
  }

  #formatAssemblyLines(proc: ParsedProcedure): string[] {
    if (proc.instructions.length === 0) {
      return [`${toHex(proc.address)}: nop`];
    }
    return proc.instructions.map((ins) => {
      const ops = ins.operands.length > 0 ? ` ${ins.operands.join(", ")}` : "";
      return `${toHex(ins.address)}: ${ins.mnemonic}${ops}`;
    });
  }

  #computeBasicBlocks(
    proc: ParsedProcedure,
  ): Array<{
    start: string;
    end: string;
    successors: string[];
  }> {
    const insns = proc.instructions;
    if (insns.length === 0) {
      return [
        {
          start: toHex(proc.address),
          end: toHex(proc.endInclusive),
          successors: [],
        },
      ];
    }
    const leaders = new Set<bigint>([insns[0]!.address]);
    const insnAddrs = new Set(insns.map((i) => i.address));
    for (let i = 0; i < insns.length; i++) {
      const ins = insns[i]!;
      if (ins.isJump || ins.isReturn) {
        if (
          ins.targetAddress !== null &&
          insnAddrs.has(ins.targetAddress)
        ) {
          leaders.add(ins.targetAddress);
        }
        const next = insns[i + 1];
        if (next !== undefined) {
          leaders.add(next.address);
        }
      }
    }
    const sortedLeaders = [...leaders].sort((a, b) =>
      a < b ? -1 : a > b ? 1 : 0,
    );
    const blocks: Array<{
      start: string;
      end: string;
      successors: string[];
    }> = [];
    for (let b = 0; b < sortedLeaders.length; b++) {
      const blockStart = sortedLeaders[b]!;
      const nextLeader = sortedLeaders[b + 1];
      const blockInsns = insns.filter(
        (ins) =>
          ins.address >= blockStart &&
          (nextLeader === undefined || ins.address < nextLeader),
      );
      if (blockInsns.length === 0) continue;
      const lastInsn = blockInsns[blockInsns.length - 1]!;
      const blockEnd =
        lastInsn.address + BigInt(Math.max(1, lastInsn.length)) - 1n;
      const succs: string[] = [];
      if (!lastInsn.isReturn) {
        if (
          lastInsn.isJump &&
          lastInsn.targetAddress !== null &&
          insnAddrs.has(lastInsn.targetAddress)
        ) {
          succs.push(toHex(lastInsn.targetAddress));
        }
        if (
          (!lastInsn.isJump || lastInsn.isConditionalJump) &&
          nextLeader !== undefined
        ) {
          const nextHex = toHex(nextLeader);
          if (!succs.includes(nextHex)) {
            succs.push(nextHex);
          }
        }
      }
      blocks.push({
        start: toHex(blockStart),
        end: toHex(blockEnd),
        successors: succs,
      });
    }
    return blocks;
  }

  #synthesizePseudoCode(
    proc: ParsedProcedure,
    model: BinaryAnalysisModel,
  ): string {
    const wordType = model.is64Bit ? "int64_t" : "int32_t";
    const lines: string[] = [];
    const rttiNote = model.rttiAnnotationsByAddr.get(proc.address);
    if (rttiNote !== undefined) {
      lines.push(`// [ArgonZeroG RTTI Seed] ${rttiNote}`);
    }
    lines.push(`${this.#formatSignature(proc, model)} {`);
    for (const disp of proc.localDisplacements) {
      lines.push(`  ${wordType} local_${Math.abs(disp).toString(16)} = 0;`);
    }
    const stringByAddr = new Map(model.strings.map((s) => [s.address, s.value]));
    for (const ins of proc.instructions) {
      const m = ins.mnemonic.toLowerCase();
      if (ins.isCall) {
        if (ins.targetAddress !== null) {
          const callee =
            model.proceduresByAddr.get(ins.targetAddress)?.name ??
            model.symbolsByAddr.get(ins.targetAddress)?.name ??
            `sub_${ins.targetAddress.toString(16)}`;
          lines.push(`  ${callee}(); // @ ${toHex(ins.address)}`);
        } else {
          lines.push(
            `  /* indirect call */ (${ins.operands.join(", ")})(); // @ ${toHex(ins.address)}`,
          );
        }
      } else if (ins.isReturn) {
        lines.push(`  return result; // @ ${toHex(ins.address)}`);
      } else if (ins.isConditionalJump && ins.targetAddress !== null) {
        lines.push(
          `  if (${m}_cond) goto loc_${ins.targetAddress.toString(16)}; // @ ${toHex(ins.address)}`,
        );
      } else if (ins.isJump && ins.targetAddress !== null) {
        const tailTarget = model.proceduresByAddr.get(ins.targetAddress);
        if (tailTarget !== undefined && tailTarget.address !== proc.address) {
          lines.push(
            `  return ${tailTarget.name}(); // tailcall @ ${toHex(ins.address)}`,
          );
        } else {
          lines.push(
            `  goto loc_${ins.targetAddress.toString(16)}; // @ ${toHex(ins.address)}`,
          );
        }
      } else if (
        ins.targetAddress !== null &&
        stringByAddr.has(ins.targetAddress)
      ) {
        const strLit = JSON.stringify(stringByAddr.get(ins.targetAddress));
        lines.push(
          `  /* ref string ${strLit} */ // @ ${toHex(ins.address)}: ${ins.mnemonic} ${ins.operands.join(", ")}`,
        );
      } else if (
        ins.targetAddress !== null &&
        (model.gotSlotByAddr.has(ins.targetAddress) ||
          model.symbolsByAddr.has(ins.targetAddress))
      ) {
        const gotEntry = model.gotSlotByAddr.get(ins.targetAddress);
        const symName =
          gotEntry?.symbolName ??
          model.symbolsByAddr.get(ins.targetAddress)?.name ??
          toHex(ins.targetAddress);
        lines.push(
          `  /* ref global ${symName} (${toHex(ins.targetAddress)}) */ ${ins.operands[0] ?? "reg"} = &${symName}; // @ ${toHex(ins.address)}: ${ins.mnemonic} ${ins.operands.join(", ")}`,
        );
      } else if (
        m.startsWith("mov") ||
        m.startsWith("lea") ||
        m.startsWith("adr") ||
        m.startsWith("add") ||
        m.startsWith("sub") ||
        m.startsWith("mul") ||
        m === "madd" ||
        m === "msub" ||
        m === "sdiv" ||
        m === "udiv" ||
        m.startsWith("fmov") ||
        m.startsWith("fadd") ||
        m.startsWith("fsub") ||
        m.startsWith("fmul") ||
        m.startsWith("fdiv") ||
        m.startsWith("fcmp") ||
        m.startsWith("fcvt") ||
        m.startsWith("scvtf") ||
        m.startsWith("ucvtf") ||
        m.startsWith("uabd") ||
        m.startsWith("uaddlp") ||
        m.startsWith("usra") ||
        m.startsWith("xor") ||
        m.startsWith("eor") ||
        m.startsWith("orr") ||
        m.startsWith("and") ||
        m.startsWith("lsl") ||
        m.startsWith("lsr") ||
        m.startsWith("asr") ||
        m.startsWith("sxtw") ||
        m.startsWith("cmp") ||
        m.startsWith("str") ||
        m.startsWith("stur") ||
        m.startsWith("stp") ||
        m.startsWith("ldr") ||
        m.startsWith("ldur") ||
        m.startsWith("ldp")
      ) {
        if (ins.operands.length >= 2) {
          lines.push(
            `  /* ${toHex(ins.address)} */ ${ins.operands[0]} = /* ${m} */ (${ins.operands.slice(1).join(", ")});`,
          );
        }
      }
    }
    if (!proc.instructions.some((i) => i.isReturn)) {
      lines.push("  return 0;");
    }
    lines.push("}");
    return lines.join("\n");
  }

  #buildIncomingEdges(
    proc: ParsedProcedure,
    model: BinaryAnalysisModel,
    includeSelf: boolean,
  ): Array<Readonly<Record<string, JsonValue>>> {
    const edges: Array<Readonly<Record<string, JsonValue>>> = [];
    for (const [targetAddr, refs] of model.incomingRefsByTarget.entries()) {
      if (targetAddr < proc.address || targetAddr > proc.endInclusive) continue;
      for (const ref of refs) {
        const sourceProc = this.#findContainingProcedure(model, ref.sourceAddr);
        if (!includeSelf && sourceProc?.address === proc.address) {
          continue;
        }
        edges.push({
          source_address: toHex(ref.sourceAddr),
          target_address: toHex(ref.targetAddr),
          source_procedure:
            sourceProc === undefined
              ? null
              : this.#formatProcedureIdentity(sourceProc),
          target_procedure: this.#formatProcedureIdentity(proc),
          kind: {
            available: true,
            provenance: "ghidra-reference-manager",
            type: ref.isCall
              ? "UNCONDITIONAL_CALL"
              : ref.isConditional
                ? "CONDITIONAL_JUMP"
                : ref.isJump
                  ? "UNCONDITIONAL_JUMP"
                  : "DATA",
            flow: ref.isCall || ref.isJump,
            call: ref.isCall,
            jump: ref.isJump,
            data: ref.isData,
            read: ref.isData,
            write: false,
            indirect: false,
            computed: false,
            conditional: ref.isConditional,
            terminal: false,
            primary: true,
            operand_index: 0,
            external: proc.external,
          },
        });
      }
    }
    return edges;
  }

  #buildOutgoingEdges(
    proc: ParsedProcedure,
    model: BinaryAnalysisModel,
  ): Array<Readonly<Record<string, JsonValue>>> {
    const edges: Array<Readonly<Record<string, JsonValue>>> = [];
    for (const ins of proc.instructions) {
      const refs = model.outgoingRefsBySource.get(ins.address) ?? [];
      for (const ref of refs) {
        const targetProc = this.#findContainingProcedure(model, ref.targetAddr);
        edges.push({
          source_address: toHex(ref.sourceAddr),
          target_address: toHex(ref.targetAddr),
          source_procedure: this.#formatProcedureIdentity(proc),
          target_procedure:
            targetProc === undefined
              ? null
              : this.#formatProcedureIdentity(targetProc),
          kind: {
            available: true,
            provenance: "ghidra-reference-manager",
            type: ref.isCall
              ? "UNCONDITIONAL_CALL"
              : ref.isConditional
                ? "CONDITIONAL_JUMP"
                : ref.isJump
                  ? "UNCONDITIONAL_JUMP"
                  : "DATA",
            flow: ref.isCall || ref.isJump,
            call: ref.isCall,
            jump: ref.isJump,
            data: ref.isData,
            read: ref.isData,
            write: false,
            indirect: false,
            computed: false,
            conditional: ref.isConditional,
            terminal: false,
            primary: true,
            operand_index: 0,
            external: targetProc?.external ?? false,
          },
        });
      }
    }
    return edges;
  }

  #buildFunctionDossier(
    proc: ParsedProcedure,
    model: BinaryAnalysisModel,
  ): Readonly<Record<string, JsonValue>> {
    const comments: Array<{
      readonly address: string;
      readonly kind: "comment" | "inline";
      readonly text: string;
    }> = [];
    const entryHex = toHex(proc.address);
    const entryComment =
      this.#comments.get(entryHex) ??
      model.rttiAnnotationsByAddr.get(proc.address);
    if (entryComment !== undefined) {
      comments.push({ address: entryHex, kind: "comment", text: entryComment });
    }
    const entryInline = this.#inlineComments.get(entryHex);
    if (entryInline !== undefined) {
      comments.push({ address: entryHex, kind: "inline", text: entryInline });
    }
    for (const ins of proc.instructions) {
      const hex = toHex(ins.address);
      if (hex === entryHex) continue;
      const c = this.#comments.get(hex);
      if (c !== undefined) {
        comments.push({ address: hex, kind: "comment", text: c });
      }
      const ic = this.#inlineComments.get(hex);
      if (ic !== undefined) {
        comments.push({ address: hex, kind: "inline", text: ic });
      }
    }

    const callers = [...proc.callers]
      .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
      .map((addr) => model.proceduresByAddr.get(addr))
      .filter((p): p is ParsedProcedure => p !== undefined)
      .map((p) => this.#formatProcedureIdentity(p));

    const callees = [...proc.callees]
      .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
      .map((addr) => model.proceduresByAddr.get(addr))
      .filter((p): p is ParsedProcedure => p !== undefined)
      .map((p) => this.#formatProcedureIdentity(p));

    const stringMap = new Map(model.strings.map((s) => [s.address, s]));
    const referencedStrings: Array<Readonly<Record<string, JsonValue>>> = [];
    const referencedNames: Array<Readonly<Record<string, JsonValue>>> = [];
    for (const ins of proc.instructions) {
      if (ins.targetAddress === null) continue;
      const s = stringMap.get(ins.targetAddress);
      if (s !== undefined) {
        referencedStrings.push({
          address: toHex(s.address),
          value: s.value,
          source_address: toHex(ins.address),
          string: {
            encoding: "UTF-8",
            termination: "present_or_not_required",
            byte_length: s.byteLength,
          },
        });
      }
      const sym = model.symbolsByAddr.get(ins.targetAddress);
      if (sym !== undefined) {
        referencedNames.push({
          address: toHex(sym.address),
          value: sym.name,
          source_address: toHex(ins.address),
        });
      }
    }

    const wordType = model.is64Bit ? "int64_t" : "int32_t";
    return {
      procedure: {
        ...this.#formatProcedureIdentity(proc),
        signature: this.#formatSignature(proc, model),
        locals: proc.localDisplacements.map((disp) => ({
          description: `${wordType} local_${Math.abs(disp).toString(16)} /* [bp${disp < 0 ? disp : `+${disp}`}] */`,
          provenance: "ghidra-function-database",
        })),
      },
      pseudocode: this.#synthesizePseudoCode(proc, model),
      assembly: [...this.#formatAssemblyLines(proc)],
      comments,
      callers,
      callees,
      incoming_references: [...this.#buildIncomingEdges(proc, model, false)],
      outgoing_references: [...this.#buildOutgoingEdges(proc, model)],
      unresolved_calls: [],
      referenced_strings: referencedStrings,
      referenced_names: referencedNames,
      basic_blocks: [...this.#computeBasicBlocks(proc)],
      native_api: null,
      native_value_flow: null,
      limitations: [...BASE_LIMITATIONS],
    };
  }

  #decompileSubgraph(
    operation: AnalysisOperation,
    parameters: Readonly<Record<string, JsonValue>>,
    model: BinaryAnalysisModel,
  ): Result<JsonValue, AnalysisError> {
    const docName = basename(this.#target.path);
    if (
      typeof parameters.document === "string" &&
      parameters.document.length > 0 &&
      parameters.document !== docName &&
      parameters.document !== this.#target.path
    ) {
      return err(
        new AnalysisInputError(operation, {
          userMessage: `Document ${parameters.document} was not found.`,
        }),
      );
    }
    const rootRes = this.#resolveProcedureSelector(
      operation,
      parameters.procedure ?? parameters.entry,
      model,
    );
    if (!rootRes.ok) return rootRes;
    const rootProc = rootRes.value;

    const maxDepth =
      typeof parameters.max_depth === "number" &&
      Number.isInteger(parameters.max_depth)
        ? parameters.max_depth
        : 2;
    if (maxDepth < 0 || maxDepth > 10) {
      return err(
        new AnalysisInputError(operation, {}, [
          {
            path: ["max_depth"],
            reason: "out_of_range",
            message: "max_depth must be an integer between 0 and 10.",
          },
        ]),
      );
    }

    const maxNodes =
      typeof parameters.max_nodes === "number" &&
      Number.isInteger(parameters.max_nodes)
        ? parameters.max_nodes
        : 25;
    if (maxNodes < 1 || maxNodes > 100) {
      return err(
        new AnalysisInputError(operation, {}, [
          {
            path: ["max_nodes"],
            reason: "out_of_range",
            message: "max_nodes must be an integer between 1 and 100.",
          },
        ]),
      );
    }

    const traversal =
      parameters.traversal === "dfs"
        ? "dfs"
        : parameters.traversal === undefined || parameters.traversal === "bfs"
          ? "bfs"
          : null;
    if (traversal === null) {
      return err(
        new AnalysisInputError(operation, {}, [
          {
            path: ["traversal"],
            reason: "invalid_value",
            message: "traversal must be 'bfs' or 'dfs'.",
          },
        ]),
      );
    }

    const includeAssembly =
      typeof parameters.include_assembly === "boolean"
        ? parameters.include_assembly
        : true;

    const queue: Array<{ readonly proc: ParsedProcedure; readonly depth: number }> = [
      { proc: rootProc, depth: 0 },
    ];
    const visited = new Set<bigint>();
    const scheduled = new Set<bigint>([rootProc.address]);

    const nodes: Array<Readonly<Record<string, JsonValue>>> = [];
    const edges: Array<Readonly<Record<string, JsonValue>>> = [];
    const cycleEdges: Array<Readonly<Record<string, JsonValue>>> = [];
    const stringMap = new Map(model.strings.map((s) => [s.address, s]));
    const aggregatedStringValues = new Map<string, string>();
    const aggregatedStringRefs = new Map<string, Set<string>>();
    let truncated = false;

    while (queue.length > 0) {
      const curr = queue.shift()!;
      const proc = curr.proc;
      if (visited.has(proc.address)) {
        continue;
      }
      if (nodes.length >= maxNodes) {
        truncated = true;
        break;
      }
      visited.add(proc.address);

      const procHex = toHex(proc.address);
      const callers = [...proc.callers]
        .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
        .map((addr) => model.proceduresByAddr.get(addr))
        .filter((p): p is ParsedProcedure => p !== undefined)
        .map((p) => ({
          address: toHex(p.address),
          name: p.name,
        }));

      const sortedCalleeAddrs = [...proc.callees].sort((a, b) =>
        a < b ? -1 : a > b ? 1 : 0,
      );
      const callees = sortedCalleeAddrs
        .map((addr) => model.proceduresByAddr.get(addr))
        .filter((p): p is ParsedProcedure => p !== undefined)
        .map((p) => ({
          address: toHex(p.address),
          name: p.name,
        }));

      const seenNodeStrings = new Set<string>();
      const nodeStrings: Array<{ readonly address: string; readonly value: string }> = [];
      for (const ins of proc.instructions) {
        if (ins.targetAddress === null) continue;
        const s = stringMap.get(ins.targetAddress);
        if (s !== undefined) {
          const sHex = toHex(s.address);
          if (!seenNodeStrings.has(sHex)) {
            seenNodeStrings.add(sHex);
            nodeStrings.push({ address: sHex, value: s.value });
          }
          aggregatedStringValues.set(sHex, s.value);
          const refSet = aggregatedStringRefs.get(sHex) ?? new Set<string>();
          refSet.add(procHex);
          aggregatedStringRefs.set(sHex, refSet);
        }
      }

      const inferredOffsets = this.#extractInferredStructOffsets(proc);
      const latentHazards = this.#extractLatentBinaryHazards(proc, model);

      nodes.push({
        procedure: {
          address: procHex,
          name: proc.name,
          signature: this.#formatSignature(proc, model),
        },
        depth: curr.depth,
        pseudocode: this.#synthesizePseudoCode(proc, model),
        assembly: includeAssembly ? this.#formatAssemblyLines(proc) : [],
        callers,
        callees,
        referenced_strings: nodeStrings,
        inferred_struct_offsets: inferredOffsets,
        latent_hazards: latentHazards,
      });

      const nextItems: Array<{ readonly proc: ParsedProcedure; readonly depth: number }> = [];
      for (const calleeAddr of sortedCalleeAddrs) {
        const callee = model.proceduresByAddr.get(calleeAddr);
        if (callee === undefined) continue;
        const calleeHex = toHex(callee.address);
        if (visited.has(calleeAddr)) {
          cycleEdges.push({
            from: procHex,
            from_name: proc.name,
            to: calleeHex,
            to_name: callee.name,
          });
          edges.push({
            from: procHex,
            from_name: proc.name,
            to: calleeHex,
            to_name: callee.name,
            kind: "cycle_call",
          });
        } else {
          edges.push({
            from: procHex,
            from_name: proc.name,
            to: calleeHex,
            to_name: callee.name,
            kind: "direct_call",
          });
          if (curr.depth + 1 > maxDepth) {
            truncated = true;
          } else if (!scheduled.has(calleeAddr) || traversal === "dfs") {
            scheduled.add(calleeAddr);
            nextItems.push({ proc: callee, depth: curr.depth + 1 });
          }
        }
      }

      if (traversal === "dfs") {
        queue.unshift(...nextItems);
      } else {
        queue.push(...nextItems);
      }
    }

    const totalLatentHazards = nodes.reduce((sum, n) => {
      const h = n.latent_hazards;
      return sum + (Array.isArray(h) ? h.length : 0);
    }, 0);

    const aggregatedStrings = [...aggregatedStringValues.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([address, value]) => ({
        address,
        value,
        referenced_by: [...(aggregatedStringRefs.get(address) ?? [])].sort(),
      }));

    return ok({
      root_procedure: {
        address: toHex(rootProc.address),
        name: rootProc.name,
        signature: this.#formatSignature(rootProc, model),
      },
      traversal,
      max_depth: maxDepth,
      max_nodes: maxNodes,
      node_count: nodes.length,
      total_latent_hazards: totalLatentHazards,
      truncated,
      cycle_edges: cycleEdges,
      nodes,
      edges,
      aggregated_strings: aggregatedStrings,
      limitations: [...BASE_LIMITATIONS],
    });
  }

  #extractLatentBinaryHazards(
    proc: ParsedProcedure,
    model: BinaryAnalysisModel,
  ): Array<Readonly<Record<string, JsonValue>>> {
    if (proc.thunk) {
      return [];
    }
    const hazards = new Map<string, Readonly<Record<string, JsonValue>>>();
    const recordHazard = (
      category:
        | "potential_integer_overflow_to_pointer"
        | "unchecked_division"
        | "thread_hostile_mutable_global"
        | "unsafe_memory_sink"
        | "uninitialized_or_stack_hazard",
      severity: "high" | "medium" | "low",
      address: string,
      instructionOrOp: string,
      description: string,
    ) => {
      const key = `${category}:${address}`;
      if (!hazards.has(key)) {
        hazards.set(key, {
          category,
          severity,
          address,
          instruction_or_op: instructionOrOp,
          description,
        });
      }
    };

    const unsafeSinks = new Set([
      "strcpy",
      "strcat",
      "sprintf",
      "vsprintf",
      "gets",
      "scanf",
      "__isoc99_scanf",
      "system",
      "popen",
    ]);

    const writableSegments = model.segments.filter((s) => s.writable);
    const isWritableGlobalAddr = (addr: bigint): boolean =>
      writableSegments.some((s) => addr >= s.start && addr < s.end);

    const hasSignExtOrArrayIndex = proc.instructions.some((ins) => {
      const m = ins.mnemonic.toLowerCase();
      if (
        m === "movsxd" ||
        m === "movslq" ||
        m === "cdqe" ||
        m === "cltq" ||
        m === "sxtw"
      ) {
        return true;
      }
      return ins.operands.some((op) => /\[.*[+*].*\]|\(.*,.*,.*\)/u.test(op));
    });

    for (let i = 0; i < proc.instructions.length; i++) {
      const ins = proc.instructions[i]!;
      const m = ins.mnemonic.toLowerCase();
      const addrHex = toHex(ins.address);
      const opsJoined = ins.operands.join(", ");
      const rendered = `${addrHex}: ${ins.mnemonic}${opsJoined.length > 0 ? ` ${opsJoined}` : ""}`;
      const lowerOps = opsJoined.toLowerCase();

      // 1. potential_integer_overflow_to_pointer
      const is32BitRegMention =
        /\b(?:e[abcd]x|e[sd]i|r(?:8|9|1[0-5])d|w\d+)\b/u.test(lowerOps);
      if (
        (m.startsWith("imul") ||
          m.startsWith("mul") ||
          m === "madd" ||
          (m.startsWith("shl") && hasSignExtOrArrayIndex)) &&
        (is32BitRegMention || hasSignExtOrArrayIndex)
      ) {
        recordHazard(
          "potential_integer_overflow_to_pointer",
          "high",
          addrHex,
          rendered,
          "32-bit integer multiplication/shift in a procedure with 64-bit sign-extension or pointer indexing can wrap before offset calculation; promote to usize/u64 and use checked_mul in Safe Rust.",
        );
      }

      // 2. unchecked_division
      if (
        m === "div" ||
        m === "idiv" ||
        m === "divl" ||
        m === "idivl" ||
        m === "divq" ||
        m === "idivq" ||
        m === "udiv" ||
        m === "sdiv" ||
        m === "divss" ||
        m === "divsd" ||
        m === "fdiv"
      ) {
        let guarded = false;
        for (let back = Math.max(0, i - 4); back < i; back++) {
          const prevM = proc.instructions[back]!.mnemonic.toLowerCase();
          if (
            prevM.startsWith("test") ||
            prevM.startsWith("cmp") ||
            prevM.startsWith("cbz") ||
            prevM.startsWith("cbnz") ||
            prevM.startsWith("ucomi")
          ) {
            guarded = true;
            break;
          }
        }
        if (!guarded) {
          recordHazard(
            "unchecked_division",
            "high",
            addrHex,
            rendered,
            "Hardware division instruction without an adjacent zero-divisor check; use checked_div / checked_rem or explicit zero guards in Safe Rust.",
          );
        }
      }

      // 3. thread_hostile_mutable_global
      const firstOpLower = (ins.operands[0] ?? "").toLowerCase();
      const lastOpLower = (
        ins.operands[ins.operands.length - 1] ?? ""
      ).toLowerCase();
      const isMutatingMnem =
        m.startsWith("mov") ||
        m.startsWith("add") ||
        m.startsWith("sub") ||
        m.startsWith("xor") ||
        m.startsWith("or") ||
        m.startsWith("and") ||
        m.startsWith("inc") ||
        m.startsWith("dec") ||
        m.startsWith("str") ||
        m.startsWith("stur") ||
        m.startsWith("stp") ||
        m.startsWith("xchg") ||
        m.startsWith("cmpxchg");
      const writesRipRelativeIntel =
        isMutatingMnem &&
        !m.startsWith("lea") &&
        firstOpLower.includes("rip") &&
        firstOpLower.includes("[");
      const writesRipRelativeAtt =
        isMutatingMnem &&
        !m.startsWith("lea") &&
        ins.operands.length >= 2 &&
        lastOpLower.includes("(%rip)");
      const gotBinding =
        ins.targetAddress !== null
          ? model.gotSlotByAddr.get(ins.targetAddress)
          : undefined;
      const accessesWritableGotGlobal =
        gotBinding !== undefined &&
        gotBinding.isWritableGlobal &&
        !gotBinding.isFunction;
      const writesGlobalTarget =
        !m.startsWith("lea") &&
        gotBinding?.isFunction !== true &&
        ins.targetAddress !== null &&
        isWritableGlobalAddr(ins.targetAddress) &&
        ((isMutatingMnem &&
          (firstOpLower.includes("rip") ||
            lastOpLower.includes("(%rip)") ||
            m.startsWith("add") ||
            m.startsWith("sub") ||
            m.startsWith("xor") ||
            m.startsWith("or") ||
            m.startsWith("and") ||
            m.startsWith("inc") ||
            m.startsWith("dec") ||
            m.startsWith("str") ||
            m.startsWith("stur") ||
            m.startsWith("stp") ||
            (m.startsWith("mov") &&
              (firstOpLower.includes("[") || lastOpLower.includes("(%rip)"))))) ||
          (m.startsWith("ldr") &&
            model.symbolsByAddr.get(ins.targetAddress)?.isFunction === false));

      if (
        writesRipRelativeIntel ||
        writesRipRelativeAtt ||
        writesGlobalTarget ||
        accessesWritableGotGlobal
      ) {
        const resolvedSym =
          gotBinding?.symbolName ??
          (ins.targetAddress !== null
            ? model.symbolsByAddr.get(ins.targetAddress)?.name
            : undefined);
        const symClause =
          resolvedSym !== undefined ? ` ('${resolvedSym}')` : "";
        recordHazard(
          "thread_hostile_mutable_global",
          "medium",
          addrHex,
          rendered,
          `Instruction accesses or mutates process-global state${symClause} in a writable data/BSS section without synchronization; move state into an explicit context struct or Atomic/Mutex in Safe Rust.`,
        );
      }

      // 4. unsafe_memory_sink
      if (ins.isCall && ins.targetAddress !== null) {
        const rawCallee =
          model.proceduresByAddr.get(ins.targetAddress)?.name ??
          model.symbolsByAddr.get(ins.targetAddress)?.name ??
          "";
        const cleanCallee = rawCallee
          .replace(/^_+/u, "")
          .replace(/@plt$/u, "")
          .toLowerCase();
        if (unsafeSinks.has(cleanCallee)) {
          recordHazard(
            "unsafe_memory_sink",
            "high",
            addrHex,
            rendered,
            `Calls unbounded C sink '${cleanCallee}'; replace with bounds-checked Rust slice/String formatting.`,
          );
        }
      }

      // 5. uninitialized_or_stack_hazard
      if (
        m.startsWith("sub") &&
        (firstOpLower === "rsp" ||
          firstOpLower === "%rsp" ||
          lastOpLower === "%rsp" ||
          firstOpLower === "sp")
      ) {
        for (const op of ins.operands) {
          const immMatch = op.match(/(?:0x([0-9a-fA-F]+)|(\d+))$/u);
          if (immMatch !== null) {
            const val =
              immMatch[1] !== undefined
                ? Number.parseInt(immMatch[1], 16)
                : Number.parseInt(immMatch[2]!, 10);
            if (!Number.isNaN(val) && val >= 4096) {
              recordHazard(
                "uninitialized_or_stack_hazard",
                "medium",
                addrHex,
                rendered,
                `Large stack frame allocation (${val} bytes); prefer heap-allocated Vec or bounded buffers in Safe Rust.`,
              );
            }
          }
        }
      }
    }

    return [...hazards.values()];
  }

  #extractInferredStructOffsets(
    proc: ParsedProcedure,
  ): Array<Readonly<Record<string, JsonValue>>> {
    const excludedBases = new Set([
      "rsp",
      "rbp",
      "esp",
      "ebp",
      "sp",
      "fp",
      "rip",
      "eip",
      "pc",
      "x29",
      "x30",
      "lr",
    ]);
    const tracked = new Map<
      string,
      {
        readonly base: string;
        readonly offset: number;
        size: number;
        hasRead: boolean;
        hasWrite: boolean;
        hasAddress: boolean;
      }
    >();

    const recordAccess = (
      rawBase: string,
      offset: number,
      size: number,
      mode: "read" | "write" | "address",
    ) => {
      const base = rawBase.replace(/^%/u, "").toLowerCase();
      if (excludedBases.has(base)) return;
      if (offset < 0) return;
      const key = `${base}:${offset}`;
      const existing = tracked.get(key);
      if (existing === undefined) {
        tracked.set(key, {
          base,
          offset,
          size: Math.max(0, size),
          hasRead: mode === "read",
          hasWrite: mode === "write",
          hasAddress: mode === "address",
        });
      } else {
        if (mode === "read") existing.hasRead = true;
        if (mode === "write") existing.hasWrite = true;
        if (mode === "address") existing.hasAddress = true;
        if (size > existing.size) existing.size = size;
      }
    };

    const inferSize = (mnem: string, rawText: string, ops: readonly string[]): number => {
      const m = mnem.toLowerCase();
      const lower = rawText.toLowerCase();
      if (m === "lea" || m === "leal" || m === "leaq") return 0;
      if (
        lower.includes("byte ptr") ||
        m === "ldrb" ||
        m === "ldrsb" ||
        m === "ldurb" ||
        m === "strb" ||
        m === "sturb"
      ) {
        return 1;
      }
      if (lower.includes("word ptr") && !lower.includes("dword ptr") && !lower.includes("qword ptr")) {
        return 2;
      }
      if (
        m === "ldrh" ||
        m === "ldrsh" ||
        m === "ldurh" ||
        m === "strh" ||
        m === "sturh" ||
        m === "movw"
      ) {
        return 2;
      }
      if (
        lower.includes("dword ptr") ||
        m === "movl" ||
        m === "addl" ||
        m === "cmpl" ||
        m === "ldrsw" ||
        m === "ldursw"
      ) {
        return 4;
      }
      if (lower.includes("qword ptr") || m === "movq" || m === "addq" || m === "cmpq") {
        return 8;
      }
      for (const op of ops) {
        const clean = op.replace(/^%/u, "").trim().toLowerCase();
        if (/^(?:[abcd]l|[sd]il|r(?:8|9|1[0-5])b|b\d+)$/u.test(clean)) return 1;
        if (/^(?:[abcd]x|[sd]i|r(?:8|9|1[0-5])w|h\d+)$/u.test(clean)) return 2;
        if (/^(?:e[abcd]x|e[sd]i|r(?:8|9|1[0-5])d|w\d+|s\d+)$/u.test(clean)) return 4;
        if (/^(?:r[abcd]x|r[sd]i|r(?:8|9|1[0-5])|x\d+|d\d+)$/u.test(clean)) return 8;
        if (/^q\d+$/u.test(clean)) return 16;
      }
      return 8;
    };

    for (const ins of proc.instructions) {
      const m = ins.mnemonic.toLowerCase();
      const isAddressOnly = m.startsWith("lea");
      const isArmStore =
        m.startsWith("str") || m.startsWith("stur") || m.startsWith("stp");
      const isArmPair = m === "ldp" || m === "stp";
      const size = inferSize(m, ins.rawText, ins.operands);

      for (let idx = 0; idx < ins.operands.length; idx++) {
        const op = ins.operands[idx]!;
        // 1. AT&T syntax: disp(%reg) or (%reg)
        const attMatch = op.match(
          /^(-?(?:0x[0-9a-fA-F]+|\d+))?\(%([a-zA-Z0-9]+)\)$/u,
        );
        if (attMatch !== null) {
          const dispStr = attMatch[1];
          const reg = attMatch[2]!;
          const offset =
            dispStr === undefined || dispStr.length === 0
              ? 0
              : dispStr.startsWith("-0x") || dispStr.startsWith("-0X")
                ? -Number.parseInt(dispStr.slice(3), 16)
                : dispStr.startsWith("0x") || dispStr.startsWith("0X")
                  ? Number.parseInt(dispStr.slice(2), 16)
                  : Number.parseInt(dispStr, 10);
          const mode: "read" | "write" | "address" = isAddressOnly
            ? "address"
            : idx === ins.operands.length - 1 &&
                !m.startsWith("cmp") &&
                !m.startsWith("test")
              ? "write"
              : "read";
          recordAccess(reg, offset, size, mode);
          continue;
        }

        // 2. Intel / ARM bracket syntax: [reg], [reg + 0x10], [x0, #16]
        const bracketMatch = op.match(
          /\[([a-zA-Z0-9]+)(?:\s*(?:([+-])\s*(0x[0-9a-fA-F]+|\d+)|,\s*#?(-?(?:0x[0-9a-fA-F]+|\d+))))?\]/u,
        );
        if (bracketMatch !== null) {
          const reg = bracketMatch[1]!;
          let offset = 0;
          if (bracketMatch[3] !== undefined) {
            const sign = bracketMatch[2] === "-" ? -1 : 1;
            const rawNum = bracketMatch[3];
            const mag =
              rawNum.startsWith("0x") || rawNum.startsWith("0X")
                ? Number.parseInt(rawNum.slice(2), 16)
                : Number.parseInt(rawNum, 10);
            offset = sign * mag;
          } else if (bracketMatch[4] !== undefined) {
            const rawImm = bracketMatch[4];
            offset =
              rawImm.startsWith("-0x") || rawImm.startsWith("-0X")
                ? -Number.parseInt(rawImm.slice(3), 16)
                : rawImm.startsWith("0x") || rawImm.startsWith("0X")
                  ? Number.parseInt(rawImm.slice(2), 16)
                  : Number.parseInt(rawImm, 10);
          }
          const mode: "read" | "write" | "address" = isAddressOnly
            ? "address"
            : isArmStore ||
                (idx === 0 &&
                  !m.startsWith("cmp") &&
                  !m.startsWith("test") &&
                  !m.startsWith("ldr") &&
                  !m.startsWith("ldur") &&
                  !m.startsWith("ldp"))
              ? "write"
              : "read";
          recordAccess(reg, offset, size, mode);
          if (isArmPair && size > 0) {
            recordAccess(reg, offset + size, size, mode);
          }
        }
      }
    }

    return [...tracked.values()]
      .sort((a, b) =>
        a.base !== b.base ? a.base.localeCompare(b.base) : a.offset - b.offset,
      )
      .map((entry) => ({
        base: entry.base,
        offset: entry.offset,
        offset_hex:
          entry.offset < 0
            ? `-0x${Math.abs(entry.offset).toString(16)}`
            : `+0x${entry.offset.toString(16)}`,
        size: entry.size,
        access:
          entry.hasRead && entry.hasWrite
            ? "read_write"
            : entry.hasRead
              ? "read"
              : entry.hasWrite
                ? "write"
                : "address",
        field_name: `field_${Math.abs(entry.offset).toString(16)}`,
      }));
  }

  #inspectNativeInstruction(
    addr: bigint,
    model: BinaryAnalysisModel,
  ): Readonly<Record<string, JsonValue>> {
    const proc = this.#findContainingProcedure(model, addr);
    const insn = model.instructionsByAddr.get(addr);
    const inSeg = model.segments.some(
      (seg) => addr >= seg.start && addr < seg.end,
    );
    if (!inSeg) {
      return {
        address: toHex(addr),
        status: "outside-memory",
        procedure: null,
        architecture: model.architecture,
        mode: model.is64Bit ? "64-bit" : "32-bit",
        bytes: null,
        length: null,
        mnemonic: null,
        raw_disassembly: null,
        operands: [],
        flow: {
          kind: "unavailable",
          conditional: false,
          computed: false,
          direct_destinations: [],
        },
        references: [],
        incoming_references: [],
        limitations: [...BASE_LIMITATIONS],
      };
    }
    if (insn === undefined) {
      return {
        address: toHex(addr),
        status: "data",
        procedure: proc === undefined ? null : toHex(proc.address),
        architecture: model.architecture,
        mode: model.is64Bit ? "64-bit" : "32-bit",
        bytes: null,
        length: null,
        mnemonic: null,
        raw_disassembly: null,
        operands: [],
        flow: {
          kind: "unavailable",
          conditional: false,
          computed: false,
          direct_destinations: [],
        },
        references: [],
        incoming_references: [],
        limitations: [...BASE_LIMITATIONS],
      };
    }
    const outgoing = (model.outgoingRefsBySource.get(addr) ?? []).map(
      (ref) => ({
        target_address: toHex(ref.targetAddr),
        type: ref.isCall
          ? "UNCONDITIONAL_CALL"
          : ref.isConditional
            ? "CONDITIONAL_JUMP"
            : ref.isJump
              ? "UNCONDITIONAL_JUMP"
              : "DATA",
        call: ref.isCall,
        jump: ref.isJump,
        indirect: insn.isIndirect,
        computed: insn.isIndirect,
        operand_index: 0,
        source_address: toHex(ref.sourceAddr),
        data: ref.isData,
        read: ref.isData,
        write: false,
        primary: true,
        provenance: "zero-install-disassembler",
        source: "analysis",
      }),
    );
    const incoming = (model.incomingRefsByTarget.get(addr) ?? []).map(
      (ref) => ({
        target_address: toHex(ref.targetAddr),
        type: ref.isCall
          ? "UNCONDITIONAL_CALL"
          : ref.isConditional
            ? "CONDITIONAL_JUMP"
            : ref.isJump
              ? "UNCONDITIONAL_JUMP"
              : "DATA",
        call: ref.isCall,
        jump: ref.isJump,
        indirect: false,
        computed: false,
        operand_index: 0,
        source_address: toHex(ref.sourceAddr),
        data: ref.isData,
        read: ref.isData,
        write: false,
        primary: true,
        provenance: "zero-install-disassembler",
        source: "analysis",
      }),
    );
    return {
      address: toHex(addr),
      status: "decoded",
      procedure: proc === undefined ? null : toHex(proc.address),
      architecture: model.architecture,
      mode: model.is64Bit ? "64-bit" : "32-bit",
      bytes: insn.bytesHex,
      length: insn.length,
      mnemonic: insn.mnemonic,
      raw_disassembly: insn.rawText,
      operands: insn.operands.map((op, idx) => ({
        index: idx,
        raw: op,
        provider_type: 1,
        components: [
          {
            kind: op.startsWith("0x") ? "address" : "register",
            text: op,
            value: op.startsWith("0x") ? op : null,
            bit_width: model.is64Bit ? 64 : 32,
          },
        ],
        memory_addressing: "unavailable",
      })),
      flow: {
        kind: insn.isCall
          ? "call"
          : insn.isJump
            ? "jump"
            : insn.isReturn
              ? "return"
              : "fallthrough",
        conditional: insn.isConditionalJump,
        computed: insn.isIndirect,
        direct_destinations:
          insn.targetAddress === null ? [] : [toHex(insn.targetAddress)],
      },
      references: outgoing,
      incoming_references: incoming,
      limitations: [...BASE_LIMITATIONS],
    };
  }

  #resolveNativeCallTargets(
    addr: bigint,
    model: BinaryAnalysisModel,
  ): Readonly<Record<string, JsonValue>> {
    const proc = this.#findContainingProcedure(model, addr);
    const insn = model.instructionsByAddr.get(addr);
    if (insn === undefined || !insn.isCall) {
      return {
        call_site: toHex(addr),
        procedure: proc === undefined ? null : toHex(proc.address),
        status: "not-call",
        mechanism: "unavailable",
        targets: [],
        limitations: [...BASE_LIMITATIONS],
      };
    }
    if (insn.targetAddress === null) {
      return {
        call_site: toHex(addr),
        procedure: proc === undefined ? null : toHex(proc.address),
        status: "unresolved",
        mechanism: insn.isIndirect ? "indirect" : "computed",
        targets: [],
        limitations: [...BASE_LIMITATIONS],
      };
    }
    const targetProc = this.#findContainingProcedure(model, insn.targetAddress);
    return {
      call_site: toHex(addr),
      procedure: proc === undefined ? null : toHex(proc.address),
      status: "direct",
      mechanism: "direct",
      targets: [
        {
          address: toHex(insn.targetAddress),
          procedure: targetProc === undefined ? null : toHex(targetProc.address),
          status: "direct",
          basis: "provider-reference",
          references: [
            {
              target_address: toHex(insn.targetAddress),
              type: "UNCONDITIONAL_CALL",
              call: true,
              jump: false,
              indirect: false,
              computed: false,
              operand_index: 0,
              source_address: toHex(addr),
              data: false,
              read: false,
              write: false,
              primary: true,
              provenance: "zero-install-disassembler",
              source: "analysis",
            },
          ],
        },
      ],
      limitations: [...BASE_LIMITATIONS],
    };
  }

  #inspectNativeDataType(
    parameters: Readonly<Record<string, JsonValue>>,
    model: BinaryAnalysisModel,
  ): Readonly<Record<string, JsonValue>> {
    const typeName =
      typeof parameters.type === "string" ? parameters.type : null;
    const addrStr =
      typeof parameters.address === "string" ? parameters.address : null;
    return {
      status: "unavailable",
      reason:
        "Zero-install static disassembly engine does not maintain a symbolic C type archive.",
      id: null,
      name: typeName,
      kind: "unavailable",
      source: "analysis-database",
      source_archive: null,
      address:
        addrStr !== null && parseAddressString(addrStr) !== null
          ? toHex(parseAddressString(addrStr)!)
          : null,
      size_bytes: model.is64Bit ? 8 : 4,
      alignment_bytes: model.is64Bit ? 8 : 4,
      packing_enabled: null,
      referenced_type: null,
      array_count: null,
      array_stride_bytes: null,
      fields: [],
      members: [],
      total_fields: 0,
      truncated: false,
      limitations: [...BASE_LIMITATIONS],
    };
  }

  #inspectNativeLoadImage(
    model: BinaryAnalysisModel,
  ): Readonly<Record<string, JsonValue>> {
    const mappings = model.segments.map((seg) => {
      const len = Math.max(1, Number(seg.end - seg.start));
      const slice =
        seg.fileSize > 0 && seg.fileOffset + seg.fileSize <= model.bytes.length
          ? model.bytes.subarray(seg.fileOffset, seg.fileOffset + seg.fileSize)
          : null;
      const digest =
        slice !== null
          ? createHash("sha256").update(slice).digest("hex")
          : null;
      return {
        block: seg.name,
        start: toHex(seg.start),
        end: toHex(seg.end - 1n),
        address_space: "ram",
        initialized: seg.initialized,
        loaded: true,
        overlay: false,
        length: len,
        source_file_index: 0,
        file_offset: seg.fileSize > 0 ? seg.fileOffset : null,
        sha256: digest,
      };
    });
    const observations = {
      executable_format: this.#target.format,
      language_id: `${model.architecture}:LE:${model.is64Bit ? 64 : 32}:default`,
      compiler_spec_id: "default",
      image_base: toHex(model.imageBase),
      default_address_space: "ram",
      source_files: [
        {
          name: basename(this.#target.path),
          size: model.bytes.length,
          original_sha256: model.sha256,
          modified_sha256: model.sha256,
        },
      ],
      mappings,
      relocations: [],
      entry_points: [toHex(model.entryPoint)],
      entry_context: [],
    };
    return {
      status: "unsupported",
      reason:
        "Zero-install native load image observation reports static segment mappings.",
      observations,
      limitations: [...BASE_LIMITATIONS],
    };
  }
}

async function buildBinaryAnalysisModel(
  target: BinaryTarget,
  environment: Readonly<NodeJS.ProcessEnv>,
  platform: NodeJS.Platform,
  logger: Logger,
): Promise<BinaryAnalysisModel> {
  const bytes = await readFile(target.path);
  const sha256 =
    target.sha256 || createHash("sha256").update(bytes).digest("hex");

  let parsedFormat = parseBinaryContainers(bytes, target);
  if (parsedFormat.segments.length === 0) {
    const fallbackStart = 0x400000n;
    const fallbackEnd = fallbackStart + BigInt(Math.max(1, bytes.length));
    parsedFormat = {
      ...parsedFormat,
      segments: [
        {
          name: ".text",
          start: fallbackStart,
          end: fallbackEnd,
          fileOffset: 0,
          fileSize: bytes.length,
          readable: true,
          writable: false,
          executable: true,
          initialized: true,
          sections: [
            {
              name: ".text",
              start: fallbackStart,
              end: fallbackEnd,
              fileOffset: 0,
              fileSize: bytes.length,
              readable: true,
              writable: false,
              executable: true,
              initialized: true,
            },
          ],
        },
      ],
    };
  }

  // Enrich symbols & disassembly with host CLI tools when available
  await enrichWithHostCliTools(
    target.path,
    parsedFormat,
    environment,
    platform,
    logger,
  );

  // Automatically seed C++ RTTI vtable methods & demangled symbols when present
  const rttiAnnotationsByAddr = new Map<bigint, string>();
  await enrichWithRustCppRttiAndSymbols(
    target.path,
    parsedFormat,
    rttiAnnotationsByAddr,
    logger,
  );

  // Ensure all executable sections have decoded instructions (fallback bytecode decoder)
  if (parsedFormat.instructionsByAddr.size === 0) {
    decodeExecutableSectionsBuiltin(bytes, parsedFormat);
  }

  // Extract printable ASCII/UTF-8 strings from initialized non-empty sections
  const strings = extractBinaryStrings(bytes, parsedFormat.segments);

  // Discover procedures (named symbols + entry point + call targets + function prologues)
  const {
    proceduresByAddr,
    sortedProcedures,
    incomingRefsByTarget,
    outgoingRefsBySource,
  } = buildProceduresAndReferences(parsedFormat, strings);

  return {
    bytes,
    sha256,
    imageBase: parsedFormat.imageBase,
    entryPoint: parsedFormat.entryPoint,
    is64Bit: parsedFormat.is64Bit,
    littleEndian: parsedFormat.littleEndian,
    architecture: parsedFormat.architecture,
    segments: parsedFormat.segments,
    symbolsByAddr: parsedFormat.symbolsByAddr,
    gotSlotByAddr: parsedFormat.gotSlotByAddr,
    rttiAnnotationsByAddr,
    proceduresByAddr,
    sortedProcedures,
    strings,
    instructionsByAddr: parsedFormat.instructionsByAddr,
    incomingRefsByTarget,
    outgoingRefsBySource,
  };
}

async function enrichWithRustCppRttiAndSymbols(
  targetPath: string,
  parsed: MutableContainerParse,
  rttiAnnotationsByAddr: Map<bigint, string>,
  logger: Logger,
): Promise<void> {
  try {
    const rustCppResult = await new RustCppBinaryInspector().inspect({
      path: targetPath,
      max_panic_locations: 100,
      max_symbols: 500,
    });
    if (!rustCppResult.ok) return;
    const report = rustCppResult.value;
    for (const cls of report.cpp.classes) {
      const cleanClassName = cls.class_name
        .replace(/^class\s+|^struct\s+/iu, "")
        .replace(/[^A-Za-z0-9_]/gu, "_")
        .replace(/_+/gu, "_")
        .replace(/^_+|_+$/gu, "");
      if (cleanClassName.length === 0) continue;
      const baseSuffix =
        cls.base_classes.length > 0
          ? ` : ${cls.base_classes.join(", ")}`
          : "";
      for (const vm of cls.virtual_methods) {
        const vmAddr = parseAddressString(vm.address);
        if (vmAddr === null || vmAddr <= 0n) continue;
        const hexSuffix = vmAddr.toString(16).toLowerCase();
        const synthName = `${cleanClassName}__vslot_${vm.slot}_${hexSuffix}`;
        const annotation = `C++ RTTI VTable Slot #${vm.slot} of ${cls.class_name}${baseSuffix} (vtable @ ${cls.vtable_address ?? "unknown"})`;
        if (!rttiAnnotationsByAddr.has(vmAddr)) {
          rttiAnnotationsByAddr.set(vmAddr, annotation);
        }
        parsed.functionStartHints.add(vmAddr);
        const existingSym = parsed.symbolsByAddr.get(vmAddr);
        if (
          existingSym === undefined ||
          existingSym.name.startsWith("sub_") ||
          existingSym.name.startsWith(".")
        ) {
          parsed.symbolsByAddr.set(vmAddr, {
            address: vmAddr,
            name: synthName,
            size: existingSym?.size ?? 0,
            isFunction: true,
            external: false,
            dynamic: false,
            thunk: false,
            thunkTarget: null,
            source: "analysis",
          });
        }
      }
    }
    for (const dem of [
      ...report.rust.demangled_symbols,
      ...report.cpp.demangled_symbols,
    ]) {
      for (const [symAddr, sym] of parsed.symbolsByAddr.entries()) {
        if (
          sym.name === dem.mangled &&
          !rttiAnnotationsByAddr.has(symAddr)
        ) {
          rttiAnnotationsByAddr.set(
            symAddr,
            `Demangled (${dem.encoding}): ${dem.demangled}`,
          );
        }
      }
    }
  } catch (cause: unknown) {
    logger.debug({ cause }, "Rust/C++ RTTI symbol seeding skipped");
  }
}

interface MutableContainerParse {
  imageBase: bigint;
  entryPoint: bigint;
  is64Bit: boolean;
  littleEndian: boolean;
  architecture: string;
  segments: ParsedSegment[];
  symbolsByAddr: Map<bigint, ParsedSymbol>;
  gotSlotByAddr: Map<bigint, GotSlotBinding>;
  instructionsByAddr: Map<bigint, DecodedInsn>;
  functionStartHints: Set<bigint>;
}

function parseBinaryContainers(
  bytes: Buffer,
  target: BinaryTarget,
): MutableContainerParse {
  if (bytes.length >= 64 && bytes.subarray(0, 4).equals(Buffer.from("\x7fELF"))) {
    return parseElfContainer(bytes, target);
  }
  if (bytes.length >= 28) {
    const magicBE = bytes.readUInt32BE(0);
    const magicLE = bytes.readUInt32LE(0);
    if (
      magicBE === 0xcafebabe ||
      magicBE === 0xcafebabf ||
      magicLE === 0xfeedface ||
      magicLE === 0xfeedfacf ||
      magicBE === 0xfeedface ||
      magicBE === 0xfeedfacf
    ) {
      return parseMachOContainer(bytes, target);
    }
  }
  if (bytes.length >= 0x40 && bytes[0] === 0x4d && bytes[1] === 0x5a) {
    return parsePeContainer(bytes, target);
  }
  const base = 0x400000n;
  return {
    imageBase: base,
    entryPoint: base,
    is64Bit: target.architecture === "x86_64" || target.architecture === "arm64",
    littleEndian: true,
    architecture: target.architecture ?? "x86_64",
    segments: [],
    symbolsByAddr: new Map(),
    gotSlotByAddr: new Map(),
    instructionsByAddr: new Map(),
    functionStartHints: new Set([base]),
  };
}

interface RawElfRelocation {
  readonly rOffset: bigint;
  readonly rInfo: bigint;
  readonly rAddend: bigint;
}

/**
 * Unpacks Android Bionic APS2 SLEB128-packed relocation sections
 * (SHT_ANDROID_REL = 0x60000001 / SHT_ANDROID_RELA = 0x60000002, magic = "APS2").
 */
export function decodeAndroidAps2Relocations(
  secBytes: Uint8Array,
): RawElfRelocation[] {
  if (
    secBytes.length < 4 ||
    secBytes[0] !== 0x41 || // 'A'
    secBytes[1] !== 0x50 || // 'P'
    secBytes[2] !== 0x53 || // 'S'
    secBytes[3] !== 0x32 // '2'
  ) {
    return [];
  }
  let pos = 4;
  const readSleb128 = (): bigint => {
    let result = 0n;
    let shift = 0n;
    let byte = 0;
    while (pos < secBytes.length) {
      byte = secBytes[pos++]!;
      result |= BigInt(byte & 0x7f) << shift;
      shift += 7n;
      if ((byte & 0x80) === 0) break;
    }
    if (shift < 64n && (byte & 0x40) !== 0) {
      result |= -1n << shift;
    }
    return BigInt.asIntN(64, result);
  };

  const totalRelocs = Number(readSleb128());
  if (totalRelocs <= 0 || totalRelocs > 500_000) return [];
  let rOffset = readSleb128();
  let rAddend = 0n;
  const relocs: RawElfRelocation[] = [];
  let remaining = totalRelocs;

  const GROUPED_BY_INFO = 1n;
  const GROUPED_BY_OFFSET_DELTA = 2n;
  const GROUPED_BY_ADDEND = 4n;
  const GROUP_HAS_ADDEND = 8n;

  while (remaining > 0 && pos < secBytes.length) {
    const groupSize = Number(readSleb128());
    if (groupSize <= 0 || groupSize > remaining) break;
    const flags = readSleb128();
    const groupedByInfo = (flags & GROUPED_BY_INFO) !== 0n;
    const groupedByOffsetDelta = (flags & GROUPED_BY_OFFSET_DELTA) !== 0n;
    const groupedByAddend = (flags & GROUPED_BY_ADDEND) !== 0n;
    const hasAddend = (flags & GROUP_HAS_ADDEND) !== 0n;

    const offsetDelta = groupedByOffsetDelta ? readSleb128() : 0n;
    let rInfo = groupedByInfo ? readSleb128() : 0n;
    if (hasAddend && groupedByAddend) {
      rAddend += readSleb128();
    } else if (!hasAddend) {
      rAddend = 0n;
    }

    for (let i = 0; i < groupSize; i++) {
      rOffset += groupedByOffsetDelta ? offsetDelta : readSleb128();
      if (!groupedByInfo) {
        rInfo = readSleb128();
      }
      if (hasAddend && !groupedByAddend) {
        rAddend += readSleb128();
      }
      relocs.push({
        rOffset: BigInt.asUintN(64, rOffset),
        rInfo: BigInt.asUintN(64, rInfo),
        rAddend,
      });
    }
    remaining -= groupSize;
  }

  return relocs;
}

function parseElfContainer(
  bytes: Buffer,
  target: BinaryTarget,
): MutableContainerParse {
  const is64Bit = bytes[4] === 2;
  const littleEndian = bytes[5] !== 2;
  const readU16 = (off: number) =>
    littleEndian ? bytes.readUInt16LE(off) : bytes.readUInt16BE(off);
  const readU32 = (off: number) =>
    littleEndian ? bytes.readUInt32LE(off) : bytes.readUInt32BE(off);
  const readU64 = (off: number) =>
    littleEndian ? bytes.readBigUInt64LE(off) : bytes.readBigUInt64BE(off);
  const readI64 = (off: number) =>
    littleEndian ? bytes.readBigInt64LE(off) : bytes.readBigInt64BE(off);
  const readI32 = (off: number) =>
    BigInt(littleEndian ? bytes.readInt32LE(off) : bytes.readInt32BE(off));

  const eType = readU16(16);
  const eMachine = readU16(18);
  const arch: string =
    eMachine === 62
      ? "x86_64"
      : eMachine === 3
        ? "x86"
        : eMachine === 183
          ? "arm64"
          : eMachine === 40
            ? "arm"
            : eMachine === 8
              ? "mips"
              : eMachine === 243
                ? "riscv"
                : (target.architecture ?? "x86_64");

  const entryPoint = is64Bit ? readU64(24) : BigInt(readU32(24));
  const phOff = Number(is64Bit ? readU64(32) : BigInt(readU32(28)));
  const shOff = Number(is64Bit ? readU64(40) : BigInt(readU32(32)));
  const phEntSize = readU16(is64Bit ? 54 : 42);
  const phNum = readU16(is64Bit ? 56 : 44);
  const shEntSize = readU16(is64Bit ? 58 : 46);
  const shNum = readU16(is64Bit ? 60 : 48);
  const shStrNdx = readU16(is64Bit ? 62 : 50);

  const defaultPieBias = eType === 3 && entryPoint < 0x400000n ? 0n : 0n;

  interface RawElfSection {
    name: string;
    shType: number;
    shFlags: bigint;
    shAddr: bigint;
    shOffset: number;
    shSize: number;
    shLink: number;
    shEntSize: number;
  }
  const rawSections: RawElfSection[] = [];
  let shStrTabOffset = 0;
  let shStrTabSize = 0;
  if (
    shOff > 0 &&
    shNum > 0 &&
    shStrNdx < shNum &&
    shOff + shNum * shEntSize <= bytes.length
  ) {
    const strHdrOff = shOff + shStrNdx * shEntSize;
    shStrTabOffset = Number(
      is64Bit ? readU64(strHdrOff + 24) : BigInt(readU32(strHdrOff + 16)),
    );
    shStrTabSize = Number(
      is64Bit ? readU64(strHdrOff + 32) : BigInt(readU32(strHdrOff + 20)),
    );
  }

  const readCString = (tableOff: number, tableSize: number, idx: number) => {
    const start = tableOff + idx;
    const limit = Math.min(bytes.length, tableOff + tableSize);
    if (start < 0 || start >= limit) return "";
    let end = start;
    while (end < limit && bytes[end] !== 0) end++;
    return bytes.subarray(start, end).toString("utf8");
  };

  if (shOff > 0 && shNum > 0 && shOff + shNum * shEntSize <= bytes.length) {
    for (let i = 0; i < shNum; i++) {
      const off = shOff + i * shEntSize;
      const shNameIdx = readU32(off);
      const shType = readU32(off + 4);
      const shFlags = is64Bit ? readU64(off + 8) : BigInt(readU32(off + 8));
      const shAddr =
        (is64Bit ? readU64(off + 16) : BigInt(readU32(off + 12))) +
        defaultPieBias;
      const shOffset = Number(
        is64Bit ? readU64(off + 24) : BigInt(readU32(off + 16)),
      );
      const shSize = Number(
        is64Bit ? readU64(off + 32) : BigInt(readU32(off + 20)),
      );
      const shLink = readU32(off + (is64Bit ? 40 : 24));
      const entSz = Number(
        is64Bit ? readU64(off + 56) : BigInt(readU32(off + 36)),
      );
      const name = readCString(shStrTabOffset, shStrTabSize, shNameIdx);
      rawSections.push({
        name: name || `sect_${i}`,
        shType,
        shFlags,
        shAddr,
        shOffset,
        shSize,
        shLink,
        shEntSize: entSz,
      });
    }
  }

  const parsedSections: ParsedSection[] = rawSections
    .filter((s) => s.shType !== 0 && s.shSize > 0 && s.shAddr > 0n)
    .map((s) => ({
      name: s.name,
      start: s.shAddr,
      end: s.shAddr + BigInt(s.shSize),
      fileOffset: s.shOffset,
      fileSize: s.shType === 8 ? 0 : s.shSize,
      readable: true,
      writable: (s.shFlags & 0x1n) !== 0n,
      executable: (s.shFlags & 0x4n) !== 0n,
      initialized: s.shType !== 8,
    }));

  const segments: ParsedSegment[] = [];
  if (phOff > 0 && phNum > 0 && phOff + phNum * phEntSize <= bytes.length) {
    let loadIdx = 0;
    for (let i = 0; i < phNum; i++) {
      const off = phOff + i * phEntSize;
      const pType = readU32(off);
      if (pType !== 1) continue; // PT_LOAD
      const pFlags = is64Bit ? readU32(off + 4) : readU32(off + 24);
      const pOffset = Number(is64Bit ? readU64(off + 8) : BigInt(readU32(off + 4)));
      const pVaddr =
        (is64Bit ? readU64(off + 16) : BigInt(readU32(off + 8))) +
        defaultPieBias;
      const pFilesz = Number(
        is64Bit ? readU64(off + 32) : BigInt(readU32(off + 16)),
      );
      const pMemsz = Number(
        is64Bit ? readU64(off + 40) : BigInt(readU32(off + 20)),
      );
      if (pMemsz === 0) continue;
      const segStart = pVaddr;
      const segEnd = pVaddr + BigInt(pMemsz);
      const childSections = parsedSections.filter(
        (sec) => sec.start >= segStart && sec.end <= segEnd,
      );
      segments.push({
        name:
          childSections.length === 1
            ? childSections[0]!.name
            : `LOAD_${loadIdx++}`,
        start: segStart,
        end: segEnd,
        fileOffset: pOffset,
        fileSize: pFilesz,
        readable: (pFlags & 4) !== 0,
        writable: (pFlags & 2) !== 0,
        executable: (pFlags & 1) !== 0,
        initialized: pFilesz > 0,
        sections: childSections,
      });
    }
  }

  if (segments.length === 0 && parsedSections.length > 0) {
    for (const sec of parsedSections) {
      segments.push({
        name: sec.name,
        start: sec.start,
        end: sec.end,
        fileOffset: sec.fileOffset,
        fileSize: sec.fileSize,
        readable: sec.readable,
        writable: sec.writable,
        executable: sec.executable,
        initialized: sec.initialized,
        sections: [sec],
      });
    }
  }

  const symbolsByAddr = new Map<bigint, ParsedSymbol>();
  const gotSlotByAddr = new Map<bigint, GotSlotBinding>();
  const functionStartHints = new Set<bigint>();
  if (entryPoint > 0n) {
    functionStartHints.add(entryPoint);
  }

  interface IndexedElfSymbol {
    readonly name: string;
    readonly value: bigint;
    readonly size: number;
    readonly shndx: number;
    readonly stType: number;
    readonly isFunc: boolean;
    readonly isObject: boolean;
  }
  const dynSymsByIndex = new Map<number, IndexedElfSymbol>();

  for (const sec of rawSections) {
    if (sec.shType !== 2 && sec.shType !== 11) continue; // SYMTAB / DYNSYM
    const strSec = rawSections[sec.shLink];
    if (strSec === undefined) continue;
    const stride = sec.shEntSize || (is64Bit ? 24 : 16);
    const count = Math.floor(sec.shSize / stride);
    for (let i = 1; i < count; i++) {
      const symOff = sec.shOffset + i * stride;
      if (symOff + stride > bytes.length) break;
      const stName = readU32(symOff);
      const stInfo = is64Bit ? bytes[symOff + 4]! : bytes[symOff + 12]!;
      const stShndx = is64Bit ? readU16(symOff + 6) : readU16(symOff + 14);
      const stValue = is64Bit ? readU64(symOff + 8) : BigInt(readU32(symOff + 4));
      const stSize = Number(
        is64Bit ? readU64(symOff + 16) : BigInt(readU32(symOff + 8)),
      );
      const name = readCString(strSec.shOffset, strSec.shSize, stName);
      if (!name || name.startsWith(".")) continue;
      const stType = stInfo & 0xf;
      const isFunc = stType === 2 || stType === 10; // STT_FUNC / STT_GNU_IFUNC
      const isObject = stType === 1 || stType === 6; // STT_OBJECT / STT_TLS
      if (sec.shType === 11) {
        dynSymsByIndex.set(i, {
          name,
          value: stValue,
          size: stSize,
          shndx: stShndx,
          stType,
          isFunc,
          isObject,
        });
      }
      if (stValue === 0n) continue;
      const isExternal = stShndx === 0;
      symbolsByAddr.set(stValue, {
        address: stValue,
        name,
        size: stSize,
        isFunction: isFunc,
        external: isExternal,
        dynamic: sec.shType === 11,
        thunk: false,
        thunkTarget: null,
        source: "imported",
      });
      if (isFunc) {
        functionStartHints.add(stValue);
      }
    }
  }

  // Helper to read standard SHT_REL (9), SHT_RELA (4), or Android APS2 (0x60000001 / 0x60000002)
  const extractSectionRelocations = (sec: RawElfSection): RawElfRelocation[] => {
    if (sec.shOffset <= 0 || sec.shSize <= 0 || sec.shOffset + sec.shSize > bytes.length) {
      return [];
    }
    const secSlice = bytes.subarray(sec.shOffset, sec.shOffset + sec.shSize);
    if (
      sec.shType === 0x60000001 ||
      sec.shType === 0x60000002 ||
      (secSlice.length >= 4 &&
        secSlice[0] === 0x41 &&
        secSlice[1] === 0x50 &&
        secSlice[2] === 0x53 &&
        secSlice[3] === 0x32)
    ) {
      return decodeAndroidAps2Relocations(secSlice);
    }
    if (sec.shType !== 4 && sec.shType !== 9) return [];
    const hasAddend = sec.shType === 4;
    const defaultEnt = is64Bit ? (hasAddend ? 24 : 16) : hasAddend ? 12 : 8;
    const stride = sec.shEntSize > 0 ? sec.shEntSize : defaultEnt;
    const count = Math.floor(sec.shSize / stride);
    const out: RawElfRelocation[] = [];
    for (let i = 0; i < count; i++) {
      const off = sec.shOffset + i * stride;
      if (off + stride > bytes.length) break;
      const rOffset = is64Bit ? readU64(off) : BigInt(readU32(off));
      const rInfo = is64Bit ? readU64(off + 8) : BigInt(readU32(off + 4));
      const rAddend = hasAddend
        ? is64Bit
          ? readI64(off + 16)
          : readI32(off + 8)
        : 0n;
      out.push({ rOffset, rInfo, rAddend });
    }
    return out;
  };

  const writableRanges = segments.filter((s) => s.writable);
  const isAddrInWritable = (addr: bigint): boolean =>
    writableRanges.some((s) => addr >= s.start && addr < s.end);
  const isSectionWritable = (shndx: number): boolean => {
    const sec = rawSections[shndx];
    return sec !== undefined && (sec.shFlags & 0x1n) !== 0n;
  };

  // Pre-scan .plt section on AArch64 / x86_64 to map .got.plt target -> .plt stub address
  const pltSec = rawSections.find(
    (s) => s.name === ".plt" && s.shAddr > 0n && s.shSize >= 16,
  );
  const gotToPltStubAddr = new Map<bigint, bigint>();
  if (pltSec !== undefined && pltSec.shOffset + pltSec.shSize <= bytes.length) {
    if (arch === "arm64") {
      // Scan AArch64 .plt for `adrp x16, #page` + `ldr x17, [x16, #off]`
      for (let off = 0; off + 12 <= pltSec.shSize; off += 4) {
        const w0 = readU32(pltSec.shOffset + off);
        const w1 = readU32(pltSec.shOffset + off + 4);
        if ((w0 & 0x9f00001f) === 0x90000010 && (w1 & 0xffc003ff) === 0xf9400211) {
          const stubVaddr = pltSec.shAddr + BigInt(off);
          const immlo = (w0 >>> 29) & 3;
          const immhi = (w0 >>> 5) & 0x7ffff;
          const imm21 = ((immhi << 2) | immlo) << 11 >> 11;
          const page = (stubVaddr & ~0xfffn) + (BigInt(imm21) << 12n);
          const imm12 = ((w1 >>> 10) & 0xfff) * 8;
          const gotAddr = page + BigInt(imm12);
          gotToPltStubAddr.set(gotAddr, stubVaddr);
        }
      }
    }
  }

  for (const sec of rawSections) {
    const isPltRel =
      sec.name === ".rela.plt" ||
      sec.name === ".rel.plt" ||
      sec.name === ".plt.got";
    const isDynRel =
      isPltRel ||
      sec.name.startsWith(".rela.") ||
      sec.name.startsWith(".rel.") ||
      sec.shType === 4 ||
      sec.shType === 9 ||
      sec.shType === 0x60000001 ||
      sec.shType === 0x60000002;
    if (!isDynRel) continue;

    const relocs = extractSectionRelocations(sec);
    for (let idx = 0; idx < relocs.length; idx++) {
      const rel = relocs[idx]!;
      const rSym = is64Bit
        ? Number(rel.rInfo >> 32n)
        : Number(rel.rInfo >> 8n);
      const rType = is64Bit
        ? Number(rel.rInfo & 0xffffffffn)
        : Number(rel.rInfo & 0xffn);
      if (rSym <= 0) continue;
      const sym = dynSymsByIndex.get(rSym);
      if (sym === undefined) continue;

      if (isPltRel || rType === 1026 || rType === 7) {
        // R_AARCH64_JUMP_SLOT (1026) / R_X86_64_JUMP_SLOT (7)
        let pltStubAddr = gotToPltStubAddr.get(rel.rOffset);
        if (pltStubAddr === undefined && pltSec !== undefined) {
          const pltHeaderSize = arch === "arm64" ? 32 : 16;
          const stubCandidate =
            pltSec.shAddr + BigInt(pltHeaderSize + idx * 16);
          if (stubCandidate < pltSec.shAddr + BigInt(pltSec.shSize)) {
            pltStubAddr = stubCandidate;
          }
        }
        const resolvedTarget = sym.value > 0n ? sym.value : null;
        if (pltStubAddr !== undefined) {
          functionStartHints.add(pltStubAddr);
          symbolsByAddr.set(pltStubAddr, {
            address: pltStubAddr,
            name: sym.value > 0n ? `${sym.name}@plt` : sym.name,
            size: 16,
            isFunction: true,
            external: sym.value === 0n,
            dynamic: true,
            thunk: true,
            thunkTarget: resolvedTarget,
            source: "imported",
          });
        }
        gotSlotByAddr.set(rel.rOffset, {
          gotAddress: rel.rOffset,
          symbolName: sym.name,
          targetAddress: resolvedTarget ?? rel.rOffset,
          isWritableGlobal: false,
          isFunction: true,
        });
      } else {
        // Global data / GOT relocation (e.g., R_AARCH64_GLOB_DAT = 1025, R_X86_64_GLOB_DAT = 6, R_AARCH64_ABS64 = 257)
        const targetAddr =
          sym.value > 0n ? sym.value + rel.rAddend : rel.rOffset;
        const isWritable =
          !sym.isFunc &&
          (sym.isObject ||
            sym.shndx === 0 ||
            isSectionWritable(sym.shndx) ||
            isAddrInWritable(targetAddr));
        const binding: GotSlotBinding = {
          gotAddress: rel.rOffset,
          symbolName: sym.name,
          targetAddress: targetAddr,
          isWritableGlobal: isWritable,
          isFunction: sym.isFunc,
        };
        gotSlotByAddr.set(rel.rOffset, binding);
        if (targetAddr !== rel.rOffset) {
          gotSlotByAddr.set(targetAddr, binding);
        }
        if (!symbolsByAddr.has(rel.rOffset)) {
          symbolsByAddr.set(rel.rOffset, {
            address: rel.rOffset,
            name: sym.name,
            size: sym.size || (is64Bit ? 8 : 4),
            isFunction: sym.isFunc,
            external: sym.shndx === 0,
            dynamic: true,
            thunk: false,
            thunkTarget: sym.value > 0n ? sym.value : null,
            source: "imported",
          });
        }
      }
    }
  }

  const imageBase =
    segments.length > 0
      ? segments.reduce(
          (min, s) => (s.start < min ? s.start : min),
          segments[0]!.start,
        )
      : 0x400000n;

  return {
    imageBase,
    entryPoint: entryPoint > 0n ? entryPoint : imageBase,
    is64Bit,
    littleEndian,
    architecture: arch,
    segments,
    symbolsByAddr,
    gotSlotByAddr,
    instructionsByAddr: new Map(),
    functionStartHints,
  };
}

function parseMachOContainer(
  bytes: Buffer,
  target: BinaryTarget,
): MutableContainerParse {
  let slice = bytes;
  const magicBE = bytes.readUInt32BE(0);
  if ((magicBE === 0xcafebabe || magicBE === 0xcafebabf) && bytes.length >= 28) {
    const nfat = bytes.readUInt32BE(4);
    for (let i = 0; i < Math.min(nfat, 16); i++) {
      const entryOff = 8 + i * (magicBE === 0xcafebabf ? 32 : 20);
      if (entryOff + 20 > bytes.length) break;
      const cpuType = bytes.readUInt32BE(entryOff);
      const sliceOffset =
        magicBE === 0xcafebabf
          ? Number(bytes.readBigUInt64BE(entryOff + 8))
          : bytes.readUInt32BE(entryOff + 8);
      const sliceSize =
        magicBE === 0xcafebabf
          ? Number(bytes.readBigUInt64BE(entryOff + 16))
          : bytes.readUInt32BE(entryOff + 12);
      const matchesArch =
        (target.architecture === "arm64" && cpuType === 0x0100000c) ||
        (target.architecture === "x86_64" && cpuType === 0x01000007) ||
        i === 0;
      if (matchesArch && sliceOffset + sliceSize <= bytes.length) {
        slice = bytes.subarray(sliceOffset, sliceOffset + sliceSize);
        if (
          (target.architecture === "arm64" && cpuType === 0x0100000c) ||
          (target.architecture === "x86_64" && cpuType === 0x01000007)
        ) {
          break;
        }
      }
    }
  }

  const magicLE = slice.readUInt32LE(0);
  const is64Bit = magicLE === 0xfeedfacf || magicLE === 0xcffaedfe;
  const littleEndian = magicLE === 0xfeedface || magicLE === 0xfeedfacf;
  const readU32 = (off: number) =>
    littleEndian ? slice.readUInt32LE(off) : slice.readUInt32BE(off);
  const readU64 = (off: number) =>
    littleEndian ? slice.readBigUInt64LE(off) : slice.readBigUInt64BE(off);

  const cpuType = readU32(4);
  const arch: string =
    cpuType === 0x0100000c
      ? "arm64"
      : cpuType === 0x01000007
        ? "x86_64"
        : cpuType === 12
          ? "arm"
          : cpuType === 7
            ? "x86"
            : (target.architecture ?? "x86_64");

  const ncmds = readU32(16);
  let cmdOff = is64Bit ? 32 : 28;
  const segments: ParsedSegment[] = [];
  const symbolsByAddr = new Map<bigint, ParsedSymbol>();
  const functionStartHints = new Set<bigint>();
  let textVmaddr = 0x100000000n;
  let entryPoint = 0n;

  for (let i = 0; i < ncmds; i++) {
    if (cmdOff + 8 > slice.length) break;
    const cmd = readU32(cmdOff);
    const cmdSize = readU32(cmdOff + 4);
    if (cmdSize < 8 || cmdOff + cmdSize > slice.length) break;

    if (cmd === 0x19 || cmd === 0x1) {
      // LC_SEGMENT_64 / LC_SEGMENT
      const segName = slice
        .subarray(cmdOff + 8, cmdOff + 24)
        .toString("utf8")
        .replace(/\0.*$/u, "");
      if (segName !== "__PAGEZERO") {
        const vmaddr =
          cmd === 0x19 ? readU64(cmdOff + 24) : BigInt(readU32(cmdOff + 24));
        const vmsize =
          cmd === 0x19 ? readU64(cmdOff + 32) : BigInt(readU32(cmdOff + 28));
        const fileoff = Number(
          cmd === 0x19 ? readU64(cmdOff + 40) : BigInt(readU32(cmdOff + 32)),
        );
        const filesize = Number(
          cmd === 0x19 ? readU64(cmdOff + 48) : BigInt(readU32(cmdOff + 36)),
        );
        const initprot = readU32(cmdOff + (cmd === 0x19 ? 60 : 44));
        const nsects = readU32(cmdOff + (cmd === 0x19 ? 64 : 48));
        if (segName === "__TEXT") {
          textVmaddr = vmaddr;
        }
        const sections: ParsedSection[] = [];
        let sectOff = cmdOff + (cmd === 0x19 ? 72 : 56);
        const sectStride = cmd === 0x19 ? 80 : 68;
        for (let s = 0; s < nsects; s++) {
          if (sectOff + sectStride > slice.length) break;
          const sectName = slice
            .subarray(sectOff, sectOff + 16)
            .toString("utf8")
            .replace(/\0.*$/u, "");
          const sAddr =
            cmd === 0x19 ? readU64(sectOff + 32) : BigInt(readU32(sectOff + 32));
          const sSize = Number(
            cmd === 0x19 ? readU64(sectOff + 40) : BigInt(readU32(sectOff + 36)),
          );
          const sFileOff = readU32(sectOff + (cmd === 0x19 ? 48 : 40));
          const sFlags = readU32(sectOff + (cmd === 0x19 ? 64 : 56));
          const isExec = (sFlags & 0x80000400) !== 0 || (initprot & 4) !== 0;
          if (sSize > 0) {
            sections.push({
              name: `${segName}.${sectName}`,
              start: sAddr,
              end: sAddr + BigInt(sSize),
              fileOffset: sFileOff,
              fileSize: sSize,
              readable: (initprot & 1) !== 0,
              writable: (initprot & 2) !== 0,
              executable: isExec,
              initialized: sFileOff > 0,
            });
          }
          sectOff += sectStride;
        }
        if (vmsize > 0n) {
          segments.push({
            name: segName,
            start: vmaddr,
            end: vmaddr + vmsize,
            fileOffset: fileoff,
            fileSize: filesize,
            readable: (initprot & 1) !== 0,
            writable: (initprot & 2) !== 0,
            executable: (initprot & 4) !== 0,
            initialized: filesize > 0,
            sections,
          });
        }
      }
    } else if (cmd === 0x80000028 && cmdSize >= 24) {
      // LC_MAIN
      const entryOff = readU64(cmdOff + 8);
      entryPoint = textVmaddr + entryOff;
      functionStartHints.add(entryPoint);
    } else if (cmd === 0x2 && cmdSize >= 24) {
      // LC_SYMTAB
      const symOff = readU32(cmdOff + 8);
      const nsyms = readU32(cmdOff + 12);
      const strOff = readU32(cmdOff + 16);
      const strSize = readU32(cmdOff + 20);
      const stride = is64Bit ? 16 : 12;
      for (let s = 0; s < nsyms; s++) {
        const off = symOff + s * stride;
        if (off + stride > slice.length) break;
        const strx = readU32(off);
        const nType = slice[off + 4]!;
        const nValue = is64Bit ? readU64(off + 8) : BigInt(readU32(off + 8));
        if ((nType & 0xe0) !== 0 || nValue === 0n) continue; // skip STAB debug symbols
        const nameStart = strOff + strx;
        if (nameStart >= slice.length || nameStart >= strOff + strSize) continue;
        let nameEnd = nameStart;
        while (nameEnd < slice.length && slice[nameEnd] !== 0) nameEnd++;
        const rawName = slice.subarray(nameStart, nameEnd).toString("utf8");
        const cleanName = rawName.startsWith("_") ? rawName.slice(1) : rawName;
        if (!cleanName) continue;
        symbolsByAddr.set(nValue, {
          address: nValue,
          name: cleanName,
          size: 0,
          isFunction: true,
          external: (nType & 0x0e) === 0,
          dynamic: false,
          thunk: false,
          thunkTarget: null,
          source: "imported",
        });
        functionStartHints.add(nValue);
      }
    } else if (cmd === 0x26 && cmdSize >= 16) {
      // LC_FUNCTION_STARTS (ULEB128 delta table)
      const dataOff = readU32(cmdOff + 8);
      const dataSize = readU32(cmdOff + 12);
      let addr = textVmaddr;
      let p = dataOff;
      const end = Math.min(slice.length, dataOff + dataSize);
      while (p < end) {
        let delta = 0n;
        let shift = 0n;
        while (p < end) {
          const b = slice[p++]!;
          delta |= BigInt(b & 0x7f) << shift;
          shift += 7n;
          if ((b & 0x80) === 0) break;
        }
        if (delta === 0n) break;
        addr += delta;
        functionStartHints.add(addr);
      }
    }
    cmdOff += cmdSize;
  }

  if (entryPoint === 0n) {
    entryPoint = textVmaddr;
  }
  return {
    imageBase: textVmaddr,
    entryPoint,
    is64Bit,
    littleEndian,
    architecture: arch,
    segments,
    symbolsByAddr,
    gotSlotByAddr: new Map(),
    instructionsByAddr: new Map(),
    functionStartHints,
  };
}

function parsePeContainer(
  bytes: Buffer,
  target: BinaryTarget,
): MutableContainerParse {
  const peOffset = bytes.readUInt32LE(0x3c);
  if (
    peOffset + 24 > bytes.length ||
    bytes.subarray(peOffset, peOffset + 4).toString("ascii") !== "PE\0\0"
  ) {
    return {
      imageBase: 0x140000000n,
      entryPoint: 0x140001000n,
      is64Bit: true,
      littleEndian: true,
      architecture: target.architecture ?? "x86_64",
      segments: [],
      symbolsByAddr: new Map(),
      gotSlotByAddr: new Map(),
      instructionsByAddr: new Map(),
      functionStartHints: new Set(),
    };
  }
  const machine = bytes.readUInt16LE(peOffset + 4);
  const numSections = bytes.readUInt16LE(peOffset + 6);
  const optHdrSize = bytes.readUInt16LE(peOffset + 20);
  const optOff = peOffset + 24;
  const optMagic = optHdrSize >= 2 ? bytes.readUInt16LE(optOff) : 0x10b;
  const is64Bit = optMagic === 0x20b;
  const entryRva = optHdrSize >= 20 ? bytes.readUInt32LE(optOff + 16) : 0x1000;
  const imageBase = is64Bit
    ? bytes.readBigUInt64LE(optOff + 24)
    : BigInt(bytes.readUInt32LE(optOff + 28));
  const arch: string =
    machine === 0x8664
      ? "x86_64"
      : machine === 0x14c
        ? "x86"
        : machine === 0xaa64
          ? "arm64"
          : (target.architecture ?? "x86_64");

  const secTableOff = optOff + optHdrSize;
  const segments: ParsedSegment[] = [];
  const functionStartHints = new Set<bigint>();
  const entryPoint = imageBase + BigInt(entryRva);
  functionStartHints.add(entryPoint);

  for (let i = 0; i < numSections; i++) {
    const off = secTableOff + i * 40;
    if (off + 40 > bytes.length) break;
    const name = bytes
      .subarray(off, off + 8)
      .toString("utf8")
      .replace(/\0.*$/u, "");
    const virtualSize = bytes.readUInt32LE(off + 8);
    const virtualAddr = bytes.readUInt32LE(off + 12);
    const rawSize = bytes.readUInt32LE(off + 16);
    const rawPtr = bytes.readUInt32LE(off + 20);
    const chars = bytes.readUInt32LE(off + 36);
    const span = Math.max(virtualSize, rawSize, 1);
    const start = imageBase + BigInt(virtualAddr);
    const end = start + BigInt(span);
    const sec: ParsedSection = {
      name: name || `sect_${i}`,
      start,
      end,
      fileOffset: rawPtr,
      fileSize: rawSize,
      readable: (chars & 0x40000000) !== 0 || true,
      writable: (chars & 0x80000000) !== 0,
      executable: (chars & 0x20000000) !== 0,
      initialized: rawSize > 0,
    };
    segments.push({
      ...sec,
      sections: [sec],
    });
    // Parse .pdata RUNTIME_FUNCTION entries on x64 PE for stripped function starts
    if (name === ".pdata" && is64Bit && rawPtr + rawSize <= bytes.length) {
      for (let p = rawPtr; p + 12 <= rawPtr + rawSize; p += 12) {
        const beginRva = bytes.readUInt32LE(p);
        if (beginRva > 0) {
          functionStartHints.add(imageBase + BigInt(beginRva));
        }
      }
    }
  }

  return {
    imageBase,
    entryPoint,
    is64Bit,
    littleEndian: true,
    architecture: arch,
    segments,
    symbolsByAddr: new Map(),
    gotSlotByAddr: new Map(),
    instructionsByAddr: new Map(),
    functionStartHints,
  };
}

async function enrichWithHostCliTools(
  targetPath: string,
  parsed: MutableContainerParse,
  environment: Readonly<NodeJS.ProcessEnv>,
  platform: NodeJS.Platform,
  logger: Logger,
): Promise<void> {
  // 1. Symbol enrichment via nm
  const nmCandidates =
    parsed.architecture === "arm64"
      ? ["llvm-nm", "aarch64-linux-gnu-nm", "nm"]
      : ["nm", "llvm-nm"];
  const nmBin = findExecutableInPath(nmCandidates, environment);
  if (nmBin !== null) {
    try {
      const { stdout } = await execFileAsync(nmBin, ["-n", targetPath], {
        timeout: 8000,
        maxBuffer: 16 * 1024 * 1024,
      });
      for (const line of stdout.split("\n")) {
        const match = /^([0-9a-fA-F]+)\s+([TtWwDdBbRr])\s+(\S+)$/u.exec(
          line.trim(),
        );
        if (match !== null) {
          const addr = BigInt(`0x${match[1]!}`);
          const code = match[2]!;
          const rawName = match[3]!;
          const cleanName =
            platform === "darwin" && rawName.startsWith("_")
              ? rawName.slice(1)
              : rawName;
          if (cleanName.startsWith(".")) continue;
          const isFunc = code === "T" || code === "t" || code === "W" || code === "w";
          if (!parsed.symbolsByAddr.has(addr)) {
            parsed.symbolsByAddr.set(addr, {
              address: addr,
              name: cleanName,
              size: 0,
              isFunction: isFunc,
              external: false,
              dynamic: false,
              thunk: false,
              thunkTarget: null,
              source: "imported",
            });
          }
          if (isFunc) {
            parsed.functionStartHints.add(addr);
          }
        }
      }
    } catch (cause: unknown) {
      logger.debug({ cause }, "nm enrichment skipped");
    }
  }

  // 2. Disassembly enrichment via objdump / llvm-objdump / otool
  if (platform === "darwin") {
    const otoolBin = findExecutableInPath(["otool"], environment);
    if (otoolBin !== null) {
      try {
        const { stdout } = await execFileAsync(otoolBin, ["-tV", targetPath], {
          timeout: 10000,
          maxBuffer: 32 * 1024 * 1024,
        });
        parseOtoolDisassembly(stdout, parsed);
        if (parsed.instructionsByAddr.size > 0) return;
      } catch (cause: unknown) {
        logger.debug({ cause }, "otool disassembly skipped");
      }
    }
  }

  const objdumpCandidates =
    parsed.architecture === "arm64"
      ? [
          "llvm-objdump",
          "aarch64-linux-gnu-objdump",
          "objdump",
          "llvm-objdump.exe",
          "objdump.exe",
        ]
      : ["objdump", "llvm-objdump", "llvm-objdump.exe", "objdump.exe"];
  const objdumpBin = findExecutableInPath(objdumpCandidates, environment);
  if (objdumpBin !== null) {
    try {
      const args =
        parsed.architecture === "x86_64" || parsed.architecture === "x86"
          ? ["-d", "-M", "intel", targetPath]
          : ["-d", targetPath];
      const { stdout } = await execFileAsync(objdumpBin, args, {
        timeout: 10000,
        maxBuffer: 32 * 1024 * 1024,
      });
      parseObjdumpDisassembly(stdout, parsed);
    } catch (cause: unknown) {
      logger.debug({ cause }, "objdump disassembly skipped");
    }
  }
}

function parseObjdumpDisassembly(
  stdout: string,
  parsed: MutableContainerParse,
): void {
  for (const rawLine of stdout.split("\n")) {
    const headerMatch = /^([0-9a-fA-F]+)\s+<([^>]+)>:$/u.exec(rawLine.trim());
    if (headerMatch !== null) {
      const fnAddr = BigInt(`0x${headerMatch[1]!}`);
      const fnName = headerMatch[2]!.replace(/@plt$/u, "");
      if (fnName.startsWith(".")) continue;
      parsed.functionStartHints.add(fnAddr);
      if (!parsed.symbolsByAddr.has(fnAddr)) {
        parsed.symbolsByAddr.set(fnAddr, {
          address: fnAddr,
          name: fnName,
          size: 0,
          isFunction: true,
          external: false,
          dynamic: headerMatch[2]!.endsWith("@plt"),
          thunk: headerMatch[2]!.endsWith("@plt"),
          thunkTarget: null,
          source: "imported",
        });
      }
      continue;
    }
    const insnMatch =
      /^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)\s*([a-zA-Z0-9._]+)(?:\s+([^;#\n]*))?/u.exec(
        rawLine,
      );
    if (insnMatch !== null) {
      const addr = BigInt(`0x${insnMatch[1]!}`);
      const bytesHex = insnMatch[2]!.replace(/\s+/gu, "").toLowerCase();
      const mnemonic = insnMatch[3]!.trim();
      const rawOps = (insnMatch[4] ?? "").trim();
      const operands =
        rawOps.length > 0
          ? rawOps.split(",").map((s) => s.trim()).filter((s) => s.length > 0)
          : [];
      const decoded = classifyInstruction(
        addr,
        bytesHex,
        Math.max(1, bytesHex.length / 2),
        mnemonic,
        operands,
        rawLine,
      );
      parsed.instructionsByAddr.set(addr, decoded);
      if (decoded.isCall && decoded.targetAddress !== null) {
        parsed.functionStartHints.add(decoded.targetAddress);
      }
    }
  }
}

function parseOtoolDisassembly(
  stdout: string,
  parsed: MutableContainerParse,
): void {
  for (const rawLine of stdout.split("\n")) {
    const labelMatch = /^_?([A-Za-z0-9_$]+):$/u.exec(rawLine.trim());
    if (labelMatch !== null) continue;
    const insnMatch =
      /^([0-9a-fA-F]{8,16})\s+([a-zA-Z0-9._]+)(?:\s+([^;\n]*))?/u.exec(
        rawLine.trim(),
      );
    if (insnMatch !== null) {
      const addr = BigInt(`0x${insnMatch[1]!}`);
      const mnemonic = insnMatch[2]!.trim();
      const rawOps = (insnMatch[3] ?? "").trim();
      const operands =
        rawOps.length > 0
          ? rawOps.split(",").map((s) => s.trim()).filter((s) => s.length > 0)
          : [];
      const decoded = classifyInstruction(
        addr,
        "00000000",
        4,
        mnemonic,
        operands,
        rawLine,
      );
      parsed.instructionsByAddr.set(addr, decoded);
      if (decoded.isCall && decoded.targetAddress !== null) {
        parsed.functionStartHints.add(decoded.targetAddress);
      }
    }
  }
}

function classifyInstruction(
  address: bigint,
  bytesHex: string,
  length: number,
  mnemonic: string,
  operands: readonly string[],
  rawLine: string,
): DecodedInsn {
  const m = mnemonic.toLowerCase();
  const isCall = m === "call" || m === "callq" || m === "bl" || m === "blr" || m === "jal";
  const isReturn =
    m === "ret" || m === "retq" || m === "retn" || m === "bx" && operands[0] === "lr";
  const isUnconditionalJump =
    m === "jmp" || m === "jmpq" || m === "b" || m === "j";
  const isConditionalJump =
    !isUnconditionalJump &&
    !isCall &&
    ((m.startsWith("j") && m !== "jmp" && m !== "jmpq") ||
      m.startsWith("b.") ||
      m === "cbz" ||
      m === "cbnz" ||
      m === "tbz" ||
      m === "tbnz" ||
      m === "beq" ||
      m === "bne");
  const isJump = isUnconditionalJump || isConditionalJump;
  const firstOp = operands[0] ?? "";
  const isIndirect =
    (isCall || isJump) &&
    (firstOp.includes("[") ||
      firstOp.includes("*") ||
      /^(?:r|e)?[abcdSD]x|x\d+$/iu.test(firstOp));

  let targetAddress: bigint | null = null;
  const hexMatch =
    /\b([0-9a-fA-F]{1,16})\s+<[^>]+>/u.exec(rawLine) ??
    /\b0x([0-9a-fA-F]{1,16})\b/u.exec(
      rawLine.replace(/\[(?:rip|eip)\s*[+-]\s*0x[0-9a-fA-F]+\]/giu, ""),
    );
  if (hexMatch !== null) {
    try {
      targetAddress = BigInt(`0x${hexMatch[1]!}`);
    } catch {
      targetAddress = null;
    }
  }

  return {
    address,
    bytesHex,
    length,
    mnemonic,
    operands,
    rawText: `${mnemonic}${operands.length > 0 ? ` ${operands.join(", ")}` : ""}`,
    isCall,
    isJump,
    isConditionalJump,
    isReturn,
    isIndirect,
    targetAddress,
  };
}

const AARCH64_COND_CODES: readonly string[] = [
  "eq",
  "ne",
  "cs",
  "cc",
  "mi",
  "pl",
  "vs",
  "vc",
  "hi",
  "ls",
  "ge",
  "lt",
  "gt",
  "le",
  "al",
  "nv",
];

function formatAArch64Gpr(reg: number, is64: boolean, allowSp: boolean): string {
  if (reg === 31) {
    return allowSp ? (is64 ? "sp" : "wsp") : is64 ? "xzr" : "wzr";
  }
  return `${is64 ? "x" : "w"}${reg}`;
}

function signExtend32(val: number, bits: number): number {
  const shift = 32 - bits;
  return (val << shift) >> shift;
}

function formatSignedHexDisp(disp: number): string {
  if (disp === 0) return "#0x0";
  return disp < 0
    ? `#-0x${Math.abs(disp).toString(16)}`
    : `#0x${disp.toString(16)}`;
}

function decodeAArch64Instruction(
  word: number,
  vaddr: bigint,
  parsed: MutableContainerParse,
): {
  readonly mnem: string;
  readonly ops: string[];
  readonly targetAddress: bigint | null;
} {
  if (word === 0xd503201f) {
    return { mnem: "nop", ops: [], targetAddress: null };
  }
  if ((word & 0xffffe0ff) === 0xd503201f) {
    return { mnem: "hint", ops: [`#0x${((word >>> 5) & 0x7f).toString(16)}`], targetAddress: null };
  }

  // 1. Unconditional B / BL: 000101 / 100101 imm26
  if ((word & 0x7c000000) === 0x14000000) {
    const isBl = (word & 0x80000000) !== 0;
    const imm26 = signExtend32(word & 0x03ffffff, 26);
    const target = vaddr + BigInt(imm26) * 4n;
    if (isBl) {
      parsed.functionStartHints.add(target);
    }
    const sym = parsed.symbolsByAddr.get(target);
    const label = sym !== undefined ? `${toHex(target)} <${sym.name}>` : toHex(target);
    return { mnem: isBl ? "bl" : "b", ops: [label], targetAddress: target };
  }

  // 2. Conditional branch B.cond: 01010100 imm19 0 cond
  if ((word & 0xff000010) === 0x54000000) {
    const imm19 = signExtend32((word >>> 5) & 0x7ffff, 19);
    const cond = AARCH64_COND_CODES[word & 0xf] ?? "al";
    const target = vaddr + BigInt(imm19) * 4n;
    return { mnem: `b.${cond}`, ops: [toHex(target)], targetAddress: target };
  }

  // 3. CBZ / CBNZ: sf 011010 op imm19 Rt
  if ((word & 0x7e000000) === 0x34000000) {
    const is64 = (word & 0x80000000) !== 0;
    const isNz = (word & 0x01000000) !== 0;
    const imm19 = signExtend32((word >>> 5) & 0x7ffff, 19);
    const rt = formatAArch64Gpr(word & 0x1f, is64, false);
    const target = vaddr + BigInt(imm19) * 4n;
    return {
      mnem: isNz ? "cbnz" : "cbz",
      ops: [rt, toHex(target)],
      targetAddress: target,
    };
  }

  // 4. TBZ / TBNZ: b5 011011 op b40 imm14 Rt
  if ((word & 0x7e000000) === 0x36000000) {
    const b5 = (word >>> 31) & 1;
    const isNz = (word & 0x01000000) !== 0;
    const b40 = (word >>> 19) & 0x1f;
    const bitNum = (b5 << 5) | b40;
    const imm14 = signExtend32((word >>> 5) & 0x3fff, 14);
    const rt = formatAArch64Gpr(word & 0x1f, b5 === 1, false);
    const target = vaddr + BigInt(imm14) * 4n;
    return {
      mnem: isNz ? "tbnz" : "tbz",
      ops: [rt, `#${bitNum}`, toHex(target)],
      targetAddress: target,
    };
  }

  // 5. Unconditional branch register: BR / BLR / RET
  if ((word & 0xfe1ffc1f) === 0xd61f0000) {
    const opc = (word >>> 21) & 0xf;
    const rn = (word >>> 5) & 0x1f;
    if (opc === 2) {
      return {
        mnem: "ret",
        ops: rn === 30 ? [] : [formatAArch64Gpr(rn, true, false)],
        targetAddress: null,
      };
    }
    if (opc === 1) {
      return {
        mnem: "blr",
        ops: [formatAArch64Gpr(rn, true, false)],
        targetAddress: null,
      };
    }
    if (opc === 0) {
      return {
        mnem: "br",
        ops: [formatAArch64Gpr(rn, true, false)],
        targetAddress: null,
      };
    }
  }

  // 6. ADR / ADRP: op immlo 10000 immhi Rd
  if ((word & 0x1f000000) === 0x10000000) {
    const isAdrp = (word & 0x80000000) !== 0;
    const immlo = (word >>> 29) & 3;
    const immhi = (word >>> 5) & 0x7ffff;
    const imm21 = signExtend32((immhi << 2) | immlo, 21);
    const rd = formatAArch64Gpr(word & 0x1f, true, false);
    const target = isAdrp
      ? (vaddr & ~0xfffn) + BigInt(imm21) * 4096n
      : vaddr + BigInt(imm21);
    return {
      mnem: isAdrp ? "adrp" : "adr",
      ops: [rd, toHex(target)],
      targetAddress: target,
    };
  }

  // 7. Move wide immediate: MOVN / MOVZ / MOVK
  if ((word & 0x1f800000) === 0x12800000) {
    const is64 = (word & 0x80000000) !== 0;
    const opc = (word >>> 29) & 3;
    const hw = (word >>> 21) & 3;
    const imm16 = (word >>> 5) & 0xffff;
    const rd = formatAArch64Gpr(word & 0x1f, is64, false);
    const mnem = opc === 0 ? "movn" : opc === 2 ? "movz" : opc === 3 ? "movk" : "mov";
    const shiftPart = hw > 0 ? `, lsl #${hw * 16}` : "";
    return {
      mnem,
      ops: [rd, `#0x${imm16.toString(16)}${shiftPart}`],
      targetAddress: null,
    };
  }

  // 8. Add/subtract immediate: sf op S 100010 sh imm12 Rn Rd
  if ((word & 0x1f000000) === 0x11000000) {
    const is64 = (word & 0x80000000) !== 0;
    const isSub = (word & 0x40000000) !== 0;
    const isS = (word & 0x20000000) !== 0;
    const sh = (word >>> 22) & 1;
    const imm12 = (word >>> 10) & 0xfff;
    const rn = (word >>> 5) & 0x1f;
    const rd = word & 0x1f;
    const val = sh === 1 ? imm12 << 12 : imm12;
    if (isSub && isS && rd === 31) {
      return {
        mnem: "cmp",
        ops: [formatAArch64Gpr(rn, is64, true), `#0x${val.toString(16)}`],
        targetAddress: null,
      };
    }
    if (!isSub && !isS && imm12 === 0 && (rn === 31 || rd === 31)) {
      return {
        mnem: "mov",
        ops: [
          formatAArch64Gpr(rd, is64, true),
          formatAArch64Gpr(rn, is64, true),
        ],
        targetAddress: null,
      };
    }
    const mnem = `${isSub ? "sub" : "add"}${isS ? "s" : ""}`;
    return {
      mnem,
      ops: [
        formatAArch64Gpr(rd, is64, !isS),
        formatAArch64Gpr(rn, is64, true),
        `#0x${val.toString(16)}`,
      ],
      targetAddress: null,
    };
  }

  // 9. Bitfield: SBFM / BFM / UBFM (SXTW, LSL, LSR, ASR)
  if ((word & 0x1f800000) === 0x13000000) {
    const is64 = (word & 0x80000000) !== 0;
    const opc = (word >>> 29) & 3;
    const immr = (word >>> 16) & 0x3f;
    const imms = (word >>> 10) & 0x3f;
    const rn = (word >>> 5) & 0x1f;
    const rd = word & 0x1f;
    const rdName = formatAArch64Gpr(rd, is64, false);
    const rnName = formatAArch64Gpr(rn, is64, false);
    if (opc === 0 && is64 && immr === 0 && imms === 31) {
      return {
        mnem: "sxtw",
        ops: [rdName, formatAArch64Gpr(rn, false, false)],
        targetAddress: null,
      };
    }
    if (opc === 2 && ((is64 && imms === 63) || (!is64 && imms === 31))) {
      return {
        mnem: "lsr",
        ops: [rdName, rnName, `#${immr}`],
        targetAddress: null,
      };
    }
    if (opc === 0 && ((is64 && imms === 63) || (!is64 && imms === 31))) {
      return {
        mnem: "asr",
        ops: [rdName, rnName, `#${immr}`],
        targetAddress: null,
      };
    }
    if (opc === 2 && imms + 1 === immr) {
      const width = is64 ? 64 : 32;
      return {
        mnem: "lsl",
        ops: [rdName, rnName, `#${(width - immr) % width}`],
        targetAddress: null,
      };
    }
    const mnem = opc === 0 ? "sbfm" : opc === 1 ? "bfm" : "ubfm";
    return {
      mnem,
      ops: [rdName, rnName, `#${immr}`, `#${imms}`],
      targetAddress: null,
    };
  }

  // 10. Load/Store Pair (LDP / STP): opc 101 V 0xx L imm7 Rt2 Rn Rt
  if ((word & 0x3a000000) === 0x28000000) {
    const opc = (word >>> 30) & 3;
    const isSimd = (word & 0x04000000) !== 0;
    const mode = (word >>> 23) & 3;
    const isLoad = (word & 0x00400000) !== 0;
    const imm7 = signExtend32((word >>> 15) & 0x7f, 7);
    const rt2 = (word >>> 10) & 0x1f;
    const rn = (word >>> 5) & 0x1f;
    const rt = word & 0x1f;
    const scale = isSimd ? 4 << opc : opc === 2 ? 8 : 4;
    const disp = imm7 * scale;
    const regPrefix = isSimd
      ? opc === 0
        ? "s"
        : opc === 1
          ? "d"
          : "q"
      : opc === 2
        ? "x"
        : "w";
    const rtName = isSimd
      ? `${regPrefix}${rt}`
      : formatAArch64Gpr(rt, opc === 2, false);
    const rt2Name = isSimd
      ? `${regPrefix}${rt2}`
      : formatAArch64Gpr(rt2, opc === 2, false);
    const rnName = formatAArch64Gpr(rn, true, true);
    const mnem = isLoad ? (opc === 1 && !isSimd ? "ldpsw" : "ldp") : "stp";
    // Prologue hint: stp x29, x30, [sp, #-...]
    if (!isLoad && rn === 31 && rt === 29 && rt2 === 30) {
      parsed.functionStartHints.add(vaddr);
    }
    const memOp =
      mode === 1
        ? `[${rnName}], ${formatSignedHexDisp(disp)}`
        : mode === 3
          ? `[${rnName}, ${formatSignedHexDisp(disp)}]!`
          : disp === 0
            ? `[${rnName}]`
            : `[${rnName}, ${formatSignedHexDisp(disp)}]`;
    return { mnem, ops: [rtName, rt2Name, memOp], targetAddress: null };
  }

  // 11. Load/Store Unsigned Immediate: size 111 V 01 opc imm12 Rn Rt
  if ((word & 0x3b000000) === 0x39000000) {
    const size = (word >>> 30) & 3;
    const isSimd = (word & 0x04000000) !== 0;
    const opc = (word >>> 22) & 3;
    const imm12 = (word >>> 10) & 0xfff;
    const rn = (word >>> 5) & 0x1f;
    const rt = word & 0x1f;
    const rnName = formatAArch64Gpr(rn, true, true);
    let mnem = "ldr";
    let rtName = formatAArch64Gpr(rt, size === 3, false);
    let scaleShift = size;
    if (isSimd) {
      const is128 = size === 0 && (opc & 2) !== 0;
      scaleShift = is128 ? 4 : size;
      const isLoad = (opc & 1) !== 0;
      mnem = isLoad ? "ldr" : "str";
      const pref = is128
        ? "q"
        : size === 0
          ? "b"
          : size === 1
            ? "h"
            : size === 2
              ? "s"
              : "d";
      rtName = `${pref}${rt}`;
    } else {
      if (opc === 0) {
        mnem = size === 0 ? "strb" : size === 1 ? "strh" : "str";
      } else if (opc === 1) {
        mnem = size === 0 ? "ldrb" : size === 1 ? "ldrh" : "ldr";
      } else {
        const is64Target = opc === 2;
        rtName = formatAArch64Gpr(rt, is64Target, false);
        mnem = size === 0 ? "ldrsb" : size === 1 ? "ldrsh" : "ldrsw";
      }
    }
    const disp = imm12 * (1 << scaleShift);
    const memOp =
      disp === 0 ? `[${rnName}]` : `[${rnName}, #0x${disp.toString(16)}]`;
    return { mnem, ops: [rtName, memOp], targetAddress: null };
  }

  // 12. Load/Store Register Offset & Unscaled/Pre/Post Immediate: size 111 V 00 opc ...
  if ((word & 0x3b000000) === 0x38000000) {
    const size = (word >>> 30) & 3;
    const isSimd = (word & 0x04000000) !== 0;
    const opc = (word >>> 22) & 3;
    const rn = (word >>> 5) & 0x1f;
    const rt = word & 0x1f;
    const rnName = formatAArch64Gpr(rn, true, true);
    const isLoad = (opc & 1) !== 0 || opc >= 2;
    const rtName = isSimd
      ? `${size === 2 ? "s" : size === 3 ? "d" : "q"}${rt}`
      : formatAArch64Gpr(rt, size === 3 || opc === 2, false);
    if ((word & 0x00200800) === 0x00200800) {
      // Register offset: [Xn, Xm/Wm, extend #amount]
      const rm = (word >>> 16) & 0x1f;
      const option = (word >>> 13) & 7;
      const rmIs64 = (option & 3) === 3;
      const rmName = formatAArch64Gpr(rm, rmIs64, false);
      const mnem = isLoad
        ? size === 0
          ? "ldrb"
          : size === 1
            ? "ldrh"
            : opc === 2 && size === 2
              ? "ldrsw"
              : "ldr"
        : size === 0
          ? "strb"
          : size === 1
            ? "strh"
            : "str";
      return {
        mnem,
        ops: [rtName, `[${rnName}, ${rmName}]`],
        targetAddress: null,
      };
    }
    const mode = (word >>> 10) & 3;
    const imm9 = signExtend32((word >>> 12) & 0x1ff, 9);
    const mnem =
      mode === 0
        ? isLoad
          ? size === 0
            ? "ldurb"
            : size === 1
              ? "ldurh"
              : "ldur"
          : size === 0
            ? "sturb"
            : size === 1
              ? "sturh"
              : "stur"
        : isLoad
          ? size === 0
            ? "ldrb"
            : size === 1
              ? "ldrh"
              : "ldr"
          : size === 0
            ? "strb"
            : size === 1
              ? "strh"
              : "str";
    const memOp =
      mode === 1
        ? `[${rnName}], ${formatSignedHexDisp(imm9)}`
        : mode === 3
          ? `[${rnName}, ${formatSignedHexDisp(imm9)}]!`
          : imm9 === 0
            ? `[${rnName}]`
            : `[${rnName}, ${formatSignedHexDisp(imm9)}]`;
    return { mnem, ops: [rtName, memOp], targetAddress: null };
  }

  // 13. Add/Subtract Shifted or Extended Register: sf op S 01011 ...
  if ((word & 0x1f000000) === 0x0b000000) {
    const is64 = (word & 0x80000000) !== 0;
    const isSub = (word & 0x40000000) !== 0;
    const isS = (word & 0x20000000) !== 0;
    const rm = (word >>> 16) & 0x1f;
    const rn = (word >>> 5) & 0x1f;
    const rd = word & 0x1f;
    if (isSub && isS && rd === 31) {
      return {
        mnem: "cmp",
        ops: [
          formatAArch64Gpr(rn, is64, true),
          formatAArch64Gpr(rm, is64, false),
        ],
        targetAddress: null,
      };
    }
    if (isSub && !isS && rn === 31) {
      return {
        mnem: "neg",
        ops: [
          formatAArch64Gpr(rd, is64, false),
          formatAArch64Gpr(rm, is64, false),
        ],
        targetAddress: null,
      };
    }
    return {
      mnem: `${isSub ? "sub" : "add"}${isS ? "s" : ""}`,
      ops: [
        formatAArch64Gpr(rd, is64, !isS),
        formatAArch64Gpr(rn, is64, true),
        formatAArch64Gpr(rm, is64, false),
      ],
      targetAddress: null,
    };
  }

  // 14. Logical Shifted Register (AND / ORR / EOR / MOV): sf opc 01010 ...
  if ((word & 0x1f000000) === 0x0a000000) {
    const is64 = (word & 0x80000000) !== 0;
    const opc = (word >>> 29) & 3;
    const nBit = (word >>> 21) & 1;
    const rm = (word >>> 16) & 0x1f;
    const imm6 = (word >>> 10) & 0x3f;
    const rn = (word >>> 5) & 0x1f;
    const rd = word & 0x1f;
    if (opc === 1 && nBit === 0 && rn === 31 && imm6 === 0) {
      return {
        mnem: "mov",
        ops: [
          formatAArch64Gpr(rd, is64, false),
          formatAArch64Gpr(rm, is64, false),
        ],
        targetAddress: null,
      };
    }
    if (opc === 3 && nBit === 0 && rd === 31) {
      return {
        mnem: "tst",
        ops: [
          formatAArch64Gpr(rn, is64, false),
          formatAArch64Gpr(rm, is64, false),
        ],
        targetAddress: null,
      };
    }
    const mnem =
      opc === 0 ? "and" : opc === 1 ? "orr" : opc === 2 ? "eor" : "ands";
    return {
      mnem,
      ops: [
        formatAArch64Gpr(rd, is64, false),
        formatAArch64Gpr(rn, is64, false),
        formatAArch64Gpr(rm, is64, false),
      ],
      targetAddress: null,
    };
  }

  // 14b. Conditional Select (CSEL / CSINC / CSINV / CSNEG): sf op 0 11010100 Rm cond 0 o2 Rn Rd
  if ((word & 0x1fe00800) === 0x1a800000) {
    const is64 = (word & 0x80000000) !== 0;
    const op = (word >>> 30) & 1;
    const o2 = (word >>> 10) & 1;
    const rm = (word >>> 16) & 0x1f;
    const cond = AARCH64_COND_CODES[(word >>> 12) & 0xf] ?? "al";
    const rn = (word >>> 5) & 0x1f;
    const rd = word & 0x1f;
    const mnem =
      op === 0
        ? o2 === 0
          ? "csel"
          : "csinc"
        : o2 === 0
          ? "csinv"
          : "csneg";
    return {
      mnem,
      ops: [
        formatAArch64Gpr(rd, is64, false),
        formatAArch64Gpr(rn, is64, false),
        formatAArch64Gpr(rm, is64, false),
        cond,
      ],
      targetAddress: null,
    };
  }

  // 15. Data-processing (3-source): MADD / MSUB / MUL / SMADDL / UMADDL
  if ((word & 0x1f000000) === 0x1b000000) {
    const is64 = (word & 0x80000000) !== 0;
    const op31 = (word >>> 21) & 7;
    const o0 = (word >>> 15) & 1;
    const rm = (word >>> 16) & 0x1f;
    const ra = (word >>> 10) & 0x1f;
    const rn = (word >>> 5) & 0x1f;
    const rd = word & 0x1f;
    if (op31 === 1 || op31 === 5) {
      // SMADDL / SMSUBL / UMADDL / UMSUBL (64-bit dest, 32-bit sources)
      const isUnsigned = op31 === 5;
      const mnem = isUnsigned
        ? o0 === 1
          ? "umsubl"
          : "umaddl"
        : o0 === 1
          ? "smsubl"
          : "smaddl";
      return {
        mnem,
        ops: [
          formatAArch64Gpr(rd, true, false),
          formatAArch64Gpr(rn, false, false),
          formatAArch64Gpr(rm, false, false),
          formatAArch64Gpr(ra, true, false),
        ],
        targetAddress: null,
      };
    }
    const rdName = formatAArch64Gpr(rd, is64, false);
    const rnName = formatAArch64Gpr(rn, is64, false);
    const rmName = formatAArch64Gpr(rm, is64, false);
    const raName = formatAArch64Gpr(ra, is64, false);
    if (o0 === 0 && ra === 31) {
      return { mnem: "mul", ops: [rdName, rnName, rmName], targetAddress: null };
    }
    return {
      mnem: o0 === 1 ? "msub" : "madd",
      ops: [rdName, rnName, rmName, raName],
      targetAddress: null,
    };
  }

  // 16. Data-processing (2-source): UDIV / SDIV / LSLV / LSRV / ASRV
  if ((word & 0x5fe00000) === 0x1ac00000) {
    const is64 = (word & 0x80000000) !== 0;
    const opcode = (word >>> 10) & 0x3f;
    const rm = (word >>> 16) & 0x1f;
    const rn = (word >>> 5) & 0x1f;
    const rd = word & 0x1f;
    const mnem =
      opcode === 2
        ? "udiv"
        : opcode === 3
          ? "sdiv"
          : opcode === 8
            ? "lsl"
            : opcode === 9
              ? "lsr"
              : opcode === 10
                ? "asr"
                : "dp2";
    return {
      mnem,
      ops: [
        formatAArch64Gpr(rd, is64, false),
        formatAArch64Gpr(rn, is64, false),
        formatAArch64Gpr(rm, is64, false),
      ],
      targetAddress: null,
    };
  }

  // 17. Scalar Floating-Point & Conversion: FMOV, FADD, FSUB, FMUL, FDIV, FCMP, FCVT, SCVTF, FCVTZS
  if ((word & 0x5f000000) === 0x1e000000) {
    const ftype = (word >>> 22) & 3;
    const fpPrefix = ftype === 1 ? "d" : "s";
    const rn = (word >>> 5) & 0x1f;
    const rd = word & 0x1f;
    const rm = (word >>> 16) & 0x1f;

    // Int <-> Float conversions (SCVTF, UCVTF, FCVTZS, FCVTZU, FMOV gpr<->fpr)
    if ((word & 0x5f20fc00) === 0x1e200000 && ((word >>> 21) & 1) === 1) {
      const is64Int = (word & 0x80000000) !== 0;
      const rmode = (word >>> 19) & 3;
      const opcode = (word >>> 16) & 7;
      if (rmode === 0 && opcode === 2) {
        return {
          mnem: "scvtf",
          ops: [
            `${fpPrefix}${rd}`,
            formatAArch64Gpr(rn, is64Int, false),
          ],
          targetAddress: null,
        };
      }
      if (rmode === 0 && opcode === 3) {
        return {
          mnem: "ucvtf",
          ops: [
            `${fpPrefix}${rd}`,
            formatAArch64Gpr(rn, is64Int, false),
          ],
          targetAddress: null,
        };
      }
      if (rmode === 3 && opcode === 0) {
        return {
          mnem: "fcvtzs",
          ops: [
            formatAArch64Gpr(rd, is64Int, false),
            `${fpPrefix}${rn}`,
          ],
          targetAddress: null,
        };
      }
      if (rmode === 0 && opcode === 7) {
        return {
          mnem: "fmov",
          ops: [
            `${fpPrefix}${rd}`,
            formatAArch64Gpr(rn, is64Int, false),
          ],
          targetAddress: null,
        };
      }
      if (rmode === 0 && opcode === 6) {
        return {
          mnem: "fmov",
          ops: [
            formatAArch64Gpr(rd, is64Int, false),
            `${fpPrefix}${rn}`,
          ],
          targetAddress: null,
        };
      }
    }

    // FP 2-source: FMUL / FDIV / FADD / FSUB
    if ((word & 0xff200c00) === 0x1e200800) {
      const op = (word >>> 12) & 0xf;
      const mnem =
        op === 0
          ? "fmul"
          : op === 1
            ? "fdiv"
            : op === 2
              ? "fadd"
              : op === 3
                ? "fsub"
                : "fp2";
      return {
        mnem,
        ops: [`${fpPrefix}${rd}`, `${fpPrefix}${rn}`, `${fpPrefix}${rm}`],
        targetAddress: null,
      };
    }

    // FCSEL: 00011110 ftype 1 Rm cond 11 Rn Rd
    if ((word & 0xff200c00) === 0x1e200c00) {
      const cond = AARCH64_COND_CODES[(word >>> 12) & 0xf] ?? "al";
      return {
        mnem: "fcsel",
        ops: [`${fpPrefix}${rd}`, `${fpPrefix}${rn}`, `${fpPrefix}${rm}`, cond],
        targetAddress: null,
      };
    }

    // FCMP
    if ((word & 0xff20fc10) === 0x1e202000) {
      const cmpWithZero = (word & 0x8) !== 0;
      return {
        mnem: "fcmp",
        ops: [
          `${fpPrefix}${rn}`,
          cmpWithZero ? "#0.0" : `${fpPrefix}${rm}`,
        ],
        targetAddress: null,
      };
    }

    // FP 1-source: FMOV / FABS / FNEG / FSQRT / FCVT
    if ((word & 0xff207c00) === 0x1e204000) {
      const opc = (word >>> 15) & 0x3f;
      if (opc === 4 || opc === 5) {
        const dstPrefix = opc === 5 ? "d" : "s";
        return {
          mnem: "fcvt",
          ops: [`${dstPrefix}${rd}`, `${fpPrefix}${rn}`],
          targetAddress: null,
        };
      }
      const mnem =
        opc === 0
          ? "fmov"
          : opc === 1
            ? "fabs"
            : opc === 2
              ? "fneg"
              : opc === 3
                ? "fsqrt"
                : "fp1";
      return {
        mnem,
        ops: [`${fpPrefix}${rd}`, `${fpPrefix}${rn}`],
        targetAddress: null,
      };
    }

    // FMOV (scalar immediate)
    if ((word & 0xff201fe0) === 0x1e201000) {
      const imm8 = (word >>> 13) & 0xff;
      return {
        mnem: "fmov",
        ops: [`${fpPrefix}${rd}`, `#0x${imm8.toString(16)}`],
        targetAddress: null,
      };
    }
  }

  // 18. Advanced SIMD / NEON DSP ops (UABD, UADDLP, USRA)
  if ((word & 0xbf20fc00) === 0x2e207400) {
    const q = (word >>> 30) & 1;
    const suffix = q === 1 ? "16b" : "8b";
    return {
      mnem: "uabd",
      ops: [
        `v${word & 0x1f}.${suffix}`,
        `v${(word >>> 5) & 0x1f}.${suffix}`,
        `v${(word >>> 16) & 0x1f}.${suffix}`,
      ],
      targetAddress: null,
    };
  }
  if ((word & 0xbf3ffc00) === 0x2e202800) {
    return {
      mnem: "uaddlp",
      ops: [`v${word & 0x1f}.8h`, `v${(word >>> 5) & 0x1f}.16b`],
      targetAddress: null,
    };
  }
  if ((word & 0xbf80fc00) === 0x2f001400) {
    return {
      mnem: "usra",
      ops: [`v${word & 0x1f}.8h`, `v${(word >>> 5) & 0x1f}.8h`, "#8"],
      targetAddress: null,
    };
  }

  return {
    mnem: "inst",
    ops: [`0x${word.toString(16)}`],
    targetAddress: null,
  };
}

function decodeExecutableSectionsBuiltin(
  bytes: Buffer,
  parsed: MutableContainerParse,
): void {
  for (const seg of parsed.segments) {
    if (!seg.executable || seg.fileSize === 0) continue;
    const maxBytes = Math.min(seg.fileSize, 512 * 1024);
    let offset = 0;
    while (offset < maxBytes && seg.fileOffset + offset < bytes.length) {
      const vaddr = seg.start + BigInt(offset);
      const pos = seg.fileOffset + offset;
      if (parsed.architecture === "arm64" && pos + 4 <= bytes.length) {
        const word = bytes.readUInt32LE(pos);
        const hex = bytes.subarray(pos, pos + 4).toString("hex");
        const { mnem, ops, targetAddress } = decodeAArch64Instruction(
          word,
          vaddr,
          parsed,
        );
        const classified = classifyInstruction(
          vaddr,
          hex,
          4,
          mnem,
          ops,
          `${mnem} ${ops.join(", ")}`,
        );
        parsed.instructionsByAddr.set(
          vaddr,
          targetAddress !== null && classified.targetAddress === null
            ? { ...classified, targetAddress }
            : classified,
        );
        offset += 4;
      } else {
        const b0 = bytes[pos]!;
        let len = 1;
        let mnem = "byte";
        let ops: string[] = [`0x${b0.toString(16)}`];
        const reg64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"];
        const reg32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"];
        if (
          pos + 4 <= bytes.length &&
          b0 === 0xf3 &&
          bytes[pos + 1] === 0x0f &&
          bytes[pos + 2] === 0x1e &&
          bytes[pos + 3] === 0xfa
        ) {
          len = 4;
          mnem = "endbr64";
          ops = [];
          parsed.functionStartHints.add(vaddr);
        } else if (b0 === 0x55) {
          len = 1;
          mnem = "push";
          ops = ["rbp"];
          if (
            pos + 4 <= bytes.length &&
            bytes[pos + 1] === 0x48 &&
            bytes[pos + 2] === 0x89 &&
            bytes[pos + 3] === 0xe5 &&
            parsed.instructionsByAddr.get(vaddr - 4n)?.mnemonic !== "endbr64"
          ) {
            parsed.functionStartHints.add(vaddr);
          }
        } else if (
          pos + 3 <= bytes.length &&
          b0 === 0x48 &&
          bytes[pos + 1] === 0x89 &&
          bytes[pos + 2] === 0xe5
        ) {
          len = 3;
          mnem = "mov";
          ops = ["rbp", "rsp"];
        } else if (b0 === 0xe8 && pos + 5 <= bytes.length) {
          len = 5;
          mnem = "call";
          const rel = bytes.readInt32LE(pos + 1);
          const target = vaddr + 5n + BigInt(rel);
          ops = [toHex(target)];
          parsed.functionStartHints.add(target);
        } else if (b0 === 0xe9 && pos + 5 <= bytes.length) {
          len = 5;
          mnem = "jmp";
          const rel = bytes.readInt32LE(pos + 1);
          const target = vaddr + 5n + BigInt(rel);
          ops = [toHex(target)];
        } else if (b0 === 0xc3) {
          len = 1;
          mnem = "ret";
          ops = [];
        } else if (b0 === 0x90) {
          len = 1;
          mnem = "nop";
          ops = [];
        } else {
          const hasRexW = b0 === 0x48 && pos + 2 < bytes.length;
          const opByte = hasRexW ? bytes[pos + 1]! : b0;
          const modrmPos = hasRexW ? pos + 2 : pos + 1;
          if (
            modrmPos < bytes.length &&
            (opByte === 0x8b ||
              opByte === 0x89 ||
              opByte === 0x8d ||
              opByte === 0x03 ||
              opByte === 0x01 ||
              opByte === 0x3b ||
              opByte === 0x39)
          ) {
            const modrm = bytes[modrmPos]!;
            const mod = (modrm >>> 6) & 3;
            const reg = (modrm >>> 3) & 7;
            const rm = modrm & 7;
            if (mod !== 3 && rm !== 4 && !(mod === 0 && rm === 5)) {
              const dispLen = mod === 1 ? 1 : mod === 2 ? 4 : 0;
              const totalLen = (hasRexW ? 2 : 1) + 1 + dispLen;
              if (pos + totalLen <= bytes.length) {
                const disp =
                  mod === 1
                    ? bytes.readInt8(modrmPos + 1)
                    : mod === 2
                      ? bytes.readInt32LE(modrmPos + 1)
                      : 0;
                const baseReg = reg64[rm]!;
                const regName = (hasRexW ? reg64 : reg32)[reg]!;
                const sizePrefix =
                  opByte === 0x8d ? "" : hasRexW ? "QWORD PTR " : "DWORD PTR ";
                const dispStr =
                  disp === 0
                    ? ""
                    : disp < 0
                      ? `-0x${Math.abs(disp).toString(16)}`
                      : `+0x${disp.toString(16)}`;
                const memOp = `${sizePrefix}[${baseReg}${dispStr}]`;
                len = totalLen;
                mnem =
                  opByte === 0x8d
                    ? "lea"
                    : opByte === 0x8b || opByte === 0x89
                      ? "mov"
                      : opByte === 0x03 || opByte === 0x01
                        ? "add"
                        : "cmp";
                ops =
                  opByte === 0x89 || opByte === 0x01 || opByte === 0x39
                    ? [memOp, regName]
                    : [regName, memOp];
              }
            }
          }
        }
        const sliceHex = bytes
          .subarray(pos, Math.min(bytes.length, pos + len))
          .toString("hex");
        parsed.instructionsByAddr.set(
          vaddr,
          classifyInstruction(
            vaddr,
            sliceHex,
            len,
            mnem,
            ops,
            `${mnem} ${ops.join(", ")}`,
          ),
        );
        offset += len;
      }
    }
  }
}

function extractBinaryStrings(
  bytes: Buffer,
  segments: readonly ParsedSegment[],
): readonly ParsedString[] {
  const results: ParsedString[] = [];
  const seenAddrs = new Set<bigint>();
  for (const seg of segments) {
    if (seg.fileSize <= 0) continue;
    const limit = Math.min(bytes.length, seg.fileOffset + seg.fileSize);
    let i = seg.fileOffset;
    while (i < limit) {
      const start = i;
      while (
        i < limit &&
        ((bytes[i]! >= 0x20 && bytes[i]! <= 0x7e) ||
          bytes[i] === 0x09 ||
          bytes[i] === 0x0a)
      ) {
        i++;
      }
      const len = i - start;
      if (len >= 4 && i < limit && bytes[i] === 0) {
        const vaddr = seg.start + BigInt(start - seg.fileOffset);
        if (!seenAddrs.has(vaddr)) {
          seenAddrs.add(vaddr);
          const value = bytes.subarray(start, i).toString("utf8");
          results.push({
            address: vaddr,
            value,
            byteLength: len + 1,
          });
        }
        i++;
      } else {
        i++;
      }
      if (results.length >= 4000) break;
    }
    if (results.length >= 4000) break;
  }
  return results;
}

function buildProceduresAndReferences(
  parsed: MutableContainerParse,
  strings: readonly ParsedString[],
): {
  readonly proceduresByAddr: Map<bigint, ParsedProcedure>;
  readonly sortedProcedures: readonly ParsedProcedure[];
  readonly incomingRefsByTarget: BinaryAnalysisModel["incomingRefsByTarget"];
  readonly outgoingRefsBySource: BinaryAnalysisModel["outgoingRefsBySource"];
} {
  // Scan instructions for additional prologue starts on stripped binaries
  const sortedInsns = [...parsed.instructionsByAddr.values()].sort((a, b) =>
    a.address < b.address ? -1 : a.address > b.address ? 1 : 0,
  );
  for (let i = 0; i < sortedInsns.length; i++) {
    const ins = sortedInsns[i]!;
    const prevMnem = sortedInsns[i - 1]?.mnemonic;
    if (
      ins.mnemonic === "endbr64" ||
      ins.mnemonic === "endbr32" ||
      (ins.mnemonic === "push" &&
        (ins.operands[0] === "rbp" ||
          ins.operands[0] === "%rbp" ||
          ins.operands[0] === "ebp" ||
          ins.operands[0] === "%ebp") &&
        prevMnem !== "endbr64" &&
        prevMnem !== "endbr32" &&
        sortedInsns[i + 1]?.mnemonic.startsWith("mov") === true)
    ) {
      parsed.functionStartHints.add(ins.address);
    }
  }

  const execRanges = parsed.segments.filter((s) => s.executable);
  const inExec = (addr: bigint) =>
    execRanges.length === 0 ||
    execRanges.some((s) => addr >= s.start && addr < s.end);

  const knownSymbolSpans = [...parsed.symbolsByAddr.values()].filter(
    (s) => s.isFunction && s.size > 0,
  );
  const isInsideKnownSymbolSpan = (addr: bigint): boolean =>
    knownSymbolSpans.some(
      (s) => addr > s.address && addr < s.address + BigInt(s.size),
    );

  const validStarts = [...parsed.functionStartHints]
    .filter(
      (a) =>
        a > 0n &&
        (parsed.symbolsByAddr.has(a) ||
          (inExec(a) && !isInsideKnownSymbolSpan(a))),
    )
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

  if (validStarts.length === 0) {
    validStarts.push(parsed.entryPoint);
  }

  const proceduresByAddr = new Map<bigint, ParsedProcedure>();
  for (let i = 0; i < validStarts.length; i++) {
    const start = validStarts[i]!;
    const nextStart = validStarts[i + 1];
    const sym = parsed.symbolsByAddr.get(start);
    const validSymName =
      sym !== undefined && !sym.name.startsWith(".") ? sym.name : undefined;
    const name =
      validSymName ??
      (start === parsed.entryPoint ? "_start" : `sub_${start.toString(16)}`);
    if (sym === undefined) {
      parsed.symbolsByAddr.set(start, {
        address: start,
        name,
        size: 0,
        isFunction: true,
        external: false,
        dynamic: false,
        thunk: false,
        thunkTarget: null,
        source: "analysis",
      });
    }

    const symEndLimit =
      sym !== undefined && sym.size > 0
        ? start + BigInt(sym.size)
        : undefined;
    const procInsns: DecodedInsn[] = [];
    const localDisps = new Set<number>();
    const adrpPageByReg = new Map<string, bigint>();
    for (const ins of sortedInsns) {
      if (ins.address < start) continue;
      if (nextStart !== undefined && ins.address >= nextStart) break;
      if (symEndLimit !== undefined && ins.address >= symEndLimit) break;

      let effectiveInsn = ins;
      const mnemLower = ins.mnemonic.toLowerCase();
      if (mnemLower === "adrp" && ins.operands.length >= 2 && ins.targetAddress !== null) {
        adrpPageByReg.set(ins.operands[0]!.toLowerCase(), ins.targetAddress);
      } else if (
        (mnemLower.startsWith("ldr") ||
          mnemLower.startsWith("str") ||
          mnemLower === "add") &&
        ins.operands.length >= 2 &&
        adrpPageByReg.size > 0
      ) {
        if (mnemLower.startsWith("ldr") || mnemLower.startsWith("str")) {
          const memOp = ins.operands[1] ?? "";
          const mMatch =
            /^\[([xX]\d+)(?:,\s*#?(0x[0-9a-fA-F]+|\d+))?\]$/u.exec(memOp);
          if (mMatch !== null) {
            const baseReg = mMatch[1]!.toLowerCase();
            const pageBase = adrpPageByReg.get(baseReg);
            if (pageBase !== undefined) {
              const rawOff = mMatch[2] ?? "0";
              const off = rawOff.toLowerCase().startsWith("0x")
                ? BigInt(rawOff)
                : BigInt(Number.parseInt(rawOff, 10));
              const resolvedAddr = pageBase + off;
              effectiveInsn = { ...ins, targetAddress: resolvedAddr };
              if (
                mnemLower.startsWith("ldr") &&
                ins.operands[0]?.toLowerCase() === baseReg
              ) {
                // If loading a pointer from .got into baseReg, propagate any bound global symbol address
                const gotSlot = parsed.gotSlotByAddr.get(resolvedAddr);
                if (gotSlot !== undefined && gotSlot.symbolValue > 0n) {
                  adrpPageByReg.set(baseReg, gotSlot.symbolValue);
                } else {
                  adrpPageByReg.delete(baseReg);
                }
              }
            }
          }
        } else if (mnemLower === "add" && ins.operands.length >= 3) {
          const dstReg = ins.operands[0]!.toLowerCase();
          const srcReg = ins.operands[1]!.toLowerCase();
          const rawImm = ins.operands[2]!.replace(/^#/u, "");
          const pageBase = adrpPageByReg.get(srcReg);
          if (
            pageBase !== undefined &&
            /^(?:0x[0-9a-fA-F]+|\d+)$/u.test(rawImm)
          ) {
            const off = rawImm.toLowerCase().startsWith("0x")
              ? BigInt(rawImm)
              : BigInt(Number.parseInt(rawImm, 10));
            const resolvedAddr = pageBase + off;
            effectiveInsn = { ...ins, targetAddress: resolvedAddr };
            if (dstReg === srcReg) {
              adrpPageByReg.delete(dstReg);
            }
          }
        }
      } else if (ins.isCall) {
        // Caller-saved x0..x18 clobbered across calls
        for (let r = 0; r <= 18; r++) {
          adrpPageByReg.delete(`x${r}`);
        }
      }

      procInsns.push(effectiveInsn);
      for (const op of effectiveInsn.operands) {
        const dispMatch = /\[(?:rbp|ebp|sp)\s*([+-]\s*0x[0-9a-fA-F]+)\]/u.exec(
          op,
        );
        if (dispMatch !== null) {
          const val = Number.parseInt(dispMatch[1]!.replace(/\s+/gu, ""), 16);
          if (!Number.isNaN(val) && val !== 0) {
            localDisps.add(val);
          }
        }
      }
      if (effectiveInsn.isReturn && (sym === undefined || sym.size === 0)) {
        break;
      }
    }

    const lastInsn = procInsns[procInsns.length - 1];
    const computedSize =
      sym !== undefined && sym.size > 0
        ? sym.size
        : lastInsn !== undefined
          ? Number(lastInsn.address - start) + Math.max(1, lastInsn.length)
          : nextStart !== undefined
            ? Math.max(1, Math.min(256, Number(nextStart - start)))
            : 16;
    const endInclusive = start + BigInt(Math.max(1, computedSize)) - 1n;

    proceduresByAddr.set(start, {
      address: start,
      name,
      size: Math.max(1, computedSize),
      endInclusive,
      external: sym?.external ?? false,
      thunk: sym?.thunk ?? false,
      thunkTarget: sym?.thunkTarget ?? null,
      instructions: procInsns,
      callees: new Set(),
      callers: new Set(),
      localDisplacements: [...localDisps].sort((a, b) => a - b),
    });
  }

  const sortedProcedures = [...proceduresByAddr.values()].sort((a, b) =>
    a.address < b.address ? -1 : a.address > b.address ? 1 : 0,
  );
  const stringAddrs = new Set(strings.map((s) => s.address));
  const incomingRefsByTarget = new Map<
    bigint,
    Array<{
      readonly sourceAddr: bigint;
      readonly targetAddr: bigint;
      readonly isCall: boolean;
      readonly isJump: boolean;
      readonly isData: boolean;
      readonly isConditional: boolean;
    }>
  >();
  const outgoingRefsBySource = new Map<
    bigint,
    Array<{
      readonly sourceAddr: bigint;
      readonly targetAddr: bigint;
      readonly isCall: boolean;
      readonly isJump: boolean;
      readonly isData: boolean;
      readonly isConditional: boolean;
    }>
  >();

  for (const proc of sortedProcedures) {
    for (const ins of proc.instructions) {
      if (ins.targetAddress === null) continue;
      const target = ins.targetAddress;
      const isData =
        !ins.isCall &&
        !ins.isJump &&
        (stringAddrs.has(target) ||
          parsed.symbolsByAddr.has(target) ||
          parsed.gotSlotByAddr.has(target));
      if (!ins.isCall && !ins.isJump && !isData) continue;
      const calleeProc = proceduresByAddr.get(target);
      const isCrossProcJump =
        ins.isJump &&
        calleeProc !== undefined &&
        calleeProc.address !== proc.address;
      const isEffectiveCall = ins.isCall || isCrossProcJump;
      const refObj = {
        sourceAddr: ins.address,
        targetAddr: target,
        isCall: isEffectiveCall,
        isJump: ins.isJump,
        isData,
        isConditional: ins.isConditionalJump,
      };
      const inList = incomingRefsByTarget.get(target) ?? [];
      inList.push(refObj);
      incomingRefsByTarget.set(target, inList);

      const outList = outgoingRefsBySource.get(ins.address) ?? [];
      outList.push(refObj);
      outgoingRefsBySource.set(ins.address, outList);

      if (isEffectiveCall && calleeProc !== undefined) {
        proc.callees.add(target);
        calleeProc.callers.add(proc.address);
        // If calling a .plt thunk whose real intra-library implementation exists, link directly!
        if (calleeProc.thunk && calleeProc.thunkTarget !== null) {
          const realTargetAddr = calleeProc.thunkTarget;
          const realTargetProc = proceduresByAddr.get(realTargetAddr);
          if (realTargetProc !== undefined) {
            proc.callees.add(realTargetAddr);
            realTargetProc.callers.add(proc.address);
            calleeProc.callees.add(realTargetAddr);
            realTargetProc.callers.add(calleeProc.address);
          }
        }
      }
    }
  }

  return {
    proceduresByAddr,
    sortedProcedures,
    incomingRefsByTarget,
    outgoingRefsBySource,
  };
}
