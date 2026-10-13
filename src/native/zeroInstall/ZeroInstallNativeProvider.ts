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
          model.sortedProcedures.map((proc) => ({
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
            .filter((proc) => matcher.value(proc.name))
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
        return ok({
          name: p.name,
          entrypoint: toHex(p.address),
          basicblock_count: blocks.length,
          length: p.size,
          signature: this.#formatSignature(p),
          locals: p.localDisplacements.map((disp) => ({
            description: `int64_t local_${Math.abs(disp).toString(16)} /* [bp${disp < 0 ? disp : `+${disp}`}] */`,
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
        return ok(this.#comments.get(toHex(addr.value)) ?? null);
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
    const byAddr = parseAddressString(selector);
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

  #formatSignature(proc: ParsedProcedure): string {
    return `int64_t ${proc.name}(int64_t arg0, int64_t arg1, int64_t arg2, int64_t arg3)`;
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
    const lines: string[] = [];
    lines.push(`${this.#formatSignature(proc)} {`);
    for (const disp of proc.localDisplacements) {
      lines.push(`  int64_t local_${Math.abs(disp).toString(16)} = 0;`);
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
        lines.push(
          `  goto loc_${ins.targetAddress.toString(16)}; // @ ${toHex(ins.address)}`,
        );
      } else if (
        ins.targetAddress !== null &&
        stringByAddr.has(ins.targetAddress)
      ) {
        const strLit = JSON.stringify(stringByAddr.get(ins.targetAddress));
        lines.push(
          `  /* ref string ${strLit} */ // @ ${toHex(ins.address)}: ${ins.mnemonic} ${ins.operands.join(", ")}`,
        );
      } else if (
        m.startsWith("mov") ||
        m.startsWith("lea") ||
        m.startsWith("add") ||
        m.startsWith("sub") ||
        m.startsWith("xor") ||
        m.startsWith("cmp") ||
        m.startsWith("str") ||
        m.startsWith("ldr")
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
    const entryComment = this.#comments.get(entryHex);
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

    return {
      procedure: {
        ...this.#formatProcedureIdentity(proc),
        signature: this.#formatSignature(proc),
        locals: proc.localDisplacements.map((disp) => ({
          description: `int64_t local_${Math.abs(disp).toString(16)} /* [bp${disp < 0 ? disp : `+${disp}`}] */`,
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
    proceduresByAddr,
    sortedProcedures,
    strings,
    instructionsByAddr: parsedFormat.instructionsByAddr,
    incomingRefsByTarget,
    outgoingRefsBySource,
  };
}

interface MutableContainerParse {
  imageBase: bigint;
  entryPoint: bigint;
  is64Bit: boolean;
  littleEndian: boolean;
  architecture: string;
  segments: ParsedSegment[];
  symbolsByAddr: Map<bigint, ParsedSymbol>;
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
    instructionsByAddr: new Map(),
    functionStartHints: new Set([base]),
  };
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
  const functionStartHints = new Set<bigint>();
  if (entryPoint > 0n) {
    functionStartHints.add(entryPoint);
  }

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
      if (!name || stValue === 0n) continue;
      const stType = stInfo & 0xf;
      const isFunc = stType === 2;
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
  const nmBin = findExecutableInPath(["nm", "llvm-nm"], environment);
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

  const objdumpBin = findExecutableInPath(
    ["objdump", "llvm-objdump", "llvm-objdump.exe", "objdump.exe"],
    environment,
  );
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

function decodeExecutableSectionsBuiltin(
  bytes: Buffer,
  parsed: MutableContainerParse,
): void {
  for (const seg of parsed.segments) {
    if (!seg.executable || seg.fileSize === 0) continue;
    const maxBytes = Math.min(seg.fileSize, 256 * 1024);
    let offset = 0;
    while (offset < maxBytes && seg.fileOffset + offset < bytes.length) {
      const vaddr = seg.start + BigInt(offset);
      const pos = seg.fileOffset + offset;
      if (parsed.architecture === "arm64" && pos + 4 <= bytes.length) {
        const word = bytes.readUInt32LE(pos);
        const hex = bytes.subarray(pos, pos + 4).toString("hex");
        let mnem = "inst";
        let ops: string[] = [`0x${word.toString(16)}`];
        let target: bigint | null = null;
        if ((word & 0xfc000000) === 0x94000000) {
          mnem = "bl";
          const imm26 = word & 0x03ffffff;
          const signed = (imm26 & 0x02000000) !== 0 ? imm26 | ~0x03ffffff : imm26;
          target = vaddr + BigInt(signed * 4);
          ops = [toHex(target)];
          parsed.functionStartHints.add(target);
        } else if (word === 0xd65f03c0) {
          mnem = "ret";
          ops = [];
        }
        parsed.instructionsByAddr.set(
          vaddr,
          classifyInstruction(vaddr, hex, 4, mnem, ops, `${mnem} ${ops.join(", ")}`),
        );
        offset += 4;
      } else {
        const b0 = bytes[pos]!;
        let len = 1;
        let mnem = "byte";
        let ops: string[] = [`0x${b0.toString(16)}`];
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
            bytes[pos + 3] === 0xe5
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
    if (
      ins.mnemonic === "endbr64" ||
      (ins.mnemonic === "push" &&
        ins.operands[0] === "rbp" &&
        sortedInsns[i + 1]?.mnemonic === "mov")
    ) {
      parsed.functionStartHints.add(ins.address);
    }
  }

  const execRanges = parsed.segments.filter((s) => s.executable);
  const inExec = (addr: bigint) =>
    execRanges.length === 0 ||
    execRanges.some((s) => addr >= s.start && addr < s.end);

  const validStarts = [...parsed.functionStartHints]
    .filter((a) => a > 0n && (inExec(a) || parsed.symbolsByAddr.has(a)))
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

  if (validStarts.length === 0) {
    validStarts.push(parsed.entryPoint);
  }

  const proceduresByAddr = new Map<bigint, ParsedProcedure>();
  for (let i = 0; i < validStarts.length; i++) {
    const start = validStarts[i]!;
    const nextStart = validStarts[i + 1];
    const sym = parsed.symbolsByAddr.get(start);
    const name =
      sym?.name ??
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

    const procInsns: DecodedInsn[] = [];
    const localDisps = new Set<number>();
    for (const ins of sortedInsns) {
      if (ins.address < start) continue;
      if (nextStart !== undefined && ins.address >= nextStart) break;
      procInsns.push(ins);
      for (const op of ins.operands) {
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
      if (ins.isReturn && sym?.size === 0) {
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
      const isData = !ins.isCall && !ins.isJump && (stringAddrs.has(target) || parsed.symbolsByAddr.has(target));
      if (!ins.isCall && !ins.isJump && !isData) continue;
      const refObj = {
        sourceAddr: ins.address,
        targetAddr: target,
        isCall: ins.isCall,
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

      if (ins.isCall) {
        const calleeProc = proceduresByAddr.get(target);
        if (calleeProc !== undefined) {
          proc.callees.add(target);
          calleeProc.callers.add(proc.address);
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
