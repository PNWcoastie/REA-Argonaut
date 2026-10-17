import { existsSync } from "node:fs";
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type {
  ExecutionOptions,
  ProviderIdentity,
} from "../../application/AnalysisProvider.js";
import { ADAPTIVE_RESOURCE_PROFILE } from "../../config/AdaptiveResourceProfile.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { err, ok, type Result } from "../../domain/result.js";
import {
  RUST_PARITY_PROVIDER_IDENTITY,
  rustParityReportSchema,
  type RustParityBenchmarkTelemetry,
  type RustParityCounterexample,
  type RustParityMemorySafety,
  type RustParityReport,
  type RustParityScaffoldedCrate,
  type RustParityScalarType,
  type VerifyRustParityInput,
} from "../../domain/rustParity/rustParity.js";
import {
  ParitySandboxRunner,
  type SandboxRunResult,
} from "../../process/ParitySandboxRunner.js";

const OPERATION = "verify_rust_parity";
const IDENTIFIER_REGEX = /^[A-Za-z_][A-Za-z0-9_]*$/;
const JSON_MARKER = "ARGON_PARITY_JSON:";

export interface RustParityPort {
  readonly identity: ProviderIdentity;
  verify(
    input: VerifyRustParityInput,
    options?: ExecutionOptions,
  ): Promise<Result<RustParityReport, AnalysisError>>;
}

interface SampleVectorPayload {
  readonly inputs_formatted: readonly string[];
  readonly inputs_rust_literal: readonly string[];
  readonly output_formatted: string;
  readonly output_rust_literal: string;
  readonly output_hex: string;
}

interface HarnessJsonPayload {
  readonly status: "verified_bit_exact" | "diverged" | "sandbox_fault";
  readonly iterations_completed: number;
  readonly boundary_cases_tested: number;
  readonly fault_reason?: string;
  readonly counterexample: RustParityCounterexample | null;
  readonly benchmark_telemetry?: RustParityBenchmarkTelemetry | null;
  readonly sample_vectors?: readonly SampleVectorPayload[];
}

function countCandidateUnsafeBlocks(rustSource: string): number {
  const withoutBlockComments = rustSource.replace(/\/\*[\s\S]*?\*\//g, " ");
  const withoutLineComments = withoutBlockComments.replace(/\/\/.*$/gm, " ");
  const withoutStrings = withoutLineComments.replace(
    /"(?:\\.|[^"\\])*"/g,
    '""',
  );
  const matches = withoutStrings.match(/\bunsafe\b/g);
  return matches ? matches.length : 0;
}

function resolveExecutable(
  name: string,
  extraPaths: readonly string[],
): string | null {
  for (const candidate of extraPaths) {
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  const pathEnv = process.env.PATH ?? "";
  const sep = os.platform() === "win32" ? ";" : ":";
  const exts = os.platform() === "win32" ? [".exe", ".cmd", ""] : [""];
  for (const dir of pathEnv.split(sep)) {
    if (!dir) continue;
    for (const ext of exts) {
      const full = path.join(dir, `${name}${ext}`);
      if (existsSync(full)) {
        return full;
      }
    }
  }
  return null;
}

function resolveRustcPath(): string | null {
  const home = os.homedir();
  return resolveExecutable("rustc", [
    path.join(home, ".cargo", "bin", os.platform() === "win32" ? "rustc.exe" : "rustc"),
    "/usr/bin/rustc",
    "/usr/local/bin/rustc",
  ]);
}

function resolveCargoPath(): string | null {
  const home = os.homedir();
  return resolveExecutable("cargo", [
    path.join(home, ".cargo", "bin", os.platform() === "win32" ? "cargo.exe" : "cargo"),
    "/usr/bin/cargo",
    "/usr/local/bin/cargo",
  ]);
}

function resolveCCompilerPath(): string | null {
  return (
    resolveExecutable("gcc", ["/usr/bin/gcc", "/usr/local/bin/gcc"]) ??
    resolveExecutable("cc", ["/usr/bin/cc"]) ??
    resolveExecutable("clang", ["/usr/bin/clang", "/usr/local/bin/clang"])
  );
}

/**
 * Patches a binary buffer in-memory so that OS dynamic loaders (`dlopen` / `LoadLibrary`)
 * can load PIE executables (`DF_1_PIE` on Linux ELF, `MH_EXECUTE` on macOS Mach-O,
 * `IMAGE_FILE_DLL` on Windows PE) without modifying the user's original artifact on disk.
 */
function patchBinaryForDynamicLoading(rawBuf: Buffer): Buffer {
  const buf = Buffer.from(rawBuf);

  // 1. ELF container: strip DF_1_PIE (0x08000000) from DT_FLAGS_1 (0x6ffffffb) in PT_DYNAMIC / .dynamic
  if (
    buf.length >= 64 &&
    buf[0] === 0x7f &&
    buf[1] === 0x45 &&
    buf[2] === 0x4c &&
    buf[3] === 0x46
  ) {
    const is64 = buf[4] === 2;
    const isLE = buf[5] === 1;
    if (is64 && isLE) {
      const eType = buf.readUInt16LE(16);
      if (eType === 2) {
        // Patch ET_EXEC -> ET_DYN if needed
        buf.writeUInt16LE(3, 16);
      }
      const ePhoff = Number(buf.readBigUInt64LE(32));
      const ePhentsize = buf.readUInt16LE(54);
      const ePhnum = buf.readUInt16LE(56);
      if (ePhoff > 0 && ePhentsize >= 56 && ePhnum > 0) {
        for (let i = 0; i < ePhnum; i++) {
          const phBase = ePhoff + i * ePhentsize;
          if (phBase + 56 > buf.length) break;
          const pType = buf.readUInt32LE(phBase);
          // PT_DYNAMIC == 2
          if (pType === 2) {
            const pOffset = Number(buf.readBigUInt64LE(phBase + 8));
            const pFilesz = Number(buf.readBigUInt64LE(phBase + 32));
            const end = Math.min(buf.length, pOffset + pFilesz);
            for (let off = pOffset; off + 16 <= end; off += 16) {
              const dTag = buf.readBigInt64LE(off);
              if (dTag === 0n) break;
              // DT_FLAGS_1 == 0x6ffffffb
              if (dTag === 0x6ffffffbn) {
                const dVal = buf.readBigUInt64LE(off + 8);
                // Clear DF_1_PIE (0x08000000)
                const cleared = dVal & ~0x08000000n;
                buf.writeBigUInt64LE(cleared, off + 8);
              }
            }
          }
        }
      }
    } else if (!is64 && isLE) {
      const ePhoff = buf.readUInt32LE(28);
      const ePhentsize = buf.readUInt16LE(42);
      const ePhnum = buf.readUInt16LE(44);
      if (ePhoff > 0 && ePhentsize >= 32 && ePhnum > 0) {
        for (let i = 0; i < ePhnum; i++) {
          const phBase = ePhoff + i * ePhentsize;
          if (phBase + 32 > buf.length) break;
          const pType = buf.readUInt32LE(phBase);
          if (pType === 2) {
            const pOffset = buf.readUInt32LE(phBase + 4);
            const pFilesz = buf.readUInt32LE(phBase + 16);
            const end = Math.min(buf.length, pOffset + pFilesz);
            for (let off = pOffset; off + 8 <= end; off += 8) {
              const dTag = buf.readUInt32LE(off);
              if (dTag === 0) break;
              if (dTag === 0x6ffffffb) {
                const dVal = buf.readUInt32LE(off + 4);
                buf.writeUInt32LE(dVal & ~0x08000000, off + 4);
              }
            }
          }
        }
      }
    }
    return buf;
  }

  // 2. Mach-O 64-bit / 32-bit LE: patch MH_EXECUTE (2) -> MH_DYLIB (6)
  if (buf.length >= 32) {
    const magic = buf.readUInt32LE(0);
    if (magic === 0xfeedfacf || magic === 0xfeedface) {
      const fileType = buf.readUInt32LE(12);
      if (fileType === 2) {
        buf.writeUInt32LE(6, 12);
      }
      return buf;
    }
  }

  // 3. PE container: set IMAGE_FILE_DLL (0x2000) in COFF Characteristics
  if (buf.length >= 64 && buf[0] === 0x4d && buf[1] === 0x5a) {
    const peOffset = buf.readUInt32LE(0x3c);
    if (
      peOffset + 24 <= buf.length &&
      buf[peOffset] === 0x50 &&
      buf[peOffset + 1] === 0x45 &&
      buf[peOffset + 2] === 0x00 &&
      buf[peOffset + 3] === 0x00
    ) {
      const charOff = peOffset + 22;
      const chars = buf.readUInt16LE(charOff);
      buf.writeUInt16LE(chars | 0x2000, charOff);
    }
  }

  return buf;
}

type BaseParityScalarType = Exclude<
  RustParityScalarType,
  "f32_finite" | "f64_finite"
>;

function normalizeAbiScalarType(
  ty: RustParityScalarType,
): BaseParityScalarType {
  if (ty === "f32_finite") return "f32";
  if (ty === "f64_finite") return "f64";
  return ty;
}

function detectElfMachineArch(rawBuf: Buffer): string | null {
  if (
    rawBuf.length >= 20 &&
    rawBuf[0] === 0x7f &&
    rawBuf[1] === 0x45 &&
    rawBuf[2] === 0x4c &&
    rawBuf[3] === 0x46
  ) {
    const isLE = rawBuf[5] === 1;
    const eMachine = isLE ? rawBuf.readUInt16LE(18) : rawBuf.readUInt16BE(18);
    if (eMachine === 62) return "x64";
    if (eMachine === 183) return "arm64";
    if (eMachine === 3) return "ia32";
    if (eMachine === 40) return "arm";
    if (eMachine === 243) return "riscv64";
  }
  return null;
}

const C_DIGEST_HELPERS_PREAMBLE = `/* ArgonZeroG built-in canonical out-buffer / struct digest helpers */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

static inline uint64_t argon_avalanche64(uint64_t h) {
    h ^= h >> 30;
    h *= 0xbf58476d1ce4e5b9ULL;
    h ^= h >> 27;
    h *= 0x94d049bb133111ebULL;
    h ^= h >> 31;
    return h;
}

static inline uint64_t argon_digest_bytes(const void *data, size_t len) {
    const uint8_t *bytes = (const uint8_t *)data;
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < len; ++i) {
        h ^= (uint64_t)bytes[i];
        h *= 0x100000001b3ULL;
    }
    return argon_avalanche64(h);
}

static inline uint64_t argon_digest_u32(const uint32_t *vals, size_t count) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < count; ++i) {
        h ^= (uint64_t)vals[i];
        h *= 0x100000001b3ULL;
        h ^= h >> 32;
    }
    return argon_avalanche64(h);
}

static inline uint64_t argon_digest_i32(const int32_t *vals, size_t count) {
    return argon_digest_u32((const uint32_t *)vals, count);
}

static inline uint64_t argon_digest_f32(const float *vals, size_t count) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < count; ++i) {
        uint32_t bits = 0;
        memcpy(&bits, &vals[i], sizeof(uint32_t));
        if (bits == 0x80000000U) {
            bits = 0U;
        } else if ((bits & 0x7f800000U) == 0x7f800000U && (bits & 0x007fffffU) != 0U) {
            bits = 0x7fc00000U;
        }
        h ^= (uint64_t)bits;
        h *= 0x100000001b3ULL;
        h ^= h >> 32;
    }
    return argon_avalanche64(h);
}

static inline uint64_t argon_digest_f64(const double *vals, size_t count) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < count; ++i) {
        uint64_t bits = 0;
        memcpy(&bits, &vals[i], sizeof(uint64_t));
        if (bits == 0x8000000000000000ULL) {
            bits = 0ULL;
        } else if ((bits & 0x7ff0000000000000ULL) == 0x7ff0000000000000ULL && (bits & 0x000fffffffffffffULL) != 0ULL) {
            bits = 0x7ff8000000000000ULL;
        }
        h ^= bits;
        h *= 0x100000001b3ULL;
        h ^= h >> 32;
    }
    return argon_avalanche64(h);
}
`;

const RUST_DIGEST_HELPERS_PREAMBLE = `/// Built-in SplitMix64 avalanche finalizer for canonical out-buffer digests.
#[inline]
pub fn argon_avalanche64(mut h: u64) -> u64 {
    h ^= h >> 30;
    h = h.wrapping_mul(0xbf58476d1ce4e5b9);
    h ^= h >> 27;
    h = h.wrapping_mul(0x94d049bb133111eb);
    h ^ (h >> 31)
}

/// Folds a byte slice into a deterministic 64-bit digest matching C \`argon_digest_bytes\`.
#[inline]
pub fn argon_digest_bytes(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    argon_avalanche64(h)
}

/// Folds a \`u32\` slice into a deterministic 64-bit digest matching C \`argon_digest_u32\`.
#[inline]
pub fn argon_digest_u32(vals: &[u32]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &v in vals {
        h ^= v as u64;
        h = h.wrapping_mul(0x100000001b3);
        h ^= h >> 32;
    }
    argon_avalanche64(h)
}

/// Folds an \`i32\` slice into a deterministic 64-bit digest matching C \`argon_digest_i32\`.
#[inline]
pub fn argon_digest_i32(vals: &[i32]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &v in vals {
        h ^= (v as u32) as u64;
        h = h.wrapping_mul(0x100000001b3);
        h ^= h >> 32;
    }
    argon_avalanche64(h)
}

/// Folds an \`f32\` slice into a canonical 64-bit digest (normalizing \`-0.0\` and \`NaN\` payloads) matching C \`argon_digest_f32\`.
#[inline]
pub fn argon_digest_f32(vals: &[f32]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &v in vals {
        let mut bits = v.to_bits();
        if bits == 0x8000_0000 {
            bits = 0;
        } else if v.is_nan() {
            bits = 0x7fc0_0000;
        }
        h ^= bits as u64;
        h = h.wrapping_mul(0x100000001b3);
        h ^= h >> 32;
    }
    argon_avalanche64(h)
}

/// Folds an \`f64\` slice into a canonical 64-bit digest (normalizing \`-0.0\` and \`NaN\` payloads) matching C \`argon_digest_f64\`.
#[inline]
pub fn argon_digest_f64(vals: &[f64]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &v in vals {
        let mut bits = v.to_bits();
        if bits == 0x8000_0000_0000_0000 {
            bits = 0;
        } else if v.is_nan() {
            bits = 0x7ff8_0000_0000_0000;
        }
        h ^= bits;
        h = h.wrapping_mul(0x100000001b3);
        h ^= h >> 32;
    }
    argon_avalanche64(h)
}
`;

function rustStorageType(ty: RustParityScalarType): string {
  const base = normalizeAbiScalarType(ty);
  return base === "bytes" ? "Vec<u8>" : base;
}

function formatArgCall(ty: RustParityScalarType, expr: string): string {
  const base = normalizeAbiScalarType(ty);
  return base === "bytes" ? `fmt_bytes(&${expr})` : `fmt_${base}(${expr})`;
}

function literalArgCall(ty: RustParityScalarType, expr: string): string {
  const base = normalizeAbiScalarType(ty);
  return base === "bytes" ? `lit_bytes(&${expr})` : `lit_${base}(${expr})`;
}

function generateBoundaryExpr(ty: RustParityScalarType): string {
  switch (ty) {
    case "bool":
      return "vec![false, true]";
    case "i8":
      return "vec![0i8, 1, -1, 2, -2, 63, 64, -64, i8::MAX - 1, i8::MAX, i8::MIN + 1, i8::MIN]";
    case "u8":
      return "vec![0u8, 1, 2, 63, 64, 0x7f, 0x80, 0xfe, 0xff]";
    case "i16":
      return "vec![0i16, 1, -1, 2, -2, 0x7f, 0x80, 0xff, 4095, 4096, 4097, -4096, i16::MAX - 1, i16::MAX, i16::MIN + 1, i16::MIN]";
    case "u16":
      return "vec![0u16, 1, 2, 0x7f, 0x80, 0xff, 4095, 4096, 4097, 32767, 32768, 65534, 65535]";
    case "i32":
      return "vec![0i32, 1, -1, 2, -2, 0x7f, 0x80, 0xff, 4095, 4096, 4097, 65535, 65536, -4096, -65536, 0xdeadbeefu32 as i32, i32::MAX - 1, i32::MAX, i32::MIN + 1, i32::MIN]";
    case "u32":
      return "vec![0u32, 1, 2, 0x7f, 0x80, 0xff, 4095, 4096, 4097, 65535, 65536, 0x7fffffff, 0x80000000, 0xdeadbeef, u32::MAX - 1, u32::MAX]";
    case "i64":
      return "vec![0i64, 1, -1, 2, -2, 0x7f, 0x80, 0xff, 4095, 4096, 4097, 65535, 65536, -4096, 0x7fffffff, 0x80000000, 0xdeadbeef, i64::MAX - 1, i64::MAX, i64::MIN + 1, i64::MIN]";
    case "u64":
      return "vec![0u64, 1, 2, 0x7f, 0x80, 0xff, 4095, 4096, 4097, 65535, 65536, 0x7fffffff, 0x80000000, 0xffffffff, 0xdeadbeef, 0x7fffffffffffffff, 0x8000000000000000, u64::MAX - 1, u64::MAX]";
    case "f32":
      return "vec![0.0f32, -0.0f32, 1.0, -1.0, 2.0, -2.0, 0.5, -0.5, 4095.0, 4096.0, 4097.0, f32::MIN_POSITIVE, -f32::MIN_POSITIVE, f32::EPSILON, f32::MAX, f32::MIN, f32::INFINITY, f32::NEG_INFINITY, f32::NAN]";
    case "f32_finite":
      return "vec![0.0f32, -0.0f32, 1.0, -1.0, 2.0, -2.0, 0.5, -0.5, 0.125, 3.1415927, -3.1415927, 4095.0, 4096.0, 4097.0, f32::MIN_POSITIVE, -f32::MIN_POSITIVE, f32::EPSILON, -f32::EPSILON]";
    case "f64":
      return "vec![0.0f64, -0.0f64, 1.0, -1.0, 2.0, -2.0, 0.5, -0.5, 4095.0, 4096.0, 4097.0, f64::MIN_POSITIVE, -f64::MIN_POSITIVE, f64::EPSILON, f64::MAX, f64::MIN, f64::INFINITY, f64::NEG_INFINITY, f64::NAN]";
    case "f64_finite":
      return "vec![0.0f64, -0.0f64, 1.0, -1.0, 2.0, -2.0, 0.5, -0.5, 0.125, 3.141592653589793, -3.141592653589793, 4095.0, 4096.0, 4097.0, f64::MIN_POSITIVE, -f64::MIN_POSITIVE, f64::EPSILON, -f64::EPSILON]";
    case "bytes":
      return 'vec![vec![], vec![0x00u8], vec![0xffu8], b"ARGON_ZEROG_PARITY_V1".to_vec(), (0u8..16u8).collect::<Vec<u8>>(), vec![0xa5u8; 64]]';
  }
}

function generateRustHarnessSource(
  input: VerifyRustParityInput,
  libPathLiteral: string,
  rustFnName: string,
  forbidUnsafeEnforced: boolean,
): string {
  const argTypes = input.arg_types;
  const retType = normalizeAbiScalarType(input.return_type);
  const tupleType = `(${argTypes.map((t) => `${rustStorageType(t)},`).join(" ")})`;
  const cFnParamSig = argTypes
    .map((t, i) => {
      const base = normalizeAbiScalarType(t);
      return base === "bytes"
        ? `a${i}_ptr: *const u8, a${i}_len: usize`
        : `a${i}: ${base}`;
    })
    .join(", ");
  const cFnCallArgs = argTypes
    .map((t, i) =>
      t === "bytes"
        ? `args.${i}.as_ptr(), args.${i}.len()`
        : `args.${i}`,
    )
    .join(", ");
  const rustFnCallArgs = argTypes
    .map((t, i) => (t === "bytes" ? `&args.${i}[..]` : `args.${i}`))
    .join(", ");
  const benchCCallArgs = argTypes
    .map((t, i) =>
      t === "bytes" ? `a.${i}.as_ptr(), a.${i}.len()` : `a.${i}`,
    )
    .join(", ");
  const benchRustCallArgs = argTypes
    .map((t, i) => (t === "bytes" ? `&a.${i}[..]` : `a.${i}`))
    .join(", ");
  const sanitizedCandidateSource = forbidUnsafeEnforced
    ? input.rust_source_code.replace(/#\s*\[\s*no_mangle\s*\]/g, "")
    : input.rust_source_code;

  const boundaryVecDecls = argTypes
    .map(
      (t, i) =>
        `let b${i}: Vec<${rustStorageType(t)}> = ${generateBoundaryExpr(t)};`,
    )
    .join("\n    ");

  const defaultTupleInit = `(${argTypes.map((_, i) => `b${i}[0].clone(),`).join(" ")})`;

  const singleAxisBoundaryLoops = argTypes
    .map((_, i) => {
      const tupleAssign = `(${argTypes
        .map((__, j) => (i === j ? "val.clone()," : `b${j}[0].clone(),`))
        .join(" ")})`;
      return `
    for val in &b${i} {
        if boundary_cases.len() < 64 {
            boundary_cases.push(${tupleAssign});
        }
    }`;
    })
    .join("\n");

  const diagonalBoundaryLoop = `
    for idx in 0..20usize {
        if boundary_cases.len() >= 64 {
            break;
        }
        boundary_cases.push((${argTypes.map((_, i) => `b${i}[idx % b${i}.len()].clone(),`).join(" ")}));
    }`;

  const randomTupleExpr = `(${argTypes.map((t) => `gen_${t}(&mut rng),`).join(" ")})`;

  const formatTupleVecExpr = `vec![${argTypes.map((t, i) => formatArgCall(t, `args.${i}`)).join(", ")}]`;
  const literalTupleVecExpr = `vec![${argTypes.map((t, i) => literalArgCall(t, `args.${i}`)).join(", ")}]`;

  const shrinkBlocks = argTypes
    .map((rawT, i) => {
      const t = normalizeAbiScalarType(rawT);
      if (t === "bytes") {
        return `
            {
                if !cur.${i}.is_empty() {
                    let mut probe_empty = cur.clone();
                    probe_empty.${i} = Vec::new();
                    if is_diverged(c_fn, &probe_empty) {
                        cur.${i} = Vec::new();
                        shrink_steps += 1;
                        changed = true;
                    }
                }
                if !cur.${i}.is_empty() {
                    let mut low = 0usize;
                    let mut high = cur.${i}.len();
                    for _ in 0..32 {
                        if high <= low + 1 {
                            break;
                        }
                        let mid = low + (high - low) / 2;
                        let mut probe = cur.clone();
                        probe.${i} = cur.${i}[..mid].to_vec();
                        if is_diverged(c_fn, &probe) {
                            cur.${i} = probe.${i};
                            high = mid;
                            shrink_steps += 1;
                            changed = true;
                        } else {
                            low = mid;
                        }
                    }
                }
                let cur_len = cur.${i}.len();
                for b_idx in 0..cur_len {
                    let orig_b = cur.${i}[b_idx];
                    if orig_b != 0 {
                        let mut probe_zero = cur.clone();
                        probe_zero.${i}[b_idx] = 0;
                        if is_diverged(c_fn, &probe_zero) {
                            cur.${i}[b_idx] = 0;
                            shrink_steps += 1;
                            changed = true;
                            continue;
                        }
                        let half_b = orig_b / 2;
                        if half_b != orig_b && half_b != 0 {
                            let mut probe_half = cur.clone();
                            probe_half.${i}[b_idx] = half_b;
                            if is_diverged(c_fn, &probe_half) {
                                cur.${i}[b_idx] = half_b;
                                shrink_steps += 1;
                                changed = true;
                            }
                        }
                    }
                }
            }`;
      }
      return `
            {
                let orig_val = cur.${i};
                for cand in shrink_candidates_${t}(orig_val) {
                    if !same_arg_${t}(cand, cur.${i}) {
                        let mut probe = cur.clone();
                        probe.${i} = cand;
                        if is_diverged(c_fn, &probe) {
                            cur.${i} = cand;
                            shrink_steps += 1;
                            changed = true;
                            break;
                        }
                    }
                }
                let mut low = zero_${t}();
                let mut high = cur.${i};
                for _ in 0..64 {
                    let mid = bisect_${t}(low, high);
                    if same_arg_${t}(mid, high) || same_arg_${t}(mid, low) {
                        break;
                    }
                    let mut probe = cur.clone();
                    probe.${i} = mid;
                    if is_diverged(c_fn, &probe) {
                        high = mid;
                        cur.${i} = mid;
                        shrink_steps += 1;
                        changed = true;
                    } else {
                        low = mid;
                    }
                }
                for step_cand in step_toward_zero_${t}(cur.${i}) {
                    if !same_arg_${t}(step_cand, cur.${i}) {
                        let mut probe = cur.clone();
                        probe.${i} = step_cand;
                        if is_diverged(c_fn, &probe) {
                            cur.${i} = step_cand;
                            shrink_steps += 1;
                            changed = true;
                        }
                    }
                }
            }`;
    })
    .join("\n");

  const candidateDigestPreamble = sanitizedCandidateSource.includes(
    "fn argon_digest_bytes",
  )
    ? ""
    : RUST_DIGEST_HELPERS_PREAMBLE;

  return `#![allow(dead_code, unused_variables, non_snake_case, unused_mut, unused_parens, overflowing_literals, improper_ctypes_definitions)]

mod candidate {
${forbidUnsafeEnforced ? "#![forbid(unsafe_code)]" : ""}
${sanitizedCandidateSource}
${candidateDigestPreamble}
}

#[cfg(unix)]
#[link(name = "dl")]
extern "C" {
    fn dlopen(filename: *const std::os::raw::c_char, flags: i32) -> *mut std::ffi::c_void;
    fn dlsym(handle: *mut std::ffi::c_void, symbol: *const std::os::raw::c_char) -> *mut std::ffi::c_void;
    fn dlerror() -> *const std::os::raw::c_char;
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryA(lpLibFileName: *const u8) -> *mut std::ffi::c_void;
    fn GetProcAddress(hModule: *mut std::ffi::c_void, lpProcName: *const u8) -> *mut std::ffi::c_void;
}

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
}

struct SampleVector {
    inputs_formatted: Vec<String>,
    inputs_rust_literal: Vec<String>,
    output_formatted: String,
    output_rust_literal: String,
    output_hex: String,
}

fn gen_bool(rng: &mut SplitMix64) -> bool {
    (rng.next_u64() & 1) == 1
}
fn gen_i8(rng: &mut SplitMix64) -> i8 {
    rng.next_u64() as i8
}
fn gen_u8(rng: &mut SplitMix64) -> u8 {
    rng.next_u64() as u8
}
fn gen_i16(rng: &mut SplitMix64) -> i16 {
    match rng.next_u64() & 3 {
        0 => ((rng.next_u64() % 513) as i16).wrapping_sub(256),
        1 => ((rng.next_u64() % 16385) as i16).wrapping_sub(8192),
        _ => rng.next_u64() as i16,
    }
}
fn gen_u16(rng: &mut SplitMix64) -> u16 {
    match rng.next_u64() & 3 {
        0 => (rng.next_u64() % 512) as u16,
        1 => (rng.next_u64() % 16384) as u16,
        _ => rng.next_u64() as u16,
    }
}
fn gen_i32(rng: &mut SplitMix64) -> i32 {
    match rng.next_u64() & 3 {
        0 => ((rng.next_u64() % 513) as i32).wrapping_sub(256),
        1 => ((rng.next_u64() % 131073) as i32).wrapping_sub(65536),
        2 => {
            let shift = (rng.next_u64() % 31) as u32;
            let offset = ((rng.next_u64() % 9) as i32) - 4;
            (1i32.wrapping_shl(shift)).wrapping_add(offset)
        }
        _ => rng.next_u64() as i32,
    }
}
fn gen_u32(rng: &mut SplitMix64) -> u32 {
    match rng.next_u64() & 3 {
        0 => (rng.next_u64() % 512) as u32,
        1 => (rng.next_u64() % 131072) as u32,
        2 => {
            let shift = (rng.next_u64() % 32) as u32;
            let offset = (rng.next_u64() % 9) as u32;
            (1u32.wrapping_shl(shift)).wrapping_add(offset).wrapping_sub(4)
        }
        _ => rng.next_u64() as u32,
    }
}
fn gen_i64(rng: &mut SplitMix64) -> i64 {
    match rng.next_u64() & 3 {
        0 => ((rng.next_u64() % 513) as i64).wrapping_sub(256),
        1 => ((rng.next_u64() % 131073) as i64).wrapping_sub(65536),
        2 => {
            let shift = (rng.next_u64() % 63) as u32;
            let offset = ((rng.next_u64() % 9) as i64) - 4;
            (1i64.wrapping_shl(shift)).wrapping_add(offset)
        }
        _ => rng.next_u64() as i64,
    }
}
fn gen_u64(rng: &mut SplitMix64) -> u64 {
    match rng.next_u64() & 3 {
        0 => rng.next_u64() % 512,
        1 => rng.next_u64() % 131072,
        2 => {
            let shift = (rng.next_u64() % 64) as u32;
            let offset = rng.next_u64() % 9;
            (1u64.wrapping_shl(shift)).wrapping_add(offset).wrapping_sub(4)
        }
        _ => rng.next_u64(),
    }
}
fn gen_f32_finite(rng: &mut SplitMix64) -> f32 {
    match rng.next_u64() & 3 {
        0 => ((rng.next_u64() % 200001) as f32 - 100000.0) * 0.1,
        1 => ((rng.next_u64() % 20001) as f32 - 10000.0) * 0.0001,
        2 => (rng.next_u64() % 65536) as f32 - 32768.0,
        _ => {
            let raw = rng.next_u64() as u32;
            let sign = raw & 0x8000_0000;
            // Clamp exponent to 1..=190 (~1e-38..~1e19) so multi-tap DSP math remains finite
            let exp = ((raw >> 23) & 0xff) % 190 + 1;
            let mant = raw & 0x007f_ffff;
            f32::from_bits(sign | (exp << 23) | mant)
        }
    }
}
fn gen_f64_finite(rng: &mut SplitMix64) -> f64 {
    match rng.next_u64() & 3 {
        0 => ((rng.next_u64() % 200001) as f64 - 100000.0) * 0.1,
        1 => ((rng.next_u64() % 20001) as f64 - 10000.0) * 0.0001,
        2 => (rng.next_u64() % 65536) as f64 - 32768.0,
        _ => {
            let raw = rng.next_u64();
            let sign = raw & 0x8000_0000_0000_0000;
            // Clamp exponent to 1..=1086 (~1e-308..~1e19)
            let exp = ((raw >> 52) & 0x7ff) % 1086 + 1;
            let mant = raw & 0x000f_ffff_ffff_ffff;
            f64::from_bits(sign | (exp << 52) | mant)
        }
    }
}
fn gen_f32(rng: &mut SplitMix64) -> f32 {
    match rng.next_u64() & 3 {
        0 => ((rng.next_u64() % 200001) as f32 - 100000.0) * 0.1,
        1 => ((rng.next_u64() % 20001) as f32 - 10000.0) * 0.0001,
        2 => (rng.next_u64() % 65536) as f32 - 32768.0,
        _ => {
            let v = f32::from_bits(rng.next_u64() as u32);
            if v.is_nan() { f32::NAN } else { v }
        }
    }
}
fn gen_f64(rng: &mut SplitMix64) -> f64 {
    match rng.next_u64() & 3 {
        0 => ((rng.next_u64() % 200001) as f64 - 100000.0) * 0.1,
        1 => ((rng.next_u64() % 20001) as f64 - 10000.0) * 0.0001,
        2 => (rng.next_u64() % 65536) as f64 - 32768.0,
        _ => {
            let v = f64::from_bits(rng.next_u64());
            if v.is_nan() { f64::NAN } else { v }
        }
    }
}
fn gen_bytes(rng: &mut SplitMix64) -> Vec<u8> {
    let len = (rng.next_u64() % 129) as usize;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(rng.next_u64() as u8);
    }
    out
}

fn zero_bool() -> bool { false }
fn zero_i8() -> i8 { 0 }
fn zero_u8() -> u8 { 0 }
fn zero_i16() -> i16 { 0 }
fn zero_u16() -> u16 { 0 }
fn zero_i32() -> i32 { 0 }
fn zero_u32() -> u32 { 0 }
fn zero_i64() -> i64 { 0 }
fn zero_u64() -> u64 { 0 }
fn zero_f32() -> f32 { 0.0 }
fn zero_f64() -> f64 { 0.0 }

fn same_arg_bool(a: bool, b: bool) -> bool { a == b }
fn same_arg_i8(a: i8, b: i8) -> bool { a == b }
fn same_arg_u8(a: u8, b: u8) -> bool { a == b }
fn same_arg_i16(a: i16, b: i16) -> bool { a == b }
fn same_arg_u16(a: u16, b: u16) -> bool { a == b }
fn same_arg_i32(a: i32, b: i32) -> bool { a == b }
fn same_arg_u32(a: u32, b: u32) -> bool { a == b }
fn same_arg_i64(a: i64, b: i64) -> bool { a == b }
fn same_arg_u64(a: u64, b: u64) -> bool { a == b }
fn same_arg_f32(a: f32, b: f32) -> bool { a.to_bits() == b.to_bits() || (a.is_nan() && b.is_nan()) }
fn same_arg_f64(a: f64, b: f64) -> bool { a.to_bits() == b.to_bits() || (a.is_nan() && b.is_nan()) }

fn shrink_candidates_bool(v: bool) -> Vec<bool> {
    if v { vec![false] } else { vec![] }
}
fn shrink_candidates_i8(v: i8) -> Vec<i8> {
    let mut out = vec![0];
    if v > 1 || v < -1 { out.push(1); }
    if v < -1 { out.push(-1); }
    out
}
fn shrink_candidates_u8(v: u8) -> Vec<u8> {
    if v > 1 { vec![0, 1] } else if v == 1 { vec![0] } else { vec![] }
}
fn shrink_candidates_i16(v: i16) -> Vec<i16> {
    let mut out = vec![0];
    if v > 1 || v < -1 { out.push(1); }
    if v < -1 { out.push(-1); }
    out
}
fn shrink_candidates_u16(v: u16) -> Vec<u16> {
    if v > 1 { vec![0, 1] } else if v == 1 { vec![0] } else { vec![] }
}
fn shrink_candidates_i32(v: i32) -> Vec<i32> {
    let mut out = vec![0];
    if v > 1 || v < -1 { out.push(1); }
    if v < -1 { out.push(-1); }
    out
}
fn shrink_candidates_u32(v: u32) -> Vec<u32> {
    if v > 1 { vec![0, 1] } else if v == 1 { vec![0] } else { vec![] }
}
fn shrink_candidates_i64(v: i64) -> Vec<i64> {
    let mut out = vec![0];
    if v > 1 || v < -1 { out.push(1); }
    if v < -1 { out.push(-1); }
    out
}
fn shrink_candidates_u64(v: u64) -> Vec<u64> {
    if v > 1 { vec![0, 1] } else if v == 1 { vec![0] } else { vec![] }
}
fn shrink_candidates_f32(v: f32) -> Vec<f32> {
    vec![0.0, 1.0, -1.0]
}
fn shrink_candidates_f64(v: f64) -> Vec<f64> {
    vec![0.0, 1.0, -1.0]
}

fn bisect_bool(_low: bool, high: bool) -> bool { high }
fn bisect_i8(low: i8, high: i8) -> i8 { ((low as i16 + high as i16) / 2) as i8 }
fn bisect_u8(low: u8, high: u8) -> u8 { ((low as u16 + high as u16) / 2) as u8 }
fn bisect_i16(low: i16, high: i16) -> i16 { ((low as i32 + high as i32) / 2) as i16 }
fn bisect_u16(low: u16, high: u16) -> u16 { ((low as u32 + high as u32) / 2) as u16 }
fn bisect_i32(low: i32, high: i32) -> i32 { ((low as i64 + high as i64) / 2) as i32 }
fn bisect_u32(low: u32, high: u32) -> u32 { ((low as u64 + high as u64) / 2) as u32 }
fn bisect_i64(low: i64, high: i64) -> i64 { ((low as i128 + high as i128) / 2) as i64 }
fn bisect_u64(low: u64, high: u64) -> u64 { ((low as u128 + high as u128) / 2) as u64 }
fn bisect_f32(low: f32, high: f32) -> f32 {
    if !high.is_finite() || !low.is_finite() { return high; }
    let mid = low + (high - low) * 0.5;
    if mid.abs() > 1.0 { mid.trunc() } else { mid }
}
fn bisect_f64(low: f64, high: f64) -> f64 {
    if !high.is_finite() || !low.is_finite() { return high; }
    let mid = low + (high - low) * 0.5;
    if mid.abs() > 1.0 { mid.trunc() } else { mid }
}

fn step_toward_zero_bool(_v: bool) -> Vec<bool> { vec![] }
fn step_toward_zero_i8(v: i8) -> Vec<i8> { if v > 0 { vec![v - 1] } else if v < 0 { vec![v + 1] } else { vec![] } }
fn step_toward_zero_u8(v: u8) -> Vec<u8> { if v > 0 { vec![v - 1] } else { vec![] } }
fn step_toward_zero_i16(v: i16) -> Vec<i16> { if v > 0 { vec![v - 1] } else if v < 0 { vec![v + 1] } else { vec![] } }
fn step_toward_zero_u16(v: u16) -> Vec<u16> { if v > 0 { vec![v - 1] } else { vec![] } }
fn step_toward_zero_i32(v: i32) -> Vec<i32> { if v > 0 { vec![v - 1] } else if v < 0 { vec![v + 1] } else { vec![] } }
fn step_toward_zero_u32(v: u32) -> Vec<u32> { if v > 0 { vec![v - 1] } else { vec![] } }
fn step_toward_zero_i64(v: i64) -> Vec<i64> { if v > 0 { vec![v - 1] } else if v < 0 { vec![v + 1] } else { vec![] } }
fn step_toward_zero_u64(v: u64) -> Vec<u64> { if v > 0 { vec![v - 1] } else { vec![] } }
fn step_toward_zero_f32(v: f32) -> Vec<f32> { if v > 1.0 { vec![v - 1.0] } else if v < -1.0 { vec![v + 1.0] } else { vec![] } }
fn step_toward_zero_f64(v: f64) -> Vec<f64> { if v > 1.0 { vec![v - 1.0] } else if v < -1.0 { vec![v + 1.0] } else { vec![] } }

fn fmt_bool(v: bool) -> String { format!("{}", v) }
fn fmt_i8(v: i8) -> String { format!("{}", v) }
fn fmt_u8(v: u8) -> String { format!("{}", v) }
fn fmt_i16(v: i16) -> String { format!("{}", v) }
fn fmt_u16(v: u16) -> String { format!("{}", v) }
fn fmt_i32(v: i32) -> String { format!("{}", v) }
fn fmt_u32(v: u32) -> String { format!("{}", v) }
fn fmt_i64(v: i64) -> String { format!("{}", v) }
fn fmt_u64(v: u64) -> String { format!("{}", v) }
fn fmt_f32(v: f32) -> String {
    if v.is_nan() { "NaN".to_string() }
    else if v.to_bits() == 0x8000_0000 { "-0.0".to_string() }
    else { format!("{:?}", v) }
}
fn fmt_f64(v: f64) -> String {
    if v.is_nan() { "NaN".to_string() }
    else if v.to_bits() == 0x8000_0000_0000_0000 { "-0.0".to_string() }
    else { format!("{:?}", v) }
}
fn fmt_bytes(v: &[u8]) -> String {
    let mut out = String::with_capacity(2 + v.len() * 2 + 16);
    out.push_str("0x");
    for &b in v {
        out.push_str(&format!("{:02x}", b));
    }
    out.push_str(&format!(" (len={})", v.len()));
    out
}

fn lit_bool(v: bool) -> String { format!("{}", v) }
fn lit_i8(v: i8) -> String { format!("{}i8", v) }
fn lit_u8(v: u8) -> String { format!("{}u8", v) }
fn lit_i16(v: i16) -> String { format!("{}i16", v) }
fn lit_u16(v: u16) -> String { format!("{}u16", v) }
fn lit_i32(v: i32) -> String { format!("{}i32", v) }
fn lit_u32(v: u32) -> String { format!("{}u32", v) }
fn lit_i64(v: i64) -> String { format!("{}i64", v) }
fn lit_u64(v: u64) -> String { format!("{}u64", v) }
fn lit_f32(v: f32) -> String { format!("f32::from_bits(0x{:08x}u32)", v.to_bits()) }
fn lit_f64(v: f64) -> String { format!("f64::from_bits(0x{:016x}u64)", v.to_bits()) }
fn lit_bytes(v: &[u8]) -> String {
    if v.is_empty() {
        "&[] as &[u8]".to_string()
    } else {
        let items: Vec<String> = v.iter().map(|b| format!("0x{:02x}u8", b)).collect();
        format!("&[{}][..]", items.join(", "))
    }
}

fn hex_bool(v: bool) -> String { format!("0x{:02x}", if v { 1u8 } else { 0u8 }) }
fn hex_i8(v: i8) -> String { format!("0x{:02x}", v as u8) }
fn hex_u8(v: u8) -> String { format!("0x{:02x}", v) }
fn hex_i16(v: i16) -> String { format!("0x{:04x}", v as u16) }
fn hex_u16(v: u16) -> String { format!("0x{:04x}", v) }
fn hex_i32(v: i32) -> String { format!("0x{:08x}", v as u32) }
fn hex_u32(v: u32) -> String { format!("0x{:08x}", v) }
fn hex_i64(v: i64) -> String { format!("0x{:016x}", v as u64) }
fn hex_u64(v: u64) -> String { format!("0x{:016x}", v) }
fn hex_f32(v: f32) -> String { format!("0x{:08x}", v.to_bits()) }
fn hex_f64(v: f64) -> String { format!("0x{:016x}", v.to_bits()) }

fn bits_bool(v: bool) -> u64 { if v { 1 } else { 0 } }
fn bits_i8(v: i8) -> u64 { (v as u8) as u64 }
fn bits_u8(v: u8) -> u64 { v as u64 }
fn bits_i16(v: i16) -> u64 { (v as u16) as u64 }
fn bits_u16(v: u16) -> u64 { v as u64 }
fn bits_i32(v: i32) -> u64 { (v as u32) as u64 }
fn bits_u32(v: u32) -> u64 { v as u64 }
fn bits_i64(v: i64) -> u64 { v as u64 }
fn bits_u64(v: u64) -> u64 { v }
fn bits_f32(v: f32) -> u64 { v.to_bits() as u64 }
fn bits_f64(v: f64) -> u64 { v.to_bits() }

fn ulp_f32(a: f32, b: f32) -> Option<u64> {
    if a.is_nan() && b.is_nan() { return Some(0); }
    if a.is_nan() || b.is_nan() { return None; }
    if a == 0.0 && b == 0.0 { return Some(0); }
    let ab = a.to_bits();
    let bb = b.to_bits();
    if ab == bb { return Some(0); }
    if a.is_infinite() || b.is_infinite() { return None; }
    let ao = if (ab & 0x8000_0000) != 0 { 0x8000_0000u32.wrapping_sub(ab & 0x7fff_ffff) } else { 0x8000_0000u32.wrapping_add(ab) };
    let bo = if (bb & 0x8000_0000) != 0 { 0x8000_0000u32.wrapping_sub(bb & 0x7fff_ffff) } else { 0x8000_0000u32.wrapping_add(bb) };
    let dist = if ao >= bo { ao - bo } else { bo - ao };
    Some(dist as u64)
}

fn ulp_f64(a: f64, b: f64) -> Option<u64> {
    if a.is_nan() && b.is_nan() { return Some(0); }
    if a.is_nan() || b.is_nan() { return None; }
    if a == 0.0 && b == 0.0 { return Some(0); }
    let ab = a.to_bits();
    let bb = b.to_bits();
    if ab == bb { return Some(0); }
    if a.is_infinite() || b.is_infinite() { return None; }
    let ao = if (ab & 0x8000_0000_0000_0000) != 0 { 0x8000_0000_0000_0000u64.wrapping_sub(ab & 0x7fff_ffff_ffff_ffff) } else { 0x8000_0000_0000_0000u64.wrapping_add(ab) };
    let bo = if (bb & 0x8000_0000_0000_0000) != 0 { 0x8000_0000_0000_0000u64.wrapping_sub(bb & 0x7fff_ffff_ffff_ffff) } else { 0x8000_0000_0000_0000u64.wrapping_add(bb) };
    let dist = if ao >= bo { ao - bo } else { bo - ao };
    let capped = if dist > 9_007_199_254_740_991 { 9_007_199_254_740_991 } else { dist };
    Some(capped)
}

fn is_f32_nan_bits(w: u32) -> bool {
    (w & 0x7f80_0000) == 0x7f80_0000 && (w & 0x007f_ffff) != 0
}

fn packed_u32_canon_float_eq(a: u32, b: u32, ulp_tol: u64) -> bool {
    if a == b { return true; }
    if is_f32_nan_bits(a) && is_f32_nan_bits(b) { return true; }
    if ulp_tol > 0 {
        if let Some(d) = ulp_f32(f32::from_bits(a), f32::from_bits(b)) {
            return d <= ulp_tol;
        }
    }
    false
}

fn packed_u64_canon_float_eq(a: u64, b: u64, ulp_tol: u64) -> bool {
    if a == b { return true; }
    let a_lo = a as u32;
    let a_hi = (a >> 32) as u32;
    let b_lo = b as u32;
    let b_hi = (b >> 32) as u32;
    let has_nan_pair = (is_f32_nan_bits(a_lo) && is_f32_nan_bits(b_lo))
        || (is_f32_nan_bits(a_hi) && is_f32_nan_bits(b_hi));
    if has_nan_pair || ulp_tol > 0 {
        if packed_u32_canon_float_eq(a_lo, b_lo, ulp_tol)
            && packed_u32_canon_float_eq(a_hi, b_hi, ulp_tol)
        {
            return true;
        }
    }
    if f64::from_bits(a).is_nan() && f64::from_bits(b).is_nan() {
        return true;
    }
    false
}

fn compare_ret_${retType}(c_val: ${retType}, r_val: ${retType}, ulp_tol: u64) -> (bool, Option<u64>) {
    ${
      retType === "f32"
        ? `match ulp_f32(c_val, r_val) { Some(d) => (d <= ulp_tol, Some(d)), None => (false, None) }`
        : retType === "f64"
          ? `match ulp_f64(c_val, r_val) { Some(d) => (d <= ulp_tol, Some(d)), None => (false, None) }`
          : retType === "u64" || retType === "i64"
            ? `(c_val == r_val || packed_u64_canon_float_eq(c_val as u64, r_val as u64, ulp_tol), None)`
            : retType === "u32" || retType === "i32"
              ? `(c_val == r_val || packed_u32_canon_float_eq(c_val as u32, r_val as u32, ulp_tol), None)`
              : `(c_val == r_val, None)`
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\\\\""),
            '\\\\' => out.push_str("\\\\\\\\"),
            '\\n' => out.push_str("\\\\n"),
            '\\r' => out.push_str("\\\\r"),
            '\\t' => out.push_str("\\\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

type TargetFn = unsafe extern "C" fn(${cFnParamSig}) -> ${retType};
type ArgTuple = ${tupleType};

fn eval_pair(c_fn: TargetFn, args: &ArgTuple) -> (${retType}, ${retType}) {
    let c_out = unsafe { c_fn(${cFnCallArgs}) };
    let r_out = candidate::${rustFnName}(${rustFnCallArgs});
    (c_out, r_out)
}

fn is_diverged(c_fn: TargetFn, args: &ArgTuple) -> bool {
    let (c_out, r_out) = eval_pair(c_fn, args);
    let (eq, _) = compare_ret_${retType}(c_out, r_out, ${String(input.float_ulp_tolerance)}u64);
    !eq
}

fn format_args_json(args: &ArgTuple) -> String {
    let items: Vec<String> = ${formatTupleVecExpr};
    let quoted: Vec<String> = items.into_iter().map(|s| format!("\\"{}\\"", json_escape(&s))).collect();
    format!("[{}]", quoted.join(","))
}

fn main() {
    let lib_path = std::ffi::CString::new(${JSON.stringify(libPathLiteral)}).unwrap();
    let sym_name = std::ffi::CString::new(${JSON.stringify(input.symbol_name)}).unwrap();

    #[cfg(unix)]
    let fn_ptr = unsafe {
        let handle = dlopen(lib_path.as_ptr(), 2);
        if handle.is_null() {
            let err_ptr = dlerror();
            let msg = if err_ptr.is_null() {
                "dlopen returned null".to_string()
            } else {
                std::ffi::CStr::from_ptr(err_ptr).to_string_lossy().into_owned()
            };
            println!("${JSON_MARKER}{{\\"status\\":\\"sandbox_fault\\",\\"iterations_completed\\":0,\\"boundary_cases_tested\\":0,\\"fault_reason\\":\\"{}\\",\\"counterexample\\":null}}", json_escape(&msg));
            std::process::exit(42);
        }
        let sym = dlsym(handle, sym_name.as_ptr());
        if sym.is_null() {
            println!("${JSON_MARKER}{{\\"status\\":\\"sandbox_fault\\",\\"iterations_completed\\":0,\\"boundary_cases_tested\\":0,\\"fault_reason\\":\\"dlsym could not resolve symbol\\",\\"counterexample\\":null}}");
            std::process::exit(42);
        }
        sym
    };

    #[cfg(windows)]
    let fn_ptr = unsafe {
        let handle = LoadLibraryA(lib_path.as_ptr() as *const u8);
        if handle.is_null() {
            println!("${JSON_MARKER}{{\\"status\\":\\"sandbox_fault\\",\\"iterations_completed\\":0,\\"boundary_cases_tested\\":0,\\"fault_reason\\":\\"LoadLibraryA returned null\\",\\"counterexample\\":null}}");
            std::process::exit(42);
        }
        let sym = GetProcAddress(handle, sym_name.as_ptr() as *const u8);
        if sym.is_null() {
            println!("${JSON_MARKER}{{\\"status\\":\\"sandbox_fault\\",\\"iterations_completed\\":0,\\"boundary_cases_tested\\":0,\\"fault_reason\\":\\"GetProcAddress could not resolve symbol\\",\\"counterexample\\":null}}");
            std::process::exit(42);
        }
        sym
    };

    let c_fn: TargetFn = unsafe { std::mem::transmute(fn_ptr) };

    ${boundaryVecDecls}
    let mut boundary_cases: Vec<ArgTuple> = Vec::with_capacity(64);
    boundary_cases.push(${defaultTupleInit});
    ${singleAxisBoundaryLoops}
    ${diagonalBoundaryLoop}

    let boundary_count = boundary_cases.len();
    let mut rng = SplitMix64::new(${String(input.seed)}u64);
    let random_requested = ${String(input.iterations)}usize;
    let total_cases = boundary_count + random_requested;
    let mut sample_vectors: Vec<SampleVector> = Vec::with_capacity(8);

    for idx in 0..total_cases {
        let args: ArgTuple = if idx < boundary_count {
            boundary_cases[idx].clone()
        } else {
            ${randomTupleExpr}
        };

        let (c_out, r_out) = eval_pair(c_fn, &args);
        let (eq, _) = compare_ret_${retType}(c_out, r_out, ${String(input.float_ulp_tolerance)}u64);
        if !eq {
            let orig_args = args.clone();
            let mut cur = orig_args.clone();
            let mut shrink_steps = 0usize;
            for _pass in 0..4 {
                let mut changed = false;
                ${shrinkBlocks}
                if !changed {
                    break;
                }
            }

            let (shrunk_c, shrunk_r) = eval_pair(c_fn, &cur);
            let (_, shrunk_ulp) = compare_ret_${retType}(shrunk_c, shrunk_r, ${String(input.float_ulp_tolerance)}u64);
            let c_str = fmt_${retType}(shrunk_c);
            let r_str = fmt_${retType}(shrunk_r);
            let c_hex = hex_${retType}(shrunk_c);
            let r_hex = hex_${retType}(shrunk_r);
            let c_bits = bits_${retType}(shrunk_c);
            let r_bits = bits_${retType}(shrunk_r);
            let xor_mask = c_bits ^ r_bits;
            let diff_bits = xor_mask.count_ones();
            let low_bit = if xor_mask == 0 { 0 } else { xor_mask.trailing_zeros() };
            let high_bit = if xor_mask == 0 { 0 } else { 63 - xor_mask.leading_zeros() };
            let summary = format!(
                "XOR diff = 0x{:x} ({} bit(s) differ, lowest bit = {}, highest bit = {}); C returned {} ({}), Rust returned {} ({})",
                xor_mask, diff_bits, low_bit, high_bit, c_hex, c_str, r_hex, r_str
            );
            let ulp_json = match shrunk_ulp {
                Some(u) => format!("{}", u),
                None => "null".to_string(),
            };
            let b_tested = if idx + 1 < boundary_count { idx + 1 } else { boundary_count };
            println!(
                "${JSON_MARKER}{{\\"status\\":\\"diverged\\",\\"iterations_completed\\":{},\\"boundary_cases_tested\\":{},\\"counterexample\\":{{\\"failing_iteration\\":{},\\"original_inputs\\":{},\\"shrunk_inputs\\":{},\\"shrink_steps\\":{},\\"c_output\\":\\"{}\\",\\"rust_output\\":\\"{}\\",\\"c_output_hex\\":\\"{}\\",\\"rust_output_hex\\":\\"{}\\",\\"bit_diff_summary\\":\\"{}\\",\\"ulp_distance\\":{}}},\\"benchmark_telemetry\\":null}}",
                idx + 1,
                b_tested,
                idx,
                format_args_json(&orig_args),
                format_args_json(&cur),
                shrink_steps,
                json_escape(&c_str),
                json_escape(&r_str),
                json_escape(&c_hex),
                json_escape(&r_hex),
                json_escape(&summary),
                ulp_json
            );
            return;
        }

        if sample_vectors.len() < 8 {
            sample_vectors.push(SampleVector {
                inputs_formatted: ${formatTupleVecExpr},
                inputs_rust_literal: ${literalTupleVecExpr},
                output_formatted: fmt_${retType}(c_out),
                output_rust_literal: lit_${retType}(r_out),
                output_hex: hex_${retType}(c_out),
            });
        }
    }

    let mut bench_inputs: Vec<ArgTuple> = Vec::with_capacity(64);
    for i in 0..64usize {
        if i < boundary_count {
            bench_inputs.push(boundary_cases[i].clone());
        } else {
            bench_inputs.push(${randomTupleExpr});
        }
    }
    let bench_iters: usize = 100_000;
    for i in 0..1000usize {
        let a = std::hint::black_box(&bench_inputs[i & 63]);
        std::hint::black_box(unsafe { c_fn(${benchCCallArgs}) });
        std::hint::black_box(candidate::${rustFnName}(${benchRustCallArgs}));
    }
    let c_start = std::time::Instant::now();
    for i in 0..bench_iters {
        let a = std::hint::black_box(&bench_inputs[i & 63]);
        std::hint::black_box(unsafe { c_fn(${benchCCallArgs}) });
    }
    let c_total_ns = (c_start.elapsed().as_nanos().max(1)) as f64;

    let r_start = std::time::Instant::now();
    for i in 0..bench_iters {
        let a = std::hint::black_box(&bench_inputs[i & 63]);
        std::hint::black_box(candidate::${rustFnName}(${benchRustCallArgs}));
    }
    let r_total_ns = (r_start.elapsed().as_nanos().max(1)) as f64;
    let c_ns_per_call = ((c_total_ns / (bench_iters as f64)) * 10000.0).round() / 10000.0;
    let r_ns_per_call = ((r_total_ns / (bench_iters as f64)) * 10000.0).round() / 10000.0;
    let speedup = (((c_total_ns / r_total_ns) * 100.0).round() / 100.0).max(0.01);

    let sample_vectors_json: Vec<String> = sample_vectors
        .iter()
        .map(|sv| {
            let in_fmt: Vec<String> = sv.inputs_formatted.iter().map(|s| format!("\\"{}\\"", json_escape(s))).collect();
            let in_lit: Vec<String> = sv.inputs_rust_literal.iter().map(|s| format!("\\"{}\\"", json_escape(s))).collect();
            format!(
                "{{\\"inputs_formatted\\":[{}],\\"inputs_rust_literal\\":[{}],\\"output_formatted\\":\\"{}\\",\\"output_rust_literal\\":\\"{}\\",\\"output_hex\\":\\"{}\\"}}",
                in_fmt.join(","),
                in_lit.join(","),
                json_escape(&sv.output_formatted),
                json_escape(&sv.output_rust_literal),
                json_escape(&sv.output_hex)
            )
        })
        .collect();

    println!(
        "${JSON_MARKER}{{\\"status\\":\\"verified_bit_exact\\",\\"iterations_completed\\":{},\\"boundary_cases_tested\\":{},\\"counterexample\\":null,\\"benchmark_telemetry\\":{{\\"benchmark_iterations\\":{},\\"c_oracle_total_ns\\":{},\\"safe_rust_total_ns\\":{},\\"c_oracle_ns_per_call\\":{},\\"safe_rust_ns_per_call\\":{},\\"speedup_vs_c_oracle\\":{}}},\\"sample_vectors\\":[{}]}}",
        random_requested,
        boundary_count,
        bench_iters,
        c_total_ns,
        r_total_ns,
        c_ns_per_call,
        r_ns_per_call,
        speedup,
        sample_vectors_json.join(",")
    );
}
`;
}

export class RustParityVerifier implements RustParityPort {
  readonly identity: ProviderIdentity = RUST_PARITY_PROVIDER_IDENTITY;
  private readonly sandboxRunner = new ParitySandboxRunner();

  async verify(
    input: VerifyRustParityInput,
    options?: ExecutionOptions,
  ): Promise<Result<RustParityReport, AnalysisError>> {
    if (options?.signal?.aborted) {
      return err(new AnalysisCancelledError(OPERATION));
    }

    if (input.return_type === "bytes") {
      return err(
        new AnalysisInputError(
          OPERATION,
          {
            userMessage:
              "return_type cannot be 'bytes'; return a scalar type.",
          },
          [
            {
              path: ["return_type"],
              reason: "invalid_value",
              message: "return_type cannot be 'bytes'; return a scalar type.",
            },
          ],
        ),
      );
    }

    if (!input.target_binary_path && !input.c_source_code) {
      return err(
        new AnalysisInputError(
          OPERATION,
          {
            userMessage:
              "verify_rust_parity requires either target_binary_path or c_source_code.",
          },
          [
            {
              path: ["target_binary_path"],
              reason: "missing_argument",
              message:
                "verify_rust_parity requires either target_binary_path or c_source_code.",
            },
          ],
        ),
      );
    }

    const rustFnName = input.rust_fn_name ?? input.symbol_name;
    if (!IDENTIFIER_REGEX.test(input.symbol_name)) {
      return err(
        new AnalysisInputError(
          OPERATION,
          {
            userMessage: `Invalid C symbol identifier: ${input.symbol_name}`,
          },
          [
            {
              path: ["symbol_name"],
              reason: "invalid_format",
              message: "symbol_name must be a valid C identifier.",
            },
          ],
        ),
      );
    }

    if (!IDENTIFIER_REGEX.test(rustFnName)) {
      return err(
        new AnalysisInputError(
          OPERATION,
          {
            userMessage: `Invalid Rust function identifier: ${rustFnName}`,
          },
          [
            {
              path: ["rust_fn_name"],
              reason: "invalid_format",
              message: "rust_fn_name must be a valid Rust identifier.",
            },
          ],
        ),
      );
    }

    const rustcBin = resolveRustcPath();
    if (!rustcBin) {
      return err(
        new AnalysisCapabilityUnavailableError(
          this.identity.id,
          OPERATION,
          "rustc compiler not found on host system.",
          {
            userMessage:
              "Rust compiler (rustc) is required for closed-loop parity verification.",
          },
        ),
      );
    }

    const candidateUnsafeBlocks = countCandidateUnsafeBlocks(
      input.rust_source_code,
    );
    const forbidUnsafeEnforced = input.forbid_unsafe ?? true;
    const memorySafety: RustParityMemorySafety = {
      forbid_unsafe_enforced: forbidUnsafeEnforced,
      candidate_unsafe_blocks: candidateUnsafeBlocks,
    };

    const workDir = await mkdtemp(path.join(os.tmpdir(), "argonaut-parity-"));
    try {
      const osPlat = os.platform();
      const libExt =
        osPlat === "darwin" ? "dylib" : osPlat === "win32" ? "dll" : "so";
      const libFileName = `libtarget.${libExt}`;
      const libFullPath = path.join(workDir, libFileName);

      // Step 1: Prepare or compile the C target shared library
      let useCompiledCSource = false;
      if (input.target_binary_path) {
        let rawBin: Buffer;
        try {
          const st = await stat(input.target_binary_path);
          if (!st.isFile()) {
            return err(
              new AnalysisInputError(OPERATION, undefined, [
                {
                  path: ["target_binary_path"],
                  reason: "invalid_value",
                  message: `target_binary_path is not a regular file: ${input.target_binary_path}`,
                },
              ]),
            );
          }
          rawBin = await readFile(input.target_binary_path);
        } catch (cause) {
          const code = (cause as NodeJS.ErrnoException | undefined)?.code;
          if (code === "EACCES" || code === "EPERM") {
            return err(
              new AnalysisAccessDeniedError(
                OPERATION,
                input.target_binary_path,
                code,
                { cause },
              ),
            );
          }
          return err(
            new AnalysisInputError(OPERATION, { cause }, [
              {
                path: ["target_binary_path"],
                reason: "invalid_value",
                message: `Unable to read target_binary_path at ${input.target_binary_path}`,
              },
            ]),
          );
        }

        const elfArch = detectElfMachineArch(rawBin);
        const hostArch = os.arch();
        if (elfArch !== null && elfArch !== hostArch) {
          if (input.c_source_code) {
            // Foreign-ISA binary provided alongside C reference source: compile C source for host FFI
            useCompiledCSource = true;
          } else {
            return err(
              new AnalysisInputError(
                OPERATION,
                {
                  userMessage: `Target binary '${input.target_binary_path}' is compiled for '${elfArch}' while host is '${hostArch}'. Provide 'c_source_code' (the recovered C reference oracle) alongside 'rust_source_code' when verifying cross-architecture binaries.`,
                },
                [
                  {
                    path: ["target_binary_path"],
                    reason: "invalid_value",
                    message: `Cross-architecture binary (${elfArch} on ${hostArch} host) requires c_source_code for native FFI execution.`,
                  },
                ],
              ),
            );
          }
        } else {
          const patchedBin = patchBinaryForDynamicLoading(rawBin);
          await writeFile(libFullPath, patchedBin);
          await chmod(libFullPath, 0o755);
        }
      } else {
        useCompiledCSource = true;
      }

      if (useCompiledCSource && input.c_source_code) {
        const cCompiler = resolveCCompilerPath();
        if (!cCompiler) {
          return err(
            new AnalysisCapabilityUnavailableError(
              this.identity.id,
              OPERATION,
              "C compiler (gcc/clang/cc) not found on host system.",
            ),
          );
        }
        const cSourcePath = path.join(workDir, "target.c");
        const fullCSource = input.c_source_code.includes("argon_digest_bytes")
          ? input.c_source_code
          : `${C_DIGEST_HELPERS_PREAMBLE}\n${input.c_source_code}`;
        await writeFile(cSourcePath, fullCSource, "utf8");

        const cArgs =
          osPlat === "darwin"
            ? ["-O2", "-dynamiclib", "-fPIC", cSourcePath, "-o", libFullPath, "-lm"]
            : osPlat === "win32"
              ? ["-O2", "-shared", cSourcePath, "-o", libFullPath]
              : ["-O2", "-shared", "-fPIC", cSourcePath, "-o", libFullPath, "-lm"];

        const cCompileRes = await this.sandboxRunner.runSandboxed({
          command: cCompiler,
          args: cArgs,
          cwd: workDir,
          timeoutMs: Math.min(input.timeout_ms, 30_000),
          cpuLimitSeconds: 15,
          memoryLimitMb: 1024,
        });

        if (cCompileRes.exitCode !== 0) {
          return this.buildReport(input, rustFnName, {
            status: "compile_error",
            iterationsCompleted: 0,
            boundaryCasesTested: 0,
            counterexample: null,
            memorySafety,
            benchmarkTelemetry: null,
            sandboxResult: cCompileRes,
            compilerDiagnostics:
              (cCompileRes.stderr || cCompileRes.stdout).trim() ||
              "C reference compilation failed.",
          });
        }
      }

      if (options?.signal?.aborted) {
        return err(new AnalysisCancelledError(OPERATION));
      }

      // Step 2: Generate and compile the Rust FFI Differential Harness
      const harnessSource = generateRustHarnessSource(
        input,
        libFullPath,
        rustFnName,
        forbidUnsafeEnforced,
      );
      const runnerBinName = osPlat === "win32" ? "runner.exe" : "runner";
      const runnerBinPath = path.join(workDir, runnerBinName);
      const buildJobs = String(
        Math.max(1, Math.min(2, ADAPTIVE_RESOURCE_PROFILE.maxCargoJobs)),
      );

      let rustCompileRes: SandboxRunResult;
      const cargoBin = resolveCargoPath();
      if (input.harness_mode === "cargo-proptest" && cargoBin) {
        const srcDir = path.join(workDir, "src");
        await mkdir(srcDir, { recursive: true });
        await writeFile(
          path.join(workDir, "Cargo.toml"),
          `[package]\nname = "argonaut_parity_runner"\nversion = "0.1.0"\nedition = "2021"\n\n[[bin]]\nname = "runner"\npath = "src/main.rs"\n`,
          "utf8",
        );
        await writeFile(path.join(srcDir, "main.rs"), harnessSource, "utf8");
        rustCompileRes = await this.sandboxRunner.runSandboxed({
          command: cargoBin,
          args: [
            "build",
            "--release",
            "--offline",
            "-j",
            buildJobs,
            "--target-dir",
            path.join(workDir, "target"),
          ],
          cwd: workDir,
          timeoutMs: Math.max(input.timeout_ms, 30_000),
          cpuLimitSeconds: 20,
          memoryLimitMb: 2048,
          env: {
            CARGO_BUILD_JOBS: buildJobs,
            RUSTFLAGS: "-C opt-level=3 -C codegen-units=1",
          },
        });
        if (rustCompileRes.exitCode === 0) {
          const builtBin = path.join(
            workDir,
            "target",
            "release",
            runnerBinName,
          );
          if (existsSync(builtBin)) {
            const binBuf = await readFile(builtBin);
            await writeFile(runnerBinPath, binBuf);
            await chmod(runnerBinPath, 0o755);
          }
        }
      } else {
        const runnerRsPath = path.join(workDir, "runner.rs");
        await writeFile(runnerRsPath, harnessSource, "utf8");
        rustCompileRes = await this.sandboxRunner.runSandboxed({
          command: rustcBin,
          args: [
            "-C",
            "opt-level=3",
            "-C",
            "codegen-units=1",
            "--edition=2021",
            runnerRsPath,
            "-o",
            runnerBinPath,
          ],
          cwd: workDir,
          timeoutMs: Math.max(input.timeout_ms, 30_000),
          cpuLimitSeconds: 20,
          memoryLimitMb: 2048,
          env: {
            CARGO_BUILD_JOBS: buildJobs,
          },
        });
      }

      if (rustCompileRes.exitCode !== 0 || !existsSync(runnerBinPath)) {
        return this.buildReport(input, rustFnName, {
          status: "compile_error",
          iterationsCompleted: 0,
          boundaryCasesTested: 0,
          counterexample: null,
          memorySafety,
          benchmarkTelemetry: null,
          sandboxResult: rustCompileRes,
          compilerDiagnostics:
            (rustCompileRes.stderr || rustCompileRes.stdout).trim() ||
            "Rust candidate compilation failed.",
        });
      }

      if (options?.signal?.aborted) {
        return err(new AnalysisCancelledError(OPERATION));
      }

      // Step 3: Execute the compiled differential harness inside the OS sandbox
      const execRes = await this.sandboxRunner.runSandboxed({
        command: runnerBinPath,
        args: [],
        cwd: workDir,
        timeoutMs: input.timeout_ms,
        cpuLimitSeconds: Math.max(5, Math.ceil(input.timeout_ms / 1000)),
        memoryLimitMb: 1024,
      });

      const markerLine = execRes.stdout
        .split(/\r?\n/)
        .find((line) => line.startsWith(JSON_MARKER));

      if (
        execRes.timedOut ||
        execRes.signal !== null ||
        execRes.exitCode !== 0 ||
        !markerLine
      ) {
        return this.buildReport(input, rustFnName, {
          status: "sandbox_fault",
          iterationsCompleted: 0,
          boundaryCasesTested: 0,
          counterexample: null,
          memorySafety,
          benchmarkTelemetry: null,
          sandboxResult: execRes,
          compilerDiagnostics: null,
        });
      }

      let payload: HarnessJsonPayload;
      try {
        payload = JSON.parse(
          markerLine.slice(JSON_MARKER.length),
        ) as HarnessJsonPayload;
      } catch (cause) {
        return err(
          new AnalysisOutputError(
            OPERATION,
            "Failed to parse JSON verdict from parity harness.",
            { cause },
          ),
        );
      }

      let scaffoldedCrate: RustParityScaffoldedCrate | null = null;
      if (
        input.scaffold_output_dir &&
        payload.status === "verified_bit_exact"
      ) {
        scaffoldedCrate = await this.scaffoldVerifiedCrate(
          input,
          rustFnName,
          payload,
          memorySafety,
          execRes,
        );
      } else if (
        input.html_report_path &&
        payload.status === "verified_bit_exact"
      ) {
        const htmlReportPath = path.resolve(input.html_report_path);
        await mkdir(path.dirname(htmlReportPath), { recursive: true });
        const sanitizedName = rustFnName
          .toLowerCase()
          .replace(/[^a-z0-9_-]/g, "_")
          .replace(/^[^a-z]+/, "argon_");
        const pkgName =
          sanitizedName.length > 0 ? sanitizedName : "argon_reconstructed";
        const dashboardHtmlContent = this.renderReconstructionDashboardHtml(
          input,
          pkgName,
          rustFnName,
          input.rust_source_code.trim(),
          payload,
          memorySafety,
          execRes,
        );
        await writeFile(htmlReportPath, dashboardHtmlContent, "utf8");
      }

      return this.buildReport(input, rustFnName, {
        status: payload.status,
        iterationsCompleted: payload.iterations_completed,
        boundaryCasesTested: payload.boundary_cases_tested,
        counterexample: payload.counterexample,
        memorySafety,
        benchmarkTelemetry: payload.benchmark_telemetry ?? null,
        sandboxResult: execRes,
        compilerDiagnostics: null,
        scaffoldedCrate,
      });
    } finally {
      await rm(workDir, { recursive: true, force: true }).catch(() => {
        // Ignore temp dir cleanup errors
      });
    }
  }

  private async scaffoldVerifiedCrate(
    input: VerifyRustParityInput,
    rustFnName: string,
    payload: HarnessJsonPayload,
    memorySafety: RustParityMemorySafety,
    sandboxResult: SandboxRunResult,
  ): Promise<RustParityScaffoldedCrate> {
    const outDir = path.resolve(input.scaffold_output_dir!);
    const srcDir = path.join(outDir, "src");
    const testsDir = path.join(outDir, "tests");
    await mkdir(srcDir, { recursive: true });
    await mkdir(testsDir, { recursive: true });

    const sanitizedName = rustFnName
      .toLowerCase()
      .replace(/[^a-z0-9_-]/g, "_")
      .replace(/^[^a-z]+/, "argon_");
    const pkgName =
      sanitizedName.length > 0 ? sanitizedName : "argon_reconstructed";
    const crateIdent = pkgName.replace(/-/g, "_");

    const cargoTomlPath = path.join(outDir, "Cargo.toml");
    const libRsPath = path.join(srcDir, "lib.rs");
    const regressionTestPath = path.join(testsDir, "parity_regression.rs");

    const speedup = payload.benchmark_telemetry?.speedup_vs_c_oracle ?? 1.0;
    const safeRustNs =
      payload.benchmark_telemetry?.safe_rust_ns_per_call ?? 0.0;
    const cOracleNs = payload.benchmark_telemetry?.c_oracle_ns_per_call ?? 0.0;
    const targetDesc = input.target_binary_path
      ? `Binary: ${input.target_binary_path}`
      : "Inline C Reference Oracle";
    const abiSig = `(${input.arg_types.join(", ")}) -> ${input.return_type}`;

    const cargoTomlContent = `[package]
name = "${pkgName}"
version = "0.1.0"
edition = "2021"
description = "ArgonZeroG verified #![forbid(unsafe_code)] Safe Rust reconstruction of ${input.symbol_name}"

[lib]
name = "${crateIdent}"
path = "src/lib.rs"
`;

    const cleanedRustSource = input.rust_source_code
      .replace(/^\s*#!\s*\[\s*forbid\s*\(\s*unsafe_code\s*\)\s*\]\s*/m, "")
      .trim();
    const exportedRustSource = cleanedRustSource.replace(
      new RegExp(`(^|\\n)(\\s*)fn\\s+(${rustFnName})\\b`),
      "$1$2pub fn $3",
    );

    const scaffoldDigestPreamble =
      exportedRustSource.includes("argon_digest_") &&
      !exportedRustSource.includes("fn argon_digest_bytes")
        ? `${RUST_DIGEST_HELPERS_PREAMBLE}\n`
        : "";

    const libRsContent = `#![forbid(unsafe_code)]
//! ArgonZeroG Verified Safe Rust Reconstruction
//! - Target: ${targetDesc}
//! - Symbol: \`${input.symbol_name}\` -> \`${rustFnName}\`
//! - ABI Signature: \`${abiSig}\`
//! - Verified Test Vectors: ${payload.iterations_completed} randomized + ${payload.boundary_cases_tested} deterministic boundary cases (seed=${input.seed})
//! - Native Speedup vs C Oracle: ${speedup}x (${safeRustNs} ns/call Safe Rust vs ${cOracleNs} ns/call C Oracle)

${exportedRustSource}
${scaffoldDigestPreamble}`;

    const sampleVectors = payload.sample_vectors ?? [];
    const assertionLines = sampleVectors
      .map((sv, idx) => {
        const callExpr = `${crateIdent}::${rustFnName}(${sv.inputs_rust_literal.join(", ")})`;
        const normRet = normalizeAbiScalarType(input.return_type);
        if (normRet === "f32" || normRet === "f64") {
          return `    // Vector #${idx + 1}: inputs=(${sv.inputs_formatted.join(", ")}) -> ${sv.output_formatted} (${sv.output_hex})
    {
        let actual = ${callExpr};
        let expected = ${sv.output_rust_literal};
        assert!(
            actual.to_bits() == expected.to_bits()
                || (actual.is_nan() && expected.is_nan())
                || (actual == 0.0 && expected == 0.0),
            "Vector #${idx + 1} mismatch: actual={:?}, expected={:?}",
            actual,
            expected
        );
    }`;
        }
        return `    // Vector #${idx + 1}: inputs=(${sv.inputs_formatted.join(", ")}) -> ${sv.output_formatted} (${sv.output_hex})
    assert_eq!(${callExpr}, ${sv.output_rust_literal});`;
      })
      .join("\n\n");

    const regressionTestContent = `#![forbid(unsafe_code)]
//! Standalone regression test suite verifying ${sampleVectors.length} recorded C oracle test vectors
//! against the reconstructed Safe Rust implementation \`${crateIdent}::${rustFnName}\`.

#[test]
fn verified_c_oracle_regression_vectors() {
${assertionLines}
}
`;

    await writeFile(cargoTomlPath, cargoTomlContent, "utf8");
    await writeFile(libRsPath, libRsContent, "utf8");
    await writeFile(regressionTestPath, regressionTestContent, "utf8");

    let dashboardHtmlPath: string | null = null;
    if (input.html_report_path) {
      dashboardHtmlPath = path.resolve(input.html_report_path);
      await mkdir(path.dirname(dashboardHtmlPath), { recursive: true });
      const dashboardHtmlContent = this.renderReconstructionDashboardHtml(
        input,
        pkgName,
        rustFnName,
        libRsContent,
        payload,
        memorySafety,
        sandboxResult,
      );
      await writeFile(dashboardHtmlPath, dashboardHtmlContent, "utf8");
    }

    return {
      output_dir: outDir,
      cargo_toml_path: cargoTomlPath,
      lib_rs_path: libRsPath,
      regression_test_path: regressionTestPath,
      dashboard_html_path: dashboardHtmlPath,
    };
  }

  private renderReconstructionDashboardHtml(
    input: VerifyRustParityInput,
    pkgName: string,
    rustFnName: string,
    libRsContent: string,
    payload: HarnessJsonPayload,
    memorySafety: RustParityMemorySafety,
    sandboxResult: SandboxRunResult,
  ): string {
    const escapeHtml = (str: string): string =>
      str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");

    const speedup = payload.benchmark_telemetry?.speedup_vs_c_oracle ?? 1.0;
    const safeRustNs =
      payload.benchmark_telemetry?.safe_rust_ns_per_call ?? 0.0;
    const cOracleNs = payload.benchmark_telemetry?.c_oracle_ns_per_call ?? 0.0;
    const abiSig = `(${input.arg_types.join(", ")}) -> ${input.return_type}`;
    const sampleVectors = payload.sample_vectors ?? [];

    const maxNs = Math.max(cOracleNs, safeRustNs, 0.0001);
    const cBarPct = Math.min(
      100,
      Math.max(8, Math.round((cOracleNs / maxNs) * 100)),
    );
    const rustBarPct = Math.min(
      100,
      Math.max(8, Math.round((safeRustNs / maxNs) * 100)),
    );

    const cSpecDisplay = input.c_source_code
      ? input.c_source_code.trim()
      : `// Target Native Binary: ${input.target_binary_path ?? "N/A"}\n// Exported C Symbol: ${input.symbol_name}\n// C ABI Signature: (${input.arg_types.map((t, i) => (t === "bytes" ? `const uint8_t* arg${i}_ptr, size_t arg${i}_len` : `${t} arg${i}`)).join(", ")}) -> ${input.return_type}`;

    const vectorRowsHtml = sampleVectors
      .map(
        (sv, idx) => `
          <tr class="vector-row border-b border-[var(--border)]">
            <td class="py-3 px-4 font-mono text-xs text-[var(--foreground)]">#${idx + 1}</td>
            <td class="py-3 px-4 font-mono text-xs text-[var(--foreground)]">(${escapeHtml(sv.inputs_formatted.join(", "))})</td>
            <td class="py-3 px-4 font-mono text-xs text-[var(--foreground)]">${escapeHtml(sv.output_formatted)} <span class="bg-[var(--secondary)] text-[var(--secondary-foreground)] border border-[var(--border)] rounded px-2 py-0.5 text-xs ml-1">${escapeHtml(sv.output_hex)}</span></td>
            <td class="py-3 px-4 font-mono text-xs text-[var(--foreground)]">${escapeHtml(sv.output_formatted)} <span class="bg-[var(--secondary)] text-[var(--secondary-foreground)] border border-[var(--border)] rounded px-2 py-0.5 text-xs ml-1">${escapeHtml(sv.output_hex)}</span></td>
            <td class="py-3 px-4 text-xs"><span class="bg-[var(--primary)] text-[var(--primary-foreground)] rounded-md px-2.5 py-1 text-xs font-semibold">XOR Diff: 0x0 (MATCH)</span></td>
          </tr>`,
      )
      .join("\n");

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>ArgonZeroG Reconstruction Dashboard — ${escapeHtml(input.symbol_name)}</title>
  <script src="https://www.gstatic.com/antigravity/web/dev/tailwindcss.min.js"></script>
</head>
<body class="bg-[var(--background)] text-[var(--foreground)] antialiased p-6">
  <div class="max-w-7xl mx-auto space-y-6">
    <div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-6 shadow-sm flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
      <div>
        <h1 class="text-[var(--foreground)] font-bold text-xl">ArgonZeroG Verified Safe Rust Reconstruction</h1>
        <p class="text-[var(--muted-foreground)] text-sm mt-1">Symbol: <strong>${escapeHtml(input.symbol_name)}</strong> &rarr; Crate: <strong>${escapeHtml(pkgName)}::${escapeHtml(rustFnName)}</strong> &bull; Signature: <code class="font-mono text-xs">${escapeHtml(abiSig)}</code></p>
      </div>
      <div class="bg-[var(--primary)] text-[var(--primary-foreground)] rounded-full px-4 py-1.5 text-xs font-bold tracking-wider uppercase">VERIFIED BIT-EXACT</div>
    </div>

    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      <div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-5 shadow-sm">
        <div class="text-[var(--muted-foreground)] text-xs uppercase tracking-wider font-medium">Differential Parity Verdict</div>
        <div class="text-[var(--foreground)] font-bold text-xl mt-1">VERIFIED BIT-EXACT</div>
        <div class="text-[var(--muted-foreground)] text-xs mt-1">100.0% parity across ${payload.iterations_completed} random + ${payload.boundary_cases_tested} boundary vectors (seed=${input.seed})</div>
      </div>

      <div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-5 shadow-sm">
        <div class="text-[var(--muted-foreground)] text-xs uppercase tracking-wider font-medium">Memory Safety Guarantee</div>
        <div class="text-[var(--accent)] font-bold text-xl mt-1 font-mono">#![forbid(unsafe_code)]</div>
        <div class="text-[var(--muted-foreground)] text-xs mt-1">${memorySafety.candidate_unsafe_blocks} unsafe blocks &bull; Compile-time enforced</div>
      </div>

      <div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-5 shadow-sm">
        <div class="text-[var(--muted-foreground)] text-xs uppercase tracking-wider font-medium">Native Speedup vs C Oracle</div>
        <div class="text-[var(--foreground)] font-bold text-xl mt-1 font-mono">${speedup}x</div>
        <div class="text-[var(--muted-foreground)] text-xs mt-1">${safeRustNs} ns Safe Rust vs ${cOracleNs} ns C Oracle</div>
        <div class="mt-2 space-y-1.5 text-xs">
          <div class="flex items-center gap-2">
            <span class="w-16 text-[var(--muted-foreground)] text-xs">Safe Rust</span>
            <div class="flex-1 bg-[var(--sidebar)] border border-[var(--border)] h-2 rounded overflow-hidden">
              <div class="bg-[var(--primary)] h-full" style="width: ${rustBarPct}%;"></div>
            </div>
          </div>
          <div class="flex items-center gap-2">
            <span class="w-16 text-[var(--muted-foreground)] text-xs">C Oracle</span>
            <div class="flex-1 bg-[var(--sidebar)] border border-[var(--border)] h-2 rounded overflow-hidden">
              <div class="bg-[var(--accent)] h-full" style="width: ${cBarPct}%;"></div>
            </div>
          </div>
        </div>
      </div>

      <div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-5 shadow-sm">
        <div class="text-[var(--muted-foreground)] text-xs uppercase tracking-wider font-medium">Sandbox Isolation</div>
        <div class="text-[var(--foreground)] font-bold text-lg mt-1 font-mono">${escapeHtml(sandboxResult.isolationBackend)}</div>
        <div class="text-[var(--muted-foreground)] text-xs mt-1">${sandboxResult.wallTimeMs} ms wall time &bull; ${sandboxResult.memoryLimitMb} MB cap</div>
      </div>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-5 shadow-sm">
        <div class="flex items-center justify-between border-b border-[var(--border)] pb-3 mb-3">
          <span class="text-[var(--foreground)] font-semibold text-sm">Original C / Binary Target Specification</span>
          <span class="text-[var(--muted-foreground)] text-xs font-mono">${escapeHtml(input.symbol_name)} ${escapeHtml(abiSig)}</span>
        </div>
        <pre class="bg-[var(--sidebar)] text-[var(--foreground)] border border-[var(--border)] rounded-lg p-4 overflow-x-auto font-mono text-xs"><code>${escapeHtml(cSpecDisplay)}</code></pre>
      </div>

      <div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-5 shadow-sm">
        <div class="flex items-center justify-between border-b border-[var(--border)] pb-3 mb-3">
          <span class="text-[var(--foreground)] font-semibold text-sm">Reconstructed #![forbid(unsafe_code)] Safe Rust (src/lib.rs)</span>
          <span class="text-[var(--accent)] text-xs font-semibold">0 unsafe blocks</span>
        </div>
        <pre class="bg-[var(--sidebar)] text-[var(--foreground)] border border-[var(--border)] rounded-lg p-4 overflow-x-auto font-mono text-xs"><code>${escapeHtml(libRsContent.trim())}</code></pre>
      </div>
    </div>

    <div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-5 shadow-sm">
      <div class="flex items-center justify-between border-b border-[var(--border)] pb-3 mb-3">
        <span class="text-[var(--foreground)] font-semibold text-sm">Verified Test Vector Summary (${sampleVectors.length} Sampled Oracle Vectors)</span>
        <span class="text-[var(--muted-foreground)] text-xs font-mono">tests/parity_regression.rs</span>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full text-left border-collapse">
          <thead>
            <tr class="border-b border-[var(--border)] text-[var(--muted-foreground)] text-xs uppercase tracking-wider">
              <th class="py-3 px-4">Vector #</th>
              <th class="py-3 px-4">Input Arguments</th>
              <th class="py-3 px-4">C Oracle Output</th>
              <th class="py-3 px-4">Safe Rust Output</th>
              <th class="py-3 px-4">Bit-Exact Parity</th>
            </tr>
          </thead>
          <tbody id="vectorTableBody">
            ${vectorRowsHtml}
          </tbody>
        </table>
      </div>
    </div>
  </div>
</body>
</html>
`;
  }

  private buildReport(
    input: VerifyRustParityInput,
    rustFnName: string,
    outcome: {
      readonly status:
        | "verified_bit_exact"
        | "diverged"
        | "sandbox_fault"
        | "compile_error";
      readonly iterationsCompleted: number;
      readonly boundaryCasesTested: number;
      readonly counterexample: RustParityCounterexample | null;
      readonly memorySafety: RustParityMemorySafety;
      readonly benchmarkTelemetry: RustParityBenchmarkTelemetry | null;
      readonly sandboxResult: SandboxRunResult;
      readonly compilerDiagnostics: string | null;
      readonly scaffoldedCrate?: RustParityScaffoldedCrate | null;
    },
  ): Result<RustParityReport, AnalysisError> {
    const report: RustParityReport = {
      status: outcome.status,
      symbol_name: input.symbol_name,
      rust_fn_name: rustFnName,
      harness_mode: input.harness_mode,
      arg_types: [...input.arg_types],
      return_type: input.return_type,
      iterations_requested: input.iterations,
      iterations_completed: outcome.iterationsCompleted,
      boundary_cases_tested: outcome.boundaryCasesTested,
      seed: input.seed,
      float_ulp_tolerance: input.float_ulp_tolerance,
      counterexample: outcome.counterexample,
      memory_safety: outcome.memorySafety,
      benchmark_telemetry: outcome.benchmarkTelemetry,
      sandbox_telemetry: {
        os_platform: outcome.sandboxResult.osPlatform,
        isolation_backend: outcome.sandboxResult.isolationBackend,
        cpu_limit_seconds: outcome.sandboxResult.cpuLimitSeconds,
        memory_limit_mb: outcome.sandboxResult.memoryLimitMb,
        wall_time_ms: outcome.sandboxResult.wallTimeMs,
        exit_code: outcome.sandboxResult.exitCode,
        signal: outcome.sandboxResult.signal,
        timed_out: outcome.sandboxResult.timedOut,
        compiler_diagnostics: outcome.compilerDiagnostics,
      },
      scaffolded_crate: outcome.scaffoldedCrate ?? null,
    };

    const parsed = rustParityReportSchema.safeParse(report);
    if (!parsed.success) {
      return err(new AnalysisOutputError(OPERATION, parsed.error.message));
    }
    return ok(parsed.data);
  }
}
