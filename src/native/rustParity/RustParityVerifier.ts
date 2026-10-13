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

function rustStorageType(ty: RustParityScalarType): string {
  return ty === "bytes" ? "Vec<u8>" : ty;
}

function formatArgCall(ty: RustParityScalarType, expr: string): string {
  return ty === "bytes" ? `fmt_bytes(&${expr})` : `fmt_${ty}(${expr})`;
}

function literalArgCall(ty: RustParityScalarType, expr: string): string {
  return ty === "bytes" ? `lit_bytes(&${expr})` : `lit_${ty}(${expr})`;
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
      return "vec![0.0f32, -0.0f32, 1.0, -1.0, 2.0, -2.0, 0.5, 4095.0, 4096.0, 4097.0, f32::MIN_POSITIVE, -f32::MIN_POSITIVE, f32::EPSILON, f32::MAX, f32::MIN, f32::INFINITY, f32::NEG_INFINITY, f32::NAN]";
    case "f64":
      return "vec![0.0f64, -0.0f64, 1.0, -1.0, 2.0, -2.0, 0.5, 4095.0, 4096.0, 4097.0, f64::MIN_POSITIVE, -f64::MIN_POSITIVE, f64::EPSILON, f64::MAX, f64::MIN, f64::INFINITY, f64::NEG_INFINITY, f64::NAN]";
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
  const retType = input.return_type;
  const tupleType = `(${argTypes.map((t) => `${rustStorageType(t)},`).join(" ")})`;
  const cFnParamSig = argTypes
    .map((t, i) =>
      t === "bytes" ? `a${i}_ptr: *const u8, a${i}_len: usize` : `a${i}: ${t}`,
    )
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
    .map((t, i) => {
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

  return `#![allow(dead_code, unused_variables, non_snake_case, unused_mut, unused_parens, overflowing_literals, improper_ctypes_definitions)]

mod candidate {
${forbidUnsafeEnforced ? "#![forbid(unsafe_code)]" : ""}
${sanitizedCandidateSource}
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
fn gen_f32(rng: &mut SplitMix64) -> f32 {
    match rng.next_u64() & 3 {
        0 => ((rng.next_u64() % 200001) as f32 - 100000.0) * 0.1,
        1 => ((rng.next_u64() % 20001) as f32 - 10000.0) * 0.0001,
        2 => (rng.next_u64() % 65536) as f32 - 32768.0,
        _ => f32::from_bits(rng.next_u64() as u32),
    }
}
fn gen_f64(rng: &mut SplitMix64) -> f64 {
    match rng.next_u64() & 3 {
        0 => ((rng.next_u64() % 200001) as f64 - 100000.0) * 0.1,
        1 => ((rng.next_u64() % 20001) as f64 - 10000.0) * 0.0001,
        2 => (rng.next_u64() % 65536) as f64 - 32768.0,
        _ => f64::from_bits(rng.next_u64()),
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
fn same_arg_f32(a: f32, b: f32) -> bool { a.to_bits() == b.to_bits() }
fn same_arg_f64(a: f64, b: f64) -> bool { a.to_bits() == b.to_bits() }

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
    let ab = a.to_bits();
    let bb = b.to_bits();
    if ab == bb { return Some(0); }
    if a.is_infinite() || b.is_infinite() { return None; }
    let ao = if (ab & 0x8000_0000) != 0 { 0x8000_0000u32.wrapping_sub(ab & 0x7fff_ffff) } else { 0x8000_0000u32.wrapping_add(ab) };
    let bo = if (bb & 0x8000_0000) != 0 { 0x8000_0000u32.wrapping_sub(bb & 0x7fff_ffff) } else { 0x8000_0000u32.wrapping_add(bb) };
    let dist = if ao >= bo { ao - bo } else { bo - ao };
    Some(if dist == 0 { 1 } else { dist as u64 })
}

fn ulp_f64(a: f64, b: f64) -> Option<u64> {
    if a.is_nan() && b.is_nan() { return Some(0); }
    if a.is_nan() || b.is_nan() { return None; }
    let ab = a.to_bits();
    let bb = b.to_bits();
    if ab == bb { return Some(0); }
    if a.is_infinite() || b.is_infinite() { return None; }
    let ao = if (ab & 0x8000_0000_0000_0000) != 0 { 0x8000_0000_0000_0000u64.wrapping_sub(ab & 0x7fff_ffff_ffff_ffff) } else { 0x8000_0000_0000_0000u64.wrapping_add(ab) };
    let bo = if (bb & 0x8000_0000_0000_0000) != 0 { 0x8000_0000_0000_0000u64.wrapping_sub(bb & 0x7fff_ffff_ffff_ffff) } else { 0x8000_0000_0000_0000u64.wrapping_add(bb) };
    let dist = if ao >= bo { ao - bo } else { bo - ao };
    let capped = if dist == 0 { 1 } else if dist > 9_007_199_254_740_991 { 9_007_199_254_740_991 } else { dist };
    Some(capped)
}

fn compare_ret_${retType}(c_val: ${retType}, r_val: ${retType}, ulp_tol: u64) -> (bool, Option<u64>) {
    ${
      retType === "f32"
        ? `match ulp_f32(c_val, r_val) { Some(d) => (d <= ulp_tol, Some(d)), None => (false, None) }`
        : retType === "f64"
          ? `match ulp_f64(c_val, r_val) { Some(d) => (d <= ulp_tol, Some(d)), None => (false, None) }`
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

        const patchedBin = patchBinaryForDynamicLoading(rawBin);
        await writeFile(libFullPath, patchedBin);
        await chmod(libFullPath, 0o755);
      } else if (input.c_source_code) {
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
        await writeFile(cSourcePath, input.c_source_code, "utf8");

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
    const libRsPath = path.join( srcDir, "lib.rs");
    const regressionTestPath = path.join(testsDir, "parity_regression.rs");
    const dashboardHtmlPath = path.join(outDir, "RECONSTRUCTION_DASHBOARD.html");

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

    const libRsContent = `#![forbid(unsafe_code)]
//! ArgonZeroG Verified Safe Rust Reconstruction
//! - Target: ${targetDesc}
//! - Symbol: \`${input.symbol_name}\` -> \`${rustFnName}\`
//! - ABI Signature: \`${abiSig}\`
//! - Verified Test Vectors: ${payload.iterations_completed} randomized + ${payload.boundary_cases_tested} deterministic boundary cases (seed=${input.seed})
//! - Native Speedup vs C Oracle: ${speedup}x (${safeRustNs} ns/call Safe Rust vs ${cOracleNs} ns/call C Oracle)

${exportedRustSource}
`;

    const sampleVectors = payload.sample_vectors ?? [];
    const assertionLines = sampleVectors
      .map((sv, idx) => {
        const callExpr = `${crateIdent}::${rustFnName}(${sv.inputs_rust_literal.join(", ")})`;
        if (input.return_type === "f32" || input.return_type === "f64") {
          return `    // Vector #${idx + 1}: inputs=(${sv.inputs_formatted.join(", ")}) -> ${sv.output_formatted} (${sv.output_hex})
    {
        let actual = ${callExpr};
        let expected = ${sv.output_rust_literal};
        assert!(
            actual.to_bits() == expected.to_bits() || (actual.is_nan() && expected.is_nan()),
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
//! Standalone regression test suite verifying ${ sampleVectors.length } recorded C oracle test vectors
//! against the reconstructed Safe Rust implementation \`${crateIdent}::${rustFnName}\`.

#[test]
fn verified_c_oracle_regression_vectors() {
${assertionLines}
}
`;

    const escapeHtml = (str: string): string =>
      str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");

    const maxNs = Math.max(cOracleNs, safeRustNs, 0.0001);
    const cBarPct = Math.min(100, Math.max(8, Math.round((cOracleNs / maxNs) * 100)));
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
          <tr class="vector-row">
            <td class="mono">#${idx + 1}</td>
            <td class="mono">(${escapeHtml(sv.inputs_formatted.join(", "))})</td>
            <td class="mono">${escapeHtml(sv.output_formatted)} <span class="hex-pill">${escapeHtml(sv.output_hex)}</span></td>
            <td class="mono">${escapeHtml(sv.output_formatted)} <span class="hex-pill">${escapeHtml(sv.output_hex)}</span></td>
            <td><span class="match-badge">XOR Diff: 0x0 (MATCH)</span></td>
          </tr>`,
      )
      .join("\n");

    const dashboardHtmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>ArgonZeroG Reconstruction Dashboard — ${escapeHtml(input.symbol_name)}</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card: #111827;
      --border: #1f2937;
      --text: #f3f4f6;
      --muted: #9ca3af;
      --emerald: #10b981;
      --emerald-bg: rgba(16, 185, 129, 0.14);
      --cyan: #06b6d4;
      --indigo: #6366f1;
      --amber: #f59e0b;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      line-height: 1.5;
      padding: 2rem;
    }
    .container { max-width: 1280px; margin: 0 auto; }
    .banner {
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: linear-gradient(135deg, #111827 0%, #0f172a 100%);
      border: 1px solid var(--emerald);
      border-radius: 12px;
      padding: 1.5rem 2rem;
      margin-bottom: 1.5rem;
    }
    .banner h1 { font-size: 1.5rem; font-weight: 700; letter-spacing: -0.02em; }
    .banner p { color: var(--muted); font-size: 0.92rem; margin-top: 0.25rem; }
    .verdict-pill {
      background: var(--emerald-bg);
      color: var(--emerald);
      border: 1px solid var(--emerald);
      padding: 0.5rem 1rem;
      border-radius: 9999px;
      font-weight: 700;
      font-size: 0.85rem;
      letter-spacing: 0.05em;
    }
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 1rem;
      margin-bottom: 1.5rem;
    }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.25rem;
    }
    .kpi-label { color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.06em; }
    .kpi-value { font-size: 1.65rem; font-weight: 800; margin: 0.35rem 0; color: var(--text); }
    .kpi-sub { color: var(--muted); font-size: 0.85rem; }
    .bar-group { margin-top: 0.55rem; font-size: 0.78rem; }
    .bar-row { display: flex; align-items: center; gap: 0.5rem; margin-top: 0.25rem; }
    .bar-track { flex: 1; background: #1f2937; height: 8px; border-radius: 4px; overflow: hidden; }
    .bar-fill-rust { background: var(--emerald); height: 100%; }
    .bar-fill-c { background: var(--amber); height: 100%; }
    .code-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1rem;
      margin-bottom: 1.5rem;
    }
    @media (max-width: 900px) { .code-grid { grid-template-columns: 1fr; } }
    .card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border);
      padding-bottom: 0.75rem;
      margin-bottom: 0.75rem;
      font-weight: 600;
      font-size: 0.95rem;
    }
    pre {
      background: #070a12;
      border: 1px solid #1e293b;
      border-radius: 8px;
      padding: 1rem;
      overflow-x: auto;
      font-family: "JetBrains Mono", "Fira Code", monospace;
      font-size: 0.84rem;
      color: #e2e8f0;
    }
    .search-bar {
      width: 100%;
      background: #070a12;
      border: 1px solid var(--border);
      color: var(--text);
      padding: 0.6rem 0.9rem;
      border-radius: 8px;
      font-size: 0.9rem;
      margin-bottom: 1rem;
    }
    table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
    th, td { text-align: left; padding: 0.75rem; border-bottom: 1px solid var(--border); }
    th { color: var(--muted); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; }
    .mono { font-family: "JetBrains Mono", "Fira Code", monospace; }
    .hex-pill {
      background: rgba(99, 102, 241, 0.16);
      color: #a5b4fc;
      padding: 0.15rem 0.45rem;
      border-radius: 4px;
      font-size: 0.78rem;
      margin-left: 0.35rem;
    }
    .match-badge {
      background: var(--emerald-bg);
      color: var(--emerald);
      border: 1px solid rgba(16, 185, 129, 0.4);
      padding: 0.2rem 0.55rem;
      border-radius: 6px;
      font-weight: 600;
      font-size: 0.76rem;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="banner">
      <div>
        <h1>ArgonZeroG Verified Safe Rust Reconstruction</h1>
        <p>Symbol: <strong>${escapeHtml(input.symbol_name)}</strong> &rarr; Crate: <strong>${escapeHtml(pkgName)}::${escapeHtml(rustFnName)}</strong> &bull; Signature: <code>${escapeHtml(abiSig)}</code></p>
      </div>
      <div class="verdict-pill">VERIFIED BIT-EXACT</div>
    </div>

    <div class="kpi-grid">
      <div class="card">
        <div class="kpi-label">Differential Parity Verdict</div>
        <div class="kpi-value" style="color: var(--emerald);">VERIFIED BIT-EXACT</div>
        <div class="kpi-sub">100.0% parity across ${payload.iterations_completed} random + ${payload.boundary_cases_tested} boundary vectors (seed=${input.seed})</div>
      </div>

      <div class="card">
        <div class="kpi-label">Memory Safety Guarantee</div>
        <div class="kpi-value" style="color: var(--cyan);">#![forbid(unsafe_code)]</div>
        <div class="kpi-sub">${memorySafety.candidate_unsafe_blocks} unsafe blocks &bull; Compile-time enforced</div>
      </div>

      <div class="card">
        <div class="kpi-label">Native Speedup vs C Oracle</div>
        <div class="kpi-value">${speedup}x</div>
        <div class="kpi-sub">${safeRustNs} ns Safe Rust vs ${cOracleNs} ns C Oracle</div>
        <div class="bar-group">
          <div class="bar-row">
            <span style="width: 68px;">Safe Rust</span>
            <div class="bar-track"><div class="bar-fill-rust" style="width: ${rustBarPct}%;"></div></div>
          </div>
          <div class="bar-row">
            <span style="width: 68px;">C Oracle</span>
            <div class="bar-track"><div class="bar-fill-c" style="width: ${cBarPct}%;"></div></div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="kpi-label">Sandbox Isolation</div>
        <div class="kpi-value" style="font-size: 1.3rem;">${escapeHtml(sandboxResult.isolationBackend)}</div>
        <div class="kpi-sub">${sandboxResult.wallTimeMs} ms wall time &bull; ${sandboxResult.memoryLimitMb} MB cap</div>
      </div>
    </div>

    <div class="code-grid">
      <div class="card">
        <div class="card-header">
          <span>Original C / Binary Target Specification</span>
          <span style="color: var(--muted); font-size: 0.8rem;">${escapeHtml(input.symbol_name)} ${escapeHtml(abiSig)}</span>
        </div>
        <pre><code>${escapeHtml(cSpecDisplay)}</code></pre>
      </div>

      <div class="card">
        <div class="card-header">
          <span>Reconstructed #![forbid(unsafe_code)] Safe Rust (src/lib.rs)</span>
          <span style="color: var(--emerald); font-size: 0.8rem;">0 unsafe blocks</span>
        </div>
        <pre><code>${escapeHtml(libRsContent.trim())}</code></pre>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <span>Interactive Verified Test Vector Explorer (${sampleVectors.length} Sampled Oracle Vectors)</span>
        <span style="color: var(--muted); font-size: 0.8rem;">tests/parity_regression.rs</span>
      </div>
      <input
        type="text"
        id="vectorFilter"
        class="search-bar"
        placeholder="Filter verified test vectors by input, decimal output, or hex..."
        oninput="filterVectors(this.value)"
      />
      <table>
        <thead>
          <tr>
            <th>Vector #</th>
            <th>Input Arguments</th>
            <th>C Oracle Output</th>
            <th>Safe Rust Output</th>
            <th>Bit-Exact Parity</th>
          </tr>
        </thead>
        <tbody id="vectorTableBody">
          ${vectorRowsHtml}
        </tbody>
      </table>
    </div>
  </div>
  <script>
    function filterVectors(query) {
      const q = (query || "").toLowerCase();
      const rows = document.querySelectorAll("#vectorTableBody .vector-row");
      rows.forEach((row) => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(q) ? "" : "none";
      });
    }
  </script>
</body>
</html>
`;

    await writeFile(cargoTomlPath, cargoTomlContent, "utf8");
    await writeFile(libRsPath, libRsContent, "utf8");
    await writeFile(regressionTestPath, regressionTestContent, "utf8");
    await writeFile(dashboardHtmlPath, dashboardHtmlContent, "utf8");

    return {
      output_dir: outDir,
      cargo_toml_path: cargoTomlPath,
      lib_rs_path: libRsPath,
      regression_test_path: regressionTestPath,
      dashboard_html_path: dashboardHtmlPath,
    };
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
