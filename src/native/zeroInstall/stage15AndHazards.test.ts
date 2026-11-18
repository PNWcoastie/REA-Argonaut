import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import pino from "pino";
import { describe, expect, it } from "vitest";
import type { AppConfig } from "../../config/types.js";
import type { BinaryTarget } from "../../domain/binaryTargetTypes.js";
import { nativeSubgraphSchema } from "../../domain/native/nativeSubgraph.js";
import {
  decodeElfRelrRelocations,
  extractValidDlopenLibraryTargets,
  filterCppLinkerTrapSymbol,
  recoverJniRegisterNativesMethods,
} from "./elfRelocations.js";
import {
  extractLatentBinaryHazards,
  type HazardInstructionRef,
  type HazardModelContext,
  type HazardProcedureRef,
} from "./latentHazards.js";
import {
  computeLinkerHygieneSummary,
  computeStage15NodeReachability,
  type Stage15ModelView,
  type Stage15ProcedureRef,
} from "./stage15Reachability.js";
import { ZeroInstallNativeProvider } from "./ZeroInstallNativeProvider.js";

function makeInsn(
  addr: bigint,
  mnemonic: string,
  operands: string[],
  opts: {
    isCall?: boolean;
    isJump?: boolean;
    isConditionalJump?: boolean;
    isReturn?: boolean;
    targetAddress?: bigint | null;
  } = {},
): HazardInstructionRef {
  return {
    address: addr,
    mnemonic,
    operands,
    rawText: `${mnemonic}${operands.length > 0 ? ` ${operands.join(", ")}` : ""}`,
    isCall: opts.isCall ?? false,
    isJump: opts.isJump ?? false,
    isConditionalJump: opts.isConditionalJump ?? false,
    isReturn: opts.isReturn ?? false,
    targetAddress: opts.targetAddress ?? null,
  };
}

function makeEmptyModel(
  overrides: Partial<HazardModelContext> = {},
): HazardModelContext {
  return {
    segments: overrides.segments ?? [],
    gotSlotByAddr: overrides.gotSlotByAddr ?? new Map(),
    symbolsByAddr: overrides.symbolsByAddr ?? new Map(),
    proceduresByAddr: overrides.proceduresByAddr ?? new Map(),
  };
}

function buildMinimalElf64WithRelrAndJni(): Buffer {
  // Layout:
  // 0x0000..0x0040: Elf64_Ehdr
  // 0x0040..0x00b0: 2x Elf64_Phdr (PT_LOAD RX @0x0..0x1000, PT_LOAD RW @0x1000..0x2000)
  // 0x0200..0x0218: .text (code: ret at 0x200, plus a helper at 0x220)
  // 0x0400..0x0500: .rodata strings ("_setNativeGain", "(I)Z", "libcamera_gyro.so", "ro.camera.sound.forced")
  // 0x0600..0x0680: .dynsym (null + 2 GLOBAL DEFAULT funcs)
  // 0x0700..0x0780: .dynstr
  // 0x0800..0x0820: .relr.dyn
  // 0x0900..0x0980: .shstrtab
  // 0x1000..0x1040: .data (JNINativeMethod triple at file offset 0x1000, vaddr 0x1000)
  // 0x1100..: Elf64_Shdr table (8 sections)
  const totalSize = 0x1400;
  const buf = Buffer.alloc(totalSize, 0);

  // ELF Header
  buf.write("\x7fELF", 0, "binary");
  buf[4] = 2; // ELFCLASS64
  buf[5] = 1; // ELFDATA2LSB
  buf[6] = 1; // EV_CURRENT
  buf.writeUInt16LE(3, 16); // ET_DYN
  buf.writeUInt16LE(183, 18); // EM_AARCH64
  buf.writeUInt32LE(1, 20); // EV_CURRENT
  buf.writeBigUInt64LE(0x200n, 24); // e_entry
  buf.writeBigUInt64LE(0x40n, 32); // e_phoff
  buf.writeBigUInt64LE(0x1100n, 40); // e_shoff
  buf.writeUInt16LE(64, 52); // e_ehsize
  buf.writeUInt16LE(56, 54); // e_phentsize
  buf.writeUInt16LE(2, 56); // e_phnum
  buf.writeUInt16LE(64, 58); // e_shentsize
  buf.writeUInt16LE(8, 60); // e_shnum
  buf.writeUInt16LE(7, 62); // e_shstrndx

  // Phdr 0: PT_LOAD RX (0x0..0x1000)
  buf.writeUInt32LE(1, 0x40);
  buf.writeUInt32LE(5, 0x44); // PF_R | PF_X
  buf.writeBigUInt64LE(0n, 0x48);
  buf.writeBigUInt64LE(0n, 0x50);
  buf.writeBigUInt64LE(0n, 0x58);
  buf.writeBigUInt64LE(0x1000n, 0x60);
  buf.writeBigUInt64LE(0x1000n, 0x68);
  buf.writeBigUInt64LE(0x1000n, 0x70);

  // Phdr 1: PT_LOAD RW (0x1000..0x1100)
  buf.writeUInt32LE(1, 0x78);
  buf.writeUInt32LE(6, 0x7c); // PF_R | PF_W
  buf.writeBigUInt64LE(0x1000n, 0x80);
  buf.writeBigUInt64LE(0x1000n, 0x88);
  buf.writeBigUInt64LE(0x1000n, 0x90);
  buf.writeBigUInt64LE(0x100n, 0x98);
  buf.writeBigUInt64LE(0x100n, 0xa0);
  buf.writeBigUInt64LE(0x1000n, 0xa8);

  // .text instructions at 0x200 (JNI_OnLoad) and 0x220 (_setNativeGain)
  // 0x200: mov x0, #0x10004; ret
  buf.writeUInt32LE(0xd2800020, 0x200); // mov x0, #1
  buf.writeUInt32LE(0xd65f03c0, 0x204); // ret
  // 0x220: ldr x8, [x19, #0x30]!; str xzr, [x19, #0x30]; ret
  buf.writeUInt32LE(0xf8430e68, 0x220); // ldr x8, [x19, #0x30]!
  buf.writeUInt32LE(0xf9001a7f, 0x224); // str xzr, [x19, #0x30]
  buf.writeUInt32LE(0xd65f03c0, 0x228); // ret

  // .rodata strings at 0x400
  buf.write("_setNativeGain\0", 0x400, "utf8");
  buf.write("(I)Z\0", 0x420, "utf8");
  buf.write("libcamera_gyro.so\0", 0x430, "utf8");
  buf.write("ro.camera.sound.forced\0", 0x450, "utf8");

  // .dynstr at 0x700
  const dynStrEntries = [
    { off: 1, val: "JNI_OnLoad\0" },
    { off: 12, val: "deadFossilHelper\0" },
  ];
  for (const s of dynStrEntries) {
    buf.write(s.val, 0x700 + s.off, "utf8");
  }

  // .dynsym at 0x600 (3 entries * 24 bytes = 72 bytes)
  // Entry 1: JNI_OnLoad @ 0x200 (STB_GLOBAL=1, STT_FUNC=2 -> 0x12, st_other=0, shndx=1)
  buf.writeUInt32LE(1, 0x618);
  buf[0x61c] = 0x12;
  buf[0x61d] = 0;
  buf.writeUInt16LE(1, 0x61e);
  buf.writeBigUInt64LE(0x200n, 0x620);
  buf.writeBigUInt64LE(8n, 0x628);

  // Entry 2: deadFossilHelper @ 0x280 (STB_GLOBAL=1, STT_FUNC=2 -> 0x12, shndx=1)
  buf.writeUInt32LE(12, 0x630);
  buf[0x634] = 0x12;
  buf[0x635] = 0;
  buf.writeUInt16LE(1, 0x636);
  buf.writeBigUInt64LE(0x280n, 0x638);
  buf.writeBigUInt64LE(4n, 0x640);
  buf.writeUInt32LE(0xd65f03c0, 0x280); // ret

  // .relr.dyn at 0x800: 2 entries (base 0x1000, bitmap 0b111 = 3 relocs -> total 3)
  buf.writeBigUInt64LE(0x1000n, 0x800);
  buf.writeBigUInt64LE(0b111n, 0x808); // bit 0 -> 1, bit 1 -> +8, bit 2 -> +16 => 3 relocs!

  // .data at 0x1000: JNINativeMethod { name=0x400, sig=0x420, fn=0x220 }
  buf.writeBigUInt64LE(0x400n, 0x1000);
  buf.writeBigUInt64LE(0x420n, 0x1008);
  buf.writeBigUInt64LE(0x220n, 0x1010);

  // .shstrtab at 0x900
  const shNames = [
    { off: 1, name: ".text\0" },
    { off: 7, name: ".rodata\0" },
    { off: 15, name: ".dynsym\0" },
    { off: 23, name: ".dynstr\0" },
    { off: 31, name: ".relr.dyn\0" },
    { off: 41, name: ".data\0" },
    { off: 47, name: ".shstrtab\0" },
  ];
  for (const s of shNames) {
    buf.write(s.name, 0x900 + s.off, "utf8");
  }

  const writeShdr = (
    idx: number,
    nameOff: number,
    type: number,
    flags: bigint,
    addr: bigint,
    offset: bigint,
    size: bigint,
    link: number,
    entsize: bigint,
  ) => {
    const base = 0x1100 + idx * 64;
    buf.writeUInt32LE(nameOff, base);
    buf.writeUInt32LE(type, base + 4);
    buf.writeBigUInt64LE(flags, base + 8);
    buf.writeBigUInt64LE(addr, base + 16);
    buf.writeBigUInt64LE(offset, base + 24);
    buf.writeBigUInt64LE(size, base + 32);
    buf.writeUInt32LE(link, base + 40);
    buf.writeBigUInt64LE(entsize, base + 56);
  };

  // Section 0: NULL
  writeShdr(0, 0, 0, 0n, 0n, 0n, 0n, 0, 0n);
  // Section 1: .text
  writeShdr(1, 1, 1, 6n, 0x200n, 0x200n, 0x100n, 0, 0n);
  // Section 2: .rodata
  writeShdr(2, 7, 1, 2n, 0x400n, 0x400n, 0x100n, 0, 0n);
  // Section 3: .dynsym (shType=11, shLink=4)
  writeShdr(3, 15, 11, 2n, 0x600n, 0x600n, 72n, 4, 24n);
  // Section 4: .dynstr (shType=3)
  writeShdr(4, 23, 3, 2n, 0x700n, 0x700n, 64n, 0, 0n);
  // Section 5: .relr.dyn (shType=19)
  writeShdr(5, 31, 19, 2n, 0x800n, 0x800n, 16n, 0, 8n);
  // Section 6: .data (SHF_WRITE | SHF_ALLOC = 3)
  writeShdr(6, 41, 1, 3n, 0x1000n, 0x1000n, 0x40n, 0, 0n);
  // Section 7: .shstrtab (shType=3)
  writeShdr(7, 47, 3, 0n, 0n, 0x900n, 64n, 0, 0n);

  return buf;
}

describe("Stage 1.5 Multi-Edge Reachability, Relocations & 9-Category Hazards", () => {
  it("decodes 64-bit and 32-bit ELF SHT_RELR (.relr.dyn) relative relocation bitmaps", () => {
    // 64-bit: entry 0 = 0x1000 (even base), entry 1 = 0b1011 (odd bitmap: bits 0, 1, 2 -> bits in entry>>1 = 0b101 => bit 0 (+0), bit 2 (+16))
    const sec64 = Buffer.alloc(16);
    sec64.writeBigUInt64LE(0x1000n, 0);
    sec64.writeBigUInt64LE((0b101n << 1n) | 1n, 8);
    expect(decodeElfRelrRelocations(sec64, true, true)).toEqual([
      0x1000n,
      0x1008n,
      0x1018n,
    ]);

    // 32-bit: entry 0 = 0x2000, entry 1 = bitmap (bit 1 and bit 3 -> offsets +4 and +12 from 0x2004)
    const sec32 = Buffer.alloc(8);
    sec32.writeUInt32LE(0x2000, 0);
    sec32.writeUInt32LE((0b1010 << 1) | 1, 4);
    expect(decodeElfRelrRelocations(sec32, false, true)).toEqual([
      0x2000n,
      0x2008n,
      0x2010n,
    ]);
  });

  it("recovers stripped LOCAL JNINativeMethod handlers from .data (including RELA zeroed slots)", () => {
    const elf = buildMinimalElf64WithRelrAndJni();
    const methods = recoverJniRegisterNativesMethods(
      elf,
      true,
      true,
      (vaddr) => Number(vaddr),
      [{ fileOffset: 0x1000, fileSize: 0x40 }],
      [{ start: 0x200n, end: 0x300n }],
    );
    expect(methods).toEqual([
      {
        methodName: "_setNativeGain",
        signature: "(I)Z",
        fnAddress: 0x220n,
      },
    ]);

    // RELA case: on-disk pointers at 0x1000..0x1018 are 0, resolved via relative relocation addends
    const relaElf = Buffer.from(elf);
    relaElf.writeBigUInt64LE(0n, 0x1000);
    relaElf.writeBigUInt64LE(0n, 0x1008);
    relaElf.writeBigUInt64LE(0n, 0x1010);
    const relaMap = new Map<number, bigint>([
      [0x1000, 0x400n],
      [0x1008, 0x420n],
      [0x1010, 0x220n],
    ]);
    const relaMethods = recoverJniRegisterNativesMethods(
      relaElf,
      true,
      true,
      (vaddr) => Number(vaddr),
      [{ fileOffset: 0x1000, fileSize: 0x40 }],
      [{ start: 0x200n, end: 0x300n }],
      (off) => relaMap.get(off) ?? null,
    );
    expect(relaMethods).toEqual(methods);
  });

  it("filters all 5 C++ linker-resolution trap classes and extracts valid dlopen .so targets", () => {
    expect(filterCppLinkerTrapSymbol("_Znwm", false)).toEqual({
      trapped: true,
      trapKind: "ndk_cpp_runtime_reexport",
    });
    expect(filterCppLinkerTrapSymbol("_ZTISt12length_error", true)).toEqual({
      trapped: true,
      trapKind: "weak_stl_typeinfo_or_vtable",
    });
    expect(filterCppLinkerTrapSymbol("_ZTINSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE", false)).toEqual({
      trapped: true,
      trapKind: "weak_stl_typeinfo_or_vtable",
    });
    expect(filterCppLinkerTrapSymbol("NV12Scale", false)).toEqual({
      trapped: true,
      trapKind: "static_third_party_collision",
    });
    expect(filterCppLinkerTrapSymbol("hal_notify_callback", false)).toEqual({
      trapped: true,
      trapKind: "sibling_hal_callback_collision",
    });
    expect(filterCppLinkerTrapSymbol("_ZNSt3__112basic_stringIcE6appendEPKc", false)).toEqual({
      trapped: true,
      trapKind: "stl_template_method_collision",
    });
    expect(filterCppLinkerTrapSymbol("compute_blur_score", false)).toEqual({
      trapped: false,
      trapKind: null,
    });

    const targets = extractValidDlopenLibraryTargets([
      { value: "ro.camera.sound.forced" },
      { value: "persist.vendor.audio.so.mode" },
      { value: "sensor.so.mode" },
      { value: "Cannot dlopen libc.so: %s" },
      { value: "[cam] dlopen failed for libmissing.so" },
      { value: "Failed to dlopen libother.so" },
      { value: "libcamera_gyro.so" },
      { value: "/vendor/lib64/libblur_engine.so.1" },
    ]);
    expect(targets).toEqual(["libblur_engine.so.1", "libcamera_gyro.so"]);
  });

  it("detects all 9 latent binary hazard categories across AArch64 and x86_64 instructions", () => {
    const model = makeEmptyModel({
      segments: [{ start: 0x5000n, end: 0x6000n, writable: true }],
      symbolsByAddr: new Map([
        [0x100n, { name: "strcpy", isFunction: true }],
        [0x110n, { name: "strlen", isFunction: true }],
        [0x120n, { name: "strncpy", isFunction: true }],
        [0x130n, { name: "malloc", isFunction: true }],
        [0x140n, { name: "storeTemplate", isFunction: true }],
        [0x150n, { name: "_Z8get_SIZEPKhiRiS1_", isFunction: true }],
        [0x5010n, { name: "g_filter_state", isFunction: false }],
      ]),
    });

    const proc: HazardProcedureRef = {
      address: 0x1000n,
      name: "_Z14fastJpegDecodePKhmPiS1_i",
      thunk: false,
      instructions: [
        // 5. uninitialized_or_stack_hazard
        makeInsn(0x1000n, "sub", ["sp", "sp", "#0x80000"]),
        // 1. potential_integer_overflow_to_pointer + 8b. size_truncation (sxtw -> malloc)
        makeInsn(0x1004n, "mul", ["w8", "w9", "w8"]),
        makeInsn(0x1008n, "sxtw", ["x0", "w8"]),
        makeInsn(0x100cn, "bl", ["0x130 <malloc>"], {
          isCall: true,
          targetAddress: 0x130n,
        }),
        // 2. unchecked_division
        makeInsn(0x1010n, "sdiv", ["w10", "w11", "w12"]),
        // 3. thread_hostile_mutable_global
        makeInsn(0x1014n, "str", ["w10", "[x1]"], { targetAddress: 0x5010n }),
        // 4. unsafe_memory_sink
        makeInsn(0x1018n, "bl", ["0x100 <strcpy>"], {
          isCall: true,
          targetAddress: 0x100n,
        }),
        // 6. register_writeback_offset_clobber
        makeInsn(0x101cn, "ldr", ["x8", "[x19, #0x30]!"]),
        makeInsn(0x1020n, "str", ["xzr", "[x19, #0x30]"]),
        // 7. null_deref_before_check
        makeInsn(0x1024n, "mov", ["x0", "x20"]),
        makeInsn(0x1028n, "bl", ["0x110 <strlen>"], {
          isCall: true,
          targetAddress: 0x110n,
        }),
        makeInsn(0x102cn, "cbz", ["x20", "0x1080"], {
          isJump: true,
          isConditionalJump: true,
        }),
        // 8a. strlen - 3 underflow into strncpy without bounds check
        makeInsn(0x1030n, "bl", ["0x110 <strlen>"], {
          isCall: true,
          targetAddress: 0x110n,
        }),
        makeInsn(0x1034n, "sub", ["x2", "x0", "#3"]),
        makeInsn(0x1038n, "bl", ["0x120 <strncpy>"], {
          isCall: true,
          targetAddress: 0x120n,
        }),
        // 9a. duplicate identical call
        makeInsn(0x103cn, "bl", ["0x140 <storeTemplate>"], {
          isCall: true,
          targetAddress: 0x140n,
        }),
        makeInsn(0x1040n, "bl", ["0x140 <storeTemplate>"], {
          isCall: true,
          targetAddress: 0x140n,
        }),
        // 9b. unpopulated out-param (zero stack slots + add stack arg + lsr #31)
        makeInsn(0x1044n, "stp", ["xzr", "xzr", "[sp, #0x8]"]),
        makeInsn(0x1048n, "add", ["x3", "sp", "#0x8"]),
        makeInsn(0x104cn, "bl", ["0x150 <_Z8get_SIZEPKhiRiS1_>"], {
          isCall: true,
          targetAddress: 0x150n,
        }),
        makeInsn(0x1050n, "lsr", ["w8", "w8", "#31"]),
      ],
    };

    const hazards = extractLatentBinaryHazards(proc, model);
    const categories = new Set(hazards.map((h) => h.category));

    expect(categories).toEqual(
      new Set([
        "potential_integer_overflow_to_pointer",
        "unchecked_division",
        "thread_hostile_mutable_global",
        "unsafe_memory_sink",
        "uninitialized_or_stack_hazard",
        "register_writeback_offset_clobber",
        "null_deref_before_check",
        "size_truncation_or_unsigned_underflow",
        "unpopulated_out_param_or_duplicate_call",
      ]),
    );
  });

  it("avoids false positives on safe C/C++ codegen idioms across all detectors", () => {
    const model = makeEmptyModel({
      symbolsByAddr: new Map([
        [0x110n, { name: "strlen", isFunction: true }],
        [0x120n, { name: "memcpy", isFunction: true }],
        [0x130n, { name: "_ZN6SampleD1Ev", isFunction: true }],
        [0x140n, { name: "helper", isFunction: true }],
      ]),
    });

    const safeProc: HazardProcedureRef = {
      address: 0x2000n,
      name: "submitFromString",
      thunk: false,
      instructions: [
        // Safe FP mulss + stack frame access [rbp + 0x10]
        makeInsn(0x2000n, "mulss", ["xmm0", "xmm1"]),
        makeInsn(0x2004n, "mov", ["rax", "[rbp + 0x10]"]),
        // Safe guarded fcmp before fdiv
        makeInsn(0x2008n, "fcmp", ["d1", "#0.0"]),
        makeInsn(0x200cn, "fdiv", ["d0", "d0", "d1"]),
        // Safe pointer-chasing load overwriting x8 before cbz x8
        makeInsn(0x2010n, "ldr", ["x8", "[x8]"]),
        makeInsn(0x2014n, "cbz", ["x8", "0x2060"], {
          isJump: true,
          isConditionalJump: true,
        }),
        // Safe strlen return value check (rax clobbered by strlen)
        makeInsn(0x2018n, "mov", ["rdi", "rax"]),
        makeInsn(0x201cn, "call", ["0x110 <strlen>"], {
          isCall: true,
          targetAddress: 0x110n,
        }),
        makeInsn(0x2020n, "test", ["rax", "rax"]),
        // Safe memcpy(dst, s, strlen(s) + 1) and constant mov edx, 64
        makeInsn(0x2024n, "bl", ["0x110 <strlen>"], {
          isCall: true,
          targetAddress: 0x110n,
        }),
        makeInsn(0x2028n, "add", ["x2", "x0", "#1"]),
        makeInsn(0x202cn, "mov", ["w2", "#64"]),
        makeInsn(0x2030n, "bl", ["0x120 <memcpy>"], {
          isCall: true,
          targetAddress: 0x120n,
        }),
        // Safe post-indexed writeback on caller-saved x0 followed by call returning new x0
        makeInsn(0x2034n, "ldr", ["x8", "[x0], #8"]),
        makeInsn(0x2038n, "bl", ["0x140 <helper>"], {
          isCall: true,
          targetAddress: 0x140n,
        }),
        makeInsn(0x203cn, "ldr", ["x9", "[x0, #0x10]"]),
        // Safe consecutive C++ destructor calls
        makeInsn(0x2040n, "bl", ["0x130 <_ZN6SampleD1Ev>"], {
          isCall: true,
          targetAddress: 0x130n,
        }),
        makeInsn(0x2044n, "bl", ["0x130 <_ZN6SampleD1Ev>"], {
          isCall: true,
          targetAddress: 0x130n,
        }),
        // Zeroed stack at #0x10, unrelated call passing #0x20, then lsr #31 signbit extraction
        makeInsn(0x2048n, "str", ["xzr", "[sp, #0x10]"]),
        makeInsn(0x204cn, "add", ["x0", "sp", "#0x20"]),
        makeInsn(0x2050n, "bl", ["0x140 <helper>"], {
          isCall: true,
          targetAddress: 0x140n,
        }),
        makeInsn(0x2054n, "lsr", ["w0", "w0", "#31"]),
      ],
    };

    expect(extractLatentBinaryHazards(safeProc, model)).toEqual([]);
  });

  it("classifies Stage 1.5 Class I live wired, Class II dead fossil, and Class II cloned-inline suspects", () => {
    const activeProc: Stage15ProcedureRef = {
      address: 0x1000n,
      name: "activeClonedDiv",
      external: false,
      thunk: false,
      callers: new Set([0x900n]),
      callees: new Set(),
      instructions: [makeInsn(0x1000n, "sdiv", ["w0", "w1", "w2"])],
    };
    const deadFossil: Stage15ProcedureRef = {
      address: 0x2000n,
      name: "getVersion",
      external: false,
      thunk: false,
      callers: new Set(),
      callees: new Set(),
      instructions: [makeInsn(0x2000n, "str", ["w1", "[x0]"], { targetAddress: 0x5010n })],
    };
    const clonedSuspect: Stage15ProcedureRef = {
      address: 0x3000n,
      name: "legacyMatrixInverse",
      external: false,
      thunk: false,
      callers: new Set(),
      callees: new Set(),
      instructions: [makeInsn(0x3000n, "fdiv", ["d0", "d1", "d2"])],
    };

    const stageModel: Stage15ModelView = {
      entryPoint: 0x900n,
      segments: [{ start: 0x5000n, end: 0x6000n, writable: true }],
      gotSlotByAddr: new Map(),
      symbolsByAddr: new Map([
        [0x1000n, { name: "activeClonedDiv", isFunction: true, dynamic: true }],
        [0x2000n, { name: "getVersion", isFunction: true, dynamic: true }],
        [0x3000n, { name: "legacyMatrixInverse", isFunction: true, dynamic: true }],
        [0x5010n, { name: "g_state", isFunction: false, dynamic: false }],
      ]),
      proceduresByAddr: new Map([
        [0x1000n, activeProc],
        [0x2000n, deadFossil],
        [0x3000n, clonedSuspect],
      ]),
      sortedProcedures: [activeProc, deadFossil, clonedSuspect],
      rttiAnnotationsByAddr: new Map(),
      strings: [{ value: "libblur_engine.so" }, { value: "ro.camera.sound.forced" }],
      elfLinkerMetrics: {
        definedDynsymFunctions: 12,
        globalDefaultFunctions: 10,
        weakFunctions: 2,
        intraBinaryPltStubs: 8,
        relrRelocationsDecoded: 3,
        jniRegisteredMethodsRecovered: 1,
        filteredCppLinkerTraps: 4,
        exportedFuncAddresses: new Set([0x1000n, 0x2000n, 0x3000n]),
        jniRegisteredAddresses: new Set(),
      },
    };

    const activeReach = computeStage15NodeReachability(
      activeProc,
      stageModel,
      extractLatentBinaryHazards(activeProc, stageModel),
    );
    expect(activeReach.classification).toBe("class_i_live_wired");
    expect(activeReach.linkage_edges).toContain("internal_call_chain");

    // Unreferenced get* export with only a single non-algorithmic global reference remains dead fossil
    const fossilReach = computeStage15NodeReachability(
      deadFossil,
      stageModel,
      extractLatentBinaryHazards(deadFossil, stageModel),
    );
    expect(fossilReach.classification).toBe("class_ii_dead_fossil");
    expect(fossilReach.linkage_edges).toContain("unreferenced_export");

    const clonedReach = computeStage15NodeReachability(
      clonedSuspect,
      stageModel,
      extractLatentBinaryHazards(clonedSuspect, stageModel),
    );
    expect(clonedReach.classification).toBe("class_ii_cloned_inline_suspect");

    const hygiene = computeLinkerHygieneSummary(stageModel);
    expect(hygiene.relr_relocations_decoded).toBe(3);
    expect(hygiene.jni_registered_methods_recovered).toBe(1);
    expect(hygiene.dlopen_targets).toEqual(["libblur_engine.so"]);
    expect(hygiene.filtered_cpp_linker_traps).toBe(4);
    expect(hygiene.fvisibility_hidden_likely_omitted).toBe(true);
  });

  it("validates end-to-end decompile_subgraph output with Stage 1.5 telemetry against nativeSubgraphSchema", async () => {
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "argonaut-stage15-"));
    try {
      const elfPath = path.join(tmpDir, "libsample_camera.so");
      const elfBytes = buildMinimalElf64WithRelrAndJni();
      writeFileSync(elfPath, elfBytes);
      const sha256 = createHash("sha256").update(elfBytes).digest("hex");

      const config: AppConfig = {
        analysisProvider: "zero-install",
        ghidraInstallDir: undefined,
        ghidraJavaHome: undefined,
        ghidraStartupTimeoutMs: 10_000,
        ilspyCmdPath: undefined,
        hopperLauncherPath: "hopper",
        hopperStartupTimeoutMs: 10_000,
        hopperTargetPath: undefined,
        hopperTargetKind: "executable",
        hopperLoaderArgs: [],
        logLevel: "silent",
        referenceSourcePolicy: "off",
      };

      const target: BinaryTarget = {
        kind: "executable",
        path: elfPath,
        format: "elf",
        architecture: "arm64",
        availableArchitectures: ["arm64"],
        sha256,
      };

      const provider = new ZeroInstallNativeProvider(
        config,
        pino({ level: "silent" }),
        { PATH: "" },
        "linux",
      );
      const client = provider.createClient(target);

      const res = await client.execute("decompile_subgraph", {
        procedure: "_setNativeGain",
        max_depth: 1,
        max_nodes: 10,
        include_assembly: true,
      });
      await client.close();

      expect(res.ok).toBe(true);
      if (!res.ok) return;
      const parsed = nativeSubgraphSchema.safeParse(res.value.result);
      expect(
        parsed.success,
        parsed.success ? "" : parsed.error.message,
      ).toBe(true);
      if (!parsed.success) return;

      expect(parsed.data.nodes.length).toBeGreaterThanOrEqual(1);
      const rootNode = parsed.data.nodes[0]!;
      expect(rootNode.procedure.name).toBe("_setNativeGain");
      expect(rootNode.stage15_reachability?.classification).toBe(
        "class_i_live_wired",
      );
      expect(rootNode.stage15_reachability?.linkage_edges).toContain(
        "jni_onload_register_natives",
      );
      expect(
        rootNode.latent_hazards.some(
          (h) => h.category === "register_writeback_offset_clobber",
        ),
      ).toBe(true);
      expect(parsed.data.linker_hygiene?.relr_relocations_decoded).toBe(3);
      expect(parsed.data.linker_hygiene?.jni_registered_methods_recovered).toBe(
        1,
      );
      expect(parsed.data.linker_hygiene?.dlopen_targets).toEqual([
        "libcamera_gyro.so",
      ]);
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  }, 15_000);
});
