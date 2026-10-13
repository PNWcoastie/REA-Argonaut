import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import type {
  ExecutionOptions,
  ProviderIdentity,
} from "../../application/AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
  AnalysisUnsupportedTargetError,
} from "../../domain/analysisErrorCore.js";
import { err, ok, type Result } from "../../domain/result.js";
import {
  RUST_CPP_PROVIDER_IDENTITY,
  rustCppBinarySchema,
  type CppClassRecord,
  type DemangledSymbolRecord,
  type InspectRustCppBinaryInput,
  type RustCppBinaryReport,
  type RustCrateDependency,
  type RustPanicLocation,
} from "../../domain/rustCpp/rustCppBinary.js";

const OPERATION = "inspect_rust_cpp_binary";

export interface RustCppBinaryPort {
  readonly identity: ProviderIdentity;
  inspect(
    input: InspectRustCppBinaryInput,
    options?: ExecutionOptions,
  ): Promise<Result<RustCppBinaryReport, AnalysisError>>;
}

interface BinarySection {
  readonly name: string;
  readonly vaddr: bigint;
  readonly offset: number;
  readonly size: number;
  readonly isExecutable: boolean;
}

interface BinarySymbol {
  readonly name: string;
  readonly address: bigint;
  readonly size: number;
  readonly isDynamic: boolean;
}

interface ParsedContainer {
  readonly format: "elf" | "macho" | "pe";
  readonly architecture: string;
  readonly bits: 32 | 64;
  readonly littleEndian: boolean;
  readonly isStripped: boolean;
  readonly imageBase: bigint;
  readonly sections: readonly BinarySection[];
  readonly symbols: readonly BinarySymbol[];
  readonly sliceBuffer: Buffer;
  vaddrToFileOffset(vaddr: bigint): number | null;
  fileOffsetToVaddr(offset: number): bigint | null;
}

function readUIntPtr(
  buf: Buffer,
  offset: number,
  bits: 32 | 64,
  littleEndian: boolean,
): bigint {
  if (bits === 64) {
    return littleEndian
      ? buf.readBigUInt64LE(offset)
      : buf.readBigUInt64BE(offset);
  }
  return BigInt(
    littleEndian ? buf.readUInt32LE(offset) : buf.readUInt32BE(offset),
  );
}

function readIntPtr(
  buf: Buffer,
  offset: number,
  bits: 32 | 64,
  littleEndian: boolean,
): bigint {
  if (bits === 64) {
    return littleEndian
      ? buf.readBigInt64LE(offset)
      : buf.readBigInt64BE(offset);
  }
  return BigInt(
    littleEndian ? buf.readInt32LE(offset) : buf.readInt32BE(offset),
  );
}

function readU16(buf: Buffer, offset: number, littleEndian: boolean): number {
  return littleEndian ? buf.readUInt16LE(offset) : buf.readUInt16BE(offset);
}

function readU32(buf: Buffer, offset: number, littleEndian: boolean): number {
  return littleEndian ? buf.readUInt32LE(offset) : buf.readUInt32BE(offset);
}

function readNullTerminatedAscii(
  buf: Buffer,
  offset: number,
  maxLen = 512,
): string {
  if (offset < 0 || offset >= buf.length) return "";
  const end = Math.min(buf.length, offset + maxLen);
  let i = offset;
  while (i < end && buf[i] !== 0) {
    i++;
  }
  return buf.subarray(offset, i).toString("utf8");
}

function formatHexAddress(addr: bigint): string {
  return `0x${addr.toString(16)}`;
}

function buildAddressResolvers(
  sections: readonly BinarySection[],
  imageBase: bigint,
  fileLength: number,
): {
  vaddrToFileOffset: (vaddr: bigint) => number | null;
  fileOffsetToVaddr: (offset: number) => bigint | null;
} {
  const vaddrToFileOffset = (vaddr: bigint): number | null => {
    if (vaddr <= 0n) return null;
    for (const sec of sections) {
      if (
        sec.size > 0 &&
        vaddr >= sec.vaddr &&
        vaddr < sec.vaddr + BigInt(sec.size)
      ) {
        const off = sec.offset + Number(vaddr - sec.vaddr);
        if (off >= 0 && off < fileLength) return off;
      }
    }
    if (imageBase > 0n && vaddr >= imageBase) {
      const rel = vaddr - imageBase;
      for (const sec of sections) {
        if (
          sec.size > 0 &&
          rel >= sec.vaddr &&
          rel < sec.vaddr + BigInt(sec.size)
        ) {
          const off = sec.offset + Number(rel - sec.vaddr);
          if (off >= 0 && off < fileLength) return off;
        }
      }
    }
    if (vaddr < BigInt(fileLength)) {
      return Number(vaddr);
    }
    return null;
  };

  const fileOffsetToVaddr = (offset: number): bigint | null => {
    for (const sec of sections) {
      if (
        sec.size > 0 &&
        offset >= sec.offset &&
        offset < sec.offset + sec.size
      ) {
        return sec.vaddr + BigInt(offset - sec.offset);
      }
    }
    return null;
  };

  return { vaddrToFileOffset, fileOffsetToVaddr };
}

function parseElfContainer(buf: Buffer): ParsedContainer | null {
  if (
    buf.length < 52 ||
    buf[0] !== 0x7f ||
    buf[1] !== 0x45 ||
    buf[2] !== 0x4c ||
    buf[3] !== 0x46
  ) {
    return null;
  }
  const eiClass = buf[4];
  const eiData = buf[5];
  const bits: 32 | 64 = eiClass === 2 ? 64 : 32;
  const littleEndian = eiData !== 2;
  const eMachine = readU16(buf, 18, littleEndian);
  const archMap: Record<number, string> = {
    3: "x86",
    8: "mips",
    20: "ppc",
    21: "ppc64",
    22: "s390x",
    40: "arm",
    62: "x86_64",
    183: "arm64",
    243: "riscv",
  };
  const architecture = archMap[eMachine] ?? `elf-machine-${String(eMachine)}`;

  const shoff =
    bits === 64
      ? Number(readUIntPtr(buf, 40, 64, littleEndian))
      : readU32(buf, 32, littleEndian);
  const shentsize = readU16(buf, bits === 64 ? 58 : 46, littleEndian);
  const shnum = readU16(buf, bits === 64 ? 60 : 48, littleEndian);
  const shstrndx = readU16(buf, bits === 64 ? 62 : 50, littleEndian);

  const sections: BinarySection[] = [];
  const rawSections: Array<{
    nameIdx: number;
    shType: number;
    shFlags: bigint;
    vaddr: bigint;
    offset: number;
    size: number;
    link: number;
    entsize: number;
  }> = [];

  if (
    shoff > 0 &&
    shentsize > 0 &&
    shnum > 0 &&
    shoff + shnum * shentsize <= buf.length
  ) {
    for (let i = 0; i < shnum; i++) {
      const base = shoff + i * shentsize;
      const nameIdx = readU32(buf, base, littleEndian);
      const shType = readU32(buf, base + 4, littleEndian);
      const shFlags =
        bits === 64
          ? readUIntPtr(buf, base + 8, 64, littleEndian)
          : BigInt(readU32(buf, base + 8, littleEndian));
      const vaddr =
        bits === 64
          ? readUIntPtr(buf, base + 16, 64, littleEndian)
          : BigInt(readU32(buf, base + 12, littleEndian));
      const offset =
        bits === 64
          ? Number(readUIntPtr(buf, base + 24, 64, littleEndian))
          : readU32(buf, base + 16, littleEndian);
      const size =
        bits === 64
          ? Number(readUIntPtr(buf, base + 32, 64, littleEndian))
          : readU32(buf, base + 20, littleEndian);
      const link = readU32(buf, base + (bits === 64 ? 40 : 24), littleEndian);
      const entsize =
        bits === 64
          ? Number(readUIntPtr(buf, base + 56, 64, littleEndian))
          : readU32(buf, base + 36, littleEndian);
      rawSections.push({
        nameIdx,
        shType,
        shFlags,
        vaddr,
        offset,
        size,
        link,
        entsize,
      });
    }
  }

  const shstrSec =
    shstrndx < rawSections.length ? rawSections[shstrndx] : undefined;
  for (const raw of rawSections) {
    const name =
      shstrSec && shstrSec.offset + raw.nameIdx < buf.length
        ? readNullTerminatedAscii(buf, shstrSec.offset + raw.nameIdx, 128)
        : "";
    if (raw.size > 0 && raw.offset >= 0 && raw.offset + raw.size <= buf.length) {
      sections.push({
        name,
        vaddr: raw.vaddr,
        offset: raw.offset,
        size: raw.size,
        isExecutable: (raw.shFlags & 0x4n) !== 0n,
      });
    }
  }

  // Also parse PT_LOAD program headers if sections were stripped
  const phoff =
    bits === 64
      ? Number(readUIntPtr(buf, 32, 64, littleEndian))
      : readU32(buf, 28, littleEndian);
  const phentsize = readU16(buf, bits === 64 ? 54 : 42, littleEndian);
  const phnum = readU16(buf, bits === 64 ? 56 : 44, littleEndian);
  let imageBase = 0n;
  if (
    phoff > 0 &&
    phentsize > 0 &&
    phnum > 0 &&
    phoff + phnum * phentsize <= buf.length
  ) {
    for (let i = 0; i < phnum; i++) {
      const base = phoff + i * phentsize;
      const pType = readU32(buf, base, littleEndian);
      if (pType === 1) {
        // PT_LOAD
        const pFlags =
          bits === 64
            ? readU32(buf, base + 4, littleEndian)
            : readU32(buf, base + 24, littleEndian);
        const pOffset =
          bits === 64
            ? Number(readUIntPtr(buf, base + 8, 64, littleEndian))
            : readU32(buf, base + 4, littleEndian);
        const pVaddr =
          bits === 64
            ? readUIntPtr(buf, base + 16, 64, littleEndian)
            : BigInt(readU32(buf, base + 8, littleEndian));
        const pFilesz =
          bits === 64
            ? Number(readUIntPtr(buf, base + 32, 64, littleEndian))
            : readU32(buf, base + 16, littleEndian);
        if (pOffset === 0 && pVaddr > 0n) {
          imageBase = pVaddr;
        }
        if (
          sections.length === 0 &&
          pFilesz > 0 &&
          pOffset + pFilesz <= buf.length
        ) {
          sections.push({
            name: `PT_LOAD_${String(i)}`,
            vaddr: pVaddr,
            offset: pOffset,
            size: pFilesz,
            isExecutable: (pFlags & 1) !== 0,
          });
        }
      }
    }
  }

  const symbols: BinarySymbol[] = [];
  const symValuesBySec = new Map<number, bigint[]>();
  let hasStaticSymtab = false;
  for (let secIdx = 0; secIdx < rawSections.length; secIdx++) {
    const raw = rawSections[secIdx]!;
    // SHT_SYMTAB = 2, SHT_DYNSYM = 11
    if (raw.shType !== 2 && raw.shType !== 11) continue;
    const isDynamic = raw.shType === 11;
    if (!isDynamic && raw.size > 0) {
      hasStaticSymtab = true;
    }
    const strSec =
      raw.link >= 0 && raw.link < rawSections.length
        ? rawSections[raw.link]
        : undefined;
    const symEntSize = raw.entsize > 0 ? raw.entsize : bits === 64 ? 24 : 16;
    const count = Math.floor(raw.size / symEntSize);
    const secSymVals: bigint[] = [];
    for (let i = 0; i < count; i++) {
      const symBase = raw.offset + i * symEntSize;
      if (symBase + symEntSize > buf.length) break;
      const stName = readU32(buf, symBase, littleEndian);
      const stValue =
        bits === 64
          ? readUIntPtr(buf, symBase + 8, 64, littleEndian)
          : BigInt(readU32(buf, symBase + 4, littleEndian));
      const stSize =
        bits === 64
          ? Number(readUIntPtr(buf, symBase + 16, 64, littleEndian))
          : readU32(buf, symBase + 8, littleEndian);
      secSymVals.push(stValue);
      if (stName === 0 || !strSec) continue;
      const name = readNullTerminatedAscii(buf, strSec.offset + stName, 512);
      if (!name) continue;
      symbols.push({
        name,
        address: stValue,
        size: stSize,
        isDynamic,
      });
    }
    symValuesBySec.set(secIdx, secSymVals);
  }

  const { vaddrToFileOffset, fileOffsetToVaddr } = buildAddressResolvers(
    sections,
    imageBase,
    buf.length,
  );

  // Create a mutable copy of buf and apply SHT_RELA relocations so PIE structures
  // in .data.rel.ro (such as Rust core::panicking::Location and C++ _ZTV/_ZTI)
  // have their target virtual addresses populated in-memory.
  const workingBuf = Buffer.from(buf);
  const ptrSize = bits === 64 ? 8 : 4;

  const writeRelocatedPtr = (targetOff: number, val: bigint): void => {
    if (targetOff < 0 || targetOff + ptrSize > workingBuf.length) return;
    if (bits === 64) {
      if (littleEndian) {
        workingBuf.writeBigUInt64LE(BigInt.asUintN(64, val), targetOff);
      } else {
        workingBuf.writeBigUInt64BE(BigInt.asUintN(64, val), targetOff);
      }
    } else {
      const u32 = Number(BigInt.asUintN(32, val));
      if (littleEndian) {
        workingBuf.writeUInt32LE(u32, targetOff);
      } else {
        workingBuf.writeUInt32BE(u32, targetOff);
      }
    }
  };

  for (const raw of rawSections) {
    // SHT_RELA = 4
    if (raw.shType !== 4 || raw.size <= 0 || raw.offset <= 0) continue;
    const relaEntSize = raw.entsize > 0 ? raw.entsize : bits === 64 ? 24 : 12;
    const count = Math.floor(raw.size / relaEntSize);
    const linkedSyms = symValuesBySec.get(raw.link);

    for (let i = 0; i < count; i++) {
      const entryBase = raw.offset + i * relaEntSize;
      if (entryBase + relaEntSize > buf.length) break;

      const rOffset =
        bits === 64
          ? readUIntPtr(buf, entryBase, 64, littleEndian)
          : BigInt(readU32(buf, entryBase, littleEndian));
      const rInfo =
        bits === 64
          ? readUIntPtr(buf, entryBase + 8, 64, littleEndian)
          : BigInt(readU32(buf, entryBase + 4, littleEndian));
      const rAddend =
        bits === 64
          ? readIntPtr(buf, entryBase + 16, 64, littleEndian)
          : BigInt(
              littleEndian
                ? buf.readInt32LE(entryBase + 8)
                : buf.readInt32BE(entryBase + 8),
            );

      const symIdx =
        bits === 64 ? Number(rInfo >> 32n) : Number(rInfo >> 8n);
      const symVal =
        symIdx > 0 && linkedSyms && symIdx < linkedSyms.length
          ? linkedSyms[symIdx]!
          : 0n;

      const resolvedVal = symVal + rAddend;
      if (resolvedVal <= 0n) continue;

      const fileOff = vaddrToFileOffset(rOffset);
      if (fileOff !== null && fileOff >= 0 && fileOff + ptrSize <= workingBuf.length) {
        const existing = readUIntPtr(workingBuf, fileOff, bits, littleEndian);
        if (existing === 0n) {
          writeRelocatedPtr(fileOff, resolvedVal);
        }
      }
    }
  }

  return {
    format: "elf",
    architecture,
    bits,
    littleEndian,
    isStripped: !hasStaticSymtab,
    imageBase,
    sections,
    symbols,
    sliceBuffer: workingBuf,
    vaddrToFileOffset,
    fileOffsetToVaddr,
  };
}

function parseMachoContainer(buf: Buffer): ParsedContainer | null {
  if (buf.length < 32) return null;
  let slice = buf;
  const magicBE = buf.readUInt32BE(0);
  if (magicBE === 0xcafebabe && buf.length >= 28) {
    const nfatArch = buf.readUInt32BE(4);
    if (nfatArch >= 1 && nfatArch <= 16) {
      const sliceOffset = buf.readUInt32BE(8 + 8);
      const sliceSize = buf.readUInt32BE(8 + 12);
      if (
        sliceOffset > 0 &&
        sliceSize > 0 &&
        sliceOffset + sliceSize <= buf.length
      ) {
        slice = buf.subarray(sliceOffset, sliceOffset + sliceSize);
      }
    }
  }
  if (slice.length < 32) return null;
  const m = slice.readUInt32BE(0);
  let bits: 32 | 64;
  let littleEndian: boolean;
  if (m === 0xfeedfacf) {
    bits = 64;
    littleEndian = false;
  } else if (m === 0xcffaedfe) {
    bits = 64;
    littleEndian = true;
  } else if (m === 0xfeedface) {
    bits = 32;
    littleEndian = false;
  } else if (m === 0xcefaedfe) {
    bits = 32;
    littleEndian = true;
  } else {
    return null;
  }

  const cpuType = readU32(slice, 4, littleEndian);
  const ncmds = readU32(slice, 16, littleEndian);
  const cpuMap: Record<number, string> = {
    7: "x86",
    0x01000007: "x86_64",
    12: "arm",
    0x0100000c: "arm64",
  };
  const architecture = cpuMap[cpuType] ?? `macho-cpu-${String(cpuType)}`;

  const sections: BinarySection[] = [];
  const symbols: BinarySymbol[] = [];
  let imageBase = 0n;
  let cmdOffset = bits === 64 ? 32 : 28;

  for (let i = 0; i < ncmds && cmdOffset + 8 <= slice.length; i++) {
    const cmd = readU32(slice, cmdOffset, littleEndian);
    const cmdsize = readU32(slice, cmdOffset + 4, littleEndian);
    if (cmdsize < 8 || cmdOffset + cmdsize > slice.length) break;

    if (cmd === 0x19 || cmd === 0x01) {
      // LC_SEGMENT_64 (0x19) or LC_SEGMENT (0x01)
      const is64 = cmd === 0x19;
      const segName = readNullTerminatedAscii(slice, cmdOffset + 8, 16);
      const vmaddr = is64
        ? readUIntPtr(slice, cmdOffset + 24, 64, littleEndian)
        : BigInt(readU32(slice, cmdOffset + 24, littleEndian));
      const nsects = readU32(slice, cmdOffset + (is64 ? 64 : 48), littleEndian);
      if (segName === "__TEXT" && vmaddr > 0n) {
        imageBase = vmaddr;
      }
      let secOffset = cmdOffset + (is64 ? 72 : 56);
      const secStep = is64 ? 80 : 68;
      for (
        let s = 0;
        s < nsects && secOffset + secStep <= cmdOffset + cmdsize;
        s++
      ) {
        const sectName = readNullTerminatedAscii(slice, secOffset, 16);
        const addr = is64
          ? readUIntPtr(slice, secOffset + 32, 64, littleEndian)
          : BigInt(readU32(slice, secOffset + 32, littleEndian));
        const size = is64
          ? Number(readUIntPtr(slice, secOffset + 40, 64, littleEndian))
          : readU32(slice, secOffset + 36, littleEndian);
        const offset = readU32(slice, secOffset + (is64 ? 48 : 40), littleEndian);
        const flags = readU32(slice, secOffset + (is64 ? 64 : 56), littleEndian);
        if (size > 0 && offset >= 0 && offset + size <= slice.length) {
          sections.push({
            name: `${segName}.${sectName}`,
            vaddr: addr,
            offset,
            size,
            isExecutable: (flags & 0x80000000) !== 0,
          });
        }
        secOffset += secStep;
      }
    } else if (cmd === 0x02 && cmdsize >= 24) {
      // LC_SYMTAB
      const symoff = readU32(slice, cmdOffset + 8, littleEndian);
      const nsyms = readU32(slice, cmdOffset + 12, littleEndian);
      const stroff = readU32(slice, cmdOffset + 16, littleEndian);
      const strsize = readU32(slice, cmdOffset + 20, littleEndian);
      const nlistSize = bits === 64 ? 16 : 12;
      if (
        symoff + nsyms * nlistSize <= slice.length &&
        stroff + strsize <= slice.length
      ) {
        for (let s = 0; s < nsyms; s++) {
          const base = symoff + s * nlistSize;
          const strx = readU32(slice, base, littleEndian);
          const nType = slice[base + 4] ?? 0;
          if ((nType & 0xe0) !== 0) continue; // skip STAB debug entries
          const nValue =
            bits === 64
              ? readUIntPtr(slice, base + 8, 64, littleEndian)
              : BigInt(readU32(slice, base + 8, littleEndian));
          if (strx > 0 && strx < strsize) {
            const rawName = readNullTerminatedAscii(slice, stroff + strx, 512);
            const cleanName = rawName.startsWith("_")
              ? rawName.slice(1)
              : rawName;
            if (cleanName) {
              symbols.push({
                name: cleanName,
                address: nValue,
                size: 0,
                isDynamic: (nType & 0x0e) === 0,
              });
            }
          }
        }
      }
    }
    cmdOffset += cmdsize;
  }

  const hasLocalSymbols = symbols.some((s) => !s.isDynamic && s.address > 0n);
  const { vaddrToFileOffset, fileOffsetToVaddr } = buildAddressResolvers(
    sections,
    imageBase,
    slice.length,
  );

  return {
    format: "macho",
    architecture,
    bits,
    littleEndian,
    isStripped: !hasLocalSymbols,
    imageBase,
    sections,
    symbols,
    sliceBuffer: slice,
    vaddrToFileOffset,
    fileOffsetToVaddr,
  };
}

function parsePeContainer(buf: Buffer): ParsedContainer | null {
  if (buf.length < 64 || buf[0] !== 0x4d || buf[1] !== 0x5a) return null;
  const peOffset = buf.readUInt32LE(0x3c);
  if (
    peOffset < 0 ||
    peOffset + 24 > buf.length ||
    buf[peOffset] !== 0x50 ||
    buf[peOffset + 1] !== 0x45 ||
    buf[peOffset + 2] !== 0x00 ||
    buf[peOffset + 3] !== 0x00
  ) {
    return null;
  }

  const coffBase = peOffset + 4;
  const machine = buf.readUInt16LE(coffBase);
  const numberOfSections = buf.readUInt16LE(coffBase + 2);
  const pointerToSymbolTable = buf.readUInt32LE(coffBase + 8);
  const numberOfSymbols = buf.readUInt32LE(coffBase + 12);
  const sizeOfOptionalHeader = buf.readUInt16LE(coffBase + 16);

  const archMap: Record<number, string> = {
    0x014c: "x86",
    0x8664: "x86_64",
    0xaa64: "arm64",
    0x01c0: "arm",
  };
  const architecture = archMap[machine] ?? `pe-machine-0x${machine.toString(16)}`;

  const optBase = coffBase + 20;
  let bits: 32 | 64 = 64;
  let imageBase = 0x140000000n;
  if (sizeOfOptionalHeader >= 28 && optBase + sizeOfOptionalHeader <= buf.length) {
    const optMagic = buf.readUInt16LE(optBase);
    bits = optMagic === 0x20b ? 64 : 32;
    imageBase =
      bits === 64
        ? buf.readBigUInt64LE(optBase + 24)
        : BigInt(buf.readUInt32LE(optBase + 28));
  }

  const sections: BinarySection[] = [];
  const secTableBase = optBase + sizeOfOptionalHeader;
  for (let i = 0; i < numberOfSections; i++) {
    const base = secTableBase + i * 40;
    if (base + 40 > buf.length) break;
    const name = readNullTerminatedAscii(buf, base, 8);
    const virtualSize = buf.readUInt32LE(base + 8);
    const virtualAddress = buf.readUInt32LE(base + 12);
    const sizeOfRawData = buf.readUInt32LE(base + 16);
    const pointerToRawData = buf.readUInt32LE(base + 20);
    const characteristics = buf.readUInt32LE(base + 36);
    const effectiveSize = Math.min(
      sizeOfRawData,
      buf.length - pointerToRawData,
    );
    if (pointerToRawData > 0 && effectiveSize > 0) {
      sections.push({
        name,
        vaddr: imageBase + BigInt(virtualAddress),
        offset: pointerToRawData,
        size: Math.max(effectiveSize, Math.min(virtualSize, effectiveSize)),
        isExecutable: (characteristics & 0x20000000) !== 0,
      });
    }
  }

  const symbols: BinarySymbol[] = [];
  if (
    pointerToSymbolTable > 0 &&
    numberOfSymbols > 0 &&
    pointerToSymbolTable + numberOfSymbols * 18 <= buf.length
  ) {
    const strTableOffset = pointerToSymbolTable + numberOfSymbols * 18;
    for (let i = 0; i < numberOfSymbols; i++) {
      const symBase = pointerToSymbolTable + i * 18;
      const zeroes = buf.readUInt32LE(symBase);
      let name = "";
      if (zeroes === 0) {
        const strOff = buf.readUInt32LE(symBase + 4);
        name = readNullTerminatedAscii(buf, strTableOffset + strOff, 512);
      } else {
        name = readNullTerminatedAscii(buf, symBase, 8);
      }
      const value = buf.readUInt32LE(symBase + 8);
      const secNum = buf.readInt16LE(symBase + 12);
      const numAux = buf[symBase + 17] ?? 0;
      if (name && secNum > 0 && secNum <= sections.length) {
        const sec = sections[secNum - 1];
        if (sec) {
          symbols.push({
            name,
            address: sec.vaddr + BigInt(value),
            size: 0,
            isDynamic: false,
          });
        }
      }
      i += numAux;
    }
  }

  const { vaddrToFileOffset, fileOffsetToVaddr } = buildAddressResolvers(
    sections,
    imageBase,
    buf.length,
  );

  return {
    format: "pe",
    architecture,
    bits,
    littleEndian: true,
    isStripped: symbols.length === 0,
    imageBase,
    sections,
    symbols,
    sliceBuffer: buf,
    vaddrToFileOffset,
    fileOffsetToVaddr,
  };
}

// ---------------------------------------------------------------------------
// Pure-TS Demanglers (Rust Legacy, Rust v0, Itanium C++, MSVC C++)
// ---------------------------------------------------------------------------

function unescapeRustLegacySegment(seg: string): string {
  return seg
    .replace(/\.\./g, "::")
    .replace(/\$SP\$/g, "@")
    .replace(/\$BP\$/g, "*")
    .replace(/\$RF\$/g, "&")
    .replace(/\$LT\$/g, "<")
    .replace(/\$GT\$/g, ">")
    .replace(/\$LP\$/g, "(")
    .replace(/\$RP\$/g, ")")
    .replace(/\$C\$/g, ",")
    .replace(/\$u20\$/g, " ")
    .replace(/\$u27\$/g, "'")
    .replace(/\$u5b\$/g, "[")
    .replace(/\$u5d\$/g, "]")
    .replace(/\$u7b\$/g, "{")
    .replace(/\$u7d\$/g, "}");
}

function isRustLegacyHash(seg: string): boolean {
  return /^h[0-9a-fA-F]{16}$/.test(seg);
}

function parseLengthPrefixedSegments(body: string): string[] | null {
  const segments: string[] = [];
  let idx = 0;
  while (idx < body.length) {
    if (body[idx] === "I") {
      // Template arguments in Itanium/Rust legacy
      idx++;
      continue;
    }
    if (body[idx] === "E") {
      idx++;
      break;
    }
    let numStr = "";
    while (idx < body.length && body[idx]! >= "0" && body[idx]! <= "9") {
      numStr += body[idx];
      idx++;
    }
    if (!numStr) return segments.length > 0 ? segments : null;
    const len = Number.parseInt(numStr, 10);
    if (len <= 0 || idx + len > body.length) break;
    let seg = body.slice(idx, idx + len);
    if (seg.startsWith("_$")) {
      seg = seg.slice(1);
    }
    segments.push(seg);
    idx += len;
  }
  return segments.length > 0 ? segments : null;
}

function demangleRustV0(mangled: string): string | null {
  if (!mangled.startsWith("_R")) return null;
  const parts: string[] = [];
  let i = 2;
  while (i < mangled.length) {
    const ch = mangled[i];
    if (ch! >= "0" && ch! <= "9") {
      let numStr = "";
      while (i < mangled.length && mangled[i]! >= "0" && mangled[i]! <= "9") {
        numStr += mangled[i];
        i++;
      }
      const len = Number.parseInt(numStr, 10);
      if (mangled[i] === "_") i++;
      if (len > 0 && i + len <= mangled.length) {
        parts.push(mangled.slice(i, i + len));
        i += len;
        continue;
      }
      break;
    }
    if (
      ch === "N" ||
      ch === "v" ||
      ch === "C" ||
      ch === "M" ||
      ch === "X" ||
      ch === "I"
    ) {
      i++;
      if (ch === "C" && i < mangled.length && /[a-zA-Z0-9]{12}/.test(mangled.slice(i, i + 12))) {
        // disambiguator hash
        while (
          i < mangled.length &&
          !(mangled[i]! >= "0" && mangled[i]! <= "9")
        ) {
          i++;
        }
      }
      continue;
    }
    i++;
  }
  if (parts.length === 0) return null;
  return parts.join("::");
}

function demangleItaniumTypeToken(code: string): string {
  const map: Record<string, string> = {
    v: "void",
    b: "bool",
    c: "char",
    a: "signed char",
    h: "unsigned char",
    s: "short",
    t: "unsigned short",
    i: "int",
    j: "unsigned int",
    l: "long",
    m: "unsigned long",
    x: "long long",
    y: "unsigned long long",
    f: "float",
    d: "double",
  };
  return map[code] ?? code;
}

function demangleSymbol(
  mangled: string,
): {
  demangled: string;
  encoding: "rust-v0" | "rust-legacy" | "itanium-cpp" | "msvc-cpp";
} | null {
  const trimmed = mangled.replace(/@@.*$/, "");
  if (trimmed.startsWith("_R")) {
    const v0 = demangleRustV0(trimmed);
    if (v0) {
      return { demangled: v0, encoding: "rust-v0" };
    }
  }

  // Itanium vtable / typeinfo / typeinfo name
  if (trimmed.startsWith("_ZTV") || trimmed.startsWith("_ZTI") || trimmed.startsWith("_ZTS")) {
    const prefix = trimmed.slice(0, 4);
    let rest = trimmed.slice(4);
    if (rest.startsWith("N")) rest = rest.slice(1);
    const segs = parseLengthPrefixedSegments(rest);
    if (segs && segs.length > 0) {
      const className = segs.join("::");
      const label =
        prefix === "_ZTV"
          ? `vtable for ${className}`
          : prefix === "_ZTI"
            ? `typeinfo for ${className}`
            : `typeinfo name for ${className}`;
      return { demangled: label, encoding: "itanium-cpp" };
    }
  }

  if (trimmed.startsWith("_ZN")) {
    let body = trimmed.slice(3);
    let isConst = false;
    if (body.startsWith("K")) {
      isConst = true;
      body = body.slice(1);
    }
    const segs = parseLengthPrefixedSegments(body);
    if (segs && segs.length > 0) {
      const lastSeg = segs[segs.length - 1]!;
      const hasRustHash = isRustLegacyHash(lastSeg);
      const hasRustEscapes = segs.some((s) => s.includes("$") || s.includes(".."));
      const isKnownRustCrate =
        segs[0] === "core" ||
        segs[0] === "std" ||
        segs[0] === "alloc" ||
        segs[0] === "rust_begin_unwind";
      if (hasRustHash || hasRustEscapes || isKnownRustCrate) {
        const cleanSegs = hasRustHash ? segs.slice(0, -1) : segs;
        if (cleanSegs.length > 0) {
          return {
            demangled: cleanSegs.map(unescapeRustLegacySegment).join("::"),
            encoding: "rust-legacy",
          };
        }
      }

      // Itanium C++ nested name
      const endEIndex = body.lastIndexOf("E");
      const suffix = endEIndex >= 0 ? body.slice(endEIndex + 1) : "";
      const classPath = segs.slice(0, -1).join("::");
      let methodName = lastSeg;
      if (/^C[123]$/.test(methodName) && segs.length >= 2) {
        methodName = segs[segs.length - 2]!;
      } else if (/^D[012]$/.test(methodName) && segs.length >= 2) {
        methodName = `~${segs[segs.length - 2]!}`;
      }
      // Also check if D0/D1/D2 or C1/C2 was trailed right before E
      if (endEIndex >= 2) {
        const beforeE = body.slice(endEIndex - 2, endEIndex);
        if (/^D[012]$/.test(beforeE)) {
          return {
            demangled: `${segs.join("::")}::~${segs[segs.length - 1]!}()`,
            encoding: "itanium-cpp",
          };
        }
        if (/^C[123]$/.test(beforeE)) {
          return {
            demangled: `${segs.join("::")}::${segs[segs.length - 1]!}()`,
            encoding: "itanium-cpp",
          };
        }
      }
      const paramStr =
        suffix === "" || suffix === "v"
          ? ""
          : suffix
              .split("")
              .map(demangleItaniumTypeToken)
              .join(", ");
      const fullName = classPath ? `${classPath}::${methodName}` : methodName;
      return {
        demangled: `${fullName}(${paramStr})${isConst ? " const" : ""}`,
        encoding: "itanium-cpp",
      };
    }
  }

  // Top-level Itanium function _Z<len><name><args>
  if (trimmed.startsWith("_Z") && /^_Z\d+/.test(trimmed)) {
    const rest = trimmed.slice(2);
    const segs = parseLengthPrefixedSegments(rest);
    if (segs && segs.length === 1) {
      return {
        demangled: `${segs[0]!}()`,
        encoding: "itanium-cpp",
      };
    }
  }

  // MSVC mangled symbol ?method@Class@@...
  if (trimmed.startsWith("?") && trimmed.includes("@@")) {
    const head = trimmed.slice(1, trimmed.indexOf("@@"));
    const parts = head.split("@").filter(Boolean);
    if (parts.length >= 2) {
      const reversed = [...parts].reverse();
      return {
        demangled: `${reversed.join("::")}()`,
        encoding: "msvc-cpp",
      };
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// Rust Forensic Scanners
// ---------------------------------------------------------------------------

function isPrintableRustPath(str: string): boolean {
  if (!str.endsWith(".rs") || str.length < 4 || str.length > 512) return false;
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if (code < 0x20 || code > 0x7e) return false;
  }
  return /[a-zA-Z0-9_./\\-]/.test(str);
}

function scanRustForensics(
  container: ParsedContainer,
  maxPanicLocations: number,
  maxSymbols: number,
): RustCppBinaryReport["rust"] {
  const buf = container.sliceBuffer;
  const textContent = buf.toString("latin1");

  let rustcVersion: string | null = null;
  let compilerCommit: string | null = null;

  const verMatch = /rustc version ([0-9]+\.[0-9]+\.[0-9]+[^\s)\0]*)/.exec(
    textContent,
  );
  if (verMatch?.[1]) {
    rustcVersion = verMatch[1];
  }

  const commitMatch = /\/rustc\/([0-9a-f]{40})\//.exec(textContent);
  if (commitMatch?.[1]) {
    compilerCommit = commitMatch[1];
  }

  const crateMap = new Map<
    string,
    { version: string | null; paths: Set<string> }
  >();
  const sourceFiles = new Set<string>();

  // Scan cargo registry paths
  const cargoRegex =
    /(?:\/[^\0\s"']*?)?\.cargo\/registry\/src\/[^/\0\s"']+\/([a-zA-Z0-9_-]+)-([0-9]+\.[0-9]+\.[0-9]+[^\0/\s"']*)\/([a-zA-Z0-9_./-]+\.rs)/g;
  let cargoMatch: RegExpExecArray | null;
  while ((cargoMatch = cargoRegex.exec(textContent)) !== null) {
    const fullPath = cargoMatch[0];
    const crateName = cargoMatch[1]!;
    const crateVer = cargoMatch[2]!;
    sourceFiles.add(fullPath);
    const existing = crateMap.get(`${crateName}@${crateVer}`) ?? {
      version: crateVer,
      paths: new Set<string>(),
    };
    existing.paths.add(fullPath);
    crateMap.set(`${crateName}@${crateVer}`, existing);
  }

  // Scan general .rs paths in binary
  const rsRegex =
    /(?:\/[a-zA-Z0-9_.-]+|[a-zA-Z0-9_.-]+)(?:\/[a-zA-Z0-9_.-]+)+\.rs\b/g;
  let rsMatch: RegExpExecArray | null;
  while ((rsMatch = rsRegex.exec(textContent)) !== null) {
    const candidate = rsMatch[0];
    if (isPrintableRustPath(candidate)) {
      sourceFiles.add(candidate);
    }
  }

  // Scan core::panicking::Location structs across sections
  const panicLocations: RustPanicLocation[] = [];
  const seenPanicOffsets = new Set<number>();
  const ptrSize = container.bits === 64 ? 8 : 4;
  const tupleSize = ptrSize * 2 + 8; // 24 bytes on 64-bit, 16 bytes on 32-bit

  const scanSections =
    container.sections.length > 0
      ? container.sections.filter((s) => !s.isExecutable)
      : [
          {
            name: "image",
            vaddr: 0n,
            offset: 0,
            size: buf.length,
            isExecutable: false,
          },
        ];

  for (const sec of scanSections) {
    const end = Math.min(buf.length - tupleSize, sec.offset + sec.size - tupleSize);
    for (let off = sec.offset; off <= end; off += 4) {
      if (panicLocations.length >= maxPanicLocations) break;
      const fileLenBig = readUIntPtr(
        buf,
        off + ptrSize,
        container.bits,
        container.littleEndian,
      );
      if (fileLenBig < 4n || fileLenBig > 512n) continue;
      const fileLen = Number(fileLenBig);
      const line = readU32(buf, off + ptrSize * 2, container.littleEndian);
      const col = readU32(buf, off + ptrSize * 2 + 4, container.littleEndian);
      if (line < 1 || line > 500_000 || col < 1 || col > 10_000) continue;

      const filePtr = readUIntPtr(
        buf,
        off,
        container.bits,
        container.littleEndian,
      );
      const strFileOff = container.vaddrToFileOffset(filePtr);
      if (
        strFileOff === null ||
        strFileOff < 0 ||
        strFileOff + fileLen > buf.length
      ) {
        continue;
      }
      const candidateStr = buf
        .subarray(strFileOff, strFileOff + fileLen)
        .toString("utf8");
      if (isPrintableRustPath(candidateStr)) {
        seenPanicOffsets.add(off);
        sourceFiles.add(candidateStr);
        panicLocations.push({
          struct_offset: off,
          file: candidateStr,
          line,
          column: col,
        });
      }
    }
  }

  // Demangle Rust symbols
  const demangledSymbols: DemangledSymbolRecord[] = [];
  let hasRustMarkerSymbol = false;
  for (const sym of container.symbols) {
    if (
      sym.name.includes("rust_begin_unwind") ||
      sym.name.includes("__rust_alloc") ||
      sym.name.includes("rust_eh_personality")
    ) {
      hasRustMarkerSymbol = true;
    }
    if (demangledSymbols.length >= maxSymbols) continue;
    const dem = demangleSymbol(sym.name);
    if (
      dem &&
      (dem.encoding === "rust-v0" || dem.encoding === "rust-legacy")
    ) {
      demangledSymbols.push({
        address: formatHexAddress(sym.address),
        mangled: sym.name,
        demangled: dem.demangled,
        encoding: dem.encoding,
      });
    }
  }

  const crates: RustCrateDependency[] = [];
  for (const [key, val] of crateMap.entries()) {
    const name = key.split("@")[0]!;
    crates.push({
      name,
      version: val.version,
      source_paths: [...val.paths].sort(),
    });
  }

  const detected =
    rustcVersion !== null ||
    compilerCommit !== null ||
    crates.length > 0 ||
    panicLocations.length > 0 ||
    sourceFiles.size > 0 ||
    demangledSymbols.length > 0 ||
    hasRustMarkerSymbol;

  return {
    detected,
    rustc_version: rustcVersion,
    compiler_commit: compilerCommit,
    crates,
    recovered_source_files: [...sourceFiles].sort(),
    panic_locations: panicLocations,
    demangled_symbols: demangledSymbols,
  };
}

// ---------------------------------------------------------------------------
// C++ ABI, RTTI & VTable Recovery (Itanium & MSVC)
// ---------------------------------------------------------------------------

function extractClassNameFromZts(ztsName: string): string | null {
  let body = ztsName.startsWith("_ZTS") ? ztsName.slice(4) : ztsName;
  if (body.startsWith("N")) body = body.slice(1);
  const segs = parseLengthPrefixedSegments(body);
  return segs && segs.length > 0 ? segs.join("::") : null;
}

function scanCppForensics(
  container: ParsedContainer,
  maxSymbols: number,
): RustCppBinaryReport["cpp"] {
  const buf = container.sliceBuffer;
  const ptrSize = container.bits === 64 ? 8 : 4;

  // Build address -> symbol map
  const addrToSymbol = new Map<bigint, BinarySymbol>();
  const nameToSymbol = new Map<string, BinarySymbol>();
  const demangledSymbols: DemangledSymbolRecord[] = [];

  for (const sym of container.symbols) {
    if (sym.address > 0n && !addrToSymbol.has(sym.address)) {
      addrToSymbol.set(sym.address, sym);
    }
    nameToSymbol.set(sym.name, sym);
    if (demangledSymbols.length < maxSymbols) {
      const dem = demangleSymbol(sym.name);
      if (
        dem &&
        (dem.encoding === "itanium-cpp" || dem.encoding === "msvc-cpp")
      ) {
        demangledSymbols.push({
          address: formatHexAddress(sym.address),
          mangled: sym.name,
          demangled: dem.demangled,
          encoding: dem.encoding,
        });
      }
    }
  }

  const classMap = new Map<string, CppClassRecord>();

  // 1. Discover Itanium C++ classes via _ZTS strings in binary (.rodata) and symbols
  interface DiscoveredTypeinfo {
    className: string;
    mangledZti: string;
    ztsFileOffset: number | null;
    ztsVaddr: bigint | null;
    ztiVaddr: bigint | null;
    ztiFileOffset: number | null;
    baseZtiVaddr: bigint | null;
  }

  const typeinfoByClass = new Map<string, DiscoveredTypeinfo>();
  const typeinfoByZtiVaddr = new Map<bigint, DiscoveredTypeinfo>();

  // First, check symbols for _ZTI / _ZTS / _ZTV
  for (const sym of container.symbols) {
    if (sym.name.startsWith("_ZTI") && !sym.name.includes("cxxabiv1")) {
      const suffix = sym.name.slice(4);
      const className = extractClassNameFromZts(suffix);
      if (!className) continue;
      const ztiFileOffset = container.vaddrToFileOffset(sym.address);
      let baseZtiVaddr: bigint | null = null;
      if (
        ztiFileOffset !== null &&
        ztiFileOffset + ptrSize * 3 <= buf.length
      ) {
        const candidateBase = readUIntPtr(
          buf,
          ztiFileOffset + ptrSize * 2,
          container.bits,
          container.littleEndian,
        );
        if (candidateBase > 0n) {
          baseZtiVaddr = candidateBase;
        }
      }
      const info: DiscoveredTypeinfo = {
        className,
        mangledZti: sym.name,
        ztsFileOffset: null,
        ztsVaddr: null,
        ztiVaddr: sym.address,
        ztiFileOffset,
        baseZtiVaddr,
      };
      typeinfoByClass.set(className, info);
      if (sym.address > 0n) {
        typeinfoByZtiVaddr.set(sym.address, info);
      }
    }
  }

  // Second, binary scan for Itanium RTTI in stripped binaries:
  // In Itanium ABI, a `_ZTI` struct in `.data.rel.ro` / `.rodata` has:
  //   [0]: vtable pointer (`__class_type_info` or `__si_class_type_info`)
  //   [ptrSize]: pointer to `_ZTS` null-terminated string (e.g. "13ThermalSensor\0")
  //   [ptrSize*2]: optional pointer to base `_ZTI`
  const dataSections = container.sections.filter((s) => !s.isExecutable);
  for (const sec of dataSections) {
    const end = Math.min(buf.length - ptrSize * 2, sec.offset + sec.size - ptrSize * 2);
    for (let off = sec.offset; off <= end; off += ptrSize) {
      const namePtr = readUIntPtr(
        buf,
        off + ptrSize,
        container.bits,
        container.littleEndian,
      );
      const nameOff = container.vaddrToFileOffset(namePtr);
      if (nameOff === null || nameOff <= 0 || nameOff >= buf.length - 3) {
        continue;
      }
      // Check if previous byte is null (start of C string) and starts with digits + identifier
      if (nameOff > 0 && buf[nameOff - 1] !== 0) continue;
      const rawZts = readNullTerminatedAscii(buf, nameOff, 128);
      if (!/^(?:N?\d+[A-Za-z_][A-Za-z0-9_]*)+E?$/.test(rawZts)) continue;
      const className = extractClassNameFromZts(rawZts);
      if (
        !className ||
        className.includes("cxxabiv1") ||
        className.includes("type_info")
      ) {
        continue;
      }
      const ztiVaddr = container.fileOffsetToVaddr(off);
      if (ztiVaddr === null) continue;
      let baseZtiVaddr: bigint | null = null;
      if (off + ptrSize * 3 <= buf.length) {
        const candidateBase = readUIntPtr(
          buf,
          off + ptrSize * 2,
          container.bits,
          container.littleEndian,
        );
        if (container.vaddrToFileOffset(candidateBase) !== null) {
          baseZtiVaddr = candidateBase;
        }
      }
      const existing = typeinfoByClass.get(className);
      if (!existing) {
        const info: DiscoveredTypeinfo = {
          className,
          mangledZti: `_ZTI${rawZts}`,
          ztsFileOffset: nameOff,
          ztsVaddr: namePtr,
          ztiVaddr,
          ztiFileOffset: off,
          baseZtiVaddr,
        };
        typeinfoByClass.set(className, info);
        typeinfoByZtiVaddr.set(ztiVaddr, info);
      } else if (existing.ztiVaddr === null || existing.ztiVaddr === 0n) {
        existing.ztiVaddr = ztiVaddr;
        existing.ztiFileOffset = off;
        existing.baseZtiVaddr = baseZtiVaddr;
        typeinfoByZtiVaddr.set(ztiVaddr, existing);
      }
    }
  }

  // Helper to read virtual method slots from a vtable file offset (starting at first virtual function pointer)
  const readVtableMethods = (fnStartOffset: number): CppClassRecord["virtual_methods"] => {
    const methods: CppClassRecord["virtual_methods"] = [];
    for (let slot = 0; slot < 32; slot++) {
      const slotOff = fnStartOffset + slot * ptrSize;
      if (slotOff + ptrSize > buf.length) break;
      const fnPtr = readUIntPtr(
        buf,
        slotOff,
        container.bits,
        container.littleEndian,
      );
      if (fnPtr === 0n) break;
      // Check if fnPtr points to an executable section or known symbol
      const sym = addrToSymbol.get(fnPtr);
      const fnFileOff = container.vaddrToFileOffset(fnPtr);
      const inExecSection =
        fnFileOff !== null &&
        container.sections.some(
          (s) =>
            s.isExecutable &&
            fnFileOff >= s.offset &&
            fnFileOff < s.offset + s.size,
        );
      if (!sym && !inExecSection) break;
      const dem = sym ? demangleSymbol(sym.name) : null;
      methods.push({
        slot,
        address: formatHexAddress(fnPtr),
        symbol: sym?.name ?? null,
        demangled: dem?.demangled ?? null,
      });
    }
    return methods;
  };

  // Match vtables to discovered typeinfos
  for (const [className, info] of typeinfoByClass.entries()) {
    const baseClasses: string[] = [];
    if (info.baseZtiVaddr !== null) {
      const baseInfo = typeinfoByZtiVaddr.get(info.baseZtiVaddr);
      if (baseInfo && baseInfo.className !== className) {
        baseClasses.push(baseInfo.className);
      } else {
        const baseSym = addrToSymbol.get(info.baseZtiVaddr);
        if (baseSym && baseSym.name.startsWith("_ZTI")) {
          const baseName = extractClassNameFromZts(baseSym.name.slice(4));
          if (baseName && baseName !== className) {
            baseClasses.push(baseName);
          }
        }
      }
    }

    // Locate vtable via _ZTV symbol or binary scan for [0, ztiVaddr, fn0, ...]
    const ztvName = info.mangledZti.replace(/^_ZTI/, "_ZTV");
    const ztvSym = nameToSymbol.get(ztvName);
    let vtableVaddr: bigint | null = null;
    let virtualMethods: CppClassRecord["virtual_methods"] = [];

    if (ztvSym && ztvSym.address > 0n) {
      vtableVaddr = ztvSym.address;
      const ztvOff = container.vaddrToFileOffset(ztvSym.address);
      if (ztvOff !== null && ztvOff + ptrSize * 3 <= buf.length) {
        virtualMethods = readVtableMethods(ztvOff + ptrSize * 2);
      }
    } else if (info.ztiVaddr !== null && info.ztiVaddr > 0n) {
      for (const sec of dataSections) {
        const end = Math.min(
          buf.length - ptrSize * 3,
          sec.offset + sec.size - ptrSize * 3,
        );
        for (let off = sec.offset; off <= end; off += ptrSize) {
          const offsetToTop = readIntPtr(
            buf,
            off,
            container.bits,
            container.littleEndian,
          );
          const rttiPtr = readUIntPtr(
            buf,
            off + ptrSize,
            container.bits,
            container.littleEndian,
          );
          if (offsetToTop === 0n && rttiPtr === info.ztiVaddr) {
            vtableVaddr = container.fileOffsetToVaddr(off);
            virtualMethods = readVtableMethods(off + ptrSize * 2);
            break;
          }
        }
        if (vtableVaddr !== null) break;
      }
    }

    classMap.set(className, {
      class_name: className,
      mangled_typeinfo: info.mangledZti,
      base_classes: baseClasses,
      vtable_address: vtableVaddr !== null ? formatHexAddress(vtableVaddr) : null,
      virtual_methods: virtualMethods,
    });
  }

  // 2. Scan MSVC RTTI TypeDescriptor strings (.?AVClassName@@ or .?AUStructName@@)
  const textLatin1 = buf.toString("latin1");
  const msvcRegex = /\.\?A[VU]([A-Za-z_][A-Za-z0-9_@ Make]*)@@/g;
  let msvcMatch: RegExpExecArray | null;
  while ((msvcMatch = msvcRegex.exec(textLatin1)) !== null) {
    const rawParts = msvcMatch[1]!.split("@").filter(Boolean).reverse();
    const className = rawParts.join("::");
    if (className && !classMap.has(className)) {
      classMap.set(className, {
        class_name: className,
        mangled_typeinfo: msvcMatch[0],
        base_classes: [],
        vtable_address: null,
        virtual_methods: [],
      });
    }
  }

  const classes = [...classMap.values()];
  const hasMsvc =
    classes.some((c) => c.mangled_typeinfo?.startsWith(".?A") === true) ||
    demangledSymbols.some((s) => s.encoding === "msvc-cpp");
  const hasItanium =
    classes.some((c) => c.mangled_typeinfo?.startsWith("_ZTI") === true) ||
    demangledSymbols.some((s) => s.encoding === "itanium-cpp") ||
    container.symbols.some((s) => s.name.includes("__gxx_personality") || s.name.includes("__cxa_"));

  const abi: "itanium" | "msvc" | "none" = hasItanium
    ? "itanium"
    : hasMsvc
      ? "msvc"
      : "none";

  return {
    detected: abi !== "none" || classes.length > 0 || demangledSymbols.length > 0,
    abi,
    classes,
    demangled_symbols: demangledSymbols,
  };
}

export class RustCppBinaryInspector implements RustCppBinaryPort {
  readonly identity: ProviderIdentity = RUST_CPP_PROVIDER_IDENTITY;

  async inspect(
    input: InspectRustCppBinaryInput,
    options?: ExecutionOptions,
  ): Promise<Result<RustCppBinaryReport, AnalysisError>> {
    if (options?.signal?.aborted) {
      return err(new AnalysisCancelledError(OPERATION));
    }

    let buf: Buffer;
    try {
      const st = await stat(input.path);
      if (!st.isFile()) {
        return err(
          new AnalysisInputError(OPERATION, undefined, [
            {
              path: ["path"],
              reason: "invalid_value",
              message: `Path is not a regular file: ${input.path}`,
            },
          ]),
        );
      }
      buf = await readFile(input.path);
    } catch (cause) {
      const code = (cause as NodeJS.ErrnoException | undefined)?.code;
      if (code === "EACCES" || code === "EPERM") {
        return err(
          new AnalysisAccessDeniedError(OPERATION, input.path, code, { cause }),
        );
      }
      return err(
        new AnalysisInputError(OPERATION, { cause }, [
          {
            path: ["path"],
            reason: "invalid_value",
            message: `Unable to read binary file at ${input.path}`,
          },
        ]),
      );
    }

    if (options?.signal?.aborted) {
      return err(new AnalysisCancelledError(OPERATION));
    }

    const container =
      parseElfContainer(buf) ??
      parseMachoContainer(buf) ??
      parsePeContainer(buf);

    if (!container) {
      return err(
        new AnalysisUnsupportedTargetError(
          OPERATION,
          input.path,
          "File is not a supported ELF, Mach-O, or PE executable container.",
        ),
      );
    }

    const sha256 = createHash("sha256").update(buf).digest("hex");
    const rust = scanRustForensics(
      container,
      input.max_panic_locations ?? 500,
      input.max_symbols ?? 500,
    );
    const cpp = scanCppForensics(container, input.max_symbols ?? 500);

    const limitations: string[] = [];
    if (container.isStripped) {
      limitations.push(
        "Static symbol table (.symtab) is stripped; symbol recovery relies on dynamic symbols, .rodata panic tuples, and binary RTTI/vtable scanning.",
      );
    }

    const report: RustCppBinaryReport = {
      artifact: {
        path: input.path,
        sha256,
        size_bytes: buf.length,
      },
      format: container.format,
      architecture: container.architecture,
      bits: container.bits,
      is_stripped: container.isStripped,
      rust,
      cpp,
      limitations,
    };

    const parsed = rustCppBinarySchema.safeParse(report);
    if (!parsed.success) {
      return err(new AnalysisOutputError(OPERATION, parsed.error.message));
    }

    return ok(parsed.data);
  }
}
