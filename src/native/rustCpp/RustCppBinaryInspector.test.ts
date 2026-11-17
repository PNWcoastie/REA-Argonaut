import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  inspectRustCppBinaryInputSchema,
  rustCppBinarySchema,
} from "../../domain/rustCpp/rustCppBinary.js";
import { RustCppBinaryInspector } from "./RustCppBinaryInspector.js";

interface ElfPanicSpec {
  readonly file: string;
  readonly line: number;
  readonly column: number;
}

interface ElfSymbolSpec {
  readonly name: string;
  readonly value?: bigint;
  readonly isDefined?: boolean;
}

interface SectionHeaderSpec {
  readonly nameOff: number;
  readonly type: number;
  readonly flags: bigint;
  readonly addr: bigint;
  readonly offset: number;
  readonly size: number;
  readonly link: number;
  readonly info: number;
  readonly addralign: bigint;
  readonly entsize: bigint;
}

function alignTo(value: number, alignment: number): number {
  const rem = value % alignment;
  return rem === 0 ? value : value + (alignment - rem);
}

function writeSectionHeader(
  buf: Buffer,
  baseOffset: number,
  sec: SectionHeaderSpec,
): void {
  buf.writeUInt32LE(sec.nameOff, baseOffset);
  buf.writeUInt32LE(sec.type, baseOffset + 4);
  buf.writeBigUInt64LE(sec.flags, baseOffset + 8);
  buf.writeBigUInt64LE(sec.addr, baseOffset + 16);
  buf.writeBigUInt64LE(BigInt(sec.offset), baseOffset + 24);
  buf.writeBigUInt64LE(BigInt(sec.size), baseOffset + 32);
  buf.writeUInt32LE(sec.link, baseOffset + 40);
  buf.writeUInt32LE(sec.info, baseOffset + 44);
  buf.writeBigUInt64LE(sec.addralign, baseOffset + 48);
  buf.writeBigUInt64LE(sec.entsize, baseOffset + 56);
}

function buildElf64Fixture(
  panics: readonly ElfPanicSpec[],
  symbols: readonly ElfSymbolSpec[],
): Buffer {
  const imageBase = 0x400000n;
  const rodataOffset = 64;
  const rodataVaddr = imageBase + BigInt(rodataOffset);

  const stringEntries: Array<{ text: string; relOff: number }> = [];
  const stringOffsets = new Map<string, number>();
  let stringsLen = 0;
  for (const spec of panics) {
    if (!stringOffsets.has(spec.file)) {
      stringOffsets.set(spec.file, stringsLen);
      stringEntries.push({ text: spec.file, relOff: stringsLen });
      stringsLen += Buffer.byteLength(spec.file, "utf8") + 1;
    }
  }

  const locationsStartRel = Math.max(8, alignTo(stringsLen, 8));
  const rodataSize = Math.max(16, locationsStartRel + panics.length * 24);
  const rodataBuf = Buffer.alloc(rodataSize);

  for (const entry of stringEntries) {
    rodataBuf.write(entry.text, entry.relOff, "utf8");
  }

  let locIndex = 0;
  for (const spec of panics) {
    const relOff = stringOffsets.get(spec.file);
    if (relOff === undefined) continue;
    const locOff = locationsStartRel + locIndex * 24;
    rodataBuf.writeBigUInt64LE(rodataVaddr + BigInt(relOff), locOff);
    rodataBuf.writeBigUInt64LE(
      BigInt(Buffer.byteLength(spec.file, "utf8")),
      locOff + 8,
    );
    rodataBuf.writeUInt32LE(spec.line, locOff + 16);
    rodataBuf.writeUInt32LE(spec.column, locOff + 20);
    locIndex++;
  }

  const dynstrChunks: Buffer[] = [Buffer.from([0])];
  let dynstrLen = 1;
  const dynsymBuf = Buffer.alloc((1 + symbols.length) * 24);

  let symIndex = 1;
  for (const sym of symbols) {
    const nameOffset = dynstrLen;
    const nameBuf = Buffer.from(`${sym.name}\0`, "utf8");
    dynstrChunks.push(nameBuf);
    dynstrLen += nameBuf.length;

    const symOff = symIndex * 24;
    dynsymBuf.writeUInt32LE(nameOffset, symOff);
    dynsymBuf[symOff + 4] = 0x12; // STB_GLOBAL | STT_FUNC
    dynsymBuf[symOff + 5] = 0;
    dynsymBuf.writeUInt16LE(sym.isDefined ? 1 : 0, symOff + 6);
    dynsymBuf.writeBigUInt64LE(sym.value ?? 0n, symOff + 8);
    dynsymBuf.writeBigUInt64LE(0n, symOff + 16);
    symIndex++;
  }
  const dynstrBuf = Buffer.concat(dynstrChunks);

  const sectionNames = [".rodata", ".dynsym", ".dynstr", ".shstrtab"] as const;
  const shstrChunks: Buffer[] = [Buffer.from([0])];
  let shstrLen = 1;
  const shNameOffsets: number[] = [];
  for (const secName of sectionNames) {
    shNameOffsets.push(shstrLen);
    const nameBuf = Buffer.from(`${secName}\0`, "utf8");
    shstrChunks.push(nameBuf);
    shstrLen += nameBuf.length;
  }
  const shstrBuf = Buffer.concat(shstrChunks);

  const dynsymOffset = alignTo(rodataOffset + rodataBuf.length, 8);
  const dynstrOffset = alignTo(dynsymOffset + dynsymBuf.length, 8);
  const shstrOffset = alignTo(dynstrOffset + dynstrBuf.length, 8);
  const shoff = alignTo(shstrOffset + shstrBuf.length, 8);
  const totalSize = shoff + 5 * 64;

  const elf = Buffer.alloc(totalSize);
  // ELF64 little-endian x86_64 header
  elf[0] = 0x7f;
  elf[1] = 0x45;
  elf[2] = 0x4c;
  elf[3] = 0x46;
  elf[4] = 2; // ELFCLASS64
  elf[5] = 1; // ELFDATA2LSB
  elf[6] = 1; // EV_CURRENT
  elf.writeUInt16LE(3, 16); // ET_DYN
  elf.writeUInt16LE(62, 18); // EM_X86_64
  elf.writeUInt32LE(1, 20); // EV_CURRENT
  elf.writeBigUInt64LE(0n, 32); // e_phoff
  elf.writeBigUInt64LE(BigInt(shoff), 40); // e_shoff
  elf.writeUInt16LE(64, 52); // e_ehsize
  elf.writeUInt16LE(0, 54); // e_phentsize
  elf.writeUInt16LE(0, 56); // e_phnum
  elf.writeUInt16LE(64, 58); // e_shentsize
  elf.writeUInt16LE(5, 60); // e_shnum
  elf.writeUInt16LE(4, 62); // e_shstrndx

  rodataBuf.copy(elf, rodataOffset);
  dynsymBuf.copy(elf, dynsymOffset);
  dynstrBuf.copy(elf, dynstrOffset);
  shstrBuf.copy(elf, shstrOffset);

  // [1] .rodata
  writeSectionHeader(elf, shoff + 64, {
    nameOff: shNameOffsets[0] ?? 0,
    type: 1, // SHT_PROGBITS
    flags: 0x2n, // SHF_ALLOC
    addr: rodataVaddr,
    offset: rodataOffset,
    size: rodataBuf.length,
    link: 0,
    info: 0,
    addralign: 8n,
    entsize: 0n,
  });

  // [2] .dynsym
  writeSectionHeader(elf, shoff + 128, {
    nameOff: shNameOffsets[1] ?? 0,
    type: 11, // SHT_DYNSYM
    flags: 0x2n,
    addr: imageBase + BigInt(dynsymOffset),
    offset: dynsymOffset,
    size: dynsymBuf.length,
    link: 3, // .dynstr
    info: 1,
    addralign: 8n,
    entsize: 24n,
  });

  // [3] .dynstr
  writeSectionHeader(elf, shoff + 192, {
    nameOff: shNameOffsets[2] ?? 0,
    type: 3, // SHT_STRTAB
    flags: 0x2n,
    addr: imageBase + BigInt(dynstrOffset),
    offset: dynstrOffset,
    size: dynstrBuf.length,
    link: 0,
    info: 0,
    addralign: 1n,
    entsize: 0n,
  });

  // [4] .shstrtab
  writeSectionHeader(elf, shoff + 256, {
    nameOff: shNameOffsets[3] ?? 0,
    type: 3, // SHT_STRTAB
    flags: 0n,
    addr: 0n,
    offset: shstrOffset,
    size: shstrBuf.length,
    link: 0,
    info: 0,
    addralign: 1n,
    entsize: 0n,
  });

  return elf;
}

describe("RustCppBinaryInspector zero-drift audit", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    await Promise.all(
      tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })),
    );
  });

  it("audits Rust core::panicking::Location origins, panic handlers, and unsafe C sinks in ELF64", async () => {
    const dir = await mkdtemp(join(tmpdir(), "argon-rust-cpp-audit-"));
    tempDirs.push(dir);
    const binPath = join(dir, "sample-rust.elf");

    const elfBytes = buildElf64Fixture(
      [
        {
          file: "/rustc/abcd1234abcd1234abcd1234abcd1234abcd1234/library/core/src/panicking.rs",
          line: 142,
          column: 5,
        },
        {
          file: "src/decoder.rs",
          line: 88,
          column: 12,
        },
      ],
      [
        {
          name: "_ZN4core9panicking18panic_bounds_check17h1234567890abcdefE",
          value: 0x401000n,
          isDefined: true,
        },
        {
          name: "rust_begin_unwind",
          value: 0x401100n,
          isDefined: true,
        },
        {
          name: "strcpy",
          value: 0n,
          isDefined: false,
        },
      ],
    );
    await writeFile(binPath, elfBytes);

    const inspector = new RustCppBinaryInspector();
    const res = await inspector.inspect(
      inspectRustCppBinaryInputSchema.parse({ path: binPath }),
    );

    expect(res.ok).toBe(true);
    if (!res.ok) {
      throw res.error;
    }

    const validated = rustCppBinarySchema.safeParse(res.value);
    expect(validated.success).toBe(true);
    expect(res.value.rust.detected).toBe(true);
    expect(res.value.rust.zero_drift_audit).toEqual({
      total_panic_locations: 2,
      std_or_core_panic_locations: 1,
      crate_panic_locations: 1,
      detected_panic_handlers: [
        "_ZN4core9panicking18panic_bounds_check17h1234567890abcdefE",
        "rust_begin_unwind",
      ],
      unsafe_c_memory_sinks_imported: ["strcpy"],
    });
  });

  it("classifies std/alloc/core vs cargo/crate panic paths, deduplicates handlers, and normalizes C sinks", async () => {
    const dir = await mkdtemp(join(tmpdir(), "argon-rust-cpp-norm-"));
    tempDirs.push(dir);
    const binPath = join(dir, "normalized-sinks.elf");

    const elfBytes = buildElf64Fixture(
      [
        { file: "library/core/src/slice/index.rs", line: 10, column: 3 },
        { file: "library/std/src/panicking.rs", line: 20, column: 4 },
        { file: "library/alloc/src/raw_vec.rs", line: 30, column: 5 },
        { file: "/checkout/library/core/src/option.rs", line: 40, column: 6 },
        {
          file: "/cargo/.cargo/registry/src/index.crates.io-6f17d22bba15001f/serde-1.0.210/src/de/mod.rs",
          line: 50,
          column: 7,
        },
        { file: "crates/parser/src/lib.rs", line: 60, column: 8 },
      ],
      [
        { name: "rust_begin_unwind" },
        { name: "rust_begin_unwind@RUST_1.0" },
        { name: "_ZN4core9panicking13unwrap_failed17h1111222233334444E" },
        { name: "_ZN4core5slice5index16slice_index_fail17h2222333344445555E" },
        { name: "_ZN4core9panicking14panic_nounwind17h3333444455556666E" },
        {
          name: "_ZN4core9panicking11panic_const23panic_const_div_by_zero17h4444555566667777E",
        },
        { name: "strcpy@GLIBC_2.2.5" },
        { name: "_strcpy" },
        { name: "strcat" },
        { name: "sprintf@GLIBC_2.2.5" },
        { name: "vsprintf" },
        { name: "gets" },
        { name: "scanf" },
        { name: "__isoc99_scanf@GLIBC_2.7" },
        { name: "_system" },
        { name: "popen" },
        // Safe or unrelated functions must not be flagged as unsafe sinks
        { name: "fgets" },
        { name: "snprintf" },
        { name: "vsnprintf" },
        { name: "__strcpy_chk" },
        { name: "filesystem_read" },
      ],
    );
    await writeFile(binPath, elfBytes);

    const inspector = new RustCppBinaryInspector();
    const res = await inspector.inspect({
      path: binPath,
      max_panic_locations: 500,
      max_symbols: 500,
    });

    expect(res.ok).toBe(true);
    if (!res.ok) {
      throw res.error;
    }

    expect(res.value.rust.zero_drift_audit).toEqual({
      total_panic_locations: 6,
      std_or_core_panic_locations: 4,
      crate_panic_locations: 2,
      detected_panic_handlers: [
        "_ZN4core5slice5index16slice_index_fail17h2222333344445555E",
        "_ZN4core9panicking11panic_const23panic_const_div_by_zero17h4444555566667777E",
        "_ZN4core9panicking13unwrap_failed17h1111222233334444E",
        "_ZN4core9panicking14panic_nounwind17h3333444455556666E",
        "rust_begin_unwind",
      ],
      unsafe_c_memory_sinks_imported: [
        "__isoc99_scanf",
        "gets",
        "popen",
        "scanf",
        "sprintf",
        "strcat",
        "strcpy",
        "system",
        "vsprintf",
      ],
    });
  });

  it("keeps zero_drift_audit optional in schema for backward compatibility and reports empty audit for clean binaries", async () => {
    const dir = await mkdtemp(join(tmpdir(), "argon-rust-cpp-clean-"));
    tempDirs.push(dir);
    const binPath = join(dir, "clean.elf");

    const elfBytes = buildElf64Fixture([], [{ name: "snprintf" }]);
    await writeFile(binPath, elfBytes);

    const inspector = new RustCppBinaryInspector();
    const res = await inspector.inspect(
      inspectRustCppBinaryInputSchema.parse({ path: binPath }),
    );

    expect(res.ok).toBe(true);
    if (!res.ok) {
      throw res.error;
    }

    expect(res.value.rust.detected).toBe(false);
    expect(res.value.rust.zero_drift_audit).toEqual({
      total_panic_locations: 0,
      std_or_core_panic_locations: 0,
      crate_panic_locations: 0,
      detected_panic_handlers: [],
      unsafe_c_memory_sinks_imported: [],
    });

    const legacyReport = {
      ...res.value,
      rust: {
        detected: res.value.rust.detected,
        rustc_version: res.value.rust.rustc_version,
        compiler_commit: res.value.rust.compiler_commit,
        crates: res.value.rust.crates,
        recovered_source_files: res.value.rust.recovered_source_files,
        panic_locations: res.value.rust.panic_locations,
        demangled_symbols: res.value.rust.demangled_symbols,
      },
    };
    const parsedLegacy = rustCppBinarySchema.safeParse(legacyReport);
    expect(parsedLegacy.success).toBe(true);
    if (parsedLegacy.success) {
      expect(parsedLegacy.data.rust.zero_drift_audit).toBeNull();
    }
  });
});
