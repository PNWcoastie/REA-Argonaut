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
import {
  PYTHON_FROZEN_PROVIDER_IDENTITY,
  pythonFrozenBinarySchema,
  type InspectPythonFrozenBinaryInput,
  type PycCodeObjectSummary,
  type PyinstallerTocEntry,
  type PythonFrozenBinaryReport,
} from "../../domain/pythonFrozen/pythonFrozenBinary.js";
import { err, ok, type Result } from "../../domain/result.js";

const OPERATION = "inspect_python_frozen_binary";

const PYINSTALLER_MAGIC = Buffer.from([
  0x4d, 0x45, 0x49, 0x0c, 0x0b, 0x0a, 0x0b, 0x0e,
]);
const PYZ_MAGIC = Buffer.from([0x50, 0x59, 0x5a, 0x00]);

export interface PythonFrozenBinaryPort {
  readonly identity: ProviderIdentity;
  inspect(
    input: InspectPythonFrozenBinaryInput,
    options?: ExecutionOptions,
  ): Promise<Result<PythonFrozenBinaryReport, AnalysisError>>;
}

function describeTocTypeCode(typeCode: string): string {
  const map: Record<string, string> = {
    s: "Python entry script",
    m: "Python module",
    M: "Python package (__init__)",
    z: "PYZ compressed bytecode archive",
    Z: "PYZ bytecode archive",
    b: "Native binary extension (.so/.pyd/.dll)",
    x: "Extracted data file",
    d: "Data file",
    o: "Python runtime option",
    a: "Binary dependency",
  };
  return map[typeCode] ?? `PyInstaller entry (${typeCode})`;
}

function formatPyinstallerVersion(pyvers: number): string | null {
  if (pyvers <= 0) return null;
  if (pyvers >= 100 && pyvers < 1000) {
    const major = Math.floor(pyvers / 100);
    const minor = pyvers % 100;
    return `${String(major)}.${String(minor)}`;
  }
  if (pyvers >= 1000 && pyvers < 10000) {
    const major = Math.floor(pyvers / 1000);
    const minor = Math.floor((pyvers % 1000) / 10);
    return `${String(major)}.${String(minor)}`;
  }
  if (pyvers >= 20 && pyvers < 100) {
    const major = Math.floor(pyvers / 10);
    const minor = pyvers % 10;
    return `${String(major)}.${String(minor)}`;
  }
  return String(pyvers);
}

function parsePyinstallerArchive(
  buf: Buffer,
  maxTocEntries: number,
): PythonFrozenBinaryReport["pyinstaller"] | null {
  const cookieOffset = buf.lastIndexOf(PYINSTALLER_MAGIC);
  if (cookieOffset < 0) return null;

  const remaining = buf.length - cookieOffset;
  if (remaining < 24) return null;

  const is88ByteCookie = remaining >= 88;
  const cookieSize = is88ByteCookie ? 88 : 24;

  const pkgLen = buf.readUInt32BE(cookieOffset + 8);
  const tocOffsetRel = buf.readUInt32BE(cookieOffset + 12);
  const tocLen = buf.readUInt32BE(cookieOffset + 16);
  const pyvers = buf.readUInt32BE(cookieOffset + 20);

  let pylibName: string | null = null;
  if (is88ByteCookie) {
    const rawLib = buf.subarray(cookieOffset + 24, cookieOffset + 88);
    const zeroIdx = rawLib.indexOf(0);
    const cleanStr = (zeroIdx >= 0 ? rawLib.subarray(0, zeroIdx) : rawLib)
      .toString("utf8")
      .trim();
    if (cleanStr.length > 0) {
      pylibName = cleanStr;
    }
  }

  const computedArchiveStart = cookieOffset + cookieSize - pkgLen;
  const archiveStart =
    computedArchiveStart >= 0 && computedArchiveStart <= cookieOffset
      ? computedArchiveStart
      : 0;
  const absTocOffset = archiveStart + tocOffsetRel;

  const tocEntries: PyinstallerTocEntry[] = [];
  const entryScripts: string[] = [];
  const nativeExtensions: string[] = [];
  const bundledModules: string[] = [];
  let pyzTocDataOffset: number | null = null;

  if (
    tocLen > 0 &&
    absTocOffset >= 0 &&
    absTocOffset + tocLen <= buf.length
  ) {
    let cursor = absTocOffset;
    const tocEnd = absTocOffset + tocLen;
    while (cursor + 18 <= tocEnd && tocEntries.length < maxTocEntries) {
      const entryLen = buf.readInt32BE(cursor);
      if (entryLen < 18 || cursor + entryLen > tocEnd) break;
      const dataOffsetRel = buf.readUInt32BE(cursor + 4);
      const compressedSize = buf.readUInt32BE(cursor + 8);
      const uncompressedSize = buf.readUInt32BE(cursor + 12);
      const compressionFlag = buf[cursor + 16] ?? 0;
      const typeCodeByte = buf[cursor + 17] ?? 0x78;
      const typeCode = String.fromCharCode(typeCodeByte);

      const nameSlice = buf.subarray(cursor + 18, cursor + entryLen);
      const nullIdx = nameSlice.indexOf(0);
      const rawName = (
        nullIdx >= 0 ? nameSlice.subarray(0, nullIdx) : nameSlice
      )
        .toString("utf8")
        .trim();
      const name = rawName || `entry_${String(tocEntries.length)}`;
      const absDataOffset = archiveStart + dataOffsetRel;

      tocEntries.push({
        name,
        type_code: typeCode,
        type_description: describeTocTypeCode(typeCode),
        data_offset: absDataOffset,
        compressed_size: compressedSize,
        uncompressed_size: uncompressedSize,
        is_compressed: compressionFlag === 1,
      });

      if (typeCode === "s") {
        entryScripts.push(name);
        bundledModules.push(name);
      } else if (typeCode === "m" || typeCode === "M") {
        bundledModules.push(name);
      } else if (
        typeCode === "b" ||
        /\.(?:so|pyd|dll|dylib)(?:\.[0-9]+)*$/i.test(name)
      ) {
        nativeExtensions.push(name);
      } else if (typeCode === "z" || typeCode === "Z") {
        pyzTocDataOffset = absDataOffset;
      }

      cursor += entryLen;
    }
  }

  let pyzHeader: PythonFrozenBinaryReport["pyinstaller"]["pyz_header"] = null;
  const candidatePyzOffset =
    pyzTocDataOffset !== null &&
    pyzTocDataOffset >= 0 &&
    pyzTocDataOffset + 12 <= buf.length &&
    buf.subarray(pyzTocDataOffset, pyzTocDataOffset + 4).equals(PYZ_MAGIC)
      ? pyzTocDataOffset
      : buf.indexOf(PYZ_MAGIC);

  if (candidatePyzOffset >= 0 && candidatePyzOffset + 12 <= buf.length) {
    const pyzMagicHex = buf
      .subarray(candidatePyzOffset + 4, candidatePyzOffset + 8)
      .toString("hex");
    const pyzInternalTocOffset = buf.readUInt32BE(candidatePyzOffset + 8);
    pyzHeader = {
      offset: candidatePyzOffset,
      python_magic_hex: pyzMagicHex,
      toc_offset: pyzInternalTocOffset,
    };
  }

  return {
    detected: true,
    cookie_offset: cookieOffset,
    archive_size: pkgLen,
    toc_offset: absTocOffset,
    toc_length: tocLen,
    python_version: formatPyinstallerVersion(pyvers),
    pylib_name: pylibName,
    entry_scripts: [...new Set(entryScripts)],
    native_extensions: [...new Set(nativeExtensions)],
    bundled_modules: [...new Set(bundledModules)],
    toc_entries: tocEntries,
    pyz_header: pyzHeader,
  };
}

// ---------------------------------------------------------------------------
// Python .pyc Header & Pure-TS Marshal Code-Object Reader
// ---------------------------------------------------------------------------

function estimatePythonVersionFromMagic(magicNumber: number): string | null {
  if (magicNumber >= 3390 && magicNumber <= 3399) return "3.7";
  if (magicNumber >= 3400 && magicNumber <= 3419) return "3.8";
  if (magicNumber >= 3420 && magicNumber <= 3429) return "3.9";
  if (magicNumber >= 3430 && magicNumber <= 3449) return "3.10";
  if (magicNumber >= 3450 && magicNumber <= 3509) return "3.11";
  if (magicNumber >= 3510 && magicNumber <= 3549) return "3.12";
  if (magicNumber >= 3550 && magicNumber <= 3599) return "3.13";
  if (magicNumber >= 3600 && magicNumber <= 3750) return "3.14";
  return null;
}

class MarshalReader {
  private offset: number;
  private readonly refs: unknown[] = [];
  readonly codeObjects: PycCodeObjectSummary[] = [];
  readonly allStrings: string[] = [];

  constructor(
    private readonly buf: Buffer,
    startOffset: number,
    private readonly magicNumber: number,
    private readonly maxCodeObjects: number,
  ) {
    this.offset = startOffset;
  }

  private ensure(bytes: number): boolean {
    return this.offset + bytes <= this.buf.length;
  }

  private readU8(): number {
    if (!this.ensure(1)) throw new Error("EOF");
    const v = this.buf[this.offset]!;
    this.offset += 1;
    return v;
  }

  private readI32(): number {
    if (!this.ensure(4)) throw new Error("EOF");
    const v = this.buf.readInt32LE(this.offset);
    this.offset += 4;
    return v;
  }

  private readBytes(len: number): Buffer {
    if (len < 0 || !this.ensure(len)) throw new Error("EOF");
    const slice = this.buf.subarray(this.offset, this.offset + len);
    this.offset += len;
    return slice;
  }

  readObject(): unknown {
    const rawByte = this.readU8();
    const flagRef = (rawByte & 0x80) !== 0;
    const typeChar = String.fromCharCode(rawByte & 0x7f);

    let refIdx = -1;
    if (flagRef) {
      refIdx = this.refs.length;
      this.refs.push(null);
    }

    const storeRef = <T>(val: T): T => {
      if (refIdx >= 0) {
        this.refs[refIdx] = val;
      }
      return val;
    };

    switch (typeChar) {
      case "0":
      case "N":
      case "F":
      case "T":
      case "S":
      case ".":
        return storeRef(null);

      case "i":
        return storeRef(this.readI32());

      case "I":
      case "g": {
        this.readBytes(8);
        return storeRef(0);
      }

      case "l": {
        const n = this.readI32();
        const count = Math.abs(n);
        this.readBytes(count * 2);
        return storeRef(0);
      }

      case "y": {
        this.readBytes(16);
        return storeRef(0);
      }

      case "s": {
        const len = this.readI32();
        const bytes = this.readBytes(len);
        return storeRef(bytes);
      }

      case "u":
      case "t":
      case "a":
      case "A": {
        const len = this.readI32();
        const str = this.readBytes(len).toString("utf8");
        this.allStrings.push(str);
        return storeRef(str);
      }

      case "z":
      case "Z": {
        const len = this.readU8();
        const str = this.readBytes(len).toString("utf8");
        this.allStrings.push(str);
        return storeRef(str);
      }

      case ")": {
        const count = this.readU8();
        const arr: unknown[] = [];
        if (refIdx >= 0) this.refs[refIdx] = arr;
        for (let i = 0; i < count; i++) {
          arr.push(this.readObject());
        }
        return arr;
      }

      case "(":
      case "[":
      case "<":
      case ">": {
        const count = this.readI32();
        if (count < 0 || count > 100_000) throw new Error("Invalid sequence");
        const arr: unknown[] = [];
        if (refIdx >= 0) this.refs[refIdx] = arr;
        for (let i = 0; i < count; i++) {
          arr.push(this.readObject());
        }
        return arr;
      }

      case "{": {
        const dict: Record<string, unknown> = {};
        if (refIdx >= 0) this.refs[refIdx] = dict;
        while (this.offset < this.buf.length) {
          const nextPeak = this.buf[this.offset]! & 0x7f;
          if (String.fromCharCode(nextPeak) === "0") {
            this.offset += 1;
            break;
          }
          const k = this.readObject();
          const v = this.readObject();
          if (typeof k === "string") dict[k] = v;
        }
        return dict;
      }

      case "r": {
        const idx = this.readI32();
        if (idx < 0 || idx >= this.refs.length) {
          throw new Error("Invalid marshal ref");
        }
        return this.refs[idx];
      }

      case "c": {
        return storeRef(this.readCodeObject());
      }

      default:
        throw new Error(`Unsupported marshal tag: ${typeChar}`);
    }
  }

  private readCodeObject(): PycCodeObjectSummary {
    const isPy311Plus = this.magicNumber >= 3495;
    const argcount = Math.max(0, this.readI32());
    const _posonlyargcount = this.readI32();
    const _kwonlyargcount = this.readI32();
    if (!isPy311Plus) {
      const _nlocals = this.readI32();
      void _nlocals;
    }
    const _stacksize = this.readI32();
    const _flags = this.readI32();
    void _posonlyargcount;
    void _kwonlyargcount;
    void _stacksize;
    void _flags;

    const codeObj = this.readObject();
    const bytecodeLength = Buffer.isBuffer(codeObj) ? codeObj.length : 0;

    const constsObj = this.readObject();
    const namesObj = this.readObject();

    let varnamesObj: unknown;
    if (isPy311Plus) {
      // localsplusnames + localspluskinds
      varnamesObj = this.readObject();
      const _localspluskinds = this.readObject();
      void _localspluskinds;
    } else {
      varnamesObj = this.readObject();
      const _freevars = this.readObject();
      const _cellvars = this.readObject();
      void _freevars;
      void _cellvars;
    }

    const filenameObj = this.readObject();
    const nameObj = this.readObject();
    if (isPy311Plus) {
      const _qualnameObj = this.readObject();
      void _qualnameObj;
    }
    const firstlineno = Math.max(0, this.readI32());
    const _linetable = this.readObject();
    void _linetable;
    if (isPy311Plus) {
      const _exceptiontable = this.readObject();
      void _exceptiontable;
    }

    const stringConstants: string[] = [];
    if (Array.isArray(constsObj)) {
      for (const c of constsObj) {
        if (typeof c === "string" && c.length > 0) {
          stringConstants.push(c);
        }
      }
    }

    const names = Array.isArray(namesObj)
      ? namesObj.filter((x): x is string => typeof x === "string")
      : [];
    const varnames = Array.isArray(varnamesObj)
      ? varnamesObj.filter((x): x is string => typeof x === "string")
      : [];

    const summary: PycCodeObjectSummary = {
      co_name: typeof nameObj === "string" ? nameObj : "<module>",
      co_filename: typeof filenameObj === "string" ? filenameObj : "<unknown>",
      co_firstlineno: firstlineno,
      argcount,
      names,
      varnames,
      string_constants: stringConstants,
      bytecode_length: bytecodeLength,
    };

    if (this.codeObjects.length < this.maxCodeObjects) {
      this.codeObjects.push(summary);
    }
    return summary;
  }
}

function fallbackScanMarshalStrings(buf: Buffer, startOffset: number): {
  strings: string[];
  codeObject: PycCodeObjectSummary;
} {
  const strings: string[] = [];
  let i = startOffset;
  while (i < buf.length - 2) {
    const tag = buf[i]! & 0x7f;
    const ch = String.fromCharCode(tag);
    if (ch === "z" || ch === "Z") {
      const len = buf[i + 1]!;
      if (len > 0 && len <= 255 && i + 2 + len <= buf.length) {
        const candidate = buf.subarray(i + 2, i + 2 + len).toString("utf8");
        if (/^[\x20-\x7e]+$/.test(candidate)) {
          strings.push(candidate);
          i += 2 + len;
          continue;
        }
      }
    } else if (ch === "u" || ch === "t" || ch === "a" || ch === "A") {
      if (i + 5 <= buf.length) {
        const len = buf.readInt32LE(i + 1);
        if (len > 0 && len <= 1024 && i + 5 + len <= buf.length) {
          const candidate = buf.subarray(i + 5, i + 5 + len).toString("utf8");
          if (/^[\x20-\x7e\r\n\t]+$/.test(candidate)) {
            strings.push(candidate);
            i += 5 + len;
            continue;
          }
        }
      }
    }
    i++;
  }

  const pyFile =
    strings.find((s) => s.endsWith(".py") || s.includes("/")) ?? "<unknown>";
  const coName =
    strings.find((s) => s === "<module>" || /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(s)) ??
    "<module>";
  const identifiers = strings.filter((s) =>
    /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(s),
  );

  return {
    strings,
    codeObject: {
      co_name: coName,
      co_filename: pyFile,
      co_firstlineno: 1,
      argcount: 0,
      names: [...new Set(identifiers)],
      varnames: [],
      string_constants: [...new Set(strings)],
      bytecode_length: Math.max(0, buf.length - startOffset),
    },
  };
}

function parsePycBytecode(
  buf: Buffer,
  maxCodeObjects: number,
): PythonFrozenBinaryReport["pyc"] | null {
  if (buf.length < 16) return null;
  if (buf[2] !== 0x0d || buf[3] !== 0x0a) return null;

  const magicNumber = buf.readUInt16LE(0);
  if (magicNumber < 3000 || magicNumber > 4000) return null;

  const magicHex = buf.subarray(0, 4).toString("hex");
  const versionEstimate = estimatePythonVersionFromMagic(magicNumber);
  const pep552Flags = buf.readUInt32LE(4);
  const isTimestampBased = (pep552Flags & 1) === 0;
  const sourceTimestamp = isTimestampBased ? buf.readUInt32LE(8) : null;
  const sourceSize = isTimestampBased ? buf.readUInt32LE(12) : null;

  const reader = new MarshalReader(buf, 16, magicNumber, maxCodeObjects);
  try {
    reader.readObject();
  } catch {
    // If marshal stream encountered a non-standard tag or minor layout variation,
    // use fallback string/code-object scanner if no codeObjects were decoded yet.
    if (reader.codeObjects.length === 0) {
      const fb = fallbackScanMarshalStrings(buf, 16);
      reader.codeObjects.push(fb.codeObject);
    }
  }

  // Reverse codeObjects so outer `<module>` comes first if inner functions were pushed first
  const codeObjects = [...reader.codeObjects].reverse();
  const importedNames = new Set<string>();
  for (const co of codeObjects) {
    for (const n of co.names) {
      importedNames.add(n);
    }
  }

  return {
    detected: true,
    magic_number: magicNumber,
    magic_hex: magicHex,
    python_version_estimate: versionEstimate,
    pep552_flags: pep552Flags,
    source_timestamp: sourceTimestamp,
    source_size: sourceSize,
    imported_names: [...importedNames],
    code_objects: codeObjects,
  };
}

export class PythonFrozenBinaryInspector implements PythonFrozenBinaryPort {
  readonly identity: ProviderIdentity = PYTHON_FROZEN_PROVIDER_IDENTITY;

  async inspect(
    input: InspectPythonFrozenBinaryInput,
    options?: ExecutionOptions,
  ): Promise<Result<PythonFrozenBinaryReport, AnalysisError>> {
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
            message: `Unable to read file at ${input.path}`,
          },
        ]),
      );
    }

    if (options?.signal?.aborted) {
      return err(new AnalysisCancelledError(OPERATION));
    }

    const pyinstaller = parsePyinstallerArchive(
      buf,
      input.max_toc_entries ?? 1000,
    );
    const pyc =
      pyinstaller === null
        ? parsePycBytecode(buf, input.max_code_objects ?? 200)
        : null;

    if (!pyinstaller && !pyc) {
      return err(
        new AnalysisUnsupportedTargetError(
          OPERATION,
          input.path,
          "Artifact is neither a PyInstaller CArchive executable nor a valid Python .pyc bytecode file.",
        ),
      );
    }

    const sha256 = createHash("sha256").update(buf).digest("hex");

    const report: PythonFrozenBinaryReport = {
      artifact: {
        path: input.path,
        sha256,
        size_bytes: buf.length,
      },
      container_format: pyinstaller
        ? "pyinstaller-executable"
        : "pyc-bytecode",
      pyinstaller: pyinstaller ?? {
        detected: false,
        cookie_offset: null,
        archive_size: null,
        toc_offset: null,
        toc_length: null,
        python_version: null,
        pylib_name: null,
        entry_scripts: [],
        native_extensions: [],
        bundled_modules: [],
        toc_entries: [],
        pyz_header: null,
      },
      pyc: pyc ?? {
        detected: false,
        magic_number: null,
        magic_hex: null,
        python_version_estimate: null,
        pep552_flags: null,
        source_timestamp: null,
        source_size: null,
        imported_names: [],
        code_objects: [],
      },
      limitations: [],
    };

    const parsed = pythonFrozenBinarySchema.safeParse(report);
    if (!parsed.success) {
      return err(new AnalysisOutputError(OPERATION, parsed.error.message));
    }

    return ok(parsed.data);
  }
}
