import { createHash } from "node:crypto";
import { open, type FileHandle } from "node:fs/promises";
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
  ENGINE_ARCHIVE_PROVIDER_IDENTITY,
  engineArchiveReportSchema,
  type ElectronAsarEntry,
  type ElectronAsarSummary,
  type EngineArchiveReport,
  type GodotPackFileEntry,
  type GodotPackSummary,
  type Il2CppMetadataSummary,
  type Il2CppMethodDescriptor,
  type Il2CppStringLiteral,
  type Il2CppTypeDescriptor,
  type InspectEngineArchiveInput,
} from "../../domain/engineArchive/engineArchive.js";
import { err, ok, type Result } from "../../domain/result.js";

const OPERATION = "inspect_engine_archive";
const IL2CPP_MAGIC = 0xfab11baf;
const GODOT_PCK_MAGIC = 0x43504447; // "GDPC" in little-endian
const STREAM_HASH_CHUNK_BYTES = 4 * 1024 * 1024;
const DIRECT_READ_THRESHOLD_BYTES = 32 * 1024 * 1024;

export interface EngineArchivePort {
  readonly identity: ProviderIdentity;
  inspect(
    input: InspectEngineArchiveInput,
    options?: ExecutionOptions,
  ): Promise<Result<EngineArchiveReport, AnalysisError>>;
}

async function readExactRange(
  handle: FileHandle,
  position: number,
  length: number,
): Promise<Buffer> {
  const target = Buffer.allocUnsafe(length);
  let totalRead = 0;
  while (totalRead < length) {
    const { bytesRead } = await handle.read(
      target,
      totalRead,
      length - totalRead,
      position + totalRead,
    );
    if (bytesRead === 0) break;
    totalRead += bytesRead;
  }
  return totalRead === length ? target : target.subarray(0, totalRead);
}

async function computeStreamingSha256(
  handle: FileHandle,
  sizeBytes: number,
  signal?: AbortSignal,
): Promise<string> {
  const hash = createHash("sha256");
  const chunkBuf = Buffer.allocUnsafe(
    Math.min(STREAM_HASH_CHUNK_BYTES, Math.max(1, sizeBytes)),
  );
  let offset = 0;
  while (offset < sizeBytes) {
    if (signal?.aborted) {
      throw new AnalysisCancelledError(OPERATION);
    }
    const toRead = Math.min(chunkBuf.length, sizeBytes - offset);
    const { bytesRead } = await handle.read(chunkBuf, 0, toRead, offset);
    if (bytesRead === 0) break;
    hash.update(
      bytesRead === chunkBuf.length
        ? chunkBuf
        : chunkBuf.subarray(0, bytesRead),
    );
    offset += bytesRead;
  }
  return hash.digest("hex");
}

interface RawAsarNode {
  files?: Record<string, RawAsarNode>;
  size?: number;
  offset?: string | number;
  unpacked?: boolean;
  executable?: boolean;
  integrity?: {
    algorithm?: string;
    hash?: string;
  };
}

async function parseElectronAsar(
  handle: FileHandle,
  headerBuf: Buffer,
  sizeBytes: number,
  input: InspectEngineArchiveInput,
): Promise<{ summary: ElectronAsarSummary; version: string } | null> {
  if (sizeBytes < 17 || headerBuf.length < 17) return null;
  const pickleIntSize = headerBuf.readUInt32LE(0);
  if (pickleIntSize !== 4) return null;

  const headerSize = headerBuf.readUInt32LE(4);
  const headerPayloadSize = headerBuf.readUInt32LE(8);
  const jsonByteLength = headerBuf.readUInt32LE(12);
  void headerPayloadSize;

  if (
    jsonByteLength <= 0 ||
    jsonByteLength > 32 * 1024 * 1024 ||
    16 + jsonByteLength > sizeBytes ||
    headerBuf[16] !== 0x7b
  ) {
    return null;
  }

  const jsonBuf = await readExactRange(handle, 16, jsonByteLength);
  let rootNode: RawAsarNode;
  try {
    rootNode = JSON.parse(jsonBuf.toString("utf8")) as RawAsarNode;
  } catch {
    return null;
  }

  if (!rootNode || typeof rootNode !== "object" || !rootNode.files) {
    return null;
  }

  const maxFiles = input.max_files ?? 2_000;
  const files: ElectronAsarEntry[] = [];
  const nativeAddons: string[] = [];
  let totalFiles = 0;
  let totalDirectories = 0;
  let unpackedFiles = 0;

  let rootPkgOffset: number | null = null;
  let rootPkgSize = 0;
  let rootPkgUnpacked = false;

  const walk = (dirMap: Record<string, RawAsarNode>, prefix: string): void => {
    for (const [name, node] of Object.entries(dirMap)) {
      if (!node || typeof node !== "object") continue;
      const relPath = prefix ? `${prefix}/${name}` : name;
      if (node.files && typeof node.files === "object") {
        totalDirectories++;
        walk(node.files, relPath);
      } else {
        totalFiles++;
        const fileSize =
          typeof node.size === "number" && node.size >= 0
            ? Math.floor(node.size)
            : 0;
        const parsedOffset =
          typeof node.offset === "string"
            ? Number.parseInt(node.offset, 10)
            : typeof node.offset === "number"
              ? Math.floor(node.offset)
              : null;
        const cleanOffset =
          parsedOffset !== null &&
          Number.isFinite(parsedOffset) &&
          parsedOffset >= 0
            ? parsedOffset
            : null;
        const isUnpacked = Boolean(node.unpacked);
        const isExecutable = Boolean(node.executable);
        const integrityHash =
          typeof node.integrity?.hash === "string"
            ? node.integrity.hash
            : null;

        if (isUnpacked) {
          unpackedFiles++;
        }
        if (/\.(?:node|dll|so|dylib)$/i.test(relPath)) {
          nativeAddons.push(relPath);
        }
        if (relPath === "package.json") {
          rootPkgOffset = cleanOffset;
          rootPkgSize = fileSize;
          rootPkgUnpacked = isUnpacked;
        }
        if (files.length < maxFiles) {
          files.push({
            path: relPath,
            size_bytes: fileSize,
            offset: cleanOffset,
            unpacked: isUnpacked,
            is_executable: isExecutable,
            integrity_hash: integrityHash,
          });
        }
      }
    }
  };

  walk(rootNode.files, "");

  let mainEntryScript: string | null = null;
  let versionLabel = "asar-v1";
  const dataBaseOffset = 8 + headerSize;

  if (
    !rootPkgUnpacked &&
    rootPkgOffset !== null &&
    rootPkgSize > 0 &&
    rootPkgSize <= 262_144 &&
    dataBaseOffset + rootPkgOffset + rootPkgSize <= sizeBytes
  ) {
    try {
      const pkgBuf = await readExactRange(
        handle,
        dataBaseOffset + rootPkgOffset,
        rootPkgSize,
      );
      const pkgJson = JSON.parse(pkgBuf.toString("utf8")) as {
        main?: unknown;
        version?: unknown;
      };
      if (typeof pkgJson.main === "string" && pkgJson.main.trim().length > 0) {
        mainEntryScript = pkgJson.main.trim();
      }
      if (
        typeof pkgJson.version === "string" &&
        pkgJson.version.trim().length > 0
      ) {
        versionLabel = `asar-v1 (package v${pkgJson.version.trim()})`;
      }
    } catch {
      // Ignore malformed embedded package.json
    }
  }

  return {
    version: versionLabel,
    summary: {
      header_size_bytes: jsonByteLength,
      total_files: totalFiles,
      total_directories: totalDirectories,
      unpacked_files: unpackedFiles,
      main_entry_script: mainEntryScript,
      native_addons: nativeAddons,
      files,
    },
  };
}

function isPrintableIdentifier(str: string, allowEmpty: boolean): boolean {
  if (str.length === 0) return allowEmpty;
  if (str.length > 512) return false;
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    if (c < 0x20 || c > 0x7e) return false;
  }
  return true;
}

function parseIl2CppMetadata(
  buf: Buffer,
  input: InspectEngineArchiveInput,
): Il2CppMetadataSummary | null {
  if (buf.length < 64 || buf.readUInt32LE(0) !== IL2CPP_MAGIC) {
    return null;
  }

  const metadataVersion = buf.readInt32LE(4);
  if (metadataVersion <= 0 || metadataVersion > 100) {
    return null;
  }

  const stringLiteralOffset = buf.readInt32LE(8);
  const stringLiteralSize = buf.readInt32LE(12);
  const stringLiteralDataOffset = buf.readInt32LE(16);
  const stringLiteralDataSize = buf.readInt32LE(20);
  const stringOffset = buf.readInt32LE(24);
  const stringSize = buf.readInt32LE(28);

  if (
    stringOffset < 32 ||
    stringSize < 0 ||
    stringOffset + stringSize > buf.length
  ) {
    return null;
  }

  // Determine header end by finding the smallest positive section offset
  let headerEnd = Math.min(stringOffset, buf.length);
  if (stringLiteralOffset >= 32 && stringLiteralOffset < headerEnd) {
    headerEnd = stringLiteralOffset;
  }
  if (stringLiteralDataOffset >= 32 && stringLiteralDataOffset < headerEnd) {
    headerEnd = stringLiteralDataOffset;
  }
  for (let off = 32; off + 8 <= headerEnd && off < 512; off += 8) {
    const secOff = buf.readInt32LE(off);
    const secSize = buf.readInt32LE(off + 4);
    if (
      secOff >= 32 &&
      secSize > 0 &&
      secOff + secSize <= buf.length &&
      secOff < headerEnd
    ) {
      headerEnd = secOff;
    }
  }

  const readIdentifier = (strIndex: number): string | null => {
    if (strIndex < 0 || strIndex >= stringSize) return null;
    const absStart = stringOffset + strIndex;
    const absEnd = Math.min(buf.length, stringOffset + stringSize);
    let end = absStart;
    while (end < absEnd && buf[end] !== 0) {
      end++;
    }
    return buf.subarray(absStart, end).toString("utf8");
  };

  const isStringBoundary = (strIndex: number): boolean => {
    if (strIndex < 0 || strIndex >= stringSize) return false;
    if (strIndex === 0) return true;
    return buf[stringOffset + strIndex - 1] === 0;
  };

  // 1. Decode string literals
  const stringLiterals: Il2CppStringLiteral[] = [];
  let totalStringLiterals = 0;
  if (
    stringLiteralOffset >= 32 &&
    stringLiteralSize >= 0 &&
    stringLiteralOffset + stringLiteralSize <= buf.length &&
    stringLiteralDataOffset >= 32 &&
    stringLiteralDataSize >= 0 &&
    stringLiteralDataOffset + stringLiteralDataSize <= buf.length
  ) {
    totalStringLiterals = Math.floor(stringLiteralSize / 8);
    const maxStrings = Math.min(
      totalStringLiterals,
      input.max_strings ?? 1_000,
    );
    for (let i = 0; i < maxStrings; i++) {
      const entryOff = stringLiteralOffset + i * 8;
      const len = buf.readUInt32LE(entryOff);
      const dataIdx = buf.readInt32LE(entryOff + 4);
      if (dataIdx >= 0 && dataIdx + len <= stringLiteralDataSize) {
        const val = buf
          .subarray(
            stringLiteralDataOffset + dataIdx,
            stringLiteralDataOffset + dataIdx + len,
          )
          .toString("utf8");
        stringLiterals.push({ index: i, value: val });
      }
    }
  }

  // Collect all valid (offset, size) sections from the header after byte 32
  interface HeaderSection {
    headerByteOffset: number;
    offset: number;
    size: number;
  }
  const extraSections: HeaderSection[] = [];
  for (let hOff = 32; hOff + 8 <= headerEnd; hOff += 8) {
    const secOff = buf.readInt32LE(hOff);
    const secSize = buf.readInt32LE(hOff + 4);
    if (secOff >= headerEnd && secSize > 0 && secOff + secSize <= buf.length) {
      extraSections.push({
        headerByteOffset: hOff,
        offset: secOff,
        size: secSize,
      });
    }
  }

  const readSectionAtHeaderOffset = (
    hOff: number,
  ): { offset: number; size: number } | null => {
    if (hOff + 8 > headerEnd) return null;
    const secOff = buf.readInt32LE(hOff);
    const secSize = buf.readInt32LE(hOff + 4);
    if (secOff >= headerEnd && secSize > 0 && secOff + secSize <= buf.length) {
      return { offset: secOff, size: secSize };
    }
    return null;
  };

  // Standard IL2CPP v24-v31 header offsets:
  // methods: byte 48, typeDefinitions: byte 168, images: byte 176
  let imagesSec = readSectionAtHeaderOffset(176);
  let typesSec = readSectionAtHeaderOffset(168);
  let methodsSec = readSectionAtHeaderOffset(48);

  // If compact header was used (e.g. headerEnd < 184), match remaining sections
  const claimedOffsets = new Set<number>();
  if (imagesSec) claimedOffsets.add(imagesSec.offset);
  if (typesSec) claimedOffsets.add(typesSec.offset);
  if (methodsSec) claimedOffsets.add(methodsSec.offset);

  for (const sec of extraSections) {
    if (claimedOffsets.has(sec.offset)) continue;
    const firstStr = readIdentifier(buf.readInt32LE(sec.offset));
    if (!imagesSec && firstStr && /\.(?:dll|exe)$/i.test(firstStr)) {
      imagesSec = { offset: sec.offset, size: sec.size };
      claimedOffsets.add(sec.offset);
    }
  }

  for (const sec of extraSections) {
    if (claimedOffsets.has(sec.offset)) continue;
    if (!typesSec) {
      typesSec = { offset: sec.offset, size: sec.size };
      claimedOffsets.add(sec.offset);
    } else if (!methodsSec) {
      methodsSec = { offset: sec.offset, size: sec.size };
      claimedOffsets.add(sec.offset);
    }
  }

  // 2. Decode Images
  const images: string[] = [];
  if (imagesSec) {
    const candidateImageStrides = [40, 44, 48, 36, 32, 28, 24, 20, 16];
    let imgStride = 40;
    for (const s of candidateImageStrides) {
      if (imagesSec.size % s !== 0) continue;
      const count = imagesSec.size / s;
      let allValid = true;
      for (let i = 0; i < count; i++) {
        const nameIdx = buf.readInt32LE(imagesSec.offset + i * s);
        const name = readIdentifier(nameIdx);
        if (
          !name ||
          !isStringBoundary(nameIdx) ||
          !isPrintableIdentifier(name, false)
        ) {
          allValid = false;
          break;
        }
      }
      if (allValid) {
        imgStride = s;
        break;
      }
    }
    const count = Math.floor(imagesSec.size / imgStride);
    for (let i = 0; i < count; i++) {
      const nameIdx = buf.readInt32LE(imagesSec.offset + i * imgStride);
      const name = readIdentifier(nameIdx);
      if (name && isPrintableIdentifier(name, false)) {
        images.push(name);
      }
    }
  }

  // Fallback: if images list is still empty, scan string table for .dll names
  if (images.length === 0 && stringSize > 0) {
    let cursor = stringOffset;
    const end = stringOffset + stringSize;
    while (cursor < end) {
      let nul = cursor;
      while (nul < end && buf[nul] !== 0) nul++;
      const s = buf.subarray(cursor, nul).toString("utf8");
      if (/^[A-Za-z0-9_.-]+\.dll$/i.test(s)) {
        images.push(s);
      }
      cursor = nul + 1;
    }
  }

  // 3. Decode TypeDefinitions
  const types: Il2CppTypeDescriptor[] = [];
  let totalTypes = 0;
  if (typesSec) {
    const candidateTypeStrides = [
      88, 92, 96, 100, 104, 84, 80, 72, 64, 40, 32, 24, 20, 16,
    ];
    let bestStride = 88;
    let bestCount = 0;

    for (const s of candidateTypeStrides) {
      if (typesSec.size % s !== 0) continue;
      const count = typesSec.size / s;
      let valid = true;
      for (let i = 0; i < count; i++) {
        const recOff = typesSec.offset + i * s;
        const nameIdx = buf.readInt32LE(recOff);
        const nsIdx = buf.readInt32LE(recOff + 4);
        const name = readIdentifier(nameIdx);
        const ns = readIdentifier(nsIdx);
        if (
          name === null ||
          ns === null ||
          !isStringBoundary(nameIdx) ||
          !isStringBoundary(nsIdx) ||
          !isPrintableIdentifier(name, false) ||
          !isPrintableIdentifier(ns, true)
        ) {
          valid = false;
          break;
        }
      }
      if (valid && count > bestCount) {
        bestStride = s;
        bestCount = count;
      }
    }

    totalTypes = Math.floor(typesSec.size / bestStride);
    const maxTypes = Math.min(totalTypes, input.max_types ?? 1_000);
    for (let i = 0; i < maxTypes; i++) {
      const recOff = typesSec.offset + i * bestStride;
      const nameIdx = buf.readInt32LE(recOff);
      const nsIdx = buf.readInt32LE(recOff + 4);
      const name = readIdentifier(nameIdx) || `Type_${String(i)}`;
      const namespace = readIdentifier(nsIdx) ?? "";
      const fullName = namespace.length > 0 ? `${namespace}.${name}` : name;

      let methodCount = 0;
      let fieldCount = 0;
      let bitfield = 0;

      if (bestStride >= 80) {
        methodCount = buf.readUInt16LE(recOff + bestStride - 24);
        const fcA = buf.readUInt16LE(recOff + bestStride - 26);
        const fcB = buf.readUInt16LE(recOff + bestStride - 18);
        fieldCount = fcA > 0 && fcA < 10000 ? fcA : fcB < 10000 ? fcB : 0;
        bitfield = buf.readUInt32LE(recOff + bestStride - 8);
      } else if (bestStride >= 24) {
        bitfield = buf.readUInt32LE(recOff + 8);
        methodCount = buf.readUInt16LE(recOff + 12);
        fieldCount = buf.readUInt16LE(recOff + 14);
        if (methodCount === 0 && fieldCount === 0 && bestStride >= 24) {
          methodCount = buf.readUInt16LE(recOff + 16);
          fieldCount = buf.readUInt16LE(recOff + 20);
        }
      }

      types.push({
        type_index: i,
        namespace,
        name,
        full_name: fullName,
        is_value_type: (bitfield & 1) !== 0,
        is_enum: (bitfield & 2) !== 0,
        method_count: methodCount,
        field_count: fieldCount,
      });
    }
  }

  // 4. Decode MethodDefinitions
  const methods: Il2CppMethodDescriptor[] = [];
  let totalMethods = 0;
  if (methodsSec) {
    const candidateMethodStrides = [28, 32, 36, 40, 24, 20, 16];
    let bestStride = 28;
    let bestCount = 0;

    for (const s of candidateMethodStrides) {
      if (methodsSec.size % s !== 0) continue;
      const count = methodsSec.size / s;
      let valid = true;
      for (let i = 0; i < count; i++) {
        const recOff = methodsSec.offset + i * s;
        const nameIdx = buf.readInt32LE(recOff);
        const declTypeIdx = buf.readInt32LE(recOff + 4);
        const name = readIdentifier(nameIdx);
        if (
          name === null ||
          !isStringBoundary(nameIdx) ||
          !isPrintableIdentifier(name, false) ||
          declTypeIdx < -1 ||
          (totalTypes > 0 && declTypeIdx >= totalTypes)
        ) {
          valid = false;
          break;
        }
      }
      if (valid && count > bestCount) {
        bestStride = s;
        bestCount = count;
      }
    }

    totalMethods = Math.floor(methodsSec.size / bestStride);
    const maxMethods = Math.min(totalMethods, input.max_methods ?? 2_000);
    for (let i = 0; i < maxMethods; i++) {
      const recOff = methodsSec.offset + i * bestStride;
      const nameIdx = buf.readInt32LE(recOff);
      const declTypeIdx = buf.readInt32LE(recOff + 4);
      const name = readIdentifier(nameIdx) || `Method_${String(i)}`;
      const declaringType =
        declTypeIdx >= 0 && declTypeIdx < types.length
          ? types[declTypeIdx]!.full_name
          : `Type_${String(Math.max(0, declTypeIdx))}`;

      let tokenVal = 0;
      for (let off = 8; off + 4 <= bestStride; off += 4) {
        const v = buf.readUInt32LE(recOff + off);
        if (v >>> 24 === 0x06) {
          tokenVal = v;
          break;
        }
      }
      if (tokenVal === 0 && bestStride >= 16) {
        tokenVal = buf.readUInt32LE(recOff + bestStride - 12);
      }
      if (tokenVal === 0) {
        tokenVal = 0x06000001 + i;
      }

      const paramCount =
        bestStride >= 16 ? buf.readUInt16LE(recOff + bestStride - 2) : 0;

      methods.push({
        method_index: i,
        name,
        declaring_type: declaringType,
        parameter_count: paramCount < 256 ? paramCount : 0,
        token: `0x${tokenVal.toString(16).padStart(8, "0")}`,
      });
    }
  }

  return {
    metadata_version: metadataVersion,
    images,
    total_types: totalTypes,
    total_methods: totalMethods,
    total_string_literals: totalStringLiterals,
    types,
    methods,
    string_literals: stringLiterals,
  };
}

function parseGodotPck(
  buf: Buffer,
  input: InspectEngineArchiveInput,
): GodotPackSummary | null {
  let pckStart = -1;
  if (buf.length >= 88 && buf.readUInt32LE(0) === GODOT_PCK_MAGIC) {
    pckStart = 0;
  } else if (
    buf.length >= 100 &&
    buf.readUInt32LE(buf.length - 4) === GODOT_PCK_MAGIC
  ) {
    const embeddedSize = Number(buf.readBigUInt64LE(buf.length - 12));
    const candidateStart = buf.length - 12 - embeddedSize;
    if (
      candidateStart >= 0 &&
      candidateStart + 88 <= buf.length &&
      buf.readUInt32LE(candidateStart) === GODOT_PCK_MAGIC
    ) {
      pckStart = candidateStart;
    } else if (
      embeddedSize >= 0 &&
      buf.length - embeddedSize >= 0 &&
      buf.readUInt32LE(buf.length - embeddedSize) === GODOT_PCK_MAGIC
    ) {
      pckStart = buf.length - embeddedSize;
    }
  }

  if (pckStart < 0 || pckStart + 88 > buf.length) {
    return null;
  }

  const packFormatVersion = buf.readUInt32LE(pckStart + 4);
  if (packFormatVersion > 10) {
    return null;
  }
  const major = buf.readUInt32LE(pckStart + 8);
  const minor = buf.readUInt32LE(pckStart + 12);
  const patch = buf.readUInt32LE(pckStart + 16);
  const engineVersion = `${String(major)}.${String(minor)}.${String(patch)}`;

  let flags = 0;
  let fileBaseOffset = 0;
  let fileCount = 0;
  let cursor = 0;

  if (packFormatVersion >= 2) {
    if (pckStart + 100 > buf.length) return null;
    flags = buf.readUInt32LE(pckStart + 20);
    fileBaseOffset = Number(buf.readBigUInt64LE(pckStart + 24));
    fileCount = buf.readUInt32LE(pckStart + 96);
    cursor = pckStart + 100;
  } else {
    fileCount = buf.readUInt32LE(pckStart + 84);
    cursor = pckStart + 88;
  }

  const files: GodotPackFileEntry[] = [];
  const maxFiles = Math.min(fileCount, input.max_files ?? 2_000);

  for (let i = 0; i < fileCount; i++) {
    if (cursor + 4 > buf.length) break;
    const pathLen = buf.readUInt32LE(cursor);
    cursor += 4;
    if (pathLen === 0 || pathLen > 4096 || cursor + pathLen + 32 > buf.length) {
      break;
    }

    const rawPath = buf
      .subarray(cursor, cursor + pathLen)
      .toString("utf8")
      .replace(/\0+$/, "");
    cursor += pathLen;

    const normalizedPath = rawPath.startsWith("res://")
      ? rawPath
      : `res://${rawPath.replace(/^\/+/, "")}`;

    const offset = Number(buf.readBigUInt64LE(cursor));
    cursor += 8;
    const sizeBytes = Number(buf.readBigUInt64LE(cursor));
    cursor += 8;
    const md5Hex = buf.subarray(cursor, cursor + 16).toString("hex");
    cursor += 16;

    let encrypted = false;
    if (packFormatVersion >= 2) {
      if (cursor + 4 > buf.length) break;
      const entryFlags = buf.readUInt32LE(cursor);
      cursor += 4;
      encrypted = (entryFlags & 1) !== 0;
    }

    if (files.length < maxFiles) {
      files.push({
        path: normalizedPath,
        offset,
        size_bytes: sizeBytes,
        md5_hex: md5Hex,
        encrypted,
      });
    }
  }

  return {
    pack_format_version: packFormatVersion,
    engine_version: engineVersion,
    flags,
    file_base_offset: fileBaseOffset,
    file_count: fileCount,
    files,
  };
}

export class EngineArchiveInspector implements EngineArchivePort {
  readonly identity: ProviderIdentity = ENGINE_ARCHIVE_PROVIDER_IDENTITY;

  async inspect(
    input: InspectEngineArchiveInput,
    options?: ExecutionOptions,
  ): Promise<Result<EngineArchiveReport, AnalysisError>> {
    if (options?.signal?.aborted) {
      return err(new AnalysisCancelledError(OPERATION));
    }

    const effectiveInput: InspectEngineArchiveInput = {
      ...input,
      max_files: input.max_entries ?? input.max_files,
    };

    let handle: FileHandle;
    try {
      handle = await open(effectiveInput.path, "r");
    } catch (cause) {
      const code = (cause as NodeJS.ErrnoException | undefined)?.code;
      if (code === "EACCES" || code === "EPERM") {
        return err(
          new AnalysisAccessDeniedError(OPERATION, effectiveInput.path, code, {
            cause,
          }),
        );
      }
      return err(
        new AnalysisInputError(OPERATION, { cause }, [
          {
            path: ["path"],
            reason: "invalid_value",
            message: `Unable to open engine archive at ${effectiveInput.path}`,
          },
        ]),
      );
    }

    try {
      const st = await handle.stat();
      if (!st.isFile()) {
        return err(
          new AnalysisInputError(OPERATION, undefined, [
            {
              path: ["path"],
              reason: "invalid_value",
              message: `Path is not a regular file: ${effectiveInput.path}`,
            },
          ]),
        );
      }

      const sizeBytes = st.size;
      const headerBuf = await readExactRange(
        handle,
        0,
        Math.min(64, sizeBytes),
      );

      if (options?.signal?.aborted) {
        return err(new AnalysisCancelledError(OPERATION));
      }

      // 1. Check for Electron .asar (Chromium Pickle Header)
      const asarResult = await parseElectronAsar(
        handle,
        headerBuf,
        sizeBytes,
        effectiveInput,
      );
      if (asarResult !== null) {
        const sha256 = await computeStreamingSha256(
          handle,
          sizeBytes,
          options?.signal,
        );
        const report: EngineArchiveReport = {
          path: effectiveInput.path,
          sha256,
          size_bytes: sizeBytes,
          archive_format: "electron-asar",
          version: asarResult.version,
          il2cpp: null,
          godot_pck: null,
          asar: asarResult.summary,
        };
        const parsed = engineArchiveReportSchema.safeParse(report);
        if (!parsed.success) {
          return err(new AnalysisOutputError(OPERATION, parsed.error.message));
        }
        return ok(parsed.data);
      }

      // 2. Check Unity IL2CPP global-metadata.dat or Godot .pck
      let buf: Buffer;
      let sha256: string;
      if (sizeBytes <= DIRECT_READ_THRESHOLD_BYTES) {
        buf = await readExactRange(handle, 0, sizeBytes);
        sha256 = createHash("sha256").update(buf).digest("hex");
      } else {
        // For files > 32 MiB, stream sha256 and read bounded header/table slice
        sha256 = await computeStreamingSha256(
          handle,
          sizeBytes,
          options?.signal,
        );
        buf = await readExactRange(
          handle,
          0,
          Math.min(sizeBytes, DIRECT_READ_THRESHOLD_BYTES),
        );
      }

      const il2cpp = parseIl2CppMetadata(buf, effectiveInput);
      const godotPck =
        il2cpp === null ? parseGodotPck(buf, effectiveInput) : null;

      if (!il2cpp && !godotPck) {
        return err(
          new AnalysisUnsupportedTargetError(
            OPERATION,
            input.path,
            "Unsupported game engine archive format (expected Unity IL2CPP global-metadata.dat, Godot .pck, or Electron .asar).",
          ),
        );
      }

      const report: EngineArchiveReport = {
        path: input.path,
        sha256,
        size_bytes: sizeBytes,
        archive_format: il2cpp ? "unity-il2cpp-metadata" : "godot-pck",
        version: il2cpp
          ? String(il2cpp.metadata_version)
          : godotPck!.engine_version,
        il2cpp: il2cpp ?? null,
        godot_pck: godotPck ?? null,
        asar: null,
      };

      const parsed = engineArchiveReportSchema.safeParse(report);
      if (!parsed.success) {
        return err(new AnalysisOutputError(OPERATION, parsed.error.message));
      }

      return ok(parsed.data);
    } catch (cause) {
      if (cause instanceof AnalysisCancelledError) {
        return err(cause);
      }
      return err(
        new AnalysisInputError(OPERATION, { cause }, [
          {
            path: ["path"],
            reason: "invalid_value",
            message: `Failed reading engine archive at ${input.path}`,
          },
        ]),
      );
    } finally {
      await handle.close().catch(() => undefined);
    }
  }
}
