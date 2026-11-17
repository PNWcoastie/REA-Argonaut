export interface RawElfRelocation {
  readonly rOffset: bigint;
  readonly rInfo: bigint;
  readonly rAddend: bigint;
}

export interface RecoveredJniMethod {
  readonly methodName: string;
  readonly signature: string;
  readonly fnAddress: bigint;
}

export interface CppLinkerTrapFilterResult {
  readonly trapped: boolean;
  readonly trapKind: string | null;
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

/**
 * Decodes standard ELF SHT_RELR (.relr.dyn, sh_type = 19 / 0x6fffff00)
 * relative relocation address bitmaps into relocated virtual addresses.
 */
export function decodeElfRelrRelocations(
  secBytes: Uint8Array,
  is64Bit: boolean,
  littleEndian: boolean,
): bigint[] {
  const wordSize = is64Bit ? 8 : 4;
  const wordBits = wordSize * 8;
  if (secBytes.length < wordSize) return [];

  const view = new DataView(
    secBytes.buffer,
    secBytes.byteOffset,
    secBytes.byteLength,
  );
  const offsets: bigint[] = [];
  let base = 0n;
  let hasBase = false;

  for (let off = 0; off + wordSize <= secBytes.length; off += wordSize) {
    const entry = is64Bit
      ? view.getBigUint64(off, littleEndian)
      : BigInt(view.getUint32(off, littleEndian));

    if ((entry & 1n) === 0n) {
      offsets.push(entry);
      base = entry + BigInt(wordSize);
      hasBase = true;
    } else if (hasBase) {
      const bitmap = entry >> 1n;
      for (let bit = 0; bit < wordBits - 1; bit++) {
        if (((bitmap >> BigInt(bit)) & 1n) !== 0n) {
          offsets.push(base + BigInt(bit) * BigInt(wordSize));
          if (offsets.length >= 1_000_000) return offsets;
        }
      }
      base += BigInt(wordBits - 1) * BigInt(wordSize);
    }
    if (offsets.length >= 1_000_000) break;
  }

  return offsets;
}

/**
 * Filters known false-positive C++ linker-resolution collisions identified in
 * cross-binary ELF reachability auditing (NDK runtime re-exports, weak STL
 * typeinfo/vtables, static third-party libraries, and sibling HAL callbacks).
 */
export function filterCppLinkerTrapSymbol(
  name: string,
  isWeak: boolean,
): CppLinkerTrapFilterResult {
  if (/^(_Znwm|_Znam|_ZdlPv|_ZdaPv|__cxa_|__gxx_personality_)/u.test(name)) {
    return { trapped: true, trapKind: "ndk_cpp_runtime_reexport" };
  }
  if (
    /^(_ZTISt|_ZTSSt|_ZTVNSt|_ZTTNSt)/u.test(name) ||
    (isWeak && /^(_ZTI|_ZTS|_ZTV|_ZTT)/u.test(name))
  ) {
    return { trapped: true, trapKind: "weak_stl_typeinfo_or_vtable" };
  }
  if (
    /^(NV12Scale|I420Scale|I420ToNV21|ARGBToNV21|NV21ToARGB|libyuv_)/u.test(
      name,
    )
  ) {
    return { trapped: true, trapKind: "static_third_party_collision" };
  }
  if (/^(ss_set_notify_callback|hal_notify_callback)$/u.test(name)) {
    return { trapped: true, trapKind: "sibling_hal_callback_collision" };
  }
  return { trapped: false, trapKind: null };
}

/**
 * Extracts valid shared-library dlopen targets from string literals while
 * rejecting Android system property strings (e.g. "ro.camera.sound.forced")
 * and diagnostic error prefixes ("Cannot dlopen ...", "dlopen failed ...").
 */
export function extractValidDlopenLibraryTargets(
  strings: readonly { readonly value: string }[],
): string[] {
  const targets = new Set<string>();
  const tokenRegex = /\b([A-Za-z0-9_.\-@]+\.so(?:\.\d+)*)\b/gu;

  for (const entry of strings) {
    const val = entry.value.trim();
    if (val.length === 0) continue;
    const lower = val.toLowerCase();
    if (
      val.startsWith("ro.") ||
      val.startsWith("persist.") ||
      val.startsWith("sys.") ||
      lower.startsWith("cannot dlopen ") ||
      lower.startsWith("dlopen failed")
    ) {
      continue;
    }
    tokenRegex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = tokenRegex.exec(val)) !== null) {
      const candidate = match[1]!;
      if (
        candidate.startsWith("ro.") ||
        candidate.startsWith("persist.") ||
        candidate.startsWith("sys.")
      ) {
        continue;
      }
      targets.add(candidate);
    }
  }

  return [...targets].sort();
}

function readBoundedCString(
  bytes: Buffer,
  offset: number,
  maxLength: number,
): string | null {
  if (offset < 0 || offset >= bytes.length) return null;
  const limit = Math.min(bytes.length, offset + maxLength);
  let end = offset;
  while (end < limit && bytes[end] !== 0) {
    const ch = bytes[end]!;
    if (ch < 0x20 || ch > 0x7e) return null;
    end++;
  }
  if (end === offset || end >= limit || bytes[end] !== 0) return null;
  return bytes.subarray(offset, end).toString("utf8");
}

/**
 * Recovers JNINativeMethod { const char* name; const char* signature; void* fnPtr; }
 * tables from .data / .data.rel.ro so stripped LOCAL JNI handlers remain reachable.
 */
export function recoverJniRegisterNativesMethods(
  bytes: Buffer,
  is64Bit: boolean,
  littleEndian: boolean,
  vaddrToFileOffset: (vaddr: bigint) => number | null,
  dataRanges: readonly { readonly fileOffset: number; readonly fileSize: number }[],
  executableRanges: readonly { readonly start: bigint; readonly end: bigint }[],
): RecoveredJniMethod[] {
  const ptrSize = is64Bit ? 8 : 4;
  const entrySize = ptrSize * 3;
  const readPtr = (off: number): bigint => {
    if (is64Bit) {
      return littleEndian
        ? bytes.readBigUInt64LE(off)
        : bytes.readBigUInt64BE(off);
    }
    return BigInt(
      littleEndian ? bytes.readUInt32LE(off) : bytes.readUInt32BE(off),
    );
  };

  const nameRegex = /^[A-Za-z_][A-Za-z0-9_]{1,127}$/u;
  const sigRegex = /^\([A-Za-z0-9_/;[\]$]*\)[VZBCSIJFDL[]/u;
  const recovered: RecoveredJniMethod[] = [];
  const seen = new Set<string>();

  for (const range of dataRanges) {
    if (range.fileOffset < 0 || range.fileSize < entrySize) continue;
    const endLimit = Math.min(
      bytes.length - entrySize,
      range.fileOffset + range.fileSize - entrySize,
    );
    for (let off = range.fileOffset; off <= endLimit; off += ptrSize) {
      const namePtr = readPtr(off);
      const sigPtr = readPtr(off + ptrSize);
      const fnPtr = readPtr(off + ptrSize * 2);
      if (namePtr === 0n || sigPtr === 0n || fnPtr === 0n) continue;
      if (
        executableRanges.length > 0 &&
        !executableRanges.some((seg) => fnPtr >= seg.start && fnPtr < seg.end)
      ) {
        continue;
      }

      const nameOff = vaddrToFileOffset(namePtr);
      const sigOff = vaddrToFileOffset(sigPtr);
      if (nameOff === null || sigOff === null) continue;

      const methodName = readBoundedCString(bytes, nameOff, 128);
      if (methodName === null || !nameRegex.test(methodName)) continue;

      const signature = readBoundedCString(bytes, sigOff, 512);
      if (signature === null || !sigRegex.test(signature)) continue;

      const dedupKey = `${fnPtr.toString(16)}:${methodName}:${signature}`;
      if (!seen.has(dedupKey)) {
        seen.add(dedupKey);
        recovered.push({
          methodName,
          signature,
          fnAddress: fnPtr,
        });
      }
      off += ptrSize * 2;
    }
  }

  return recovered;
}
