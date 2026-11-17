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

export type CppLinkerTrapKind =
  | "ndk_cpp_runtime_reexport"
  | "weak_stl_typeinfo_or_vtable"
  | "static_third_party_collision"
  | "sibling_hal_callback_collision"
  | "stl_template_method_collision";

export interface CppLinkerTrapFilterResult {
  readonly trapped: boolean;
  readonly trapKind: CppLinkerTrapKind | null;
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
 * Filters all 5 false-positive C++ linker-resolution collision classes identified
 * in cross-binary ELF reachability auditing:
 * 1. NDK static C++ runtime re-exports (_Znwm, _ZdlPv, __cxa_*, __gxx_personality_*)
 * 2. Weak or libc++/libstdc++ STL RTTI typeinfo/vtables (_ZTI*, _ZTS*, _ZTV*, _ZTT*)
 * 3. Statically linked third-party multimedia/compression library symbols
 * 4. Generic unscoped sibling HAL/plugin callback collisions
 * 5. Weak/inline STL template method instantiations (_ZNSt3__1*, _ZNSt6__ndk1*, etc.)
 */
export function filterCppLinkerTrapSymbol(
  name: string,
  isWeak: boolean,
): CppLinkerTrapFilterResult {
  if (/^(_Znwm|_Znam|_ZdlPv|_ZdaPv|__cxa_|__gxx_personality_)/u.test(name)) {
    return { trapped: true, trapKind: "ndk_cpp_runtime_reexport" };
  }
  if (
    /^(_ZTISt|_ZTSSt|_ZTVNSt|_ZTTNSt|_ZTINSt3__1|_ZTSNSt3__1|_ZTVNSt3__1|_ZTTNSt3__1|_ZTINSt6__ndk1|_ZTSNSt6__ndk1|_ZTVNSt6__ndk1|_ZTTNSt6__ndk1)/u.test(
      name,
    ) ||
    (isWeak && /^(_ZTI|_ZTS|_ZTV|_ZTT)/u.test(name))
  ) {
    return { trapped: true, trapKind: "weak_stl_typeinfo_or_vtable" };
  }
  if (
    /^(NV12Scale|I420Scale|I420ToNV21|ARGBToNV21|NV21ToARGB|libyuv_|jpeg_Create|png_create_|inflateInit|deflateInit)/u.test(
      name,
    )
  ) {
    return { trapped: true, trapKind: "static_third_party_collision" };
  }
  if (
    /^(?:hal_notify_callback|set_notify_callback|register_hal_callback|notify_callback)$/u.test(
      name,
    )
  ) {
    return { trapped: true, trapKind: "sibling_hal_callback_collision" };
  }
  if (
    /^(_ZNSt3__1|_ZNKSt3__1|_ZNSt6__ndk1|_ZNKSt6__ndk1|_ZNSt\d|_ZNKSt\d)/u.test(
      name,
    ) ||
    (isWeak && /^_ZN?K?St/u.test(name))
  ) {
    return { trapped: true, trapKind: "stl_template_method_collision" };
  }
  return { trapped: false, trapKind: null };
}

/**
 * Extracts valid shared-library dlopen targets from string literals while
 * rejecting Android system property strings (e.g. "ro.camera.sound.forced"),
 * non-library ".so.<word>" tokens, and diagnostic dlopen error messages.
 */
export function extractValidDlopenLibraryTargets(
  strings: readonly { readonly value: string }[],
): string[] {
  const targets = new Set<string>();
  const tokenRegex =
    /(?:^|[\s"'(\x2f:;,=])([A-Za-z0-9_.\-@]+\.so(?:\.\d+)*)(?![A-Za-z0-9_.-])/gu;
  const sysPropPrefixRegex = /^(?:ro|persist|sys|vendor|dalvik|debug)\./iu;
  const diagnosticLogRegex =
    /(?:cannot\s+dlopen\b|dlopen\s+failed|failed\s+to\s+dlopen\b|unable\s+to\s+dlopen\b)/iu;

  for (const entry of strings) {
    const val = entry.value.trim();
    if (val.length === 0) continue;
    if (sysPropPrefixRegex.test(val) || diagnosticLogRegex.test(val)) {
      continue;
    }
    tokenRegex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = tokenRegex.exec(val)) !== null) {
      const candidate = match[1]!;
      if (sysPropPrefixRegex.test(candidate) || candidate === ".so") {
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
  relocatedPtrAtFileOffset?: (fileOffset: number) => bigint | null,
): RecoveredJniMethod[] {
  const ptrSize = is64Bit ? 8 : 4;
  const entrySize = ptrSize * 3;
  const readPtr = (off: number): bigint => {
    const raw = is64Bit
      ? littleEndian
        ? bytes.readBigUInt64LE(off)
        : bytes.readBigUInt64BE(off)
      : BigInt(
          littleEndian ? bytes.readUInt32LE(off) : bytes.readUInt32BE(off),
        );
    if (raw !== 0n) return raw;
    return relocatedPtrAtFileOffset?.(off) ?? 0n;
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
