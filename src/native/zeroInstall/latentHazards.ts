import type {
  LatentBinaryHazard,
  LatentBinaryHazardCategory,
} from "../../domain/native/nativeSubgraph.js";

export interface HazardSegmentRef {
  readonly start: bigint;
  readonly end: bigint;
  readonly writable: boolean;
}

export interface HazardSymbolRef {
  readonly name: string;
  readonly isFunction: boolean;
}

export interface HazardGotSlotRef {
  readonly symbolName: string;
  readonly isWritableGlobal: boolean;
  readonly isFunction: boolean;
}

export interface HazardInstructionRef {
  readonly address: bigint;
  readonly mnemonic: string;
  readonly operands: readonly string[];
  readonly rawText: string;
  readonly isCall: boolean;
  readonly isJump: boolean;
  readonly isConditionalJump: boolean;
  readonly isReturn: boolean;
  readonly targetAddress: bigint | null;
}

export interface HazardProcedureRef {
  readonly address: bigint;
  readonly name: string;
  readonly thunk: boolean;
  readonly instructions: readonly HazardInstructionRef[];
}

export interface HazardModelContext {
  readonly segments: readonly HazardSegmentRef[];
  readonly gotSlotByAddr: ReadonlyMap<bigint, HazardGotSlotRef>;
  readonly symbolsByAddr: ReadonlyMap<bigint, HazardSymbolRef>;
  readonly proceduresByAddr: ReadonlyMap<bigint, { readonly name: string }>;
}

const UNSAFE_MEMORY_SINKS = new Set([
  "strcpy",
  "strcat",
  "sprintf",
  "vsprintf",
  "gets",
  "scanf",
  "__isoc99_scanf",
  "system",
  "popen",
]);

const NULL_UNSAFE_CALLEES = new Set([
  "strlen",
  "wcslen",
  "strcmp",
  "strncmp",
  "strcpy",
  "strncpy",
  "strcat",
  "memcpy",
  "memmove",
]);

const BENIGN_REPEAT_CALLEES = new Set([
  "free",
  "printf",
  "fprintf",
  "puts",
  "putchar",
  "memset",
  "memcpy",
  "__stack_chk_fail",
  "__android_log_print",
  "_zdlpv",
  "_zdapv",
]);

const EXCLUDED_POINTER_REGS = new Set([
  "sp",
  "wsp",
  "fp",
  "lr",
  "xzr",
  "wzr",
  "rsp",
  "rbp",
  "esp",
  "ebp",
  "rip",
  "eip",
  "pc",
  "x29",
  "x30",
]);

const ALLOC_OR_COPY_CALLEES =
  /^(?:malloc|calloc|realloc|memcpy|memmove|_znwm|_znam|get_size|getdecodebufsize|getencodebufsize)$/iu;

function toHexAddr(addr: bigint): string {
  return `0x${(addr < 0n ? 0n : addr).toString(16)}`;
}

function resolveCalleeName(
  targetAddress: bigint | null,
  model: HazardModelContext,
): string {
  if (targetAddress === null) return "";
  const raw =
    model.proceduresByAddr.get(targetAddress)?.name ??
    model.symbolsByAddr.get(targetAddress)?.name ??
    "";
  return raw.replace(/^_+/u, "").replace(/@plt$/u, "").toLowerCase();
}

function resolveRawCalleeName(
  targetAddress: bigint | null,
  model: HazardModelContext,
): string {
  if (targetAddress === null) return "";
  return (
    model.proceduresByAddr.get(targetAddress)?.name ??
    model.symbolsByAddr.get(targetAddress)?.name ??
    ""
  ).replace(/@plt$/u, "");
}

function parseImmValue(raw: string): number | null {
  const cleaned = raw.trim().replace(/^#/u, "");
  if (/^-?0x[0-9a-fA-F]+$/u.test(cleaned)) {
    const neg = cleaned.startsWith("-");
    const mag = Number.parseInt(neg ? cleaned.slice(3) : cleaned.slice(2), 16);
    return Number.isNaN(mag) ? null : neg ? -mag : mag;
  }
  if (/^-?\d+$/u.test(cleaned)) {
    const val = Number.parseInt(cleaned, 10);
    return Number.isNaN(val) ? null : val;
  }
  return null;
}

function isCalleeSavedReg(reg: string): boolean {
  const r = reg.toLowerCase();
  if (/^x(?:19|2[0-8])$/u.test(r)) return true;
  return (
    r === "rbx" ||
    r === "ebx" ||
    r === "r12" ||
    r === "r13" ||
    r === "r14" ||
    r === "r15"
  );
}

function writesRegisterAsDestination(
  ins: HazardInstructionRef,
  reg: string,
): boolean {
  const m = ins.mnemonic.toLowerCase();
  if (
    m.startsWith("str") ||
    m.startsWith("stur") ||
    m.startsWith("stp") ||
    m.startsWith("cmp") ||
    m.startsWith("test") ||
    m.startsWith("cbz") ||
    m.startsWith("cbnz") ||
    m.startsWith("b.") ||
    ins.isCall ||
    ins.isJump ||
    ins.isReturn
  ) {
    return false;
  }
  const targetReg = reg.toLowerCase();
  const dest = (ins.operands[0] ?? "").replace(/^%/u, "").trim().toLowerCase();
  if (dest === targetReg) return true;
  if (
    targetReg.startsWith("x") &&
    dest === `w${targetReg.slice(1)}`
  ) {
    return true;
  }
  if (
    targetReg.startsWith("r") &&
    dest === `e${targetReg.slice(1)}`
  ) {
    return true;
  }
  return false;
}

function isNullCheckOnReg(ins: HazardInstructionRef, reg: string): boolean {
  const m = ins.mnemonic.toLowerCase();
  const r = reg.toLowerCase();
  const op0 = (ins.operands[0] ?? "").replace(/^%/u, "").trim().toLowerCase();
  const op1 = (ins.operands[1] ?? "").replace(/^%/u, "").trim().toLowerCase();
  if ((m === "cbz" || m === "cbnz") && op0 === r) {
    return true;
  }
  if (
    m.startsWith("cmp") &&
    op0 === r &&
    (op1 === "#0" || op1 === "#0x0" || op1 === "0" || op1 === "0x0" || op1 === "xzr" || op1 === "wzr")
  ) {
    return true;
  }
  if (m.startsWith("test") && op0 === r && op1 === r) {
    return true;
  }
  return false;
}

/**
 * Extracts all 9 categories of latent binary and undefined-behavior hazards
 * from a decoded native procedure so Safe Rust reconstruction eliminates them.
 */
export function extractLatentBinaryHazards(
  proc: HazardProcedureRef,
  model: HazardModelContext,
): LatentBinaryHazard[] {
  if (proc.thunk) {
    return [];
  }
  const hazards = new Map<string, LatentBinaryHazard>();
  const recordHazard = (
    category: LatentBinaryHazardCategory,
    severity: "high" | "medium" | "low",
    address: string,
    instructionOrOp: string,
    description: string,
  ) => {
    const key = `${category}:${address}`;
    if (!hazards.has(key)) {
      hazards.set(key, {
        category,
        severity,
        address,
        instruction_or_op: instructionOrOp,
        description,
      });
    }
  };

  const writableSegments = model.segments.filter((s) => s.writable);
  const isWritableGlobalAddr = (addr: bigint): boolean =>
    writableSegments.some((s) => addr >= s.start && addr < s.end);

  const hasSignExtOrArrayIndex = proc.instructions.some((ins) => {
    const m = ins.mnemonic.toLowerCase();
    if (
      m === "movsxd" ||
      m === "movslq" ||
      m === "cdqe" ||
      m === "cltq" ||
      m === "sxtw"
    ) {
      return true;
    }
    return ins.operands.some((op) => /\[.*[+*].*\]|\(.*,.*,.*\)/u.test(op));
  });

  const procTakesSizeT = /(?:PKhm|Pvm|m(?:Pi|S|i)|size_t|unsigned\s+long)/u.test(
    proc.name,
  );
  let hasZeroedStackSlots = false;
  let passedStackAddrToCallee = false;

  for (let i = 0; i < proc.instructions.length; i++) {
    const ins = proc.instructions[i]!;
    const m = ins.mnemonic.toLowerCase();
    const addrHex = toHexAddr(ins.address);
    const opsJoined = ins.operands.join(", ");
    const rendered = `${addrHex}: ${ins.mnemonic}${opsJoined.length > 0 ? ` ${opsJoined}` : ""}`;
    const lowerOps = opsJoined.toLowerCase();
    const rawLower = ins.rawText.toLowerCase();

    // 1. potential_integer_overflow_to_pointer
    const is32BitRegMention =
      /\b(?:e[abcd]x|e[sd]i|r(?:8|9|1[0-5])d|w\d+)\b/u.test(lowerOps);
    if (
      (m.startsWith("imul") ||
        m.startsWith("mul") ||
        m === "madd" ||
        (m.startsWith("shl") && hasSignExtOrArrayIndex)) &&
      (is32BitRegMention || hasSignExtOrArrayIndex)
    ) {
      recordHazard(
        "potential_integer_overflow_to_pointer",
        "high",
        addrHex,
        rendered,
        "32-bit integer multiplication/shift in a procedure with 64-bit sign-extension or pointer indexing can wrap before offset calculation; promote to usize/u64 and use checked_mul in Safe Rust.",
      );
    }

    // 2. unchecked_division
    if (
      m === "div" ||
      m === "idiv" ||
      m === "divl" ||
      m === "idivl" ||
      m === "divq" ||
      m === "idivq" ||
      m === "udiv" ||
      m === "sdiv" ||
      m === "divss" ||
      m === "divsd" ||
      m === "fdiv"
    ) {
      let guarded = false;
      for (let back = Math.max(0, i - 4); back < i; back++) {
        const prevM = proc.instructions[back]!.mnemonic.toLowerCase();
        if (
          prevM.startsWith("test") ||
          prevM.startsWith("cmp") ||
          prevM.startsWith("cbz") ||
          prevM.startsWith("cbnz") ||
          prevM.startsWith("ucomi")
        ) {
          guarded = true;
          break;
        }
      }
      if (!guarded) {
        recordHazard(
          "unchecked_division",
          "high",
          addrHex,
          rendered,
          "Hardware division instruction without an adjacent zero-divisor check; use checked_div / checked_rem or explicit zero guards in Safe Rust.",
        );
      }
    }

    // 3. thread_hostile_mutable_global
    const firstOpLower = (ins.operands[0] ?? "").toLowerCase();
    const lastOpLower = (
      ins.operands[ins.operands.length - 1] ?? ""
    ).toLowerCase();
    const isMutatingMnem =
      m.startsWith("mov") ||
      m.startsWith("add") ||
      m.startsWith("sub") ||
      m.startsWith("xor") ||
      m.startsWith("or") ||
      m.startsWith("and") ||
      m.startsWith("inc") ||
      m.startsWith("dec") ||
      m.startsWith("str") ||
      m.startsWith("stur") ||
      m.startsWith("stp") ||
      m.startsWith("xchg") ||
      m.startsWith("cmpxchg");
    const writesRipRelativeIntel =
      isMutatingMnem &&
      !m.startsWith("lea") &&
      firstOpLower.includes("rip") &&
      firstOpLower.includes("[");
    const writesRipRelativeAtt =
      isMutatingMnem &&
      !m.startsWith("lea") &&
      ins.operands.length >= 2 &&
      lastOpLower.includes("(%rip)");
    const gotBinding =
      ins.targetAddress !== null
        ? model.gotSlotByAddr.get(ins.targetAddress)
        : undefined;
    const accessesWritableGotGlobal =
      gotBinding !== undefined &&
      gotBinding.isWritableGlobal &&
      !gotBinding.isFunction;
    const writesGlobalTarget =
      !m.startsWith("lea") &&
      gotBinding?.isFunction !== true &&
      ins.targetAddress !== null &&
      isWritableGlobalAddr(ins.targetAddress) &&
      ((isMutatingMnem &&
        (firstOpLower.includes("rip") ||
          lastOpLower.includes("(%rip)") ||
          m.startsWith("add") ||
          m.startsWith("sub") ||
          m.startsWith("xor") ||
          m.startsWith("or") ||
          m.startsWith("and") ||
          m.startsWith("inc") ||
          m.startsWith("dec") ||
          m.startsWith("str") ||
          m.startsWith("stur") ||
          m.startsWith("stp") ||
          (m.startsWith("mov") &&
            (firstOpLower.includes("[") || lastOpLower.includes("(%rip)"))))) ||
        (m.startsWith("ldr") &&
          model.symbolsByAddr.get(ins.targetAddress)?.isFunction === false));

    if (
      writesRipRelativeIntel ||
      writesRipRelativeAtt ||
      writesGlobalTarget ||
      accessesWritableGotGlobal
    ) {
      const resolvedSym =
        gotBinding?.symbolName ??
        (ins.targetAddress !== null
          ? model.symbolsByAddr.get(ins.targetAddress)?.name
          : undefined);
      const symClause =
        resolvedSym !== undefined ? ` ('${resolvedSym}')` : "";
      recordHazard(
        "thread_hostile_mutable_global",
        "medium",
        addrHex,
        rendered,
        `Instruction accesses or mutates process-global state${symClause} in a writable data/BSS section without synchronization; move state into an explicit context struct or Atomic/Mutex in Safe Rust.`,
      );
    }

    // 4. unsafe_memory_sink
    if (ins.isCall && ins.targetAddress !== null) {
      const cleanCallee = resolveCalleeName(ins.targetAddress, model);
      if (UNSAFE_MEMORY_SINKS.has(cleanCallee)) {
        recordHazard(
          "unsafe_memory_sink",
          "high",
          addrHex,
          rendered,
          `Calls unbounded C sink '${cleanCallee}'; replace with bounds-checked Rust slice/String formatting.`,
        );
      }
    }

    // 5. uninitialized_or_stack_hazard
    if (
      m.startsWith("sub") &&
      (firstOpLower === "rsp" ||
        firstOpLower === "%rsp" ||
        lastOpLower === "%rsp" ||
        firstOpLower === "sp")
    ) {
      for (const op of ins.operands) {
        const immMatch = op.match(/(?:0x([0-9a-fA-F]+)|(\d+))$/u);
        if (immMatch !== null) {
          const val =
            immMatch[1] !== undefined
              ? Number.parseInt(immMatch[1], 16)
              : Number.parseInt(immMatch[2]!, 10);
          if (!Number.isNaN(val) && val >= 4096) {
            recordHazard(
              "uninitialized_or_stack_hazard",
              "medium",
              addrHex,
              rendered,
              `Large stack frame allocation (${val} bytes); prefer heap-allocated Vec or bounded buffers in Safe Rust.`,
            );
          }
        }
      }
    }

    // 6. register_writeback_offset_clobber (AArch64 pre/post-indexed writeback followed by base+imm access)
    if (
      m.startsWith("ldr") ||
      m.startsWith("ldur") ||
      m.startsWith("ldp") ||
      m.startsWith("str") ||
      m.startsWith("stur") ||
      m.startsWith("stp")
    ) {
      const preWritebackMatch =
        /\[(x(?:[0-9]|1[0-9]|2[0-8])),\s*#?(-?(?:0x[0-9a-fA-F]+|\d+))\]!/u.exec(
          rawLower,
        );
      const postWritebackMatch =
        /\[(x(?:[0-9]|1[0-9]|2[0-8]))\],\s*#?(-?(?:0x[0-9a-fA-F]+|\d+))(?:\s|$)/u.exec(
          rawLower,
        );
      const wbMatch = preWritebackMatch ?? postWritebackMatch;
      if (wbMatch !== null) {
        const baseReg = wbMatch[1]!.toLowerCase();
        const wbOffset = parseImmValue(wbMatch[2]!);
        if (wbOffset !== null && wbOffset !== 0) {
          const offsetPattern = new RegExp(
            `\\[${baseReg},\\s*#?(-?(?:0x[0-9a-fA-F]+|\\d+))\\]`,
            "iu",
          );
          const end = Math.min(proc.instructions.length - 1, i + 12);
          for (let j = i + 1; j <= end; j++) {
            const next = proc.instructions[j]!;
            if (next.isReturn) break;
            const nextMemMatch = offsetPattern.exec(next.rawText);
            if (nextMemMatch !== null) {
              const followOff = parseImmValue(nextMemMatch[1]!);
              if (followOff !== null && followOff !== 0) {
                recordHazard(
                  "register_writeback_offset_clobber",
                  "high",
                  addrHex,
                  rendered,
                  `Pre/post-indexed writeback on '${baseReg}' shifts the base pointer before subsequent offset access at [${baseReg}, ${nextMemMatch[1]}]; use named Rust struct fields instead of raw pointer register writebacks.`,
                );
                break;
              }
            }
            if (writesRegisterAsDestination(next, baseReg)) {
              break;
            }
          }
        }
      }
    }

    // 7. null_deref_before_check (dereference or strlen-style call followed by null check)
    const derefRegs = new Set<string>();
    const bracketMemMatch = /\[([a-zA-Z0-9]+)(?:\s*[,+\]-]|\])/u.exec(
      rawLower,
    );
    if (
      bracketMemMatch !== null &&
      !m.startsWith("lea") &&
      !EXCLUDED_POINTER_REGS.has(bracketMemMatch[1]!.toLowerCase())
    ) {
      derefRegs.add(bracketMemMatch[1]!.toLowerCase());
    }
    const attMemMatch = /\(%([a-zA-Z0-9]+)\)/u.exec(rawLower);
    if (
      attMemMatch !== null &&
      !m.startsWith("lea") &&
      !EXCLUDED_POINTER_REGS.has(attMemMatch[1]!.toLowerCase())
    ) {
      derefRegs.add(attMemMatch[1]!.toLowerCase());
    }
    if (ins.isCall && ins.targetAddress !== null) {
      const callee = resolveCalleeName(ins.targetAddress, model);
      if (NULL_UNSAFE_CALLEES.has(callee)) {
        for (let back = Math.max(0, i - 3); back < i; back++) {
          const prev = proc.instructions[back]!;
          const pm = prev.mnemonic.toLowerCase();
          if (pm.startsWith("mov")) {
            const dst = (prev.operands[0] ?? "")
              .replace(/^%/u, "")
              .trim()
              .toLowerCase();
            const src = (prev.operands[1] ?? "")
              .replace(/^%/u, "")
              .trim()
              .toLowerCase();
            if (
              (dst === "x0" || dst === "rdi") &&
              src.length > 0 &&
              !EXCLUDED_POINTER_REGS.has(src)
            ) {
              derefRegs.add(src);
            }
          }
        }
      }
    }

    for (const dReg of derefRegs) {
      const end = Math.min(proc.instructions.length - 1, i + 6);
      for (let j = i + 1; j <= end; j++) {
        const next = proc.instructions[j]!;
        if (next.isReturn) break;
        if (isNullCheckOnReg(next, dReg)) {
          recordHazard(
            "null_deref_before_check",
            "high",
            addrHex,
            rendered,
            `Pointer register '${dReg}' is dereferenced before a subsequent null check at ${toHexAddr(next.address)}; represent nullable inputs with Option<&T> / Option<&[u8]> in Safe Rust.`,
          );
          break;
        }
        if (writesRegisterAsDestination(next, dReg)) {
          break;
        }
        if (next.isCall && !isCalleeSavedReg(dReg)) {
          break;
        }
      }
    }

    // 8. size_truncation_or_unsigned_underflow
    if (ins.isCall && ins.targetAddress !== null) {
      const cleanCallee = resolveCalleeName(ins.targetAddress, model);
      // 8a: strlen() - const without bounds check before strncpy/memcpy/memmove
      if (cleanCallee === "strlen" || cleanCallee === "wcslen") {
        let sawLenAdjust = false;
        let sawBoundsGuard = false;
        const scanEnd = Math.min(proc.instructions.length - 1, i + 10);
        for (let j = i + 1; j <= scanEnd; j++) {
          const next = proc.instructions[j]!;
          const nm = next.mnemonic.toLowerCase();
          if (next.isReturn) break;
          if (
            nm.startsWith("cmp") ||
            nm === "subs" ||
            nm.startsWith("test")
          ) {
            sawBoundsGuard = true;
          }
          if (
            (nm === "sub" || nm === "subs" || nm === "add") &&
            /\b(?:x0|w0|x2|w2|rax|eax|rdx|edx)\b/u.test(
              next.rawText.toLowerCase(),
            )
          ) {
            sawLenAdjust = true;
          }
          if (next.isCall && next.targetAddress !== null) {
            const copyCallee = resolveCalleeName(next.targetAddress, model);
            if (
              sawLenAdjust &&
              !sawBoundsGuard &&
              (copyCallee === "strncpy" ||
                copyCallee === "memcpy" ||
                copyCallee === "memmove" ||
                copyCallee === "snprintf")
            ) {
              recordHazard(
                "size_truncation_or_unsigned_underflow",
                "high",
                addrHex,
                rendered,
                `Length from '${cleanCallee}' is decremented without an underflow bounds check prior to '${copyCallee}'; use checked_sub() and slice slicing in Safe Rust.`,
              );
              break;
            }
          }
        }
      }

      // 8b: size_t -> 32-bit int narrowing at callsite or sxtw/movsxd into alloc/copy
      if (
        procTakesSizeT &&
        ALLOC_OR_COPY_CALLEES.test(cleanCallee)
      ) {
        for (let back = Math.max(0, i - 5); back < i; back++) {
          const prev = proc.instructions[back]!;
          if (
            /\b(?:w[1-5]|esi|edx|ecx)\b/u.test(prev.rawText.toLowerCase())
          ) {
            recordHazard(
              "size_truncation_or_unsigned_underflow",
              "high",
              addrHex,
              rendered,
              `Procedure accepting 64-bit size_t narrows or passes a 32-bit length register into '${resolveRawCalleeName(ins.targetAddress, model)}'; preserve full usize width with TryFrom in Safe Rust.`,
            );
            break;
          }
        }
      }
    }

    if (m === "sxtw" || m === "movsxd" || m === "movslq") {
      const scanEnd = Math.min(proc.instructions.length - 1, i + 4);
      for (let j = i + 1; j <= scanEnd; j++) {
        const next = proc.instructions[j]!;
        if (next.isCall && next.targetAddress !== null) {
          const allocCallee = resolveCalleeName(next.targetAddress, model);
          if (ALLOC_OR_COPY_CALLEES.test(allocCallee)) {
            recordHazard(
              "size_truncation_or_unsigned_underflow",
              "high",
              addrHex,
              rendered,
              `Sign-extension '${m}' promotes a 32-bit signed length directly into '${allocCallee}'; compute allocation sizes in checked usize arithmetic in Safe Rust.`,
            );
            break;
          }
        }
      }
    }

    // 9. unpopulated_out_param_or_duplicate_call
    // 9a: Back-to-back duplicate identical calls with no conditional branch between
    if (ins.isCall && ins.targetAddress !== null) {
      const cleanCallee = resolveCalleeName(ins.targetAddress, model);
      if (cleanCallee.length > 0 && !BENIGN_REPEAT_CALLEES.has(cleanCallee)) {
        const scanEnd = Math.min(proc.instructions.length - 1, i + 4);
        for (let j = i + 1; j <= scanEnd; j++) {
          const next = proc.instructions[j]!;
          if (next.isJump || next.isConditionalJump || next.isReturn) {
            break;
          }
          if (next.isCall) {
            if (next.targetAddress === ins.targetAddress) {
              recordHazard(
                "unpopulated_out_param_or_duplicate_call",
                "medium",
                addrHex,
                rendered,
                `Duplicate back-to-back call to '${resolveRawCalleeName(ins.targetAddress, model)}' at ${toHexAddr(next.address)} without intervening control flow; consolidate into a single explicit call or Result-returning helper in Safe Rust.`,
              );
            }
            break;
          }
        }
      }
    }

    // 9b: Zeroed stack out-parameter slots passed to a callee followed by bit-31 sign shift
    if (
      (m.startsWith("str") || m.startsWith("stp") || m.startsWith("mov")) &&
      /(?:xzr|wzr|,\s*#?0\b)/u.test(rawLower) &&
      /\[(?:sp|rsp)/u.test(rawLower)
    ) {
      hasZeroedStackSlots = true;
    }
    if (
      (m === "add" || m === "lea") &&
      /\b(?:sp|rsp)\b/u.test(rawLower)
    ) {
      const scanEnd = Math.min(proc.instructions.length - 1, i + 4);
      for (let j = i + 1; j <= scanEnd; j++) {
        if (proc.instructions[j]!.isCall) {
          passedStackAddrToCallee = true;
          break;
        }
      }
    }
    if (
      hasZeroedStackSlots &&
      passedStackAddrToCallee &&
      ((m === "lsr" && /#(?:31|0x1f)\b/u.test(rawLower)) ||
        (m === "ubfx" && /#(?:31|0x1f),\s*#1\b/u.test(rawLower)) ||
        (m === "shr" && /\b(?:31|0x1f)\b/u.test(rawLower)))
    ) {
      recordHazard(
        "unpopulated_out_param_or_duplicate_call",
        "medium",
        addrHex,
        rendered,
        "Zero-initialized stack out-parameter passed to callee before bit-31 sign extraction (0 > thresh pattern); return structured tuple/struct values instead of nullable C out-pointers in Safe Rust.",
      );
    }
  }

  return [...hazards.values()];
}
