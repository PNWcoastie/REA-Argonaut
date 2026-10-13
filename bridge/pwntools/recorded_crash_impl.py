"""Bounded Linux core evidence via unchanged ELFFile/structs and pwntools ctypes.

No Corefile-selected thread, executable guessing, process lookup or target launch.
"""
import base64
import ctypes
import importlib.metadata
import io
from pathlib import Path
import struct
import sys

PROFILE = "pwntools@4.15.0;pyelftools@0.33;unicorn@2.1.2"
PACKAGES = {"pwntools": "4.15.0", "pyelftools": "0.33", "unicorn": "2.1.2"}

PT_CORE_MAP = {
    0: "PT_NULL",
    1: "PT_LOAD",
    2: "PT_DYNAMIC",
    3: "PT_INTERP",
    4: "PT_NOTE",
    5: "PT_SHLIB",
    6: "PT_PHDR",
    7: "PT_TLS",
    0x6474E550: "PT_GNU_EH_FRAME",
    0x6474E551: "PT_GNU_STACK",
    0x6474E552: "PT_GNU_RELRO",
    0x6474E553: "PT_GNU_PROPERTY",
}

NT_CORE_MAP = {
    1: "NT_PRSTATUS",
    2: "NT_FPREGSET",
    3: "NT_PRPSINFO",
    4: "NT_TASKSTRUCT",
    6: "NT_AUXV",
    0x46494C45: "NT_FILE",
    0x53494749: "NT_SIGINFO",
}


class _StdlibUserRegsAmd64(ctypes.LittleEndianStructure):
    _fields_ = [
        ("r15", ctypes.c_uint64),
        ("r14", ctypes.c_uint64),
        ("r13", ctypes.c_uint64),
        ("r12", ctypes.c_uint64),
        ("rbp", ctypes.c_uint64),
        ("rbx", ctypes.c_uint64),
        ("r11", ctypes.c_uint64),
        ("r10", ctypes.c_uint64),
        ("r9", ctypes.c_uint64),
        ("r8", ctypes.c_uint64),
        ("rax", ctypes.c_uint64),
        ("rcx", ctypes.c_uint64),
        ("rdx", ctypes.c_uint64),
        ("rsi", ctypes.c_uint64),
        ("rdi", ctypes.c_uint64),
        ("orig_rax", ctypes.c_uint64),
        ("rip", ctypes.c_uint64),
        ("cs", ctypes.c_uint64),
        ("eflags", ctypes.c_uint64),
        ("rsp", ctypes.c_uint64),
        ("ss", ctypes.c_uint64),
        ("fs_base", ctypes.c_uint64),
        ("gs_base", ctypes.c_uint64),
        ("ds", ctypes.c_uint64),
        ("es", ctypes.c_uint64),
        ("fs", ctypes.c_uint64),
        ("gs", ctypes.c_uint64),
    ]


class _StdlibElfPrstatusAmd64(ctypes.LittleEndianStructure):
    _fields_ = [
        ("si_signo", ctypes.c_int32),
        ("si_code", ctypes.c_int32),
        ("si_errno", ctypes.c_int32),
        ("pr_cursig", ctypes.c_uint16),
        ("_pad_cursig", ctypes.c_uint16),
        ("pr_sigpend", ctypes.c_uint64),
        ("pr_sighold", ctypes.c_uint64),
        ("pr_pid", ctypes.c_int32),
        ("pr_ppid", ctypes.c_int32),
        ("pr_pgrp", ctypes.c_int32),
        ("pr_sid", ctypes.c_int32),
        ("pr_utime_sec", ctypes.c_int64),
        ("pr_utime_usec", ctypes.c_int64),
        ("pr_stime_sec", ctypes.c_int64),
        ("pr_stime_usec", ctypes.c_int64),
        ("pr_cutime_sec", ctypes.c_int64),
        ("pr_cutime_usec", ctypes.c_int64),
        ("pr_cstime_sec", ctypes.c_int64),
        ("pr_cstime_usec", ctypes.c_int64),
        ("pr_reg", _StdlibUserRegsAmd64),
        ("pr_fpvalid", ctypes.c_int32),
    ]


class _StdlibElfSiginfo64(ctypes.LittleEndianStructure):
    _fields_ = [
        ("si_signo", ctypes.c_int32),
        ("si_errno", ctypes.c_int32),
        ("si_code", ctypes.c_int32),
        ("_pad0", ctypes.c_int32),
        ("sigfault_addr", ctypes.c_uint64),
        ("_pad_rest", ctypes.c_uint8 * 104),
    ]


class CoreFailure(Exception):
    def __init__(self, reason, message):
        super().__init__(message)
        self.reason = reason


def encoded(value):
    return base64.b64encode(value).decode("ascii")


def location(offset, size, limit):
    if not 0 <= offset <= limit or not 0 <= size <= limit - offset:
        raise CoreFailure("format", "Recorded source range exceeds its declared container.")
    return {"offset": hex(offset), "bytes": hex(size)}


def _has_pinned_pwntools():
    for package, required in PACKAGES.items():
        try:
            actual = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            return False
        if actual != required:
            return False
    try:
        import elftools  # noqa: F401
        import pwnlib  # noqa: F401
    except ImportError:
        return False
    return True


def _inspect_core_stdlib(content):
    (
        _e_type,
        _e_machine,
        _e_version,
        _e_entry,
        e_phoff,
        e_shoff,
        _e_flags,
        _e_ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        _e_shnum,
        _e_shstrndx,
    ) = struct.unpack_from("<HHIQQQIHHHHHH", content, 16)
    count = e_phnum
    if count == 0xFFFF:
        if e_shoff == 0 or e_shentsize < 64:
            raise CoreFailure("format", "Extended program-header count requires a valid section-zero header.")
        location(e_shoff, e_shentsize, len(content))
        _, _, _, _, _, _, _, sh0_info, _, _ = struct.unpack_from("<IIQQQQIIQQ", content, e_shoff)
        count = sh0_info
    if count and e_phentsize < 56:
        raise CoreFailure("format", "Program-header entry is shorter than the required ELF64 structure.")
    location(e_phoff, count * e_phentsize, len(content))
    segments, notes, padding, threads, signals = [], [], [], [], []
    header_size = 12
    for segment_index in range(count):
        ph_pos = e_phoff + segment_index * e_phentsize
        location(ph_pos, e_phentsize, len(content))
        p_type_num, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(
            "<IIQQQQQQ", content, ph_pos
        )
        p_type = PT_CORE_MAP.get(p_type_num, p_type_num)
        backing = p_type != "PT_NULL" and p_filesz > 0
        if backing:
            location(p_offset, p_filesz, len(content))
        if p_type == "PT_LOAD" and p_filesz > p_memsz:
            raise CoreFailure("format", "Recorded PT_LOAD file bytes exceed memory size.")
        segments.append(
            {
                "index": segment_index,
                "type": p_type,
                "header_location": location(ph_pos, e_phentsize, len(content)),
                "offset": hex(p_offset),
                "file_size": hex(p_filesz),
                "memory_size": hex(p_memsz),
                "virtual_address": hex(p_vaddr),
                "physical_address": hex(p_paddr),
                "alignment": hex(p_align),
                "flags": hex(p_flags),
                "file_backing": "file" if backing else "none",
            }
        )
        if p_type != "PT_NOTE" or p_filesz == 0:
            continue
        position, end = p_offset, p_offset + p_filesz
        while position < end:
            if end - position < header_size:
                raw = content[position:end]
                if any(raw):
                    raise CoreFailure("format", "Nonzero trailing note bytes lack a complete note header.")
                padding.append(
                    {
                        "segment_index": segment_index,
                        "location": location(position, len(raw), end),
                        "bytes_base64": encoded(raw),
                    }
                )
                break
            n_namesz, n_descsz, n_type_num = struct.unpack_from("<III", content, position)
            n_type = NT_CORE_MAP.get(n_type_num, n_type_num)
            owner_start = position + header_size
            descriptor_start = owner_start + ((n_namesz + 3) // 4) * 4
            note_end = descriptor_start + ((n_descsz + 3) // 4) * 4
            location(position, note_end - position, end)
            owner = content[owner_start:owner_start + n_namesz]
            if owner and b"\0" not in owner:
                raise CoreFailure("format", "Declared note owner has no NUL terminator.")
            display = owner.split(b"\0", 1)[0].decode("utf-8", "replace") if owner else None
            descriptor = content[descriptor_start:descriptor_start + n_descsz]
            note_index = len(notes)
            notes.append(
                {
                    "index": note_index,
                    "segment_index": segment_index,
                    "type": n_type,
                    "location": location(position, note_end - position, end),
                    "owner_location": location(owner_start, len(owner), end),
                    "owner_bytes_base64": encoded(owner),
                    "owner_display": display,
                    "descriptor_location": location(descriptor_start, len(descriptor), end),
                    "descriptor_bytes_base64": encoded(descriptor),
                }
            )
            position = note_end
            if owner != b"CORE\0":
                continue
            if n_type == "NT_PRSTATUS":
                if len(descriptor) < ctypes.sizeof(_StdlibElfPrstatusAmd64):
                    raise CoreFailure("format", "Linux amd64 NT_PRSTATUS descriptor is truncated.")
                status = _StdlibElfPrstatusAmd64.from_buffer_copy(descriptor)
                registers = []
                for name, kind in _StdlibUserRegsAmd64._fields_:
                    relative = _StdlibElfPrstatusAmd64.pr_reg.offset + getattr(_StdlibUserRegsAmd64, name).offset
                    registers.append(
                        {
                            "name": name,
                            "value": hex(getattr(status.pr_reg, name)),
                            "location": location(descriptor_start + relative, ctypes.sizeof(kind), end),
                        }
                    )
                threads.append(
                    {
                        "note_index": note_index,
                        "historical_pid": ctypes.c_int32(status.pr_pid).value,
                        "recorded_current_signal": status.pr_cursig,
                        "registers": registers,
                    }
                )
            elif n_type == "NT_SIGINFO":
                if len(descriptor) < ctypes.sizeof(_StdlibElfSiginfo64):
                    raise CoreFailure("format", "Linux amd64 NT_SIGINFO descriptor is truncated.")
                signal = _StdlibElfSiginfo64.from_buffer_copy(descriptor)
                number = ctypes.c_int32(signal.si_signo).value
                code = ctypes.c_int32(signal.si_code).value
                known = number == 11 and code in (1, 2)
                signals.append(
                    {
                        "note_index": note_index,
                        "number": number,
                        "code": code,
                        "errno": ctypes.c_int32(signal.si_errno).value,
                        "fault_address": hex(signal.sigfault_addr) if known else None,
                        "fault_address_meaning": "recorded-sigsegv-address" if known else "unknown",
                        "thread_association": "unknown",
                    }
                )
    return {
        "format": "elf-core",
        "architecture": "x86_64-little-endian",
        "target_execution": "not-performed",
        "live_process_identity": "unknown",
        "segments": segments,
        "notes": notes,
        "note_padding": padding,
        "threads": threads,
        "signals": signals,
        "note_interpretation_completeness": "unknown",
        "limitations": [
            "The initial Linux note profile accepts System V/unspecified or GNU/Linux OSABI with ABI version zero; an unspecified OSABI alone does not prove operating-system origin.",
            "Historical PID and signal values are recorded metadata, not current process identity or attach authority.",
            "Only exact Linux CORE NT_PRSTATUS/NT_SIGINFO owners are interpreted; every descriptor and owner retains original bytes. Other note semantics remain unknown.",
            "NT_SIGINFO thread association is unknown. Only SIGSEGV SEGV_MAPERR/SEGV_ACCERR initially establish a fault-address union meaning.",
            "PT_LOAD file bytes are recorded bytes. Undumped memory and current executable/library identity remain unknown; no current host file is resolved from a recorded pathname.",
            "Missing notes/registers/signals do not establish their absence at the original crash. Full unwinding, executable pairing and live control are not provided.",
        ],
    }


def inspect_core(path, cache):
    content = path.read_bytes()
    if len(content) < 16 or content[:4] != b"\x7fELF":
        raise CoreFailure("format", "Selected recording lacks a complete ELF identification.")
    if content[4:6] != b"\x02\x01":
        raise CoreFailure("unsupported-target", "Initial recorded-core profile requires ELF64 little-endian.")
    if len(content) < 64:
        raise CoreFailure("format", "Selected ELF64 core header is truncated.")
    if content[6] != 1:
        raise CoreFailure("format", "ELF identification version is not EV_CURRENT.")
    if int.from_bytes(content[20:24], "little") != 1:
        raise CoreFailure("format", "ELF header version is not EV_CURRENT.")
    # Linux commonly emits ELFOSABI_NONE (0), also accepted as GNU/Linux (3).
    # Other declared OSABIs must never select Linux note ctypes.
    if content[7] not in (0, 3) or content[8] != 0:
        raise CoreFailure("unsupported-target", "Initial recorded-core profile requires System V or GNU/Linux OSABI with ABI version zero; selected OSABI=" + str(content[7]) + ", ABI version=" + str(content[8]) + ".")
    if int.from_bytes(content[16:18], "little") != 4 or int.from_bytes(content[18:20], "little") != 62:
        raise CoreFailure("unsupported-target", "Initial recorded-core profile requires x86-64 ET_CORE.")
    if not _has_pinned_pwntools():
        try:
            return _inspect_core_stdlib(content)
        except CoreFailure:
            raise
        except (struct.error, ValueError, AssertionError, IndexError) as error:
            raise CoreFailure("format", "Recorded core failed stdlib structural parsing: " + str(error)) from error
    from elftools.common.exceptions import ELFError
    from elftools.common.utils import struct_parse
    from elftools.elf.elffile import ELFFile
    from pwnlib.elf.datatypes import elf_prstatus_amd64, elf_siginfo_64, user_regs_struct_amd64
    try:
        image = ELFFile(io.BytesIO(content))
        header = image.header
        count = image.num_segments()
        if count and header.e_phentsize < image.structs.Elf_Phdr.sizeof():
            raise CoreFailure("format", "Program-header entry is shorter than the required ELF64 structure.")
        location(header.e_phoff, count * header.e_phentsize, len(content))
        segments, notes, padding, threads, signals = [], [], [], [], []
        for segment_index, segment in enumerate(image.iter_segments()):
            h = segment.header
            backing = h.p_type != "PT_NULL" and h.p_filesz > 0
            if backing:
                location(h.p_offset, h.p_filesz, len(content))
            if h.p_type == "PT_LOAD" and h.p_filesz > h.p_memsz:
                raise CoreFailure("format", "Recorded PT_LOAD file bytes exceed memory size.")
            segments.append({"index": segment_index, "type": h.p_type,
                             "header_location": location(header.e_phoff + segment_index * header.e_phentsize, header.e_phentsize, len(content)),
                             "offset": hex(h.p_offset), "file_size": hex(h.p_filesz), "memory_size": hex(h.p_memsz),
                             "virtual_address": hex(h.p_vaddr), "physical_address": hex(h.p_paddr), "alignment": hex(h.p_align), "flags": hex(h.p_flags), "file_backing": "file" if backing else "none"})
            if h.p_type != "PT_NOTE" or h.p_filesz == 0:
                continue
            position, end = h.p_offset, h.p_offset + h.p_filesz
            header_size = image.structs.Elf_Nhdr.sizeof()
            while position < end:
                if end - position < header_size:
                    raw = content[position:end]
                    if any(raw):
                        raise CoreFailure("format", "Nonzero trailing note bytes lack a complete note header.")
                    padding.append({"segment_index": segment_index, "location": location(position, len(raw), end), "bytes_base64": encoded(raw)})
                    break
                note = struct_parse(image.structs.Elf_Nhdr, image.stream, stream_pos=position)
                owner_start = position + header_size
                descriptor_start = owner_start + ((note.n_namesz + 3) // 4) * 4
                note_end = descriptor_start + ((note.n_descsz + 3) // 4) * 4
                location(position, note_end - position, end)
                owner = content[owner_start:owner_start + note.n_namesz]
                if owner and b"\0" not in owner:
                    raise CoreFailure("format", "Declared note owner has no NUL terminator.")
                display = owner.split(b"\0", 1)[0].decode("utf-8", "replace") if owner else None
                descriptor = content[descriptor_start:descriptor_start + note.n_descsz]
                note_index = len(notes)
                notes.append({"index": note_index, "segment_index": segment_index, "type": note.n_type,
                              "location": location(position, note_end - position, end),
                              "owner_location": location(owner_start, len(owner), end), "owner_bytes_base64": encoded(owner), "owner_display": display,
                              "descriptor_location": location(descriptor_start, len(descriptor), end), "descriptor_bytes_base64": encoded(descriptor)})
                position = note_end
                # Only the initial Linux CORE ABI is interpreted. Other owners retain exact bytes.
                if owner != b"CORE\0":
                    continue
                if note.n_type == "NT_PRSTATUS":
                    if len(descriptor) < ctypes.sizeof(elf_prstatus_amd64):
                        raise CoreFailure("format", "Linux amd64 NT_PRSTATUS descriptor is truncated.")
                    status = elf_prstatus_amd64.from_buffer_copy(descriptor)
                    registers = []
                    for name, kind in user_regs_struct_amd64._fields_:
                        relative = elf_prstatus_amd64.pr_reg.offset + getattr(user_regs_struct_amd64, name).offset
                        registers.append({"name": name, "value": hex(getattr(status.pr_reg, name)), "location": location(descriptor_start + relative, ctypes.sizeof(kind), end)})
                    threads.append({"note_index": note_index, "historical_pid": ctypes.c_int32(status.pr_pid).value, "recorded_current_signal": status.pr_cursig, "registers": registers})
                elif note.n_type == "NT_SIGINFO":
                    if len(descriptor) < ctypes.sizeof(elf_siginfo_64):
                        raise CoreFailure("format", "Linux amd64 NT_SIGINFO descriptor is truncated.")
                    signal = elf_siginfo_64.from_buffer_copy(descriptor)
                    number = ctypes.c_int32(signal.si_signo).value
                    code = ctypes.c_int32(signal.si_code).value
                    known = number == 11 and code in (1, 2)
                    signals.append({"note_index": note_index, "number": number, "code": code, "errno": ctypes.c_int32(signal.si_errno).value,
                                    "fault_address": hex(signal.sigfault_addr) if known else None,
                                    "fault_address_meaning": "recorded-sigsegv-address" if known else "unknown", "thread_association": "unknown"})
        return {"format": "elf-core", "architecture": "x86_64-little-endian", "target_execution": "not-performed", "live_process_identity": "unknown",
                "segments": segments, "notes": notes, "note_padding": padding, "threads": threads, "signals": signals,
                "note_interpretation_completeness": "unknown",
                "limitations": ["The initial Linux note profile accepts System V/unspecified or GNU/Linux OSABI with ABI version zero; an unspecified OSABI alone does not prove operating-system origin.",
                                "Historical PID and signal values are recorded metadata, not current process identity or attach authority.",
                                "Only exact Linux CORE NT_PRSTATUS/NT_SIGINFO owners are interpreted; every descriptor and owner retains original bytes. Other note semantics remain unknown.",
                                "NT_SIGINFO thread association is unknown. Only SIGSEGV SEGV_MAPERR/SEGV_ACCERR initially establish a fault-address union meaning.",
                                "PT_LOAD file bytes are recorded bytes. Undumped memory and current executable/library identity remain unknown; no current host file is resolved from a recorded pathname.",
                                "Missing notes/registers/signals do not establish their absence at the original crash. Full unwinding, executable pairing and live control are not provided."]}
    except CoreFailure:
        raise
    except (ELFError, ValueError, AssertionError, IndexError) as error:
        raise CoreFailure("format", "Recorded core failed unchanged upstream structural parsing: " + str(error)) from error


if __name__ == "__main__":
    runtime_path = Path(__file__).with_name("decoder_runtime.py")
    runtime = {"__file__": str(runtime_path), "__name__": "rea_decoder_runtime"}
    exec(compile(runtime_path.read_bytes(), str(runtime_path), "exec"), runtime)
    runtime["main"](sys.argv[-1], inspect_core, CoreFailure, PROFILE)
