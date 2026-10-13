"""Offline adapter to unchanged pwntools 4.15.0; never use libs/maps/libc.

Owned request/snapshot/reply paths are supplied by REA. No host target-process launch,
user configuration initialization, debugger startup, or dependency installation.
"""
import base64
import importlib.metadata
import io
import json
import os
from pathlib import Path
import resource
import shutil
import struct
import subprocess
import sys

PROFILE = "pwntools@4.15.0;pyelftools@0.33;unicorn@2.1.2"
PACKAGES = {"pwntools": "4.15.0", "pyelftools": "0.33", "unicorn": "2.1.2"}
OUTPUT_BYTES = 64 * 1024 * 1024

SHT_MAP = {
    0: "SHT_NULL",
    1: "SHT_PROGBITS",
    2: "SHT_SYMTAB",
    3: "SHT_STRTAB",
    4: "SHT_RELA",
    5: "SHT_HASH",
    6: "SHT_DYNAMIC",
    7: "SHT_NOTE",
    8: "SHT_NOBITS",
    9: "SHT_REL",
    10: "SHT_SHLIB",
    11: "SHT_DYNSYM",
    14: "SHT_INIT_ARRAY",
    15: "SHT_FINI_ARRAY",
    16: "SHT_PREINIT_ARRAY",
    17: "SHT_GROUP",
    18: "SHT_SYMTAB_SHNDX",
    19: "SHT_RELR",
    0x6FFFFFF5: "SHT_GNU_ATTRIBUTES",
    0x6FFFFFF6: "SHT_GNU_HASH",
    0x6FFFFFFD: "SHT_GNU_verdef",
    0x6FFFFFFE: "SHT_GNU_verneed",
    0x6FFFFFFF: "SHT_GNU_versym",
    0x70000001: "SHT_X86_64_UNWIND",
}

PT_MAP = {
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

STB_MAP = {
    0: "STB_LOCAL",
    1: "STB_GLOBAL",
    2: "STB_WEAK",
    10: "STB_LOOS",
    12: "STB_HIOS",
    13: "STB_LOPROC",
    15: "STB_HIPROC",
}

STT_MAP = {
    0: "STT_NOTYPE",
    1: "STT_OBJECT",
    2: "STT_FUNC",
    3: "STT_SECTION",
    4: "STT_FILE",
    5: "STT_COMMON",
    6: "STT_TLS",
    10: "STT_LOOS",
    12: "STT_HIOS",
    13: "STT_LOPROC",
    15: "STT_HIPROC",
}

STV_MAP = {
    0: "STV_DEFAULT",
    1: "STV_INTERNAL",
    2: "STV_HIDDEN",
    3: "STV_PROTECTED",
}

SHN_MAP = {
    0: "SHN_UNDEF",
    0xFF00: "SHN_LOPROC",
    0xFF1F: "SHN_HIPROC",
    0xFF20: "SHN_LOOS",
    0xFF3F: "SHN_HIOS",
    0xFFF1: "SHN_ABS",
    0xFFF2: "SHN_COMMON",
    0xFFFF: "SHN_XINDEX",
}

DT_MAP = {
    0: "DT_NULL",
    1: "DT_NEEDED",
    2: "DT_PLTRELSZ",
    3: "DT_PLTGOT",
    4: "DT_HASH",
    5: "DT_STRTAB",
    6: "DT_SYMTAB",
    7: "DT_RELA",
    8: "DT_RELASZ",
    9: "DT_RELAENT",
    10: "DT_STRSZ",
    11: "DT_SYMENT",
    12: "DT_INIT",
    13: "DT_FINI",
    14: "DT_SONAME",
    15: "DT_RPATH",
    16: "DT_SYMBOLIC",
    17: "DT_REL",
    18: "DT_RELSZ",
    19: "DT_RELENT",
    20: "DT_PLTREL",
    21: "DT_DEBUG",
    22: "DT_TEXTREL",
    23: "DT_JMPREL",
    24: "DT_BIND_NOW",
    29: "DT_RUNPATH",
    30: "DT_FLAGS",
    0x6FFFFFFB: "DT_FLAGS_1",
}


class LayoutFailure(Exception):
    def __init__(self, reason, message):
        super().__init__(message)
        self.reason = reason


def address(value):
    return hex(int(value))


def file_range(offset, size, length):
    return 0 <= offset <= length and 0 <= size <= length - offset


def location(offset, size, length):
    if not file_range(offset, size, length):
        raise LayoutFailure("format", "ELF contains a file-backed range outside the selected snapshot.")
    return {"offset": address(offset), "bytes": address(size)}


def name_reference(display, section, offset, content):
    header = getattr(section, "header", None)
    if header is None or header.sh_type != "SHT_STRTAB":
        return {"display": display, "bytes_base64": None, "location": None,
                "unknown_reason": "Referenced string table could not be resolved."}
    return name_in_table(display, header.sh_offset, header.sh_size, offset, content)


def name_in_table(display, table_start, table_size, offset, content):
    location(table_start, table_size, len(content))
    if not 0 <= offset < table_size:
        raise LayoutFailure("format", f"ELF name offset {offset} lies outside its declared string table of {table_size} bytes at file offset {table_start}.")
    start = table_start + offset
    limit = table_start + table_size
    end = content.find(b"\0", start, limit)
    if end < 0:
        raise LayoutFailure("format", "ELF name lacks a terminator within its reported string table.")
    raw = content[start:end]
    return {"display": raw.decode("utf-8", "replace") if display is None else display, "bytes_base64": base64.b64encode(raw).decode("ascii"),
            "location": location(start, len(raw) + 1, len(content)), "unknown_reason": None}


def dynamic_name_reference(tags, offset, image, content):
    starts = [tag.d_val for tag in tags if tag.d_tag == "DT_STRTAB"]
    sizes = [tag.d_val for tag in tags if tag.d_tag == "DT_STRSZ"]
    if not starts or not sizes:
        raise LayoutFailure("format", "ELF dependency requires DT_STRTAB and DT_STRSZ.")
    if len(starts) != 1 or len(sizes) != 1:
        raise LayoutFailure("unsupported-target", "ELF dependency string-table tags are ambiguous: " + repr({"DT_STRTAB": starts, "DT_STRSZ": sizes}))
    if not 0 <= offset < sizes[0]:
        raise LayoutFailure("format", f"ELF dependency name offset {offset} lies outside declared DT_STRSZ {sizes[0]}.")
    offsets = set()
    if len(starts) == 1 and len(sizes) == 1:
        for segment in image.iter_segments_by_type("PT_LOAD"):
            h = segment.header
            if starts[0] >= h.p_vaddr and starts[0] + sizes[0] <= h.p_vaddr + h.p_filesz:
                offsets.add(h.p_offset + starts[0] - h.p_vaddr)
    if len(offsets) != 1:
        raise LayoutFailure("unsupported-target", "Dynamic string table lacks a unique file-backed mapping: " + repr({"DT_STRTAB": starts, "DT_STRSZ": sizes, "candidate_file_offsets": sorted(offsets)}))
    return name_in_table(None, offsets.pop(), sizes[0], offset, content)


def symbol_value_meaning(raw, image_type, sections):
    index = raw.st_shndx
    if raw.st_info.type == "STT_FILE": return "no-address"
    if index == "SHN_UNDEF": return "undefined"
    if index == "SHN_COMMON": return "alignment"
    if index == "SHN_ABS": return "absolute-value"
    if not isinstance(index, int) or not 0 < index < len(sections) or index >= 0xff00:
        return "unknown-section-index"
    if sections[index].header.sh_type == "SHT_NULL":
        return "unknown-section-index"
    if image_type == "ET_REL": return "section-offset"
    if raw.st_info.type == "STT_TLS": return "tls-offset"
    return "linked-virtual-address"


def relocation_target(image_type, section_index, offset, sections):
    if image_type != "ET_REL":
        return {"kind": "linked-virtual-address", "address": address(offset)}
    if section_index == 0 or sections[section_index].header.sh_type == "SHT_NULL":
        return {"kind": "unknown-section", "reported_section_index": section_index,
                "offset": address(offset), "unknown_reason": "undefined-section-reference" if section_index == 0 else "inactive-section-header"}
    return {"kind": "section-offset", "section_index": section_index, "offset": address(offset)}


class _StdlibAttrDict(dict):
    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError as error:
            raise AttributeError(key) from error


class _StdlibSection:
    def __init__(self, header_dict):
        self.header = _StdlibAttrDict(header_dict)


class _StdlibSegment:
    def __init__(self, header_dict):
        self.header = _StdlibAttrDict(header_dict)


class _StdlibImage:
    def __init__(self, segments):
        self._segments = segments

    def iter_segments_by_type(self, seg_type):
        return (s for s in self._segments if s.header.p_type == seg_type)


def _decode_relr_entries_stdlib(content, sh_offset, sh_size, sh_entsize):
    if sh_entsize == 0 or sh_size % sh_entsize != 0 or sh_entsize != 8:
        raise LayoutFailure("format", "ELF RELR section has invalid entry size or unaligned byte length.")
    entries = []
    where = 0
    for off in range(sh_offset, sh_offset + sh_size, 8):
        (word,) = struct.unpack_from("<Q", content, off)
        if (word & 1) == 0:
            where = word
            entries.append({"decoded_index": len(entries), "reported_offset": address(where)})
            where += 8
        else:
            bitmap = word >> 1
            bit = 0
            while bitmap:
                if bitmap & 1:
                    entries.append({"decoded_index": len(entries), "reported_offset": address(where + bit * 8)})
                bitmap >>= 1
                bit += 1
            where += 63 * 8
    return entries


def _infer_got_plt_stdlib(image_type, all_sections, symbols_by_table, relocations, content):
    if image_type == "ET_REL":
        return [], []
    got_map = {}
    addr_to_name = {}
    for rel in relocations:
        sym_idx = rel["symbol_index"]
        table_idx = rel["symbol_table_index"]
        if sym_idx == 0:
            continue
        table_syms = symbols_by_table.get(table_idx, [])
        if 0 <= sym_idx < len(table_syms):
            sym_name = table_syms[sym_idx]["name"]["display"]
            if sym_name:
                rel_addr = int(rel["reported_offset"], 16)
                got_map[sym_name] = rel_addr
                addr_to_name[rel_addr] = sym_name
    plt_map = {}
    for sec in all_sections:
        h = sec.header
        if h.sh_type != "SHT_PROGBITS" or h.sh_size == 0:
            continue
        sec_data = content[h.sh_offset:h.sh_offset + h.sh_size]
        # Scan for jmp qword ptr [rip + disp32] (ff 25 <disp32>) inside PLT stubs
        pos = 0
        while pos + 6 <= len(sec_data):
            idx = sec_data.find(b"\xff\x25", pos)
            if idx < 0 or idx + 6 > len(sec_data):
                break
            (disp,) = struct.unpack_from("<i", sec_data, idx + 2)
            insn_vaddr = h.sh_addr + idx
            target_got = (insn_vaddr + 6 + disp) & 0xFFFFFFFFFFFFFFFF
            if target_got in addr_to_name:
                sym_name = addr_to_name[target_got]
                stub_addr = insn_vaddr - 4 if idx >= 4 and sec_data[idx - 4:idx] == b"\xf3\x0f\x1e\xfa" else insn_vaddr
                if sym_name not in plt_map:
                    plt_map[sym_name] = stub_addr
            pos = idx + 2
    got_list = [{"display_name": k, "address": address(v)} for k, v in got_map.items()]
    plt_list = [{"display_name": k, "address": address(v)} for k, v in plt_map.items()]
    return got_list, plt_list


def _inspect_elf_stdlib(content):
    length = len(content)
    (
        e_type_num,
        e_machine_num,
        e_version,
        e_entry,
        e_phoff,
        e_shoff,
        e_flags,
        e_ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    ) = struct.unpack_from("<HHIQQQIHHHHHH", content, 16)
    if e_version != 1:
        raise LayoutFailure("format", "ELF header version is not EV_CURRENT.")
    image_type = {1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN"}.get(e_type_num)
    if image_type is None:
        raise LayoutFailure("unsupported-target", "Selected ELF type is outside the EXEC/DYN/REL layout profile; recorded core analysis is separate.")

    section_count = e_shnum
    sh0_link = 0
    sh0_info = 0
    if e_shoff != 0 and (e_shnum == 0 or e_shstrndx == 0xFFFF or e_phnum == 0xFFFF):
        if e_shentsize < 64:
            raise LayoutFailure("format", "ELF section header entry size is smaller than Elf64_Shdr.")
        location(e_shoff, e_shentsize, length)
        _, _, _, _, _, sh0_size, sh0_link, sh0_info, _, _ = struct.unpack_from("<IIQQQQIIQQ", content, e_shoff)
        if e_shnum == 0:
            section_count = sh0_size
    elif e_shoff == 0 and e_shnum != 0:
        raise LayoutFailure("format", "ELF declares non-zero section count with zero section header offset.")

    if section_count > 0:
        if e_shentsize < 64:
            raise LayoutFailure("format", "ELF section header entry size is smaller than Elf64_Shdr.")
        location(e_shoff, section_count * e_shentsize, length)

    raw_name_index = e_shstrndx
    if raw_name_index == 0xFFFF and section_count == 0:
        raise LayoutFailure("format", "ELF extended section-name index requires a declared section-zero header.")
    if 0xFF00 <= raw_name_index < 0xFFFF:
        raise LayoutFailure("format", f"ELF section-name index {raw_name_index} is reserved and cannot directly reference a section.")
    section_name_index = sh0_link if raw_name_index == 0xFFFF else raw_name_index
    if raw_name_index == 0xFFFF and section_name_index < 0xFF00:
        raise LayoutFailure("format", f"ELF SHN_XINDEX resolves to ordinary index {section_name_index}; the escape requires an index at least SHN_LORESERVE (0xff00).")

    all_sections = []
    for idx in range(section_count):
        hdr_off = e_shoff + idx * e_shentsize
        location(hdr_off, e_shentsize, length)
        sh_name, sh_type_num, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack_from(
            "<IIQQQQIIQQ", content, hdr_off
        )
        sh_type = SHT_MAP.get(sh_type_num, sh_type_num)
        all_sections.append(
            _StdlibSection(
                {
                    "sh_name": sh_name,
                    "sh_type": sh_type,
                    "sh_flags": sh_flags,
                    "sh_addr": sh_addr,
                    "sh_offset": sh_offset,
                    "sh_size": sh_size,
                    "sh_link": sh_link,
                    "sh_info": sh_info,
                    "sh_addralign": sh_addralign,
                    "sh_entsize": sh_entsize,
                }
            )
        )

    if section_name_index != 0:
        if section_name_index >= section_count:
            raise LayoutFailure("format", f"ELF section-name table index {section_name_index} lies outside the declared section count {section_count}.")
        names_header = all_sections[section_name_index].header
        if names_header.sh_type != "SHT_STRTAB":
            raise LayoutFailure("format", f"ELF section-name table {section_name_index} is not SHT_STRTAB.")
        location(names_header.sh_offset, names_header.sh_size, length)

    shstrings = all_sections[section_name_index] if all_sections and section_name_index != 0 else None
    sections, segments, symbols, relocations, packed_relatives = [], [], [], [], []
    needed, interpreters = [], []
    symbols_by_table = {}
    dynamic_tags_all = []

    for index, section in enumerate(all_sections):
        h = section.header
        backing = h.sh_type not in ("SHT_NOBITS", "SHT_NULL")
        if backing:
            location(h.sh_offset, h.sh_size, length)
        sec_name_obj = (
            name_reference(None, shstrings, h.sh_name, content)
            if shstrings is not None
            else {
                "display": "",
                "bytes_base64": None,
                "location": None,
                "unknown_reason": "ELF declares no section-name table (SHN_UNDEF index 0).",
            }
        )
        sections.append(
            {
                "index": index,
                "name": sec_name_obj,
                "name_offset": address(h.sh_name),
                "type": h.sh_type,
                "header_location": location(e_shoff + index * e_shentsize, e_shentsize, length),
                "address": address(h.sh_addr),
                "offset": address(h.sh_offset),
                "size": address(h.sh_size),
                "alignment": address(h.sh_addralign),
                "flags": address(h.sh_flags),
                "link": h.sh_link,
                "info": h.sh_info,
                "entry_size": address(h.sh_entsize),
                "file_backing": "file" if backing else "none",
            }
        )
        if h.sh_type in ("SHT_SYMTAB", "SHT_DYNSYM"):
            if h.sh_entsize < 24:
                raise LayoutFailure("format", "ELF symbol entry is smaller than the decoded Elf64_Sym structure.")
            if h.sh_link >= len(all_sections) or all_sections[h.sh_link].header.sh_type != "SHT_STRTAB":
                raise LayoutFailure("format", f"ELF symbol table {index} links to invalid string table {h.sh_link}.")
            strings = all_sections[h.sh_link]
            location(strings.header.sh_offset, strings.header.sh_size, length)
            num_syms = h.sh_size // h.sh_entsize
            table_list = []
            for entry in range(num_syms):
                sym_off = h.sh_offset + entry * h.sh_entsize
                location(sym_off, h.sh_entsize, length)
                st_name, st_info, st_other, st_shndx_num, st_value, st_size = struct.unpack_from("<IBBHQQ", content, sym_off)
                bind_val = STB_MAP.get(st_info >> 4, st_info >> 4)
                type_val = STT_MAP.get(st_info & 0xF, st_info & 0xF)
                vis_val = STV_MAP.get(st_other & 0x3, st_other & 0x3)
                shndx_val = SHN_MAP.get(st_shndx_num, st_shndx_num)
                raw_sym = _StdlibAttrDict(
                    {
                        "st_name": st_name,
                        "st_value": st_value,
                        "st_size": st_size,
                        "st_shndx": shndx_val,
                        "st_info": _StdlibAttrDict({"bind": bind_val, "type": type_val}),
                        "st_other": _StdlibAttrDict({"visibility": vis_val}),
                    }
                )
                sym_item = {
                    "table_index": index,
                    "entry_index": entry,
                    "name": name_reference(None, strings, st_name, content),
                    "name_offset": address(st_name),
                    "location": location(sym_off, h.sh_entsize, length),
                    "value": address(st_value),
                    "value_meaning": symbol_value_meaning(raw_sym, image_type, all_sections),
                    "size": address(st_size),
                    "binding": bind_val,
                    "type": type_val,
                    "visibility": vis_val,
                    "section_index": shndx_val,
                }
                symbols.append(sym_item)
                table_list.append(sym_item)
            symbols_by_table[index] = table_list

    for index, section in enumerate(all_sections):
        h = section.header
        if h.sh_type in ("SHT_REL", "SHT_RELA"):
            min_ent = 24 if h.sh_type == "SHT_RELA" else 16
            if h.sh_entsize < min_ent or h.sh_size % h.sh_entsize != 0:
                raise LayoutFailure(
                    "format",
                    f"ELF relocation section {index} size is not a multiple of its {h.sh_entsize}-byte entries.",
                )
            if image_type == "ET_REL" and h.sh_info >= len(all_sections):
                raise LayoutFailure("format", f"ELF relocation section {index} references missing target section {h.sh_info}.")
            symtab_count = 0
            if h.sh_link != 0:
                if h.sh_link >= len(all_sections) or all_sections[h.sh_link].header.sh_type not in ("SHT_SYMTAB", "SHT_DYNSYM"):
                    raise LayoutFailure("format", f"ELF relocation section {index} links to invalid symbol table {h.sh_link}.")
                symtab_sec = all_sections[h.sh_link].header
                if symtab_sec.sh_entsize < 24:
                    raise LayoutFailure("format", "ELF symbol entry is smaller than the decoded Elf64_Sym structure.")
                symtab_count = symtab_sec.sh_size // symtab_sec.sh_entsize
            num_rels = h.sh_size // h.sh_entsize
            for entry in range(num_rels):
                rel_off = h.sh_offset + entry * h.sh_entsize
                location(rel_off, h.sh_entsize, length)
                if h.sh_type == "SHT_RELA":
                    r_offset, r_info, r_addend = struct.unpack_from("<QQq", content, rel_off)
                    addend_str = str(r_addend)
                else:
                    r_offset, r_info = struct.unpack_from("<QQ", content, rel_off)
                    addend_str = None
                r_info_sym = r_info >> 32
                r_info_type = r_info & 0xFFFFFFFF
                if r_info_sym != 0 and (h.sh_link == 0 or r_info_sym >= symtab_count):
                    raise LayoutFailure("format", f"ELF relocation section {index} entry {entry} references missing symbol {r_info_sym} in table {h.sh_link}.")
                relocations.append(
                    {
                        "section_index": index,
                        "entry_index": entry,
                        "reported_offset": address(r_offset),
                        "target": relocation_target(image_type, h.sh_info, r_offset, all_sections),
                        "location": location(rel_off, h.sh_entsize, length),
                        "type": r_info_type,
                        "symbol_table_index": h.sh_link,
                        "symbol_index": r_info_sym,
                        "symbol_reference_meaning": "zero-symbol-value" if r_info_sym == 0 else "symbol-table-entry",
                        "addend": addend_str,
                    }
                )
        elif h.sh_type == "SHT_RELR":
            packed_relatives.append(
                {
                    "section_index": index,
                    "location": location(h.sh_offset, h.sh_size, length),
                    "encoded_bytes_base64": base64.b64encode(content[h.sh_offset:h.sh_offset + h.sh_size]).decode("ascii"),
                    "entries": _decode_relr_entries_stdlib(content, h.sh_offset, h.sh_size, h.sh_entsize),
                    "offset_meaning": "unknown" if image_type == "ET_REL" else "linked-virtual-address",
                    "evidence_kind": "derived",
                    "entry_source_locations": None,
                    "addends": None,
                }
            )

    ph_count = sh0_info if e_phnum == 0xFFFF else e_phnum
    raw_segments = []
    if ph_count > 0:
        if e_phentsize < 56:
            raise LayoutFailure("format", "ELF program header entry size is smaller than Elf64_Phdr.")
        location(e_phoff, ph_count * e_phentsize, length)
        for index in range(ph_count):
            ph_off = e_phoff + index * e_phentsize
            location(ph_off, e_phentsize, length)
            p_type_num, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from("<IIQQQQQQ", content, ph_off)
            p_type = PT_MAP.get(p_type_num, p_type_num)
            raw_segments.append(
                _StdlibSegment(
                    {
                        "p_type": p_type,
                        "p_flags": p_flags,
                        "p_offset": p_offset,
                        "p_vaddr": p_vaddr,
                        "p_paddr": p_paddr,
                        "p_filesz": p_filesz,
                        "p_memsz": p_memsz,
                        "p_align": p_align,
                    }
                )
            )

    stdlib_image = _StdlibImage(raw_segments)
    for index, segment in enumerate(raw_segments):
        h = segment.header
        backing = h.p_type != "PT_NULL" and h.p_filesz != 0
        if backing:
            location(h.p_offset, h.p_filesz, length)
        if h.p_type == "PT_LOAD" and h.p_memsz < h.p_filesz:
            raise LayoutFailure("format", "ELF load segment memory size is smaller than its file size.")
        segments.append(
            {
                "index": index,
                "type": h.p_type,
                "offset": address(h.p_offset),
                "header_location": location(e_phoff + index * e_phentsize, e_phentsize, length),
                "file_size": address(h.p_filesz),
                "memory_size": address(h.p_memsz),
                "virtual_address": address(h.p_vaddr),
                "physical_address": address(h.p_paddr),
                "alignment": address(h.p_align),
                "flags": address(h.p_flags),
                "file_backing": "file" if backing else "none",
                "permissions": None if h.p_type == "PT_NULL" else {"read": bool(h.p_flags & 4), "write": bool(h.p_flags & 2), "execute": bool(h.p_flags & 1)},
            }
        )
        if h.p_type == "PT_DYNAMIC":
            tag_size = 16
            tags = []
            for tag_index in range(h.p_filesz // tag_size):
                d_tag_num, d_val = struct.unpack_from("<Qq", content, h.p_offset + tag_index * tag_size)
                d_val_u = d_val & 0xFFFFFFFFFFFFFFFF
                d_tag = DT_MAP.get(d_tag_num, d_tag_num)
                tag = _StdlibAttrDict({"d_tag": d_tag, "d_val": d_val_u})
                tags.append(tag)
                dynamic_tags_all.append(tag)
                if d_tag == "DT_NULL":
                    break
            else:
                raise LayoutFailure("format", f"ELF dynamic segment {index} has no complete DT_NULL terminator within its reported file range.")
            for tag in tags:
                if tag.d_tag == "DT_NEEDED":
                    needed.append(dynamic_name_reference(tags, tag.d_val, stdlib_image, content))
        if h.p_type == "PT_INTERP":
            raw = content[h.p_offset:h.p_offset + h.p_filesz]
            end = raw.find(b"\0")
            if end < 0:
                raise LayoutFailure("format", "ELF interpreter lacks a reported terminator.")
            interpreters.append(
                {
                    "display": raw[:end].decode("utf-8", "replace"),
                    "bytes_base64": base64.b64encode(raw[:end]).decode("ascii"),
                    "location": location(h.p_offset, end + 1, length),
                    "unknown_reason": None,
                }
            )

    got_list, plt_list = _infer_got_plt_stdlib(image_type, all_sections, symbols_by_table, relocations, content)

    # Mitigations inference matching pwntools static heuristics
    pie = image_type == "ET_DYN"
    gnu_stack_segs = [s for s in raw_segments if s.header.p_type == "PT_GNU_STACK"]
    if gnu_stack_segs:
        execstack = any(bool(s.header.p_flags & 1) for s in gnu_stack_segs)
        nx = not execstack
    else:
        nx = False
        execstack = bool(raw_segments)
    canary = any(
        sym["name"]["display"] in ("__stack_chk_fail", "__stack_chk_guard", "__intel_security_cookie")
        for sym in symbols
    )
    has_relro_seg = any(s.header.p_type == "PT_GNU_RELRO" for s in raw_segments)
    bind_now = any(
        (t.d_tag == "DT_BIND_NOW")
        or (t.d_tag == "DT_FLAGS" and (t.d_val & 0x8))
        or (t.d_tag == "DT_FLAGS_1" and (t.d_val & 0x1))
        for t in dynamic_tags_all
    )
    if has_relro_seg:
        relro = "Full" if bind_now else "Partial"
    elif bind_now:
        relro = "Partial"
    else:
        relro = None

    return {
        "format": "elf",
        "architecture": {"machine": "EM_X86_64", "bits": 64, "byte_order": "little"},
        "image_type": image_type,
        "entry_point": {
            "reported_value": address(e_entry),
            "meaning": "not-applicable" if image_type == "ET_REL" else "absent" if e_entry == 0 else "linked-virtual-address",
            "execution_status": "unknown",
        },
        "runtime_load_base": None,
        "sections": sections,
        "segments": segments,
        "symbols": symbols,
        "relocations": relocations,
        "packed_relative_relocations": packed_relatives,
        "relocation_inventory_completeness": "unknown",
        "linkage": {
            "needed_libraries": needed,
            "interpreters": interpreters,
            "got": got_list,
            "plt": plt_list,
            "convenience_maps_completeness": "unknown",
            "runtime_library_paths": None,
        },
        "mitigations": {
            "evidence_kind": "inferred",
            "position_independent": pie,
            "nx_indicator": nx,
            "executable_stack_indicator": execstack,
            "stack_canary_indicator": canary,
            "relro": relro,
        },
        "limitations": [
            "PT_NULL payload fields are unused and retain their reported numbers without file-byte or permission claims. Zero-file-size segments provide no file bytes.",
            "SHN_XINDEX symbol values remain unresolved in this upstream representation; an external index table does not establish a resolved index in this report.",
            "Reported values preserve linked addresses, section offsets, TLS offsets, alignment and absolute values separately. Runtime load base and library paths are unknown.",
            "Names are display strings plus raw bytes and file ranges where resolvable; section/table/entry indices preserve identity and duplicates. Name ranges include their terminating NUL; raw name bytes exclude it.",
            "Ordinary relocation rows cover REL/RELA. RELR tables retain complete encoded bytes and upstream-decoded offsets as derived evidence; per-offset packed-word locations and implicit addends remain unknown. Relocation inventory completeness is unknown, including other encodings and missing section tables.",
            "Relocation symbol index zero uses a zero symbol value without a table lookup. Positive indices reference validated original symbol-table entries; raw table and symbol indices remain reported.",
            "Relocatable relocation targets with SHN_UNDEF or inactive SHT_NULL headers retain their reported section index/offset as unknown; they do not establish an associated target section.",
            "GOT/PLT are derived upstream convenience maps; PLT inference can emulate selected instructions in Unicorn. They do not establish target runtime behavior; aliases may collapse and warnings may indicate incomplete coverage. Their completeness is unknown.",
            "Mitigations are upstream static heuristics, not runtime protection. ET_DYN does not prove an executable; absent canary symbols do not prove every function unprotected.",
            "This profile inspects ELF EXEC/DYN/REL layout only. It does not analyze recorded cores, resolve loaded libraries, launch the target as a host process or start a debugger.",
            "Symbol/relocation inventories reflect original section tables. A sectionless image can still report dynamic dependency names; missing tables do not prove absence of dynamic symbols or relocations.",
            *(["Absent section-name table: section-dependent RELRO/canary heuristics may be incomplete; protection coverage is unknown."] if all_sections and section_name_index == 0 else []),
            *(["Sectionless images lack the .dynamic section and symbol tables used by upstream heuristics. RELRO/canary indicators may be incomplete; their values remain reported static candidates, with protection coverage unknown."] if not all_sections else []),
        ],
    }


def inspect_macho_stdlib(content):
    """Zero-dependency Mach-O (32/64-bit thin & Universal) structural parser using Python stdlib."""
    if len(content) < 28:
        raise LayoutFailure("format", "Mach-O image is truncated.")
    magic_be = struct.unpack_from(">I", content, 0)[0]
    if magic_be in (0xCAFEBABE, 0xCAFEBABF):
        nfat_arch = struct.unpack_from(">I", content, 4)[0]
        if nfat_arch == 0 or len(content) < 8 + nfat_arch * 20:
            raise LayoutFailure("format", "Universal Mach-O fat header is truncated.")
        offset = struct.unpack_from(">I", content, 16)[0]
        size = struct.unpack_from(">I", content, 20)[0]
        content = content[offset:offset + size]
    magic_le = struct.unpack_from("<I", content, 0)[0]
    is_64 = magic_le in (0xFEEDFACF, 0xCFFAEDFE)
    endian = "<" if magic_le in (0xFEEDFACE, 0xFEEDFACF) else ">"
    hdr_fmt = endian + ("IIIIIIII" if is_64 else "IIIIIII")
    hdr_fields = struct.unpack_from(hdr_fmt, content, 0)
    ncmds = hdr_fields[4]
    cmd_offset = 32 if is_64 else 28
    segments = []
    sections = []
    for _ in range(ncmds):
        if cmd_offset + 8 > len(content):
            break
        cmd, cmdsize = struct.unpack_from(endian + "II", content, cmd_offset)
        if cmd in (0x1, 0x19) and cmdsize >= (72 if cmd == 0x19 else 56):
            segname = content[cmd_offset + 8:cmd_offset + 24].split(b"\0", 1)[0].decode("utf-8", "replace")
            if cmd == 0x19:
                vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags = struct.unpack_from(
                    endian + "QQQQiiII", content, cmd_offset + 24
                )
                sect_off = cmd_offset + 72
                sect_stride = 80
            else:
                vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags = struct.unpack_from(
                    endian + "IIIIiiII", content, cmd_offset + 24
                )
                sect_off = cmd_offset + 56
                sect_stride = 68
            segments.append({"name": segname, "vmaddr": address(vmaddr), "vmsize": address(vmsize), "fileoff": address(fileoff), "filesize": address(filesize), "initprot": initprot})
            for _ in range(nsects):
                if sect_off + sect_stride <= len(content):
                    sectname = content[sect_off:sect_off + 16].split(b"\0", 1)[0].decode("utf-8", "replace")
                    sections.append({"name": sectname, "segment": segname})
                sect_off += sect_stride
        cmd_offset += max(cmdsize, 8)
    return {"format": "mach-o", "bits": 64 if is_64 else 32, "segments": segments, "sections": sections}


def inspect_pe_stdlib(content):
    """Zero-dependency PE/COFF (PE32/PE32+) structural parser using Python stdlib."""
    if len(content) < 0x40 or content[:2] != b"MZ":
        raise LayoutFailure("format", "PE image lacks MZ DOS header.")
    pe_offset = struct.unpack_from("<I", content, 0x3C)[0]
    if pe_offset + 24 > len(content) or content[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        raise LayoutFailure("format", "PE image lacks PE signature.")
    machine, num_sections, _, _, _, opt_hdr_size, characteristics = struct.unpack_from("<HHIIIHH", content, pe_offset + 4)
    opt_offset = pe_offset + 24
    opt_magic = struct.unpack_from("<H", content, opt_offset)[0] if opt_hdr_size >= 2 else 0
    is_pe32_plus = opt_magic == 0x20B
    sec_table_off = opt_offset + opt_hdr_size
    sections = []
    for idx in range(num_sections):
        off = sec_table_off + idx * 40
        if off + 40 > len(content):
            break
        raw_name = content[off:off + 8].split(b"\0", 1)[0].decode("utf-8", "replace")
        vsize, vaddr, raw_size, raw_ptr, _, _, _, _, sec_chars = struct.unpack_from("<IIIIIIHHI", content, off + 8)
        sections.append({"index": idx, "name": raw_name, "virtual_address": address(vaddr), "virtual_size": address(vsize), "raw_offset": address(raw_ptr), "raw_size": address(raw_size), "characteristics": address(sec_chars)})
    return {"format": "pe", "bits": 64 if is_pe32_plus else 32, "machine": address(machine), "characteristics": address(characteristics), "sections": sections}


def _has_pinned_pwntools():
    for package, expected in PACKAGES.items():
        try:
            version = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            return False, ("unavailable", "Selected Python lacks " + package + " " + expected + ".")
        if version != expected:
            return False, ("unsupported", "Expected " + package + " " + expected + "; selected Python reports " + version + ".")
    try:
        import elftools  # noqa: F401
        import pwnlib  # noqa: F401
    except ImportError as error:
        return False, ("unavailable", str(error))
    return True, None


def inspect_elf(path, cache):
    content = path.read_bytes()
    if len(content) < 4 or content[:4] != b"\x7fELF":
        raise LayoutFailure("format", "Selected object does not contain an ELF header.")
    if len(content) < 16:
        raise LayoutFailure("format", "Selected ELF identification is truncated.")
    if content[4] != 2 or content[5] != 1:
        raise LayoutFailure("unsupported-target", "Initial layout profile requires ELF64 little-endian objects.")
    if len(content) < 64:
        raise LayoutFailure("format", "Selected ELF64 header is truncated.")
    if int.from_bytes(content[18:20], "little") != 62:
        raise LayoutFailure("unsupported-target", "Initial layout profile requires x86-64 ELF objects.")
    if int.from_bytes(content[16:18], "little") not in (1, 2, 3):
        raise LayoutFailure("unsupported-target", "Selected ELF type is outside the EXEC/DYN/REL layout profile; recorded core analysis is separate.")
    has_pwntools, _ = _has_pinned_pwntools()
    if not has_pwntools:
        try:
            return _inspect_elf_stdlib(content)
        except LayoutFailure:
            raise
        except (struct.error, ValueError, AssertionError, IndexError) as error:
            raise LayoutFailure("format", "Selected ELF failed stdlib structural parsing: " + str(error)) from error
    from pwnlib.context import context
    with context.local(cache_dir=str(cache), log_level="warning"):
        from elftools.common.exceptions import ELFError
        from elftools.elf.elffile import ELFFile
        from pwnlib.elf import ELF
        try:
            headers = ELFFile(io.BytesIO(content))
            section_count = headers.num_sections()
            if headers.header.e_shstrndx == 0xffff and section_count == 0:
                raise LayoutFailure("format", "ELF extended section-name index requires a declared section-zero header.")
            raw_name_index = headers.header.e_shstrndx
            if 0xff00 <= raw_name_index < 0xffff:
                raise LayoutFailure("format", f"ELF section-name index {raw_name_index} is reserved and cannot directly reference a section.")
            section_name_index = headers.get_shstrndx()
            if raw_name_index == 0xffff and section_name_index < 0xff00:
                raise LayoutFailure("format", f"ELF SHN_XINDEX resolves to ordinary index {section_name_index}; the escape requires an index at least SHN_LORESERVE (0xff00).")
            if section_name_index != 0:
                if section_name_index >= section_count:
                    raise LayoutFailure("format", f"ELF section-name table index {section_name_index} lies outside the declared section count {section_count}.")
                names_header = headers._get_section_header(section_name_index)
                if names_header.sh_type != "SHT_STRTAB":
                    raise LayoutFailure("format", f"ELF section-name table {section_name_index} is not SHT_STRTAB.")
                location(names_header.sh_offset, names_header.sh_size, len(content))
        except ELFError as error:
            raise LayoutFailure("format", str(error)) from error
        class LayoutELF(ELF):
            def _get_section_name(self, header):
                # SHN_UNDEF declares no names; upstream would otherwise read
                # strings at the inactive section-zero offset.
                return "" if section_name_index == 0 else super()._get_section_name(header)

            # pyelftools 0.33 calls these documented filters internally;
            # pwntools 4.15.0's cached overrides do not accept the argument.
            # Forward the filter on this adapter instance, without modifying
            # either upstream package or process-global methods.
            def iter_segments(self, type=None):
                return (segment for segment in super().iter_segments()
                        if type is None or segment.header.p_type == type)

            def iter_sections(self, type=None):
                return (section for section in super().iter_sections()
                        if type is None or section.header.sh_type == type)
        try:
            image = LayoutELF(str(path), checksec=False)
            if image.arch != "amd64" or image.bits != 64 or image.endian != "little":
                raise LayoutFailure("unsupported-target", "Initial layout profile requires x86-64 ELF64 little-endian objects.")
            if image.header.e_type not in ("ET_EXEC", "ET_DYN", "ET_REL"):
                raise LayoutFailure("unsupported-target", "Selected ELF type is outside the EXEC/DYN/REL layout profile; recorded core analysis is separate.")
            length = len(content)
            all_sections = list(image.iter_sections())
            shstrings = image.get_section(section_name_index) if all_sections and section_name_index != 0 else None
            sections, segments, symbols, relocations, packed_relatives = [], [], [], [], []
            needed, interpreters = [], []
            for index, section in enumerate(all_sections):
                h = section.header
                backing = h.sh_type not in ("SHT_NOBITS", "SHT_NULL")
                if backing: location(h.sh_offset, h.sh_size, length)
                sections.append({
                    "index": index, "name": name_reference(section.name, shstrings, h.sh_name, content) if shstrings is not None else {"display": "", "bytes_base64": None, "location": None, "unknown_reason": "ELF declares no section-name table (SHN_UNDEF index 0)."}, "name_offset": address(h.sh_name), "type": h.sh_type,
                    "header_location": location(image.header.e_shoff + index * image.header.e_shentsize, image.header.e_shentsize, length),
                    "address": address(h.sh_addr), "offset": address(h.sh_offset),
                    "size": address(h.sh_size), "alignment": address(h.sh_addralign),
                    "flags": address(h.sh_flags), "link": h.sh_link, "info": h.sh_info,
                    "entry_size": address(h.sh_entsize), "file_backing": "file" if backing else "none",
                })
                if h.sh_type in ("SHT_SYMTAB", "SHT_DYNSYM"):
                    if h.sh_entsize < image.structs.Elf_Sym.sizeof():
                        raise LayoutFailure("format", "ELF symbol entry is smaller than the decoded Elf64_Sym structure.")
                    if h.sh_link >= len(all_sections) or all_sections[h.sh_link].header.sh_type != "SHT_STRTAB":
                        raise LayoutFailure("format", f"ELF symbol table {index} links to invalid string table {h.sh_link}.")
                    strings = all_sections[h.sh_link]
                    for entry, symbol in enumerate(section.iter_symbols()):
                        raw = symbol.entry
                        symbols.append({
                            "table_index": index, "entry_index": entry,
                            "name": name_reference(symbol.name, strings, raw.st_name, content), "name_offset": address(raw.st_name),
                            "location": location(h.sh_offset + entry * h.sh_entsize, h.sh_entsize, length),
                            "value": address(raw.st_value), "value_meaning": symbol_value_meaning(raw, image.header.e_type, all_sections),
                            "size": address(raw.st_size), "binding": raw.st_info.bind, "type": raw.st_info.type,
                            "visibility": raw.st_other.visibility, "section_index": raw.st_shndx,
                        })
                if h.sh_type in ("SHT_REL", "SHT_RELA"):
                    if h.sh_size % h.sh_entsize != 0:
                        raise LayoutFailure(
                            "format",
                            f"ELF relocation section {index} size is not a multiple of its {h.sh_entsize}-byte entries.",
                        )
                    if image.header.e_type == "ET_REL" and h.sh_info >= len(all_sections):
                        raise LayoutFailure("format", f"ELF relocation section {index} references missing target section {h.sh_info}.")
                    symbol_table = None
                    if h.sh_link != 0:
                        if h.sh_link >= len(all_sections) or all_sections[h.sh_link].header.sh_type not in ("SHT_SYMTAB", "SHT_DYNSYM"):
                            raise LayoutFailure("format", f"ELF relocation section {index} links to invalid symbol table {h.sh_link}.")
                        symbol_table = all_sections[h.sh_link]
                    for entry, relocation in enumerate(section.iter_relocations()):
                        raw = relocation.entry
                        if raw.r_info_sym != 0 and (symbol_table is None or raw.r_info_sym >= symbol_table.num_symbols()):
                            raise LayoutFailure("format", f"ELF relocation section {index} entry {entry} references missing symbol {raw.r_info_sym} in table {h.sh_link}.")
                        relocations.append({
                            "section_index": index, "entry_index": entry, "reported_offset": address(raw.r_offset),
                            "target": relocation_target(image.header.e_type, h.sh_info, raw.r_offset, all_sections),
                            "location": location(h.sh_offset + entry * h.sh_entsize, h.sh_entsize, length),
                            "type": raw.r_info_type, "symbol_table_index": h.sh_link, "symbol_index": raw.r_info_sym,
                            "symbol_reference_meaning": "zero-symbol-value" if raw.r_info_sym == 0 else "symbol-table-entry",
                            "addend": None if "r_addend" not in raw else str(raw.r_addend),
                        })
                if h.sh_type == "SHT_RELR":
                    packed_relatives.append({
                        "section_index": index,
                        "location": location(h.sh_offset, h.sh_size, length),
                        "encoded_bytes_base64": base64.b64encode(content[h.sh_offset:h.sh_offset + h.sh_size]).decode("ascii"),
                        "entries": [{"decoded_index": decoded, "reported_offset": address(relocation.entry.r_offset)} for decoded, relocation in enumerate(section.iter_relocations())],
                        "offset_meaning": "unknown" if image.header.e_type == "ET_REL" else "linked-virtual-address",
                        "evidence_kind": "derived", "entry_source_locations": None, "addends": None,
                    })
            for index, segment in enumerate(image.iter_segments()):
                h = segment.header
                backing = h.p_type != "PT_NULL" and h.p_filesz != 0
                if backing: location(h.p_offset, h.p_filesz, length)
                if h.p_type == "PT_LOAD" and h.p_memsz < h.p_filesz:
                    raise LayoutFailure("format", "ELF load segment memory size is smaller than its file size.")
                segments.append({
                    "index": index, "type": h.p_type, "offset": address(h.p_offset),
                    "header_location": location(image.header.e_phoff + index * image.header.e_phentsize, image.header.e_phentsize, length),
                    "file_size": address(h.p_filesz), "memory_size": address(h.p_memsz),
                    "virtual_address": address(h.p_vaddr), "physical_address": address(h.p_paddr),
                    "alignment": address(h.p_align), "flags": address(h.p_flags),
                    "file_backing": "file" if backing else "none",
                    "permissions": None if h.p_type == "PT_NULL" else {"read": bool(h.p_flags & 4), "write": bool(h.p_flags & 2), "execute": bool(h.p_flags & 1)},
                })
                if h.p_type == "PT_DYNAMIC":
                    tag_size = image.structs.Elf_Dyn.sizeof()
                    tags = []
                    for tag_index in range(h.p_filesz // tag_size):
                        tag = segment._get_tag(tag_index)
                        tags.append(tag)
                        if tag.d_tag == "DT_NULL":
                            break
                    else:
                        raise LayoutFailure("format", f"ELF dynamic segment {index} has no complete DT_NULL terminator within its reported file range.")
                    for tag in tags:
                        if tag.d_tag == "DT_NEEDED":
                            needed.append(dynamic_name_reference(tags, tag.d_val, image, content))
                if h.p_type == "PT_INTERP":
                    raw = content[h.p_offset:h.p_offset + h.p_filesz]
                    end = raw.find(b"\0")
                    if end < 0:
                        raise LayoutFailure("format", "ELF interpreter lacks a reported terminator.")
                    interpreters.append({"display": raw[:end].decode("utf-8", "replace"), "bytes_base64": base64.b64encode(raw[:end]).decode("ascii"), "location": location(h.p_offset, end + 1, length), "unknown_reason": None})
            return {
                "format": "elf", "architecture": {"machine": image.header.e_machine, "bits": image.bits, "byte_order": image.endian},
                "image_type": image.header.e_type,
                "entry_point": {"reported_value": address(image.header.e_entry), "meaning": "not-applicable" if image.header.e_type == "ET_REL" else "absent" if image.header.e_entry == 0 else "linked-virtual-address", "execution_status": "unknown"},
                "runtime_load_base": None, "sections": sections, "segments": segments, "symbols": symbols, "relocations": relocations,
                "packed_relative_relocations": packed_relatives, "relocation_inventory_completeness": "unknown",
                "linkage": {"needed_libraries": needed, "interpreters": interpreters,
                    "got": [{"display_name": name, "address": address(value)} for name, value in image.got.items()],
                    "plt": [{"display_name": name, "address": address(value)} for name, value in image.plt.items()],
                    "convenience_maps_completeness": "unknown", "runtime_library_paths": None},
                "mitigations": {"evidence_kind": "inferred", "position_independent": image.pie, "nx_indicator": image.nx, "executable_stack_indicator": image.execstack, "stack_canary_indicator": image.canary, "relro": image.relro},
                "limitations": [
                    "PT_NULL payload fields are unused and retain their reported numbers without file-byte or permission claims. Zero-file-size segments provide no file bytes.",
                    "SHN_XINDEX symbol values remain unresolved in this upstream representation; an external index table does not establish a resolved index in this report.",
                    "Reported values preserve linked addresses, section offsets, TLS offsets, alignment and absolute values separately. Runtime load base and library paths are unknown.",
                    "Names are display strings plus raw bytes and file ranges where resolvable; section/table/entry indices preserve identity and duplicates. Name ranges include their terminating NUL; raw name bytes exclude it.",
                    "Ordinary relocation rows cover REL/RELA. RELR tables retain complete encoded bytes and upstream-decoded offsets as derived evidence; per-offset packed-word locations and implicit addends remain unknown. Relocation inventory completeness is unknown, including other encodings and missing section tables.",
                    "Relocation symbol index zero uses a zero symbol value without a table lookup. Positive indices reference validated original symbol-table entries; raw table and symbol indices remain reported.",
                    "Relocatable relocation targets with SHN_UNDEF or inactive SHT_NULL headers retain their reported section index/offset as unknown; they do not establish an associated target section.",
                    "GOT/PLT are derived upstream convenience maps; PLT inference can emulate selected instructions in Unicorn. They do not establish target runtime behavior; aliases may collapse and warnings may indicate incomplete coverage. Their completeness is unknown.",
                    "Mitigations are upstream static heuristics, not runtime protection. ET_DYN does not prove an executable; absent canary symbols do not prove every function unprotected.",
                    "This profile inspects ELF EXEC/DYN/REL layout only. It does not analyze recorded cores, resolve loaded libraries, launch the target as a host process or start a debugger.",
                    "Symbol/relocation inventories reflect original section tables. A sectionless image can still report dynamic dependency names; missing tables do not prove absence of dynamic symbols or relocations.",
                    *(["Absent section-name table: section-dependent RELRO/canary heuristics may be incomplete; protection coverage is unknown."] if all_sections and section_name_index == 0 else []),
                    *(["Sectionless images lack the .dynamic section and symbol tables used by upstream heuristics. RELRO/canary indicators may be incomplete; their values remain reported static candidates, with protection coverage unknown."] if not all_sections else []),
                ],
            }
        except LayoutFailure:
            raise
        except (ELFError, ValueError, AssertionError, IndexError) as error:
            raise LayoutFailure("format", "Selected ELF failed unchanged upstream structural parsing: " + str(error)) from error


if __name__ == "__main__":
    runtime_path = Path(__file__).with_name("decoder_runtime.py")
    runtime = {"__file__": str(runtime_path), "__name__": "rea_decoder_runtime"}
    exec(compile(runtime_path.read_bytes(), str(runtime_path), "exec"), runtime)
    runtime["main"](sys.argv[-1], inspect_elf, LayoutFailure, PROFILE)

