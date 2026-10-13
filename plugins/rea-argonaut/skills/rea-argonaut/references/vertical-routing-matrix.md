# Forensic Vertical Routing Matrix (16 Domains + Core Containers)

Use this routing matrix to immediately select the highest-precision `ArgonZeroG` MCP tool based on magic bytes, file extensions, or section headers.

---

## 1. Primary 16-Vertical Routing Table

| # | Forensic Vertical | Magic Bytes / Signatures / Extensions | Primary MCP Tool | Follow-Up Tools |
| :--- | :--- | :--- | :--- | :--- |
| 1 | **Go Binaries** | `.gopclntab` / `runtime.pclntab` (`0xfffffffb`, `0xfffffffa`, `0xfffffff0`, `0xfffffff1`), `go.buildid` | `inspect_go_binary` | `open_binary` -> `decompile_subgraph` |
| 2 | **Rust & C++ Binaries** | `_RNv...` (Rust v0), `_ZN...` (Rust legacy / Itanium C++), `.gcc_except_table`, RTTI `_ZTV`/`_ZTI` | `inspect_rust_cpp_binary` | `open_binary` -> `decompile_subgraph` |
| 3 | **WebAssembly / WASI** | `00 61 73 6D 01 00 00 00` (`\0asm`), `.wasm` | `inspect_wasm_module` | `extract_strings` |
| 4 | **JVM & Android DEX** | `CA FE BA BE` (`.class`), `64 65 78 0A 30 33 35 00` (`dex\n035\0`, `.dex`) | `inspect_jvm_dex` | `extract_strings` |
| 5 | **Packer / Entropy / YARA** | `UPX!`, `.vmp0`, `.themida`, high Shannon entropy ($H > 6.8$) | `detect_packing_and_yara` | `inspect_binary_layout` / `inspect_pe_resources` |
| 6 | **Linux eBPF Objects** | ELF `e_machine == 247` (`EM_BPF`), `.BTF`, `xdp`/`kprobe`/`tracepoint`, `.bpf.o` | `inspect_ebpf_object` | `inspect_binary_layout` |
| 7 | **Firmware / SVD / DTB** | `D0 0D FE ED` (`.dtb`), `<device schemaVersion=` (`.svd`), Cortex-M vector tables (`.bin`/`.hex`) | `inspect_firmware_blob` | `open_binary` -> `decompile_subgraph` |
| 8 | **Game & App Engines** | `AF 1B B1 FA` (Unity `global-metadata.dat`), `GDPC` (Godot `.pck`), Chromium Pickle JSON header (Electron `.asar`) | `inspect_engine_archive` | `inspect_dotnet_assembly` / `extract_strings` |
| 9 | **Python Bytecode / PyInstaller** | `.pyc` magic + `\r\n`, `MEI\x0c\x0b\x0a\x0b\x0e` trailer | `inspect_python_bytecode` | `extract_strings` |
| 10 | **.NET CIL / CLR** | PE `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`, `BSJB` (`0x424A5342`) metadata root | `inspect_dotnet_assembly` | `inspect_pe_resources` |
| 11 | **Solana SBF / BPF** | ELF `EM_BPF` (`247`) or `0x28` with `entrypoint` & `sol_invoke_signed_*` syscalls | `inspect_solana_program` | `open_binary` -> `decompile_subgraph` |
| 12 | **EVM / Solidity Bytecode** | `60 80 60 40 52` (`PUSH1 0x80 PUSH1 0x40 MSTORE`), `.bin` / `.hex` | `inspect_evm_bytecode` | — |
| 13 | **UEFI / DXE / TE** | `_FVH` (`0x4856465F`, `.fv`), `VZ` (`0x5A56`, `.te`), PE32+ Subsystem `10..13` (`.efi`) | `inspect_uefi_image` | `open_binary` -> `decompile_subgraph` |
| 14 | **Shaders & Media** | `03 02 23 07` (SPIR-V `.spv`), `DXBC` (`.dxbc`), `ftyp`/`moov` (MP4), `1A 45 DF A3` (MKV/WebM), `RIFF` | `inspect_media_shader` | `extract_strings` |
| 15 | **Network Captures (PCAP)** | `D4 C3 B2 A1` / `A1 B2 C3 D4` (`.pcap`), `0A 0D 0D 0A` (`.pcapng`) | `inspect_network_capture` | — |
| 16 | **Retro & Mainframe** | `MZ`/`NE`/`LE`/`LX` (16-bit DOS/OS2), `00 00 03 F3` (Amiga Hunk), `Joy!peff` (Mac PEF), ELF `EM_S390` (`22`) / EBCDIC | `inspect_retro_binary` | `extract_strings` |

---

## 2. Native Container Inspection Routing (ELF vs. PE vs. Mach-O)

| Container Format | Magic Bytes | Primary Container Inspector | Decompilation & Parity Pipeline |
| :--- | :--- | :--- | :--- |
| **Linux / System V ELF** (`.so`, `.so.1`, PIE executables, `.o`) | `7F 45 4C 46` (`\x7fELF`) | `inspect_binary_layout` | `open_binary({ path, provider_id: "auto" })` -> `binary_overview({})` -> `decompile_subgraph` -> `verify_rust_parity` |
| **Windows PE / COFF** (`.exe`, `.dll`, `.sys`) | `4D 5A` (`MZ`) + `PE\0\0` | `inspect_pe_resources` + `inspect_rust_cpp_binary` | `open_binary({ path, provider_id: "auto" })` -> `binary_overview({})` -> `decompile_subgraph` -> `verify_rust_parity` |
| **Apple Mach-O** (`.dylib`, `.bundle`, universal fat binaries) | `FE ED FA CF` / `CF FA ED FE` / `CA FE BA BE` | `inspect_macho` + `inspect_rust_cpp_binary` | `open_binary({ path, provider_id: "auto" })` -> `binary_overview({})` -> `decompile_subgraph` -> `verify_rust_parity` |

> [!IMPORTANT]
> `inspect_binary_layout` is an ELF-specific structural analyzer (`readelf`/`objdump`/DWARF). Do **not** invoke `inspect_binary_layout` on Windows PE (`.exe`/`.dll`) or macOS Mach-O binaries; use `inspect_pe_resources` / `inspect_macho`, `inspect_rust_cpp_binary`, and `open_binary` + `binary_overview` instead.
