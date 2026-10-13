# Niche Forensic Verticals Guide (16 Domains)

`ArgonZeroG` ships deterministic, pure-TypeScript binary parsers for 16 specialized reverse-engineering verticals. Always invoke the domain-specific vertical tool **before** falling back to generic instruction disassembly.

---

## 1. Go Binaries (`inspect_go_binary`)
- **Target**: ELF, PE, and Mach-O binaries compiled by `gc` (`go build`).
- **Forensic Capabilities**:
  - Parses `.gopclntab` (`runtime.pclntab`) across Go 1.2, 1.16, 1.18, and 1.20+ magic headers (`0xfffffffb`, `0xfffffffa`, `0xfffffff0`, `0xfffffff1`).
  - Recovers stripped function names, entry virtual addresses, and source file paths even when standard ELF/PE symbol tables are stripped (`-ldflags="-s -w"`).
  - Extracts embedded Go compiler version and module build info (`runtime.buildVersion`).
- **Invocation**:
  ```json
  { "path": "/path/to/go_binary", "max_functions": 250 }
  ```

---

## 2. Rust & Modern C++ Binaries (`inspect_rust_cpp_binary`)
- **Target**: Rust (`rustc`) and C++ (`gcc`/`clang`/`MSVC`) ELF, PE, and Mach-O binaries.
- **Forensic Capabilities**:
  - Demangles Rust **v0** (`_RNv...`) and **legacy** (`_ZN...17h...E`) symbols alongside Itanium C++ ABI (`_Z...`) symbols.
  - Extracts crate dependency graphs from embedded `.comment`, `.rodata` panic strings (`src/main.rs`, `/cargo/registry/src/...`), and `rustc` commit hashes.
  - Reconstructs C++ RTTI (`_ZTV` vtables, `_ZTI` typeinfo structures) and virtual method dispatch tables.
- **Invocation**:
  ```json
  { "path": "/path/to/rust_or_cpp_binary", "max_symbols": 250 }
  ```

---

## 3. WebAssembly & WASI Modules (`inspect_wasm_module`)
- **Target**: `.wasm` modules (`\0asm` magic `0x00 0x61 0x73 0x6d`, version `0x01`).
- **Forensic Capabilities**:
  - Decodes all standard WASM sections (`Type`, `Import`, `Function`, `Table`, `Memory`, `Global`, `Export`, `Element`, `Code`, `Data`) and custom `.debug` / `name` sections.
  - Flags WASI capability imports (`wasi_snapshot_preview1`, `fd_write`, `path_open`, `sock_accept`, `proc_exit`) and linear memory boundaries.
- **Invocation**:
  ```json
  { "path": "/path/to/module.wasm" }
  ```

---

## 4. JVM `.class` & Android DEX (`inspect_jvm_dex`)
- **Target**: Java `.class` (`0xCAFEBABE`) and Android Dalvik Executable `.dex` (`dex\n035\0` .. `dex\n039\0`).
- **Forensic Capabilities**:
  - `.class`: Parses constant pool tags, access flags, class/superclass/interface hierarchies, field descriptors, and method bytecode attributes (`Code`, `Exceptions`).
  - `.dex`: Parses `header_item`, `string_ids`, `type_ids`, `proto_ids`, `field_ids`, `method_ids`, and `class_defs`, plus JNI `native` method bindings.
- **Invocation**:
  ```json
  { "path": "/path/to/classes.dex" }
  ```

---

## 5. Packer, Entropy & YARA Triage (`detect_packing_and_yara`)
- **Target**: Obfuscated, packed, or unknown binaries across ELF, PE, Mach-O, or raw blobs.
- **Forensic Capabilities**:
  - Computes per-section and sliding-window Shannon entropy ($H \in [0.0, 8.0]$ bits/byte), automatically flagging encrypted/compressed sections ($H > 6.8$).
  - Detects UPX (`UPX0`, `UPX1`, `UPX!` magic), VMProtect (`.vmp0`, `.vmp1`), Themida, ASPack, and MPress signatures.
  - Evaluates built-in and custom YARA-style hex/string/regex rules for crypto constants (AES S-Boxes, SHA-256 initial vectors, ChaCha20 `"expand 32-byte k"`) and anti-debug markers.
- **Invocation**:
  ```json
  { "path": "/path/to/suspect.bin" }
  ```

---

## 6. eBPF Object Programs (`inspect_ebpf_object`)
- **Target**: Linux eBPF ELF relocatable objects (`.bpf.o`, `EM_BPF = 247`).
- **Forensic Capabilities**:
  - Enumerates hook program sections (`xdp`, `tc`, `kprobe/*`, `kretprobe/*`, `tracepoint/*`, `lsm/*`, `cgroup/*`).
  - Parses BPF map definitions (`maps` / `.maps` BTF-defined maps: `BPF_MAP_TYPE_HASH`, `BPF_MAP_TYPE_ARRAY`, `BPF_MAP_TYPE_RINGBUF`, `BPF_MAP_TYPE_PERF_EVENT_ARRAY`).
  - Resolves BPF helper calls (`bpf_probe_read_kernel`, `bpf_skb_load_bytes`, `bpf_override_return`) and `.BTF` / `.BTF.ext` CO-RE relocation metadata.
- **Invocation**:
  ```json
  { "path": "/path/to/filter.bpf.o" }
  ```

---

## 7. Crypto Firmware, SVD & DeviceTree (`inspect_firmware_blob`)
- **Target**: Flattened DeviceTree blobs (`.dtb`, magic `0xD00DFEED`), CMSIS-SVD XML peripheral maps (`.svd`), and raw microcontroller ROMs (`.bin`, `.hex`).
- **Forensic Capabilities**:
  - `.dtb`: Parses `fdt_header`, structure block tokens (`FDT_BEGIN_NODE`, `FDT_PROP`), memory-mapped register ranges (`reg`), and interrupt controllers.
  - `.svd`: Extracts peripheral base addresses, register offsets, bitfields, and read/write permissions.
  - Raw ARM Cortex-M firmware: Identifies initial MSP (Main Stack Pointer), Reset_Handler vector tables, and candidate load base addresses.
- **Invocation**:
  ```json
  { "path": "/path/to/board.dtb" }
  ```

---

## 8. Game & Application Engine Archives (`inspect_engine_archive`)
- **Target**:
  1. **Unity IL2CPP**: `global-metadata.dat` (magic `0xFAB11BAF`).
  2. **Godot Engine**: `.pck` resource packs (magic `GDPC` / `0x43504447`).
  3. **Electron**: `.asar` archives (Chromium Pickle header + JSON directory tree).
- **Forensic Capabilities**:
  - Unity `global-metadata.dat`: Extracts IL2CPP header version, string literal tables, namespace/type definitions, and method metadata offsets.
  - Godot `.pck`: Extracts engine version, pack flags, and embedded file paths, offsets, sizes, and MD5 hashes.
  - Electron `.asar`: Parses the Chromium Pickle uint32 header framing and recursively enumerates the embedded JSON virtual filesystem (`files`, `offset`, `size`, `unpacked`, `integrity`).
- **Invocation**:
  ```json
  { "path": "/path/to/app.asar" }
  ```

---

## 9. Python `.pyc` & PyInstaller Archives (`inspect_python_bytecode`)
- **Target**: Compiled Python `.pyc` files (Python 2.7 through 3.13 magic numbers) and PyInstaller `MEI` (`MEI\x0c\x0b\x0a\x0b\x0e`) executables/archives.
- **Forensic Capabilities**:
  - `.pyc`: Parses magic number, PEP 552 bitfield/timestamp/hash headers, and marshaled `PyCodeObject` trees (`co_name`, `co_varnames`, `co_names`, `co_consts`, `co_code`).
  - PyInstaller: Locates the `MEI` CArchive cookie at EOF, parses the Table of Contents (TOC), and lists bundled `.pyc` modules, C extensions (`.so`/`.pyd`), and embedded data files.
- **Invocation**:
  ```json
  { "path": "/path/to/module.pyc" }
  ```

---

## 10. .NET CIL / CLR Assemblies (`inspect_dotnet_assembly`)
- **Target**: Managed Windows PE `.exe` / `.dll` assemblies containing a CLI header (`IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`).
- **Forensic Capabilities**:
  - Parses the `#~` / `#-` metadata table stream (`Module`, `TypeRef`, `TypeDef`, `Field`, `MethodDef`, `Param`, `InterfaceImpl`, `MemberRef`, `CustomAttribute`, `ImplMap`), `#Strings`, `#US` (user strings), `#GUID`, and `#Blob` heaps.
  - Extracts `[DllImport]` P/Invoke unmanaged native bindings (`ImplMap`) and method RVA locations.
- **Invocation**:
  ```json
  { "path": "/path/to/ManagedAssembly.dll" }
  ```

---

## 11. Solana SBF / BPF On-Chain Programs (`inspect_solana_program`)
- **Target**: Solana SBF/BPF shared objects (`.so`, ELF `EM_BPF = 247` or legacy `0x28`).
- **Forensic Capabilities**:
  - Extracts the `entrypoint` symbol and detects Anchor framework 8-byte `sha256("global:<instruction_name>")[0..8]` instruction discriminators and account validation handlers.
  - Audits Solana runtime syscalls (`sol_invoke_signed_c`, `sol_invoke_signed_rust`, `sol_log_`, `sol_sha256`, `sol_keccak256`, `sol_set_return_data`) for Cross-Program Invocation (CPI) and signer privilege analysis.
- **Invocation**:
  ```json
  { "path": "/path/to/solana_program.so" }
  ```

---

## 12. EVM / Solidity Smart Contract Bytecode (`inspect_evm_bytecode`)
- **Target**: Raw EVM bytecode `.bin` or hex-encoded `.hex` files (runtime or creation bytecode).
- **Forensic Capabilities**:
  - Disassembles EVM opcodes (`PUSH1`..`PUSH32`, `CALLDATALOAD`, `SHR`, `EQ`, `JUMPI`, `SSTORE`, `SLOAD`, `DELEGATECALL`, `SELFDESTRUCT`).
  - Extracts 4-byte Solidity function selector dispatch tables (`PUSH4 0x........ EQ PUSH2 0x.... JUMPI`) and resolves common ABI signatures (`transfer(address,uint256)`, `approve(address,uint256)`, `balanceOf(address)`).
  - Decodes appended CBOR compiler metadata (`ipfs://`, `bzzr0`, `solc` version).
- **Invocation**:
  ```json
  { "path": "/path/to/contract.bin" }
  ```

---

## 13. UEFI Firmware Volumes, TE & DXE Drivers (`inspect_uefi_image`)
- **Target**: UEFI Firmware Volumes (`.fv`, `_FVH` signature `0x4856465F`), Terse Executables (`.te`, `VZ` magic `0x5A56`), and EFI PE32+ DXE/SMM drivers (`.efi`).
- **Forensic Capabilities**:
  - Parses `EFI_FIRMWARE_VOLUME_HEADER`, FFS file GUIDs, and section headers.
  - Parses Terse Executable (`EFI_TE_IMAGE_HEADER`) stripped headers used in SEC/PEI phases.
  - Detects well-known EFI protocol GUIDs (`EFI_SMM_BASE2_PROTOCOL_GUID`, `EFI_DXE_SERVICES_TABLE_GUID`, `EFI_GLOBAL_VARIABLE`) and NVRAM variable service calls (`GetVariable`, `SetVariable`).
- **Invocation**:
  ```json
  { "path": "/path/to/driver.efi" }
  ```

---

## 14. Multimedia Containers & Shader Bytecode (`inspect_media_shader`)
- **Target**:
  - **Shaders**: Vulkan/OpenGL SPIR-V (`.spv`, magic `0x07230203`) and DirectX DXBC (`.dxbc`, magic `DXBC`).
  - **Containers**: ISO Base Media File Format (`MP4`/`MOV` `ftyp`/`moov`/`mdat` atoms), Matroska/WebM (`EBML` `0x1A45DFA3`), and RIFF (`WAV`/`AVI`/`WEBP`).
- **Forensic Capabilities**:
  - SPIR-V: Parses version, generator magic, bound IDs, execution models (`Vertex`, `Fragment`, `GLCompute`), `OpEntryPoint`, and `OpName` debug symbols.
  - DXBC: Parses chunk directory (`RDEF`, `ISGN`, `OSGN`, `SHDR`/`SHEX`, `STAT`).
  - Containers: Walks box/chunk trees and flags anomalous out-of-bounds atom sizes or trailing hidden payloads.
- **Invocation**:
  ```json
  { "path": "/path/to/shader.spv" }
  ```

---

## 15. Network Protocol Payloads & PCAP (`inspect_network_capture`)
- **Target**: Classic libpcap (`.pcap`, magic `0xA1B2C3D4` / `0xD4C3B2A1` / nanosecond `0xA1B23C4D`) and PCAPNG (`.pcapng`, Section Header Block `0x0A0D0D0A`).
- **Forensic Capabilities**:
  - Parses link-layer frames (Ethernet II / Linux cooked SLL), IPv4/IPv6 headers, and TCP/UDP flows.
  - Performs deep packet inspection (DPI) for DNS queries/responses, TLS ClientHello SNI (Server Name Indication) & JA3 fingerprint components, HTTP/1.1 headers, and HTTP/2 connection preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`).
- **Invocation**:
  ```json
  { "path": "/path/to/capture.pcap" }
  ```

---

## 16. Legacy Mainframe & Retro Architectures (`inspect_retro_binary`)
- **Target**:
  - **MS-DOS / 16-bit**: MZ (`MZ` / `ZM`), NE (16-bit New Executable), LE/LX (Linear Executable / DOS4GW).
  - **AmigaOS**: Amiga Hunk executables (`HUNK_HEADER = 0x000003F3`).
  - **Classic Mac OS / PowerPC**: Preferred Executable Format (`Joy!peff` / `pwpc`).
  - **IBM Mainframe**: z/Architecture / System/390 ELF (`EM_S390 = 22`) and EBCDIC text/record streams.
- **Forensic Capabilities**:
  - Parses segment/relocation tables, hunk allocations (`HUNK_CODE`, `HUNK_DATA`, `HUNK_BSS`, `HUNK_RELOC32`), PEF loader sections, and translates EBCDIC string literals to UTF-8.
- **Invocation**:
  ```json
  { "path": "/path/to/legacy.bin" }
  ```
