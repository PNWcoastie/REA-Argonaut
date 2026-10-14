# Forensic Vertical Routing Matrix (39 Domains & Canonical MCP Tools)

Use this routing matrix to immediately select the canonical `ArgonZeroG` MCP tool (registered in `src/contracts/toolContracts.ts`) based on magic bytes, file extensions, or section headers.

---

## 1. Universal 4-Mount Recon Kit & Primary Forensic Vertical Routing Table

| # | Forensic Vertical | Magic Bytes / Signatures / Extensions | Primary MCP Tool | Follow-Up Tools |
| :--- | :--- | :--- | :--- | :--- |
| 0 | **Universal 4-Mount Recon Kit** | Any native binary, packaged UI/game archive, firmware/protocol capture, or AI model/SQLite artifact | `export_recon_kit` | Native `ask_question` -> `decompile_subgraph` / `verify_rust_parity` |
| 1 | **Go Binaries** | `.gopclntab` / `runtime.pclntab` (`0xfffffffb`, `0xfffffffa`, `0xfffffff0`, `0xfffffff1`), `go.buildid` | `inspect_go_binary` | `open_binary` -> `decompile_subgraph` |
| 2 | **Stripped Rust & C++ Binaries** | `_RNv...` (Rust v0), `_ZN...` (Rust legacy / Itanium C++), `core::panicking::Location`, RTTI `_ZTV`/`_ZTI`/MSVC `vftable` | `inspect_rust_cpp_binary` | `open_binary` -> `decompile_subgraph` -> `verify_rust_parity` |
| 3 | **Frozen Python & PyInstaller** | `.pyc` PEP 552 magic (`3.8`–`3.14`), PyInstaller `MEI\x0c\x0b\x0a\x0b\x0e` CArchive trailer | `inspect_python_frozen_binary` | `search_strings` |
| 4 | **AI Models & Prompt Forensics** | `GGUF` (`0x46554747` v1–v3), `.safetensors`, `.onnx`, `.tflite` (`TFL3`) | `inspect_ai_model_artifact` | `export_recon_kit` (Mount 4) |
| 5 | **Game & App Engine Archives** | `0xFAB11BAF` (Unity `global-metadata.dat`), `GDPC` (Godot `.pck`), Chromium Pickle JSON header (Electron `.asar`) | `inspect_engine_archive` | `inspect_managed_artifact` / `decompile_subgraph` |
| 6 | **WebAssembly / WASI** | `00 61 73 6D 01 00 00 00` (`\0asm`), `.wasm` | `inspect_wasm_artifact` | `search_strings` |
| 7 | **Android APK / DEX & Mobile** | `PK\x03\x04` (`.apk`/`.aab`), `64 65 78 0A 30 33 35 00` (`dex\n035\0`, `.dex`) | `inspect_android_package` | `search_strings` |
| 8 | **.NET CIL / CLR Assemblies** | PE `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`, `BSJB` (`0x424A5342`) metadata root | `inspect_managed_artifact` | `inspect_pe_resources` |
| 9 | **EVM / Solidity Bytecode** | `60 80 60 40 52` (`PUSH1 0x80 PUSH1 0x40 MSTORE`), `.bin` / `.hex` | `inspect_evm_interface` | — |
| 10 | **Firmware / SVD / UF2 / DTB** | `D0 0D FE ED` (`.dtb`), `<device schemaVersion=` (`.svd`), `UF2\n`, Cortex-M ROMs (`.bin`/`.hex`) | `inspect_firmware_regions` | `extract_firmware` / `export_recon_kit` (Mount 3) |
| 11 | **Network Captures (PCAP / HAR)** | `D4 C3 B2 A1` / `A1 B2 C3 D4` (`.pcap`), `0A 0D 0D 0A` (`.pcapng`), `.har` | `inspect_packet_capture` | `inspect_web_network_capture` |
| 12 | **Logic Analyzer / Digital Signals** | Sigrok `.sr`, VCD, Saleae CSV digital waveform captures | `decode_signal_recording` | `export_recon_kit` (Mount 3) |
| 13 | **SQLite Databases** | `SQLite format 3\0` (`.sqlite`, `.db`, `.sqlite3`) | `inspect_sqlite_database` | `export_recon_kit` (Mount 4) |
| 14 | **JavaScript / Electron / Web Apps** | Bundled/minified `.js`, SourceMaps (`.js.map`), Hermes/QuickJS/V8 bundles | `analyze_javascript_application` | `inspect_engine_archive` |
| 15 | **Crash Dumps & Core Files** | ELF `ET_CORE` (`e_type == 4`), Windows Minidump (`MDMP`, `.dmp`) | `inspect_recorded_crash` | `inspect_binary_layout` / `open_binary` |
| 16 | **Generic / Packed / Media / Shaders** | UPX/packed blobs, SPIR-V (`.spv`), DXBC, PDF, Office, archives, unknown blobs | `inspect_artifact` | `inspect_binary_layout` / `inspect_pe_resources` |

---

## 2. Native Container Inspection Routing (ELF vs. PE vs. Mach-O)

| Container Format | Magic Bytes | Primary Container Inspector | Decompilation & Parity Pipeline |
| :--- | :--- | :--- | :--- |
| **Linux / System V ELF** (`.so`, `.so.1`, PIE executables, `.o`, `.bpf.o`) | `7F 45 4C 46` (`\x7fELF`) | `inspect_binary_layout` + `inspect_rust_cpp_binary` | `open_binary({ path, provider_id: "auto" })` -> `binary_overview({})` -> `decompile_subgraph` -> `verify_rust_parity` |
| **Windows PE / COFF** (`.exe`, `.dll`, `.sys`, `.efi`) | `4D 5A` (`MZ`) + `PE\0\0` | `inspect_pe_resources` + `inspect_rust_cpp_binary` | `open_binary({ path, provider_id: "auto" })` -> `binary_overview({})` -> `decompile_subgraph` -> `verify_rust_parity` |
| **Apple Mach-O** (`.dylib`, `.bundle`, universal fat binaries) | `FE ED FA CF` / `CF FA ED FE` / `CA FE BA BE` | `inspect_binary_layout` + `inspect_rust_cpp_binary` | `open_binary({ path, provider_id: "auto" })` -> `binary_overview({})` -> `decompile_subgraph` -> `verify_rust_parity` |

> [!IMPORTANT]
> For Windows PE binaries (`.exe`/`.dll`/`.sys`), always use `inspect_pe_resources`, `inspect_rust_cpp_binary`, and `open_binary` + `binary_overview` rather than the ELF-oriented `inspect_binary_layout` tool.
