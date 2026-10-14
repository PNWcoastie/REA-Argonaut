# Specialized Forensic Verticals Guide (Canonical MCP Tools)

`ArgonZeroG` ships deterministic, execution-free binary and container inspectors across all specialized reverse-engineering verticals. Always invoke `export_recon_kit` or the domain-specific vertical MCP tool **before** falling back to generic instruction disassembly.

---

## 0. Universal 4-Mount Recon Kit (`export_recon_kit`)
- **Target**: Any native binary (`ELF`, `PE`, `Mach-O`), packaged UI/game archive (`IL2CPP`, `Godot .pck`, `Electron .asar`, `PyInstaller`, `APK/DEX`, `.NET`), hardware/firmware/protocol artifact (`SVD`, `DBC`, `UF2`, `DTB`, `PCAP`, `Sigrok`), or AI model/data artifact (`GGUF`, `SafeTensors`, `ONNX`, `TFLite`, `SQLite`).
- **Forensic Capabilities**:
  - Automatically detects all applicable mounts (`Mount 1..4`) and writes `RECON_BLUEPRINT.md` and `recon-kit/*.md` + `.json` artifacts directly to `output_dir`.
  - Emits `0` unsolicited `.html` files by default (`mock_ui_concepts: false`).
- **Invocation**:
  ```json
  { "path": "/path/to/target_artifact", "mount_override": "auto", "mock_ui_concepts": false }
  ```

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

## 2. Stripped Rust & Modern C++ Binaries (`inspect_rust_cpp_binary`)
- **Target**: Rust (`rustc`) and C++ (`gcc`/`clang`/`MSVC`) ELF, PE, and Mach-O binaries (including Solana SBF/BPF `.so` programs compiled with `rustc`).
- **Forensic Capabilities**:
  - Demangles Rust **v0** (`_RNv...`) and **legacy** (`_ZN...17h...E`) symbols alongside Itanium C++ ABI (`_Z...`) and MSVC (`?...`) symbols.
  - Extracts crate dependency graphs from embedded `.comment`, `.rodata` + `.rela.dyn` `core::panicking::Location` tuples (`src/main.rs`, `/cargo/registry/src/...`), and `rustc` commit hashes.
  - Reconstructs C++ Itanium (`_ZTV` vtables, `_ZTI` typeinfo structures) and MSVC (`RTTICompleteObjectLocator`, `RTTIClassHierarchyDescriptor`, `vftable`) class hierarchies and virtual method dispatch tables.
- **Invocation**:
  ```json
  { "path": "/path/to/rust_or_cpp_binary", "max_panic_locations": 500, "max_symbols": 500 }
  ```

---

## 3. Frozen Python & PyInstaller Archives (`inspect_python_frozen_binary`)
- **Target**: Standalone PyInstaller `ELF`/`PE`/`Mach-O` executables (`MEI\x0c\x0b\x0a\x0b\x0e` CArchive trailer) and compiled Python `.pyc` files (Python `3.8`–`3.14` PEP 552 headers).
- **Forensic Capabilities**:
  - Locates the `MEI` CArchive cookie, parses the Table of Contents (`toc_entries`), embedded `PYZ-00.pyz` zlib archive header (`pyz_header`), entrypoint scripts (`entry_scripts`), and bundled native C extensions (`native_extensions`).
  - Parses marshaled `.pyc` code objects (`code_objects`: `co_name`, `co_varnames`, `co_names`, `co_consts`) and string constants without executing untrusted bytecode.
- **Invocation**:
  ```json
  { "path": "/path/to/pyinstaller_or_pyc", "max_toc_entries": 500, "max_code_objects": 200, "max_strings": 500 }
  ```

---

## 4. Streaming AI Model & Prompt Forensics (`inspect_ai_model_artifact`)
- **Target**: `.gguf` (v1–v3), `.safetensors`, `.onnx`, and `.tflite` model files.
- **Forensic Capabilities**:
  - Streams only the header/metadata prefix (`header_bytes_read` << `size_bytes`) in `< 50 ms` without loading multi-GB tensor weights into RAM.
  - Extracts architecture hyperparameters, quantization distribution, tensor shapes/dtypes/offsets, embedded Jinja `tokenizer.chat_template` / system prompts (`extracted_prompts`), and pickle-free `security_audit` checks.
- **Invocation**:
  ```json
  { "path": "/path/to/model.gguf", "max_tensors": 500, "max_metadata": 500 }
  ```

---

## 5. Game & Application Engine Archives (`inspect_engine_archive`)
- **Target**:
  1. **Unity IL2CPP**: `global-metadata.dat` (magic `0xFAB11BAF`, v24–v31).
  2. **Godot Engine**: `.pck` resource packs (magic `GDPC` / `0x43504447`, v1–v3).
  3. **Electron**: `.asar` archives (Chromium Pickle header + JSON directory tree).
- **Forensic Capabilities**:
  - Unity `global-metadata.dat`: Extracts IL2CPP header version, string literal tables (`il2cpp.string_literals`), C# namespace/type definitions (`il2cpp.types`), and method metadata (`il2cpp.methods`).
  - Godot `.pck`: Extracts engine version, pack flags, and embedded `res://` file paths, offsets, sizes, and MD5 hashes (`godot_pck.files`).
  - Electron `.asar`: Parses the Chromium Pickle uint32 header framing, extracts `main_entry_script` from `package.json`, enumerates `asar.files`, and flags native `.node` addons (`asar.native_addons`).
- **Invocation**:
  ```json
  { "path": "/path/to/app.asar", "max_files": 500 }
  ```

---

## 6. WebAssembly & WASI Artifacts (`inspect_wasm_artifact`)
- **Target**: `.wasm` modules (`\0asm` magic `0x00 0x61 0x73 0x6d`, version `0x01`).
- **Forensic Capabilities**:
  - Decodes standard WASM sections (`Type`, `Import`, `Function`, `Table`, `Memory`, `Global`, `Export`, `Element`, `Code`, `Data`) and custom debug/`name` sections.
  - Flags WASI capability imports (`wasi_snapshot_preview1`, `fd_write`, `path_open`, `sock_accept`, `proc_exit`) and linear memory boundaries.
- **Invocation**:
  ```json
  { "path": "/path/to/module.wasm" }
  ```

---

## 7. Android APK / DEX & JVM Packages (`inspect_android_package`)
- **Target**: Android `.apk`, `.aab`, Dalvik Executable `.dex` (`dex\n035\0` .. `dex\n039\0`), and packaged mobile archives.
- **Forensic Capabilities**:
  - Inspects `AndroidManifest.xml` components, permissions, exported activities/services/receivers, DEX class hierarchies, JNI `native` method bindings, and bundled native `.so` libraries.
- **Invocation**:
  ```json
  { "path": "/path/to/app.apk" }
  ```

---

## 8. .NET CIL / CLR Managed Assemblies (`inspect_managed_artifact`)
- **Target**: Managed Windows PE `.exe` / `.dll` assemblies containing a CLI header (`IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`, `BSJB` metadata root).
- **Forensic Capabilities**:
  - Parses CLR metadata tables (`Module`, `TypeRef`, `TypeDef`, `Field`, `MethodDef`, `ImplMap`), user strings, and `[DllImport]` P/Invoke native bindings.
- **Invocation**:
  ```json
  { "path": "/path/to/ManagedAssembly.dll" }
  ```

---

## 9. EVM / Solidity Smart Contract Bytecode (`inspect_evm_interface`)
- **Target**: Raw EVM bytecode `.bin` or hex-encoded `.hex` files (runtime or creation bytecode).
- **Forensic Capabilities**:
  - Disassembles EVM opcodes, extracts 4-byte Solidity function selector dispatch tables (`PUSH4 0x........ EQ PUSH2 0x.... JUMPI`), resolves ABI signatures, and decodes CBOR compiler metadata.
- **Invocation**:
  ```json
  { "path": "/path/to/contract.bin" }
  ```

---

## 10. Firmware Images, SVD, UF2 & DeviceTree (`inspect_firmware_regions` & `extract_firmware`)
- **Target**: Flattened DeviceTree blobs (`.dtb`, magic `0xD00DFEED`), UF2 blocks, CMSIS-SVD peripheral maps (`.svd`), and embedded ROM/flash dumps (`.bin`, `.hex`).
- **Forensic Capabilities**:
  - Maps firmware regions, entropy distributions, embedded filesystems, bootloaders, and memory-mapped peripheral registers (also integrated into `export_recon_kit` Mount 3).
- **Invocation**:
  ```json
  { "path": "/path/to/firmware.bin" }
  ```

---

## 11. Network Captures & Web Traffic (`inspect_packet_capture` & `inspect_web_network_capture`)
- **Target**: libpcap (`.pcap`), `.pcapng`, and `.har` HTTP archive captures.
- **Forensic Capabilities**:
  - Parses Ethernet/IPv4/IPv6/TCP/UDP flows, DNS queries, TLS SNI handshakes, and HTTP/WebSocket request/response payloads.
- **Invocation**:
  ```json
  { "path": "/path/to/capture.pcap" }
  ```

---

## 12. Logic Analyzer & Signal Captures (`decode_signal_recording`)
- **Target**: Sigrok `.sr` captures, Saleae logic exports, and VCD/CSV digital waveform recordings.
- **Forensic Capabilities**:
  - Decodes digital signal channels, timing transitions, and UART/SPI/I2C protocol frames.
- **Invocation**:
  ```json
  { "path": "/path/to/capture.sr" }
  ```

---

## 13. SQLite Databases (`inspect_sqlite_database`)
- **Target**: `.sqlite`, `.db`, `.sqlite3` files (`SQLite format 3\0` header).
- **Forensic Capabilities**:
  - Extracts `sqlite_master` table/index/trigger DDL schemas, page counts, encoding, and bounded table row previews.
- **Invocation**:
  ```json
  { "path": "/path/to/database.sqlite" }
  ```

---

## 14. Native Binary Layout, PE Resources, Crash Dumps & Generic Artifacts (`inspect_binary_layout`, `inspect_pe_resources`, `inspect_recorded_crash`, `inspect_artifact`)
- **Target**:
  - `inspect_binary_layout`: ELF/Mach-O structural layout, sections, segments, dynamic tags (`NEEDED`, `SONAME`, `RPATH`), security mitigations (`PIE`, `NX`, `RELRO`, `Canary`, `FORTIFY`), eBPF objects (`.bpf.o`), and DWARF metadata.
  - `inspect_pe_resources`: Windows PE/COFF (`.exe`, `.dll`, `.sys`, `.efi`) headers, imports, exports, version info, manifests, and embedded resource directories.
  - `inspect_recorded_crash`: ELF `ET_CORE` coredumps and Windows Minidump `.dmp` crash state.
  - `inspect_artifact`: Universal magic-byte, entropy, and container triage across unknown binaries, media containers, shaders, documents, and archives.
- **Invocation**:
  ```json
  { "path": "/path/to/binary_or_artifact" }
  ```
