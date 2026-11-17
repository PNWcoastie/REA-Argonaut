# Specialized Forensic Verticals Guide (Canonical MCP Tools)

`ArgonZeroG` ships deterministic, execution-free binary and container inspectors across all specialized reverse-engineering verticals. Always invoke `export_recon_kit` or the domain-specific vertical MCP tool **before** falling back to generic instruction disassembly.

---

## 0. Universal 4-Mount Recon Kit (`export_recon_kit`)
- **Target**: Any native binary (`ELF`, `PE`, `Mach-O`), packaged UI/game archive (`IL2CPP`, `Godot .pck`, `Electron .asar`, `PyInstaller`, `APK/DEX`, `.NET`), hardware/firmware/protocol artifact (`SVD`, `DBC`, `UF2`, `DTB`, `PCAP`, `Sigrok`), or AI model/data artifact (`GGUF`, `SafeTensors`, `ONNX`, `TFLite`, `SQLite`).
- **Forensic Capabilities**:
  - Automatically detects all applicable mounts (`Mount 1..4`) and writes `RECON_BLUEPRINT.md` alongside structured Mount 1–4 artifacts (`.rs`, `.h`, `.c`, `.sql`, `.txt`, `.json`, and `.md`) directly to `output_dir`.
  - Emits `0` unsolicited `.html` files by default (`mock_ui_concepts: false`).
- **Invocation**:
  ```json
  { "path": "/path/to/target_artifact", "mount_override": "auto", "mock_ui_concepts": false }
  ```

---

## 1. Go Binaries (`inspect_go_binary`)
- **Target**: ELF, PE, and thin Mach-O binaries compiled by `gc` (`go build`).
- **Forensic Capabilities**:
  - Parses embedded `.go.buildinfo` / `__go_buildinfo` (`runtime/debug.BuildInfo`) metadata across inline and historical pointer encodings in pure TypeScript without requiring Go or opening a disassembler.
  - Extracts Go compiler version (`build_info.go_version`), main module identity (`build_info.module.main`), dependency & replacement versions (`build_info.module.dependencies`), and compiler build settings (`build_info.module.settings`).
  - Use `open_binary` + `decompile_subgraph` for native Go procedure/CFG recovery.
- **Invocation**:
  ```json
  { "path": "/path/to/go_binary" }
  ```

---

## 2. Stripped Rust & Modern C++ Binaries (`inspect_rust_cpp_binary`)
- **Target**: Rust (`rustc`) and C++ (`gcc`/`clang`/`MSVC`) ELF, PE, and Mach-O binaries (including Solana SBF/BPF `.so` programs compiled with `rustc`).
- **Forensic Capabilities**:
  - Demangles Rust **v0** (`_RNv...`) and **legacy** (`_ZN...17h...E`) symbols alongside Itanium C++ ABI (`_Z...`) and MSVC (`?...`) symbols.
  - Extracts crate dependency graphs (`rust.crates`) from `.rodata` + `.rela.dyn` `core::panicking::Location` tuples (`src/main.rs`, `.cargo/registry/src/...`), `rustc` version (`rust.rustc_version`), and `rustc` commit hashes (`rust.compiler_commit`).
  - Computes **`rust.zero_drift_audit`** telemetry (`total_panic_locations`, `std_or_core_panic_locations`, `crate_panic_locations`, `detected_panic_handlers`, `unsafe_c_memory_sinks_imported`) to audit panic bloat and unsafe `-sys` FFI sinks across release Rust binaries.
  - Reconstructs C++ Itanium (`_ZTV` vtables, `_ZTI` typeinfo structures) and MSVC (`RTTICompleteObjectLocator`, `RTTIClassHierarchyDescriptor`, `vftable`) class hierarchies and virtual method dispatch tables (`cpp.classes`).
- **Invocation**:
  ```json
  { "path": "/path/to/rust_or_cpp_binary", "max_panic_locations": 500, "max_symbols": 500 }
  ```

---

## 3. Frozen Python & PyInstaller Archives (`inspect_python_frozen_binary`)
- **Target**: Standalone PyInstaller `ELF`/`PE`/`Mach-O` executables (`MEI\x0c\x0b\x0a\x0b\x0e` CArchive trailer) and compiled Python `.pyc` files (Python `3.8`–`3.14` PEP 552 headers).
- **Forensic Capabilities**:
  - Locates the `MEI` CArchive cookie, parses the Table of Contents (`toc_entries`), embedded `PYZ-00.pyz` zlib archive header (`pyz_header`), entrypoint scripts (`entry_scripts`), and bundled native C extensions (`native_extensions`).
  - Parses marshaled `.pyc` code objects (`code_objects`: `co_name`, `co_filename`, `co_firstlineno`, `argcount`, `names`, `varnames`, `string_constants`, `bytecode_length`) without executing untrusted bytecode.
- **Invocation**:
  ```json
  { "path": "/path/to/pyinstaller_or_pyc", "max_toc_entries": 500, "max_code_objects": 200, "max_strings": 500 }
  ```

---

## 4. Streaming AI Model & Prompt Forensics (`inspect_ai_model_artifact`)
- **Target**: `.gguf` (v1–v3), `.safetensors`, `.onnx`, and `.tflite` model files.
- **Forensic Capabilities**:
  - Streams only the header/metadata prefix (`header_bytes_read` << `size_bytes`) in `< 50 ms` without loading multi-GB tensor weights into RAM or executing pickle payloads.
  - Extracts `architecture`, `model_name`, `quantization_or_dtype`, scalar hyperparameters (`metadata`), tensor descriptors (`tensors`: `name`, `dtype`, `shape`, `byte_offset`, `byte_length`), and embedded Jinja `tokenizer.chat_template` / system prompts (`extracted_prompts`).
- **Invocation**:
  ```json
  { "path": "/path/to/model.gguf", "max_tensors": 500, "max_metadata_entries": 500, "extract_prompts": true }
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
  - Validates and inspects local `.wasm` modules using caller-supplied WABT `1.0.42` (`wasm-validate`, `wasm-objdump`, `wasm2wat`), returning section bounds (`sections`), `imports`, `exports`, decoded WAT (`wat.text`), and optional JavaScript glue literal associations (`glue_paths`, `candidate_paths`).
  - Pass `detail: "summary"` on large modules to retain the complete Evidence and inspect WAT/section pages via `inspect_analysis_view`.
- **Invocation**:
  ```json
  { "path": "/path/to/module.wasm", "glue_paths": [], "candidate_paths": [] }
  ```

---

## 7. Android APK / DEX & Mobile Packages (`inspect_android_package`)
- **Target**: Local Android `.apk` packages (paired with `search_android_classes`, `inspect_android_class`, `inspect_android_method`, `trace_android_references`, and `decode_android_resources`).
- **Forensic Capabilities**:
  - Inspects `AndroidManifest.xml` components, SDK targets, permissions, and class/resource counts using a caller-supplied JADX engine without executing the APK.
  - Supports `detail: "summary"` to retain the decoded manifest and page through `inspect_analysis_view`.
- **Invocation**:
  ```json
  { "path": "/path/to/app.apk" }
  ```

---

## 8. .NET CIL / CLR Managed Assemblies (`inspect_managed_artifact`)
- **Target**: Managed Windows PE/CLI `.exe` / `.dll` assemblies containing a CLI header (`IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`, `BSJB` metadata root), paired with `inspect_managed_members` and `inspect_managed_native_boundaries`.
- **Forensic Capabilities**:
  - Parses CLR metadata inventories (`Module`, `TypeRef`, `TypeDef`, `Field`, `MethodDef`, `ImplMap`), framework markers, and `[DllImport]` P/Invoke native declarations without loading or executing target code.
  - Supports `detail: "summary"` to retain the full inventory and page through `inspect_analysis_view`.
- **Invocation**:
  ```json
  { "path": "/path/to/ManagedAssembly.dll" }
  ```

---

## 9. EVM / Solidity Smart Contract Bytecode (`inspect_evm_interface`)
- **Target**: Flat EVM bytecode carriers in either binary (`"encoding": "raw"`) or UTF-8 hexadecimal (`"encoding": "hex"`) representation.
- **Forensic Capabilities**:
  - Recovers 4-byte Solidity function selector dispatch candidates (`selector`, `bytecode_offset`, `dispatch`, `inferred_arguments`, `inferred_state_mutability`) via bundled EVMole `0.9.3`/WASM without chain/RPC access or execution.
  - `encoding` (`"raw" | "hex"`) is required alongside `path` (and optional `detail: "summary" | "complete"`).
- **Invocation**:
  ```json
  { "path": "/path/to/contract.bin", "encoding": "raw" }
  ```

---

## 10. Firmware Images & Extraction (`inspect_firmware_regions` & `extract_firmware`)
- **Target**: Embedded ROM/flash dumps and firmware blobs (`.bin`, `.img`, `.rom`); CMSIS-SVD (`.svd`), UF2, CAN `.dbc`, and DeviceTree `.dtb` structures are also parsed in `export_recon_kit` Mount 3.
- **Forensic Capabilities**:
  - `inspect_firmware_regions` scans signature candidates (offsets, lengths, descriptions, confidence) with Binwalk `3.1.x` without executing extracted payloads.
  - `extract_firmware` extracts a whole file or byte `range` (`{ offset, length }`) into an absent `output_directory` via Unblob `26.6.x`.
- **Invocations**:
  ```json
  { "path": "/path/to/firmware.bin" }
  ```
  ```json
  { "path": "/path/to/firmware.bin", "output_directory": "/path/to/firmware-output" }
  ```

---

## 11. Network Captures & Web Traffic (`inspect_packet_capture` & `inspect_web_network_capture`)
- **Target**:
  - `inspect_packet_capture`: `libpcap` (`.pcap`) and `.pcapng` packet captures via TShark `4.x` (`path` + non-empty `fields` array required).
  - `inspect_web_network_capture`: retained `.har`, native `mitmproxy`, Fiddler `.saz`, and `aioquic` `.qlog` captures (`capture_path` + `format` required).
- **Forensic Capabilities**:
  - Extracts selected TShark protocol fields with display filters (`display_filter`), `decode_as` rules, and `match_offset`/`match_limit` paging, or decodes historical HAR/mitmproxy/SAZ/qlog records offline without contacting recorded URLs.
- **Invocations**:
  ```json
  {
    "path": "/path/to/capture.pcapng",
    "fields": ["ip.addr", "udp.port", "data.data"],
    "display_filter": "udp",
    "two_pass": true
  }
  ```
  ```json
  {
    "capture_path": "/path/to/session.har",
    "format": "har"
  }
  ```

---

## 12. Logic Analyzer & Signal Captures (`decode_signal_recording`)
- **Target**: Sigrok `.sr` captures, VCD, and digital waveform recordings decoded via `sigrok-cli` `0.7.2` (`path` + `decoders` required).
- **Forensic Capabilities**:
  - Decodes digital signal channels and protocol frames (UART/SPI/I2C, etc.) with optional `input_format`, `annotations`, and `line_offset`/`line_limit` paging.
- **Invocation**:
  ```json
  {
    "path": "/path/to/uart.vcd",
    "decoders": "uart:rx=RX:baudrate=9600",
    "input_format": "vcd",
    "annotations": "uart=rx-data"
  }
  ```

---

## 13. SQLite Databases (`inspect_sqlite_database`)
- **Target**: `.sqlite`, `.db`, `.sqlite3` snapshot files (`SQLite format 3\0` header) and existing sibling WAL files.
- **Forensic Capabilities**:
  - Extracts database/WAL SHA-256 digests, compact schema inventories (`schema_scope`), and bounded ordinary-table row previews (`table`, `columns`, `row_limit`).
- **Invocation**:
  ```json
  { "path": "/path/to/database.sqlite" }
  ```

---

## 14. Native Binary Layout, PE Resources, Crash Dumps & Active Artifacts (`inspect_binary_layout`, `inspect_pe_resources`, `inspect_recorded_crash`, `inspect_artifact`)
- **Target**:
  - `inspect_binary_layout`: ELF section/segment ranges, linked addresses, symbol/`REL`/`RELA`/`RELR` tables, interpreter/dependency names, and static mitigation inferences (`path` + optional `detail`).
  - `inspect_pe_resources`: Windows PE32/PE32+ (`.exe`, `.dll`, `.sys`, `.efi`) bounded type/name/language resource trees and `RT_GROUP_ICON` candidates (`path`, optional `max_file_bytes`, `max_entries`).
  - `inspect_recorded_crash`: Linux ELF64 `ET_CORE` coredump segments, notes, `PRSTATUS` registers, and `SIGINFO` fields (`path`, optional `include_debugger_context`).
  - `inspect_artifact`: Content-addressed artifact graph inventory over the **currently open `open_binary` session** (`{ integrity_policy, detail }`—no `path` field).
- **Invocations**:
  ```json
  { "path": "/path/to/binary_or_coredump" }
  ```
  ```json
  { "integrity_policy": "fail" }
  ```
