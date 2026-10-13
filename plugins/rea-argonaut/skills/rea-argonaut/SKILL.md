---
name: rea-argonaut
description: Zero-G Reverse Engineering Anything & Verified Rust Reconstruction for Gemini 4 Argon and Google Antigravity 2.0. Use whenever reverse-engineering native binaries (ELF/Mach-O/PE), stripped Rust/C++, frozen Python/PyInstaller, AI models (GGUF/SafeTensors/ONNX/TFLite), game engines (Unity IL2CPP/Godot .pck/Electron .asar), .NET, Go, Flutter, WebAssembly, EVM contracts, Electron/JS, Android APKs, firmware, network captures, or porting C/C++ subsystems to verified safe Rust.
---

# REA-Argonaut (`ArgonZeroG` Engine)

`REA-Argonaut` is the Zero-G reverse-engineering and verified reconstruction engine built for **Gemini 4 Argon** and **Google Antigravity 2.0**. It exposes **193 MCP tools** across **39 forensic domains** with unthrottled whole-subgraph extraction (`detail: "full"` by default), 2-tier cross-platform native resilience (Linux, macOS, Windows), a 4-subagent Hub-and-Spoke Super-Swarm, and closed-loop property-based C-to-Rust parity verification.

## The 5 Core `ArgonZeroG` Operational Laws

### Law 1 — Whole-Subsystem Subgraph Caching Over Micro-Paging (`decompile_subgraph`)
- **Never page 50 lines at a time.** Legacy 4K-context truncation (`detail: "summary"`, `max_lines: 50`) destroys cross-procedural type and invariant recovery and causes 18+ sequential MCP round-trips.
- Always open the target and ingest the connected call subgraph in one turn so the entire subsystem resides in the Gemini 4 Argon prompt context cache:
  1. `open_binary({ path: "/abs/path/to/binary", provider_id: "auto" })` *(note: `provider: "auto"` is also accepted as an alias for `provider_id`)*
  2. `binary_overview({})` and `list_procedures({})` *(automatically seeds recovered C++ Itanium/MSVC RTTI virtual methods as `ClassName__vslot_N_<addr>` across stripped binaries)*
  3. `decompile_subgraph({ procedure: "<symbol_or_hex>", max_depth: 3, max_nodes: 50, traversal: "bfs", include_assembly: true })` *(note: `entry` is also accepted as an alias for `procedure`, and seeded `ClassName__vslot_N_<addr>` symbols can be targeted directly)*
- `decompile_subgraph` returns full decompiled pseudocode, disassembled instruction lines, callers, callees, cycle edges (`cycle_edges`), aggregated strings (`aggregated_strings`), recovered struct field displacements (`inferred_struct_offsets`), and pre-extracted binary vulnerability/porting hazards (`latent_hazards`, `total_latent_hazards`) for every procedure in the subgraph in a single round-trip.

### Law 2 — 2-Tier Native Resilience (`provider_id: "auto"`)
- `REA-Argonaut` operates across **Linux (`ELF`)**, **macOS (`Mach-O` thin & Universal)**, and **Windows (`PE/COFF` PE32/PE32+)** without brittle single-tool dependencies:
  - **Tier 1 (`ghidra` / `hopper` / `ida`)**: Full symbolic decompilation, P-Code value-flow graphs (`trace_native_values`), and HighFunction `PTRSUB`/`PTRADD` struct offset recovery when a Tier-1 provider is configured via `GHIDRA_INSTALL_DIR` (or alias `REA_GHIDRA_HOME`) and `JAVA_HOME` (supports Ghidra `11.x` and `12.x`, verified on `12.1.4`).
  - **Tier 2 (`zero-install` / `ZeroInstallNativeProvider`)**: Automatic fallback when Ghidra/Hopper/IDA are absent. Combines pure-TypeScript ELF/Mach-O/PE container parsers with host OS binutils (`objdump`, `llvm-objdump`, `readelf`, `nm`, `otool -tV`, `dumpbin`) and a built-in x86/x86_64/ARM64 bytecode decoder. Automatically recovers stripped-binary procedure boundaries (`sub_<hex>`) from entrypoints, `CALL`/`BL` targets, `endbr64`/`push rbp` prologues, and cross-vertical C++ RTTI/VTable virtual method slots (`ClassName__vslot_N_<addr>`).
  - **Format-Specific Layout, Resource & Crash Routing**:
    - **ELF Binaries & SONAME Symlinks**: Use `inspect_binary_layout({ path })` (resolves symlinks such as `/lib/x86_64-linux-gnu/liblz4.so.1` via `os.path.realpath`) and `inspect_recorded_crash({ path })` (`ET_CORE`).
    - **Windows PE Binaries (`.exe`, `.dll`, `.sys`)**: Use `inspect_rust_cpp_binary({ path })`, `inspect_pe_resources({ path })`, and `open_binary` + `binary_overview` (do not pass PE/Mach-O binaries to the ELF-specific `inspect_binary_layout` tool).
    - **macOS Mach-O Binaries**: Use `inspect_macho({ path })`, `inspect_signature({ path })`, `inspect_rust_cpp_binary({ path })`, and `open_binary` + `binary_overview`.

### Law 3 — Specialized Forensic Verticals First
- Before brute-force disassembling a stripped binary, container, or runtime bundle, run the dedicated `ArgonZeroG` forensic vertical to recover high-level structure:
  - **Stripped Rust & C++ (`inspect_rust_cpp_binary`)**: Extracts Rust compiler version, cargo registry crate versions (`rust.crates`), `.rela.dyn` `core::panicking::Location` source file/line trees (`rust.panic_locations`), demangled v0 (`_RNv`) / legacy (`_ZN`) symbols, and C++ Itanium (`_ZTV`, `_ZTI`, `_ZTS`) & MSVC (`RTTICompleteObjectLocator`, `RTTIClassHierarchyDescriptor`, `vftable`) class hierarchies (`cpp.classes`).
  - **Frozen Python (`inspect_python_frozen_binary`)**: Unpacks PyInstaller `MEI\x0c\x0b\x0a\x0b\x0e` CArchive cookies, TOC entries (`toc_entries`, capped via `max_toc_entries` or alias `max_entries`), `PYZ-00.pyz` headers (`pyz_header`), entrypoint scripts (`entry_scripts`), and Python `3.8`–`3.14` `.pyc` marshaled code objects (`code_objects`).
  - **AI Model & Prompt Forensics (`inspect_ai_model_artifact`)**: Streams `.gguf` (v1–v3), `.safetensors`, `.onnx`, and `.tflite` headers in `< 50 ms` without loading multi-GB weights into RAM (`header_bytes_read` << `size_bytes`), extracting hyperparameters, tensor layouts, embedded Jinja `tokenizer.chat_template` / system prompts (`extracted_prompts`), and pickle-free `security_audit` checks.
  - **Game Engine & Application Archives (`inspect_engine_archive`)**: Parses **all 3** archive formats in pure TypeScript (with `max_files` or alias `max_entries`):
    1. **Unity `IL2CPP` `global-metadata.dat` (`0xFAB11BAF` v24–v31)**: Recovers C# namespaces, types, methods (`il2cpp.types`, `il2cpp.methods`), and string literals (`il2cpp.string_literals`).
    2. **Godot Engine `.pck` (`GDPC` `0x43504447` v1–v3)**: Enumerates bundled `res://` scenes, `.gd`/`.gdc` scripts, offsets, and MD5 hashes (`godot_pck.files`).
    3. **Electron `.asar` Chromium Pickle Archives**: Streams the Pickle JSON header tree (`asar.files`), extracts `main_entry_script` from embedded `package.json`, and flags native `.node` addons (`asar.native_addons`).
  - **All 35 Classic REA Verticals**: `.NET` CIL, Go `gopclntab`, Dart/Flutter AOT, WebAssembly, EVM bytecode, Hermes/QuickJS/V8 bytecode, Android APK/DEX, Java/Kotlin `.class`/`.jar`, iOS `.ipa`, macOS `.app`, Windows MSI/Registry/Minidump, Firmware/UF2/DeviceTree, PCAP, Sigrok logic captures, SQLite, PDF, Office OLE/OOXML, Font SFNT, Media containers, and Shader SPIR-V/DXBC/DXIL.

### Law 4 — Hub-and-Spoke Super-Swarm Orchestration Playbook
When analyzing multi-subsystem binaries, multi-artifact bundles, or porting C/C++ subsystems to verified Safe Rust, orchestrate the **4 Bundled Antigravity 2.0 Swarm Subagents** (`plugins/rea-argonaut/agents/*.md`) in a **Hub-and-Spoke** topology:

1. **The 4 Domain-Locked Specialist Subagents**:
   - **`subgraph-architect`**: Stage 1 Native Subgraph, Struct Layout & Latent Hazard Mapper (`open_binary`, `binary_overview`, `list_procedures`, `inspect_rust_cpp_binary`, `decompile_subgraph`).
   - **`forensic-vertical-specialist`**: Multi-Vertical Binary, Game Engine Archive, Frozen Python & AI Model Forensic Specialist (`inspect_rust_cpp_binary`, `inspect_python_frozen_binary`, `inspect_ai_model_artifact`, `inspect_engine_archive`, `inspect_binary_layout`, `inspect_pe_resources`).
   - **`safe-rust-reconstructor`**: Stage 2 `#![forbid(unsafe_code)]` Safe Rust Reconstruction Engineer (synthesizes idiomatic, zero-unsafe Rust that eliminates every Stage 1 `latent_hazard` while preserving bit-exact C ABI/arithmetic semantics).
   - **`adversarial-parity-auditor`**: Stage 3 & 4 Closed-Loop Differential Fuzzer & Executive Scorecard Auditor (`verify_rust_parity` with `10,000+` SplitMix64 + boundary cases, coordinate-wise binary-search counterexample shrinking, C-vs-Rust micro-benchmarking, and `EXECUTIVE_SCORECARD.html` generation).
2. **Parallel Discovery vs. Serialized Build/Fuzz Coordination**:
   - **Phase A — Parallel Read-Only Discovery**: Dispatch `subgraph-architect` and `forensic-vertical-specialist` in parallel across disjoint subsystems or binary artifacts. Because `decompile_subgraph` and vertical inspectors are read-only, multiple subagents can map separate call subgraphs simultaneously without lock contention.
   - **Phase B — Parallel File-Fenced Reconstruction**: Assign each subsystem module to a `safe-rust-reconstructor` subagent with a strict directory/file fence. Subagents perform file reads and file edits only inside their assigned module fence.
   - **Phase C — Serialized `verify_rust_parity` & Self-Healing Loop**: Dispatch `adversarial-parity-auditor` to run `verify_rust_parity` one subsystem at a time so CPU-bound `rustc -C opt-level=3` compilation and 100,000-iteration micro-benchmarks never contend for CPU cores. If `status === "diverged"`, route `counterexample.shrunk_inputs` and `bit_diff_summary` back to `safe-rust-reconstructor` until `status === "verified_bit_exact"`.
3. **Hardware-Adaptive Resource Scaling (Zero Hardware Assumptions)**:
   - Never hardcode core counts, thread pool sizes, or machine-specific paths. All parallel workers scale dynamically at runtime via `os.availableParallelism()` and `os.totalmem()` in Node.js (`AdaptiveResourceProfile.ts`) and `std::thread::available_parallelism()` in Rust.

### Law 5 — Closed-Loop Mathematical Verification (`verify_rust_parity`)
- **Never claim a C/C++-to-Rust reconstruction is equivalent by visual inspection alone.**
- After synthesizing safe Rust from a decompiled native procedure or subgraph, invoke `verify_rust_parity`:
  - **Input Contract**: `symbol_name`, `rust_fn_name` (optional, defaults to `symbol_name`), `rust_source_code`, `target_binary_path` (or `c_source_code`), `arg_types` (`1..8` parameters of `"i8" | "u8" | "i16" | "u16" | "i32" | "u32" | "i64" | "u64" | "f32" | "f64" | "bool" | "bytes"`, where `"bytes"` bridges `(*const u8, usize)` in C ABI $\leftrightarrow$ `&[u8]` in Safe Rust), `return_type`, `iterations` (default `10000`), `seed` (default `1337420`), `float_ulp_tolerance` (default `0`), `forbid_unsafe` (default `true`), optional `scaffold_output_dir` (automatically scaffolds a pure `#![forbid(unsafe_code)]` `Cargo.toml` + `src/lib.rs` + `tests/parity_regression.rs` crate without HTML clutter), and optional `html_report_path` (`--html-report <path>`, writes an Antigravity `generative_ui`-compliant HTML parity report when `status === "verified_bit_exact"`).
  - **Sandboxed Execution & PIE Patching**: Automatically strips ELF `DF_1_PIE` (`0x08000000` in `DT_FLAGS_1`), patches Mach-O `MH_EXECUTE -> MH_DYLIB`, or sets PE `IMAGE_FILE_DLL` on a temporary workspace copy so `dlopen()` / `LoadLibrary` can load both shared libraries and PIE executables inside an OS sandbox (`linux-bwrap+prlimit`, `linux-prlimit`, `darwin-sandbox-exec`, `win32-job-object`).
  - **Output Telemetry**:
    - `status`: `"verified_bit_exact" | "diverged" | "sandbox_fault" | "compile_error"`
    - `memory_safety`: `{ forbid_unsafe_enforced: true, candidate_unsafe_blocks: 0 }`
    - `benchmark_telemetry`: `{ benchmark_iterations: 100000, c_oracle_total_ns, safe_rust_total_ns, c_oracle_ns_per_call, safe_rust_ns_per_call, speedup_vs_c_oracle }`
    - `counterexample`: `{ failing_iteration, original_inputs, shrunk_inputs, shrink_steps, c_output, rust_output, c_output_hex, rust_output_hex, bit_diff_summary, ulp_distance }`
    - `scaffolded_crate`: `{ output_dir, cargo_toml_path, lib_rs_path, regression_test_path, dashboard_html_path }` (when `scaffold_output_dir` is supplied; `dashboard_html_path` is populated only when `html_report_path` is provided)
  - If `status === "diverged"`, inspect `counterexample.shrunk_inputs`, `counterexample.c_output_hex`, `counterexample.rust_output_hex`, and `counterexample.bit_diff_summary`, patch the Rust code, and re-run `verify_rust_parity` until `status === "verified_bit_exact"`.

---

## The 4-Phase Recon-to-Argon Handoff Workflow (`export_recon_kit`)

When reverse-engineering complex native binaries, packaged UI archives, firmware images, or AI model bundles for architectural exploration, clean-room reconstruction, or security auditing, execute the **4-Phase Recon-to-Argon Handoff Workflow**:

- **Phase 1 — Universal 4-Mount Recon Kit Materialization (`export_recon_kit`):**
  Call `export_recon_kit({ path: "/abs/path/to/target" })` to automatically detect all applicable domain mounts (`Mount 1: native-binary`, `Mount 2: packaged-ui-archive`, `Mount 3: hardware-firmware-protocol`, `Mount 4: ai-model-data`) and materialize `RECON_BLUEPRINT.md`, the Antigravity `generative_ui`-compliant `RECON_EXPLORER.html`, and the structured `recon-kit/` workspace directory (`types/`, `vtables/`, `decompiled/`, `ui-assets/`, `hardware-hal/`, `ai-model/`).
- **Phase 2 — Interactive `RECON_EXPLORER.html` Side-Pane Review & Harness Selection:**
  Present `RECON_EXPLORER.html` as a `UserFacing: true` Antigravity artifact in the Side Pane and use `ask_question` so the human operator selects which subsystem and which of the **4 Engineering Harnesses** to execute:
  1. `verified-safe-rust-port` — Port a native C/C++ subsystem to `#![forbid(unsafe_code)]` Safe Rust.
  2. `clean-room-app-ui-rebuild` — Reconstruct a modern web/desktop UI or game scene from extracted Mount 2 assets and state machines.
  3. `hardware-hal-protocol-replay` — Synthesize a typed Rust/C HAL driver or protocol parser from Mount 3 register/frame maps.
  4. `security-hazard-audit` — Remediate and verify latent memory, arithmetic, and deserialization hazards across all mounts.
- **Phase 3 — Antigravity + Gemini 4 Argon Execution from `recon-kit/`:**
  Hand off to **Antigravity + Gemini 4 Argon** (or copy the ready-to-use `argon_handoff_prompt` from `RECON_EXPLORER.html`) to build/recreate the selected library, application, UI, or hardware driver directly from `RECON_BLUEPRINT.md` and `recon-kit/` without re-running decompilers.
- **Phase 4 — Mathematical Referee Verification (`verify_rust_parity` / `verify_reconstruction`):**
  Run `verify_rust_parity` (with a clean pure-Rust `scaffold_output_dir` and optional `--html-report <path>`) or `verify_reconstruction` as the mathematical referee to prove bit-exact behavioral equivalence.

---

## The 4-Stage Continuous Modernization Pipeline (C/C++ Binary to Verified Safe Rust)

### Stage 1 — Subgraph Audit, Domain Model & `latent_hazards` Census (`subgraph-architect`)
1. Open the binary session (`open_binary({ path, provider_id: "auto" })`) and extract the target subsystem in a single call with `decompile_subgraph`.
2. Catalog all pre-extracted **`latent_hazards`** (`total_latent_hazards`) across every procedure in the subgraph:
   - `potential_integer_overflow_to_pointer` — 32-bit index arithmetic (`imul`/`shl`) sign-extended into a 64-bit pointer offset (`movsxd`), risking out-of-bounds memory corruption.
   - `unchecked_division` — hardware `div`/`idiv`/`udiv`/`sdiv` without an adjacent zero-divisor guard.
   - `thread_hostile_mutable_global` — RIP-relative writes to `.bss`/`.data` static state that break multi-threaded reentrancy.
   - `unsafe_memory_sink` — unbounded `strcpy`, `strcat`, `sprintf`, `gets`, `scanf`, or `system` calls.
   - `uninitialized_or_stack_hazard` — large stack frame allocations (`>= 4096` bytes).
3. Combine `inferred_struct_offsets`, `aggregated_strings`, and control-flow topology to synthesize the clean mathematical or physical **Domain Model** before writing Rust code.

### Stage 2 — `#![forbid(unsafe_code)]` Safe Rust Port (`safe-rust-reconstructor`)
1. Implement the reconstructed subsystem in modular Safe Rust (`#![forbid(unsafe_code)]`, `candidate_unsafe_blocks === 0`, `<= 400 LOC` per file, `0` warnings under `cargo clippy --all-targets -- -D warnings`).
2. Replace every cataloged `latent_hazard` with compile-time or checked Rust guarantees (checked/wrapping integer math, slice bounds, thread-safe value state instead of mutable globals, `Result`/`Option` error propagation).
3. Inline hot helper functions (`#[inline(always)]`) and structure hot loops for LLVM autovectorization (`-C opt-level=3 -C codegen-units=1`).

### Stage 3 — Closed-Loop `verify_rust_parity` Crucible (`adversarial-parity-auditor`)
1. Run `verify_rust_parity` with `forbid_unsafe: true` and `iterations: 10000` (or higher).
2. If any SplitMix64 or boundary seed diverges, use the shrunk counterexample (`counterexample.shrunk_inputs` and `bit_diff_summary`) to self-heal the Rust implementation in a closed loop until `status === "verified_bit_exact"`.
3. Record both **`memory_safety`** (`forbid_unsafe_enforced: true`, `candidate_unsafe_blocks: 0`) and **`benchmark_telemetry`** (`c_oracle_ns_per_call`, `safe_rust_ns_per_call`, `speedup_vs_c_oracle`).

### Stage 4 — Interactive HTML Executive Scorecard (`EXECUTIVE_SCORECARD.html`)
1. Present the completed modernization using an interactive HTML executive scorecard (`EXECUTIVE_SCORECARD.html`) that visualizes:
   - **Headline KPIs:** Native Speedup (`speedup_vs_c_oracle`), `0 Unsafe` (`#![forbid(unsafe_code)]`), `100.0%` Bit-Exact Output Parity across `10,064` FFI test vectors, and MCP Round-Trip Collapse (`18 -> 1`, `-94.4%`).
   - **Eliminated Hazard Matrix:** Side-by-side mapping of each Stage 1 `latent_hazard` address/procedure to the Stage 2 Safe Rust remediation and Stage 3 verification proof.

---

## Reference Guides
- [Whole-Subgraph Extraction & Context Caching Guide](references/subgraph-caching.md) — `decompile_subgraph` parameters, `inferred_struct_offsets`, `latent_hazards`, and single-turn KV-cache optimization.
- [Specialized Forensic Verticals Guide](references/niche-verticals-guide.md) — Deep-dive schemas and workflows for `inspect_rust_cpp_binary`, `inspect_python_frozen_binary`, `inspect_ai_model_artifact`, and `inspect_engine_archive`.
- [Hub-and-Spoke Super-Swarm Orchestration Guide](references/swarm-orchestration.md) — Coordinating `subgraph-architect`, `safe-rust-reconstructor`, `forensic-vertical-specialist`, and `adversarial-parity-auditor`.
- [Closed-Loop Rust Parity Verification Guide](references/rust-parity-verification.md) — `verify_rust_parity` FFI harness, ELF `DF_1_PIE` / Mach-O / PE patching, counterexample shrinker, and OS sandboxing.
- [ArgonZeroG Step-by-Step Playbooks](references/argon-zerog-workflow.md) — Copy-pasteable JSON tool call sequences across all 4 flagship workflows.
- [39-Domain Vertical Routing Matrix](references/vertical-routing-matrix.md) — Complete lookup table mapping file extensions and magic bytes to primary and secondary MCP tools and CLI commands.
