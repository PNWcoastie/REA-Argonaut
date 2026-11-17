# REA-Argonaut (`ArgonZeroG`) Active Operational Rules

When the `rea-argonaut` plugin is enabled, adhere strictly to the following reverse-engineering and verified Safe Rust modernization rules:

## 1. Whole-Subgraph Extraction, Stage 1.5 Reachability & Hazard Auditing (`decompile_subgraph`)
- Never page native disassembly or decompiled pseudocode 50 lines at a time.
- Always ingest connected call subgraphs in a single call via `decompile_subgraph` (`detail: "full"`, `include_assembly: true`) to maximize KV context-cache reuse.
- On every `decompile_subgraph` response, inspect `inferred_struct_offsets`, **Stage 1.5 Reachability & Linker-Hygiene** (`stage15_reachability`: `class_i_live_wired`, `class_ii_dead_fossil`, `class_ii_cloned_inline_suspect`; `linker_hygiene`: `-fvisibility=hidden`/PLT bloat, `SHT_RELR` `.relr.dyn`, `RegisterNatives` recovery, 5 filtered C++ linker traps, valid `dlopen` `.so` targets), and **all 9 `latent_hazards` categories**:
  - `potential_integer_overflow_to_pointer`, `unchecked_division`, `thread_hostile_mutable_global`, `unsafe_memory_sink`, `uninitialized_or_stack_hazard`, `register_writeback_offset_clobber`, `null_deref_before_check`, `size_truncation_or_unsigned_underflow`, `unpopulated_out_param_or_duplicate_call`.
- Audit cross-generation **Class III Zombie Activation** with `compare_artifacts` / `find_changed_behavior`, and audit compiled Rust binaries via `inspect_rust_cpp_binary` (`rust.zero_drift_audit`: `total_panic_locations`, `std_or_core_panic_locations`, `crate_panic_locations`, `detected_panic_handlers`, `unsafe_c_memory_sinks_imported`).

## 2. `#![forbid(unsafe_code)]` Rust `1.100` (`edition = "2024"`) & `rust-zero-drift` Standards
- Every Rust module synthesized from a legacy C/C++ binary or source subsystem must declare `#![forbid(unsafe_code)]` at the crate/module root and target `edition = "2024"` (`rust-version = "1.100"`) with `[lints.rust] unsafe_code = "forbid"`, `[lints.cargo] unused_dependencies = "warn"`, and `[lints.clippy]` denying `unwrap_used`, `expect_used`, `todo`, `unimplemented`, and `dbg_macro`.
- Keep each Rust source file modular (`<= 400 LOC` per module), enforce zero warnings under `cargo clippy --all-targets -- -D warnings`, and document every public type, trait, and function with `///` rustdoc comments explaining the recovered domain invariant and eliminated legacy hazards.
- Apply **`rust-zero-drift`** patterns to eliminate all 9 hazard categories: `#[repr(transparent)]` Newtypes, `PhantomData<State>` Typestate lifecycles, const-generic array capacities, `core::mem::DropGuard` cleanup, `std::sync::LazyLock`/`OnceLock` (or `&mut Context`), `Option<&T>`/`Option<&[u8]>` null modeling, `usize` + `TryFrom` + `.checked_sub()`, and structured return tuples/`Result`.
- Preserve strict IEEE-754 floating-point evaluation order and exact integer wrapping/widening semantics in the primary `<fn>` oracle port (`rust_source_code`) so `verify_rust_parity` proves 0-ULP bit-exact equivalence, and emit `<fn>_remediated` (`remediated_rust_source_code`) when legacy C/binary defects require hardened safe semantics.

## 3. Mandatory Closed-Loop Dual-Oracle Verification & `rust-zero-drift` Bridge (`verify_rust_parity`)
- Never claim a C/C++-to-Rust port is equivalent by visual inspection alone.
- Always execute `verify_rust_parity` with `forbid_unsafe: true` and `10,000+` deterministic SplitMix64 + boundary seeds (using `"f32_finite"` / `"f64_finite"` when testing finite-domain DSP/sensor filters, and relying on built-in canonical IEEE-754 `NaN` & `±0.0` equivalence). Pass `remediated_rust_source_code` alongside `rust_source_code` when scaffolding Dual-Oracle `edition = "2024"` crates via `scaffold_output_dir`, then verify `cargo clippy --all-targets -- -D warnings` and `cargo test`.
- Bridge bidirectionally with `rust-zero-drift`: run `verify_rust_parity` (`c_source_code`) to differentially fuzz optimized Rust SIMD/crypto/DSP kernels, and run `inspect_rust_cpp_binary` (`zero_drift_audit`) on compiled release binaries to confirm zero crate panic bloat or unsafe `-sys` FFI sinks.
- If `status === "diverged"`, inspect `counterexample.shrunk_inputs`, `counterexample.c_output_hex`, `counterexample.rust_output_hex`, and `counterexample.bit_diff_summary`, patch the Rust implementation, and re-run `verify_rust_parity` until `status === "verified_bit_exact"` and `benchmark_telemetry.speedup_vs_c_oracle` is recorded.

## 4. Hardware-Adaptive Concurrency (Zero Hardcoded Core Limits)
- Never hardcode CPU core counts, worker thread counts, or single-OS path assumptions.
- Always scale analysis pools, build jobs, and verification workers dynamically at runtime via `os.availableParallelism()`, `os.totalmem()`, and `std::thread::available_parallelism()` across Linux (`linux`), macOS (`darwin`), and Windows (`win32`).

## 5. 4-Phase Recon-to-Argon Handoff Workflow (`export_recon_kit`)
- **Phase 1 — Materialize the 4-Mount Recon Kit (`export_recon_kit`):** Produces `RECON_BLUEPRINT.md` and the 4-Mount `recon-kit/` directory (`0` unsolicited `.html` files by default; `mock_ui_concepts: false`).
- **Phase 2 — Native `ask_question` Harness Selection (& Opt-In UI Concept Mock):** Always use Antigravity's native `ask_question` tool (never generate HTML with clickable `<button>` or `onclick=` controls) so the user selects which subsystem and which of the **4 Harnesses** (`verified-safe-rust-port`, `clean-room-app-ui-rebuild`, `hardware-hal-protocol-replay`, `security-hazard-audit`) to execute. If Mount 2 UI assets were discovered, include an option in `ask_question` asking if the user wants to generate a visual `generative_ui` UI concept mock (`mock_ui_concepts: true`).
- **Phase 3 — Antigravity + Gemini 4 Argon Reconstruction:** Build/recreate from `RECON_BLUEPRINT.md` and `recon-kit/`.
- **Phase 4 — Mathematical Referee Verification:** Run `verify_rust_parity` (scaffolds a clean `#![forbid(unsafe_code)]` Cargo crate by default via `scaffold_output_dir`, with `html_report_path` strictly opt-in) or CLI `argonaut verify-reconstruction`.

## 6. Living Workspace Docs vs. Brain Artifacts & Native Decision Controls
- **Native Decision Controls (`ask_question`):** All architectural, subsystem, and harness routing choices must be presented via Antigravity's native `ask_question` tool. Never emit static HTML files containing fake interactive `<button>` or `onclick=` workflow controls.
- **Living Workspace Docs (`output_dir`):** `export_recon_kit` writes `RECON_BLUEPRINT.md` and `recon-kit/*.md` directly into the workspace `output_dir` as standard Markdown files (without `ArtifactMetadata`) so they persist as living repository documentation.
- **Brain Artifacts (`<appDataDir>/brain/<conversation-id>`):** Reserve brain artifacts with `RequestFeedback: true` strictly for actionable step-by-step implementation plans requiring user sign-off. When opt-in `generative_ui` HTML mocks (`mock_ui_concepts: true` or `html_report_path`) are written as brain artifacts, always set `UserFacing: true` and `RequestFeedback: false`.


