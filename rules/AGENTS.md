# REA-Argonaut (`ArgonZeroG`) Active Operational Rules

When the `rea-argonaut` plugin is enabled, adhere strictly to the following reverse-engineering and verified Safe Rust modernization rules:

## 1. Whole-Subgraph Extraction Over 50-Line Paging (`decompile_subgraph`)
- Never page native disassembly or decompiled pseudocode 50 lines at a time.
- Always ingest connected call subgraphs in a single call via `decompile_subgraph` (`detail: "full"`, `include_assembly: true`) to maximize KV context-cache reuse.
- On every `decompile_subgraph` response, inspect both `inferred_struct_offsets` and `latent_hazards` (`potential_integer_overflow_to_pointer`, `unchecked_division`, `thread_hostile_mutable_global`, `unsafe_memory_sink`, `uninitialized_or_stack_hazard`) before writing any reconstruction or audit report.

## 2. `#![forbid(unsafe_code)]` Safe Rust Reconstruction Standards
- Every Rust module synthesized from a legacy C/C++ binary or source subsystem must declare `#![forbid(unsafe_code)]` at the crate/module root.
- Keep each Rust source file modular (`<= 400 LOC` per module), enforce zero warnings under `cargo clippy --all-targets -- -D warnings`, and document every public type, trait, and function with `///` rustdoc comments explaining the recovered domain invariant and eliminated legacy hazards.
- Preserve strict IEEE-754 floating-point evaluation order and exact integer wrapping/widening semantics in the baseline port so `verify_rust_parity` can prove 0-ULP / bit-exact equivalence before layering Structure-of-Arrays (SoA), SIMD, or parallel rayon/thread-pool optimizations.

## 3. Mandatory Closed-Loop Parity & Speedup Verification (`verify_rust_parity`)
- Never claim a C/C++-to-Rust port is equivalent by visual inspection alone.
- Always execute `verify_rust_parity` with `forbid_unsafe: true` and `10,000+` deterministic SplitMix64 + boundary seeds.
- If `status === "diverged"`, inspect `counterexample.shrunk_inputs`, `counterexample.c_return_hex`, `counterexample.rust_return_hex`, and `counterexample.bit_diff_summary`, patch the Rust implementation, and re-run `verify_rust_parity` until `status === "verified_bit_exact"` and `benchmark_telemetry.speedup_vs_c_oracle` is recorded.

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


