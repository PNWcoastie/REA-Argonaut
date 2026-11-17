# Antigravity 2.0 Hub-and-Spoke Super-Swarm Orchestration Guide

`ArgonZeroG` ships 4 domain-specialized Antigravity 2.0 subagents in `plugins/rea-argonaut/agents/` to parallelize execution-free binary triage, whole-subgraph extraction, `#![forbid(unsafe_code)]` Rust reconstruction, and adversarial property-based parity auditing.

---

## 1. The 4 Bundled Swarm Subagents

| Agent Name | Definition File | Primary Responsibility | Canonical MCP Tools Used |
| :--- | :--- | :--- | :--- |
| **`forensic-vertical-specialist`** | `agents/forensic-vertical-specialist.md` | Rapid execution-free triage via the Universal 4-Mount Recon Kit (`export_recon_kit`) and specialized binary/archive/model verticals. | `export_recon_kit`, `inspect_rust_cpp_binary`, `inspect_python_frozen_binary`, `inspect_ai_model_artifact`, `inspect_engine_archive`, `inspect_go_binary`, `inspect_wasm_artifact`, `inspect_android_package`, `inspect_managed_artifact`, `inspect_evm_interface`, `inspect_firmware_regions`, `extract_firmware`, `inspect_packet_capture`, `inspect_web_network_capture`, `decode_signal_recording`, `inspect_sqlite_database`, `inspect_binary_layout`, `inspect_pe_resources`, `inspect_recorded_crash`, `inspect_artifact` |
| **`subgraph-architect`** | `agents/subgraph-architect.md` | Opens native binaries with 2-Tier resilience (`provider_id: "auto"`), extracts connected call subgraphs via `decompile_subgraph`, classifies Stage 1.5 reachability & linker hygiene (`SHT_RELR`, `APS2`, `RegisterNatives`, 5 C++ linker traps), audits `rust.zero_drift_audit` and Class III Zombie Activation, recovers `inferred_struct_offsets`, and catalogs all 9 `latent_hazards` categories. | `open_binary`, `binary_overview`, `list_procedures`, `inspect_rust_cpp_binary`, `decompile_subgraph`, `compare_artifacts`, `find_changed_behavior`, `analyze_function`, `procedure_pseudo_code`, `procedure_assembly`, `procedure_callers`, `procedure_callees`, `search_strings`, `search_procedures`, `close_binary` |
| **`safe-rust-reconstructor`** | `agents/safe-rust-reconstructor.md` | Translates Stage 1 & 1.5 `decompile_subgraph` dossiers and all 9 `latent_hazards` categories into `#![forbid(unsafe_code)]` `edition = "2024"` (`rust-version = "1.100"`) `rust-zero-drift` Rust inside a strict module file fence, emitting Dual-Oracle `<fn>` (`rust_source_code`) + `<fn>_remediated` (`remediated_rust_source_code`) implementations. | `decompile_subgraph`, `analyze_function`, `procedure_pseudo_code`, `procedure_assembly`, `procedure_callers`, `procedure_callees`, `search_strings`, `verify_rust_parity` |
| **`adversarial-parity-auditor`** | `agents/adversarial-parity-auditor.md` | Runs serialized `10,000+` (`10,000` SplitMix64 + up to `64` boundary vectors) `verify_rust_parity` FFI fuzzing inside OS sandboxes, shrinks counterexamples, benchmarks C vs. Safe Rust speedup, scaffolds Dual-Oracle `#![forbid(unsafe_code)]` `edition = "2024"` (`rust-version = "1.100"`) crates with `[lints.rust]`/`[lints.cargo]`/`[lints.clippy]` zero-drift lints, and verifies `cargo clippy --all-targets -- -D warnings` + `cargo test`. | `verify_rust_parity`, `inspect_rust_cpp_binary`, `decompile_subgraph`, `analyze_function`, `procedure_assembly` |

---

## 2. Hub-and-Spoke Swarm Execution Topology

```mermaid
flowchart TD
    Lead["Lead Orchestrator Agent<br/>(export_recon_kit + Native ask_question)"]
    FVS["1. forensic-vertical-specialist<br/>(4-Mount Recon Kit & Vertical Triage)"]
    SA["2. subgraph-architect<br/>(2-Tier decompile_subgraph, Stage 1.5 & 9 Hazards)"]
    SRR1["3a. safe-rust-reconstructor<br/>(File-Fenced Module A: edition 2024 Dual-Oracle)"]
    SRR2["3b. safe-rust-reconstructor<br/>(File-Fenced Module B: edition 2024 Dual-Oracle)"]
    APA["4. adversarial-parity-auditor<br/>(Serialized 10,000+up-to-64 verify_rust_parity & Clippy)"]

    Lead --> FVS
    Lead --> SA
    FVS --> SA
    SA --> SRR1
    SA --> SRR2
    SRR1 --> APA
    SRR2 --> APA
```

---

## 3. Swarm Coordination Protocol

### Phase A: Parallel Read-Only Discovery (`forensic-vertical-specialist` + `subgraph-architect`)
Spawn `forensic-vertical-specialist` and `subgraph-architect` concurrently:
- `forensic-vertical-specialist` runs `export_recon_kit` (with `mock_ui_concepts: false` by default) or the domain-specific vertical inspector (`inspect_rust_cpp_binary`, `inspect_python_frozen_binary`, `inspect_ai_model_artifact`, `inspect_engine_archive`, etc.) to identify compiler toolchains, `rust.zero_drift_audit` panic/sink telemetry, RTTI/VTables, embedded scripts, and security mitigations.
- `subgraph-architect` calls `open_binary({ path, provider_id: "auto" })`, `binary_overview({})`, `list_procedures({})`, `inspect_rust_cpp_binary({ path, max_panic_locations: 500, max_symbols: 500 })`, and `decompile_subgraph({ procedure, max_depth: 3, max_nodes: 50, traversal: "bfs", include_assembly: true })` to produce the Stage 1 & Stage 1.5 subsystem dossier (`stage15_reachability` per node, binary-wide `linker_hygiene`, `inferred_struct_offsets`, and all 9 `latent_hazards` categories), using `compare_artifacts` and `find_changed_behavior` across releases to detect Class III Zombie Activation.

### Phase B: Parallel File-Fenced `#![forbid(unsafe_code)]` Reconstruction (`safe-rust-reconstructor`)
Assign each independent subsystem module to a `safe-rust-reconstructor` instance with a strict directory/file fence:
- Each `safe-rust-reconstructor` edits only files inside its assigned fence and enforces `#![forbid(unsafe_code)]` (`candidate_unsafe_blocks === 0`) targeting `edition = "2024"` (`rust-version = "1.100"`) with `[lints.rust] unsafe_code = "forbid"`, `[lints.cargo] unused_dependencies = "warn"`, and `[lints.clippy]` denying `unwrap_used`, `expect_used`, `todo`, `unimplemented`, and `dbg_macro`.
- All **9 Stage 1 `latent_hazards` categories** (`potential_integer_overflow_to_pointer`, `unchecked_division`, `thread_hostile_mutable_global`, `unsafe_memory_sink`, `uninitialized_or_stack_hazard`, `register_writeback_offset_clobber`, `null_deref_before_check`, `size_truncation_or_unsigned_underflow`, `unpopulated_out_param_or_duplicate_call`) are systematically eliminated using `rust-zero-drift` patterns (`#[repr(transparent)]` Newtypes, `PhantomData<State>` Typestates, const-generic fixed capacities, `core::mem::DropGuard`, `std::sync::LazyLock`/`OnceLock`, `Option`/`Result`, `TryFrom`, `.checked_sub()`, and `.checked_div()`).
- Produces **Dual-Oracle** outputs: `<fn>` (`rust_source_code`, bit-exact C-oracle equivalence) alongside `<fn>_remediated` (`remediated_rust_source_code`, defects eliminated).

### Phase C: Serialized `verify_rust_parity` & Self-Healing Loop (`adversarial-parity-auditor`)
Hand the candidate Rust source and target symbols to `adversarial-parity-auditor` one subsystem at a time so CPU-bound `rustc -C opt-level=3` compilation, Cargo builds, and `100,000`-iteration micro-benchmarks never contend for CPU cores (all parallel read/discovery workers scale dynamically via `os.availableParallelism()`, `os.totalmem()`, and `std::thread::available_parallelism()` with zero hardcoded core assumptions):
- The auditor runs `verify_rust_parity` with `forbid_unsafe: true`, `iterations: 10000` (plus **up to `64` deterministic boundary vectors**), and optional `remediated_rust_source_code` + `scaffold_output_dir`.
- If `status === "diverged"`, the auditor relays `counterexample.shrunk_inputs`, `counterexample.c_output_hex`, `counterexample.rust_output_hex`, and `counterexample.bit_diff_summary` back to `safe-rust-reconstructor` for immediate self-healing.
- When `scaffold_output_dir` is supplied, `verify_rust_parity` scaffolds a pure `#![forbid(unsafe_code)]` Rust `1.100` (`edition = "2024"`) Cargo crate (`Cargo.toml` enforcing `[lints.rust]`/`[lints.cargo]`/`[lints.clippy]`, `src/lib.rs` containing `<fn>` + `<fn>_remediated`, `tests/parity_regression.rs`) with zero HTML clutter by default (`scaffolded_crate.rust_edition === "2024"`, `zero_drift_lints_enforced === true`, `dashboard_html_path === null` unless `html_report_path` is opted in), and the auditor certifies `cargo clippy --all-targets -- -D warnings` and `cargo test`.
