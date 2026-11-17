# Whole-Subgraph Extraction & Gemini 4 Argon Context-Cache Locking (`decompile_subgraph`)

## 1. Architectural Rationale: Collapsing 18+ RPC Round-Trips into 1

Traditional reverse-engineering MCP servers were built for small-context models, forcing agents to issue one RPC per function (`analyze_function`, `procedure_pseudo_code`, `procedure_callees`, `procedure_assembly`) and micro-paging 50 lines at a time. That pattern incurs 18–50+ sequential tool calls for a single subsystem and fragments the prompt prefix so KV context caching cannot be reused.

`ArgonZeroG` replaces function-by-function micro-paging with **Single-Shot Whole-Subgraph Extraction (`decompile_subgraph`)** over the **2-Tier Native Engine**:
- **Tier 1 (`ghidra` / `hopper` / `ida`)**: Headless Ghidra (`11.x` / `12.x`, verified on `12.1.4`) when `GHIDRA_INSTALL_DIR` (or `REA_GHIDRA_HOME`) and `JAVA_HOME` are configured, recovering HighFunction P-Code `PTRSUB`/`PTRADD` struct field displacements and symbolic pseudocode.
- **Tier 2 (`zero-install` / `ZeroInstallNativeProvider`)**: Automatic fallback when Ghidra/Hopper/IDA are absent, combining pure-TypeScript ELF/Mach-O/PE container parsers, host binutils (`objdump`, `llvm-objdump`, `readelf`, `nm`, `otool`), a built-in x86/x86_64/ARM64 bytecode decoder, `SHT_RELR` (`.relr.dyn`) relative bitmap decoding, Android Bionic `APS2` (`SHT_ANDROID_REL`/`SHT_ANDROID_RELA`) SLEB128 relocation unpacking, stripped `LOCAL` JNI `RegisterNatives` (`JNINativeMethod`) table recovery, 5-class C++ linker-trap filtering, and automatic stripped-binary procedure boundary & C++ RTTI/VTable slot seeding (`ClassName__vslot_N_<addr>`).

---

## 2. `decompile_subgraph` Traversal & Parameters

### Tool Invocation Signature
```json
{
  "procedure": "LZ4_decompress_safe",
  "document": null,
  "max_depth": 3,
  "max_nodes": 50,
  "traversal": "bfs",
  "include_assembly": true
}
```
*(Note: `entry` is supported as an alias for `procedure`; supply either `procedure` or `entry`. `decompile_subgraph` uses a `.strict()` schema and operates on the active `open_binary` session—optional `document` defaults to `null`.)*

### Parameter Reference
| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `procedure` (or `entry`) | `string` | *(Required)* | Root procedure selector: exact symbol name (e.g., `"main"`, `"LZ4_compress_default"`, or seeded RTTI slot `"ClassName__vslot_0_401120"`) or `0x`-prefixed hexadecimal entry address (`"0x401120"`). |
| `document` | `string \| null` | `null` | Optional document name for multi-document providers; defaults to `null` for the active binary target. |
| `max_depth` | `number` | `2` | Maximum call-graph traversal depth from the root procedure (`0..10`; `0` = root only). |
| `max_nodes` | `number` | `25` | Hard cap (`1..100`) on unique procedures to decompile in the subgraph payload. |
| `traversal` | `"bfs" \| "dfs"` | `"bfs"` | Breadth-First Search (`"bfs"`) prioritizes immediate helper callees; Depth-First Search (`"dfs"`) traces deep execution paths first. |
| `include_assembly` | `boolean` | `true` | Includes disassembled instruction lines (`assembly`) alongside decompiled pseudocode (`pseudocode`) for bit-level verification and hazard detection. |

*(Referenced strings `referenced_strings` / `aggregated_strings`, struct field displacements `inferred_struct_offsets`, all 9 `latent_hazards` categories, `stage15_reachability`, and `linker_hygiene` are always extracted automatically.)*

---

## 3. Single-Payload Dossier Structure (`nodes`, `stage15_reachability`, `linker_hygiene`, `inferred_struct_offsets`, `latent_hazards`)

Every `decompile_subgraph` response returns a deterministic, topologically ordered subgraph dossier (`root_procedure`, `node_count`, `total_latent_hazards`, `truncated`, `nodes`, `edges`, `cycle_edges`, `aggregated_strings`, `linker_hygiene`, `limitations`) that locks into the Gemini 4 Argon KV context cache:

1. **`nodes`**: Array of visited procedure dossiers (`procedure` `{ address, name, signature }`, `depth`, `pseudocode`, `assembly`, `callers`, `callees`, `referenced_strings`, `inferred_struct_offsets`, `latent_hazards`, and `stage15_reachability`).
2. **`edges` & `cycle_edges`**: Directed call-graph edges (`from -> to`, `kind`: `"direct_call" | "indirect_call" | "cycle_call"`) and detected recursion/loop edges (`cycle_edges`).
3. **`aggregated_strings`**: Deduplicated string literals referenced across the subgraph (`address`, `value`, `referenced_by`).
4. **`inferred_struct_offsets`**: Recovered base register/parameter (`rdi`, `rcx`, `x0`, `param_1`), signed byte displacement (`offset`, `offset_hex`), access width (`1`, `2`, `4`, `8`, etc.; `0` if address-only), `access` mode (`"read" | "write" | "read_write" | "address"`), and `field_name` (`string | null`)—ready to synthesize `#[repr(C)]` or idiomatic Safe Rust domain types.
5. **Stage 1.5 Multi-Edge Reachability (`stage15_reachability` per node)**:
   - `classification`:
     - `class_i_live_wired` — reachable via internal callers, entrypoints (`main`, `_start`, `DllMain`, `WinMain`), `Java_*`/`JNI_OnLoad`, recovered `RegisterNatives` entries, RTTI/vtable dispatch, or `dlopen` plugin dispatch exports. Prioritize Stage 2 Safe Rust reconstruction when active hazards exist.
     - `class_ii_dead_fossil` — zero intra-binary callers and no live entry edge (`unreferenced_export` or `unreferenced_internal`); recommend stripping with `-fvisibility=hidden -ffunction-sections` and `-Wl,--gc-sections`.
     - `class_ii_cloned_inline_suspect` — unreferenced procedure sharing matching high-severity algorithmic hazard categories or `>= 2` hazard categories with a live wired procedure; audit active callers or inlined/threaded clones before stripping.
   - Includes `intra_binary_caller_count`, `is_exported_global_default`, `linkage_edges` (`dynsym_export`, `jni_java_export`, `jni_onload_register_natives`, `vtable_dispatch`, `dlopen_plugin_entry`, `internal_call_chain`, `unreferenced_export`, `unreferenced_internal`), and `remediation_action`.
   - **Class III Zombie Activation**: When comparing baseline vs. updated binaries, pair `decompile_subgraph` with `compare_artifacts` and `find_changed_behavior` to catch formerly `class_ii_dead_fossil` procedures acquiring live edges in newer builds.
6. **Binary-Wide Linker Hygiene (`linker_hygiene`)**:
   - `-fvisibility=hidden` & PLT bloat audit (`defined_dynsym_functions`, `global_default_functions`, `global_default_ratio`, `weak_functions`, `intra_binary_plt_stubs`, `fvisibility_hidden_likely_omitted`).
   - `relr_relocations_decoded` (`SHT_RELR` `.relr.dyn` decoding alongside Android Bionic `APS2`), `jni_registered_methods_recovered` (stripped `LOCAL` JNI `RegisterNatives` `JNINativeMethod` recovery), `filtered_cpp_linker_traps` (5 C++ linker-trap filters: `ndk_cpp_runtime_reexport`, `weak_stl_typeinfo_or_vtable`, `static_third_party_collision`, `sibling_hal_callback_collision`, `stl_template_method_collision`), and clean `dlopen_targets` (system property prefixes and diagnostic `dlopen` errors excluded).
7. **All 9 `latent_hazards` Categories & `total_latent_hazards`**:
   - `potential_integer_overflow_to_pointer` — 32-bit multiply/shift sign-extended into a 64-bit pointer offset (`movsxd`/`sxtw`).
   - `unchecked_division` — hardware `div`/`idiv`/`udiv`/`sdiv`/`divss`/`divsd`/`fdiv` without an adjacent zero-divisor guard.
   - `thread_hostile_mutable_global` — unsynchronized reads/writes to `.bss`/`.data`/`.got` mutable globals.
   - `unsafe_memory_sink` — calls to unbounded C memory/command sinks (`strcpy`, `strcat`, `sprintf`, `vsprintf`, `gets`, `scanf`, `__isoc99_scanf`, `system`, `popen`).
   - `uninitialized_or_stack_hazard` — oversized stack frame allocations (`>= 4096` bytes).
   - `register_writeback_offset_clobber` — pre/post-indexed base-register writeback (`[xN, #imm]!`, `[xN], #imm`) shifting the base pointer before subsequent `[xN, #off]` memory accesses.
   - `null_deref_before_check` — pointer dereferenced or passed to null-unsafe sinks (`strlen`, `wcslen`, `strcmp`, `strcpy`, `memcpy`, etc.) before a null check.
   - `size_truncation_or_unsigned_underflow` — `strlen`/`wcslen` length decremented without an underflow guard, 64-bit `size_t` narrowed to 32-bit at alloc/copy callsites, or signed 32-bit promotion into alloc/copy sinks.
   - `unpopulated_out_param_or_duplicate_call` — duplicate back-to-back calls without intervening control flow, or zeroed stack out-parameter passed to a callee followed by bit-31 sign extraction.

---

## 4. Leaf-to-Root Safe Rust Reconstruction & `export_recon_kit` Mount 1

When porting a C/C++ call-graph into `#![forbid(unsafe_code)]` Safe Rust:
- **Materialize Persistent Artifacts via `export_recon_kit`**: Running `export_recon_kit({ path })` extracts Mount 1 (`native-binary`) subsystems into `RECON_BLUEPRINT.md`, `types/recovered_types.rs`, `types/recovered_types.h`, `classes/vtable_hierarchy.json`, `classes/subsystem_clusters.md`, `subsystems/primary_entrypoints.c`, and `hazards/security_audit.md` in `output_dir` so downstream agents can reconstruct directly from workspace files.
- **Step 1 (Leaf Callees)**: Reconstruct and verify pure leaf procedures (checksums, bitfield extractors, bounds helpers) that have zero outgoing calls.
- **Step 2 (Intermediate Nodes)**: Compose verified Rust leaf functions into intermediate parsers/decompressors and verify them via `verify_rust_parity`.
- **Step 3 (Root Entrypoint)**: Reconstruct the root API entrypoint last, guaranteeing that any parity divergence is isolated to the current call-graph layer.
