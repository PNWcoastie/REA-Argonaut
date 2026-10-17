# Whole-Subgraph Extraction & Gemini 4 Argon Context-Cache Locking (`decompile_subgraph`)

## 1. Architectural Rationale: Collapsing 18+ RPC Round-Trips into 1

Traditional reverse-engineering MCP servers were built for small-context models, forcing agents to issue one RPC per function (`analyze_function`, `procedure_pseudocode`, `procedure_callees`, `procedure_disassembly`) and micro-paging 50 lines at a time. That pattern incurs 18–50+ sequential tool calls for a single subsystem and fragments the prompt prefix so KV context caching cannot be reused.

`ArgonZeroG` replaces function-by-function micro-paging with **Single-Shot Whole-Subgraph Extraction (`decompile_subgraph`)** over the **2-Tier Native Engine**:
- **Tier 1 (`ghidra` / `hopper` / `ida`)**: Headless Ghidra (`11.x` / `12.x`, verified on `12.1.4`) when `GHIDRA_INSTALL_DIR` (or `REA_GHIDRA_HOME`) and `JAVA_HOME` are configured, recovering HighFunction P-Code `PTRSUB`/`PTRADD` struct field displacements and symbolic pseudocode.
- **Tier 2 (`zero-install` / `ZeroInstallNativeProvider`)**: Automatic fallback when Ghidra/Hopper/IDA are absent, combining pure-TypeScript ELF/Mach-O/PE container parsers, host binutils (`objdump`, `llvm-objdump`, `readelf`, `nm`, `otool`), a built-in x86/x86_64/ARM64 bytecode decoder, and automatic stripped-binary procedure boundary & C++ RTTI/VTable slot seeding (`ClassName__vslot_N_<addr>`).

---

## 2. `decompile_subgraph` Traversal & Parameters

### Tool Invocation Signature
```json
{
  "procedure": "LZ4_decompress_safe",
  "max_depth": 3,
  "max_nodes": 50,
  "traversal": "bfs",
  "include_assembly": true
}
```
*(Note: `entry` is supported as a backward-compatible parameter alias for `procedure`, and `session_id` is optional when an active binary session is open.)*

### Parameter Reference
| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `procedure` (or `entry`) | `string` | *(Required)* | Root symbol name (e.g., `"main"`, `"LZ4_compress_default"`, or seeded RTTI slot `"ClassName__vslot_0_401120"`) or hex virtual address (`"0x401120"`). |
| `max_depth` | `number` | `2` | Maximum call-graph hop distance (`0` = root only, `1..5` = transitive callees). |
| `max_nodes` | `number` | `32` | Hard cap (`1..256`) on total procedures returned in the subgraph payload. |
| `traversal` | `"bfs" \| "dfs"` | `"bfs"` | Breadth-First Search (`"bfs"`) prioritizes immediate helper callees; Depth-First Search (`"dfs"`) traces deep execution paths first. |
| `include_assembly` | `boolean` | `true` | Includes disassembled instruction lines alongside decompiled C pseudocode for bit-level verification and hazard detection. |
| `include_strings` | `boolean` | `true` | Aggregates referenced string literals (`aggregated_strings`) across all visited nodes. |
| `include_struct_offsets` | `boolean` | `true` | Extracts composite struct/class field displacements (`inferred_struct_offsets`) from pointer-offset memory accesses. |

---

## 3. Single-Payload Dossier Structure (`nodes`, `inferred_struct_offsets`, `latent_hazards`)

Every `decompile_subgraph` response returns a deterministic, topologically ordered subgraph dossier that locks into the Gemini 4 Argon KV context cache:

1. **`nodes`**: Array of visited procedure nodes (`address`, `name`, `depth`, `pseudocode`, `assembly`, `callers`, `callees`, `inferred_struct_offsets`, `latent_hazards`).
2. **`edges` & `cycle_edges`**: Directed call-graph edges (`from -> to`) and detected recursion/loop edges (`cycle_edges`).
3. **`aggregated_strings`**: Deduplicated string literals referenced across the subgraph.
4. **`inferred_struct_offsets`**: Recovered base register/parameter (`rdi`, `rcx`, `x0`, `param_1`), byte offset (`offset`, `offset_hex`), access width (`1`, `2`, `4`, `8`), and read/write operation mode—ready to synthesize `#[repr(C)]` Safe Rust domain types.
5. **`latent_hazards` & `total_latent_hazards`**: Pre-extracted binary vulnerability and C-to-Rust porting hazards:
   - `potential_integer_overflow_to_pointer` — 32-bit multiply/shift sign-extended into a 64-bit pointer offset (`movsxd`).
   - `unchecked_division` — hardware `div`/`idiv`/`udiv`/`sdiv` without an adjacent zero-divisor guard.
   - `thread_hostile_mutable_global` — unsynchronized writes to `.bss`/`.data` mutable globals.
   - `unsafe_memory_sink` — calls to unbounded C memory/command sinks (`strcpy`, `sprintf`, `gets`, `scanf`, `system`).
   - `uninitialized_or_stack_hazard` — oversized stack frame allocations (`>= 4096` bytes).

---

## 4. Leaf-to-Root Safe Rust Reconstruction & `export_recon_kit` Mount 1

When porting a C/C++ call-graph into `#![forbid(unsafe_code)]` Safe Rust:
- **Materialize Persistent Subgraphs via `export_recon_kit`**: Running `export_recon_kit({ path })` automatically extracts top native subsystems into `recon-kit/native/subgraphs/*.md` and `recon-kit/native/struct-layouts.json` + `hazards.json` so downstream agents can reconstruct directly from workspace files.
- **Step 1 (Leaf Callees)**: Reconstruct and verify pure leaf procedures (checksums, bitfield extractors, bounds helpers) that have zero outgoing calls.
- **Step 2 (Intermediate Nodes)**: Compose verified Rust leaf functions into intermediate parsers/decompressors and verify them via `verify_rust_parity`.
- **Step 3 (Root Entrypoint)**: Reconstruct the root API entrypoint last, guaranteeing that any parity divergence is isolated to the current call-graph layer.
