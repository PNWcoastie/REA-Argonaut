# Subgraph Decompilation & Content-Addressed SQLite DAG Caching

## 1. Architectural Rationale: Eliminating IPC Roundtrips & Re-Analysis

Traditional reverse engineering MCP integrations issue one RPC per function (`decompile(fn_A)`, `get_callees(fn_A)`, `decompile(fn_B)`, `decompile(fn_C)`), incurring 40–100+ process or socket roundtrips for a single subsystem and repeatedly re-running analysis passes on unmodified binaries.

`ArgonZeroG` replaces single-function polling with **Subgraph Batch Decompilation (`decompile_subgraph`)** backed by a persistent, content-addressed **SQLite Call-Graph & Decompilation Cache (`BinaryCacheStore`)**.

---

## 2. Content-Addressed SQLite Cache (`BinaryCacheStore`)

### Cache Key & Storage Layout
- **Cache Location**: `~/.cache/rea-argonaut/subgraph-cache.sqlite` (configurable via `REA_ARGONAUT_CACHE_DIR`).
- **Content Key**: Every binary is indexed by its full **SHA-256 digest** (`binary_sha256`) computed when `open_binary` is invoked.
  - Renaming or moving a binary on disk preserves 100% of cached procedures, call edges, and decompiled pseudocode.
  - Recompiling or patching even a single byte changes `binary_sha256`, preventing stale pseudocode collisions.
- **SQLite PRAGMAs**:
  - `PRAGMA journal_mode = WAL;` — enables concurrent reads across parallel Antigravity 2.0 swarm subagents (`subgraph-architect`, `safe-rust-reconstructor`, `forensic-vertical-specialist`, `adversarial-parity-auditor`).
  - `PRAGMA synchronous = NORMAL;` — balances durability with sub-millisecond read/write throughput.

### Core Schema Tables
1. `binaries(binary_sha256 PRIMARY KEY, path, format, arch, endian, provider_id, analyzed_at)`
2. `procedures(binary_sha256, address PRIMARY KEY, name, size, signature, pseudocode, assembly, decompiled_at)`
3. `call_edges(binary_sha256, caller_address, callee_address, call_site_address, PRIMARY KEY (binary_sha256, caller_address, callee_address))`

---

## 3. `decompile_subgraph` Traversal & Parameters

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
*(Note: `entry` is supported as a backward-compatible parameter alias for `procedure`.)*

### Parameter Reference
| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `procedure` (or `entry`) | `string` | *(Required)* | Root symbol name (e.g., `"main"`, `"LZ4_compress_default"`) or hex virtual address (`"0x401120"`). |
| `max_depth` | `number` | `2` | Maximum call-graph hop distance (`0` = root only, `1..6` = transitive callees). |
| `max_nodes` | `number` | `32` | Hard cap (`1..250`) on total procedures returned in the subgraph payload to prevent context window bloat. |
| `traversal` | `"bfs" \| "dfs"` | `"bfs"` | Breadth-First Search (`"bfs"`) prioritizes immediate helper callees; Depth-First Search (`"dfs"`) traces deep execution paths first. |
| `include_assembly` | `boolean` | `true` | Includes disassembled instructions alongside C pseudocode for bit-level verification. |

---

## 4. Topological Leaf-to-Root Reconstruction Ordering

Every `decompile_subgraph` response returns:
1. `nodes`: Array of decompiled procedure nodes (`address`, `name`, `signature`, `pseudocode`, `assembly`, `callees`, `callers`, `cache_hit`).
2. `edges`: Directed call-graph edges (`caller -> callee`).
3. `topological_order`: Post-order leaf-to-root reconstruction schedule (via Tarjan's Strongly Connected Components + Kahn's topological sort for DAG condensation).
4. `cache_stats`: `{ hits, misses, hit_rate, sqlite_wal_enabled }`.

### Why Leaf-to-Root Ordering Matters
When porting a C/C++ call-graph into safe `#![forbid(unsafe_code)]` Rust:
- **Step 1 (Leaf Callees)**: Reconstruct and verify pure leaf procedures (checksums, bitfield extractors, bounds helpers) that have zero outgoing calls.
- **Step 2 (Intermediate Nodes)**: Compose verified Rust leaf functions into intermediate parsers/decompressors and verify them via `verify_rust_parity`.
- **Step 3 (Root Entrypoint)**: Reconstruct the root API entrypoint last, guaranteeing that any parity divergence is isolated to the current call-graph layer rather than an unverified helper.
