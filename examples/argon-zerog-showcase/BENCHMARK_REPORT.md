# ArgonZeroG End-to-End Showcase & Benchmark Report

## 1. Whole-Subgraph Extraction vs. Legacy Sequential Micro-Paging

Target Call Graph (4-function compiled C shared object `libargon_showcase.so`):
`argon_authenticate_packet` $\rightarrow$ `argon_keystream_round` & `argon_tag_finalize` $\rightarrow$ `argon_rotl32`

| Metric | Legacy Sequential Workflow | ArgonZeroG `decompile_subgraph` | Improvement |
| :--- | :--- | :--- | :--- |
| **MCP Tool Round-Trips** | `18` calls | `1` call | **-94.4% round-trips** |
| **Wall-Clock Latency** | `189.56 ms` | `11.41 ms` | **16.61x faster** |
| **Connected Procedures Recovered** | `4` (across 18 turns) | `4` (`argon_authenticate_packet, argon_keystream_round, argon_tag_finalize, argon_rotl32`) | **100% single-shot graph recovery** |
| **Call Edges Recovered** | Manual stitch required | `4` typed call edges | **Zero manual stitching** |
| **Latent Binary Hazards Detected** | `0` (manual audit required) | `4` hazard(s) (`potential_integer_overflow_to_pointer, potential_integer_overflow_to_pointer, unchecked_division, thread_hostile_mutable_global`) | **Automated UB & thread-safety audit** |
| **Serialized Wire Payload** | `74650 B` | `16089 B` | **1 contiguous context-cacheable block** |

---

## 2. Closed-Loop Self-Healing Rust Reconstruction (`verify_rust_parity`)

| Phase | Verdict | Memory Safety | Sandbox & Benchmark Telemetry |
| :--- | :--- | :--- | :--- |
| **Attempt 1 (Mutated Candidate)** | `diverged` | `#![forbid(unsafe_code)]` (`0` unsafe blocks) | Caught 1-bit divergence; shrunk `[4096, 4096, 4096]` $\rightarrow$ `[1024, 4096, 2]` in `13` binary-search steps (`XOR diff = 0x2000 (1 bit(s) differ, lowest bit = 13, highest bit = 13); C returned 0xab1f5326 (2870956838), Rust returned 0xab1f7326 (2870965030)`) |
| **Attempt 2 (Self-Healed Safe Rust)** | `verified_bit_exact` | `#![forbid(unsafe_code)]` (`0` unsafe blocks) | **`10,000 / 10,000`** randomized FFI cases + **`64`** boundary cases verified bit-exact • **`2.41x` speedup** (`12.7924 ns` C vs `5.2991 ns` Safe Rust) |
