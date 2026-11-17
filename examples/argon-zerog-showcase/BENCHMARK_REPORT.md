# ArgonZeroG End-to-End Showcase & Benchmark Report

## 1. Whole-Subgraph Extraction vs. Legacy Sequential Micro-Paging

Target Call Graph (4-function compiled C shared object `libargon_showcase.so`):
`argon_authenticate_packet` $\rightarrow$ `argon_keystream_round` & `argon_tag_finalize` $\rightarrow$ `argon_rotl32`

| Metric | Legacy Sequential Workflow | ArgonZeroG `decompile_subgraph` | Improvement |
| :--- | :--- | :--- | :--- |
| **MCP Tool Round-Trips** | `18` calls | `1` call | **-94.4% round-trips** |
| **Wall-Clock Latency** | `152.48 ms` | `9.73 ms` | **15.67x faster** |
| **Connected Procedures Recovered** | `4` (across 18 turns) | `4` (`argon_authenticate_packet, argon_keystream_round, argon_tag_finalize, argon_rotl32`) | **100% single-shot graph recovery** |
| **Call Edges Recovered** | Manual stitch required | `4` typed call edges | **Zero manual stitching** |
| **Latent Binary Hazards Detected** | `0` (manual audit required) | `4` hazard(s) (`potential_integer_overflow_to_pointer, potential_integer_overflow_to_pointer, unchecked_division, thread_hostile_mutable_global`) | **Automated UB & thread-safety audit** |
| **Stage 1.5 Reachability & Linker Hygiene** | `0` (no reachability or ELF linker audit) | `3` `class_i_live_wired`, `1` `class_ii_dead_fossil`, `0` `class_ii_cloned_inline_suspect` (`dynsym=4, global_default=4 (100.0%), weak=0, plt_stubs=0, relr=0, jni=0, traps_filtered=1, dlopen=0, fvisibility_hidden_omitted=false`) | **Automated Stage 1.5 & visibility audit** |
| **Serialized Wire Payload** | `74780 B` | `19715 B` | **1 contiguous context-cacheable block** |

---

## 2. Closed-Loop Self-Healing Rust Reconstruction (`verify_rust_parity`)

| Phase | Verdict | Memory Safety | Sandbox & Benchmark Telemetry |
| :--- | :--- | :--- | :--- |
| **Attempt 1 (Mutated Candidate)** | `diverged` | `#![forbid(unsafe_code)]` (`0` unsafe blocks) | Caught 1-bit divergence; shrunk `[4096, 4096, 4096]` $\rightarrow$ `[1024, 4096, 2]` in `13` binary-search steps (`XOR diff = 0x2000 (1 bit(s) differ, lowest bit = 13, highest bit = 13); C returned 0xab1f5326 (2870956838), Rust returned 0xab1f7326 (2870965030)`) |
| **Attempt 2 (Self-Healed Safe Rust)** | `verified_bit_exact` | `#![forbid(unsafe_code)]` (`0` unsafe blocks) | **`10,000 / 10,000`** randomized FFI cases + **`64`** boundary cases verified bit-exact • **`1.94x` speedup** (`9.1411 ns` C vs `4.7079 ns` Safe Rust) |
