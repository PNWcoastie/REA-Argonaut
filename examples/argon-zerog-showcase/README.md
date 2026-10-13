# ArgonZeroG End-to-End Showcase (`examples/argon-zerog-showcase`)

This directory contains the reproducible, zero-mock end-to-end benchmark and closed-loop Rust verification showcase for **`REA-Argonaut` (`ArgonZeroG`)**.

## What It Demonstrates

1. **Live C Compilation (`libargon_showcase.so`):**
   Compiles a 4-function packet authentication call graph (`argon_authenticate_packet` $\rightarrow$ `argon_keystream_round` & `argon_tag_finalize` $\rightarrow$ `argon_rotl32`) into a native shared library with `gcc -O2`.
2. **Legacy Micro-Paged Workflow vs. `decompile_subgraph`:**
   - **Run A (Legacy):** Executes the 18-call sequential workflow (`binary_overview`, `list_procedures`, and `analyze_function` + `procedure_assembly` + `procedure_callers` + `procedure_callees` across all 4 functions) over `StdioClientTransport`.
   - **Run B (`ArgonZeroG`):** Executes a single `decompile_subgraph` call rooted at `argon_authenticate_packet`, recovering all 4 procedures, their decompiled pseudocode, assembly instructions, and call-graph edges in **1 MCP round-trip (94.4% fewer round-trips)**.
3. **Closed-Loop Self-Healing Rust Reconstruction (`verify_rust_parity`):**
   - **Attempt 1 (Buggy Candidate):** Submits a candidate Rust implementation with a deliberate 1-bit divergence on the threshold branch `seed >= 1024 && payload >= 4096`. `verify_rust_parity` loads `libargon_showcase.so` via FFI `dlopen`, detects the divergence, and binary-search shrinks the counterexample to the exact threshold boundary (`[1024, 4096, 0]`).
   - **Attempt 2 (Self-Healed Candidate):** Submits the repaired safe Rust implementation and proves bit-exact equivalence across **10,000 randomized SplitMix64 FFI test cases + 64 deterministic boundary cases** inside the OS sandbox.

## Running the Showcase

```bash
npm run build
node examples/argon-zerog-showcase/run-showcase.mjs
```

Running the script regenerates:
- `examples/argon-zerog-showcase/benchmark-results.json`
- `examples/argon-zerog-showcase/BENCHMARK_REPORT.md`
