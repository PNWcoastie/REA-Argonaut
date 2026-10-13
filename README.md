# REA-Argonaut (`ArgonZeroG`)

> *Zero-G Reverse Engineering & Verified Rust Reconstruction for Gemini 4 Argon + Antigravity*

**`REA-Argonaut`** (`rea-argonaut` / CLI: `argonaut`) is a cross-platform (`linux`, `darwin`, `win32`) reverse-engineering and verified Rust transpilation suite + first-class Google Antigravity Plugin.

## Core Pillars

1. **`ArgonZeroG` Subgraph Batch Engine (`decompile_subgraph`):** Replaces 50-line micro-pagination with cycle-safe whole-subsystem call-graph extraction (pseudocode, disassembly, XREFs, strings, and struct offsets in a single context-cacheable payload).
2. **2-Tier Cross-Platform Native Architecture:**
   - **Tier 1 (Deep Decompiler Engine):** Headless Ghidra (with custom Java control-flow/ABI fixes), Hopper, and IDA Pro.
   - **Tier 2 (Zero-Install Fallback):** Out-of-the-box binary layout, call-graph, and disassembly engine across Linux (`ELF` + GNU `binutils`), macOS (`Mach-O` + `otool`/`nm`/`lipo`/`llvm-objdump`), and Windows (`PE/COFF` + `llvm-objdump`/`dumpbin`).
3. **Closed-Loop Rust Parity Verifier (`verify_rust_parity`):** Scaffolds a clean-room Rust `cargo` harness (`libloading` across `.so`/`.dylib`/`.dll` + `proptest`) inside OS-native sandboxes (`bwrap`+`prlimit` on Linux, `/usr/bin/sandbox-exec` on macOS, Windows Job Objects on Windows) to prove bit-exact behavioral equivalence.
4. **Hardware-Adaptive Concurrency:** Dynamically scales worker threads and analysis budgets to the host's runtime hardware (`os.availableParallelism()` and `os.totalmem()`).

## Attribution & License

Released under the [MIT License](./LICENSE). Incorporates and builds upon the MIT-licensed native decompiler bridges, process supervision, and JavaScript static analyzer from [`morluto/rea`](https://github.com/morluto/rea).
