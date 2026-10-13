# REA-Argonaut (`ArgonZeroG`)

> **Zero-G Reverse Engineering Anything & Sandboxed Closed-Loop Rust Parity Verifier for Gemini 4 Argon + Google Antigravity 2.0**

**`REA-Argonaut`** (package: `rea-argonaut`, CLI: `argonaut`, MCP server: `rea-argonaut`) is a cross-platform (`linux`, `darwin`, `win32`) reverse-engineering and verified Rust reconstruction suite, engineered as a first-class **Google Antigravity 2.0 Plugin** and **Model Context Protocol (MCP)** server.

Built as a full superset of [`morluto/rea`](https://github.com/morluto/rea) (*Reverse Engineer Anything*), `REA-Argonaut` preserves all **35 original REA reverse-engineering domains (`187` tools)** while introducing the **`ArgonZeroG` architecture** and **6 new high-throughput forensic & verification tools (`193` total MCP tools)** designed for long-context frontier reasoning models.

---

## Why `REA-Argonaut`? (`ArgonZeroG` Architecture)

Legacy MCP reverse-engineering servers were architected for small-context models, enforcing tiny pagination limits (`64`-character string previews, `50`-line pseudocode slices, `20`-row table pages) that force frontier agents into hundreds of sequential RPC round-trips and destroy KV context-cache reuse.

`REA-Argonaut` eliminates token-scarcity bottlenecks across five architectural pillars:

### 1. `decompile_subgraph` (`ArgonZeroG` Subgraph Batch Engine)
- **Single-Call Call-Graph Extraction:** Traverses a target binary's call graph (`BFS` or `DFS`, cycle-safe up to `max_depth: 5` and `max_nodes: 256`) and returns an entire subsystem's **decompiled C pseudocode, disassembly, cross-references (XREFs), referenced string literals (`2048`-char previews), and P-Code inferred struct field offsets** in one deterministic JSON payload.
- **95%+ Context-Cache Reuse:** Emits a topologically ordered, immutable subgraph representation so multi-turn agent reasoning and Rust reconstruction reuse cached KV prefixes instead of fragmenting context across dozens of micro-paginated tool calls.
- **Raised `ArgonZeroG` Limits Across All Tools:**
  - `list_strings`: `max_preview_length` raised to **`2048`** (`default: 512`), `limit` raised to **`2000`** (`default: 250`).
  - `get_pseudocode`: `max_lines` raised to **`5000`** (`default: 1000`).
  - `disassemble_function`: `max_instructions` raised to **`5000`** (`default: 1000`).
  - `list_functions` / `list_imports` / `list_exports`: `limit` raised to **`2500`** (`default: 500`).

### 2. 2-Tier Cross-Platform Native Engine (`linux`, `darwin`, `win32`)
- **Tier 1 (Deep Decompiler Engine):** Full Headless Ghidra (`analyzeHeadless` with custom Java bridge enhancements for P-Code struct field offset recovery), Hopper Disassembler, and IDA Pro (`idalib`).
- **Tier 2 (`ZeroInstallNativeProvider` Zero-Install Fallback):** Out-of-the-box binary layout, symbol/section discovery, call-graph extraction, and disassembly when Ghidra/Hopper/IDA are not installed:
  - **Linux (`ELF`):** GNU `binutils` (`objdump`, `readelf`, `nm`) + native ELF header parser.
  - **macOS (`Mach-O`):** `otool`, `nm`, `lipo`, `llvm-objdump` + universal fat-binary slice parser.
  - **Windows (`PE/COFF`):** `llvm-objdump`, `dumpbin` + native PE/COFF header/import/export parser.
  - **Python Bridge (`bridge/binutils/rea_binutils_bridge.py`):** Dual-path backend supporting `pwntools` when installed and a **100% Python stdlib fallback** (`elftools` / `objdump` / `otool` / `llvm-objdump`) on clean hosts.

### 3. 100% Vanilla REA Superset (`35` Retained Domains) + `4` New `ArgonZeroG` Forensic Verticals (`193` Total MCP Tools)
In addition to every original REA capability (JavaScript/Web bundles, Source Maps, Chrome DevTools/CDP, Frida, GDB/LLDB/WinDbg, Android APK/DEX, iOS IPA, JVM/JAR, .NET CIL, WebAssembly, Electron ASAR, Mach-O/ELF/PE, Hermit/React Native, Lua, Flash SWF, Archives, PCAP/HAR, EVM/Solidity, Firmware, Symbolic Execution, YARA/Capa), `REA-Argonaut` adds four purpose-built forensic verticals:

- **`inspect_rust_cpp_binary` — Stripped Rust & Modern C++ Binary Forensics:**
  - Recovers crate names and exact versions from `.cargo/registry/src/...` paths and `core::panicking::Location` tuples even in `strip --strip-all` binaries.
  - Native TypeScript **Rust `_RNv` v0** and **legacy `_ZN`** symbol demangler + **Itanium (`_Z`)** and **MSVC (`?`)** C++ demangler.
  - Reconstructs **C++ VTables and RTTI (`typeinfo`)** across ELF (`SHT_RELA` PIE relocation resolution), Mach-O, and PE binaries without launching a heavy decompiler session.
- **`inspect_python_frozen_binary` — Execution-Free Frozen Python Unpacker:**
  - Pure-TypeScript parser for **PyInstaller (`MEI\x0c\x0b\x0a\x0b\x0e`)** CArchive trailers, `PYZ` zlib-compressed embedded module tables, and **PEP 552 `.pyc` code-object marshal streams**.
  - Extracts Python version, entry-point scripts, bundled package manifests, `co_names`, `co_consts`, and string literals without executing untrusted bytecode.
- **`inspect_ai_model_artifact` — Zero-Copy Streaming AI Model Forensics:**
  - Constant-memory (`fs.open` + bounded `read()`) streaming inspector for **`GGUF` (v1–v3)**, **`SafeTensors`**, **`ONNX`**, and **`TFLite`** artifacts.
  - Extracts architecture hyperparameters, quantization distribution, tensor layouts, and **embedded Jinja `tokenizer.chat_template` / `system_prompt` strings** without loading multi-gigabyte weight buffers into RAM.
- **`inspect_engine_archive` — Game Engine Metadata & Asset Pack Inspector:**
  - Parses **Unity IL2CPP `global-metadata.dat` (`0xFAB11BAF`, v24–v31)** to recover C# namespaces, class/type definitions, method names, and string literals from native-compiled Unity binaries.
  - Parses **Godot Engine `.pck` (`GDPC`, v1–v2)** archives to enumerate packed `.gd` / `.gdc` scripts, `.tscn` scenes, and asset SHA-256 digests.

### 4. Closed-Loop Sandboxed Rust Parity Verifier (`verify_rust_parity`)
- **Automated Differential FFI Harness:** Compiles a C reference implementation (or loads an existing `.so` / `.dylib` / `.dll` via `dlopen`/`dlsym`) alongside a candidate Rust reconstruction (`rustc --crate-type cdylib`) and runs **`10,000+` SplitMix64 randomized + boundary test vectors** (`0`, `1`, `-1`, `MIN`, `MAX`, powers of two, bitmasks) in-process.
- **Deterministic Counterexample Shrinking:** Automatically binary-searches any diverging input down to the minimal failing argument tuple and reports exact `c_output`, `rust_output`, and `shrunk_counterexample` diagnostics so the agent can self-heal its Rust port in a closed loop.
- **OS-Native Sandboxed Execution:** Runs compiled harnesses inside isolated OS sandboxes:
  - **Linux:** `bwrap` (`bubblewrap` network-isolated namespace) + `prlimit` CPU/AS/NOFILE caps.
  - **macOS:** `/usr/bin/sandbox-exec` (`(deny network*)` Seatbelt profile) + `ulimit`.
  - **Windows:** Restricted Job Objects / timeout-bounded process groups.

### 5. Hardware-Adaptive Runtime Scaling (`AdaptiveResourceProfile`)
- Dynamically inspects `os.availableParallelism()` and `os.totalmem()` at startup (`src/config/AdaptiveResourceProfile.ts`) to scale JavaScript AST worker pools, Headless Ghidra JVM heap (`-XX:ActiveProcessorCount`, `-Xmx`), and concurrent subprocess budgets across laptops, CI containers, and 128-core workstations with zero hardcoded CPU limits.

---

## Quickstart

### 1. Install & Build
```bash
npm install
npm run build
```

### 2. Run the End-to-End `ArgonZeroG` Showcase
Compile a multi-function C cryptographic/compression pipeline (`argon_cipher_pipeline`), strip all symbols, extract the whole call-graph in one `decompile_subgraph` call, inspect stripped Rust/C++ panics & VTables, stream-inspect a `GGUF` AI model header, and prove bit-exact C-to-Rust parity across `10,000` FFI test inputs:
```bash
npm run showcase
```

### 3. CLI Usage (`argonaut`)
```bash
# Check host toolchains and adaptive hardware profile
node dist/cli.js doctor

# Single-call ArgonZeroG call-graph extraction
node dist/cli.js open /path/to/binary --alias target
node dist/cli.js decompile-subgraph --session target --entry 0x401120 --max-depth 3

# Standalone forensic inspectors (no binary session required)
node dist/cli.js inspect-rust-cpp-binary --path /path/to/stripped_rust_or_cpp_bin
node dist/cli.js inspect-python-frozen-binary --path /path/to/pyinstaller_binary
node dist/cli.js inspect-ai-model-artifact --path /path/to/model.gguf
node dist/cli.js inspect-engine-archive --path /path/to/global-metadata.dat

# Closed-loop C vs. Rust FFI differential parity verification
node dist/cli.js verify-rust-parity \
  --target-binary-path /path/to/libtarget.so \
  --symbol-name compute_tag \
  --arg-types u64,u32 \
  --return-type u64 \
  --rust-source-code '#[no_mangle] pub extern "C" fn compute_tag(a: u64, b: u32) -> u64 { ... }' \
  --iterations 10000
```

---

## Google Antigravity 2.0 Plugin & MCP Server Setup

### First-Class Antigravity Plugin (`plugin.json`)
`REA-Argonaut` ships with a root [`plugin.json`](./plugin.json) manifest and bundled agent skills:
- [`.agents/skills/rea-argonaut/SKILL.md`](./.agents/skills/rea-argonaut/SKILL.md) — `ArgonZeroG` Subgraph Batch Decompilation, Stripped Rust/C++/PyInstaller/AI-Model/Engine-Archive Forensics, and Closed-Loop Rust Parity Verification playbooks.
- [`.agents/skills/reverse-engineer-anything/SKILL.md`](./.agents/skills/reverse-engineer-anything/SKILL.md) — Full multi-domain reverse-engineering routing guide.

### `.gemini/settings.json` / MCP Configuration
Copy [`.gemini/settings.json.example`](./.gemini/settings.json.example) to `.gemini/settings.json` (or register in your MCP client):

```json
{
  "mcpServers": {
    "rea-argonaut": {
      "command": "node",
      "args": ["/absolute/path/to/REA-Argonaut/dist/main.js"],
      "env": {
        "MCP_TOOL_RESULT_CONTENT_MODE": "text-only"
      }
    }
  }
}
```

Or via `npx`:
```json
{
  "mcpServers": {
    "rea-argonaut": {
      "command": "npx",
      "args": ["-y", "rea-argonaut"],
      "env": {
        "MCP_TOOL_RESULT_CONTENT_MODE": "text-only"
      }
    }
  }
}
```

---

## Attribution & License

Released under the [MIT License](./LICENSE).

`REA-Argonaut` gratefully acknowledges and builds upon [`morluto/rea`](https://github.com/morluto/rea) (*Reverse Engineer Anything*, Copyright (c) 2026 morluto, MIT License), preserving its complete multi-domain reverse-engineering architecture, process supervision, and decompiler bridges while extending it with the `ArgonZeroG` subgraph engine, zero-install cross-platform fallback, specialized forensic inspectors, and sandboxed Rust parity verifier. See [`LICENSE`](./LICENSE) and [`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md) for full details.
