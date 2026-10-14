# Security Policy

## Architectural Security Guarantees (`ArgonZeroG`)

`REA-Argonaut` is engineered to inspect untrusted binaries, archives, firmware blobs, and AI models safely:

1. **Execution-Free Static Triage (Stage 1):**
   - `export_recon_kit`, `inspect_rust_cpp_binary`, `inspect_python_frozen_binary`, `inspect_ai_model_artifact`, `inspect_engine_archive`, `inspect_go_binary`, `inspect_wasm_artifact`, and `inspect_binary_layout` operate via **pure static binary parsing**.
   - Untrusted targets are never executed during static reconnaissance or `.pyc` marshal / archive inspection.
2. **Sandboxed Differential Parity Verification (Stage 3 — `verify_rust_parity`):**
   - When `verify_rust_parity` executes differential FFI fuzzing against a native shared library or PIE binary, execution is isolated inside [`ParitySandboxRunner`](src/process/ParitySandboxRunner.ts):
     - **Linux:** Wrapped in `bwrap` (read-only root bind, isolated `/tmp`, `--unshare-net`, `--die-with-parent`) and `prlimit` (`RLIMIT_CPU`, `RLIMIT_AS` memory cap, `RLIMIT_CORE=0`).
     - **macOS (`darwin`):** Wrapped in `sandbox-exec` with `(deny network*)`.
     - **Windows (`win32`):** Isolated process tree with strict wall-clock timeout and process-tree termination.
3. **`#![forbid(unsafe_code)]` Reconstructed Rust Targets:**
   - All reconstructed Rust modules and Cargo crates scaffolded by `verify_rust_parity` enforce `#![forbid(unsafe_code)]` at the crate root.

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `1.0.x` | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security issue in `REA-Argonaut` (for example, a parser resource-exhaustion bug or sandbox escape), please report it via [GitHub Security Advisories](https://github.com/PNWcoastie/REA-Argonaut/security/advisories/new) or by opening an issue on [GitHub Issues](https://github.com/PNWcoastie/REA-Argonaut/issues) without including proprietary binary samples.
