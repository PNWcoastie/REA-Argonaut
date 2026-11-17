# Sandboxed Safe Rust Parity Verification (`verify_rust_parity`)

## 1. Overview: Proving Bit-Exact Equivalence Without `unsafe`

LLM-generated decompilation translations frequently introduce subtle integer overflow, sign-extension, shift-masking, or floating-point rounding bugs. `verify_rust_parity` eliminates guesswork by compiling the candidate Rust code with `#![forbid(unsafe_code)]` and executing property-based differential fuzzing (`10,000` SplitMix64 seeds + up to `64` deterministic boundary cases) against the original native C/C++ symbol inside an OS-level sandbox.

---

## 2. Input Schema & Modes

### Mode A: Direct Native Binary FFI (`target_binary_path`)
Loads a compiled shared library or position-independent executable (`.so` on Linux, `.dylib` on macOS, `.dll` on Windows) directly via `dlopen` / `LoadLibrary`.
- **PIE Executable Support**: If `target_binary_path` is an ELF PIE executable (`ET_DYN` with `DF_1_PIE` set in `.dynamic`), Mach-O executable (`MH_EXECUTE`), or PE executable, `verify_rust_parity` automatically patches a temporary copy in the sandbox directory (stripping `DF_1_PIE` / patching `MH_DYLIB` / setting `IMAGE_FILE_DLL`) so `dlopen`/`LoadLibrary` can resolve exported symbols directly.

```json
{
  "target_binary_path": "/lib/x86_64-linux-gnu/libz.so.1",
  "symbol_name": "crc32",
  "rust_source_code": "pub fn crc32(crc: u64, buf: &[u8]) -> u64 { ... }",
  "rust_fn_name": "crc32",
  "arg_types": ["u64", "bytes"],
  "return_type": "u64",
  "iterations": 10000,
  "seed": 1337420,
  "forbid_unsafe": true
}
```

### Mode B: C Oracle Compilation (`c_source_code`)
When the target procedure is non-exported (`static`) or requires a custom struct harness, pass `c_source_code` to compile a reference C shared library on the fly alongside the safe Rust candidate:

```json
{
  "c_source_code": "#include <stdint.h>\nuint32_t rotl32(uint32_t x, uint32_t n) { return (x << (n & 31)) | (x >> ((32 - n) & 31)); }",
  "symbol_name": "rotl32",
  "rust_source_code": "pub fn rotl32(x: u32, n: u32) -> u32 { x.rotate_left(n & 31) }",
  "arg_types": ["u32", "u32"],
  "return_type": "u32",
  "iterations": 10000,
  "seed": 1337420,
  "forbid_unsafe": true
}
```

### Supported `arg_types` (`1..=16`) & `return_type`
- **Scalar Integers**: `"i8"`, `"u8"`, `"i16"`, `"u16"`, `"i32"`, `"u32"`, `"i64"`, `"u64"`, `"bool"`
- **Floating Point**: `"f32"`, `"f64"` (full IEEE-754 bit-pattern fuzzing with canonical `NaN` and `+0.0 == -0.0` equivalence), plus `"f32_finite"` and `"f64_finite"` (finite-domain DSP/numerical fuzzing in `[-1e6, 1e6]`)
- **Buffer Slices (`arg_types` only)**: `"bytes"` — automatically bridges a C ABI `(const uint8_t* ptr, size_t len)` pointer+length pair to a safe `&[u8]` slice in the Rust candidate function.

### Built-In Canonical Out-Buffer & Struct Digest Helpers (`argon_digest_*`)
When verifying a C/C++ function that mutates an output array, matrix, or struct in-place (`void fn(..., float* out_buf)`), `verify_rust_parity` automatically injects matching 64-bit FNV-1a + SplitMix64 digest helpers into both the C compilation unit and the Safe Rust candidate module (`return_type: "u64"`):
- **C Oracle Helpers (pre-included)**:
  - `uint64_t argon_digest_bytes(const void *data, size_t len)`
  - `uint64_t argon_digest_u32(const uint32_t *vals, size_t count)` / `argon_digest_i32(const int32_t *vals, size_t count)`
  - `uint64_t argon_digest_f32(const float *vals, size_t count)` / `argon_digest_f64(const double *vals, size_t count)` *(automatically canonicalizes `-0.0` to `+0.0` and any `NaN` payload to canonical quiet `NaN` before hashing)*
- **Safe Rust Candidate Helpers (pre-included in `mod candidate` and scaffolded `src/lib.rs`)**:
  - `argon_digest_bytes(data: &[u8]) -> u64`
  - `argon_digest_u32(vals: &[u32]) -> u64` / `argon_digest_i32(vals: &[i32]) -> u64`
  - `argon_digest_f32(vals: &[f32]) -> u64` / `argon_digest_f64(vals: &[f64]) -> u64`

### Cross-`libm` Transcendental Note (`glibc` vs. `musl` / `Bionic` / `libsystem_m`)
- Inside `verify_rust_parity` on the same host, both the C oracle and Safe Rust link the same system `libm`, so `sinf`, `cosf`, `atan2f`, `asinf`, `expf`, and `logf` match at `0 ULP` (`float_ulp_tolerance: 0`).
- When cross-compiling standalone verification binaries across distinct C standard libraries (e.g., `x86_64-unknown-linux-gnu` `glibc` vs. `aarch64-unknown-linux-musl` `musl` or Android `Bionic`), `libm` polynomial approximations for transcendentals can differ by `1 ULP`. Link the same `libm` on both targets (e.g., `musl` on both `x86_64` and `aarch64`) for `0 ULP` digest identity, or set `float_ulp_tolerance: 1` for transcendental kernels.

### Dual-Oracle Cargo Crate Scaffolding (`scaffold_output_dir`) & Opt-In HTML Report (`html_report_path`)
- **`scaffold_output_dir`** *(optional)*: When provided and `status === "verified_bit_exact"`, `verify_rust_parity` scaffolds a **100% pure `#![forbid(unsafe_code)]` Rust `1.100` (`edition = "2024"`) Cargo crate** (`Cargo.toml`, `src/lib.rs`, `tests/parity_regression.rs`) with zero HTML clutter by default:
  - **`Cargo.toml` zero-drift lints**: Configures `edition = "2024"`, `rust-version = "1.100"`, `[lints.rust] unsafe_code = "forbid"`, `[lints.cargo] unused_dependencies = "warn"`, and `[lints.clippy]` denying `unwrap_used`, `expect_used`, `todo`, `unimplemented`, and `dbg_macro`.
  - **`remediated_rust_source_code` Dual-Oracle Scaffolding (`<fn>` + `<fn>_remediated`)**: When optional `remediated_rust_source_code` is supplied alongside `rust_source_code`, `src/lib.rs` emits both the bit-exact `<fn>` C-oracle port and the defect-eliminated `<fn>_remediated` Safe Rust sibling (under `// --- Remediated Implementation (Defects Eliminated) ---`), injecting `argon_digest_*` helpers if referenced.
  - **Attribute & ABI Normalization**: `CrateScaffolder` strips redundant crate-level `#![forbid(unsafe_code)]`, FFI `#[no_mangle]` / `#[unsafe(no_mangle)]` attributes, and `extern "C"` qualifiers from both `rust_source_code` and `remediated_rust_source_code` while preserving `pub fn` visibility and enforcing `#![forbid(unsafe_code)]` at the `src/lib.rs` crate root.
  - **Clippy-Clean Regression Tests (`tests/parity_regression.rs`)**: Emits deterministic vector assertions using `assert!(...)` / `assert!(!...)` for `bool`, `.to_bits()` plus canonical `NaN` / `±0.0` bit checks for `f32`/`f64`, and `assert_eq!` for integers—ready for `cargo clippy --all-targets -- -D warnings` and `cargo test`.
- **`html_report_path`** *(optional, CLI `--html-report <path>`)*: Explicit opt-in path. Only when `html_report_path` is provided does `verify_rust_parity` emit an Antigravity `generative_ui` HTML parity dashboard (`scaffolded_crate.dashboard_html_path`; otherwise `null`).
- **`scaffolded_crate` Telemetry**: Returns `{ output_dir, cargo_toml_path, lib_rs_path, regression_test_path, dashboard_html_path, rust_edition: "2024", zero_drift_lints_enforced: true }` when `scaffold_output_dir` is supplied (or `null` otherwise).

---

## 3. Tri-Platform OS Sandboxing

Untrusted native C binaries are never executed directly in the MCP server process. `verify_rust_parity` isolates the FFI harness executable inside an OS-native sandbox:

1. **Linux (`linux-bwrap+prlimit` / `linux-prlimit`)**: `bwrap` (Bubblewrap unprivileged user/network/PID namespaces with `--unshare-all`, `--ro-bind`, `--tmpfs /tmp`, `--die-with-parent`) + `prlimit` address-space and CPU time caps.
2. **macOS (`darwin-sandbox-exec`)**: `/usr/bin/sandbox-exec` with an ephemeral Seatbelt `(version 1) (deny default) (deny network*)` profile + `ulimit` resource caps.
3. **Windows (`win32-job-object`)**: Win32 Job Object (`JOB_OBJECT_LIMIT_ACTIVE_PROCESS`, `JOB_OBJECT_LIMIT_PROCESS_MEMORY`, `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) with timeout enforcement.

---

## 4. Telemetry & Counterexample Shrinker Output

Every `verify_rust_parity` call returns structured JSON telemetry (`rustParityReportSchema`):

```json
{
  "status": "verified_bit_exact",
  "symbol_name": "rotl32",
  "rust_fn_name": "rotl32",
  "harness_mode": "native-rustc",
  "arg_types": ["u32", "u32"],
  "return_type": "u32",
  "iterations_requested": 10000,
  "iterations_completed": 10000,
  "boundary_cases_tested": 17,
  "seed": 1337420,
  "float_ulp_tolerance": 0,
  "counterexample": null,
  "memory_safety": {
    "forbid_unsafe_enforced": true,
    "candidate_unsafe_blocks": 0
  },
  "benchmark_telemetry": {
    "benchmark_iterations": 100000,
    "c_oracle_total_ns": 1842000,
    "safe_rust_total_ns": 1421000,
    "c_oracle_ns_per_call": 18.42,
    "safe_rust_ns_per_call": 14.21,
    "speedup_vs_c_oracle": 1.3
  },
  "sandbox_telemetry": {
    "os_platform": "linux",
    "isolation_backend": "linux-bwrap+prlimit",
    "cpu_limit_seconds": 10,
    "memory_limit_mb": 512,
    "wall_time_ms": 185,
    "exit_code": 0,
    "signal": null,
    "timed_out": false,
    "compiler_diagnostics": null
  },
  "scaffolded_crate": {
    "output_dir": "/path/to/workspace/rotl32_rs",
    "cargo_toml_path": "/path/to/workspace/rotl32_rs/Cargo.toml",
    "lib_rs_path": "/path/to/workspace/rotl32_rs/src/lib.rs",
    "regression_test_path": "/path/to/workspace/rotl32_rs/tests/parity_regression.rs",
    "dashboard_html_path": null,
    "rust_edition": "2024",
    "zero_drift_lints_enforced": true
  }
}
```

### Debugging `"diverged"` Counterexamples
When a semantic discrepancy is detected (`status: "diverged"`), `verify_rust_parity` automatically runs its deterministic **Minimal Counterexample Shrinker** (coordinate-wise binary-searching scalar magnitudes toward `0` and truncating byte slices across `shrink_steps`) and populates `counterexample`:
- `failing_iteration`: 0-based index of the first diverging test vector (`iterations_completed` equals `failing_iteration + 1`).
- `original_inputs` vs. `shrunk_inputs` (`shrink_steps`): Raw inputs that triggered the mismatch vs. minimal inputs that still reproduce it (e.g., `["0", "32"]` exposing an unmasked shift), plus the number of successful shrinking reductions.
- `c_output` / `rust_output` & `c_output_hex` / `rust_output_hex`: Exact decimal and hex outputs.
- `bit_diff_summary`: XOR bitmask and differing bit indices (e.g., `"XOR diff = 0x80000000 (1 bit(s) differ, lowest bit = 31, highest bit = 31); C returned 0x80000000 (...), Rust returned 0x00000000 (...)"`).
- `ulp_distance`: Exact Units in the Last Place distance for `f32`/`f64` outputs, or `null` for integer/boolean return types.
