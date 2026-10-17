# Sandboxed Safe Rust Parity Verification (`verify_rust_parity`)

## 1. Overview: Proving Bit-Exact Equivalence Without `unsafe`

LLM-generated decompilation translations frequently introduce subtle integer overflow, sign-extension, shift-masking, or floating-point rounding bugs. `verify_rust_parity` eliminates guesswork by compiling the candidate Rust code with `#![forbid(unsafe_code)]` and executing property-based differential fuzzing (`10,000` SplitMix64 seeds + `64` deterministic boundary cases) against the original native C/C++ symbol inside an OS-level sandbox.

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

### Clean Cargo Crate Scaffolding (`scaffold_output_dir`) & Opt-In HTML Report (`html_report_path`)
- **`scaffold_output_dir` *(optional)***: When provided and `status === "verified_bit_exact"`, `verify_rust_parity` scaffolds a **100% pure `#![forbid(unsafe_code)]` Rust Cargo crate** (`Cargo.toml`, `src/lib.rs`, `tests/parity_regression.rs`) with zero HTML clutter by default.
- **`html_report_path` *(optional, CLI `--html-report <path>`)* **: Explicit opt-in path. Only when `html_report_path` is provided does `verify_rust_parity` emit an Antigravity `generative_ui` HTML parity dashboard (`scaffolded_crate.dashboard_html_path`).

---

## 3. Tri-Platform OS Sandboxing

Untrusted native C binaries are never executed directly in the MCP server process. `verify_rust_parity` isolates the FFI harness executable inside an OS-native sandbox:

1. **Linux (`linux-bwrap+prlimit` / `linux-prlimit`)**: `bwrap` (Bubblewrap unprivileged user/network/PID namespaces with `--unshare-all`, `--ro-bind`, `--tmpfs /tmp`, `--die-with-parent`) + `prlimit` address-space and CPU time caps.
2. **macOS (`darwin-sandbox-exec`)**: `/usr/bin/sandbox-exec` with an ephemeral Seatbelt `(version 1) (deny default) (deny network*)` profile + `ulimit` resource caps.
3. **Windows (`win32-job-object`)**: Win32 Job Object (`JOB_OBJECT_LIMIT_ACTIVE_PROCESS`, `JOB_OBJECT_LIMIT_PROCESS_MEMORY`, `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) with timeout enforcement.

---

## 4. Telemetry & Counterexample Shrinker Output

Every `verify_rust_parity` call returns structured JSON telemetry:

```json
{
  "status": "verified_bit_exact",
  "symbol_name": "rotl32",
  "rust_fn_name": "rotl32",
  "iterations_completed": 10064,
  "seed": 1337420,
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
    "isolation_backend": "linux-bwrap+prlimit",
    "cpu_limit_seconds": 10,
    "memory_limit_mb": 512,
    "wall_time_ms": 185
  }
}
```

### Debugging `"diverged"` Counterexamples
When a semantic discrepancy is detected (`status: "diverged"`), `verify_rust_parity` automatically runs its deterministic **Minimal Counterexample Shrinker** (coordinate-wise binary-searching scalar magnitudes toward `0` and truncating byte slices across `shrink_steps`) and populates `counterexample`:
- `failing_iteration`: Index of the first diverging test vector.
- `original_inputs`: The raw inputs that first triggered the mismatch.
- `shrunk_inputs`: The minimal inputs that still reproduce the mismatch (e.g., `["0", "32"]` exposing an unmasked shift).
- `c_output` / `rust_output` & `c_output_hex` / `rust_output_hex`: Exact decimal and hex outputs.
- `bit_diff_summary`: XOR bitmask and differing bit indices (e.g., `"XOR=0x80000000 (1 bit differs: [31]); sign bit mismatch"`).
- `ulp_distance`: Exact Units in the Last Place distance for `f32`/`f64` outputs.
