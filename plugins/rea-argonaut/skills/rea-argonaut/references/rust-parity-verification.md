# Sandboxed Safe Rust Parity Verification (`verify_rust_parity`)

## 1. Overview: Proving Bit-Exact Equivalence Without `unsafe`

LLM-generated decompilation translations frequently introduce subtle integer overflow, sign-extension, shift-masking, or floating-point rounding bugs. `verify_rust_parity` eliminates guesswork by compiling the candidate Rust code with `#![forbid(unsafe_code)]` and executing property-based differential fuzzing (`proptest`) against the original native C/C++ symbol inside an OS-level sandbox.

---

## 2. Input Schema & Modes

### Mode A: Direct Native Binary FFI (`target_binary_path`)
Loads a compiled shared library or position-independent executable (`.so` on Linux, `.dylib` on macOS, `.dll` on Windows) directly via `libloading`.
- **PIE Executable Support**: If `target_binary_path` is an ELF PIE executable (`ET_DYN` with `DF_1_PIE` set in `.dynamic`), Mach-O executable (`MH_EXECUTE`), or PE executable, `ParityVerifier` automatically patches a temporary copy in the sandbox directory (stripping `DF_1_PIE` / patching `MH_DYLIB` / setting `IMAGE_FILE_DLL`) so `dlopen`/`LoadLibrary` can resolve exported symbols directly.

```json
{
  "target_binary_path": "/lib/x86_64-linux-gnu/libz.so.1",
  "symbol_name": "crc32",
  "rust_source_code": "pub fn crc32(crc: u64, buf: &[u8]) -> u64 { ... }",
  "rust_fn_name": "crc32",
  "arg_types": ["u64", "bytes_len"],
  "return_type": "u64",
  "iterations": 500,
  "seed": 1337,
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
  "iterations": 500,
  "seed": 42,
  "forbid_unsafe": true
}
```

### Supported `arg_types` & `return_type`
- **Scalar Integers**: `"i8"`, `"u8"`, `"i16"`, `"u16"`, `"i32"`, `"u32"`, `"i64"`, `"u64"`, `"usize"`, `"bool"`
- **Floating Point**: `"f32"`, `"f64"` (supports configurable `float_ulp_tolerance`, default `0`)
- **Buffer Slices (`arg_types` only)**: `"bytes_len"` — passes `(const uint8_t* ptr, size_t len)` to the C ABI symbol while passing a safe `&[u8]` slice to the Rust candidate function!

---

## 3. Tri-Platform OS Sandboxing (`ParitySandboxRunner`)

Untrusted native C binaries are never executed directly in the MCP server process. `ParitySandboxRunner` isolates the runner executable inside an OS-native container:

1. **Linux**: `bwrap` (Bubblewrap unprivileged user/network/PID namespaces with `--unshare-all`, `--ro-bind /usr /usr`, `--ro-bind /lib /lib`, `--tmpfs /tmp`, `--die-with-parent`) + `prlimit` (`--as=536870912` 512 MB address space cap, `--cpu=10` seconds, `--nproc=32`).
2. **macOS**: `/usr/bin/sandbox-exec` with an ephemeral Seatbelt `(version 1) (deny default) (deny network*)` profile + `ulimit` resource caps.
3. **Windows**: `WindowsJobProcess.ts` Win32 Job Object (`JOB_OBJECT_LIMIT_ACTIVE_PROCESS`, `JOB_OBJECT_LIMIT_PROCESS_MEMORY`, `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) with restricted token privileges.

---

## 4. Telemetry & Counterexample Shrinker Output

Every `verify_rust_parity` call returns structured JSON telemetry:

```json
{
  "status": "verified_bit_exact",
  "symbol_name": "rotl32",
  "rust_fn_name": "rotl32",
  "harness_mode": "proptest_cargo",
  "iterations_completed": 500,
  "seed": 42,
  "memory_safety": {
    "forbid_unsafe_enforced": true,
    "candidate_unsafe_blocks": 0
  },
  "benchmark_telemetry": {
    "benchmark_iterations": 10000,
    "c_oracle_total_ns": 184200,
    "safe_rust_total_ns": 142100,
    "c_oracle_ns_per_call": 18.42,
    "safe_rust_ns_per_call": 14.21,
    "speedup_vs_c_oracle": 1.3
  },
  "sandbox_telemetry": {
    "platform": "linux",
    "mechanism": "bwrap+prlimit",
    "isolation_active": true,
    "timed_out": false
  }
}
```

### Debugging `"diverged"` Counterexamples
When a semantic discrepancy is detected (`status: "diverged"`), `verify_rust_parity` automatically runs its deterministic **Minimal Counterexample Shrinker** (binary-searching scalar magnitudes toward `0` and truncating byte slices) and populates `counterexample`:
- `original_inputs`: The raw random inputs that first triggered the mismatch.
- `shrunk_inputs`: The minimal inputs that still reproduce the mismatch (e.g., `["0", "32"]` exposing an unmasked shift).
- `c_output` / `rust_output` & `c_output_hex` / `rust_output_hex`: Exact decimal and hex outputs.
- `bit_diff_summary`: XOR bitmask and differing bit indices (e.g., `"XOR=0x80000000 (1 bit differs: [31]); sign bit mismatch"`).
- `ulp_distance`: Exact Units in the Last Place distance for `f32`/`f64` outputs.
