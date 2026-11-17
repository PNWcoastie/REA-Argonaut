import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { ADAPTIVE_RESOURCE_PROFILE } from "../../config/AdaptiveResourceProfile.js";
import { verifyRustParityInputSchema } from "../../domain/rustParity/rustParity.js";
import { cleanRustSourceForSafeCrate } from "./CrateScaffolder.js";
import { RustParityVerifier } from "./RustParityVerifier.js";

function resolveCargoBin(): string {
  const exeName = os.platform() === "win32" ? "cargo.exe" : "cargo";
  const candidates = [
    path.join(os.homedir(), ".cargo", "bin", exeName),
    "/usr/bin/cargo",
    "/usr/local/bin/cargo",
  ];
  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  return "cargo";
}

async function runCargoCommand(
  args: readonly string[],
  cwd: string,
  timeoutMs = 60_000,
): Promise<{
  readonly exitCode: number | null;
  readonly stdout: string;
  readonly stderr: string;
}> {
  const cargoBin = resolveCargoBin();
  const buildJobs = String(
    Math.max(1, Math.min(2, ADAPTIVE_RESOURCE_PROFILE.maxCargoJobs)),
  );
  return await new Promise((resolve, reject) => {
    const child = spawn(cargoBin, [...args], {
      cwd,
      env: {
        ...process.env,
        CARGO_BUILD_JOBS: buildJobs,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(
        new Error(
          `cargo ${args.join(" ")} timed out after ${timeoutMs}ms\n${stderr}`,
        ),
      );
    }, timeoutMs);
    child.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ exitCode: code, stdout, stderr });
    });
  });
}

describe("CrateScaffolder (Rust 2024 / 1.100 Zero-Drift Crate Scaffolding)", () => {
  it("normalizes #[no_mangle], #[unsafe(no_mangle)], #![forbid(unsafe_code)], and extern \"C\" fn", () => {
    const raw = `
#![forbid(unsafe_code)]

#[unsafe(no_mangle)]
pub extern "C" fn sample_kernel(x: u32) -> u32 {
    x.wrapping_add(1)
}
`;
    const cleaned = cleanRustSourceForSafeCrate(raw, "sample_kernel");
    expect(cleaned).not.toContain("#![forbid(unsafe_code)]");
    expect(cleaned).not.toContain("no_mangle");
    expect(cleaned).not.toContain('extern "C"');
    expect(cleaned).toContain("pub fn sample_kernel(x: u32) -> u32");

    const bareExtern = `#[no_mangle]\nextern "C" fn helper_op(v: i32) -> i32 { v }`;
    expect(cleanRustSourceForSafeCrate(bareExtern, "helper_op")).toBe(
      "pub fn helper_op(v: i32) -> i32 { v }",
    );
  });

  it(
    "scaffolds a Rust 2024 zero-drift crate with remediated sibling code that passes clippy -D warnings and cargo test",
    async () => {
      const tmpRoot = await mkdtemp(
        path.join(os.tmpdir(), "argon-crate-scaffold-"),
      );
      const scaffoldDir = path.join(tmpRoot, "verified_checksum_crate");

      try {
        const verifier = new RustParityVerifier();
        const input = verifyRustParityInputSchema.parse({
          c_source_code: `
#include <stdint.h>
uint32_t compute_packet_checksum(uint32_t seed, uint32_t length) {
    return (seed * 2654435761u) ^ (length + 0x9e3779b9u);
}
`,
          rust_source_code: `
#![forbid(unsafe_code)]
#[no_mangle]
pub extern "C" fn compute_packet_checksum(seed: u32, length: u32) -> u32 {
    seed.wrapping_mul(2654435761u32) ^ length.wrapping_add(0x9e37_79b9u32)
}
`,
          remediated_rust_source_code: `
#![forbid(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn compute_packet_checksum_remediated(seed: u32, length: u32) -> u32 {
    seed.saturating_mul(2654435761u32) ^ length.saturating_add(0x9e37_79b9u32)
}
`,
          symbol_name: "compute_packet_checksum",
          arg_types: ["u32", "u32"],
          return_type: "u32",
          iterations: 50,
          scaffold_output_dir: scaffoldDir,
        });

        const result = await verifier.verify(input);
        expect(result.ok, result.ok ? "" : result.error.message).toBe(true);
        if (!result.ok) return;

        const report = result.value;
        expect(report.status).toBe("verified_bit_exact");
        expect(report.scaffolded_crate).not.toBeNull();
        expect(report.scaffolded_crate?.rust_edition).toBe("2024");
        expect(report.scaffolded_crate?.zero_drift_lints_enforced).toBe(true);

        const cargoToml = await readFile(
          path.join(scaffoldDir, "Cargo.toml"),
          "utf8",
        );
        expect(cargoToml).toContain('edition = "2024"');
        expect(cargoToml).toContain('rust-version = "1.100"');
        expect(cargoToml).toContain("[lints.rust]");
        expect(cargoToml).toContain('unsafe_code = "forbid"');
        expect(cargoToml).toContain("[lints.cargo]");
        expect(cargoToml).toContain('unused_dependencies = "warn"');
        expect(cargoToml).toContain("[lints.clippy]");
        expect(cargoToml).toContain('unwrap_used = "deny"');
        expect(cargoToml).toContain('expect_used = "deny"');
        expect(cargoToml).toContain('todo = "deny"');
        expect(cargoToml).toContain('unimplemented = "deny"');
        expect(cargoToml).toContain('dbg_macro = "deny"');

        const libRs = await readFile(
          path.join(scaffoldDir, "src/lib.rs"),
          "utf8",
        );
        expect(libRs).toContain("#![forbid(unsafe_code)]");
        expect(libRs.match(/#!\s*\[\s*forbid\s*\(\s*unsafe_code\s*\)\s*\]/g)).toHaveLength(1);
        expect(libRs).toContain("pub fn compute_packet_checksum(");
        expect(libRs).toContain(
          "// --- Remediated Implementation (Defects Eliminated) ---",
        );
        expect(libRs).toContain("pub fn compute_packet_checksum_remediated(");
        expect(libRs).not.toContain("#[no_mangle]");
        expect(libRs).not.toContain("#[unsafe(no_mangle)]");
        expect(libRs).not.toContain('extern "C"');

        const clippyRes = await runCargoCommand(
          ["clippy", "--all-targets", "--", "-D", "warnings"],
          scaffoldDir,
          60_000,
        );
        expect(clippyRes.exitCode, clippyRes.stderr).toBe(0);

        const testRes = await runCargoCommand(["test"], scaffoldDir, 60_000);
        expect(testRes.exitCode, testRes.stderr).toBe(0);
      } finally {
        await rm(tmpRoot, { recursive: true, force: true });
      }
    },
    90_000,
  );

  it(
    "emits clippy-clean bool regression assertions without bool_assert_comparison warnings",
    async () => {
      const tmpRoot = await mkdtemp(
        path.join(os.tmpdir(), "argon-crate-bool-"),
      );
      const scaffoldDir = path.join(tmpRoot, "bool_crate");

      try {
        const verifier = new RustParityVerifier();
        const input = verifyRustParityInputSchema.parse({
          c_source_code: `
#include <stdbool.h>
#include <stdint.h>
bool is_aligned_packet(uint32_t offset) {
    return (offset & 0x0fu) == 0u;
}
`,
          rust_source_code: `
#[no_mangle]
pub extern "C" fn is_aligned_packet(offset: u32) -> bool {
    (offset & 0x0f) == 0
}
`,
          symbol_name: "is_aligned_packet",
          arg_types: ["u32"],
          return_type: "bool",
          iterations: 50,
          scaffold_output_dir: scaffoldDir,
        });

        const result = await verifier.verify(input);
        expect(result.ok, result.ok ? "" : result.error.message).toBe(true);
        if (!result.ok) return;

        expect(result.value.status).toBe("verified_bit_exact");

        const regressionRs = await readFile(
          path.join(scaffoldDir, "tests/parity_regression.rs"),
          "utf8",
        );
        expect(regressionRs).not.toMatch(/assert_eq!\([^;]+,\s*(true|false)\s*\)/);
        expect(regressionRs).toContain("assert!(");

        const clippyRes = await runCargoCommand(
          ["clippy", "--all-targets", "--", "-D", "warnings"],
          scaffoldDir,
          60_000,
        );
        expect(clippyRes.exitCode, clippyRes.stderr).toBe(0);

        const testRes = await runCargoCommand(["test"], scaffoldDir, 60_000);
        expect(testRes.exitCode, testRes.stderr).toBe(0);
      } finally {
        await rm(tmpRoot, { recursive: true, force: true });
      }
    },
    90_000,
  );

  it(
    "emits clippy-clean float regression assertions using to_bits() comparisons",
    async () => {
      const tmpRoot = await mkdtemp(
        path.join(os.tmpdir(), "argon-crate-float-"),
      );
      const scaffoldDir = path.join(tmpRoot, "float_crate");

      try {
        const verifier = new RustParityVerifier();
        const input = verifyRustParityInputSchema.parse({
          c_source_code: `
double mix_gain_f64(double sample, double gain) {
    return sample * gain;
}
`,
          rust_source_code: `
pub extern "C" fn mix_gain_f64(sample: f64, gain: f64) -> f64 {
    sample * gain
}
`,
          symbol_name: "mix_gain_f64",
          arg_types: ["f64_finite", "f64_finite"],
          return_type: "f64",
          iterations: 50,
          scaffold_output_dir: scaffoldDir,
        });

        const result = await verifier.verify(input);
        expect(result.ok, result.ok ? "" : result.error.message).toBe(true);
        if (!result.ok) return;

        expect(result.value.status).toBe("verified_bit_exact");

        const regressionRs = await readFile(
          path.join(scaffoldDir, "tests/parity_regression.rs"),
          "utf8",
        );
        expect(regressionRs).toContain("actual.to_bits() == expected.to_bits()");
        expect(regressionRs).not.toContain("actual == 0.0");

        const clippyRes = await runCargoCommand(
          ["clippy", "--all-targets", "--", "-D", "warnings"],
          scaffoldDir,
          60_000,
        );
        expect(clippyRes.exitCode, clippyRes.stderr).toBe(0);

        const testRes = await runCargoCommand(["test"], scaffoldDir, 60_000);
        expect(testRes.exitCode, testRes.stderr).toBe(0);
      } finally {
        await rm(tmpRoot, { recursive: true, force: true });
      }
    },
    90_000,
  );
});
