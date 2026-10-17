import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { renderReconExplorerHtml } from "../artifacts/reconKit/ReconExplorerTemplate.js";
import {
  ADAPTIVE_RESOURCE_PROFILE,
  resolveAdaptiveResourceProfile,
} from "../config/AdaptiveResourceProfile.js";
import {
  exportReconKitInputSchema,
  type ReconKitReport,
} from "../domain/reconKit/reconKit.js";
import { TOOL_CONTRACTS } from "./toolContracts.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, "../..");

const ALLOWED_PLUGIN_MANIFEST_KEYS = new Set([
  "name",
  "displayName",
  "version",
  "description",
  "logo",
  "suggestedPrompts",
  "disabled",
]);

const BANNED_STALE_DRAFT_TOOL_NAMES = [
  "detect_packing_and_yara",
  "inspect_wasm_module",
  "inspect_jvm_dex",
  "inspect_ebpf_object",
  "inspect_firmware_blob",
  "inspect_python_bytecode",
  "inspect_dotnet_assembly",
  "inspect_solana_program",
  "inspect_evm_bytecode",
  "inspect_uefi_image",
  "inspect_media_shader",
  "inspect_network_capture",
  "inspect_retro_binary",
  "inspect_macho",
  "decompile_procedure",
  "disassemble_procedure",
  "get_cross_references",
  "extract_strings",
  "export_cfg",
  "close_session",
] as const;

function createSampleReconKitReport(): Omit<
  ReconKitReport,
  "explorer_html_path"
> {
  return {
    target_path: "/workspace/targets/sample_app.exe",
    sha256: "a".repeat(64),
    size_bytes: 131_072,
    detected_format: "PE32+ executable (x86-64)",
    detected_mounts: [
      "native-binary",
      "packaged-ui-archive",
      "hardware-firmware-protocol",
      "ai-model-data",
    ],
    primary_mount: "native-binary",
    output_dir: "/workspace/targets/sample_app-recon-kit",
    blueprint_path:
      "/workspace/targets/sample_app-recon-kit/RECON_BLUEPRINT.md",
    materialized_files: [
      {
        relative_path: "RECON_BLUEPRINT.md",
        absolute_path:
          "/workspace/targets/sample_app-recon-kit/RECON_BLUEPRINT.md",
        mount: "native-binary",
        category: "blueprint",
        size_bytes: 4096,
        description: "Master Universal 4-Mount Reverse-Engineering Blueprint",
      },
    ],
    subsystems: [
      {
        id: "core-engine",
        name: "Core Engine Subsystem",
        mount: "native-binary",
        summary: "Primary simulation loop and state serialization.",
        class_count: 12,
        function_or_method_count: 64,
        file_or_resource_count: 4,
        hazard_count: 2,
        sample_items: ["EngineRoot::tick", "XferArchive::serialize"],
        kit_relative_paths: [
          "types/recovered_types.rs",
          "classes/vtable_hierarchy.json",
        ],
        recommended_harnesses: ["verified-safe-rust-port"],
      },
    ],
    ui_preview_items: [
      {
        logical_path: "ui/views/MainWindow.html",
        asset_kind: "html-view",
        size_bytes: 2048,
        summary: "Main application viewport layout",
      },
      {
        logical_path: "ui/styles/theme.css",
        asset_kind: "stylesheet",
        size_bytes: 1024,
        summary: "Design system tokens",
      },
      {
        logical_path: "scenes/HudRoot.tscn",
        asset_kind: "scene-or-prefab",
        size_bytes: 1536,
        summary: "HUD scene hierarchy",
      },
    ],
    hardware_or_protocol_items: [
      {
        name: "DMA_CTRL_STATUS",
        address_or_offset: "0x40020000",
        width_bits: 32,
        access: "RW",
        description: "DMA channel control and transfer status register",
      },
    ],
    harnesses: [
      {
        harness_id: "verified-safe-rust-port",
        title: "Harness 1: Verified Safe Rust Port",
        mount: "native-binary",
        target_subsystems: ["Core Engine Subsystem"],
        rationale: "Port native C/C++ logic to #![forbid(unsafe_code)] Rust.",
        kit_inputs: ["types/recovered_types.rs"],
        argon_handoff_prompt:
          "Port Core Engine Subsystem to #![forbid(unsafe_code)] Safe Rust.",
        verification_command: "cargo test",
      },
    ],
    summary_metrics: {
      total_subsystems: 1,
      total_classes_or_types: 12,
      total_functions_or_methods: 64,
      total_files_or_entries: 4,
      total_hazards: 2,
      total_materialized_files: 1,
    },
  };
}

function assertGenerativeUiCompliantHtml(html: string, label: string): void {
  expect(
    html,
    `${label} must include allowlisted gstatic Tailwind script`,
  ).toContain("https://www.gstatic.com/antigravity/web/dev/tailwindcss.min.js");

  expect(html, `${label} must reference host var(--background)`).toContain(
    "var(--background)",
  );
  expect(html, `${label} must reference host var(--card)`).toContain(
    "var(--card)",
  );
  expect(html, `${label} must reference host var(--foreground)`).toContain(
    "var(--foreground)",
  );

  expect(
    /:\s*root\b/i.test(html),
    `${label} must not declare local color fallbacks on :root`,
  ).toBe(false);

  expect(
    /<button\b/i.test(html),
    `${label} must not contain <button> elements that compete with native ask_question`,
  ).toBe(false);

  expect(
    /\bonclick\s*=/i.test(html),
    `${label} must not contain inline onclick= handlers`,
  ).toBe(false);

  expect(
    /text-\[(10|11)px\]/.test(html),
    `${label} must not use sub-12px Tailwind classes (text-[10px] or text-[11px])`,
  ).toBe(false);

  expect(
    /font-size:\s*(10|11)px/i.test(html),
    `${label} must not use sub-12px CSS font-size declarations`,
  ).toBe(false);
}

describe("Antigravity 2.0 Native-Compliance 6-Pillar Audit Suite", () => {
  describe("Checkpoint 1 & 2 — Native Decision Controls & generative_ui Role Boundaries", () => {
    it("defaults mock_ui_concepts and include_explorer_html to false in exportReconKitInputSchema", () => {
      const parsed = exportReconKitInputSchema.parse({});
      expect(parsed.mock_ui_concepts).toBe(false);
      expect(parsed.include_explorer_html).toBe(false);
    });

    it("enforces generative_ui theming, typography >= 12px, and zero <button>/:root/onclick in renderReconExplorerHtml", () => {
      const sampleReport = createSampleReconKitReport();
      const html = renderReconExplorerHtml(sampleReport);
      assertGenerativeUiCompliantHtml(html, "renderReconExplorerHtml output");
    });

    it("enforces generative_ui theming, typography >= 12px, and zero <button>/:root/onclick in EXECUTIVE_SCORECARD.html", () => {
      const scorecardPath = path.join(
        REPO_ROOT,
        "examples/argon-zerog-showcase/EXECUTIVE_SCORECARD.html",
      );
      expect(existsSync(scorecardPath)).toBe(true);
      const html = readFileSync(scorecardPath, "utf8");
      assertGenerativeUiCompliantHtml(html, "EXECUTIVE_SCORECARD.html");
    });

    it("ensures ReconKitExporter.ts and RustParityVerifier.ts contain zero :root or <button elements in HTML templates", () => {
      const exporterSource = readFileSync(
        path.join(REPO_ROOT, "src/artifacts/reconKit/ReconKitExporter.ts"),
        "utf8",
      );
      const verifierSource = readFileSync(
        path.join(REPO_ROOT, "src/native/rustParity/RustParityVerifier.ts"),
        "utf8",
      );

      expect(/:\s*root\b/i.test(exporterSource)).toBe(false);
      expect(/<button\b/i.test(exporterSource)).toBe(false);

      expect(/:\s*root\b/i.test(verifierSource)).toBe(false);
      expect(/<button\b/i.test(verifierSource)).toBe(false);
    });
  });

  describe("Checkpoint 3 — Plugin Manifest & Canonical MCP Tool Schema Strictness", () => {
    const manifestLocations = [
      {
        label: "root plugin.json",
        manifestPath: path.join(REPO_ROOT, "plugin.json"),
        bundleDir: REPO_ROOT,
      },
      {
        label: "plugins/rea-argonaut/plugin.json",
        manifestPath: path.join(REPO_ROOT, "plugins/rea-argonaut/plugin.json"),
        bundleDir: path.join(REPO_ROOT, "plugins/rea-argonaut"),
      },
    ];

    for (const { label, manifestPath, bundleDir } of manifestLocations) {
      it(`validates ${label} against Antigravity plugin/SKILL.md schema`, () => {
        expect(existsSync(manifestPath)).toBe(true);
        const raw = readFileSync(manifestPath, "utf8");
        const parsed = JSON.parse(raw) as Record<string, unknown>;

        expect(parsed.name).toBe("rea-argonaut");

        for (const key of Object.keys(parsed)) {
          expect(
            ALLOWED_PLUGIN_MANIFEST_KEYS.has(key),
            `Disallowed top-level key "${key}" in ${label}`,
          ).toBe(true);
        }

        expect(parsed.logo).toBe("assets/logo.svg");
        const resolvedLogo = path.join(bundleDir, String(parsed.logo));
        expect(
          existsSync(resolvedLogo),
          `Logo at ${resolvedLogo} must exist on disk`,
        ).toBe(true);

        expect(Array.isArray(parsed.suggestedPrompts)).toBe(true);
        const prompts = parsed.suggestedPrompts as unknown[];
        expect(prompts.length).toBeGreaterThanOrEqual(1);
        expect(prompts.length).toBeLessThanOrEqual(3);
        for (const prompt of prompts) {
          expect(typeof prompt).toBe("string");
          expect((prompt as string).trim().length).toBeGreaterThan(0);
        }
      });
    }

    it("verifies all customization Markdown files contain 0 banned/stale draft MCP tool names and reference registered TOOL_CONTRACTS", () => {
      const registeredToolNames = new Set<string>(
        TOOL_CONTRACTS.map((contract) => contract.name),
      );
      expect(registeredToolNames.size).toBeGreaterThanOrEqual(190);
      expect(registeredToolNames.has("export_recon_kit")).toBe(true);
      expect(registeredToolNames.has("decompile_subgraph")).toBe(true);
      expect(registeredToolNames.has("verify_rust_parity")).toBe(true);

      const pluginBase = path.join(REPO_ROOT, "plugins/rea-argonaut");
      const referencesDir = path.join(
        pluginBase,
        "skills/rea-argonaut/references",
      );
      const agentsDir = path.join(pluginBase, "agents");

      const markdownFilesToScan: string[] = [
        path.join(pluginBase, "skills/rea-argonaut/SKILL.md"),
        path.join(pluginBase, "rules/AGENTS.md"),
        ...readdirSync(referencesDir)
          .filter((f) => f.endsWith(".md"))
          .map((f) => path.join(referencesDir, f)),
        ...readdirSync(agentsDir)
          .filter((f) => f.endsWith(".md"))
          .map((f) => path.join(agentsDir, f)),
      ];

      for (const filePath of markdownFilesToScan) {
        const content = readFileSync(filePath, "utf8");
        const relPath = path.relative(REPO_ROOT, filePath);
        for (const staleName of BANNED_STALE_DRAFT_TOOL_NAMES) {
          const regex = new RegExp(`\\b${staleName}\\b`, "g");
          const matches = content.match(regex) ?? [];
          expect(
            matches.length,
            `Found banned/stale draft tool "${staleName}" in ${relPath}`,
          ).toBe(0);
        }
      }
    });
  });

  describe("Checkpoint 4 — Subagent & Rule Frontmatter Conventions", () => {
    it("enforces plain markdown without YAML frontmatter and < 24,000 bytes on plugins/rea-argonaut/rules/AGENTS.md", () => {
      const rulesPath = path.join(
        REPO_ROOT,
        "plugins/rea-argonaut/rules/AGENTS.md",
      );
      expect(existsSync(rulesPath)).toBe(true);

      const content = readFileSync(rulesPath, "utf8");
      const byteLength = Buffer.byteLength(content, "utf8");
      const fileStat = statSync(rulesPath);

      expect(content.trimStart().startsWith("---")).toBe(false);
      expect(byteLength).toBeLessThan(24_000);
      expect(fileStat.size).toBeLessThan(24_000);
    });

    it("validates YAML frontmatter across all 4 subagents and ensures safe-rust-reconstructor.md quotes #![forbid(unsafe_code)]", () => {
      const agentsDir = path.join(REPO_ROOT, "plugins/rea-argonaut/agents");
      const agentFiles = readdirSync(agentsDir)
        .filter((f) => f.endsWith(".md"))
        .sort();

      expect(agentFiles).toEqual([
        "adversarial-parity-auditor.md",
        "forensic-vertical-specialist.md",
        "safe-rust-reconstructor.md",
        "subgraph-architect.md",
      ]);

      for (const fileName of agentFiles) {
        const fullPath = path.join(agentsDir, fileName);
        const content = readFileSync(fullPath, "utf8");
        const frontmatterMatch = content.match(/^---\r?\n([\s\S]*?)\r?\n---/);
        expect(
          frontmatterMatch,
          `${fileName} must start with YAML frontmatter`,
        ).not.toBeNull();

        const frontmatter = frontmatterMatch![1]!;
        const expectedSlug = fileName.replace(/\.md$/, "");
        expect(frontmatter).toMatch(new RegExp(`^name:\\s*${expectedSlug}\\b`, "m"));
        expect(frontmatter).toMatch(/^description:\s*.+/m);
        expect(frontmatter).toMatch(/^subagent:\s*true\b/m);

        if (fileName === "safe-rust-reconstructor.md") {
          const descLine = frontmatter
            .split(/\r?\n/)
            .find((line) => line.startsWith("description:"));
          expect(descLine).toBeDefined();
          const rawValue = descLine!.replace(/^description:\s*/, "").trim();
          expect(
            rawValue.startsWith('"') && rawValue.endsWith('"'),
            "safe-rust-reconstructor.md description must be double-quoted in YAML so #![forbid(unsafe_code)] is not truncated as a YAML comment",
          ).toBe(true);
          expect(rawValue).toContain("#![forbid(unsafe_code)]");
        }
      }
    });
  });

  describe("Checkpoint 5 — MCP Server Naming & Global Namespace Collision Safety", () => {
    it("enforces rea-argonaut prefixed mcpServers keys, text-only mode, and zero hardcoded local paths in mcp_config.json and settings.json.example", () => {
      const rootMcpConfigPath = path.join(REPO_ROOT, "mcp_config.json");
      const mcpConfigPath = path.join(
        REPO_ROOT,
        "plugins/rea-argonaut/mcp_config.json",
      );
      const settingsExamplePath = path.join(
        REPO_ROOT,
        ".gemini/settings.json.example",
      );

      for (const configPath of [
        rootMcpConfigPath,
        mcpConfigPath,
        settingsExamplePath,
      ]) {
        expect(existsSync(configPath)).toBe(true);
        const raw = readFileSync(configPath, "utf8");
        expect(raw).not.toContain(os.homedir());

        const parsed = JSON.parse(raw) as {
          mcpServers?: Record<
            string,
            { env?: Record<string, string>; command?: string; args?: string[] }
          >;
        };
        expect(parsed.mcpServers).toBeDefined();
        const serverKeys = Object.keys(parsed.mcpServers!);
        expect(serverKeys.length).toBeGreaterThan(0);

        for (const key of serverKeys) {
          expect(
            key.startsWith("rea-argonaut"),
            `MCP server key "${key}" in ${path.relative(REPO_ROOT, configPath)} must be prefixed with "rea-argonaut"`,
          ).toBe(true);
          const serverEntry = parsed.mcpServers![key]!;
          expect(serverEntry.env?.MCP_TOOL_RESULT_CONTENT_MODE).toBe(
            "text-only",
          );
        }
      }

      expect(readFileSync(rootMcpConfigPath, "utf8")).toBe(
        readFileSync(mcpConfigPath, "utf8"),
      );
      expect(readFileSync(path.join(REPO_ROOT, "rules/AGENTS.md"), "utf8")).toBe(
        readFileSync(
          path.join(REPO_ROOT, "plugins/rea-argonaut/rules/AGENTS.md"),
          "utf8",
        ),
      );
      expect(
        readFileSync(
          path.join(REPO_ROOT, "skills/rea-argonaut/SKILL.md"),
          "utf8",
        ),
      ).toBe(
        readFileSync(
          path.join(
            REPO_ROOT,
            "plugins/rea-argonaut/skills/rea-argonaut/SKILL.md",
          ),
          "utf8",
        ),
      );

      const pluginMcp = JSON.parse(readFileSync(mcpConfigPath, "utf8")) as {
        mcpServers: Record<string, unknown>;
      };
      expect(Object.keys(pluginMcp.mcpServers)).toContain("rea-argonaut-mcp");
    });
  });

  describe("Checkpoint 6 — Living Workspace Docs vs. Brain Artifacts & Hardware-Adaptive Portability", () => {
    it("verifies SKILL.md and rules/AGENTS.md document ask_question, mock_ui_concepts, and workspace RECON_BLUEPRINT.md placement", () => {
      const skillContent = readFileSync(
        path.join(REPO_ROOT, "plugins/rea-argonaut/skills/rea-argonaut/SKILL.md"),
        "utf8",
      );
      const rulesContent = readFileSync(
        path.join(REPO_ROOT, "plugins/rea-argonaut/rules/AGENTS.md"),
        "utf8",
      );

      for (const [label, text] of [
        ["SKILL.md", skillContent],
        ["rules/AGENTS.md", rulesContent],
      ] as const) {
        expect(text, `${label} must document ask_question`).toContain(
          "ask_question",
        );
        expect(text, `${label} must document mock_ui_concepts`).toContain(
          "mock_ui_concepts",
        );
        expect(text, `${label} must document RECON_BLUEPRINT.md`).toContain(
          "RECON_BLUEPRINT.md",
        );
        expect(text).not.toContain(os.homedir());
      }
    });

    it("verifies ADAPTIVE_RESOURCE_PROFILE scales dynamically and repository contains zero developer paths or field-test brand names", () => {
      const profile = resolveAdaptiveResourceProfile();
      expect(profile.logicalCores).toBeGreaterThanOrEqual(1);
      expect(profile.totalMemBytes).toBeGreaterThanOrEqual(512 * 1024 * 1024);
      expect(profile.workerConcurrency).toBeGreaterThanOrEqual(1);
      expect(profile.workerConcurrency).toBeLessThanOrEqual(16);
      expect(profile.maxCargoJobs).toBe(profile.workerConcurrency);
      expect(ADAPTIVE_RESOURCE_PROFILE.logicalCores).toBe(profile.logicalCores);

      const reconKitSrcDir = path.join(REPO_ROOT, "src/artifacts/reconKit");
      const files = readdirSync(reconKitSrcDir).filter((f) => f.endsWith(".ts"));
      expect(files.length).toBeGreaterThan(0);

      const bannedTerms = [
        "open" + "front",
        "cnc" + "3",
        "tiberium",
        "command and conquer",
        "generals_engine",
        "generals.exe",
        "w3dshader",
        "fxlist",
        "xfercrc",
      ];

      for (const file of files) {
        const content = readFileSync(path.join(reconKitSrcDir, file), "utf8");
        expect(content).not.toContain(os.homedir());
        const lower = content.toLowerCase();
        for (const term of bannedTerms) {
          expect(lower).not.toContain(term);
        }
      }
    });
  });
});
