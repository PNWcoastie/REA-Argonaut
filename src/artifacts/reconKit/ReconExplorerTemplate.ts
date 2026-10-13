import path from "node:path";
import type {
  ReconHarnessKind,
  ReconHarnessRecommendation,
  ReconHardwareRegisterItem,
  ReconKitReport,
  ReconMountKind,
  ReconSubsystemEntry,
  ReconUiPreviewItem,
} from "../../domain/reconKit/reconKit.js";

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) {
    return "0 B";
  }
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  const kb = bytes / 1024;
  if (kb < 1024) {
    return `${kb.toFixed(1)} KiB`;
  }
  const mb = kb / 1024;
  if (mb < 1024) {
    return `${mb.toFixed(2)} MiB`;
  }
  const gb = mb / 1024;
  return `${gb.toFixed(2)} GiB`;
}

function formatMountLabel(mount: ReconMountKind): string {
  switch (mount) {
    case "native-binary":
      return "Mount 1: Native Binary";
    case "packaged-ui-archive":
      return "Mount 2: Packaged UI/Archive";
    case "hardware-firmware-protocol":
      return "Mount 3: Hardware/Firmware";
    case "ai-model-data":
      return "Mount 4: AI/Data";
  }
}

function formatHarnessLabel(harnessId: ReconHarnessKind): string {
  switch (harnessId) {
    case "verified-safe-rust-port":
      return "Harness 1: Verified Safe Rust Port";
    case "clean-room-app-ui-rebuild":
      return "Harness 2: Clean-Room App/UI Rebuild";
    case "hardware-hal-protocol-replay":
      return "Harness 3: Hardware HAL & Protocol Replay";
    case "security-hazard-audit":
      return "Harness 4: Security Hazard Audit";
  }
}

function renderUiConceptMockCard(item: ReconUiPreviewItem): string {
  const kindLabelMap: Record<ReconUiPreviewItem["asset_kind"], string> = {
    "html-view": "View / Route Surface",
    stylesheet: "Theme & Layout Tokens",
    "script-module": "State & Controller Logic",
    "svg-or-image": "Vector / Bitmap Asset",
    "scene-or-prefab": "Engine Scene / Prefab Hierarchy",
    "pe-dialog-or-icon": "Native Win32 Dialog / Icon Resource",
    "config-manifest": "Application Manifest & Routing",
  };

  let wireframePreview = "";
  switch (item.asset_kind) {
    case "html-view":
    case "pe-dialog-or-icon":
      wireframePreview = `<div class="bg-[var(--sidebar)] border border-[var(--border)] rounded-lg p-3 space-y-2">
        <div class="flex items-center justify-between border-b border-[var(--border)] pb-2">
          <span class="text-xs font-mono font-semibold text-[var(--foreground)]">${escapeHtml(path.basename(item.logical_path))}</span>
          <div class="flex gap-1.5">
            <span class="w-2.5 h-2.5 rounded-full bg-[var(--border)]"></span>
            <span class="w-2.5 h-2.5 rounded-full bg-[var(--border)]"></span>
            <span class="w-2.5 h-2.5 rounded-full bg-[var(--primary)]"></span>
          </div>
        </div>
        <div class="grid grid-cols-3 gap-2 pt-1">
          <div class="col-span-1 bg-[var(--card)] border border-[var(--border)] rounded p-2 text-xs text-[var(--muted-foreground)]">Nav / Tree</div>
          <div class="col-span-2 bg-[var(--card)] border border-[var(--border)] rounded p-2 text-xs text-[var(--foreground)]">Primary Viewport Surface</div>
        </div>
      </div>`;
      break;
    case "scene-or-prefab":
      wireframePreview = `<div class="bg-[var(--sidebar)] border border-[var(--border)] rounded-lg p-3 space-y-1.5 font-mono text-xs">
        <div class="text-[var(--accent)] font-semibold">SceneRoot &bull; ${escapeHtml(path.basename(item.logical_path))}</div>
        <div class="pl-3 text-[var(--muted-foreground)]">&vdash; CameraRig / Viewport2D</div>
        <div class="pl-3 text-[var(--muted-foreground)]">&vdash; UIOverlayCanvas &amp; HUD</div>
        <div class="pl-3 text-[var(--muted-foreground)]">&boxur; InteractiveControllerNode</div>
      </div>`;
      break;
    case "stylesheet":
      wireframePreview = `<div class="bg-[var(--sidebar)] border border-[var(--border)] rounded-lg p-3 flex items-center gap-2">
        <span class="w-5 h-5 rounded bg-[var(--primary)] border border-[var(--border)]"></span>
        <span class="w-5 h-5 rounded bg-[var(--secondary)] border border-[var(--border)]"></span>
        <span class="w-5 h-5 rounded bg-[var(--accent)] border border-[var(--border)]"></span>
        <span class="text-xs font-mono text-[var(--muted-foreground)] ml-1">Design System &amp; Layout Rules</span>
      </div>`;
      break;
    default:
      wireframePreview = `<div class="bg-[var(--sidebar)] border border-[var(--border)] rounded-lg p-3 font-mono text-xs text-[var(--muted-foreground)]">
        Asset Binding: <span class="text-[var(--foreground)]">${escapeHtml(item.logical_path)}</span>
      </div>`;
      break;
  }

  return `<div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-4 shadow-sm flex flex-col justify-between gap-3">
    <div class="space-y-2">
      <div class="flex flex-wrap items-center justify-between gap-2">
        <span class="bg-[var(--secondary)] text-[var(--secondary-foreground)] border border-[var(--border)] rounded px-2 py-0.5 text-xs font-mono">${escapeHtml(kindLabelMap[item.asset_kind])}</span>
        <span class="text-[var(--muted-foreground)] text-xs font-mono">${escapeHtml(formatBytes(item.size_bytes))}</span>
      </div>
      <h4 class="text-[var(--foreground)] font-semibold text-sm font-mono break-all">${escapeHtml(item.logical_path)}</h4>
      <p class="text-[var(--muted-foreground)] text-xs">${escapeHtml(item.summary)}</p>
    </div>
    ${wireframePreview}
  </div>`;
}

function renderSubsystemCard(subsystem: ReconSubsystemEntry): string {
  const samplePills =
    subsystem.sample_items.length > 0
      ? subsystem.sample_items
          .map(
            (item) =>
              `<span class="inline-block bg-[var(--secondary)] text-[var(--secondary-foreground)] border border-[var(--border)] rounded-md px-2 py-0.5 text-xs font-mono">${escapeHtml(item)}</span>`,
          )
          .join("\n")
      : `<span class="text-[var(--muted-foreground)] text-xs italic">No sample symbols recorded</span>`;

  const kitPathsHtml =
    subsystem.kit_relative_paths.length > 0
      ? subsystem.kit_relative_paths
          .map(
            (relPath) =>
              `<code class="inline-block bg-[var(--sidebar)] text-[var(--foreground)] border border-[var(--border)] rounded px-2 py-0.5 text-xs font-mono">${escapeHtml(relPath)}</code>`,
          )
          .join("\n")
      : `<span class="text-[var(--muted-foreground)] text-xs italic">RECON_BLUEPRINT.md</span>`;

  const harnessBadgesHtml = subsystem.recommended_harnesses
    .map(
      (harnessId) =>
        `<span class="inline-flex items-center bg-[var(--primary)] text-[var(--primary-foreground)] rounded-md px-2.5 py-1 text-xs font-medium">${escapeHtml(formatHarnessLabel(harnessId))}</span>`,
    )
    .join("\n");

  return `<div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-5 shadow-sm flex flex-col justify-between gap-4">
    <div>
      <div class="flex flex-wrap items-start justify-between gap-2 mb-2">
        <div>
          <h3 class="text-[var(--foreground)] font-semibold text-base">${escapeHtml(subsystem.name)}</h3>
          <p class="text-[var(--muted-foreground)] text-xs font-mono">id: ${escapeHtml(subsystem.id)}</p>
        </div>
        <span class="bg-[var(--secondary)] text-[var(--secondary-foreground)] border border-[var(--border)] rounded-full px-3 py-1 text-xs font-medium">${escapeHtml(formatMountLabel(subsystem.mount))}</span>
      </div>
      <p class="text-[var(--muted-foreground)] text-sm mb-4">${escapeHtml(subsystem.summary)}</p>

      <div class="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-4">
        <div class="bg-[var(--sidebar)] border border-[var(--border)] rounded-lg p-2.5">
          <div class="text-[var(--muted-foreground)] text-xs">Classes / Types</div>
          <div class="text-[var(--foreground)] font-semibold text-sm font-mono">${subsystem.class_count}</div>
        </div>
        <div class="bg-[var(--sidebar)] border border-[var(--border)] rounded-lg p-2.5">
          <div class="text-[var(--muted-foreground)] text-xs">Functions / Methods</div>
          <div class="text-[var(--foreground)] font-semibold text-sm font-mono">${subsystem.function_or_method_count}</div>
        </div>
        <div class="bg-[var(--sidebar)] border border-[var(--border)] rounded-lg p-2.5">
          <div class="text-[var(--muted-foreground)] text-xs">Files / Entries</div>
          <div class="text-[var(--foreground)] font-semibold text-sm font-mono">${subsystem.file_or_resource_count}</div>
        </div>
        <div class="bg-[var(--sidebar)] border border-[var(--border)] rounded-lg p-2.5">
          <div class="text-[var(--muted-foreground)] text-xs">Hazards</div>
          <div class="text-[var(--foreground)] font-semibold text-sm font-mono">${subsystem.hazard_count}</div>
        </div>
      </div>

      <div class="mb-3">
        <div class="text-[var(--muted-foreground)] text-xs font-medium uppercase tracking-wider mb-1.5">Representative Symbols / Entities</div>
        <div class="flex flex-wrap gap-1.5">${samplePills}</div>
      </div>

      <div class="mb-3">
        <div class="text-[var(--muted-foreground)] text-xs font-medium uppercase tracking-wider mb-1.5">Materialized recon-kit/ Artifacts</div>
        <div class="flex flex-wrap gap-1.5">${kitPathsHtml}</div>
      </div>
    </div>

    <div class="pt-3 border-t border-[var(--border)] flex flex-wrap items-center justify-between gap-2">
      <span class="text-[var(--muted-foreground)] text-xs font-medium">Compatible Harnesses:</span>
      <div class="flex flex-wrap gap-2">${harnessBadgesHtml}</div>
    </div>
  </div>`;
}

function renderHarnessReferenceCard(harness: ReconHarnessRecommendation): string {
  const inputPills =
    harness.kit_inputs.length > 0
      ? harness.kit_inputs
          .map(
            (inputPath) =>
              `<code class="bg-[var(--sidebar)] text-[var(--foreground)] border border-[var(--border)] rounded px-2 py-0.5 text-xs font-mono">${escapeHtml(inputPath)}</code>`,
          )
          .join("\n")
      : `<span class="text-[var(--muted-foreground)] text-xs">RECON_BLUEPRINT.md</span>`;

  return `<div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-5 shadow-sm space-y-3">
    <div class="flex flex-wrap items-start justify-between gap-2">
      <div>
        <span class="text-[var(--accent)] text-xs font-mono uppercase tracking-wider">${escapeHtml(harness.harness_id)}</span>
        <h3 class="text-[var(--foreground)] font-semibold text-base mt-0.5">${escapeHtml(harness.title)}</h3>
      </div>
      <span class="bg-[var(--secondary)] text-[var(--secondary-foreground)] border border-[var(--border)] rounded-full px-3 py-1 text-xs font-medium">${escapeHtml(formatMountLabel(harness.mount))}</span>
    </div>
    <p class="text-[var(--muted-foreground)] text-sm">${escapeHtml(harness.rationale)}</p>
    <div>
      <div class="text-[var(--muted-foreground)] text-xs font-medium uppercase tracking-wider mb-1">recon-kit/ Inputs</div>
      <div class="flex flex-wrap gap-1.5">${inputPills}</div>
    </div>
  </div>`;
}

function renderHardwareRegisterRow(item: ReconHardwareRegisterItem): string {
  return `<tr class="border-b border-[var(--border)]">
    <td class="py-2.5 px-4 font-mono text-xs font-semibold text-[var(--foreground)]">${escapeHtml(item.name)}</td>
    <td class="py-2.5 px-4 font-mono text-xs text-[var(--accent)]">${escapeHtml(item.address_or_offset)}</td>
    <td class="py-2.5 px-4 font-mono text-xs text-[var(--muted-foreground)]">${item.width_bits}-bit</td>
    <td class="py-2.5 px-4 font-mono text-xs">
      <span class="bg-[var(--secondary)] text-[var(--secondary-foreground)] border border-[var(--border)] rounded px-2 py-0.5 text-xs">${escapeHtml(item.access)}</span>
    </td>
    <td class="py-2.5 px-4 text-sm text-[var(--muted-foreground)]">${escapeHtml(item.description)}</td>
  </tr>`;
}

/**
 * Renders the opt-in Antigravity `generative_ui`-compliant static visual
 * UI Concept & Architecture Mockup (`RECON_EXPLORER.html`) when `mock_ui_concepts: true`.
 *
 * Strictly adheres to Antigravity design principles:
 * - Uses `https://www.gstatic.com/antigravity/web/dev/tailwindcss.min.js`
 * - Uses injected host theme variables (`--background`, `--card`, `--foreground`, `--muted-foreground`, `--border`, `--primary`)
 * - Zero `:root` overrides, `>= 12px` (`text-xs`) typography
 * - Purely visual/static layout so it never competes with Antigravity's native `ask_question` tool.
 */
export function renderReconExplorerHtml(
  report: Omit<ReconKitReport, "explorer_html_path">,
): string {
  const targetFileName = path.basename(report.target_path);

  const mountPillsHtml = report.detected_mounts
    .map((mount) => {
      const isPrimary = mount === report.primary_mount;
      const badgeClass = isPrimary
        ? "bg-[var(--primary)] text-[var(--primary-foreground)] font-semibold"
        : "bg-[var(--secondary)] text-[var(--secondary-foreground)] border border-[var(--border)] font-medium";
      return `<span class="${badgeClass} rounded-full px-3 py-1 text-xs">${escapeHtml(formatMountLabel(mount))}${isPrimary ? " (Primary)" : ""}</span>`;
    })
    .join("\n");

  const uiMockCardsHtml =
    report.ui_preview_items.length > 0
      ? report.ui_preview_items
          .map((item) => renderUiConceptMockCard(item))
          .join("\n")
      : `<div class="bg-[var(--sidebar)] border border-[var(--border)] rounded-xl p-5 text-sm text-[var(--muted-foreground)]">
          No Mount 2 packaged UI views, stylesheets, scenes, or dialog resources were detected in this target. The clean-room architecture mockup below reflects the recovered native/firmware/AI subsystems.
        </div>`;

  const subsystemCardsHtml =
    report.subsystems.length > 0
      ? report.subsystems.map((sub) => renderSubsystemCard(sub)).join("\n")
      : `<div class="bg-[var(--card)] border border-[var(--border)] rounded-xl p-6 text-sm text-[var(--muted-foreground)]">No subsystems discovered for this artifact.</div>`;

  const harnessCardsHtml =
    report.harnesses.length > 0
      ? report.harnesses.map((h) => renderHarnessReferenceCard(h)).join("\n")
      : "";

  const hardwareSectionHtml =
    report.hardware_or_protocol_items.length > 0
      ? `<section class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-5 shadow-sm overflow-x-auto space-y-3">
          <div>
            <h2 class="text-[var(--foreground)] font-semibold text-lg">Mount 3 — Hardware Peripheral Register &amp; Protocol Map (${report.hardware_or_protocol_items.length})</h2>
            <p class="text-[var(--muted-foreground)] text-xs">Recovered memory-mapped I/O (MMIO) registers, SVD/DeviceTree nodes, and protocol frame layouts.</p>
          </div>
          <table class="w-full text-left border-collapse">
            <thead>
              <tr class="border-b border-[var(--border)] text-[var(--muted-foreground)] text-xs uppercase tracking-wider">
                <th class="py-2.5 px-4">Register / Field</th>
                <th class="py-2.5 px-4">Address / Offset</th>
                <th class="py-2.5 px-4">Width</th>
                <th class="py-2.5 px-4">Access</th>
                <th class="py-2.5 px-4">Description</th>
              </tr>
            </thead>
            <tbody>
              ${report.hardware_or_protocol_items.map((item) => renderHardwareRegisterRow(item)).join("\n")}
            </tbody>
          </table>
        </section>`
      : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>ArgonZeroG UI Concept &amp; Architecture Mockup — ${escapeHtml(targetFileName)}</title>
  <script src="https://www.gstatic.com/antigravity/web/dev/tailwindcss.min.js"></script>
</head>
<body class="bg-[var(--background)] text-[var(--foreground)] antialiased p-6">
  <div class="max-w-7xl mx-auto space-y-6">
    <!-- Header Banner -->
    <div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-6 shadow-sm">
      <div class="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div class="space-y-1.5">
          <div class="flex flex-wrap items-center gap-2">
            <span class="bg-[var(--secondary)] text-[var(--secondary-foreground)] border border-[var(--border)] rounded-md px-2.5 py-1 text-xs font-mono font-semibold uppercase">${escapeHtml(report.detected_format)}</span>
            ${mountPillsHtml}
          </div>
          <h1 class="text-[var(--foreground)] font-bold text-2xl tracking-tight">${escapeHtml(targetFileName)} — UI Concept &amp; Architecture Mockup</h1>
          <p class="text-[var(--muted-foreground)] text-xs font-mono break-all">Target: ${escapeHtml(report.target_path)}</p>
        </div>

        <div class="bg-[var(--sidebar)] border border-[var(--border)] rounded-lg p-3.5 space-y-1 text-xs font-mono">
          <div><span class="text-[var(--muted-foreground)]">SHA-256:</span> <span class="text-[var(--foreground)]">${escapeHtml(report.sha256)}</span></div>
          <div><span class="text-[var(--muted-foreground)]">Size:</span> <span class="text-[var(--foreground)]">${escapeHtml(formatBytes(report.size_bytes))} (${report.size_bytes} bytes)</span></div>
          <div><span class="text-[var(--muted-foreground)]">Kit Dir:</span> <span class="text-[var(--foreground)]">${escapeHtml(report.output_dir)}</span></div>
          <div><span class="text-[var(--muted-foreground)]">Blueprint:</span> <span class="text-[var(--foreground)]">${escapeHtml(report.blueprint_path)}</span></div>
        </div>
      </div>
    </div>

    <!-- KPI Summary Cards -->
    <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
      <div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-4 shadow-sm">
        <div class="text-[var(--muted-foreground)] text-xs font-medium uppercase tracking-wider">Subsystems</div>
        <div class="text-[var(--foreground)] font-bold text-2xl mt-1 font-mono">${report.summary_metrics.total_subsystems}</div>
        <div class="text-[var(--muted-foreground)] text-xs mt-1">Clustered architectural domains</div>
      </div>
      <div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-4 shadow-sm">
        <div class="text-[var(--muted-foreground)] text-xs font-medium uppercase tracking-wider">Classes / Types</div>
        <div class="text-[var(--foreground)] font-bold text-2xl mt-1 font-mono">${report.summary_metrics.total_classes_or_types}</div>
        <div class="text-[var(--muted-foreground)] text-xs mt-1">Recovered C++/Rust/VM types</div>
      </div>
      <div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-4 shadow-sm">
        <div class="text-[var(--muted-foreground)] text-xs font-medium uppercase tracking-wider">Functions / Methods</div>
        <div class="text-[var(--foreground)] font-bold text-2xl mt-1 font-mono">${report.summary_metrics.total_functions_or_methods}</div>
        <div class="text-[var(--muted-foreground)] text-xs mt-1">Procedures &amp; vtable slots</div>
      </div>
      <div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-4 shadow-sm">
        <div class="text-[var(--muted-foreground)] text-xs font-medium uppercase tracking-wider">Files / Entries</div>
        <div class="text-[var(--foreground)] font-bold text-2xl mt-1 font-mono">${report.summary_metrics.total_files_or_entries}</div>
        <div class="text-[var(--muted-foreground)] text-xs mt-1">Archive, tensor &amp; HAL entries</div>
      </div>
      <div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-4 shadow-sm">
        <div class="text-[var(--muted-foreground)] text-xs font-medium uppercase tracking-wider">Materialized Files</div>
        <div class="text-[var(--foreground)] font-bold text-2xl mt-1 font-mono">${report.summary_metrics.total_materialized_files}</div>
        <div class="text-[var(--muted-foreground)] text-xs mt-1">Written to recon-kit/</div>
      </div>
      <div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-4 shadow-sm">
        <div class="text-[var(--muted-foreground)] text-xs font-medium uppercase tracking-wider">Latent Hazards</div>
        <div class="text-[var(--foreground)] font-bold text-2xl mt-1 font-mono">${report.summary_metrics.total_hazards}</div>
        <div class="text-[var(--muted-foreground)] text-xs mt-1">Memory &amp; arithmetic hazards</div>
      </div>
    </div>

    <!-- Visual UI Concept Mockup Wireframes -->
    <section class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-6 shadow-sm space-y-4">
      <div class="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--border)] pb-3">
        <div>
          <h2 class="text-[var(--foreground)] font-semibold text-lg">Extracted UI Concept &amp; Surface Wireframes (${report.ui_preview_items.length})</h2>
          <p class="text-[var(--muted-foreground)] text-sm">Visual concept mockup of discovered views, stylesheets, scripts, icons/SVGs, scenes, and native dialogs for clean-room UI reconstruction.</p>
        </div>
        <span class="bg-[var(--primary)] text-[var(--primary-foreground)] rounded-md px-3 py-1 text-xs font-semibold">Generative UI Concept Mock</span>
      </div>
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        ${uiMockCardsHtml}
      </div>
    </section>

    <!-- Architectural Subsystem & Module Overview Cards -->
    <section class="space-y-4">
      <div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-5 shadow-sm">
        <h2 class="text-[var(--foreground)] font-semibold text-lg">Architectural Subsystems &amp; Recovered Modules (${report.subsystems.length})</h2>
        <p class="text-[var(--muted-foreground)] text-sm mt-0.5">Clustered subsystem hierarchy extracted into <code class="font-mono text-xs">recon-kit/</code>. Use Antigravity's native <code class="font-mono text-xs">ask_question</code> prompt to select which subsystem and engineering harness to execute next.</p>
      </div>
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
        ${subsystemCardsHtml}
      </div>
    </section>

    ${hardwareSectionHtml}

    <!-- Available Engineering Harnesses Overview -->
    <section class="space-y-4">
      <div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-5 shadow-sm">
        <h2 class="text-[var(--foreground)] font-semibold text-lg">Available Recon-to-Argon Engineering Harnesses (${report.harnesses.length})</h2>
        <p class="text-[var(--muted-foreground)] text-sm mt-0.5">Reference summary of the 4 engineering tracks selectable via Antigravity's native <code class="font-mono text-xs">ask_question</code> workflow.</p>
      </div>
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
        ${harnessCardsHtml}
      </div>
    </section>
  </div>
</body>
</html>
`;
}
