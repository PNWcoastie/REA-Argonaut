import path from "node:path";
import type {
  ReconHarnessKind,
  ReconHarnessRecommendation,
  ReconHardwareRegisterItem,
  ReconKitReport,
  ReconMaterializedFile,
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
      : `<span class="text-[var(--muted-foreground)] text-xs italic">Root blueprint</span>`;

  const harnessBadgesHtml = subsystem.recommended_harnesses
    .map(
      (harnessId) =>
        `<button type="button" onclick="selectHarnessTrack('${escapeHtml(harnessId)}')" class="inline-flex items-center gap-1 bg-[var(--primary)] text-[var(--primary-foreground)] rounded-md px-2.5 py-1 text-xs font-medium hover:opacity-90 transition-opacity">${escapeHtml(formatHarnessLabel(harnessId))} &rarr;</button>`,
    )
    .join("\n");

  const searchBlob = [
    subsystem.id,
    subsystem.name,
    subsystem.mount,
    subsystem.summary,
    ...subsystem.sample_items,
    ...subsystem.kit_relative_paths,
  ]
    .join(" ")
    .toLowerCase();

  return `<div class="subsystem-card bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-5 shadow-sm flex flex-col justify-between gap-4" data-mount="${escapeHtml(subsystem.mount)}" data-search="${escapeHtml(searchBlob)}">
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
      <span class="text-[var(--muted-foreground)] text-xs font-medium">Recommended Harnesses:</span>
      <div class="flex flex-wrap gap-2">${harnessBadgesHtml}</div>
    </div>
  </div>`;
}

function renderHarnessCard(
  harness: ReconHarnessRecommendation,
  index: number,
): string {
  const targetPills =
    harness.target_subsystems.length > 0
      ? harness.target_subsystems
          .map(
            (sub) =>
              `<span class="bg-[var(--secondary)] text-[var(--secondary-foreground)] border border-[var(--border)] rounded px-2 py-0.5 text-xs font-mono">${escapeHtml(sub)}</span>`,
          )
          .join("\n")
      : `<span class="text-[var(--muted-foreground)] text-xs">All discovered subsystems</span>`;

  const inputPills =
    harness.kit_inputs.length > 0
      ? harness.kit_inputs
          .map(
            (inputPath) =>
              `<code class="bg-[var(--sidebar)] text-[var(--foreground)] border border-[var(--border)] rounded px-2 py-0.5 text-xs font-mono">${escapeHtml(inputPath)}</code>`,
          )
          .join("\n")
      : `<span class="text-[var(--muted-foreground)] text-xs">RECON_BLUEPRINT.md</span>`;

  const promptId = `argon-prompt-${index}`;
  const btnId = `copy-btn-${index}`;

  return `<div id="harness-card-${escapeHtml(harness.harness_id)}" class="harness-card bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-5 shadow-sm flex flex-col justify-between gap-4">
    <div>
      <div class="flex flex-wrap items-start justify-between gap-2 mb-2">
        <div>
          <span class="text-[var(--accent)] text-xs font-mono uppercase tracking-wider">${escapeHtml(harness.harness_id)}</span>
          <h3 class="text-[var(--foreground)] font-semibold text-lg mt-0.5">${escapeHtml(harness.title)}</h3>
        </div>
        <span class="bg-[var(--secondary)] text-[var(--secondary-foreground)] border border-[var(--border)] rounded-full px-3 py-1 text-xs font-medium">${escapeHtml(formatMountLabel(harness.mount))}</span>
      </div>

      <p class="text-[var(--muted-foreground)] text-sm mb-4">${escapeHtml(harness.rationale)}</p>

      <div class="mb-3">
        <div class="text-[var(--muted-foreground)] text-xs font-medium uppercase tracking-wider mb-1.5">Target Subsystems</div>
        <div class="flex flex-wrap gap-1.5">${targetPills}</div>
      </div>

      <div class="mb-3">
        <div class="text-[var(--muted-foreground)] text-xs font-medium uppercase tracking-wider mb-1.5">recon-kit/ Input Files</div>
        <div class="flex flex-wrap gap-1.5">${inputPills}</div>
      </div>

      <div class="mb-3">
        <div class="text-[var(--muted-foreground)] text-xs font-medium uppercase tracking-wider mb-1.5">Phase 4 Mathematical Verification Command</div>
        <pre class="bg-[var(--sidebar)] text-[var(--foreground)] border border-[var(--border)] rounded-lg p-3 text-xs font-mono overflow-x-auto"><code>${escapeHtml(harness.verification_command)}</code></pre>
      </div>

      <div>
        <div class="text-[var(--muted-foreground)] text-xs font-medium uppercase tracking-wider mb-1.5">Phase 3 Gemini 4 Argon Handoff Prompt</div>
        <pre id="${promptId}" class="bg-[var(--sidebar)] text-[var(--foreground)] border border-[var(--border)] rounded-lg p-3 text-xs font-mono whitespace-pre-wrap break-words">${escapeHtml(harness.argon_handoff_prompt)}</pre>
      </div>
    </div>

    <div class="pt-3 border-t border-[var(--border)] flex items-center justify-between gap-3">
      <span class="text-[var(--muted-foreground)] text-xs">Ready for Phase 3 Antigravity + Gemini 4 Argon execution</span>
      <button
        id="${btnId}"
        type="button"
        onclick="copyArgonPrompt('${promptId}', '${btnId}')"
        class="bg-[var(--primary)] text-[var(--primary-foreground)] rounded-lg px-4 py-2 text-xs font-semibold hover:opacity-90 transition-opacity"
      >
        Copy Argon Handoff Prompt
      </button>
    </div>
  </div>`;
}

function renderMaterializedFileRow(file: ReconMaterializedFile): string {
  const searchBlob = [
    file.relative_path,
    file.mount,
    file.category,
    file.description,
  ]
    .join(" ")
    .toLowerCase();

  return `<tr class="materialized-file-row border-b border-[var(--border)]" data-mount="${escapeHtml(file.mount)}" data-search="${escapeHtml(searchBlob)}">
    <td class="py-3 px-4 font-mono text-xs text-[var(--foreground)]">
      <div>${escapeHtml(file.relative_path)}</div>
      <div class="text-[var(--muted-foreground)] text-xs truncate max-w-md">${escapeHtml(file.absolute_path)}</div>
    </td>
    <td class="py-3 px-4 text-xs">
      <span class="bg-[var(--secondary)] text-[var(--secondary-foreground)] border border-[var(--border)] rounded-full px-2.5 py-0.5 text-xs font-medium">${escapeHtml(formatMountLabel(file.mount))}</span>
    </td>
    <td class="py-3 px-4 text-xs font-mono text-[var(--accent)]">${escapeHtml(file.category)}</td>
    <td class="py-3 px-4 text-xs font-mono text-[var(--muted-foreground)]">${escapeHtml(formatBytes(file.size_bytes))} (${file.size_bytes} B)</td>
    <td class="py-3 px-4 text-sm text-[var(--muted-foreground)]">${escapeHtml(file.description)}</td>
  </tr>`;
}

function renderUiPreviewRow(item: ReconUiPreviewItem): string {
  return `<tr class="border-b border-[var(--border)]">
    <td class="py-3 px-4 font-mono text-xs text-[var(--foreground)]">${escapeHtml(item.logical_path)}</td>
    <td class="py-3 px-4 text-xs">
      <span class="bg-[var(--secondary)] text-[var(--secondary-foreground)] border border-[var(--border)] rounded px-2 py-0.5 text-xs font-mono">${escapeHtml(item.asset_kind)}</span>
    </td>
    <td class="py-3 px-4 font-mono text-xs text-[var(--muted-foreground)]">${escapeHtml(formatBytes(item.size_bytes))}</td>
    <td class="py-3 px-4 text-sm text-[var(--muted-foreground)]">${escapeHtml(item.summary)}</td>
  </tr>`;
}

function renderHardwareRegisterRow(item: ReconHardwareRegisterItem): string {
  return `<tr class="border-b border-[var(--border)]">
    <td class="py-3 px-4 font-mono text-xs font-semibold text-[var(--foreground)]">${escapeHtml(item.name)}</td>
    <td class="py-3 px-4 font-mono text-xs text-[var(--accent)]">${escapeHtml(item.address_or_offset)}</td>
    <td class="py-3 px-4 font-mono text-xs text-[var(--muted-foreground)]">${item.width_bits}-bit</td>
    <td class="py-3 px-4 font-mono text-xs">
      <span class="bg-[var(--secondary)] text-[var(--secondary-foreground)] border border-[var(--border)] rounded px-2 py-0.5 text-xs">${escapeHtml(item.access)}</span>
    </td>
    <td class="py-3 px-4 text-sm text-[var(--muted-foreground)]">${escapeHtml(item.description)}</td>
  </tr>`;
}

/**
 * Renders the interactive Antigravity `generative_ui`-compliant `RECON_EXPLORER.html`
 * workbench for inspecting a 4-Mount `export_recon_kit` report and selecting an
 * engineering harness for Gemini 4 Argon handoff.
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

  const subsystemCardsHtml =
    report.subsystems.length > 0
      ? report.subsystems.map((sub) => renderSubsystemCard(sub)).join("\n")
      : `<div class="bg-[var(--card)] border border-[var(--border)] rounded-xl p-6 text-sm text-[var(--muted-foreground)]">No subsystems discovered for this artifact.</div>`;

  const harnessCardsHtml =
    report.harnesses.length > 0
      ? report.harnesses
          .map((harness, idx) => renderHarnessCard(harness, idx))
          .join("\n")
      : `<div class="bg-[var(--card)] border border-[var(--border)] rounded-xl p-6 text-sm text-[var(--muted-foreground)]">No engineering harnesses generated.</div>`;

  const materializedRowsHtml =
    report.materialized_files.length > 0
      ? report.materialized_files
          .map((file) => renderMaterializedFileRow(file))
          .join("\n")
      : `<tr><td colspan="5" class="py-4 px-4 text-sm text-[var(--muted-foreground)]">No materialized files recorded.</td></tr>`;

  const uiPreviewRowsHtml =
    report.ui_preview_items.length > 0
      ? report.ui_preview_items.map((item) => renderUiPreviewRow(item)).join("\n")
      : `<tr><td colspan="4" class="py-4 px-4 text-sm text-[var(--muted-foreground)]">No Mount 2 packaged UI/scene assets detected in this artifact.</td></tr>`;

  const hardwareRowsHtml =
    report.hardware_or_protocol_items.length > 0
      ? report.hardware_or_protocol_items
          .map((item) => renderHardwareRegisterRow(item))
          .join("\n")
      : `<tr><td colspan="5" class="py-4 px-4 text-sm text-[var(--muted-foreground)]">No Mount 3 peripheral registers or protocol frames detected in this artifact.</td></tr>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>ArgonZeroG Recon Explorer — ${escapeHtml(targetFileName)}</title>
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
          <h1 class="text-[var(--foreground)] font-bold text-2xl tracking-tight">${escapeHtml(targetFileName)}</h1>
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

    <!-- Interactive Navigation Bar + Global Search & Mount Filter -->
    <div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-4 shadow-sm space-y-4">
      <div class="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border)] pb-3">
        <div class="flex flex-wrap gap-2" role="tablist">
          <button
            id="tab-btn-subsystems"
            type="button"
            onclick="switchReconTab('subsystems')"
            class="recon-tab-btn bg-[var(--primary)] text-[var(--primary-foreground)] rounded-lg px-4 py-2 text-sm font-semibold transition-colors"
          >
            1. Subsystems &amp; Architecture (${report.subsystems.length})
          </button>
          <button
            id="tab-btn-harnesses"
            type="button"
            onclick="switchReconTab('harnesses')"
            class="recon-tab-btn bg-[var(--secondary)] text-[var(--secondary-foreground)] rounded-lg px-4 py-2 text-sm font-medium transition-colors"
          >
            2. Selectable Engineering Harnesses (${report.harnesses.length})
          </button>
          <button
            id="tab-btn-materialized_files"
            type="button"
            onclick="switchReconTab('materialized_files')"
            class="recon-tab-btn bg-[var(--secondary)] text-[var(--secondary-foreground)] rounded-lg px-4 py-2 text-sm font-medium transition-colors"
          >
            3. Materialized recon-kit/ Files (${report.materialized_files.length})
          </button>
          <button
            id="tab-btn-domain_previews"
            type="button"
            onclick="switchReconTab('domain_previews')"
            class="recon-tab-btn bg-[var(--secondary)] text-[var(--secondary-foreground)] rounded-lg px-4 py-2 text-sm font-medium transition-colors"
          >
            4. Domain Previews (${report.ui_preview_items.length + report.hardware_or_protocol_items.length})
          </button>
        </div>

        <div class="flex flex-wrap items-center gap-1.5">
          <span class="text-[var(--muted-foreground)] text-xs font-medium mr-1">Mount Filter:</span>
          <button type="button" onclick="setMountFilter('all')" data-mount-btn="all" class="mount-filter-btn bg-[var(--primary)] text-[var(--primary-foreground)] rounded-full px-3 py-1 text-xs font-semibold">All Mounts</button>
          <button type="button" onclick="setMountFilter('native-binary')" data-mount-btn="native-binary" class="mount-filter-btn bg-[var(--secondary)] text-[var(--secondary-foreground)] border border-[var(--border)] rounded-full px-3 py-1 text-xs font-medium">Mount 1: Native</button>
          <button type="button" onclick="setMountFilter('packaged-ui-archive')" data-mount-btn="packaged-ui-archive" class="mount-filter-btn bg-[var(--secondary)] text-[var(--secondary-foreground)] border border-[var(--border)] rounded-full px-3 py-1 text-xs font-medium">Mount 2: UI/Archive</button>
          <button type="button" onclick="setMountFilter('hardware-firmware-protocol')" data-mount-btn="hardware-firmware-protocol" class="mount-filter-btn bg-[var(--secondary)] text-[var(--secondary-foreground)] border border-[var(--border)] rounded-full px-3 py-1 text-xs font-medium">Mount 3: Hardware</button>
          <button type="button" onclick="setMountFilter('ai-model-data')" data-mount-btn="ai-model-data" class="mount-filter-btn bg-[var(--secondary)] text-[var(--secondary-foreground)] border border-[var(--border)] rounded-full px-3 py-1 text-xs font-medium">Mount 4: AI/Data</button>
        </div>
      </div>

      <div>
        <input
          id="recon-global-search"
          type="text"
          oninput="applyReconFilters()"
          placeholder="Search subsystems, C++ classes, virtual methods, recon-kit/ file paths, or descriptions..."
          class="w-full bg-[var(--sidebar)] text-[var(--foreground)] border border-[var(--border)] rounded-lg px-4 py-2.5 text-sm focus:outline-none"
        />
      </div>
    </div>

    <!-- Tab 1: Subsystems & Architecture -->
    <section id="tab-panel-subsystems" class="recon-tab-panel space-y-4">
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
        ${subsystemCardsHtml}
      </div>
    </section>

    <!-- Tab 2: Selectable Engineering Harnesses -->
    <section id="tab-panel-harnesses" class="recon-tab-panel hidden space-y-4">
      <div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-4 shadow-sm">
        <h2 class="text-[var(--foreground)] font-semibold text-base">Phase 2 &rarr; Phase 3 Recon-to-Argon Handoff Selection</h2>
        <p class="text-[var(--muted-foreground)] text-sm mt-1">Select one of the 4 Engineering Harnesses below and click <strong>Copy Argon Handoff Prompt</strong> to launch clean-room reconstruction or auditing directly from the materialized <code class="font-mono text-xs">recon-kit/</code> workspace without re-running decompilers.</p>
      </div>
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
        ${harnessCardsHtml}
      </div>
    </section>

    <!-- Tab 3: Materialized recon-kit/ Files -->
    <section id="tab-panel-materialized_files" class="recon-tab-panel hidden">
      <div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-5 shadow-sm overflow-x-auto">
        <h2 class="text-[var(--foreground)] font-semibold text-base mb-3">Materialized recon-kit/ Filesystem Artifacts</h2>
        <table class="w-full text-left border-collapse">
          <thead>
            <tr class="border-b border-[var(--border)] text-[var(--muted-foreground)] text-xs uppercase tracking-wider">
              <th class="py-3 px-4">Relative / Absolute Path</th>
              <th class="py-3 px-4">Mount</th>
              <th class="py-3 px-4">Category</th>
              <th class="py-3 px-4">Size</th>
              <th class="py-3 px-4">Description</th>
            </tr>
          </thead>
          <tbody>
            ${materializedRowsHtml}
          </tbody>
        </table>
      </div>
    </section>

    <!-- Tab 4: Domain Previews (UI Assets & Hardware/Protocol Maps) -->
    <section id="tab-panel-domain_previews" class="recon-tab-panel hidden space-y-6">
      <div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-5 shadow-sm overflow-x-auto">
        <h2 class="text-[var(--foreground)] font-semibold text-base mb-1">Mount 2 — Packaged UI, Scene &amp; Resource Preview (${report.ui_preview_items.length})</h2>
        <p class="text-[var(--muted-foreground)] text-xs mb-3">Extracted HTML views, stylesheets, scripts, scenes, prefabs, and PE dialog/icon descriptors.</p>
        <table class="w-full text-left border-collapse">
          <thead>
            <tr class="border-b border-[var(--border)] text-[var(--muted-foreground)] text-xs uppercase tracking-wider">
              <th class="py-3 px-4">Logical Path</th>
              <th class="py-3 px-4">Asset Kind</th>
              <th class="py-3 px-4">Size</th>
              <th class="py-3 px-4">Summary</th>
            </tr>
          </thead>
          <tbody>
            ${uiPreviewRowsHtml}
          </tbody>
        </table>
      </div>

      <div class="bg-[var(--card)] text-[var(--foreground)] border border-[var(--border)] rounded-xl p-5 shadow-sm overflow-x-auto">
        <h2 class="text-[var(--foreground)] font-semibold text-base mb-1">Mount 3 — Hardware Peripheral Registers &amp; Protocol Frames (${report.hardware_or_protocol_items.length})</h2>
        <p class="text-[var(--muted-foreground)] text-xs mb-3">Memory-mapped I/O (MMIO) register definitions, SVD/DeviceTree nodes, and protocol frame layouts.</p>
        <table class="w-full text-left border-collapse">
          <thead>
            <tr class="border-b border-[var(--border)] text-[var(--muted-foreground)] text-xs uppercase tracking-wider">
              <th class="py-3 px-4">Register / Field</th>
              <th class="py-3 px-4">Address / Offset</th>
              <th class="py-3 px-4">Width</th>
              <th class="py-3 px-4">Access</th>
              <th class="py-3 px-4">Description</th>
            </tr>
          </thead>
          <tbody>
            ${hardwareRowsHtml}
          </tbody>
        </table>
      </div>
    </section>
  </div>

  <script>
    let activeMountFilter = "all";

    function switchReconTab(tabId) {
      const panels = ["subsystems", "harnesses", "materialized_files", "domain_previews"];
      panels.forEach((id) => {
        const panel = document.getElementById("tab-panel-" + id);
        const btn = document.getElementById("tab-btn-" + id);
        if (panel) {
          if (id === tabId) {
            panel.classList.remove("hidden");
          } else {
            panel.classList.add("hidden");
          }
        }
        if (btn) {
          if (id === tabId) {
            btn.className = "recon-tab-btn bg-[var(--primary)] text-[var(--primary-foreground)] rounded-lg px-4 py-2 text-sm font-semibold transition-colors";
          } else {
            btn.className = "recon-tab-btn bg-[var(--secondary)] text-[var(--secondary-foreground)] rounded-lg px-4 py-2 text-sm font-medium transition-colors";
          }
        }
      });
    }

    function setMountFilter(mount) {
      activeMountFilter = mount;
      const buttons = document.querySelectorAll(".mount-filter-btn");
      buttons.forEach((btn) => {
        const btnMount = btn.getAttribute("data-mount-btn");
        if (btnMount === mount) {
          btn.className = "mount-filter-btn bg-[var(--primary)] text-[var(--primary-foreground)] rounded-full px-3 py-1 text-xs font-semibold";
        } else {
          btn.className = "mount-filter-btn bg-[var(--secondary)] text-[var(--secondary-foreground)] border border-[var(--border)] rounded-full px-3 py-1 text-xs font-medium";
        }
      });
      applyReconFilters();
    }

    function applyReconFilters() {
      const input = document.getElementById("recon-global-search");
      const query = (input ? input.value : "").toLowerCase().trim();

      const subsystemCards = document.querySelectorAll(".subsystem-card");
      subsystemCards.forEach((card) => {
        const cardMount = card.getAttribute("data-mount") || "";
        const cardSearch = card.getAttribute("data-search") || "";
        const mountMatch = activeMountFilter === "all" || cardMount === activeMountFilter;
        const textMatch = !query || cardSearch.includes(query);
        card.style.display = mountMatch && textMatch ? "" : "none";
      });

      const fileRows = document.querySelectorAll(".materialized-file-row");
      fileRows.forEach((row) => {
        const rowMount = row.getAttribute("data-mount") || "";
        const rowSearch = row.getAttribute("data-search") || "";
        const mountMatch = activeMountFilter === "all" || rowMount === activeMountFilter;
        const textMatch = !query || rowSearch.includes(query);
        row.style.display = mountMatch && textMatch ? "" : "none";
      });
    }

    function selectHarnessTrack(harnessId) {
      switchReconTab("harnesses");
      const targetCard = document.getElementById("harness-card-" + harnessId);
      if (targetCard) {
        targetCard.scrollIntoView({ behavior: "smooth", block: "center" });
      }
    }

    function copyArgonPrompt(promptElementId, buttonElementId) {
      const promptEl = document.getElementById(promptElementId);
      const btnEl = document.getElementById(buttonElementId);
      if (!promptEl || !btnEl) return;
      const text = promptEl.textContent || "";

      const showCopiedState = () => {
        const originalText = btnEl.textContent;
        btnEl.textContent = "Copied Argon Prompt!";
        setTimeout(() => {
          btnEl.textContent = originalText;
        }, 2000);
      };

      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(showCopiedState).catch(() => {
          fallbackCopy(text, showCopiedState);
        });
      } else {
        fallbackCopy(text, showCopiedState);
      }
    }

    function fallbackCopy(text, onDone) {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand("copy");
      } catch (_err) {
        // Ignore clipboard errors in restricted frames
      }
      document.body.removeChild(ta);
      onDone();
    }
  </script>
</body>
</html>
`;
}
