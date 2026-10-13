import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { ReconKitExporter } from "./ReconKitExporter.js";

function buildSyntheticElfWithMsvcRtti(rttiSymbols: readonly string[]): Buffer {
  const rttiPayload = Buffer.from(
    rttiSymbols.map((s) => `\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0${s}\0`).join(""),
    "latin1",
  );
  const totalSize = Math.max(256, 128 + rttiPayload.length);
  const buf = Buffer.alloc(totalSize, 0);

  // ELF64 little-endian header
  buf[0] = 0x7f;
  buf[1] = 0x45; // 'E'
  buf[2] = 0x4c; // 'L'
  buf[3] = 0x46; // 'F'
  buf[4] = 2; // EI_CLASS = 64-bit
  buf[5] = 1; // EI_DATA = little-endian
  buf[6] = 1; // EI_VERSION = 1
  buf.writeUInt16LE(2, 16); // e_type = ET_EXEC
  buf.writeUInt16LE(62, 18); // e_machine = EM_X86_64
  buf.writeUInt32LE(1, 20); // e_version = 1

  rttiPayload.copy(buf, 128);
  return buf;
}

function buildSyntheticAsarArchive(): Buffer {
  const pkgBytes = Buffer.from(
    JSON.stringify({
      name: "argon-workbench-ui",
      version: "2.4.0",
      main: "src/main.js",
    }),
    "utf8",
  );
  const htmlBytes = Buffer.from(
    "<!DOCTYPE html><html><head><title>App</title></head><body><div id='root'></div></body></html>",
    "utf8",
  );
  const jsBytes = Buffer.from(
    "const { ipcRenderer } = require('electron'); ipcRenderer.invoke('app:init');",
    "utf8",
  );

  const headerObj = {
    files: {
      "package.json": {
        size: pkgBytes.length,
        offset: "0",
      },
      src: {
        files: {
          "index.html": {
            size: htmlBytes.length,
            offset: String(pkgBytes.length),
          },
          "main.js": {
            size: jsBytes.length,
            offset: String(pkgBytes.length + htmlBytes.length),
          },
        },
      },
    },
  };

  const jsonBuf = Buffer.from(JSON.stringify(headerObj), "utf8");
  const jsonLen = jsonBuf.length;
  const alignedJsonLen = Math.ceil(jsonLen / 4) * 4;
  const headerPayloadSize = alignedJsonLen + 4;
  const headerSize = headerPayloadSize + 4;

  const prefix = Buffer.alloc(16 + alignedJsonLen, 0);
  prefix.writeUInt32LE(4, 0);
  prefix.writeUInt32LE(headerSize, 4);
  prefix.writeUInt32LE(headerPayloadSize, 8);
  prefix.writeUInt32LE(jsonLen, 12);
  jsonBuf.copy(prefix, 16);

  return Buffer.concat([prefix, pkgBytes, htmlBytes, jsBytes]);
}

function writeGgufString(text: string): Buffer {
  const strBytes = Buffer.from(text, "utf8");
  const lenBuf = Buffer.alloc(8);
  lenBuf.writeBigUInt64LE(BigInt(strBytes.length), 0);
  return Buffer.concat([lenBuf, strBytes]);
}

function buildSyntheticGgufModel(systemPrompt: string): Buffer {
  const header = Buffer.alloc(24);
  header.write("GGUF", 0, 4, "ascii");
  header.writeUInt32LE(3, 4); // version 3
  header.writeBigUInt64LE(1n, 8); // tensor_count = 1
  header.writeBigUInt64LE(2n, 16); // metadata_kv_count = 2

  const kvArchKey = writeGgufString("general.architecture");
  const kvArchType = Buffer.alloc(4);
  kvArchType.writeUInt32LE(8, 0); // string
  const kvArchVal = writeGgufString("llama");

  const kvPromptKey = writeGgufString("tokenizer.chat_template");
  const kvPromptType = Buffer.alloc(4);
  kvPromptType.writeUInt32LE(8, 0); // string
  const kvPromptVal = writeGgufString(
    `{% for message in messages %}<|im_start|>system\n${systemPrompt}<|im_end|>{% endfor %}`,
  );

  // Tensor 0 descriptor: name, n_dims=2, dims=[64, 64], type=1 (F16), offset=0
  const tensorName = writeGgufString("blk.0.attn_q.weight");
  const tensorMeta = Buffer.alloc(4 + 8 + 8 + 4 + 8);
  tensorMeta.writeUInt32LE(2, 0); // n_dims = 2
  tensorMeta.writeBigUInt64LE(64n, 4);
  tensorMeta.writeBigUInt64LE(64n, 12);
  tensorMeta.writeUInt32LE(1, 20); // F16
  tensorMeta.writeBigUInt64LE(0n, 24); // offset 0

  return Buffer.concat([
    header,
    kvArchKey,
    kvArchType,
    kvArchVal,
    kvPromptKey,
    kvPromptType,
    kvPromptVal,
    tensorName,
    tensorMeta,
  ]);
}

describe("ReconKitExporter (Universal 4-Mount Recon Kit & Blueprint Engine)", () => {
  let tempDir = "";

  beforeEach(async () => {
    tempDir = await mkdtemp(path.join(os.tmpdir(), "argon-recon-kit-test-"));
  });

  afterEach(async () => {
    if (tempDir) {
      await rm(tempDir, { recursive: true, force: true });
    }
  });

  it("Mount 1 (native-binary): clusters C++ RTTI classes into subsystems and materializes #![forbid(unsafe_code)] Rust types, C headers, vtable JSON, blueprint, and explorer HTML", async () => {
    const binPath = path.join(tempDir, "generals_engine.elf");
    const outDir = path.join(tempDir, "generals-recon-kit");
    const elfBuf = buildSyntheticElfWithMsvcRtti([
      ".?AVFXList@@",
      ".?AVW3DShader@@",
      ".?AVXferCRC@@",
    ]);
    await writeFile(binPath, elfBuf);

    const exporter = new ReconKitExporter();
    const res = await exporter.exportKit({
      target_path: binPath,
      output_dir: outDir,
    });

    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const report = res.value;
    expect(report.primary_mount).toBe("native-binary");
    expect(report.detected_mounts).toContain("native-binary");
    expect(report.subsystems.length).toBeGreaterThanOrEqual(3);

    const blueprintStat = await stat(path.join(outDir, "RECON_BLUEPRINT.md"));
    expect(blueprintStat.isFile()).toBe(true);

    const explorerStat = await stat(path.join(outDir, "RECON_EXPLORER.html"));
    expect(explorerStat.isFile()).toBe(true);

    const rustTypes = await readFile(
      path.join(outDir, "types/recovered_types.rs"),
      "utf8",
    );
    expect(rustTypes).toContain("#![forbid(unsafe_code)]");
    expect(rustTypes).toContain("FXList");
    expect(rustTypes).toContain("W3DShader");
    expect(rustTypes).toContain("XferCRC");

    const cHeader = await readFile(
      path.join(outDir, "types/recovered_types.h"),
      "utf8",
    );
    expect(cHeader).toContain("#pragma once");
    expect(cHeader).toContain("FXList_Vtable");
    expect(cHeader).toContain("W3DShader_Vtable");
    expect(cHeader).toContain("XferCRC_Vtable");

    const vtableJsonRaw = await readFile(
      path.join(outDir, "classes/vtable_hierarchy.json"),
      "utf8",
    );
    const vtableHierarchy = JSON.parse(vtableJsonRaw) as {
      total_classes: number;
      classes: Array<{ class_name: string }>;
    };
    expect(vtableHierarchy.total_classes).toBeGreaterThanOrEqual(3);
    const classNames = vtableHierarchy.classes.map((c) => c.class_name);
    expect(classNames).toEqual(
      expect.arrayContaining(["FXList", "W3DShader", "XferCRC"]),
    );
  });

  it("Mount 2 (packaged-ui-archive): parses Electron .asar archive and materializes ui-preview/index.html, ui-preview/ui_inventory.json, scripts/module_inventory.md, and ipc_and_routes.md", async () => {
    const asarPath = path.join(tempDir, "app.asar");
    const outDir = path.join(tempDir, "asar-recon-kit");
    await writeFile(asarPath, buildSyntheticAsarArchive());

    const exporter = new ReconKitExporter();
    const res = await exporter.exportKit({
      target_path: asarPath,
      output_dir: outDir,
    });

    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const report = res.value;
    expect(report.primary_mount).toBe("packaged-ui-archive");
    expect(report.ui_preview_items.length).toBeGreaterThanOrEqual(3);

    const uiHtml = await readFile(
      path.join(outDir, "ui-preview/index.html"),
      "utf8",
    );
    expect(uiHtml).toContain("src/index.html");

    const uiInvRaw = await readFile(
      path.join(outDir, "ui-preview/ui_inventory.json"),
      "utf8",
    );
    const uiInv = JSON.parse(uiInvRaw) as {
      total_items: number;
      items: Array<{ logical_path: string }>;
    };
    expect(uiInv.total_items).toBeGreaterThanOrEqual(3);
    expect(uiInv.items.map((i) => i.logical_path)).toEqual(
      expect.arrayContaining(["package.json", "src/index.html", "src/main.js"]),
    );

    const modInv = await readFile(
      path.join(outDir, "scripts/module_inventory.md"),
      "utf8",
    );
    expect(modInv).toContain("src/main.js");

    const ipcRoutes = await readFile(
      path.join(outDir, "ipc_and_routes.md"),
      "utf8",
    );
    expect(ipcRoutes).toContain("src/main.js");
  });

  it("Mount 3 (hardware-firmware-protocol): parses SVD/MMIO definitions and materializes hardware/memory_and_mmio_map.md and #![forbid(unsafe_code)] hardware/register_hal.rs", async () => {
    const svdPath = path.join(tempDir, "stm32f4_usart.svd");
    const outDir = path.join(tempDir, "hw-recon-kit");
    const svdXml = `<?xml version="1.0" encoding="utf-8"?>
<device schemaVersion="1.1">
  <name>STM32F407</name>
  <peripherals>
    <peripheral>
      <name>USART1</name>
      <baseAddress>0x40011000</baseAddress>
      <registers>
        <register>
          <name>SR</name>
          <addressOffset>0x00</addressOffset>
          <size>32</size>
          <access>read-write</access>
          <description>Status register</description>
        </register>
        <register>
          <name>DR</name>
          <addressOffset>0x04</addressOffset>
          <size>32</size>
          <access>read-write</access>
          <description>Data register</description>
        </register>
      </registers>
    </peripheral>
  </peripherals>
</device>`;
    await writeFile(svdPath, svdXml, "utf8");

    const exporter = new ReconKitExporter();
    const res = await exporter.exportKit({
      target_path: svdPath,
      output_dir: outDir,
    });

    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const report = res.value;
    expect(report.primary_mount).toBe("hardware-firmware-protocol");
    expect(report.hardware_or_protocol_items.length).toBeGreaterThanOrEqual(2);

    const mmioMap = await readFile(
      path.join(outDir, "hardware/memory_and_mmio_map.md"),
      "utf8",
    );
    expect(mmioMap).toContain("USART1_SR");
    expect(mmioMap).toContain("0x40011000");

    const registerHal = await readFile(
      path.join(outDir, "hardware/register_hal.rs"),
      "utf8",
    );
    expect(registerHal).toContain("#![forbid(unsafe_code)]");
    expect(registerHal).toContain("USART1_SR_ADDR");
    expect(registerHal).toContain("USART1_DR_ADDR");
  });

  it("Mount 4 (ai-model-data): parses GGUF model with embedded system prompt and materializes ai/model_card_and_architecture.md and ai/extracted_system_prompts.txt", async () => {
    const ggufPath = path.join(tempDir, "argon_assistant.gguf");
    const outDir = path.join(tempDir, "ai-recon-kit");
    const embeddedPrompt =
      "You are ArgonZeroG, a deterministic binary reconstruction assistant.";
    await writeFile(ggufPath, buildSyntheticGgufModel(embeddedPrompt));

    const exporter = new ReconKitExporter();
    const res = await exporter.exportKit({
      target_path: ggufPath,
      output_dir: outDir,
    });

    expect(res.ok).toBe(true);
    if (!res.ok) return;

    const report = res.value;
    expect(report.primary_mount).toBe("ai-model-data");

    const modelCard = await readFile(
      path.join(outDir, "ai/model_card_and_architecture.md"),
      "utf8",
    );
    expect(modelCard).toContain("llama");
    expect(modelCard).toContain("gguf");

    const extractedPrompts = await readFile(
      path.join(outDir, "ai/extracted_system_prompts.txt"),
      "utf8",
    );
    expect(extractedPrompts).toContain(embeddedPrompt);
  });
});
