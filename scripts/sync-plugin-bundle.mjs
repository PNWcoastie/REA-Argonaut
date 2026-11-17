#!/usr/bin/env node

import {
  cpSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(SCRIPT_DIR, "..");
const CANONICAL_BUNDLE_ROOT = path.join(REPO_ROOT, "plugins", "rea-argonaut");

const SYNC_FILES = ["plugin.json", "mcp_config.json"];
const SYNC_DIRECTORIES = ["rules", "agents", "skills"];

function compareStrings(a, b) {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

function toPosixRelative(relPath) {
  return relPath.split(path.sep).join("/");
}

function collectDirectoryFiles(
  rootDir,
  currentDir = rootDir,
  out = new Map(),
) {
  const entries = readdirSync(currentDir, { withFileTypes: true });
  entries.sort((a, b) => compareStrings(a.name, b.name));

  for (const entry of entries) {
    const fullPath = path.join(currentDir, entry.name);
    const relPath = toPosixRelative(path.relative(rootDir, fullPath));
    if (entry.isDirectory()) {
      collectDirectoryFiles(rootDir, fullPath, out);
    } else if (entry.isFile()) {
      out.set(relPath, fullPath);
    } else if (entry.isSymbolicLink()) {
      const targetStat = statSync(fullPath);
      if (targetStat.isDirectory()) {
        collectDirectoryFiles(rootDir, fullPath, out);
      } else if (targetStat.isFile()) {
        out.set(relPath, fullPath);
      }
    }
  }

  return out;
}

function parseArgs(argv) {
  let checkOnly = false;
  let showHelp = false;

  for (const arg of argv) {
    if (arg === "--check") {
      checkOnly = true;
    } else if (arg === "--help" || arg === "-h") {
      showHelp = true;
    } else {
      throw new Error(
        `Unknown argument "${arg}". Usage: node scripts/sync-plugin-bundle.mjs [--check]`,
      );
    }
  }

  return { checkOnly, showHelp };
}

function compareFileBytes(canonicalPath, rootPath, displayPath, diffs) {
  const canonicalBytes = readFileSync(canonicalPath);
  const rootBytes = readFileSync(rootPath);
  if (!canonicalBytes.equals(rootBytes)) {
    diffs.push(`out of sync: ${displayPath}`);
  }
}

function checkFileEntry(relPath, diffs) {
  const canonicalPath = path.join(CANONICAL_BUNDLE_ROOT, relPath);
  const rootPath = path.join(REPO_ROOT, relPath);

  if (!existsSync(canonicalPath) || !statSync(canonicalPath).isFile()) {
    diffs.push(`missing canonical source file: plugins/rea-argonaut/${relPath}`);
    return 0;
  }

  if (!existsSync(rootPath)) {
    diffs.push(`missing in root: ${relPath}`);
    return 1;
  }

  if (!statSync(rootPath).isFile()) {
    diffs.push(`type mismatch in root (expected file): ${relPath}`);
    return 1;
  }

  compareFileBytes(canonicalPath, rootPath, relPath, diffs);
  return 1;
}

function checkDirectoryEntry(relDir, diffs) {
  const canonicalDir = path.join(CANONICAL_BUNDLE_ROOT, relDir);
  const rootDir = path.join(REPO_ROOT, relDir);

  if (!existsSync(canonicalDir) || !statSync(canonicalDir).isDirectory()) {
    diffs.push(
      `missing canonical source directory: plugins/rea-argonaut/${relDir}/`,
    );
    return 0;
  }

  const canonicalFiles = collectDirectoryFiles(canonicalDir);

  if (!existsSync(rootDir)) {
    diffs.push(`missing directory in root: ${relDir}/`);
    for (const relFile of canonicalFiles.keys()) {
      diffs.push(`missing in root: ${relDir}/${relFile}`);
    }
    return canonicalFiles.size;
  }

  if (!statSync(rootDir).isDirectory()) {
    diffs.push(`type mismatch in root (expected directory): ${relDir}/`);
    return canonicalFiles.size;
  }

  const rootFiles = collectDirectoryFiles(rootDir);
  const allRelFiles = [
    ...new Set([...canonicalFiles.keys(), ...rootFiles.keys()]),
  ];
  allRelFiles.sort(compareStrings);

  for (const relFile of allRelFiles) {
    const displayPath = `${relDir}/${relFile}`;
    const canonicalFile = canonicalFiles.get(relFile);
    const rootFile = rootFiles.get(relFile);

    if (canonicalFile === undefined) {
      diffs.push(`extra in root: ${displayPath}`);
      continue;
    }

    if (rootFile === undefined) {
      diffs.push(`missing in root: ${displayPath}`);
      continue;
    }

    compareFileBytes(canonicalFile, rootFile, displayPath, diffs);
  }

  return canonicalFiles.size;
}

function syncFileEntry(relPath) {
  const canonicalPath = path.join(CANONICAL_BUNDLE_ROOT, relPath);
  const rootPath = path.join(REPO_ROOT, relPath);

  if (!existsSync(canonicalPath) || !statSync(canonicalPath).isFile()) {
    throw new Error(
      `Canonical source file not found: plugins/rea-argonaut/${relPath}`,
    );
  }

  mkdirSync(path.dirname(rootPath), { recursive: true });
  if (existsSync(rootPath) && statSync(rootPath).isDirectory()) {
    rmSync(rootPath, { recursive: true, force: true });
  }
  cpSync(canonicalPath, rootPath, { force: true });
  return 1;
}

function syncDirectoryEntry(relDir) {
  const canonicalDir = path.join(CANONICAL_BUNDLE_ROOT, relDir);
  const rootDir = path.join(REPO_ROOT, relDir);

  if (!existsSync(canonicalDir) || !statSync(canonicalDir).isDirectory()) {
    throw new Error(
      `Canonical source directory not found: plugins/rea-argonaut/${relDir}/`,
    );
  }

  const canonicalFiles = collectDirectoryFiles(canonicalDir);
  rmSync(rootDir, { recursive: true, force: true });
  mkdirSync(rootDir, { recursive: true });
  cpSync(canonicalDir, rootDir, { recursive: true, force: true });
  return canonicalFiles.size;
}

function main() {
  const { checkOnly, showHelp } = parseArgs(process.argv.slice(2));
  if (showHelp) {
    process.stdout.write(
      "Usage: node scripts/sync-plugin-bundle.mjs [--check]\n",
    );
    return;
  }

  if (!existsSync(CANONICAL_BUNDLE_ROOT)) {
    throw new Error(
      "Canonical plugin bundle directory plugins/rea-argonaut/ does not exist.",
    );
  }

  if (checkOnly) {
    const diffs = [];
    let checkedFiles = 0;

    for (const relFile of SYNC_FILES) {
      checkedFiles += checkFileEntry(relFile, diffs);
    }
    for (const relDir of SYNC_DIRECTORIES) {
      checkedFiles += checkDirectoryEntry(relDir, diffs);
    }

    if (diffs.length > 0) {
      const diffLines = diffs.map((item) => `  - ${item}`).join("\n");
      process.stderr.write(
        `Plugin bundle out of sync with plugins/rea-argonaut/:\n${diffLines}\nRun "npm run sync:plugin" to synchronize.\n`,
      );
      process.exitCode = 1;
      return;
    }

    process.stdout.write(
      `Plugin bundle in sync with plugins/rea-argonaut/ (${checkedFiles} files verified).\n`,
    );
    return;
  }

  let syncedFiles = 0;
  for (const relFile of SYNC_FILES) {
    syncedFiles += syncFileEntry(relFile);
  }
  for (const relDir of SYNC_DIRECTORIES) {
    syncedFiles += syncDirectoryEntry(relDir);
  }

  process.stdout.write(
    `Synced ${syncedFiles} plugin bundle files from plugins/rea-argonaut/ to repository root.\n`,
  );
}

try {
  main();
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`sync-plugin-bundle error: ${message}\n`);
  process.exitCode = 1;
}
