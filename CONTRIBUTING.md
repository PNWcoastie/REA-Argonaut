# Contributing to REA-Argonaut (`ArgonZeroG`)

Thank you for your interest in contributing to **REA-Argonaut**!

## Core Architectural Principles

1. **Antigravity 2.0 Native Compliance:**
   - All plugin manifests (`plugin.json`, `plugins/rea-argonaut/plugin.json`), rules (`plugins/rea-argonaut/rules/AGENTS.md`), subagents (`plugins/rea-argonaut/agents/*.md`), and `generative_ui` templates are continuously verified by [`src/contracts/antigravityCompliance.test.ts`](src/contracts/antigravityCompliance.test.ts).
   - Never introduce unsolicited HTML files by default (`mock_ui_concepts: false`, `include_explorer_html: false`), and never emit `<button>` or `:root` CSS variable overrides in `generative_ui` artifacts.
2. **Hardware-Adaptive Concurrency:**
   - Never hardcode CPU core counts, thread limits, or machine-specific paths. Always scale via [`ADAPTIVE_RESOURCE_PROFILE`](src/config/AdaptiveResourceProfile.ts) (`os.availableParallelism()`, `os.totalmem()`).
3. **`#![forbid(unsafe_code)]` Safe Rust Standard:**
   - All reconstructed Rust code and parity templates must compile cleanly under `#![forbid(unsafe_code)]`.

## Development & Verification Workflow

```bash
# 1. Install dependencies
npm ci

# 2. Build the TypeScript MCP server and CLI
npm run build

# 3. Run the compliance and unit test suites
npx vitest run src/contracts/antigravityCompliance.test.ts src/artifacts/reconKit/ReconKitExporter.test.ts
```

## Submitting Pull Requests

1. Fork the repository and create a descriptive feature branch from `main`.
2. Ensure `npm run build` and the compliance test suite pass with zero errors.
3. Open a Pull Request targeting `main`. All Pull Requests are reviewed by `@PNWcoastie` before merging.
