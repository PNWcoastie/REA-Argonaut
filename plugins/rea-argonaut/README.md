# REA-Argonaut (`ArgonZeroG`) — Antigravity 2.0 Plugin

> **Zero-G Reverse Engineering Anything & Sandboxed Closed-Loop Safe Rust Verifier for Gemini 4 Argon and Google Antigravity 2.0**

This directory contains the canonical **Google Antigravity 2.0 Plugin** bundle for **`REA-Argonaut`** (`rea-argonaut`), registered via [`.agents/plugins.json`](../../.agents/plugins.json).

## Bundle Contents

- [`plugin.json`](./plugin.json) — Canonical Antigravity 2.0 plugin manifest (`name`, `displayName`, `version`, `description`, `logo`, `suggestedPrompts`, `disabled`).
- [`mcp_config.json`](./mcp_config.json) — Registers the `rea-argonaut-mcp` server (`39` canonical reverse-engineering, 4-Mount recon kit, whole-subgraph, and verification MCP tools across `35` domains).
- [`assets/logo.svg`](./assets/logo.svg) — `256x256` transparent SVG emblem with `>=10%` safe margin for light and dark UI themes.
- [`rules/AGENTS.md`](./rules/AGENTS.md) — Always-on operational rules enforcing single-call `decompile_subgraph` extraction, `#![forbid(unsafe_code)]` Safe Rust reconstruction, `verify_rust_parity` closed-loop verification, the 4-Phase Recon-to-Argon Handoff (`export_recon_kit`), native `ask_question` decision controls, and hardware-adaptive scaling.
- [`agents/`](./agents/) — 4 domain-specialized Antigravity 2.0 subagents (`forensic-vertical-specialist`, `subgraph-architect`, `safe-rust-reconstructor`, `adversarial-parity-auditor`).
- [`skills/rea-argonaut/SKILL.md`](./skills/rea-argonaut/SKILL.md) — Full `ArgonZeroG` skill playbook including the **4-Phase Recon-to-Argon Handoff Workflow (`export_recon_kit`)** and the **4-Stage Continuous Modernization Pipeline** (`decompile_subgraph` -> `#![forbid(unsafe_code)]` Safe Rust Port -> `10,000+` Seed `verify_rust_parity` Crucible -> Executive Verification Scorecard).
- [`USER_GUIDE.md`](../../USER_GUIDE.md) — Visual Zero-to-Hero User Guide, 3-Stage Division of Labor Map, and 4-Mount / 4-Harness Decoder Ring.

## License

MIT License — see root [`LICENSE`](../../LICENSE) and [`README.md`](../../README.md).
