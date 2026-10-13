# REA-Argonaut (`ArgonZeroG`) — Antigravity 2.0 Plugin

> **Zero-G Reverse Engineering Anything & Sandboxed Closed-Loop Safe Rust Verifier for Gemini 4 Argon and Google Antigravity 2.0**

This directory contains the canonical **Google Antigravity 2.0 Plugin** bundle for **`REA-Argonaut`** (`rea-argonaut`), registered via [`.agents/plugins.json`](../../.agents/plugins.json).

## Bundle Contents

- [`plugin.json`](./plugin.json) — Canonical Antigravity 2.0 plugin manifest (`name`, `displayName`, `version`, `description`, `logo`, `suggestedPrompts`, `disabled`).
- [`mcp_config.json`](./mcp_config.json) — Registers the `rea-argonaut-mcp` server (`193` reverse-engineering and verification tools across `39` domains).
- [`assets/logo.svg`](./assets/logo.svg) — `256x256` transparent SVG emblem with `>=10%` safe margin for light and dark UI themes.
- [`rules/AGENTS.md`](./rules/AGENTS.md) — Always-on operational rules enforcing single-call `decompile_subgraph` extraction, `#![forbid(unsafe_code)]` Safe Rust reconstruction, `verify_rust_parity` closed-loop verification, and hardware-adaptive scaling.
- [`skills/rea-argonaut/SKILL.md`](./skills/rea-argonaut/SKILL.md) — Full `ArgonZeroG` skill playbook including the **4-Stage Continuous Modernization Pipeline** (Subgraph `latent_hazards` Audit -> `#![forbid(unsafe_code)]` Dual AoS/SoA Safe Rust Port -> `10,000+` Seed `verify_rust_parity` Crucible & Speedup Staircase -> Interactive HTML Executive Scorecard).

## License

MIT License — see root [`LICENSE`](../../LICENSE) and [`README.md`](../../README.md).
