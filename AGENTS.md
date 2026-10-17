# agent-pool — agent instructions

rust-minijinja-v1 response profile. Read docs/MCP_RESPONSE_STANDARD.md;
docs/architecture.md is the behavior truth source.

## Single workflow

`cargo xtask check` is the full non-mutating gate.
Use `cargo xtask add-tool NAME --effect read --response entity|page|ack` to add a typed skeleton.
Definitions live in src/tools/mod.rs; JSON is an exported snapshot. `contract update` is explicit.
Generated stubs remain unimplemented and release-blocking until their behavior and tests are reviewed.

## Invariants

Rust 2024, resolver 3, pinned toolchain, committed application lock, publish=false, shared lints.
No Python/Node scripting dependencies. No daemon/database without a product requirement.
Normal MCP text uses strict embedded MiniJinja over small typed views. No raw JSON dumping.
Preserve execution outcome, exact identifiers, pagination and recovery even when rendering fails.
stdout of mcp is protocol-only. Secrets never enter responses or diagnostics.

## Delivery and updates

The initial profile is in-process + no state + single-binary-v1. Other profiles need explicit design.
Package locally only after committing source. Release prepare defaults to preview and never pushes.
The publisher checks qualification, tag/source/run identity, cargo-deny, no stubs and the actual payload.
Never flip qualification to make a pipeline green. No pruning, service restart or host registration is implicit.
Template updates are dry-run three-way plans. Resolve conflicts through normal Git review.
Do not claim native/host tests passed without evidence from those runs.
