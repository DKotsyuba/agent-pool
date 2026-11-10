# Changelog

## Unreleased

### Changed

- Upgrade persistent state to schema v5 so older binaries refuse durable replacement metadata.
- Run release checks and payload construction in parallel while keeping publication gated on both.
- Seed separate check/package dependency caches from main; document focused checks for local iteration.
- Reuse Cargo dependency builds and versioned cargo-deny tooling in CI and release jobs.
- Run Clippy/tests once for featureless workspaces; retain both default and all-features configurations when workspace features exist.

### Fixed

- Isolate completion release keys per durable Pool store
  (`completion-keys/<store UUID>/`) so Pool databases sharing one private parent
  never sweep each other's keys; startup migrates only this store's owned legacy
  flat keys and never deletes from the shared root.
- A late admission receipt for a completed pool (schema v14) is retained exactly
  and settles its effect as terminal `reconciliation_needed` with one owner
  notice instead of stopping the resident worker.
- Refuse direct installation or activation of a bundle for another product or platform,
  and preserve existing installation-directory permissions.
- Allow only the explicitly pinned Bridge SDK repository in the dependency source check.
- Allow explicitly trusted, protected cross-user Linux Run sockets while preserving
  the same-user defaults and Bridge/Pool boundaries.
- Reject credential files when their parent directory is not private to the
  configured user.
- Modern MCP 2026-07-28 tools/list includes a 60000 ms private cache lifetime; legacy catalog responses stay unchanged.
- Raw stdio regression tests cover modern/legacy tools/list and modern server/discover; supported protocol revisions are explicit.

### Added

- Formal Pool completion (P3-C, schema v12, following v10 egress and v11 re-pin
  and issuer retirement): automatic resident settlement with a
  durable Run lineage-hold saga, per-saga protected Ed25519 release keys, one
  atomic CAS that appends an immutable digest-bound completion record, owner
  `completion_get` pages (`completion_record_v1`) and non-null inventory
  `open`/`completed` counts (`inventory_completion_v1`). Completion freezes the pool.
- Recoverable Run-member replacement with atomic Run preconditions and a frozen roster on unknown outcomes.
- Optional structured acceptance criteria and durable per-criterion vote checks.
- Recoverable grouped Run admission with local all-or-nothing membership reservation;
  the Run batch integration remains subject to a matching runtime implementation.
- Bounded participant history waits with membership and shutdown checks.
- Reverse participant history pages with exact exclusive cursor strings.
- Messages up to 8192 UTF-8 bytes with atomic bounded journal parts.
- Exact paged purposes up to 8192 bytes and proposal snapshots up to 65536 bytes.
- Opt-in owner history windows with backward paging and exact 64-bit cursors.
- Linux x86-64 candidate support in the installer and native CI, alongside
  the existing Apple Silicon macOS candidate. Neither target is release-qualified.
- Build and verify an archived Linux x86-64 candidate in CI and retain it as a
  seven-day workflow artifact, without publishing it as a release.
- Retain an independently verified macOS arm64 CI candidate on main and manual
  runs, alongside the Linux candidate.
- Prepare one gated release containing separately verified macOS and Linux bundles,
  with target-specific manifests and unchanged legacy macOS naming.
- Persistent pools, authenticated messaging and the local development gate.

No published release is implied by the Cargo package version.
