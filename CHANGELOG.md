# Changelog

## Unreleased

## 0.2.1

- Chat start and replacement reject the Run `research` profile. Other roles Run reports as restricted settle their notices immediately.
- Unconfirmed Bridge custody retries the exact frozen publication for up to ten minutes. Recovery assumes the configured producer socket and credential still address the same Bridge deployment. Bridge deduplicates by event ID. Confirmed custody and possible sends past the retry window use status reconciliation.
- Chat notices run in an indexed, bounded queue. Close and replacement fence first sends. The owner overview shows recently retired seats and delivery results identify the exact target seat.

### Fixed

- Chat member notices use Bridge for public messages, direct messages, vote requests, owner posts, completion and closure. Pool retries unresolved member addresses with bounded backoff and records `notice_undeliverable` for owners and observers when resolution fails. Notices are best effort and history remains durable.

### Changed

- Store schema v19 persists notice retry schedules and event/seat uniqueness. Before upgrade, take a private WAL-consistent backup. Pool 0.2.0 refuses a v19 store.

## 0.2.0

Feature release, 2026-11-19. Qualification fields are unchanged from 0.1.0: `x86_64-unknown-linux-gnu` on the host `dobi`; this release ships that target only.

Upgrade note: this release migrates the store to schema v18 on the first open. Take a private, WAL-consistent `pool.sqlite` backup before the upgrade: 0.1.5 and older refuse a v18 store, and restoring the backup loses later admissions and release credentials. Treat v18 database files, WAL files, dumps and backups as credential-bearing. Chat pools require Run 0.33.0 or newer; upgrade Pool before Run. Legacy managed pools keep working with older Run.

### Added

- Linux owner ingress and Pool chat v1 for ordinary Run profiles. Start the owner frontend with `agent-pool mcp --owner-socket PATH --server-uid UID`. Authorized owners share eight chat management tools, including `pool_start` and `pool_completion_get`, and current seats reach a durable agreement through Run-authenticated chat tools (`member_call_v1` and `chat_catalog_v1` on the Run relay). This requires Run 0.33.0 or newer.
- Agreement records, resident reconciliation of uncertain chat admissions by Run request ID, and observer fields for Hub.

### Changed

- Store schema v18 adds durable chat batches, agreement records and retry timing for closed batches. 0.1.5 and older refuse a v18 store.

## 0.1.5

Feature release, 2026-11-19. Qualification fields are unchanged from 0.1.0: `x86_64-unknown-linux-gnu` on the host `dobi`; this release ships that target only.

Upgrade note: upgrade Pool before Run 0.32. This release migrates the store to schema v17 on the first open. Take a private, WAL-consistent `pool.sqlite` backup before the upgrade: 0.1.4 and older refuse a v17 store, and restoring the backup loses later admissions and release credentials. Treat v17 database files, WAL files, dumps and backups as credential-bearing.

### Changed

- Run 0.32 public batch and replacement pins use a bearer token delivered only in the original socket acknowledgement. Pool stores it privately in schema v17 and chooses legacy wire shapes from the Run socket catalog. Managed-enrollment pins keep the authenticated attempt route. Missing tokens and rejected release parameters require owner attention. After offline release, the owner can reissue the release request to verify the exact pin on the original Run store.
- Upgrade Pool before Run 0.32. Take a private, WAL-consistent pre-upgrade SQLite backup before opening the store with the new Pool. Pool 0.1.4 refuses schema v17. Restoring the pre-upgrade backup loses subsequent admissions and credentials. Treat v17 database files, WAL files, dumps and backups as credential-bearing.

## 0.1.4

Fix release, 2026-11-18. Qualification fields are unchanged from 0.1.0: `x86_64-unknown-linux-gnu` on the host `dobi`; this release ships that target only.

Upgrade note: this release migrates the store to schema v16 on the first open. 0.1.3 and older refuse a v16 store, so a rollback requires a `pool.sqlite` backup taken before the upgrade.

### Fixed

- Closing a pool no longer leaves member states and delivery work open (#17, #29). Members of a closed pool are recorded `removed`. Never-published deliveries settle as `not_delivered`: final notices to members without a managed binding settle in the close transaction with attention `pool_closed`, and a bound member's final notice settles `pool_closed` after at most three non-decisive attempts instead of being retried every 300 s forever (each retry cost a rejected Run egress receipt and a Pool currentness row). Known-unsent and uncertain effects of closed pools keep their original identity and receipts, are only reconciled under that identity (never republished) and are paced by a backoff of 60 s doubling to one hour.
- A member created by `pool_add`, `pool_start_agent` or `pool_start_batch` no longer receives a second native turn for its own creation event in addition to its onboarding (#18). Onboarding delivery after binding is unchanged.

### Added

- Owner observer operation `delivery_attention` (capability `delivery_attention_v1`, owner grant only) with counts of closed pools, their open members, unsettled and unresolved deliveries. `agent-pool doctor --config` reports it as `closed_pool_attention`; it does not change the exit code.

### Changed

- Store schema v16: non-current incarnations are recorded `removed`, and every open settles closed pools' never-published deliveries idempotently, so pools closed by 0.1.3 settle on upgrade. 0.1.3 and older refuse a v16 store.
- `deny.toml` now ignores RUSTSEC-2026-0543 ("chrono is unmaintained", informational, no vulnerability) with an owner-approved re-check date of 2027-02-01; chrono remains required by rmcp and by our own use.

## 0.1.3

Fix release, 2026-11-14. Qualification fields are unchanged from 0.1.0: `x86_64-unknown-linux-gnu` on the host `dobi`; this release ships that target only.

### Fixed

- A pending managed delivery whose route, binding or Run attempt is unavailable now waits out a durable pause before its next attempt (5 s doubling per non-decisive attempt, capped at 300 s) instead of retrying on every 5-second resident pass. Each retry repeated a new durable currentness request and executable peer proofs of Run and Bridge; undeliverable final notices of closed pools kept the resident and Run busy indefinitely. Freezing an effect clears the count, so unknown-outcome lookups keep their full budget.

## 0.1.2

Feature release, 2026-11-13. Qualification fields are unchanged from 0.1.0: `x86_64-unknown-linux-gnu` on the host `dobi`; this release ships that target only.

### Added

- Optional group observer socket (`[observer_socket]`, Linux only, capability `observer_socket_v1`). The resident binds a second endpoint with a configured group and mode (0660 by default) in an existing directory owned by the Pool UID or root, without group/other write and without other access. Peers are admitted only when their kernel-reported UID is in `allowed_uids`; others get one `unauthorized` line before any input is read. There is no credential. The request is the plain observer request, and only `identity`, `list`, `get` (state sections, without bindings or Run proof), `inventory_snapshot`, `completion_get` and `enrollment_get` are served. `managed_capacity`, the `binding` and `run_proof` sections and `include_bindings` are `unauthorized`; anything else is `invalid` and never dispatched. At most 8 observer connections, 64 KiB request lines.
- `agent-pool observe --socket PATH --server-uid UID` reads through that socket without a config or credential. It applies the cross-user path policy for the server UID and checks the peer UID before writing.

## 0.1.1

Security release, 2026-11-13. Qualification fields are unchanged from 0.1.0: `x86_64-unknown-linux-gnu` on the host `dobi`; this release ships that target only.

### Security

- The live proof for pinned Pool and Run peers now meets errata E13/E14, matching Run's own peer proof. It applies to the Run attempt endpoint, the Run reader and the managed frontend/resident session. The peer may not have any `LD_*` variable in its initial environment or a tracer, and `/etc/ld.so.preload` must be absent or blank. The pinned path may not name a generic interpreter. Pool opens `/proc/PID/exe` and checks the same descriptor three ways: the file must currently be owned by the Pool UID or root without group/other write; its fdinfo `mnt_id` must resolve to a filesystem that denies writes to a running executable (ext2/3/4, xfs, btrfs, tmpfs); and its own digest must equal the pin. After hashing, its identity and the configured path's inode must be unchanged. Previously Pool accepted a genuine pinned build started with a loader override or under a tracer, a writable loaded file, or a file on any filesystem. Operator re-pin also refuses an interpreter path.
- Tests that use the test executable as a trusted peer re-run themselves without `LD_*` variables (nextest exports `LD_LIBRARY_PATH`), and drop group/other write from the executable while they run.
- The Agent Bridge SDK pin moves from v0.7.0 (`c12376f`) to v0.7.2 (`2743c00`), which also refuses a Bridge server peer that has `LD_*` in its environment, is traced, has a non-blank `/etc/ld.so.preload`, or is a generic interpreter. Synthetic Bridge servers in tests start without `LD_*`.

### Changed

- Stale test scratch cleanup accepts only canonical decimal PIDs and is skipped when the PID namespace is unknown.
- Gate test scratch directories are named with the PID namespace and a random suffix, and stale cleanup only removes directories of exited processes from the same namespace.
- The integration-test check ignores commented-out module lines and requires `autotests = false`. Every `exec-hash` nextest group entry must name a test that takes `TEST_EXEC_HASH_LOCK`.
- CI installs cargo-nextest into a runner-owned directory added to `PATH` (macOS runners lack `~/.cargo/bin`).
- `cargo xtask check` follows the Rust gate standard: tests run under cargo-nextest (required; CI installs 0.9.149 from a checksum-verified archive) with every failure reported, doctests via `cargo test --doc`, and test temporaries in a fresh tmpfs directory (`XTASK_TEST_TMPFS=0` opts out). Integration tests build into one `it` binary: every `tests/*.rs` must be a module of `tests/it/main.rs`. Release acceptance runs `--test it <suite>::` filters and refuses a filter that selects no tests. The dev profile keeps line-table debug info only (`--profile debugging` for full). Tests serialized by the in-process `TEST_EXEC_HASH_LOCK` run in a one-thread nextest group; the gate rejects a lock user missing from it.

## 0.1.0

First release, 2026-11-11. Attempt-bound managed ingress and egress with
operator re-pin, E11 namespace retirement, formal Pool completion, and P3
managed enrollment and conditioned replacement, qualified on Linux x86-64 with
Agent Bridge 0.7.1 and Agent Run 0.31.0 RC.

### Qualification

`x86_64-unknown-linux-gnu` is release-qualified on the host `dobi`; this release
ships that target only. `aarch64-apple-darwin` remains a candidate target and is
not qualified or published.

Host evidence: dobi, 2026-11-11, run 6c. Managed members were Claude Code 2.1.311
with `claude-haiku-5-5` and codex-cli 0.167.0 with `gpt-6-luna`, both through
Agent Bridge 0.7.1 and Agent Run 0.31.0 RC. Scenarios Q1–Q5 passed:

- Q1 create
- Q2 enroll and join
- Q3 egress
- Q4 vote and completion
- Q5 freeze

### Known limitations

- Managed attempt binding requires that Run, Pool, the Bridge worker and the
  agents all run under a single UID. On dobi that is the dedicated `agent-mcp`
  account. Multi-UID deployments are not supported.

### Added

- P3 managed enrollment (schema v15): with the explicit
  `managed_run_transport.enrollment_enabled` switch and exact `managed_role`,
  owner `pool_start_agent`/`pool_start_batch` reserve members and a durable
  enrollment journal before any Run I/O, submit Run `_managed_start_batch_v1`
  under one permanent key, recover only by same-key submit/lookup/abort, bind
  generation 1 from a qualified current attestation (or the first rootless
  hook) and open managed `pool_join` only for owner-enrolled roots.
- P3 conditioned replacement: `pool_replace` admits a new lineage and member ID
  on the exact frozen old-lineage precondition and atomically retires the old
  member when the qualified candidate is switched in.
- Owner `pool_enrollment_get` and `pool_enrollment_resolve`
  (`retain_unassigned`), and the observer `enrollment_get` operation with
  capability `managed_enrollment_v1`.

### Changed

- Upgrade persistent state to schema v5 so older binaries refuse durable replacement metadata.
- Run release checks and payload construction in parallel while keeping publication gated on both.
- Seed separate check/package dependency caches from main; document focused checks for local iteration.
- Reuse Cargo dependency builds and versioned cargo-deny tooling in CI and release jobs.
- Run Clippy/tests once for featureless workspaces; retain both default and all-features configurations when workspace features exist.

### Security

- Update `rmcp` to 3.9.0 (RUSTSEC-2026-0457, RUSTSEC-2026-0461, RUSTSEC-2026-0462) and
  `rusqlite` to 0.41.1, which brings bundled `libsqlite3-sys` 0.39.1 (RUSTSEC-2026-0459).

### Fixed

- Managed Codex calls are no longer refused as `unauthorized` (errata E16).
  codex-cli 0.167.0 presents MCP tools as `mcp__{seg(server)}__{tool}`, where
  seg maps every character outside `[A-Za-z0-9_]` to `_`. Pool now checks the
  consumed `tool_name` against the exact name the attested harness presents,
  using the same rule as Bridge 0.7.1. The harness comes only from Bridge's
  attested actor address. Claude keeps the raw `mcp__{server}__{tool}`, Codex
  must match the normalized name exactly, and any other harness is refused.
  `managed_run_transport.mcp_server` is refused when its Codex segment is
  empty, starts or ends with `_`, or contains `__`, or when any Codex tool name
  would exceed 128 bytes.
- `agent-pool repin` accepts a moved Bridge `server_executable` and Run
  `executable` (for example a versioned Bridge 0.7.1 install path) with their
  new SHA-256, instead of failing with `Conflict`. Before it commits, it proves
  each candidate file: absolute canonical path, regular file owned by the
  resident UID or root, not group/other-writable, digest equal to the pin. Each
  live peer is then proved through the pinned capability exchange. The path
  change records a new route pin generation. Existing intents, effects and
  enrollment keys keep their frozen pins, and only new work uses the new pin.
  Route IDs, stores, worker UID, sockets, producer and credential file must
  still match exactly; a mismatch is a `Conflict` that leaves every pin unchanged.
- A stored route pin that no longer matches the configured Bridge or Run
  executable no longer stops the resident (`resident: Conflict`). Only the
  affected managed delivery is refused, with `route_unavailable` attention. The
  resident logs once that `agent-pool repin` is required and keeps serving
  everything else.
- E11 namespace retirement records durable owner attention
  (`namespace_retirement_attention_<code>`) with capped backoff when Bridge
  issuer discovery fails, instead of silently skipping retirement; `repin`
  reports which discovery failed.
- Erratum E12 egress liveness: an unknown managed publish whose exact lookups
  stay non-decisive is aborted for the exact original effect after bounded
  backoff; only a durable `aborted` creates one new effect for the same event.
  A successor aborted again is republished after a durable exponential pause
  (cap 300 s, attention `delivery_retrying_outcome_unknown`; one live effect
  per event), and `known_unsent` `attempt_mismatch` is terminal `not_delivered`
  (`delivery_refused_attempt_mismatch`) for its generation, so a Run pinned to
  an older Bridge build cannot cause a loop.
- Enrollment abort tombstones release never-admitted start members, scopes and
  effects in the same transaction, so a lost abort response or a crash before
  the refusal is recorded no longer leaks reserved members.
- Mutations refused because a pool is formally completed keep the `closed`
  code but no longer claim the pool was explicitly closed.
- `bind_run` never overwrites a terminal (`refused`, `cancelled`,
  `reconciliation_needed`) effect or a completed pool.
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
  the existing Apple Silicon macOS candidate. Only Linux x86-64 is release-qualified (see Qualification).
- Build and verify an archived Linux x86-64 candidate in CI and retain it as a
  seven-day workflow artifact, without publishing it as a release.
- Retain an independently verified macOS arm64 CI candidate on main and manual
  runs, alongside the Linux candidate.
- Prepare one gated release containing separately verified macOS and Linux bundles,
  with target-specific manifests and unchanged legacy macOS naming.
- Persistent pools, authenticated messaging and the local development gate.

No published release is implied by the Cargo package version.
