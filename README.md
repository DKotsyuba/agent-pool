# agent-pool

<!-- Replace this paragraph with your product's purpose: what it does for its
caller and what it deliberately never does. -->
A stdio MCP server. Repository: .
Read AGENTS.md and docs/MCP_RESPONSE_STANDARD.md before adding tools.

## Tools

| Tool | Effect | Purpose |
|---|---|---|
| `get_status` | read | product identity and release qualification status |

Replace this table with the product's real tools as their contracts are implemented.

## Development

```bash
cargo fetch --locked
cargo xtask check
cargo xtask add-tool NAME --effect read --response page
cargo xtask test protocol
cargo xtask test presentation
cargo xtask test delivery
cargo run --locked -- doctor --json
cargo run --locked -- mcp
```

Product source is in src/, the authoritative tool registry in src/tools/mod.rs,
tool text templates in assets/mcp/tools/, and the exported discovery snapshot
in schemas/tools.json. `cargo xtask contract update` is an explicit reviewed
snapshot change. Generated tool stubs do not perform effects or return fake
success; finish their contract and tests.

Cargo.lock must be reviewed and committed.

For a short edit loop, fetch the locked dependencies once, run formatting
directly, then check the changed crate or run its relevant test target:

```bash
cargo fmt --all --check
cargo check --frozen -p agent-pool --all-targets --all-features
cargo test --frozen -p agent-pool --all-features --test protocol
```

Select the changed workspace crate and test filter as appropriate. These focused
commands give early feedback; finish a coherent change with `cargo xtask check`
and its applicable protocol/presentation/delivery checks before a PR. Changes to
embedded templates or other compile-time assets require the same checks as code.
Optimized packaging belongs to delivery, not every edit iteration.

## Local delivery

Commit your source first. No remote repository is required to build a local package.

```bash
cargo xtask package
cargo xtask package verify dist/agent-pool-0.1.0-aarch64-apple-darwin
```

The bundle executable accepts `self-install --bundle PATH --home ABS_PATH --bin-dir ABS_PATH`.
Create the bin directory explicitly. Installation preserves immutable versions, never restarts
services and does not edit MCP host configuration. `releases use VERSION` verifies and selects
a retained compatible version. This profile has no local data migration; external effects are
not undone by a binary rollback. No automatic pruning or removal of user data.

CI restores Cargo dependency builds and a versioned cargo-deny tool cache. Successful
main check jobs warm the check cache; an independent main-only package job warms
optimized package dependencies without uploading or publishing a release. This
adds an optimized build to main CI, which runs alongside checks and costs extra
compute on cold inputs. PRs use the check cache without the package producer.
Release jobs restore both workloads without writing competing cache snapshots.
Cache misses run the normal commands. The gate still
runs on cache hits: workspaces without features need one all-features Clippy/test
pass; workspaces with features retain default and all-features passes. Platform,
compiler, dependency and build-setting changes invalidate the relevant cache.
Release packages and their integrity/acceptance evidence remain separate artifacts.

The release source check and exact payload build run in parallel. Publication
waits for both to succeed, then preserves environment approval and tests the
downloaded payload's exact bytes. Packaging does not enable release publication
or establish native host qualification.

The release workflow is guarded by release.enabled=false and qualification settings in family.toml.
Version preparation is `cargo xtask release prepare VERSION --apply`; inspect/commit the changes,
then create and push an annotated tag yourself. Publishing tests the exact shipped executable.

## Template updates

`cargo xtask template diff --from /trusted/template/checkout` compares original managed bytes,
local changes and the next template. `template upgrade --dry-run` writes nothing.
Apply the reviewed plan through Git; conflicting local changes and Cargo dependencies need review.
The build has no live dependency on the private template repository.
