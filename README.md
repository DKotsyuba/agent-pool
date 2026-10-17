# agent-pool

Persistent groups of native agents managed by an external leader. One leader can
own several pools and never joins their rosters. Members collaborate through a
shared journal, targeted messages and unanimous proposals. Run owns individual
execution; Bridge owns identity and delivery. Pool owns group state.

This candidate is not installed or live-qualified. Read
[the architecture](docs/architecture.md) for trust boundaries and recovery behavior.

## Running

Provision explicit private paths and the required Bridge producer/audience grants
using [config.example.toml](config.example.toml). Start the resident separately:

```sh
agent-pool serve --config /absolute/private/agent-pool/config.toml
agent-pool mcp --config /absolute/private/agent-pool/config.toml
```

The second command belongs in the actual native host's MCP configuration so it
receives protected original call metadata. Arbitrary shell invocations cannot
invent a caller identity. The resident survives MCP frontend EOF. `get_status`,
`doctor --json` and `contract export` work without live credentials.

## Tools

| Tools | Purpose |
|---|---|
| `pool_create`, `pool_list`, `pool_get` | Create and inspect authorized persistent groups |
| `pool_update`, `pool_close` | Owner changes metadata or explicitly closes a group |
| `pool_add`, `pool_start_agent`, `pool_join` | Invite/start, onboard and confirm native membership |
| `pool_member_update`, `pool_remove` | Change assignments or revoke an exact incarnation |
| `pool_post`, `pool_send_member`, `pool_notify_owner` | Member broadcast, peer delivery and explicit owner contact |
| `pool_propose`, `pool_vote` | Freeze criteria/roster and record unanimous acceptance |

All mutations require a stable `request_key`; existing-pool mutations also require
`expected_revision`. Read current state before new intent. A lost reply is recovered
using the identical key and intent. `pool_get` sections are `overview`, `members`,
`history`, `proposal`, `votes`, and `deliveries`; use the exact returned cursor.
The owner can use `binding` with an exact `member_id` to retrieve a removed mapping.
Removed agents cannot read or act. Removal does not stop their execution process.

## Development

Use the pinned Rust toolchain and prepared offline dependencies. Set `TMPDIR`,
`TMP`, `TEMP`, `CARGO_TARGET_DIR` and `CARGO_BUILD_BUILD_DIR` to the approved
project-specific temporary/build directories before checks.

```sh
cargo check -p agent-pool --all-targets --offline --locked
cargo test -p agent-pool --offline --locked
cargo xtask contract update
cargo xtask check
```

Rust is the authoritative tool catalog; `schemas/tools.json` is a reviewed exported
snapshot. The strict embedded MiniJinja layouts are in `src/templates`. No new
framework, runtime language or external database service is required.

Packaging requires committed source and never grants native qualification.
Choose the approved artifact directory explicitly and verify the resulting bundle:

```sh
cargo xtask package --out /absolute/package-directory
cargo xtask package verify /absolute/package-directory
```

`self-install` and `releases use` preserve immutable version directories, check the
state schema and do not register/restart services or edit host configuration.
Release remains disabled until native qualification and explicit delivery approval.
Legacy Run pools remain operational during additive qualification; archive and
retirement are a separate guarded cutover, never an implicit database deletion.
