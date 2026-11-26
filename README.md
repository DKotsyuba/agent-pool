# agent-pool

Persistent groups of native agents managed by an external leader. One leader can
own several pools and never joins their rosters. Members collaborate through a
shared journal, targeted messages and unanimous proposals. Run owns individual
execution; Bridge owns identity and delivery. Pool owns group state.

Apple Silicon macOS (`aarch64-apple-darwin`) is a candidate target. x86-64 Linux with
GNU libc (`x86_64-unknown-linux-gnu`) is release-qualified on the host `dobi`; see the
0.1.0 changelog for evidence and the single-UID limitation. Read
[the architecture](docs/architecture.md) for trust boundaries and recovery behavior.
The Linux CI candidate is built on Ubuntu 24.04 and requires a compatible GNU libc;
compatibility with older distributions has not been verified.

## Running

Provision explicit private paths and the required Bridge producer/audience grants
using [config.example.toml](config.example.toml).
Upgrade Pool before upgrading Run. Chat pools require Run 0.33.0 or newer;
legacy managed pools keep working with older Run. The Pool resident migrates the
SQLite store to schema v18 on first open. Take a private, WAL-consistent
pre-upgrade backup using SQLite’s backup API or a consistent offline snapshot.
Pool 0.1.5 and older refuse v18. Restoring the pre-upgrade backup loses subsequent
admissions and release credentials. Protect v18 database files, WAL files,
dumps and backups as credential-bearing data.

Run uses a private same-user socket by default. On Linux, an explicit different
`run_peer_uid` enables a protected shared Run socket when OS permissions already
allow access; it does not change the Pool or Bridge trust boundaries. See the
configuration example for the ownership and UID mapping requirements.
Run-managed members currently remain unavailable after admission until Run can
prove the exact execution and caller attempt; Bridge-only participants still work.
New single and grouped admissions request durable Run history pins. A single
admission requires Run's read-only batch receipt lookup before it can start; after
removal Pool only looks up its original receipt and never starts it again.
After closure, an owner may explicitly request release. Pool sends it only to the
original verified Run store. Run 0.32 public pins use a private bearer token
returned only on original admission. Pool selects older release methods from
Run socket discovery. For missing tokens, owner deliveries show the exact
offline recovery inputs when available. Submit `pool_release_history` with
a fresh request key after offline release to confirm the released pin.
Guarded replacement requires a terminal, cleaned lineage and an atomic Run
precondition. Uncertain results freeze the old roster.
Admission receipts alone cannot establish completion. Older uncertain intents
without a stored identity remain on hold.
Replaced members' history pins also remain retained until explicit release after
pool closure; long-lived pools can accumulate retained Run history.

Start the resident separately:

```sh
agent-pool serve --config /absolute/private/agent-pool/config.toml
agent-pool mcp --config /absolute/private/agent-pool/config.toml
```

Pool 0.2.3 recovers stale resident sockets on startup. Systemd units no longer
require `ExecStartPre=rm -f pool.sock`.

The second command belongs in the actual native host's MCP configuration so it
receives protected original call metadata. Arbitrary shell invocations cannot
invent a caller identity. The resident survives MCP frontend EOF. `get_status`,
`doctor --json` and `contract export` work without live credentials.

## Tools

| Tools | Purpose |
|---|---|
| `pool_create`, `pool_list`, `pool_get` | Create and inspect authorized persistent groups |
| `pool_update`, `pool_close` | Owner changes metadata or explicitly closes a group |
| `pool_add`, `pool_start_agent`, `pool_start_batch`, `pool_join` | Invite/start, onboard and confirm native membership |
| `pool_enrollment_get`, `pool_enrollment_resolve` | Owner reads one managed start/replace enrollment, or closes an admitted but unbound one as `retain_unassigned` |
| `pool_member_update`, `pool_remove`, `pool_replace`, `pool_cancel_replacement` | Change assignments, revoke or safely replace an exact incarnation |
| `pool_release_history` | Request release of a closed member's retained Run history |
| `pool_post`, `pool_send_member`, `pool_notify_owner` | Member broadcast (optional `notify` list limits who is woken; history stays shared), peer delivery and explicit owner contact |
| `pool_propose`, `pool_vote` | Freeze criteria/roster and record unanimous acceptance |

All mutations require a stable `request_key`; existing-pool mutations also require
`expected_revision`. Read current state before new intent. A lost reply is recovered
using the identical key and intent. `pool_get` sections are `overview`, `members`,
`history`, `proposal`, `votes`, `criteria`, `content`, and `deliveries`; use the exact returned cursor.
The owner can use `binding` with an exact `member_id` to retrieve a removed mapping.
Removed agents cannot read or act. Removal does not stop their execution process.

## Development

Use the pinned Rust toolchain and prepared offline dependencies. Set `TMPDIR`,
`TMP`, `TEMP`, `CARGO_TARGET_DIR` and `CARGO_BUILD_BUILD_DIR` to the approved
project-specific temporary/build directories before checks.

```sh
cargo check -p agent-pool --all-targets --offline --locked
cargo nextest run -p agent-pool --offline --locked
cargo xtask contract update
cargo xtask check
```

Rust is the authoritative tool catalog; `schemas/tools.json` is a reviewed exported
snapshot. The strict embedded MiniJinja layouts are in `src/templates`. No new
framework, runtime language or external database service is required.
`live_synthetic_run_batch` is an opt-in cross-project test: it requires a disposable
Run home under `TMPDIR`, a `.pool-synthetic-run` marker, a fake-engine broker with
capacity three, and `AGENT_POOL_SYNTHETIC_RUN_HOME` pointing at that home. It never
uses a real account; the ordinary gate leaves it ignored. The related
`live_synthetic_pool_outbox` test also needs the Pool MCP catalog selected in that
fixture and exercises admission plus an explicit test-only history release.
The `live_synthetic_run_receipt_and_status` test requires a fresh empty fixture
with both draft Run methods and `AGENT_POOL_SYNTHETIC_RUN_FIXTURE_BINARY`
pointing to its configured fake engine. Its caller owns the fake broker and must
stop its processes and remove the fixture even if the test fails or times out.
`live_synthetic_pool_replacement` additionally needs a fresh fixture with the
conditioned batch API and a synthetic global `agent-pool` MCP entry using
`/bin/true`. It resumes and replaces a fake execution, exercises atomic batch
preconditions and replay, and verifies that cancelling a later unsubmitted
replacement creates no additional Run admission. With `--nocapture` it prints
the synthetic Pool and operation IDs for observer checks. It leaves all
broker/process cleanup to its caller.

Packaging requires committed source and never grants native qualification.
Choose the approved artifact directory explicitly and verify the resulting bundle:

```sh
cargo xtask package --out /absolute/package-directory
cargo xtask package verify /absolute/package-directory
```

`self-install` and `releases use` preserve immutable version directories, check the
state schema and refuse a different product or platform; they do not register or
restart services or edit host configuration. Existing installation directories
must already be private (0700); their permissions are never silently changed.
Keep the bundle and its files, the installation and launcher directories, and
their ancestors trusted and not writable by other users throughout installation.
A missing lock in an existing installation or an interrupted first installation
is refused; recovery must first establish that no old installer still holds it.
The installer verifies both binary and manifest hashes before execution, using
`shasum` on macOS or `sha256sum` on Linux. Hashes are not signatures; it trusts
the selected GitHub origin. CI defines native source checks for both candidates.
CI also builds candidates from the committed checkout, verifies each archived
binary and retains it with its manifest for seven days. Linux is available as
`candidate-linux-x86_64`; macOS is available on main and manual runs as
`candidate-macos-aarch64`. These are not published releases or evidence of native
or host qualification.
The release workflow starts only by manual dispatch on an annotated version tag;
creating or pushing a tag alone does not start publication. Select `paired` to
require separately tested macOS and Linux payloads from the same source and CI
run, or `linux-only` to publish only the independently tested Linux bundle. The
initial `select-targets` choice is rejected. The version tag must point to a
commit containing this dispatch-only workflow; older commits can contain the
previous tag-push trigger. The workflow must also exist on the default branch
for GitHub to allow a manual dispatch. Runs for the same tag share a concurrency
group; an existing draft or release is never replaced.
The macOS manifest keeps the existing `release-manifest.json` name; Linux uses
`release-manifest-x86_64-unknown-linux-gnu.json`. Release remains disabled until
native and host qualification and explicit delivery approval; a Linux-only run
does not qualify macOS. The workflow's identity and digest checks are not
cryptographic provenance verification.
`cargo xtask release wait` retains its macOS default; pass
`--target x86_64-unknown-linux-gnu` to verify the Linux release assets instead.
It also observes historical releases produced by tag-push runs.
Legacy Run pools remain operational until a separately coordinated cutover.
Existing Run pool data and history are not migrated to Agent Pool; source checks
never delete that data or change a running service.

## Pool chat v1

Chat pools require Run 0.33.0 or newer. On Linux, provision `[owner_ingress]` and point the resident's `run_socket` at
Run's operator socket. Start the owner frontend with
`agent-pool mcp --owner-socket /run/agent-pool/owner.sock --server-uid 1003`.
Use the actual resident UID. Every allowlisted owner can manage any chat pool
and retrieve legacy completions. The resident UID cannot use owner ingress.

| Owner tool | Purpose |
| --- | --- |
| `pool_start` | Start an ordered group of ordinary Run agents with `{assignment, spec}` per seat. Pass `provider`, `model`, `profile` and `workdir` in each Run spec. |
| `pool_list` | List pools across owners with optional `state=open\|completed\|closed` and an exclusive `after` cursor. |
| `pool_get` | Read the goal, current roster, admission/join/process states, votes and result status. Select `history` for journal pages. |
| `pool_post`, `pool_send_member` | Broadcast or send to one exact current seat. Owner posts always wake every seat. |
| `pool_replace` | Retire a seat and launch a fresh seat at the expected pool revision. Returns the prior Run ID when there was an admission. |
| `pool_close` | Close the chat and revoke seat authority. Use Run for cancellation. |
| `pool_completion_get` | Read the agreed result by pool ID. For historical managed records, select `section=content` and page with `after`. |

| Member tool | Purpose |
| --- | --- |
| `pool_join`, `pool_get` | Confirm the seat and inspect the pool or its journal. |
| `pool_post`, `pool_send_member`, `pool_notify_owner` | Broadcast (`notify` wakes only the listed member IDs, names or roles; everyone can still read it), message one current seat or notify the initiating chat. |
| `pool_propose`, `pool_vote` | Open a proposal and record your ready vote in the same revision, or vote ready, block or revoke against the exact proposal and roster. |

A sole joined seat completes the pool when it proposes. While a proposal is open,
the proposer can change its vote. For free-text criteria, send `evidence` for
ready or block and omit `checks`. For structured acceptance, use `pool_get
section=criteria` and send one check per exact criterion ID for ready. Each
check has `criterion_id`, `status` (`met` or `unmet`), and `evidence`.

Run supplies member identity through its ordinary worker MCP. Choose each worker's
wakeable profile such as `implement` or `review`. Pool refuses `research` for both
start and replacement because it cannot receive pool chat notices. The owner
`pool_get` overview includes up to five recently retired seats and reports
`notice_undeliverable` per seat. Use `section=members` to page through all current
and retired chat seats. For each continuation, pass the previous page’s `next` as
the string `after` and the first page’s `revision` as `expected_revision`. If the
revision changed, restart at the first page. Mutations take the observed
`expected_revision`. Owners supply a
stable `request_key`. The resident reconciles Run receipts when admission is uncertain,
even if the owner disconnects.
`pool_start` accepts an optional canonical `owner_address` for Bridge notices.
The pool remains readable and can reach agreement if the initiating chat ends.

### Owner binding

Crew binds the session that called `pool_start` through the owner ingress socket.
Set `host_id` to the host ID from the local Bridge adapter configuration, and map
each allowed owner's Linux UID to its Bridge store namespace for each enabled
harness. The socket path and resident UID must match the owner MCP command.

```toml
[owner_ingress]
path = "/run/agent-pool/owner.sock"
gid = 1000 # Use the provisioned socket group.
allowed_uids = [1002]
host_id = "dobi"

[owner_ingress.stores]
1002 = { claude-code = "claude-agent-claude", codex = "codex-agent-claude" }
```

Add this hook to Crew's hook configuration for both runtimes. Adjust the binary
path, socket path and resident UID to match the owner MCP deployment.

```toml
[[hooks]]
name = "agent-pool-owner-bind"
runtimes = ["codex", "claude"]
command = ["/usr/local/bin/agent-pool", "hook", "bind", "--owner-socket", "/run/agent-pool/owner.sock", "--server-uid", "1003", "--harness", "codex"]
timeout = 5

[hooks.codex]
event = "PostToolUse"
matcher = "^mcp__agent[-_]pool__pool_start$"

[hooks.claude]
event = "PostToolUse"
matcher = "^mcp__agent[-_]pool__pool_start$"
command = ["/usr/local/bin/agent-pool", "hook", "bind", "--owner-socket", "/run/agent-pool/owner.sock", "--server-uid", "1003", "--harness", "claude-code"]
```

Only the kernel UID that created the pool can bind it. An explicit
`owner_address` takes precedence. Repeating the same binding is safe.
The resident queues the latest 20 owner messages and completion notices
recorded before the first bind. Older notices remain in pool history.
Schema v19 and earlier did not record the starter UID. Existing unbound pools
remain readable and their historical notices remain in the journal.

When upgrading to 0.2.4, keep a pre-upgrade database backup if you may need
to roll back. Version 0.2.3 refuses to open a store migrated to schema v20.
