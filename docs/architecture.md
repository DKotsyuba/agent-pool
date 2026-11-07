# Agent Pool architecture

Agent Pool owns persistent pools, permanent global leaders, membership incarnations,
shared history and consensus on one host. Apple Silicon macOS and x86-64 Linux with
GNU libc are candidate targets. It is a separate resident process
with a private Unix socket and SQLite database. The stdio MCP process is a frontend;
its EOF never starts, stops or replaces the resident.

## Boundaries

- `domain.rs` defines strict flat commands, safe public views and private outbox work.
- `store.rs` owns the single SQLite writer and synchronous transactions. A process
  lifetime file lock excludes a second writer. WAL, full synchronization, foreign
  keys and schema version 5 are explicit. Future schema versions refuse to open.
  Schema v1–v4 upgrades transactionally to v5 before use; older binaries must
  refuse v5 because they cannot preserve replacement intents and stable slots.
- `runtime.rs` supervises bounded frontend connections, one serial effect worker
  and rotating observation batches. Blocking database work never spans provider I/O.
- `integrations.rs` uses Bridge's public SDK and Run's public NDJSON JSON-RPC API.
- `config.rs` checks explicit endpoints, private files and same-user socket ownership.
- `tools/mod.rs`, `response.rs` and embedded templates present only selected typed
  results. The catalog snapshot is exported from Rust, never loaded as authority.

Run owns execution, limits, results and cleanup. Bridge proves native caller
identity and carries notifications. Pool does not kill processes, auto-replace
agents, block independent Bridge use or claim that an agent forgot known addresses.

## Authority and membership

Every Pool call, including reads and replay, consumes a **Current** Bridge assertion.
The actual harness-launched frontend registers original protected `tools/call._meta`;
the resident checks producer, audience and invocation. The actor key hashes the
versioned canonical address/native actor/role tuple, not caller-provided IDs.
Historical assertions, shared child identity and missing native proof refuse.

A global leader may own multiple pools but cannot be pending or confirmed in any
pool. Closing a pool never clears that role. Current actor/address reservations
are globally unique. An invitation reserves a new opaque member ID; only a fresh
verified `pool_join` binds the actor and confirms the current onboarding revision.
Run retention can remove a lineage tail and a later resume can reuse its sequence;
a sampled address also does not identify the current attempt. Until a generic
attempt-bound proof is available, Run admissions are retained but their member
binding, participant calls and fresh deliveries fail closed as unknown. Existing
managed mappings are likewise not used as authority, and their runtime projection
is unknown. Stored Run-managed ballots are exposed with `validity:unknown` and do
not count toward a new acceptance; already accepted historical decisions remain
unchanged. Bridge-only participants remain available. The required generic Run
identity/proof work is pending; admission is not proof that onboarding succeeded.
A removed incarnation loses all access and is never reused.

Participant output contains local member IDs, names, assignments, states and safe
operation IDs. Owner-only roster pages additionally expose native/Run mappings.
The owner can also retrieve one removed incarnation with `pool_get section=binding`
and its exact `member_id`, for separate Run process control or audit.
These mappings never appear in participant events, errors, receipts or notifications.
Shared history includes direct and owner messages, while delivery audiences differ:
posts go to members, direct messages to one member, explicit owner messages to the
external owner. The sender's tool receipt replaces its own extra wakeup.

## Transactions, delivery and recovery

Each mutation atomically stores state, its safe journal entry, exact idempotency
receipt and per-recipient effects. Authorization precedes replay lookup. Reusing a
key with changed intent refuses; the optimistic revision is a first-execution fence,
while proposal and frozen-roster identity remain part of replay identity.
Pool revision tracks domain commands; background Run admission and binding updates
can change private mappings without incrementing it. A caller that relies on a
binding must compare the exact binding and its route as well as the revision.

Queued delivery is claimed before I/O. The full Bridge publication and producer
association are frozen before the first possible provider write. Unknown delivery
uses exact event status, with producer, destination and intent hash verification.
Custody remains monitored until native handoff or refusal; native acceptance is
never proof of comprehension. A restart converts inflight work to unknown.

A pending Run member without a native address has `awaiting_binding` deliveries.
Their original payloads become queued only when the exact binding is established.
Removal cancels queued/waiting work and retires the membership's Bridge delivery
scope; already handed-off or uncertain effects are not claimed as recalled. One
independent final service notice tells the removed agent its access ended.

Run admission persists the original enriched `task`, required-MCP assertions and
stable globally unique request key before I/O. New admissions also retain the
unmodified caller specification privately for later replacement; it is never sent
as a separate Run argument or exposed in pool views. Older effects without that
field are not reconstructed from enriched task text. A receipt is saved immediately even
before address resolution. New single starts use the same store-fenced, pinned
batch protocol with one job and require Run's read-only receipt lookup before any
admission. The public receipt still identifies the member. Once removed, a single
member's uncertain admission is checked only through that lookup, never by a
mutating retry. A missing receipt is only a snapshot, not proof of refusal; the
intent remains unknown and may be checked again. Older scalar starts retain their
original specification and key and remain on hold when their store is unproven.
Removed admissions remain recorded; this single-start recovery never launches a replacement.

`pool_start_batch` reserves 1–20 ordered new members and persists one frozen Run
`start_batch` request. Its Pool receipt returns `created_id` as the safe batch
operation ID and `created_ids` as the ordered local members; this receipt confirms
the Pool intent, not Run admission. `deliveries` reports `start_batch` status:
`accepted` means Run atomically registered all jobs, not that all processes
launched. Definitive refusal admits none; pending member reservations remain
visible and can be removed by the owner. Only a correlated, explicitly classified
pre-admission refusal on the first possible submission is definitive; a later
refusal cannot settle an earlier unknown outcome. New fenced batches retain their Run key,
payload, socket and durable store ID before admission; retries require a matching
read-only preflight and atomic `expected_store_id` check by Run. Older unknown
intents without that durable fence remain on hold. Until admission is resolved, roster edits and pool closure
return conflict, preventing a delayed retry from launching removed members.
New batches request `retain_history:true`; the whole response is validated and
all Run IDs, sequences, immutable `execution_ref` values and unique `pin_id`
values plus per-member binding resolvers are committed together in Pool. Missing,
malformed or duplicate references or pins leave admission unknown. Pins have no
automatic expiry. After pool closure the owner may record an explicit release
intent per member. Pool sends it only through the original fenced endpoint after
a matching store-ID preflight, with `expected_store_id` checked by Run. Unknown
or legacy origins remain on hold; an uncertain response is retried by the same pin.
A release permits later pruning and cannot be undone.
A receipt's pin ID does not prove the pin is still active. The execution reference
is an identifier, not an authorization or current-attempt proof. A restored or
cloned Run database can retain the same store ID; detecting rollback needs an
independent recovery policy and is not claimed here.
There is no transaction across
the two databases, and remote process launch and identity binding remain separate.
The current batch wire is verified with local fixtures and requires the matching
general Run implementation before use against a real resident.

`pool_replace` accepts one current Run-managed `member_id` and an optional ordinary
start `spec`. Omission reuses the original private specification; if that original
is unavailable, Pool refuses to invent it. The replacement keeps the Pool name,
role and assignment; an explicit Run task can differ from that assignment. Change
the assignment first if it needs to change as well. Pool records a replacement operation and
new member ID while the old member remains current. It freezes roster edits,
enrollment, votes, proposals and closure until the operation is resolved; messages
can continue. The operation appears in `deliveries` as `replace`. The Pool receipt
records the request, not a successful replacement. Pool name and purpose are also
frozen until resolution so the replacement cannot start with an obsolete goal.
An owner can explicitly cancel the exact operation with `pool_cancel_replacement`
only while no Run admission may have been submitted and no worker claim is active.
After any possible submission, cancellation is refused and the original intent is
reconciled instead; absence of a receipt alone does not make cancellation safe.

Before submitting, Pool reads the original fenced Run store. It selects the proven
latest execution only with the original active pin, complete lineage coverage,
terminality, no pending restart and confirmed lineage cleanup; any terminal outcome
can qualify. A proven busy or unclean member is refused before submission. Pool
persists the exact latest execution precondition, route, candidate member and start
intent before the Run mutation. Run rechecks the precondition atomically with the
new admission; a changed execution or cleanup cannot pass on stale evidence.

After an exact conditioned Run receipt, Pool atomically archives the old member,
installs the fresh member in the same roster position, stales an open proposal,
records the transition and queues binding. If the result is unknown, the old roster
remains frozen and Pool reconciles the same key and intent. A later refusal cannot
resolve an earlier unknown outcome. A crash or failed Pool commit reuses the Run
receipt without creating a second replacement. The two databases are not one
transaction: Run may start the new execution before Pool commits the roster, and
a later resume of the old execution after Run's admission is not prohibited.
Neither preconditions nor receipts authenticate the new participant's attempt;
the existing managed-member guard remains active.
The replaced member's pin remains retained until the pool is closed and the owner
explicitly releases it. Frequent replacements can therefore grow retained Run
history throughout the pool's lifetime; closure does not release any pin itself.

`pool_get section=deliveries` exposes safe per-operation states without private
addresses. Separate system observations record actionable failures and notify the
owner; ordinary conversation and consensus do not subscribe the owner to delivery.

## Consensus and bounded reads

One open proposal freezes result, criteria and confirmed membership/assignments.
An explicit replacement at the current revision archives the prior open proposal
and its votes as stale, then requires fresh votes on the new result and criteria.
Only those members vote. Pools created without `acceptance` retain the original
single-evidence vote contract. Passing `acceptance` enables immutable structured
criteria; an empty array selects `[{"id":"goal","text":"The stated goal is met."}]`.
There may be 1–10 unique ASCII IDs (up to 32 bytes; letters, digits, `_`, `-`,
`.`), each with text of 1–1024 UTF-8 bytes. A structured ready vote must contain
exactly one check for every criterion. Each check has `criterion_id`, `status`
(`met` or `unmet`) and 1–1024 bytes of evidence; the encoded array is at most
16384 bytes. Missing, extra, duplicate or invalid checks are rejected before a
write. A complete vote with an unmet check is recorded but does not count toward
agreement. Block may omit checks and revoke must omit them. Unanimous valid ready
votes accept a decision. Membership/assignment changes stale an open
proposal; accepted decisions are independently archived and immutable. No vote,
completion or observation closes a pool automatically.

The current roster is limited to 20 pending/confirmed members. Names, roles and tasks
have byte limits of 80, 160 and 512; messages allow 8192, individual evidence 2048.
Purpose allows 8192 UTF-8 bytes and an optional proposal snapshot allows 65536.
Notifications contain explicitly marked short roster previews; exact assignments
remain available through paged `pool_get`. Sections separately page roster, history,
proposal, votes, structured criteria and delivery states. `criteria` returns up to
three complete immutable criteria by offset. A structured ballot includes
`checks_met` for ready, a decimal-string `vote_event_id`, and `checks_count`.
Its checks are consecutive `vote_check` journal events following that vote event,
committed in the same transaction. Read history after the vote event and follow its
cursor until `checks_count` matching events have been read. Each carries the exact
string `vote_event_id` and the typed `check`; older votes and checks remain in the
journal even after a later vote. History applies both row and byte budgets and
advances only after displayed rows. `proposal_id` selects an archived decision.
Rendered MCP output is capped at 16 KiB with no partial publication. Degraded
presentation preserves a committed receipt and its no-new-key recovery rule.
Long purposes are shown as marked previews with `purpose_bytes`; proposal views
expose `snapshot_bytes` while omitting the snapshot body. Read exact text through
`pool_get section=content,field=purpose|snapshot`, with optional `proposal_id` for
an archived snapshot. Each `content` value contains the selected field, an exact
UTF-8 byte `offset`, `total_bytes` and bounded `text`; concatenate pages in cursor
order. `next_after` is the next byte offset. On continuation, supply the preceding
pool `revision` as `expected_revision`; changes return `stale` and require a fresh
first page. Non-character-boundary or out-of-range offsets are invalid. A cursor
equal to the text length returns an empty terminal page. A missing snapshot is
invalid, never an invented empty value. Short purposes preserve their prior JSON.
Messages over 2048 UTF-8 bytes are stored as consecutive journal events in one
transaction. The first keeps its original message kind; later events have kind
`message_part`. Each carries the exact decimal `message_event_id` of the first
event plus one-based `part_index` and `part_count`; concatenate all bodies in
order for the exact text. Author, target and revision are retained on every part.
Pages can begin or end inside a message, so a partial group is never complete.
Short messages retain the original event JSON. Notifications and receipts label
their first-part preview and direct readers to history. The owner observer
advertises this contract with `identity.capabilities` value `message_parts_v1`.
For participant forward history, optional `wait_seconds` from 0 to 25 holds an
empty read until an event arrives, the pool closes, or the timeout expires. Other
sections cannot wait. A resident admits at most eight concurrent waits so writers
retain connection capacity; each poll rechecks membership and the original
consumed assertion using the same consumer and request ID. These rechecks do not
renew the assertion: expiry, revocation, loss of proof or Bridge unavailability
ends the wait with an error. The original expiry is also fenced against wall-clock
rollback after the local consume began with a monotonic deadline and checked before
returning or sending a page. Observation times inconsistent with consumption or
the local starting clock are refused. A clock rollback before all observations
cannot be detected without a monotonic issuer proof. The response write is bounded
by the remaining lifetime, with the deadline checked and prioritized before each
write; a timed-out partial response is not a successful reply. Scheduling between
that check and a kernel write cannot provide an absolute byte-by-byte expiry fence.
If a full frame reached the socket before the final deadline check failed, it cannot
be recalled and the recipient may still observe it as successful.
Before returning a page the resident rechecks both authority and membership, and
retries if the pool revision changed between the two reads. Bridge revocation can
still happen after its last confirmed observation, so authority is established at
that observation rather than guaranteed at delivery; the two services do not share
a transaction. Shutdown cancels waiting reads. A contended store at the final poll
returns `unavailable` instead of a stale page; a small allowance covers that final
read. An already executing blocking SQLite operation can finish after cancellation.
The read-only owner observer remains immediate.
Participant `pool_get section=history,reverse=true` reads the newest bounded page
in ascending order; continuation uses the returned `next_before` decimal string
as the exclusive `before` boundary. New later events do not enter earlier pages.
On an empty page `next_before` is `"0"` and `has_more` is false; do not reuse it
as `before`. Reverse reads cannot combine a positive `after` or `wait_seconds`.
For live follow, resume separately from the highest event ID initially observed.

## Qualification and deployment

The repository remains `not_verified`, with no qualified targets or hosts, until
real native sessions pass the cross-product scenarios. CI defines native source
checks on both candidate targets; those checks and local domain and transport
fixtures do not substitute for native identity, message delivery or installed-version
evidence. CI additionally builds and verifies archived Linux x86-64 and macOS arm64
candidates, retained as workflow artifacts for seven days; the macOS candidate is
built on main and manual runs. Release is disabled. Its workflow requires a
manual dispatch on an annotated version tag and an explicit target selection;
pushing a tag cannot start publication. The `paired` selection requires
independently tested macOS and Linux payloads from the same source and CI run.
The `linux-only` selection does not run or qualify macOS. The publisher verifies
every selected bundle and bootstrap file before opening one draft; Linux
acceptance is bound to the binary and manifest hashes reported by its native job.
These checks trust the CI run and do not establish
cryptographic provenance or isolate the acceptance process from a hostile
program running as the same CI user. Protocol tests are compiled before the
candidate executes and their bytes are checked around acceptance.
The Linux candidate is built on Ubuntu 24.04 and requires a compatible GNU libc;
older distributions have not been verified.
The Bridge SDK dependency is pinned to an exact candidate commit; an unpublished
local candidate is not a remotely available release.

Configuration is explicit; see `config.example.toml`. Provision the protected
producer/audience and MCP profile through the existing deployment authority. The
Pool producer needs SelfActor registration, its assertion audience, direct-address
Message delivery with KeepAll, kind `agent_pool`, and delivery scopes. Observation
uses a separate opt-in credential. Missing Run leaves external-agent pools usable.
Run defaults to the same-user private socket policy. Linux can opt into a different
`run_peer_uid` only with a full identity UID map and a Run-owned socket without
other access or special bits. Every ancestor must be owned by root or that peer,
with no group/other write; the immediate parent must also deny other access. Pool
checks the connected peer UID and rechecks path identities before sending requests.
Existing OS permissions still decide access. This option changes neither the Pool
listener nor Bridge endpoint and credential checks.
No host registration, credentials, resident service, legacy migration or release is
silently installed by the binary or source checks.

## Owner Hub observation v1

An optional `owner_observer_credential_file` enables a separate ingress on the
existing resident socket. The operator provisions this private same-user 0600
file in a 0700 directory. Provisioning the grant and activating a configured
resident are separate owner actions; neither is performed by `observe`.
The Bridge observation credential above retains its existing, independent role.
Native participant calls still consume Current assertions, including reads and
replay. Owner ingress cannot represent any participant command and never creates
a native actor, leader, membership or assertion consumption.

`agent-pool observe --config /absolute/config.toml` accepts exactly one bounded
UTF-8 JSON line on stdin followed by EOF, and emits one JSON line. Input is
`{"schema_version":1,"operation":"identity|list|get","params":{...}}`.
`identity` requires `{}`; `list` accepts `after` (last pool ID). `get` requires
`pool_id`, accepts numeric `after` (default 0), `section` (default `overview`),
`proposal_id`, `member_id`, `field`, `include_bindings` (default false), and optional
`expected_revision`. Continuing overview/members/votes/content with `after > 0` requires
the preceding `view.pool.revision` as `expected_revision`; changed revisions
return `stale` rather than silently skipping rows. Restart that section at zero.
Sections are `overview`, `members`, `history`, `proposal`, `votes`, `criteria`, `content`, `deliveries`,
`binding`, `decisions`, `run_proof`. Binding requires an exact current/removed `member_id`;
roster mappings appear only with `include_bindings:true`. Archive enumeration
includes open, stale and accepted proposals without votes; use exact proposal ID
with proposal/votes sections for independent evidence pages.
`content_pages_v1` advertises the content contract above; the observer's `cursor`
is the exact decimal byte offset and continuations require `expected_revision`.
`identity.capabilities` includes `structured_acceptance_v1` when the criteria and
check contract above is available. Criteria appear only in `view.pool.acceptance`
of the `criteria` section; an absent value means the pool uses the original
single-evidence contract. The criteria cursor is a decimal offset. For structured
ballots, `view.pool.proposal.votes[member_id]` contains `checks_count` and the
exact string `vote_event_id`; `checks_met:false` records a ready vote that does
not count. Read the next `checks_count` matching `vote_check` events through
`history` after that ID. On the opt-in history window use its string cursor and
`event_id_exact` for event navigation, including IDs beyond JavaScript's exact
number range. `check` and `vote_event_id` are omitted from unrelated events.

Success is `{schema_version:1,kind:"identity|pool_page|pool_detail|run_proof",data:...}`.
Failure has the same family (or `error` for undecodable input), `error` instead
of `data`, and fixed `code`, `outcome` (`blocked|unavailable`), `detail` fields.
Inventory data has `pools:[{pool,leader_id}]`; detail has `section`, `view`
(the existing typed section), `leader_id`, optional `bindings`, and `decisions`.
Both page families include `cursor` (string; get also accepts exact decimal text),
`has_more`, `returned`, `observed_at_unix_ms`, `source_timestamp`, `coverage`.
Identity contains product, compiled package version, embedded qualification,
capabilities and observed time, without claiming an installed/source revision.

### Run execution evidence v1

`identity.capabilities` advertises `run_proof_v1`. An owner can request one exact
current or removed member using `get` with `section:"run_proof"`, `pool_id` and
`member_id`. Supply the displayed roster revision as `expected_revision`; the
resident returns `stale` if the revision or binding changes while Run is read.
Pagination, history, proposal, content and `include_bindings` parameters do not
apply. The result has kind `run_proof` and data containing `pool_id`, `member_id`,
`pool_revision`, `current`, and Pool's `observed_at_unix_ms`.

With `state:"observed"`, `store_id` identifies the fenced Run store and
`run_observed_at` is its separate snapshot time in Unix seconds. `proof.status`
contains the requested `selector`, `canonical_agent_id`, `match`, `pin_id`,
`pin_state`, `selected`, `retained_latest`, `coverage`, `restart_resume`,
`lineage_terminal`, `terminal_outcome`, `success_commit`, and `cleanup`.
`selected` and `retained_latest` are nullable execution facts with `sequence`,
`execution_ref`, and `raw_status`; the outcome and success commit describe
`retained_latest`, as stated by `proof.outcome_scope`. `proof.historical_success`
is true only when the selected incarnation is the verified successful retained
tail with complete pinned lineage coverage and confirmed cleanup. It is a
historical database fact, not a guarantee that an answer file is still available.

With `state:"unknown"`, `reason` is `incomplete_binding`, `origin_unavailable`,
or `run_unavailable`; `proof` and `run_observed_at` are absent. A known `store_id`
may still be returned. A Run selector mismatch can instead be an observed status
whose `match` is `mismatch`; it is never a positive proof. Every result has
`author_identity:"unknown"`: no response authenticates a worker, current attempt,
transcript or answer. This is one member's snapshot, not an atomic proof of the
whole pool or permission to complete or replace a member.

### History window v1

Identity advertises `history_window_v1` when opt-in history windows are supported.
The original history request with only `after` retains its previous response.
For an exact window, set `direction` to `backward` or `forward`; `after`, `before`
and `through` accept nonnegative JSON integers or canonical decimal strings within
SQLite's signed 64-bit range. `before` is exclusive, positive and valid only with
`backward`; a backward request requires `after=0`. `before` and `through` without
an explicit direction, or any history-window field on another section, are invalid.

Backward without `before` returns the newest page, ordered oldest to newest. Its
`history_watermark` is the exact decimal string of the pool's latest event at that
read, or `"0"` for an empty history. Each event adds `event_id_exact` as a decimal
string. Continue backwards with `before=cursor` and `through=history_watermark`;
`cursor` is the oldest displayed event ID. An empty backward page has cursor `"0"`,
`view.next_after=0` and `has_more=false`.

For a bounded export, start forward at `after="0"` and keep the original watermark
as `through`; the server includes events through that ID and returns the same
watermark on every page. `through="0"` remains an empty snapshot even if events
arrive later. For live follow, start forward at `after=history_watermark` without a
fixed `through`. Forward cursor is the newest displayed event ID, or the supplied
`after` on an empty page. Pages remain limited to three events and 10 KiB of source
event data, and never silently skip an oversized row.

All nonzero cursors and watermarks must identify existing events of that pool; a
future, foreign or missing ID, or a cursor beyond `through`, returns `stale`.
Malformed, overflowing, noncanonical or contradictory arguments return `invalid`.
`view.next_after` remains the legacy JSON number and mirrors the directional cursor;
clients needing exact 64-bit IDs must use the string `cursor`, `history_watermark`
and `event_id_exact`, not the numeric duplicates. Omit `expected_revision` when
following a fixed history window across unrelated pool changes: if supplied, it
still fences the current whole-pool revision. The event watermark does not freeze
roster, votes, delivery state or any other section.

Reads use the resident's already-owned Store connection without write
transactions, claims, reconciliation or outbox flush. The `run_proof` section
also makes one read-only Run status request against the original verified store;
other sections do not contact Run. The leader
is independent of the roster; Run completion, voting, decision acceptance and
delivery are separate facts. Inventory orders by pool ID; archive orders by
retained proposal insertion sequence; other sections preserve existing cursor
semantics. Pages observe current state independently; mutable offset sections
require the revision fence on continuation.
Store schema v5 has no historical timestamps: `source_timestamp:null` and
coverage text disclose that absence. Complete encoded envelopes including the
newline are capped at 1 MiB; oversized results fail explicitly without partial
publication or silently advancing a cursor. Resident exchanges use the existing
finite transport timeout; stdin waits for EOF without an execution deadline.
No observer configuration, grant, release qualification or service is installed.
