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
  keys and schema version 15 are explicit. Future schema versions refuse to open.
  Schema v1–v14 upgrades transactionally to v15 before use; older binaries must
  refuse v15 because they cannot preserve newer durable state. The v5 replacement
  and stable-slot migration and v6 inventory revision fence remain in that upgrade.
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
a sampled address also does not identify the current attempt. Managed calls need
the original Bridge observation and the pinned Run proof described below. Managed
join opens only for an owner-enrolled P3 root (see "P3 managed enrollment and
replacement"); manual or ordinary Run roots stay refused, admission is not proof
that onboarding succeeded, and fresh managed delivery requires the separately
enabled egress path below. Unverified historical mappings are not authority
and their runtime projection is unknown. Old Run-managed ballots remain
`validity:unknown` and cannot count toward a new acceptance; already accepted
historical decisions remain unchanged. Bridge-only participants remain available.
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

Qualification is `verified` for `x86_64-unknown-linux-gnu` on the host `dobi` only
(see the 0.1.0 changelog for the evidence); `aarch64-apple-darwin` remains a
candidate target without qualification. Managed attempt binding requires Run, Pool,
the Bridge worker and the agents to run under one UID; multi-UID is not supported.
CI defines native source
checks on both candidate targets; those checks and local domain and transport
fixtures do not substitute for native identity, message delivery or installed-version
evidence. CI additionally builds and verifies archived Linux x86-64 and macOS arm64
candidates, retained as workflow artifacts for seven days; the macOS candidate is
built on main and manual runs. Release is enabled for qualified targets only. Its workflow requires a
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
configuration also requires `bridge_server_executable` and `bridge_server_sha256`;
there is no inferred managed-server pin. The B1 SDK checks that exact loaded build
on the same socket before sending any request or credential. Changing an existing
configuration to include these fields is an operator action, not an installation.
The Pool producer needs SelfActor registration, its assertion audience, direct-address
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
`{"schema_version":1,"operation":"identity|list|get|inventory_snapshot|managed_capacity|completion_get","params":{...}}`.
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

Success is `{schema_version:1,kind:"identity|pool_page|pool_detail|run_proof|inventory_snapshot|managed_capacity|completion_page",data:...}`.
Failure has the same family (or `error` for undecodable input), `error` instead
of `data`, and fixed `code`, `outcome` (`blocked|unavailable`), `detail` fields.
Inventory data has `pools:[{pool,leader_id}]`; detail has `section`, `view`
(the existing typed section), `leader_id`, optional `bindings`, and `decisions`.
Both page families include `cursor` (string; get also accepts exact decimal text),
`has_more`, `returned`, `observed_at_unix_ms`, `source_timestamp`, `coverage`.
Identity contains product, compiled package version, embedded qualification,
capabilities and observed time, without claiming an installed/source revision.

### Source-wide inventory snapshot v1

Identity advertises `inventory_snapshot_v1`. This owner-only operation is distinct
from `list`: it returns exact source-wide retained totals and a page of complete
current rosters from one SQLite read transaction. It never calls Run or Bridge.
For example, request:

```json
{"schema_version":1,"operation":"inventory_snapshot","params":{"filter":"all","limit":1}}
```

The following abbreviated identifiers illustrate the exact JSON shape (actual IDs
are opaque). Unlike totals and source revision, `limit` and `returned` are JSON
integers; all counts and the source revision are canonical decimal strings:

```json
{"schema_version":1,"kind":"inventory_snapshot","data":{"source":{"store_id":"store-uuid","read_epoch":"epoch-uuid","revision":"42"},"totals":{"total":"2","open":"1","completed":"1","unknown":"0","closed":"1"},"coverage":"Retained Pool rows only. Completed counts pools with a committed immutable completion record; every other retained pool is open, including accepted, closed, delivered or Run-succeeded pools without a record and all pools from before the completion ledger. Closed is independent of completion. Pages and totals share one Pool SQLite snapshot; no cross-service or clone/restore anti-rollback guarantee.","pools":[{"pool":{"pool_id":"pool-a","name":"Example","purpose":"Goal","revision":1,"closed":false,"proposal":null},"leader_id":"leader-id","roster":[{"member_id":"member-id","name":"Worker","role":"Implement","task":"Check","state":"active","runtime":"unknown"}]}],"returned":1,"has_more":true,"next_cursor":{"version":1,"source":{"store_id":"store-uuid","read_epoch":"epoch-uuid","revision":"42"},"filter":"all","limit":1,"after":"pool-a"},"observed_at_unix_ms":1730000000000}}
```

`filter` is required and is `all`, `closed`, or `not_closed`; it selects page
rows only. `limit` is required and is an integer 1–10. `cursor` is omitted or
null on the first page; pass the entire previous `next_cursor` and the same
filter and limit on the next request. Do not construct or alter cursors. Order
is ascending pool ID; `after` is exclusive. A cursor is an explicit binding,
not an authentication token. Source, epoch, revision, filter, limit and a retained
matching boundary are checked on continuation. Any mismatch is `stale`; restart
at the first page. Invalid arguments and unknown cursor versions are `invalid`.
An empty page has `returned:0`, `has_more:false`, `next_cursor:null`; a nonempty
terminal page also has a null cursor. Every page may fail as a whole with an
`unavailable` error if its complete encoded envelope exceeds 1 MiB. No row or
roster is silently cut to fit. For example, an empty response's data has
`"pools":[],"returned":0,"has_more":false,"next_cursor":null`.

Continuing the illustrative first page uses:

```json
{"schema_version":1,"operation":"inventory_snapshot","params":{"filter":"all","limit":1,"cursor":{"version":1,"source":{"store_id":"store-uuid","read_epoch":"epoch-uuid","revision":"42"},"filter":"all","limit":1,"after":"pool-a"}}}
```

For example, if the store changed, the response is
`{"schema_version":1,"kind":"inventory_snapshot","error":{"code":"stale","outcome":"blocked","detail":"Observation refused; check request and separately provisioned owner read grant."}}`.
There is no `data` branch in an error; restart the inventory instead of mixing
pages from different source revisions.

Totals count retained rows across the whole store, independent of the filter.
Identity also advertises `inventory_completion_v1`: `completed` counts retained
pools with a committed immutable completion record and `open` every other
retained pool, read in the same snapshot as `total`, so `total=open+completed`
and `unknown` is `"0"`. Accepted proposals, closure, delivery and Run success
alone never count as completed; the schema v12 upgrade creates no records, so
every pre-existing pool is open. `closed` counts the independent closure flag.
The completion commit and the source revision advance in one transaction.
Retention-deleted rows are outside all these counts; v1 deletes none.

Each row contains the existing pool metadata projection (purpose may be a marked
preview with `purpose_bytes`; proposal and criteria are omitted), the stable
leader ID separately, and the complete current roster in stable slot order.
The roster includes pending and active incarnations, not removed ones or the
leader. It uses the existing member fields and excludes private bindings; managed
Run members retain `runtime:"unknown"`. This operation does not authenticate
attempts or change the fail-closed managed participant guard.

Schema v6 adds a random durable `store_id` and a signed-64-bit nonnegative source
revision, initially `"0"` on migration. Transactional triggers increment the
revision on inserts, updates and deletes of durable state tables; even private or
background changes can invalidate a cursor, except completion saga and observation
bookkeeping; the completion record itself advances the revision. An overflow aborts the write. A fresh
random `read_epoch` is created each time the Store opens. Neither reopening nor
the revision is a wall-clock timestamp. Clone/restore can preserve a store ID and
roll back its revision, so this is not anti-rollback or a cross-service snapshot.

### Formal completion ledger (P3-C) and completion_record_v1

Owner decisions C1–C4 are final: settlement is automatic in the resident (no
owner-finalize operation), the owner notice does not gate completion, completion
is final, and each saga has its own protected Ed25519 release key. Automatic
settlement is enabled only when both `run_socket` and the managed consensus
transport are configured; otherwise no new settlement starts and unfinished
sagas require the original route for recovery.
Observers, Hub reads and `completion_get` never acquire or release holds.

A pool becomes a candidate when its latest proposal is accepted, it has no
record or unreleased saga, no pending start, batch or replacement admission, and fewer than three sagas were already attempted for
the same proposal and pool revision. One read snapshot must show every frozen
voter current and active with a ready ballot (all checks met when structured),
no legacy `Unknown` ballot, and, for each Run member, a managed attempt binding
with matching generation, incarnation and committed ballot provenance. Non-Run
native voters keep their existing Bridge-verified ballot. Ordinary Run members
without an attempt binding are never eligible. At least one and at most twenty
Run lineages, all in one Run store, are required; multi-store settlement is
refused. Before preparing, the resident freshly asks Run consensus for every
managed voter (only `terminal_no_successor` with the exact attempt and
incarnation qualifies) and reads Run status for the retained latest execution:
active original pin, complete coverage, recorded successful terminal commit and
confirmed whole-lineage cleanup. These reads have no effect and leave no local
currentness request rows. Ineligible candidates back off exponentially per
proposal and revision, up to five minutes; a local revision change permits an
immediate recheck.

The saga stages are `prepared -> acquire_possible -> held -> committed|aborted ->
release_pending -> released`, stored in `completion_sagas`. A fresh key file
(32-byte seed, mode 0600, in the store's own 0700 directory
`completion-keys/<Pool store UUID>/` beside the database) is fsynced before the
saga row records only its opaque reference and public key. Several Pool
databases may share one private parent: each durable store identity has its
own key directory, so one store's startup can never remove or race another
store's keys. Every key operation rechecks owner, mode and non-symlink status of
the shared root and the store directory, whose device and inode are pinned when
the resident opens it. The row freezes the complete settlement (`agent-mcp/pool/completion-settlement/v1`
digest, also the hold `intent_digest`), the configured Run route and store, the
hold request ID `agent-pool.completion.<saga>`, ordered targets and roots and the
hold fingerprint; triggers make these fields and the terminal outcome immutable.
`acquire_possible` is durable before the first `_lineage_hold_acquire`. A lost
or failed acknowledgement is recovered by exact lookup and, after an absent
snapshot, exact replay of the same request; never a new request ID or key. A
replay or lookup that observes `released` aborts without a CAS. A correlated
Run `RequestConflict` on the first acquire terminates without a hold; a refusal
after an uncertain earlier attempt remains unknown. After three
uncertain acquire attempts the Pool outcome is fenced as aborted while exact
replay continues, so any late hold is found and released, never committed. No
new saga for that pool starts until the earlier saga is released. Recovery uses
exponential retry delays capped at five minutes.

With the hold active, Run consensus and status are read again outside SQLite.
Live or superseded voters, unverifiable facts or a changed snapshot abort; three
unavailable reads abort. The single immediate transaction then re-derives the
frozen settlement and compares every field (pool revision and data, proposal and
ballots, roster, slots, managed generations/incarnations, invalidations and
binding epoch), checks each held fact, appends the immutable record, advances
the pool revision, journals `pool_completed`, queues one owner notice and marks
the saga committed. Abort claims the same exclusive outcome, so a late commit
loses to a durable abort and vice versa. The release message is signed with the
saga key only after the outcome is durable and `release_pending` is stored; a
verified receipt, linked to the record as an immutable observation, precedes
key deletion. A missing or substituted key or a changed configured route leaves
the saga at its stage with a nonsecret `attention` code (`key_unavailable`,
`route_changed`, `outcome_unknown`, `release_unknown`, `hold_unavailable`,
`run_unavailable`): there is no TTL unlock and no key regeneration. Restoring the
original key file or route resumes the same saga. Unexpected driver errors are
recorded as `internal_error` and retried with backoff. If the driver cannot
start, unfinished sagas receive `key_unavailable` or `route_changed`, the
resident logs the condition, and owner identity capabilities include
`completion_attention_<code>` while that condition persists. Startup first
migrates the earlier shared flat layout once: only `<reference>.key` files that
this database's sagas still own (unreleased, or released with the key not yet
destroyed) are atomically renamed into the store's directory, never over an
existing key, and both directories are fsynced. Nothing in the shared root is
ever deleted; other legacy files (other stores' keys, staging files) stay and
the resident logs only their count. Startup then removes unreferenced key and
temporary files inside the store's own directory while preserving keys of all
unreleased sagas. Ed25519 signing keys and transient seeds are zeroized on drop. The
record preserves Run's exact status timestamp text.

C3: once a record exists, update, add, start, batch, replace, cancel
replacement, assignment change, remove, join, propose and vote return `closed`;
the text states that the pool is completed, not explicitly closed (internally a
distinct `completed` refusal).
Late admission receipts cannot change a completed pool. When a start, batch or
replacement admission (including one found by recovery) arrives after
completion, one transaction retains the exact receipt identifiers in the
immutable `completed_admissions` table (schema v14), moves the effect to the
terminal state `reconciliation_needed` (never redelivered, never overwritten by
a later settlement) and queues one deduplicated owner reconciliation notice;
the resident worker continues with other work. An identical replay returns the
same outcome; a different receipt for that effect conflicts. Eligibility is checked again in the
completion transaction, including pending admission effects.
Reads, messages, explicit close, history-pin release and recovery continue.
Records and observations cannot be updated or deleted. Saga intent fields and
terminal outcomes are immutable; recovery advances its stage and observations.

`completion_get` (capability `completion_record_v1`) takes
`{pool_id,completion_id,section,after,limit}` with section `header`, `content`,
`roster`, `ballots`, `run_facts` or `notice`, `limit` 1–10 and `after` null or
the previous `next_cursor`. Every read re-verifies the record digest. Pages bind
completion ID, record version, digest, algorithm and section; cursors bind the
digest and section and a foreign, stale or out-of-range cursor fails. Content
slices are at most 16384 bytes at UTF-8 boundaries with exact field, offset,
total length and SHA-256; an absent snapshot has no slice, an empty one has one
empty slice. No key, key reference, signature or path appears. The complete wire
and canonical vectors are in the Completion section of `contracts/pool-p1-wire.md`.

### Managed attempt binding (P-context and P1)

The optional `managed_run_reader` grant configures a separate same-UID Run reader
by absolute executable, SHA-256, exact Run store/route and Bridge store/route/
producer. Its private `_managed_intent_outcome_v1` and
`_managed_namespace_seal_v1` calls verify the connected kernel peer and loaded
executable before accessing the Store. A namespace seal fences later local work;
it reports `draining` until tracked abort and settlement recovery is durable.
The exact proposed wire is in the shared `contracts/pool-p1-wire.md`.

Pool verifies every pinned Pool or Run peer on Linux before it sends or
accepts any bytes, following errata E13/E14 of the attempt-binding
contract. That covers the Run attempt endpoint, the Run reader on the Pool
socket, and the frontend and resident checking each other. Pool takes the PID
from the connected socket's kernel credentials. The peer must have the
expected effective UID, share Pool's PID namespace and have unchanged start
ticks. Its initial environment must have no `LD_*` variable, and
`/proc/PID/status` must show no tracer. The pinned path must be canonical and
must not name a generic interpreter (`python3`, `bash`, `node` and similar).
`/etc/ld.so.preload` must be absent or blank. Pool opens `/proc/PID/exe` and
checks that descriptor for all of the following:

- its inode equals the inode at the configured path;
- it is currently a regular file of at most 512 MiB, owned by the Pool UID or
  root, that group and other cannot write;
- its `mnt_id` from fdinfo resolves to exactly one mountinfo record of type
  ext2/3/4, xfs, btrfs or tmpfs, where the kernel denies writes to a running
  executable;
- its own SHA-256 equals the pin.

After hashing, Pool requires the following to be unchanged: the descriptor's
full identity (dev, ino, owner, mode, size, mtime, ctime), the link target, the
configured path's inode, the process facts, the environment and tracer checks,
and the preload list. Any unreadable, ambiguous or changed fact fails closed.
Pool refuses overlay, network and FUSE filesystems. Non-Linux platforms have
no such evidence and refuse these routes. Wall-clock time is never used.
Accepted residuals, the same as Run's own peer proof:

- the PID can be reused before the socket credential is read;
- a tracer can attach after the proof;
- a peer can rewrite its own environment memory after exec, which requires
  foreign code that the other checks exclude.

The Bridge managed-server proof belongs to the Bridge SDK (see
`bridge_server_executable` above). The legacy Run socket checks only the peer UID.

Schema v7 adds separate managed binding generations, binding epochs, original
contexts and rebind records; v8 adds managed intents, domain-key reservations and
ballot provenance; v9 adds an open-ballot invalidation overlay, retained binding
incarnation and current-read ownership for bounded capacity. Where migration
cannot recover an incarnation from an authenticated retained receipt, the next
attested rebind bumps its generation. Legacy members and ballots do not acquire verified provenance
by migration. The optional `managed_run_transport` pins the Run attempt endpoint
and its route independently of the legacy Run socket. `frontend_enabled` defaults
to false; enabling it requires the matching reader grant and the exact `mcp_server`
name in the Bridge tool mapping. The managed frontend is stdio-only. It and the
resident use the same Pool executable and authenticate each other on their private
connection; configure Bridge's frontend and consumer pins to the same Pool path
and SHA-256. Bridge must independently establish their different process roles.
Bridge may return `relaunch_required` when the resident predates managed-role
initialization. Pool preserves that typed refusal and tells the caller to relaunch
the resident, while retaining original request keys for recovery. It never
restarts the resident itself.

The explicit opt-in is safe only because Run issues a current receipt after the
exact launch has a durable managed-role qualification. A missing or unqualified
role returns `attempt_not_ready` or `role_unqualified`; Pool refuses the call
before participant reads, domain-key reservation or effects. The consumed
observation's `tool_name` must be the exact name the attested harness presents
(errata E16), with the harness taken only from Bridge's attested actor address:
Claude uses the raw `mcp__{server}__{command_name}`; Codex uses
`mcp__{seg(server)}__{command_name}`, where seg maps every character outside
`[A-Za-z0-9_]` to `_`; any other harness is refused. Pool refuses an
`mcp_server` whose segment is empty, starts or ends with `_` or contains `__`,
or that makes any Codex tool name longer than 128 bytes, because Codex would
trim it or substitute a hash. Bridge verifies the same mapping and Pool checks
the same association. Installed provider hook behavior remains subject to
separate dobi qualification.

For a managed call the frontend prepares the original B1 context. The resident
persists the pinned routes and original key, then asks Run for rootless ingress
currentness with that context reference and invocation key. Run resolves the
original observation and returns actor, full incarnation, attempt and a
root-to-current proof. Pool selects its member by that lineage and applies any
generation-fenced rebind before freezing the full command and context digest.
The original frontend registers it; the resident consumes it and obtains fresh
Run currentness before reserving a domain key. A definitive early-hook
`attempt_not_ready` retries the original request for a bounded local interval.
Lost prepare replies are abandoned behind a local continuation fence; if
registration or consumption may have been submitted, exact-key abort recovery
uses the original digest. Expiry is not an admission or abort proof.

The admission dispatcher retains the original intent and Run pin, commits the
domain mutation after admission and local CAS, and reconciles uncertain work by
exact key. A bounded rotating recovery worker uses per-key activity leases shared
with live operations. A consumed read or fresh replay with no new intent remains
pending until its original Bridge abort is durably recorded. Immediate managed
list and get projections recheck the captured binding in the same transaction;
managed long polls are not implemented.

### Operator re-pin after an upgrade or credential rotation

The resident never implicitly accepts a different executable path, executable hash
or Bridge credential hash. To approve an upgrade, stop the Pool resident and wait
for it to exit, then install and start the intended Run and Bridge services.
An upgrade may install a build at a new versioned path, for example
`/opt/agent-bridge/releases/0.7.1+b2666a5d02f8/bin/bridge-native-daemon`.
Update the private Pool config with the new `bridge_server_executable` and
`managed_run_transport.executable` paths and their SHA-256 values, including
`managed_run_reader` when that reader uses the upgraded Run build. Provision a
rotated Bridge credential at its existing private path.
Run `agent-pool repin --config /absolute/path/to/pool.toml`, then start the Pool
resident separately. This command does not stop or start any service. It requires
the existing private Pool store and its exclusive writer lease. It checks every
fixed route field first. Then it proves each candidate executable on disk: the
absolute path is already canonical and does not name a generic interpreter, and
it names a regular file owned by the Pool
UID or root that group and other cannot write, whose digest equals the configured
SHA-256. Only then does it authenticate both candidate service peers and their
configured stores, through the same pinned capability exchanges and live
loaded-executable proofs used by managed operation. Only executable paths,
executable digests and the credential digest may change. It refuses changed Run,
Bridge or known Pool store/route identities, worker UID, sockets, producer or
credential path with `Conflict`, and refuses an untrusted executable with
`Unauthorized`. A failed check leaves both active pins unchanged. If multiple stored route identities share
either configured endpoint, re-pin refuses the ambiguous store. A repeated command with the same identities
is a no-op and reports the same per-route generation. Each actual pin change
increments its generation; previous pins remain in the store.

The Pool route is stored with the Run pin on initial use. For migrated v10 stores,
Pool derives it from retained intents when possible. If no intent recorded that
route, the first successful re-pin records the configured Pool route; subsequent
uses and re-pins must match it. If prior intents disagree, re-pin fails closed.
Each bootstrap retains its original Bridge pin, each intent its original Run pin,
and a frozen delivery retains both original pins and target. Re-pinning never
retargets or resends them. Recovery continues only when the original route, build
and credential can still be authenticated; otherwise the original work remains
unresolved or unknown under its existing recovery rules. Preserve old binaries and
credentials if they may be needed to reconcile such work. Re-pin does not itself
settle or discard unresolved work.

A resident started with a configuration that no longer matches the stored route
pin does not exit. It refuses only the managed work that would use that route: a
pending managed delivery gets `route_unavailable` attention, a managed frontend
call gets `Conflict`, and namespace retirement waits. It logs once that
`agent-pool repin` is required. Legacy work, owner observation and unmanaged
pools keep running. Stop the resident, run `repin`, then start it again.

Consensus captures voter identities in a SQLite read snapshot, checks all voters
against Run without holding that transaction, then applies generation and roster
CAS. A superseded verified voter triggers a separately capability-gated Run egress
rebind before the old consensus attempt is aborted. A nonfinal vote can be
recorded without changing other ballots or evaluating acceptance. Egress
currentness uses its own Run capability and provides no delivery or owner handoff.
A member rebind marks that member's open ballot not-ready without changing the pool
revision; other voters can still record nonfinal votes. A freshly re-observed
actor-epoch change bumps its binding generation even if the Run attempt is the
same. The aggregate binding/roster epoch fences consensus CAS, while an unrelated
member's context is fenced by its own binding generation and the domain roster.
These refinements follow shared `contracts/attempt-binding-v1-errata.md` E1 and E7.
Managed join is open only through the P3 enrollment gate below; no other managed
participant capability is advertised. This code has synthetic coverage; actual Run/Bridge
endpoints, installed providers and managed-harness role qualification have not
been qualified together. The grant installs no service, endpoint, credential or
release.

### P3 managed enrollment and replacement

This implements the Pool side of `contracts/enrollment-p3.md` sections 2–5, 7
and 9 against Run's `contracts/run-p3-wire.md`. It is opt-in:
`managed_run_transport.enrollment_enabled = true` requires `frontend_enabled`
and an exact `managed_role` (configuration refuses either alone). Only then do
the owner's `pool_start_agent`, `pool_start_batch` and `pool_replace` take the
managed path; without the switch they keep the legacy behavior above. Turning
the switch off refuses every not-yet-submitted enrollment (no Run I/O occurred)
while exact-key recovery of submitted keys continues on their original route.

**Owner reservation.** The owner is authorized by the existing leader check in
the domain transaction before anything is reserved; participants, copied IDs
or receipts and managed participant sessions cannot reach these operations.
The owner calls through a frontend configuration without `frontend_enabled`
(the native Bridge-assertion path) against the same resident.
One transaction reserves the pending members (roster bound 20 includes them),
advances the pool revision, queues P2 onboarding seeds (awaiting binding) and
writes the schema v15 journal: `managed_enrollments` (owner, domain scope/key/
digest, Run request ID `agent-pool.enroll.<uuid>`, frozen route = Run endpoint,
Pool, Bridge routes, producer, role and public status route) and ordered
`managed_enrollment_jobs` (member, retained original spec). For a start the
complete `_managed_start_batch_v1` params and fingerprint
(`SHA256("agent-mcp/enrollment/start/v1" || 00 || C(params))`, the published
597-byte vector is a unit test) are frozen in the same transaction. Each spec
must name `profile = managed_role`; Pool adds `explicit_finish:true` and
`write:false` when absent, refuses other values, `required_mcp`,
`orchestrator` and `request_id`, and appends the onboarding text to `task`. The
receipt's `created_id` is the enrollment ID and `created_ids` the members.
Single start is a one-job batch. Identity, keys, routes, params, fingerprint,
receipt and replacement source are trigger-immutable; rows are never deleted.

**Run I/O.** A serial resident pass handles pending enrollments outside
SQLite. It is bounded and fair: a keyset cursor over the journal rotates through
every pending enrollment (64 per page, resuming where the previous pass
stopped), each unsubmitted/uncertain enrollment and each admitted unbound job
that keeps waiting (not ready, refused, uncertain) backs off exponentially
(5 s doubling, capped at 300 s; an enrollment revision change such as an owner
abort request makes it due again), and one pass makes at most 64 Run calls, so
egress, scope retirement and completion always get their turn in the same tick.
The schedule is resident memory only; a restart makes everything due again.
`reserved` -> capability check (`managed_enrollment_v1` and
`attempt_current_egress_v1`; absence refuses definitively) -> durable
`submit_possible` -> submit. A typed refusal is definitive only on that first
possible submission; later refusals are attention only. Recovery always
increments its attempt counter before I/O and then uses the original key:
`lookup` (an `absent` snapshot is never a fence) followed by same-key submit
replay, including after `request_in_progress` (a Run-prepared key, e.g. after a
Run configuration revision change). An owner `pool_cancel_replacement` of an
uncertain replacement records `abort_requested`; the resident then calls the
same-key abort: a tombstone settles `aborted` and fences any delayed submit, an
admitted key returns its original receipt and nothing is cancelled. A changed
configured route or endpoint never retargets a key (`route_changed`
attention, no I/O). The receipt is validated (store, request, fingerprint,
order, member, role, Run ID grammar, distinct roots/pins/refs, never an
already enrolled root) and installed in one transaction: start members gain
their Run root, sequence, execution reference, pin and store. A member removed
before admission, or a completed pool, leaves the job `unassigned`.
A definitive refusal fences the key with an exact-key abort; the durable abort
tombstone (`record_aborted`, reached directly, by lookup after a lost abort
response, or after a crash before `record_refusal`) releases the never-admitted
start members, scopes and queued effects in the same transaction through the
same guarded helper as a refusal (once; replacement members stay untouched).

**Generation 1.** For each admitted unbound job the resident stages a
`current_request_id` before calling `_managed_enrollment_current_v1`; the
receipt is re-read through `_attempt_current_receipt_v1` before use. A reply to
a key whose earlier exchange was uncertain resolves that key but is never used
as fresh authority. The CAS requires the live owner enrollment, the exact
admitted root, the current pending unbound member with matching Run facts, an
egress receipt anchored at the admitted execution, matching launch and role
digest qualification and an unused address; it installs the managed binding at
generation 1, sets the member address and leaves the pool revision unchanged.
`attempt_not_ready` keeps the same key and reports the Run job snapshot
(`qualification_pending`, `execution_failed`, ...) as job attention. The first
protected hook may win instead: rootless ingress whose root is an admitted,
unbound start job installs generation 1 under the same CAS, so exactly one first
binding exists; a replacement candidate is `not_ready` until switched. An
unknown root while a same-route start or replacement in the hook's pool is
still `submit_possible` (Run may have admitted it before Pool journaled the
receipt, e.g. after ACK loss) is a retryable `unavailable` (§4 `not_ready`),
never a binding; any other unknown root is forbidden. Binding, delivery accepted and join are separate
facts: delivery never activates a member.

**Join.** `pool_join` runs through the normal P1 context, Bridge consume, Run
admission and domain CAS. `managed_enrollment::join_gate` additionally requires
the owner enrollment receipt mapping this root, its recorded enrollment binding,
and the job still `bound_pending_join` (the job's own fact: it stays joinable
after the owner resolved its unbound siblings); the domain CAS then checks the
acknowledged revision and pending -> active. While pending, an enrollee may only
read (`pool_get`) and join. The legacy Bridge-only path still refuses every
Run-started member.

**Replacement.** `pool_replace` freezes the old binding, its managed generation,
slot, the reserved candidate (not yet a member), and the candidate spec (explicit
or the retained original), and freezes roster edits, close, join, proposals and
votes like the legacy replacement. The resident reads Run status for the old
lineage: a proven terminal, cleaned tip with active pin, complete coverage and no
restart becomes the frozen `precondition` (proven busy/unclean refuses before
submission). After admission and a fresh qualified candidate attestation the
resident re-reads the old tip; a moved tip (`old_resumed`) or changed old
generation (`old_rebound`) leaves attention and changes nothing. Otherwise one
transaction retires the old member (scope draining, unfrozen seeds not
delivered, frozen unknown effects retained, one final notice), installs the
candidate as a current pending member in the same slot with generation 1,
advances the revision, stales the open proposal, journals `member_replaced`
and queues the candidate's onboarding. A roster change or completion abandons
the qualified candidate as `unassigned` (root and pin retained). Retiring a
member does not forbid a Run resume of its lineage; it never regains membership.

**Owner controls and reads.** `pool_enrollment_get {pool_id,enrollment_id}` and
the observer `enrollment_get` (capability `managed_enrollment_v1`) return the
mode, state (`reserved`, `submit_possible`, `admitted`, `refused`, `aborted`,
`switched`, `abandoned`, `resolved`), revision, attention and per-job state
(`reserved`, `admitted`, `bound_pending_join`, `active`, `unassigned`,
`retired`), root, pin and binding generation; no sockets, payloads or sessions.
They never contact Run. `pool_enrollment_resolve {pool_id,enrollment_id,
expected_enrollment_revision,request_key,disposition:"retain_unassigned"}`
closes only an admitted enrollment (uncertain submissions conflict): unbound
jobs become `unassigned`, their still-pending start members leave the roster, a
failed replacement keeps the old member; jobs already `bound_pending_join` keep
their member, generation-1 binding and join eligibility; no process is cancelled and no pin
released. Pending enrollments also fence formal completion.

E11 issuer discovery failures in namespace retirement are durable
(`managed_route_attention`), retried with capped backoff and visible to the owner
as identity capability `namespace_retirement_attention_<code>`.

### Managed owner delivery

Managed egress is explicitly opt-in with `managed_run_transport.egress_enabled`,
which defaults to false. `producer_scope_prefix` must be exactly
`pool/<Pool store UUID>/`. Bridge's producer grant and Run's custody grant must
authorize this prefix. A member uses `pool/<store>/<pool>/<member>`; membership
IDs cannot be `final-notice`. Independent final notices use the shared
`pool/<store>/<pool>/final-notice` scope. Legacy delivery keeps its existing
scope and is never the fallback for a managed delivery.

Schema v10 commits an immutable seed with the originating event and payload
hash/length. Before any publish, a fresh capability-gated Run egress observation
attests the lineage, launch, actor and kernel incarnation. Pool applies any
same-lineage rebind and freezes the complete target and digest under a binding
generation CAS. No ingress context is needed. A pending observation retains and
retries its original request ID, including across restart. When Run reports the
old launch stale after relaunch, Pool fences that probe and uses a new request
ID; the old key cannot be retargeted. A reply recovered after an uncertain
currentness exchange is not fresh authority: Pool resolves the old key, then
obtains a new observation before freezing. A frozen effect is never retargeted.
The owner-facing delivery record
can expose typed, nonsecret attention such as `awaiting_root_hook`,
`relaunch_required` or `actor_unavailable`; it does not assert delivery. For
`relaunch_required`, `attention_subject` distinguishes the member process
(`member`) from the Pool resident (`resident`).

An exact known-unsent effect may be sent again only with its frozen target and
digest. Unknown effects are looked up or aborted under their original identity;
they never resend the original or lock the member against unrelated effects.
Erratum E12 (liveness): exact lookups use capped exponential backoff; after
three non-decisive results (for example `binding_unavailable`/`same_key_lookup`
when the publish never reached Bridge) Pool fences and aborts the exact original
effect with `abort_managed_owner_v1`. `accepted` resolves delivered; transport
loss or `unknown` keeps retrying with `outcome_unknown` attention. Only a durable
`aborted` lets Pool create one NEW effect (new effect ID, same event, payload
and scope) that is frozen again under the normal rules; the original stays
aborted and is never retargeted, so at most one live effect exists per event.
The `aborted` result and the successor (with its `managed_delivery_liveness`
link, schema v15) commit in one transaction: a crash cannot separate them, and
a successor refused for outbox capacity rolls the result back, keeping the
original fenced `abort_pending` until a later same-key abort succeeds.
Erratum E14(d): a proven-unsent (aborted) publish is never by itself a
deterministic refusal, so the republish is paced rather than terminal. The first
successor is created immediately; a successor that is liveness-aborted again is
republished with exponential backoff (5 s doubling, capped at 300 s, durable in
`managed_delivery_liveness.next_attempt` and gating the successor's first
publish) and owner attention `delivery_retrying_outcome_unknown` while it
retries. The pause is the only loop bound; there is never more than one live
effect per event, and delivery ends only for deterministic reasons: a
`known_unsent` `attempt_mismatch` (below), a retired scope, a removed or
replaced member, or a closed or completed pool.
A `known_unsent` result with
reason `attempt_mismatch` (Run pinned to another Bridge build) is terminal for
that generation: the effect becomes `not_delivered` with attention
`delivery_refused_attempt_mismatch`, is never resent or republished, and later
events deliver normally once a rebind produces a new generation.
Removal or replacement before freezing makes an ordinary seed not delivered.
A final notice is the exception: it may be frozen for the exact removed
membership's previously bound lineage, with a fresh Run receipt and a same-lineage
rebind, and grants no participant access. A different lineage is not delivered.
These rules implement `contracts/attempt-binding-v1-errata.md` E8–E10.

Each effect retains its original Bridge pin. New effects use the approved active
pin after re-pin, including in an already-used final-notice scope. On removal, Pool drains the exact member scope, resolves all its effects, then
records a pinned Bridge retirement receipt before requesting bounded compaction.
The final-notice scope drains when the pool closes. Uncertain effects and fences
survive restart; scope retirement never claims that an accepted or unknown effect
was recalled. Each of the active outbox and active scope sets is bounded at
100,000; terminal records and rejecting fences remain retained. Scope retirement
freezes the active pin and audience when retirement is first prepared, before
I/O, and uses the SDK's same-connection pinned Bridge method, retaining that
pin and original key after an uncertain reply. Schema v13 clears delivery-era
scope pins only on open or draining scopes; prepared retirement pins remain
immutable. Schema v14 adds only the immutable late-admission receipt table. Synthetic fakes do not qualify the Run/Bridge endpoints
or native provider delivery.

The B1 issuer namespace seal covers P1 ingress contexts, consumes and admissions.
It neither fences nor waits for P2 egress. Managed egress derives its authority
from a Run egress receipt and uses its separate B2 effect ledger and producer
scope retirement lifecycle.

The resident discovers the current Bridge issuer over the pinned authenticated
route and checks superseded issuer namespaces for drain. It waits for their
bootstraps, contexts, intents and Run/Bridge settlement, and for undelivered
egress seeds attributed to that issuer. Schema v11 records the exact namespace
on each managed-origin seed in the same transaction as its event. New owner or
legacy-origin seeds have an explicit non-issuer origin: their B2 authority is the
producer scope and Run egress receipt. Migrated v10 seeds have unknown origin and
conservatively block every issuer until terminal. Other issuers' new traffic does
not block retirement of a drained namespace.

Pool atomically fences the drained namespace and records the Run retirement
request, retirement key, Pool seal request ID and original Run endpoint before
I/O. Run authenticates Pool, fences the old issuer and calls Pool's namespace
seal; Pool accepts the already recorded seal key and returns a stable seal ID.
Run then retires the Bridge namespace. Pool records only a matching authenticated
terminal result after its own seal; unavailable services and lost replies retry
the same keys with bounded exponential backoff. A changed pin never silently
retargets a pending retirement. This implements erratum E11 and does not authorize
native delivery or claim installed-provider qualification.

The owner observer capability `managed_capacity_v1` accepts
`{"schema_version":1,"operation":"managed_capacity","params":{}}` through
the existing separately authorized owner grant. It returns a single SQLite
snapshot of active, retained, reserved, limit and reservation-adjusted headroom
for namespaces, bootstraps, contexts, intents and currentness requests, plus
bootstrap and context reservation totals. It is diagnostic, not a promise that
a future operation fits. Only active/unresolved work consumes these admission
limits; permanent rejecting keys and terminal evidence remain retained. A sealed
namespace compacts no-longer-actionable command and snapshot payloads while
preserving intent outcomes, domain replay keys, routes and remote recovery
receipts. Sealed namespace fences and per-key tombstones do not expire; retained
storage can still grow and requires operator monitoring. `doctor --config PATH`
uses that same explicitly configured owner grant to include the capacity snapshot;
without a config, `doctor` remains a nonmutating local resource check.

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
Store schema v15 has no historical timestamps: `source_timestamp:null` and
coverage text disclose that absence. Complete encoded envelopes including the
newline are capped at 1 MiB; oversized results fail explicitly without partial
publication or silently advancing a cursor. Resident exchanges use the existing
finite transport timeout; stdin waits for EOF without an execution deadline.
No observer configuration, grant, release qualification or service is installed.
