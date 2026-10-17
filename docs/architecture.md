# Agent Pool architecture

Agent Pool owns persistent pools, permanent global leaders, membership incarnations,
shared history and consensus on one macOS host. It is a separate resident process
with a private Unix socket and SQLite database. The stdio MCP process is a frontend;
its EOF never starts, stops or replaces the resident.

## Boundaries

- `domain.rs` defines strict flat commands, safe public views and private outbox work.
- `store.rs` owns the single SQLite writer and synchronous transactions. A process
  lifetime file lock excludes a second writer. WAL, full synchronization, foreign
  keys and schema version 1 are explicit. Future schema versions refuse to open.
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
Run members also require a fresh exact-sequence communication observation at join.
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
stable globally unique request key before I/O. A receipt is saved immediately even
before address resolution. Unknown starts reuse that same specification and key;
there is no replacement launch. Removed known admissions remain recorded.

`pool_get section=deliveries` exposes safe per-operation states without private
addresses. Separate system observations record actionable failures and notify the
owner; ordinary conversation and consensus do not subscribe the owner to delivery.

## Consensus and bounded reads

One open proposal freezes result, criteria and confirmed membership/assignments.
An explicit replacement at the current revision archives the prior open proposal
and its votes as stale, then requires fresh votes on the new result and criteria.
Only those members vote. Ready requires evidence; block and revoke remain in the
journal. Unanimity accepts a decision. Membership/assignment changes stale an open
proposal; accepted decisions are independently archived and immutable. No vote,
completion or observation closes a pool automatically.

The current roster is limited to 20 pending/confirmed members. Names, roles and tasks
have byte limits of 80, 160 and 512; messages and individual evidence fields 2048.
Notifications contain explicitly marked short roster previews; exact assignments
remain available through paged `pool_get`. Sections separately page roster, history,
proposal, votes and delivery states. History applies both row and byte budgets and
advances only after displayed rows. `proposal_id` selects an archived decision.
Rendered MCP output is capped at 16 KiB with no partial publication. Degraded
presentation preserves a committed receipt and its no-new-key recovery rule.

## Qualification and deployment

The repository remains `not_verified` for release until real supported native
sessions pass the cross-product scenarios. Local domain and transport fixtures do
not substitute for native identity, message delivery or installed-version evidence.
The Bridge SDK dependency is pinned to an exact candidate commit; an unpublished
local candidate is not a remotely available release.

Configuration is explicit; see `config.example.toml`. Provision the protected
producer/audience and MCP profile through the existing deployment authority. The
Pool producer needs SelfActor registration, its assertion audience, direct-address
Message delivery with KeepAll, kind `agent_pool`, and delivery scopes. Observation
uses a separate opt-in credential. Missing Run leaves external-agent pools usable.
No host registration, credentials, resident service, legacy migration or release is
silently installed by the binary or source checks.
