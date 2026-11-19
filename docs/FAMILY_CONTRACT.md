# Family contract summary — target 1.0.0-rc.2

1. Every family product is Rust. This is a family invariant, not a default.
2. Cargo workspace/application conventions are mandatory: edition 2024, resolver 3,
   pinned toolchain, committed lockfile, shared lints, publish=false.
3. Repository automation belongs in Rust `xtask`; shell is bootstrap/glue only.
   Python/Node are not family development dependencies.
4. Separate process topology from source of state. A resident is not a reason to add a DB.
5. One product identity from Cargo; compiler, SDK, protocol, config/state and IPC versions are distinct.
6. One authoritative tool contract, stable discovery snapshot, truthful hints and typed errors.
7. Bound input/output/deadlines/queues. Cancellation does not prove a remote mutation was undone.
8. A request ID is not idempotency; document deduplication and recovery.
9. Product HOME is explicit and test-isolated. Secrets never enter tool args or logs.
10. Build once and test the shipped payload; bind release identity to exact artifact bytes.
11. Published tags/assets are immutable; install atomically into immutable version directories.
12. Release publication, installation and agent notification are separate outcomes.
13. A shell background process does not prove an agent was awakened.
14. Unknown/skipped/unimplemented acceptance remains not_verified.

### Pool chat v1

The Linux owner ingress advertises exactly eight tools separately from the legacy
managed catalog. The resident private socket hosts the Run-facing
`chat_catalog_v1` and `member_call_v1` JSON-RPC methods. Both require
`version: 1`. Membership refusals are JSON-RPC errors with code `-32000`
and `data.kind` set to `not_member`, `seat_retired` or `pool_closed`. The
inter-service wire contract is
`contracts/pool-chat-v1.md` in the Agent MCP family checkout. The
observer `completion_get` header data can also be an ordinary chat agreement
with `version: 1`, `completion_id`, `pool_id`, `revision`, `event_id`,
`proposal_id`, `roster_key`, `result`, and per-seat `ballots` references.

A seat that is awaiting its Run receipt returns JSON-RPC `-32000` with
`data.kind=admission_pending` and `data.retry_after_ms`. Observer inventory rows
and get details expose `kind` (`chat` or `managed`) and `completion_id` when
completed. Chat rows in `pools[].roster[]` and `view.members[]` expose
`seat_id`, nullable `run_agent_id`, `profile`, `admission` and `joined`.
Admission is `pending`, `admitted`, `refused` or `unknown`. Group observer
chat history includes direct and owner-only messages only for peers also
allowlisted on owner ingress.
