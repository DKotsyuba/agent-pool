# Pool immutable completion record — design

Status: P3-C implements the v1 subset chosen by owner decisions C1–C4 (automatic
settlement, non-gating notice, final completion, per-saga protected key); see
`docs/architecture.md` "Formal completion ledger" and the Completion section of
`contracts/pool-p1-wire.md`. The open questions below record the remaining
trust-model limits; anti-rollback anchoring, key rotation, export and deletion
policy are not implemented.

The original design text follows. Accepted proposals,
closure, delivery, and Run success are separate facts. Completion requires the
later attempt-binding agreement, an authenticated Run hold, and one atomic Pool
transaction; an observer must never acquire a hold.

## Record and atomic boundary

One immutable, uniquely identified `completion_id` is created at most once for a
Pool settlement. The transaction must compare and freeze the exact pool identity,
store identity, expected Pool and roster revisions, full roster and bindings,
current proposal and its sequence, authenticated ballot evidence and the held
Run facts. It creates the completion record and a durable release intent together;
it must serialize with abort and late store tasks. A timeout, cancellation,
missing lookup, failed presentation or process death is not proof of abort. A
recovery worker reconciles the original durable intent, route and store, hold
identity and protected signing key before authenticated release. No network I/O
is performed inside the Pool SQLite transaction. The record is append-only;
subsequent cleanup or notices need separate immutable, linked observations rather
than overwriting the original evidence.

The frozen record must include:

- completion ID, Pool store ID, Pool ID, transaction/record version and commit
  sequence; any time is labelled as an observation rather than ordering proof;
- exact goal and structured or legacy criteria, exact proposed result and optional
  snapshot bytes, proposal ID and insertion/event sequence, and whether the
  snapshot was absent or empty;
- roster revision and exact frozen ordered membership incarnations, assignments,
  and binding/attempt references needed to verify eligibility; leader separately;
- all relevant ballots, choices, exact checks and evidence, journal sequence
  references, author/attempt proof provenance and verification version, including
  explicit unknowns where a fact cannot be proven; only fully verified required
  ballots can authorize a new settlement;
- exact held Run store, original route identity, hold ID/fingerprint and retained
  execution/pin references, facts and cleanup observations used for the CAS,
  their scope, source revisions/coverage and uncertainty; historical success is
  never by itself author authentication;
- exact notice intent/recipient and its durable operation ID, plus known delivery
  outcome without equating custody or handoff with recipient processing; and
- a versioned integrity binding over an unambiguous canonical representation of
  all frozen fields and linked evidence, with domain separation, byte lengths,
  field order, algorithm identifier and published test vectors. It detects
  accidental or malicious alteration only within the stated key/trust model;
  a plain digest is not proof of authorship or rollback resistance.

Secrets, signing material, worker tokens and private assertion credentials must
not appear in the record's owner projection, logs, cursors or model-visible text.
Protected secret storage and recovery are separate from public evidence.

## Owner read and retention

A future advertised owner capability should retrieve by exact Pool and
completion ID, with a compact immutable header and bounded pages of exact content,
roster, ballots/checks, Run facts, cleanup and notice observations. Every page
must bind completion ID, record version/digest, section and exclusive cursor;
separately paged byte content needs exact offsets, total length and digest. A
missing, expired, foreign or mismatched cursor fails explicitly; empty pages are
unambiguous and no oversized row or evidence is silently omitted. Owner access
uses the separately provisioned read grant, performs no hold or write, and does
not expose protected proof secrets. Advertise this only after its complete wire,
limits, behavior, recovery and tests exist.

Retention must preserve the record and all evidence needed to verify it for as
long as the associated Pool is counted completed. Deletion must be a deliberate
policy with an atomic count/coverage transition, never inferred from a missing
Run history or an expired hold. A release allows external Run pruning and does
not establish that historical facts remain retrievable. If an audit requires
evidence beyond that lifetime, explicit export/retention authority is required.

## Open questions before implementation

1. What attempt-bound authority, expiry semantics and durable admission right do
   Run, Bridge and Pool jointly guarantee, including resume and late commits?
2. What exact canonical encoding, hash/signature algorithm, key custody, rotation,
   test vectors and anti-rollback or external anchoring, if any, are required?
3. Which Run facts and cleanup/notice stages are mandatory at settlement versus
   immutable later observations, and how are failed or unknown stages represented?
4. What owner evidence fields, size bounds, pagination and authorization are safe
   across products, including provenance that is sensitive but audit-relevant?
5. What exact retention period, deletion authorization, linked evidence lifetime
   and migration policy govern completed and legacy pools?
6. What is the recovery procedure for a lost hold-release key, restore or clone,
   and which authority may decide an orphaned intent?
