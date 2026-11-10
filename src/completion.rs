//! Formal Pool completion ledger (P3-C): frozen settlement, durable hold saga
//! rows, the single CAS that appends an immutable completion record, linked
//! later observations and bounded owner pages.
//!
//! Everything here is synchronous SQLite work. No function performs network
//! I/O; the asynchronous driver in `completion_saga` calls these steps between
//! separately awaited Run exchanges. Accepted proposals, closure, delivery and
//! Run success are separate facts: only a committed record counts as completed.
use crate::{
    domain::{Binding, CheckStatus, Choice, Criterion, Fault, MemberState, Pool, ProposalState},
    managed_state::{
        AttemptRef, Incarnation, ManagedBinding, SuccessorProof, VerifiedBallot, VoterState,
    },
    run_hold::HoldIntent,
    run_status::{ProofProjection, Target},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Current Pool schema step; steps 12-14 belong to the completion ledger.
pub(crate) const SCHEMA_VERSION: i64 = 15;
/// Version of the frozen record body and its canonical integrity preimage.
pub(crate) const RECORD_VERSION: u32 = 1;
/// Published integrity algorithm label: SHA-256 over domain, NUL and canonical C.
pub(crate) const INTEGRITY_ALGORITHM: &str = "sha256/c1/agent-mcp/pool/completion/v1";
const RECORD_DOMAIN: &[u8] = b"agent-mcp/pool/completion/v1\0";
const SETTLEMENT_DOMAIN: &[u8] = b"agent-mcp/pool/completion-settlement/v1\0";
const OBSERVATION_DOMAIN: &[u8] = b"agent-mcp/pool/completion-observation/v1\0";
/// Automatic settlement attempts for one unchanged accepted proposal and revision.
pub(crate) const MAX_ABORTED_ATTEMPTS: i64 = 3;
/// Hold v1 accepts 1–20 distinct lineages.
const MAX_TARGETS: usize = 20;
/// Exact byte budget of one content chunk.
const CONTENT_CHUNK: usize = 16384;

/// Test fixtures simulate a pre-completion store by removing exactly this step.
#[cfg(test)]
pub(crate) const TEST_DROP_SCHEMA: &str = "DROP TABLE managed_delivery_liveness; DROP TABLE managed_route_attention; DROP TABLE managed_enrollment_jobs; DROP TABLE managed_enrollments; DROP TABLE completed_admissions; DROP TABLE completion_observations; DROP TABLE completion_records; DROP TABLE completion_sagas;";

/// Installs saga, record and observation tables with immutability triggers.
/// Pre-feature pools receive no record: they are classified open, never inferred completed.
pub(crate) fn migrate(db: &Connection) -> Result<(), Fault> {
    db.execute_batch("\
CREATE TABLE completion_sagas(id TEXT PRIMARY KEY, pool TEXT NOT NULL REFERENCES pools(id), proposal TEXT NOT NULL, source_revision INTEGER NOT NULL CHECK(typeof(source_revision)='integer' AND source_revision>=0), frozen TEXT NOT NULL, frozen_digest TEXT NOT NULL, run_store_id TEXT NOT NULL, run_route TEXT NOT NULL, hold_request_id TEXT NOT NULL UNIQUE, hold_targets TEXT NOT NULL, hold_roots TEXT NOT NULL, verifying_key TEXT NOT NULL, key_ref TEXT NOT NULL UNIQUE, intent_digest TEXT NOT NULL, hold_fingerprint TEXT NOT NULL, stage TEXT NOT NULL CHECK(stage IN ('prepared','acquire_possible','held','committed','aborted','release_pending','released')), outcome TEXT CHECK(outcome IS NULL OR outcome IN ('committed','aborted')), hold_id TEXT, hold_observed TEXT CHECK(hold_observed IS NULL OR hold_observed IN ('active','released')), abort_reason TEXT, completion_id TEXT UNIQUE, release_receipt TEXT, key_state TEXT NOT NULL DEFAULT 'present' CHECK(key_state IN ('present','destroyed')), attention TEXT, failures INTEGER NOT NULL DEFAULT 0, notice_state TEXT, created_at_unix_ms INTEGER NOT NULL);\
CREATE UNIQUE INDEX completion_saga_live ON completion_sagas(pool) WHERE outcome IS NULL;\
CREATE INDEX completion_saga_stage ON completion_sagas(stage,id);\
CREATE TABLE completion_records(completion_id TEXT PRIMARY KEY, pool TEXT NOT NULL UNIQUE REFERENCES pools(id), saga TEXT NOT NULL UNIQUE REFERENCES completion_sagas(id), commit_sequence INTEGER NOT NULL UNIQUE CHECK(typeof(commit_sequence)='integer' AND commit_sequence>0), record_version INTEGER NOT NULL CHECK(record_version=1), record TEXT NOT NULL, record_digest TEXT NOT NULL, canonical_length INTEGER NOT NULL);\
CREATE TABLE completion_observations(sequence INTEGER PRIMARY KEY AUTOINCREMENT, completion_id TEXT NOT NULL REFERENCES completion_records(completion_id), record_digest TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('notice','release')), data TEXT NOT NULL, observation_digest TEXT NOT NULL UNIQUE);\
CREATE TRIGGER completion_record_immutable BEFORE UPDATE ON completion_records BEGIN SELECT RAISE(ABORT,'completion record is immutable'); END;\
CREATE TRIGGER completion_record_retained BEFORE DELETE ON completion_records BEGIN SELECT RAISE(ABORT,'completion record is retained'); END;\
CREATE TRIGGER completion_observation_immutable BEFORE UPDATE ON completion_observations BEGIN SELECT RAISE(ABORT,'completion observation is immutable'); END;\
CREATE TRIGGER completion_observation_retained BEFORE DELETE ON completion_observations BEGIN SELECT RAISE(ABORT,'completion observation is retained'); END;\
CREATE TRIGGER completion_saga_retained BEFORE DELETE ON completion_sagas BEGIN SELECT RAISE(ABORT,'completion saga is retained'); END;\
CREATE TRIGGER completion_saga_frozen BEFORE UPDATE OF id,pool,proposal,source_revision,frozen,frozen_digest,run_store_id,run_route,hold_request_id,hold_targets,hold_roots,verifying_key,key_ref,intent_digest,hold_fingerprint,created_at_unix_ms ON completion_sagas BEGIN SELECT RAISE(ABORT,'completion saga intent is frozen'); END;\
CREATE TRIGGER completion_saga_terminal BEFORE UPDATE OF outcome,completion_id,hold_id ON completion_sagas WHEN (OLD.outcome IS NOT NULL AND NEW.outcome IS NOT OLD.outcome) OR (OLD.completion_id IS NOT NULL AND NEW.completion_id IS NOT OLD.completion_id) OR (OLD.hold_id IS NOT NULL AND NEW.hold_id IS NOT OLD.hold_id) BEGIN SELECT RAISE(ABORT,'completion saga outcome is terminal'); END;")?;
    for table in [
        "completion_sagas",
        "completion_records",
        "completion_observations",
    ] {
        for action in ["INSERT", "UPDATE", "DELETE"] {
            db.execute_batch(&format!(
                "CREATE TRIGGER inventory_rev_{table}_{action} AFTER {action} ON {table} BEGIN UPDATE inventory_source SET revision=revision+1 WHERE singleton=1; END;"
            ))?;
        }
    }
    Ok(())
}

/// Exact UTF-8 text with explicit byte length and digest in the canonical preimage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Text {
    pub length: u64,
    pub sha256: String,
    pub text: String,
}
impl Text {
    pub(crate) fn new(text: &str) -> Self {
        Self {
            length: text.len() as u64,
            sha256: format!("{:x}", Sha256::digest(text.as_bytes())),
            text: text.to_owned(),
        }
    }
    fn valid(&self) -> bool {
        self.length == self.text.len() as u64
            && self.sha256 == format!("{:x}", Sha256::digest(self.text.as_bytes()))
    }
}
/// Pool label and goal exactly as frozen at settlement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Goal {
    pub name: Text,
    pub purpose: Text,
}
/// Proposal criteria text and, for structured pools, the exact acceptance list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Criteria {
    /// structured or legacy.
    pub kind: String,
    pub text: Text,
    pub acceptance: Option<Vec<Criterion>>,
}
/// Original Run admission identity retained with a membership.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RunAdmission {
    pub run_store_id: Option<String>,
    pub agent_id: String,
    pub sequence: Option<u64>,
    pub execution_ref: Option<String>,
    pub pin_id: Option<String>,
}
/// Verified attempt binding of a managed member at settlement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedFacts {
    pub generation: u64,
    pub binding: ManagedBinding,
    pub incarnation: Option<Incarnation>,
}
/// One frozen current membership in stable slot order; observed runtime is excluded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RosterEntry {
    pub position: u64,
    pub member_id: String,
    pub name: String,
    pub role: String,
    pub task: String,
    pub state: MemberState,
    pub voter: bool,
    pub run: Option<RunAdmission>,
    pub managed: Option<ManagedFacts>,
}
/// Frozen roster, voters and aggregate binding epoch; the leader is separate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Roster {
    pub roster_key: String,
    pub binding_epoch: i64,
    pub voters: Vec<String>,
    pub members: Vec<RosterEntry>,
}
/// One structured check exactly as journaled after its vote.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CheckRecord {
    pub event_id: u64,
    pub criterion_id: String,
    pub status: CheckStatus,
    pub evidence: Text,
}
/// How the ballot author was established; unknown facts stay explicit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Provenance {
    /// A Run-attested managed attempt, admitted and committed by the managed vote CAS.
    ManagedAttemptV1 {
        verification_version: u32,
        generation: u64,
        attempt: AttemptRef,
        incarnation: Incarnation,
        admission_id: String,
        security_digest: String,
    },
    /// A non-Run native member authenticated by its Bridge assertion when voting.
    NativeAssertion {
        verification_version: u32,
        run_attempt: Option<AttemptRef>,
    },
}
/// One required ballot with all evidence used to authorize settlement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BallotRecord {
    pub member_id: String,
    pub choice: Choice,
    pub evidence: Text,
    pub checks_met: Option<bool>,
    pub vote_event_id: u64,
    pub checks: Vec<CheckRecord>,
    pub provenance: Provenance,
}
/// Complete local state frozen before any hold and compared again by the CAS.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Frozen {
    pub pool_store_id: String,
    pub pool_id: String,
    pub source_revision: u64,
    pub fingerprint: String,
    pub goal: Goal,
    pub criteria: Criteria,
    pub result: Text,
    pub snapshot_present: bool,
    pub snapshot: Option<Text>,
    pub proposal_id: String,
    pub proposal_event_sequence: u64,
    pub roster: Roster,
    pub leader_id: String,
    pub ballots: Vec<BallotRecord>,
}
/// Held Run facts for one lineage, observed under the active hold.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetFacts {
    pub member_id: String,
    pub canonical_root: String,
    pub target: Target,
    pub consensus_state: VoterState,
    pub consensus_attempt: AttemptRef,
    pub consensus_incarnation: Incarnation,
    pub successor_proof: SuccessorProof,
    pub status: ProofProjection,
}
/// Exact hold identity used for the CAS; the public key and signatures are excluded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HoldFacts {
    pub request_id: String,
    pub hold_id: String,
    pub fingerprint: String,
    pub intent_digest: String,
    pub state_at_commit: String,
}
/// Run evidence frozen into the record; Run may later prune its own history.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RunEvidence {
    pub run_store_id: String,
    pub route_digest: String,
    pub hold: HoldFacts,
    /// Run's own snapshot time as decimal text: an observation, not ordering proof.
    pub status_observed_at: String,
    pub scope: String,
    pub targets: Vec<TargetFacts>,
}
/// Durable owner notice intent committed with the record; handoff is not processing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NoticeIntent {
    pub operation_id: String,
    pub recipient: String,
    pub scope: String,
    pub payload_sha256: String,
    pub payload_length: u64,
}
/// RecordV1 integrity preimage: every frozen field except the digest itself.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecordBody {
    pub completion_id: String,
    pub pool_store_id: String,
    pub pool_id: String,
    pub commit_sequence: u64,
    pub record_version: u32,
    pub source_revision: u64,
    pub proposal_id: String,
    pub proposal_event_sequence: u64,
    pub goal: Goal,
    pub criteria: Criteria,
    pub result: Text,
    pub snapshot_present: bool,
    pub snapshot_bytes: Option<Text>,
    pub roster: Roster,
    pub leader: Leader,
    pub ballots: Vec<BallotRecord>,
    pub run_evidence: RunEvidence,
    pub notice_intent: NoticeIntent,
    pub notice_observed_outcome: String,
    pub integrity_algorithm: String,
}
/// External pool owner; never a roster member.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Leader {
    pub leader_id: String,
}

fn encoded<T: Serialize>(value: &T) -> Result<String, Fault> {
    serde_json::to_string(value).map_err(|_| Fault::Internal)
}
fn decoded<T: for<'a> Deserialize<'a>>(text: &str) -> Result<T, Fault> {
    serde_json::from_str(text).map_err(|_| Fault::Internal)
}
fn read_generation(value: &[u8]) -> Result<u64, Fault> {
    let bytes: [u8; 8] = value.try_into().map_err(|_| Fault::Internal)?;
    Ok(u64::from_be_bytes(bytes))
}

/// Canonical record digest and preimage length; the body never contains its own digest.
pub(crate) fn record_digest(body: &RecordBody) -> Result<(usize, String), Fault> {
    let value = serde_json::to_value(body).map_err(|_| Fault::Internal)?;
    crate::managed_codec::digest(RECORD_DOMAIN, &value)
}
/// Settlement digest pinned into the hold intent; binds the hold to the frozen Pool state.
pub(crate) fn settlement_digest(frozen: &Frozen) -> Result<String, Fault> {
    let value = serde_json::to_value(frozen).map_err(|_| Fault::Internal)?;
    Ok(crate::managed_codec::digest(SETTLEMENT_DOMAIN, &value)?.1)
}
/// Linked observation digest; it references the original record digest.
pub(crate) fn observation_digest(
    completion_id: &str,
    record_digest: &str,
    kind: &str,
    data: &serde_json::Value,
) -> Result<String, Fault> {
    let value = serde_json::json!({"completion_id":completion_id,"record_digest":record_digest,"kind":kind,"data":data});
    Ok(crate::managed_codec::digest(OBSERVATION_DOMAIN, &value)?.1)
}

/// Whether a pool has a committed record; C3 freezes its goal, roster, proposals and votes.
pub(crate) fn completed(db: &Connection, pool_id: &str) -> Result<bool, Fault> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM completion_records WHERE pool=?1)",
        [pool_id],
        |row| row.get(0),
    )?)
}
/// Retained pools with an intact committed record, read in the caller's snapshot.
pub(crate) fn completed_count(db: &Connection) -> Result<i64, Fault> {
    Ok(db.query_row(
        "SELECT count(*) FROM completion_records r JOIN pools p ON p.id=r.pool",
        [],
        |row| row.get(0),
    )?)
}

/// Deterministic complete CAS fingerprint: pool snapshot (revision, proposal, ballots),
/// current roster/slots, managed bindings/generations/incarnations, invalidations and epoch.
fn fingerprint(db: &Connection, pool_id: &str) -> Result<String, Fault> {
    let pool: String = db.query_row("SELECT data FROM pools WHERE id=?1", [pool_id], |r| {
        r.get(0)
    })?;
    let mut stmt = db.prepare("SELECT m.id,m.data,coalesce(s.slot,m.id) FROM members m LEFT JOIN member_slots s ON s.member=m.id WHERE m.pool=?1 AND m.current=1 ORDER BY m.id")?;
    let members = stmt
        .query_map([pool_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut stmt = db.prepare("SELECT member,hex(generation),binding,coalesce(incarnation,'') FROM managed_bindings WHERE pool=?1 ORDER BY member")?;
    let managed = stmt
        .query_map([pool_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut stmt = db.prepare(
        "SELECT proposal,member FROM managed_invalidated_ballots WHERE pool=?1 ORDER BY proposal,member",
    )?;
    let invalidated = stmt
        .query_map([pool_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let epoch = binding_epoch(db, pool_id)?;
    let bytes = serde_json::to_vec(&(pool, members, managed, invalidated, epoch))
        .map_err(|_| Fault::Internal)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
fn binding_epoch(db: &Connection, pool_id: &str) -> Result<i64, Fault> {
    Ok(db
        .query_row(
            "SELECT epoch FROM managed_pool_epochs WHERE pool=?1",
            [pool_id],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(0))
}

/// A managed voter whose lineage must be held and freshly checked by Run.
#[derive(Clone)]
pub(crate) struct ManagedVoter {
    pub member_id: String,
    pub ballot: VerifiedBallot,
    /// Original admission selector, used only to locate the retained latest execution.
    pub selector: Target,
    pub run_store_id: String,
}
/// Eligible settlement snapshot read in one SQLite transaction.
pub(crate) struct Candidate {
    pub frozen: Frozen,
    pub frozen_digest: String,
    pub voters: Vec<ManagedVoter>,
}

/// Latest journaled vote of one member for one proposal.
fn latest_vote_event(
    db: &Connection,
    pool_id: &str,
    member_id: &str,
    proposal_id: &str,
) -> Result<Option<i64>, Fault> {
    let prefix = format!("Proposal {proposal_id}: ");
    Ok(db.query_row("SELECT max(id) FROM events WHERE pool=?1 AND json_extract(data,'$.author.kind')='member' AND json_extract(data,'$.author.member_id')=?2 AND json_extract(data,'$.kind') IN ('vote_recorded','proposal_accepted') AND substr(json_extract(data,'$.body'),1,length(?3))=?3",params![pool_id,member_id,prefix],|r|r.get(0))?)
}

/// Reads one complete eligibility snapshot. `None` means not eligible now:
/// no accepted proposal, an existing record, an unverifiable or legacy ballot,
/// no Run lineage to hold, more than one Run store, or more than 20 lineages.
pub(crate) fn snapshot(db: &Connection, pool_id: &str) -> Result<Option<Candidate>, Fault> {
    let row: Option<(String, String)> = db
        .query_row("SELECT data,owner FROM pools WHERE id=?1", [pool_id], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .optional()?;
    let Some((data, leader_id)) = row else {
        return Ok(None);
    };
    let pool: Pool = decoded(&data)?;
    if pool.pool_id != pool_id
        || completed(db, pool_id)?
        || crate::store::completion_admission_pending(db, pool_id)?
    {
        return Ok(None);
    }
    let Some(proposal) = pool.proposal.as_ref() else {
        return Ok(None);
    };
    if proposal.state != ProposalState::Accepted
        || proposal.voters.is_empty()
        || proposal.voters.len() > crate::domain::MAX_MEMBERS
        || proposal.voters.iter().collect::<BTreeSet<_>>().len() != proposal.voters.len()
    {
        return Ok(None);
    }
    let prefix = format!("Proposal {}: ", proposal.proposal_id);
    let accepted: Option<i64> = db.query_row("SELECT max(id) FROM events WHERE pool=?1 AND json_extract(data,'$.kind')='proposal_accepted' AND substr(json_extract(data,'$.body'),1,length(?2))=?2",params![pool_id,prefix],|r|r.get(0))?;
    let Some(accepted) = accepted.and_then(|id| u64::try_from(id).ok()) else {
        return Ok(None);
    };
    let pool_store_id: String = db.query_row(
        "SELECT store_id FROM inventory_source WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    let epoch = binding_epoch(db, pool_id)?;
    let mut stmt = db.prepare("SELECT m.data FROM members m LEFT JOIN member_slots s ON s.member=m.id WHERE m.pool=?1 AND m.current=1 ORDER BY COALESCE(s.slot,m.id),m.id")?;
    let roster = stmt
        .query_map([pool_id], |r| r.get::<_, String>(0))?
        .map(|row| decoded::<Binding>(&row?))
        .collect::<Result<Vec<_>, Fault>>()?;
    drop(stmt);
    let structured = pool.acceptance.is_some();
    let mut members = Vec::with_capacity(roster.len());
    for (position, binding) in roster.iter().enumerate() {
        if binding.pool_id != pool_id {
            return Err(Fault::Internal);
        }
        let managed: Option<(Vec<u8>, String, Option<String>)> = db
            .query_row(
                "SELECT generation,binding,incarnation FROM managed_bindings WHERE member=?1 AND pool=?2",
                params![binding.member.member_id, pool_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let managed = match managed {
            Some((generation, raw, incarnation)) => Some(ManagedFacts {
                generation: read_generation(&generation)?,
                binding: decoded(&raw)?,
                incarnation: incarnation.as_deref().map(decoded).transpose()?,
            }),
            None => None,
        };
        members.push(RosterEntry {
            position: position as u64,
            member_id: binding.member.member_id.clone(),
            name: binding.member.name.clone(),
            role: binding.member.role.clone(),
            task: binding.member.task.clone(),
            state: binding.member.state.clone(),
            voter: proposal.voters.contains(&binding.member.member_id),
            run: binding.run_id.as_ref().map(|agent_id| RunAdmission {
                run_store_id: binding.run_store_id.clone(),
                agent_id: agent_id.clone(),
                sequence: binding.run_sequence,
                execution_ref: binding.run_execution_ref.clone(),
                pin_id: binding.run_pin_id.clone(),
            }),
            managed,
        });
    }
    let mut ballots = Vec::with_capacity(proposal.voters.len());
    let mut voters = Vec::new();
    for member_id in &proposal.voters {
        let Some((binding, entry)) = roster
            .iter()
            .zip(&members)
            .find(|(binding, _)| &binding.member.member_id == member_id)
        else {
            return Ok(None);
        };
        if binding.member.state != MemberState::Active {
            return Ok(None);
        }
        let Some(ballot) = proposal.votes.get(member_id) else {
            return Ok(None);
        };
        // Legacy Unknown ballots never count, and every required ballot must be ready.
        if ballot.validity.is_some()
            || ballot.choice != Choice::Ready
            || (structured && ballot.checks_met != Some(true))
        {
            return Ok(None);
        }
        let Some(latest) = latest_vote_event(db, pool_id, member_id, &proposal.proposal_id)? else {
            return Ok(None);
        };
        if ballot
            .vote_event_id
            .as_ref()
            .is_some_and(|id| id != &latest.to_string())
            || (structured && ballot.vote_event_id.is_none())
        {
            return Ok(None);
        }
        let vote_event_id = u64::try_from(latest).map_err(|_| Fault::Internal)?;
        let mut checks = Vec::new();
        if structured {
            let mut stmt = db.prepare("SELECT id,data FROM events WHERE pool=?1 AND json_extract(data,'$.kind')='vote_check' AND json_extract(data,'$.vote_event_id')=?2 ORDER BY id")?;
            let rows = stmt
                .query_map(params![pool_id, latest.to_string()], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            for (id, raw) in rows {
                let event: crate::domain::Event = decoded(&raw)?;
                let check = event.check.ok_or(Fault::Internal)?;
                checks.push(CheckRecord {
                    event_id: u64::try_from(id).map_err(|_| Fault::Internal)?,
                    criterion_id: check.criterion_id,
                    status: check.status,
                    evidence: Text::new(&check.evidence),
                });
            }
            let required: BTreeSet<_> = pool
                .acceptance
                .iter()
                .flatten()
                .map(|c| c.id.as_str())
                .collect();
            let supplied: BTreeSet<_> = checks.iter().map(|c| c.criterion_id.as_str()).collect();
            if Some(checks.len()) != ballot.checks_count
                || supplied != required
                || checks.len() != required.len()
                || checks.iter().any(|c| c.status != CheckStatus::Met)
            {
                return Ok(None);
            }
        }
        let provenance = match (&binding.run_id, &entry.managed) {
            (None, None) => Provenance::NativeAssertion {
                verification_version: 1,
                run_attempt: None,
            },
            // An ordinary Run member without an attempt binding has no proven author.
            (Some(_), None) | (None, Some(_)) => return Ok(None),
            (Some(_), Some(managed)) => {
                let invalidated: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM managed_invalidated_ballots WHERE pool=?1 AND proposal=?2 AND member=?3)",params![pool_id,proposal.proposal_id,member_id],|r|r.get(0))?;
                let prior: Option<(Vec<u8>, String, String, String, String)> = db.query_row("SELECT generation,attempt,incarnation,admission_id,security_digest FROM managed_ballot_provenance WHERE pool=?1 AND proposal=?2 AND member=?3 AND event_id=?4",params![pool_id,proposal.proposal_id,member_id,latest],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
                let Some((generation, attempt, incarnation, admission_id, security_digest)) = prior
                else {
                    return Ok(None);
                };
                let generation = read_generation(&generation)?;
                let attempt: AttemptRef = decoded(&attempt)?;
                let incarnation: Incarnation = decoded(&incarnation)?;
                let run_store_id = binding.run_store_id.clone().unwrap_or_default();
                let selector = match (
                    binding.run_id.as_ref(),
                    binding.run_sequence.and_then(|s| u32::try_from(s).ok()),
                    binding.run_execution_ref.as_ref(),
                    binding.run_pin_id.as_ref(),
                ) {
                    (Some(agent_id), Some(sequence), Some(execution_ref), Some(pin_id)) => Target {
                        agent_id: agent_id.clone(),
                        sequence,
                        execution_ref: execution_ref.clone(),
                        pin_id: pin_id.clone(),
                    },
                    _ => return Ok(None),
                };
                if invalidated
                    || generation != managed.generation
                    || managed.binding.binding_generation != generation
                    || managed.binding.pool_id != pool_id
                    || managed.binding.member_id != *member_id
                    || attempt != managed.binding.attempt
                    || managed.incarnation.as_ref() != Some(&incarnation)
                    || attempt.run_store_id != run_store_id
                    || managed.binding.run_route.component_store_id != run_store_id
                    || crate::domain::store_id(&run_store_id).is_err()
                {
                    return Ok(None);
                }
                voters.push(ManagedVoter {
                    member_id: member_id.clone(),
                    ballot: VerifiedBallot {
                        binding: managed.binding.clone(),
                        generation,
                        attempt: attempt.clone(),
                        incarnation: incarnation.clone(),
                    },
                    selector,
                    run_store_id,
                });
                Provenance::ManagedAttemptV1 {
                    verification_version: 1,
                    generation,
                    attempt,
                    incarnation,
                    admission_id,
                    security_digest,
                }
            }
        };
        ballots.push(BallotRecord {
            member_id: member_id.clone(),
            choice: ballot.choice.clone(),
            evidence: Text::new(&ballot.evidence),
            checks_met: ballot.checks_met,
            vote_event_id,
            checks,
            provenance,
        });
    }
    // Hold v1 needs 1–20 lineages in one pinned Run store; v1 refuses multi-store settlement.
    if voters.is_empty()
        || voters.len() > MAX_TARGETS
        || voters
            .iter()
            .any(|voter| voter.run_store_id != voters[0].run_store_id)
    {
        return Ok(None);
    }
    let frozen = Frozen {
        pool_store_id,
        pool_id: pool_id.to_owned(),
        source_revision: pool.revision,
        fingerprint: fingerprint(db, pool_id)?,
        goal: Goal {
            name: Text::new(&pool.name),
            purpose: Text::new(&pool.purpose),
        },
        criteria: Criteria {
            kind: if structured { "structured" } else { "legacy" }.into(),
            text: Text::new(&proposal.criteria),
            acceptance: pool.acceptance.clone(),
        },
        result: Text::new(&proposal.result),
        snapshot_present: proposal.snapshot.is_some(),
        snapshot: proposal.snapshot.as_deref().map(Text::new),
        proposal_id: proposal.proposal_id.clone(),
        proposal_event_sequence: accepted,
        roster: Roster {
            roster_key: proposal.roster_key.clone(),
            binding_epoch: epoch,
            voters: proposal.voters.clone(),
            members,
        },
        leader_id,
        ballots,
    };
    let frozen_digest = settlement_digest(&frozen)?;
    Ok(Some(Candidate {
        frozen,
        frozen_digest,
        voters,
    }))
}

/// Pools that may become settlement candidates, after an exclusive rotating cursor.
pub(crate) fn candidates(db: &Connection, after: &str, limit: u32) -> Result<Vec<String>, Fault> {
    let mut stmt = db.prepare(&format!("SELECT p.id FROM pools p WHERE p.id>?1 AND json_extract(p.data,'$.proposal.state')='accepted' AND NOT EXISTS(SELECT 1 FROM completion_records r WHERE r.pool=p.id) AND NOT EXISTS(SELECT 1 FROM completion_sagas s WHERE s.pool=p.id AND s.stage!='released') AND (SELECT count(*) FROM completion_sagas s WHERE s.pool=p.id AND s.proposal=json_extract(p.data,'$.proposal.proposal_id') AND s.source_revision=json_extract(p.data,'$.revision'))<{MAX_ABORTED_ATTEMPTS} ORDER BY p.id LIMIT ?2"))?;
    Ok(stmt
        .query_map(params![after, limit], |r| r.get(0))?
        .collect::<Result<Vec<String>, _>>()?)
}

/// Local proposal identity for pre-hold retry scheduling.
pub(crate) fn candidate_version(db: &Connection, pool_id: &str) -> Result<(String, i64), Fault> {
    Ok(db.query_row("SELECT json_extract(data,'$.proposal.proposal_id'),json_extract(data,'$.revision') FROM pools WHERE id=?1", [pool_id], |row| Ok((row.get(0)?, row.get(1)?)))?)
}

/// Durable saga stage, in the documented order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stage {
    Prepared,
    AcquirePossible,
    Held,
    Committed,
    Aborted,
    ReleasePending,
    Released,
}
impl Stage {
    fn parse(value: &str) -> Result<Self, Fault> {
        Ok(match value {
            "prepared" => Self::Prepared,
            "acquire_possible" => Self::AcquirePossible,
            "held" => Self::Held,
            "committed" => Self::Committed,
            "aborted" => Self::Aborted,
            "release_pending" => Self::ReleasePending,
            "released" => Self::Released,
            _ => return Err(Fault::Internal),
        })
    }
}
/// One loaded saga with its reconstructed and rechecked immutable hold intent.
#[derive(Clone)]
pub(crate) struct Saga {
    pub id: String,
    pub pool_id: String,
    pub stage: Stage,
    pub outcome: Option<String>,
    pub hold_id: Option<String>,
    pub hold_observed: Option<String>,
    pub key_ref: String,
    pub key_present: bool,
    pub public_key: [u8; 32],
    pub intent: HoldIntent,
    pub intent_digest: String,
    pub route: crate::domain::RunRoute,
    pub run_store_id: String,
    pub frozen: Frozen,
    pub frozen_digest: String,
    pub targets: Vec<Target>,
    pub roots: Vec<String>,
}
fn hex32(value: &str) -> Result<[u8; 32], Fault> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Fault::Internal);
    }
    let mut out = [0_u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| Fault::Internal)?;
    }
    Ok(out)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
/// Rebuilds the hold intent and refuses any row whose fingerprint no longer matches.
fn build_intent(
    run_store_id: &str,
    request_id: &str,
    targets: &[Target],
    roots: &[String],
    public_key: [u8; 32],
    intent_digest: &str,
) -> Result<HoldIntent, Fault> {
    HoldIntent::new(
        run_store_id.to_owned(),
        request_id.to_owned(),
        targets.to_vec(),
        roots.to_vec(),
        public_key,
        Some(hex32(intent_digest)?),
    )
    .map_err(|_| Fault::Invalid)
}

/// Records a prepared saga after its key file exists. The candidate is
/// re-snapshotted and compared in the same writer transaction.
#[allow(
    clippy::too_many_arguments,
    reason = "Each value is an independent frozen saga field"
)]
pub(crate) fn prepare(
    db: &mut Connection,
    saga_id: &str,
    key_ref: &str,
    pool_id: &str,
    frozen_digest: &str,
    public_key: [u8; 32],
    targets: &[Target],
    route: &crate::domain::RunRoute,
    now_unix_ms: u64,
) -> Result<(), Fault> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let candidate = snapshot(&tx, pool_id)?.ok_or(Fault::Stale)?;
    if candidate.frozen_digest != frozen_digest {
        return Err(Fault::Stale);
    }
    let live: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM completion_sagas WHERE pool=?1 AND stage!='released')",
        [pool_id],
        |r| r.get(0),
    )?;
    let attempts: i64 = tx.query_row(
        "SELECT count(*) FROM completion_sagas WHERE pool=?1 AND proposal=?2 AND source_revision=?3",
        params![
            pool_id,
            candidate.frozen.proposal_id,
            i64::try_from(candidate.frozen.source_revision).map_err(|_| Fault::Internal)?
        ],
        |r| r.get(0),
    )?;
    if live || attempts >= MAX_ABORTED_ATTEMPTS {
        return Err(Fault::Conflict);
    }
    let run_store_id = candidate.voters[0].run_store_id.clone();
    let roots: Vec<String> = candidate
        .voters
        .iter()
        .map(|voter| voter.ballot.attempt.lineage_root_id.clone())
        .collect();
    if targets.len() != candidate.voters.len()
        || route.store_id.as_deref() != Some(run_store_id.as_str())
        || targets
            .iter()
            .zip(&candidate.voters)
            .any(|(target, voter)| target.pin_id != voter.selector.pin_id)
    {
        return Err(Fault::Invalid);
    }
    let request_id = format!("agent-pool.completion.{saga_id}");
    let intent = build_intent(
        &run_store_id,
        &request_id,
        targets,
        &roots,
        public_key,
        frozen_digest,
    )?;
    let created = i64::try_from(now_unix_ms).map_err(|_| Fault::Internal)?;
    tx.execute("INSERT INTO completion_sagas(id,pool,proposal,source_revision,frozen,frozen_digest,run_store_id,run_route,hold_request_id,hold_targets,hold_roots,verifying_key,key_ref,intent_digest,hold_fingerprint,stage,created_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,'prepared',?16)",params![saga_id,pool_id,candidate.frozen.proposal_id,i64::try_from(candidate.frozen.source_revision).map_err(|_|Fault::Internal)?,encoded(&candidate.frozen)?,frozen_digest,run_store_id,encoded(route)?,request_id,encoded(&targets)?,encoded(&roots)?,hex(&public_key),key_ref,frozen_digest,intent.fingerprint(),created])?;
    tx.commit()?;
    Ok(())
}

/// Loads one saga and rechecks its frozen intent, digest and fingerprint.
pub(crate) fn load(db: &Connection, saga_id: &str) -> Result<Saga, Fault> {
    #[allow(
        clippy::type_complexity,
        reason = "One row of independent frozen columns"
    )]
    let row: (
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    ) = db.query_row("SELECT pool,stage,outcome,hold_id,hold_observed,key_ref,key_state,verifying_key,run_store_id,run_route,hold_request_id,hold_targets,hold_roots,intent_digest,hold_fingerprint,frozen FROM completion_sagas WHERE id=?1",[saga_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?,r.get(11)?,r.get(12)?,r.get(13)?,r.get(14)?,r.get(15)?)))?;
    let frozen_digest: String = db.query_row(
        "SELECT frozen_digest FROM completion_sagas WHERE id=?1",
        [saga_id],
        |r| r.get(0),
    )?;
    let public_key = hex32(&row.7)?;
    let targets: Vec<Target> = decoded(&row.11)?;
    let roots: Vec<String> = decoded(&row.12)?;
    let intent = build_intent(&row.8, &row.10, &targets, &roots, public_key, &row.13)?;
    let frozen: Frozen = decoded(&row.15)?;
    if intent.fingerprint() != row.14
        || settlement_digest(&frozen)? != frozen_digest
        || row.13 != frozen_digest
        || frozen.pool_id != row.0
    {
        return Err(Fault::Internal);
    }
    Ok(Saga {
        id: saga_id.to_owned(),
        pool_id: row.0,
        stage: Stage::parse(&row.1)?,
        outcome: row.2,
        hold_id: row.3,
        hold_observed: row.4,
        key_ref: row.5,
        key_present: row.6 == "present",
        public_key,
        intent,
        intent_digest: row.13,
        route: decoded(&row.9)?,
        run_store_id: row.8,
        frozen,
        frozen_digest,
        targets,
        roots,
    })
}

/// Unfinished sagas, key cleanup and notice links, in stable ID order after a cursor.
pub(crate) fn pending(db: &Connection, after: &str, limit: u32) -> Result<Vec<String>, Fault> {
    let mut stmt = db.prepare("SELECT id FROM completion_sagas WHERE id>?1 AND (stage!='released' OR key_state='present' OR (outcome='committed' AND coalesce(notice_state,'') NOT IN ('accepted','refused','cancelled'))) ORDER BY id LIMIT ?2")?;
    Ok(stmt
        .query_map(params![after, limit], |r| r.get(0))?
        .collect::<Result<Vec<String>, _>>()?)
}

/// Keys needed by unresolved sagas, read before the startup filesystem sweep.
pub(crate) fn retained_keys(db: &Connection) -> Result<std::collections::HashSet<String>, Fault> {
    let mut stmt = db.prepare("SELECT key_ref FROM completion_sagas WHERE stage!='released'")?;
    Ok(stmt
        .query_map([], |row| row.get(0))?
        .collect::<Result<_, _>>()?)
}

/// Keys this store's sagas still own (unreleased or awaiting destruction); only
/// these may be migrated out of the legacy shared key directory.
pub(crate) fn owned_keys(db: &Connection) -> Result<std::collections::HashSet<String>, Fault> {
    let mut stmt = db.prepare(
        "SELECT key_ref FROM completion_sagas WHERE stage!='released' OR key_state='present'",
    )?;
    Ok(stmt
        .query_map([], |row| row.get(0))?
        .collect::<Result<_, _>>()?)
}

/// Persist driver-wide unavailability without repeatedly incrementing failures.
pub(crate) fn driver_unavailable(db: &Connection, reason: &str) -> Result<usize, Fault> {
    Ok(db.execute("UPDATE completion_sagas SET attention=?1,failures=0 WHERE stage!='released' AND attention IS NOT ?1", [reason])?)
}

fn guarded(db: &mut Connection, sql: &str, args: impl rusqlite::Params) -> Result<(), Fault> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if tx.execute(sql, args)? != 1 {
        return Err(Fault::Stale);
    }
    tx.commit()?;
    Ok(())
}
/// Persisted before the first possible acquire request.
pub(crate) fn mark_acquire_possible(db: &mut Connection, saga_id: &str) -> Result<(), Fault> {
    guarded(
        db,
        "UPDATE completion_sagas SET stage='acquire_possible',attention=NULL,failures=0 WHERE id=?1 AND stage='prepared' AND outcome IS NULL",
        [saga_id],
    )
}
/// Records a correlated active hold; an already aborted saga goes straight to release.
pub(crate) fn record_held(db: &mut Connection, saga_id: &str, hold_id: &str) -> Result<(), Fault> {
    guarded(
        db,
        "UPDATE completion_sagas SET hold_id=?2,hold_observed='active',stage=CASE WHEN outcome IS NULL THEN 'held' ELSE 'aborted' END,attention=NULL,failures=0 WHERE id=?1 AND stage='acquire_possible' AND (hold_id IS NULL OR hold_id=?2)",
        params![saga_id, hold_id],
    )
}
/// An exact replay found a released hold: it can never authorize a CAS.
pub(crate) fn record_found_released(
    db: &mut Connection,
    saga_id: &str,
    hold_id: &str,
) -> Result<(), Fault> {
    guarded(
        db,
        "UPDATE completion_sagas SET hold_id=?2,hold_observed='released',outcome=coalesce(outcome,'aborted'),abort_reason=coalesce(abort_reason,'hold_released'),stage='released',attention=NULL,failures=0 WHERE id=?1 AND stage='acquire_possible' AND (hold_id IS NULL OR hold_id=?2)",
        params![saga_id, hold_id],
    )
}
/// Claims the exclusive terminal outcome as aborted; a committed saga cannot be aborted.
pub(crate) fn abort(db: &mut Connection, saga_id: &str, reason: &str) -> Result<(), Fault> {
    guarded(
        db,
        "UPDATE completion_sagas SET outcome='aborted',abort_reason=?2,stage=CASE WHEN stage IN ('prepared','held') THEN 'aborted' ELSE stage END,failures=CASE WHEN stage IN ('prepared','held') THEN 0 ELSE failures END,attention=CASE WHEN stage IN ('prepared','held') THEN NULL ELSE attention END WHERE id=?1 AND outcome IS NULL AND stage IN ('prepared','acquire_possible','held')",
        params![saga_id, reason],
    )
}
/// Persisted before signing and sending the release of a terminal saga's hold.
pub(crate) fn mark_release_pending(db: &mut Connection, saga_id: &str) -> Result<(), Fault> {
    guarded(
        db,
        "UPDATE completion_sagas SET stage='release_pending',attention=NULL,failures=0 WHERE id=?1 AND stage IN ('committed','aborted') AND outcome IS NOT NULL AND hold_id IS NOT NULL",
        [saga_id],
    )
}
/// A prepared saga aborted before any acquire was possible has no hold to release.
pub(crate) fn finish_without_hold(db: &mut Connection, saga_id: &str) -> Result<(), Fault> {
    guarded(
        db,
        "UPDATE completion_sagas SET stage='released',attention=NULL,failures=0 WHERE id=?1 AND stage='aborted' AND outcome='aborted' AND hold_id IS NULL",
        [saga_id],
    )
}
/// A correlated refusal of the first acquire proves that no hold was created.
pub(crate) fn refuse_first_acquire(db: &mut Connection, saga_id: &str) -> Result<(), Fault> {
    guarded(
        db,
        "UPDATE completion_sagas SET stage='aborted',outcome='aborted',abort_reason='hold_refused',attention=NULL,failures=0 WHERE id=?1 AND stage='acquire_possible' AND outcome IS NULL AND hold_id IS NULL",
        [saga_id],
    )
}
/// Records a verified release receipt and, for a completion, a linked release observation.
pub(crate) fn record_released(
    db: &mut Connection,
    saga_id: &str,
    already_released: bool,
    now_unix_ms: u64,
) -> Result<(), Fault> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (hold_id, completion_id): (String, Option<String>) = tx.query_row(
        "SELECT hold_id,completion_id FROM completion_sagas WHERE id=?1 AND stage='release_pending' AND hold_id IS NOT NULL",
        [saga_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    ).optional()?.ok_or(Fault::Stale)?;
    let receipt = serde_json::json!({"hold_id":hold_id,"state":"released","already_released":already_released,"observed_at_unix_ms":now_unix_ms.to_string()});
    tx.execute("UPDATE completion_sagas SET stage='released',hold_observed='released',release_receipt=?2,attention=NULL,failures=0 WHERE id=?1 AND stage='release_pending'", params![saga_id, encoded(&receipt)?])?;
    if let Some(completion_id) = completion_id {
        append_observation(&tx, &completion_id, "release", &receipt)?;
    }
    tx.commit()?;
    Ok(())
}
/// Marks the key destroyed; the file is removed only after a verified release.
pub(crate) fn mark_key_destroyed(db: &mut Connection, saga_id: &str) -> Result<(), Fault> {
    guarded(
        db,
        "UPDATE completion_sagas SET key_state='destroyed' WHERE id=?1 AND stage='released' AND key_state='present'",
        [saga_id],
    )
}
/// Records a bounded nonsecret attention code; uncertainty stays at the original stage.
pub(crate) fn note_attention(
    db: &mut Connection,
    saga_id: &str,
    attention: &str,
) -> Result<i64, Fault> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute(
        "UPDATE completion_sagas SET failures=CASE WHEN attention=?2 THEN min(failures+1,100) ELSE 1 END,attention=?2 WHERE id=?1",
        params![saga_id, attention],
    )?;
    let failures: i64 = tx.query_row(
        "SELECT failures FROM completion_sagas WHERE id=?1",
        [saga_id],
        |r| r.get(0),
    )?;
    tx.commit()?;
    Ok(failures)
}

/// Clear a resolved route problem before counting failures of a different operation.
pub(crate) fn clear_route_attention(db: &Connection, saga_id: &str) -> Result<(), Fault> {
    db.execute("UPDATE completion_sagas SET attention=NULL,failures=0 WHERE id=?1 AND attention='route_changed'", [saga_id])?;
    Ok(())
}

fn append_observation(
    db: &Connection,
    completion_id: &str,
    kind: &str,
    data: &serde_json::Value,
) -> Result<(), Fault> {
    let record_digest: String = db.query_row(
        "SELECT record_digest FROM completion_records WHERE completion_id=?1",
        [completion_id],
        |r| r.get(0),
    )?;
    let digest = observation_digest(completion_id, &record_digest, kind, data)?;
    db.execute("INSERT INTO completion_observations(completion_id,record_digest,kind,data,observation_digest) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(observation_digest) DO NOTHING",params![completion_id,record_digest,kind,encoded(data)?,digest])?;
    Ok(())
}
/// Links a changed owner-notice delivery state as a new immutable observation.
pub(crate) fn link_notice(
    db: &mut Connection,
    saga_id: &str,
    now_unix_ms: u64,
) -> Result<(), Fault> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let row: Option<(String, Option<String>, String)> = tx.query_row("SELECT s.completion_id,s.notice_state,r.record FROM completion_sagas s JOIN completion_records r ON r.completion_id=s.completion_id WHERE s.id=?1 AND s.outcome='committed'",[saga_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
    let Some((completion_id, previous, record)) = row else {
        return Ok(());
    };
    let body: RecordBody = decoded(&record)?;
    let state: Option<String> = tx
        .query_row(
            "SELECT state FROM effects WHERE id=?1",
            [&body.notice_intent.operation_id],
            |r| r.get(0),
        )
        .optional()?;
    let state = state.unwrap_or_else(|| "unknown".into());
    if previous.as_deref() == Some(state.as_str())
        || matches!(state.as_str(), "queued" | "inflight")
    {
        return Ok(());
    }
    let data = serde_json::json!({"operation_id":body.notice_intent.operation_id,"state":state,"observed_at_unix_ms":now_unix_ms.to_string(),"meaning":"Delivery custody or handoff state; never recipient processing."});
    append_observation(&tx, &completion_id, "notice", &data)?;
    tx.execute(
        "UPDATE completion_sagas SET notice_state=?2 WHERE id=?1",
        params![saga_id, state],
    )?;
    tx.commit()?;
    Ok(())
}

/// Held facts gathered outside SQLite for one CAS attempt.
pub(crate) struct HeldFacts {
    pub status_observed_at: String,
    pub targets: Vec<TargetFacts>,
}

/// The single completion CAS. With the hold active, it re-derives the complete
/// frozen settlement, compares every field, checks the held Run facts, and
/// atomically appends the record, its terminal saga outcome, the owner notice
/// intent and the pool's frozen state. Abort uses the same exclusive outcome.
pub(crate) fn commit(
    db: &mut Connection,
    saga_id: &str,
    facts: &HeldFacts,
) -> Result<String, Fault> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let saga = load(&tx, saga_id)?;
    let hold_id = saga.hold_id.clone().ok_or(Fault::Stale)?;
    if saga.stage != Stage::Held
        || saga.outcome.is_some()
        || saga.hold_observed.as_deref() != Some("active")
    {
        return Err(Fault::Stale);
    }
    let candidate = snapshot(&tx, &saga.pool_id)?.ok_or(Fault::Stale)?;
    if candidate.frozen_digest != saga.frozen_digest || candidate.frozen != saga.frozen {
        return Err(Fault::Stale);
    }
    if facts.targets.len() != saga.targets.len() {
        return Err(Fault::Invalid);
    }
    for ((fact, (target, root)), voter) in facts
        .targets
        .iter()
        .zip(saga.targets.iter().zip(&saga.roots))
        .zip(&candidate.voters)
    {
        // Finished workers only: a live or superseded voter cannot settle.
        if fact.member_id != voter.member_id
            || &fact.target != target
            || &fact.canonical_root != root
            || fact.consensus_state != VoterState::TerminalNoSuccessor
            || fact.consensus_attempt != voter.ballot.attempt
            || fact.consensus_incarnation != voter.ballot.incarnation
            || !fact.status.historical_success
            || fact.status.selector() != target
            || fact.target.sequence != voter.ballot.attempt.sequence
        {
            return Err(Fault::Conflict);
        }
    }
    let completion_id = crate::domain::id();
    let commit_sequence: i64 = tx.query_row(
        "SELECT coalesce(max(commit_sequence),0)+1 FROM completion_records",
        [],
        |r| r.get(0),
    )?;
    let (operation_id, payload) =
        crate::store::completion_effects(&tx, &saga.pool_id, &completion_id)?;
    let frozen = saga.frozen.clone();
    let body = RecordBody {
        completion_id: completion_id.clone(),
        pool_store_id: frozen.pool_store_id,
        pool_id: frozen.pool_id,
        commit_sequence: u64::try_from(commit_sequence).map_err(|_| Fault::Internal)?,
        record_version: RECORD_VERSION,
        source_revision: frozen.source_revision,
        proposal_id: frozen.proposal_id,
        proposal_event_sequence: frozen.proposal_event_sequence,
        goal: frozen.goal,
        criteria: frozen.criteria,
        result: frozen.result,
        snapshot_present: frozen.snapshot_present,
        snapshot_bytes: frozen.snapshot,
        roster: frozen.roster,
        leader: Leader {
            leader_id: frozen.leader_id,
        },
        ballots: frozen.ballots,
        run_evidence: RunEvidence {
            run_store_id: saga.run_store_id.clone(),
            route_digest: format!("{:x}", Sha256::digest(encoded(&saga.route)?.as_bytes())),
            hold: HoldFacts {
                request_id: format!("agent-pool.completion.{saga_id}"),
                hold_id,
                fingerprint: saga.intent.fingerprint().to_owned(),
                intent_digest: saga.intent_digest.clone(),
                state_at_commit: "active".into(),
            },
            status_observed_at: facts.status_observed_at.clone(),
            scope: "Exact Run facts observed under the active hold; historical success is not author authentication, and later Run pruning does not alter this record.".into(),
            targets: facts.targets.clone(),
        },
        notice_intent: NoticeIntent {
            operation_id,
            recipient: "owner".into(),
            scope: format!("owner:{}", saga.pool_id),
            payload_sha256: format!("{:x}", Sha256::digest(payload.as_bytes())),
            payload_length: payload.len() as u64,
        },
        notice_observed_outcome: "pending".into(),
        integrity_algorithm: INTEGRITY_ALGORITHM.into(),
    };
    let (length, digest) = record_digest(&body)?;
    tx.execute("INSERT INTO completion_records(completion_id,pool,saga,commit_sequence,record_version,record,record_digest,canonical_length) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",params![completion_id,saga.pool_id,saga_id,commit_sequence,RECORD_VERSION,encoded(&body)?,digest,i64::try_from(length).map_err(|_|Fault::Internal)?])?;
    if tx.execute("UPDATE completion_sagas SET outcome='committed',stage='committed',completion_id=?2,attention=NULL,failures=0 WHERE id=?1 AND stage='held' AND outcome IS NULL",params![saga_id,completion_id])? != 1 {
        return Err(Fault::Stale);
    }
    tx.commit()?;
    Ok(completion_id)
}

/// Owner read section of `completion_get`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Section {
    /// Compact immutable header with section sizes and content digests.
    Header,
    /// Exact goal, criteria, result and snapshot bytes in UTF-8 chunks.
    Content,
    /// Frozen ordered roster, generations and attempt bindings.
    Roster,
    /// Required ballots, checks and author provenance.
    Ballots,
    /// Held Run facts and hold identity.
    RunFacts,
    /// Notice intent and linked later notice/release observations.
    Notice,
}
/// Exclusive continuation bound to one record digest and section.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cursor {
    /// Cursor format version, exactly 1.
    pub version: u8,
    /// Exact completion selected by the first page.
    pub completion_id: String,
    /// Record digest verified by the first page.
    pub record_digest: String,
    /// Section selected by the first page.
    pub section: Section,
    /// Exclusive position: item index, or `field:offset` for content.
    pub position: String,
}
/// Owner-only exact completion read; never acquires a hold or writes.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetRequest {
    /// Exact pool owning the record.
    pub pool_id: String,
    /// Exact completion ID from the pool_completed event or owner notice.
    pub completion_id: String,
    /// Selected section.
    pub section: Section,
    /// Omit or null to start; otherwise the exact previous next_cursor.
    #[serde(default)]
    pub after: Option<Cursor>,
    /// Maximum items, 1 through 10.
    pub limit: u8,
}
impl GetRequest {
    /// Validates identifiers and bounds before any read.
    pub(crate) fn validate(&self) -> Result<(), Fault> {
        crate::domain::identifier(&self.pool_id)?;
        crate::domain::identifier(&self.completion_id)?;
        if !(1..=10).contains(&self.limit)
            || (self.section == Section::Header && self.after.is_some())
            || self.after.as_ref().is_some_and(|cursor| {
                cursor.version != 1 || cursor.position.is_empty() || cursor.position.len() > 64
            })
        {
            return Err(Fault::Invalid);
        }
        Ok(())
    }
}
/// One content field descriptor for the header.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentField {
    /// Field name used in content items and cursors.
    pub field: String,
    /// Whether the field is present; absent snapshot differs from empty.
    pub present: bool,
    /// Exact UTF-8 byte length.
    pub length: u64,
    /// Lowercase SHA-256 of the exact bytes.
    pub sha256: Option<String>,
}
/// Compact immutable header.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    /// Pool store identity.
    pub pool_store_id: String,
    /// Monotonic local commit sequence.
    pub commit_sequence: u64,
    /// Pool revision frozen by the CAS.
    pub source_revision: u64,
    /// Accepted proposal.
    pub proposal_id: String,
    /// Event sequence of the acceptance.
    pub proposal_event_sequence: u64,
    /// Whether a snapshot existed; an empty snapshot is present with length 0.
    pub snapshot_present: bool,
    /// Separate leader identity.
    pub leader_id: String,
    /// Exact canonical preimage length.
    pub canonical_length: u64,
    /// Notice state observed at commit.
    pub notice_observed_outcome: String,
    /// Content fields and digests.
    pub content: Vec<ContentField>,
    /// Number of roster entries.
    pub roster_entries: u64,
    /// Number of required ballots.
    pub ballots: u64,
    /// Number of held Run targets.
    pub run_targets: u64,
    /// Notice intent plus linked observations at read time.
    pub notice_entries: u64,
    /// Hold identity used by the CAS.
    pub hold_id: String,
    /// Fixed explanation of scope and limits.
    pub coverage: String,
}
/// One owner page item; each section returns exactly one item kind.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "item", rename_all = "snake_case")]
pub enum Item {
    /// Exact UTF-8 slice; concatenation by field reconstructs the frozen bytes.
    Content {
        /// Field name.
        field: String,
        /// Inclusive byte offset.
        offset: u64,
        /// Full field length.
        total_bytes: u64,
        /// Full field digest.
        sha256: String,
        /// Exact text slice.
        text: String,
    },
    /// Frozen roster entry.
    Member(Box<serde_json::Value>),
    /// Required ballot with checks and provenance.
    Ballot(Box<serde_json::Value>),
    /// Held Run facts for one lineage.
    Target(Box<serde_json::Value>),
    /// Notice intent or a linked immutable observation.
    Notice(Box<serde_json::Value>),
}
/// One bounded, cursor-fenced completion page.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    /// Exact pool.
    pub pool_id: String,
    /// Exact completion.
    pub completion_id: String,
    /// Record version.
    pub record_version: u32,
    /// Verified record digest.
    pub record_digest: String,
    /// Integrity algorithm label.
    pub integrity_algorithm: String,
    /// Selected section.
    pub section: Section,
    /// Header, only for the header section.
    pub header: Option<Header>,
    /// Section items.
    pub items: Vec<Item>,
    /// Number of items.
    pub returned: usize,
    /// Whether more items follow.
    pub has_more: bool,
    /// Present exactly when has_more is true.
    pub next_cursor: Option<Cursor>,
    /// Resident observation time; not a record timestamp.
    pub observed_at_unix_ms: u64,
}
impl Page {
    /// Rejects contradictory page envelopes at the owner frontend.
    pub(crate) fn valid(&self, request: &GetRequest) -> bool {
        self.pool_id == request.pool_id
            && self.completion_id == request.completion_id
            && self.section == request.section
            && self.record_version == RECORD_VERSION
            && self.integrity_algorithm == INTEGRITY_ALGORITHM
            && self.returned == self.items.len()
            && self.has_more == self.next_cursor.is_some()
            && self.header.is_some() == (self.section == Section::Header)
            && self.next_cursor.as_ref().is_none_or(|cursor| {
                cursor.completion_id == self.completion_id
                    && cursor.record_digest == self.record_digest
                    && cursor.section == self.section
            })
            && request
                .after
                .as_ref()
                .is_none_or(|cursor| cursor.record_digest == self.record_digest)
    }
}

/// Loads and re-verifies one exact record; a digest mismatch fails closed.
fn verified_record(
    db: &Connection,
    pool_id: &str,
    completion_id: &str,
) -> Result<(RecordBody, String, u64), Fault> {
    let row: Option<(String, String, String, i64)> = db
        .query_row(
            "SELECT pool,record,record_digest,canonical_length FROM completion_records WHERE completion_id=?1",
            [completion_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let (pool, record, digest, length) = row.ok_or(Fault::Forbidden)?;
    if pool != pool_id {
        return Err(Fault::Forbidden);
    }
    let value: serde_json::Value = serde_json::from_str(&record).map_err(|_| Fault::Internal)?;
    let (actual_length, actual) = crate::managed_codec::digest(RECORD_DOMAIN, &value)?;
    let body: RecordBody = serde_json::from_value(value).map_err(|_| Fault::Internal)?;
    if actual != digest
        || i64::try_from(actual_length).ok() != Some(length)
        || body.completion_id != completion_id
        || body.pool_id != pool_id
        || !content_fields(&body)
            .iter()
            .all(|(_, text)| text.is_none_or(Text::valid))
    {
        return Err(Fault::Internal);
    }
    Ok((body, digest, actual_length as u64))
}
fn content_fields(body: &RecordBody) -> [(&'static str, Option<&Text>); 5] {
    [
        ("goal_name", Some(&body.goal.name)),
        ("goal", Some(&body.goal.purpose)),
        ("criteria", Some(&body.criteria.text)),
        ("result", Some(&body.result)),
        ("snapshot", body.snapshot_bytes.as_ref()),
    ]
}
fn notice_entries(db: &Connection, body: &RecordBody) -> Result<Vec<serde_json::Value>, Fault> {
    let mut entries = vec![
        serde_json::json!({"entry":"intent","notice_intent":body.notice_intent,"notice_observed_outcome":body.notice_observed_outcome}),
    ];
    let mut stmt = db.prepare("SELECT sequence,kind,data,observation_digest,record_digest FROM completion_observations WHERE completion_id=?1 ORDER BY sequence")?;
    let rows = stmt
        .query_map([&body.completion_id], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    for (sequence, kind, data, digest, record_digest) in rows {
        let data: serde_json::Value = decoded(&data)?;
        if observation_digest(&body.completion_id, &record_digest, &kind, &data)? != digest {
            return Err(Fault::Internal);
        }
        entries.push(serde_json::json!({"entry":"observation","sequence":sequence.to_string(),"kind":kind,"record_digest":record_digest,"observation_digest":digest,"data":data}));
    }
    Ok(entries)
}
/// Largest UTF-8 boundary at most one chunk after `offset`.
fn chunk_end(text: &str, offset: usize) -> usize {
    let mut end = (offset + CONTENT_CHUNK).min(text.len());
    while end > offset && !text.is_char_boundary(end) {
        end -= 1;
    }
    end
}

/// Builds one owner page in a single read snapshot. No hold or write occurs.
pub(crate) fn page(db: &Connection, request: &GetRequest) -> Result<Page, Fault> {
    request.validate()?;
    let tx = db.unchecked_transaction()?;
    let (body, digest, canonical_length) =
        verified_record(&tx, &request.pool_id, &request.completion_id)?;
    if let Some(cursor) = &request.after
        && (cursor.completion_id != request.completion_id
            || cursor.record_digest != digest
            || cursor.section != request.section)
    {
        return Err(Fault::Stale);
    }
    let limit = usize::from(request.limit);
    let mut header = None;
    let mut items = Vec::new();
    let mut next = None;
    let list = |values: Vec<serde_json::Value>,
                wrap: fn(Box<serde_json::Value>) -> Item|
     -> Result<(Vec<Item>, Option<String>), Fault> {
        let start = match &request.after {
            None => 0,
            Some(cursor) => cursor
                .position
                .parse::<usize>()
                .map_err(|_| Fault::Invalid)?,
        };
        if start > values.len()
            || request
                .after
                .as_ref()
                .is_some_and(|c| c.position != start.to_string())
        {
            return Err(Fault::Stale);
        }
        let end = (start + limit).min(values.len());
        let items = values[start..end]
            .iter()
            .cloned()
            .map(|value| wrap(Box::new(value)))
            .collect();
        Ok((items, (end < values.len()).then(|| end.to_string())))
    };
    match request.section {
        Section::Header => {
            let notices = notice_entries(&tx, &body)?;
            header = Some(Header {
                pool_store_id: body.pool_store_id.clone(),
                commit_sequence: body.commit_sequence,
                source_revision: body.source_revision,
                proposal_id: body.proposal_id.clone(),
                proposal_event_sequence: body.proposal_event_sequence,
                snapshot_present: body.snapshot_present,
                leader_id: body.leader.leader_id.clone(),
                canonical_length,
                notice_observed_outcome: body.notice_observed_outcome.clone(),
                content: content_fields(&body)
                    .iter()
                    .map(|(field, text)| ContentField {
                        field: (*field).into(),
                        present: text.is_some(),
                        length: text.map_or(0, |t| t.length),
                        sha256: text.map(|t| t.sha256.clone()),
                    })
                    .collect(),
                roster_entries: body.roster.members.len() as u64,
                ballots: body.ballots.len() as u64,
                run_targets: body.run_evidence.targets.len() as u64,
                notice_entries: notices.len() as u64,
                hold_id: body.run_evidence.hold.hold_id.clone(),
                coverage: "Immutable committed record verified against its digest on this read. The digest detects alteration within the local trust model; it is not an authorship signature or anti-rollback proof. Notice and release are later linked observations.".into(),
            });
        }
        Section::Content => {
            // Every present field yields at least one slice, so an empty snapshot stays visible.
            let mut chunks = Vec::new();
            for (name, text) in content_fields(&body) {
                let Some(text) = text else { continue };
                let mut offset = 0;
                loop {
                    let end = chunk_end(&text.text, offset);
                    chunks.push((name, text, offset, end));
                    if end >= text.text.len() {
                        break;
                    }
                    offset = end;
                }
            }
            let start = match &request.after {
                None => 0,
                Some(cursor) => chunks
                    .iter()
                    .position(|(name, _, offset, _)| cursor.position == format!("{name}:{offset}"))
                    .ok_or(Fault::Stale)?,
            };
            let end = (start + limit).min(chunks.len());
            for (name, text, offset, stop) in &chunks[start..end] {
                items.push(Item::Content {
                    field: (*name).into(),
                    offset: *offset as u64,
                    total_bytes: text.length,
                    sha256: text.sha256.clone(),
                    text: text.text[*offset..*stop].to_owned(),
                });
            }
            if let Some((name, _, offset, _)) = chunks.get(end) {
                next = Some(format!("{name}:{offset}"));
            }
        }
        Section::Roster => {
            let values = body
                .roster
                .members
                .iter()
                .map(|member| serde_json::to_value(member).map_err(|_| Fault::Internal))
                .collect::<Result<Vec<_>, _>>()?;
            (items, next) = list(values, Item::Member)?;
        }
        Section::Ballots => {
            let values = body
                .ballots
                .iter()
                .map(|ballot| serde_json::to_value(ballot).map_err(|_| Fault::Internal))
                .collect::<Result<Vec<_>, _>>()?;
            (items, next) = list(values, Item::Ballot)?;
        }
        Section::RunFacts => {
            let hold = serde_json::json!({"entry":"hold","run_store_id":body.run_evidence.run_store_id,"route_digest":body.run_evidence.route_digest,"hold":body.run_evidence.hold,"status_observed_at":body.run_evidence.status_observed_at,"scope":body.run_evidence.scope});
            let mut values = vec![hold];
            for target in &body.run_evidence.targets {
                let mut value = serde_json::to_value(target).map_err(|_| Fault::Internal)?;
                value
                    .as_object_mut()
                    .ok_or(Fault::Internal)?
                    .insert("entry".into(), "target".into());
                values.push(value);
            }
            (items, next) = list(values, Item::Target)?;
        }
        Section::Notice => {
            (items, next) = list(notice_entries(&tx, &body)?, Item::Notice)?;
        }
    }
    tx.commit()?;
    let next_cursor = next.map(|position| Cursor {
        version: 1,
        completion_id: request.completion_id.clone(),
        record_digest: digest.clone(),
        section: request.section,
        position,
    });
    Ok(Page {
        pool_id: request.pool_id.clone(),
        completion_id: request.completion_id.clone(),
        record_version: body.record_version,
        record_digest: digest,
        integrity_algorithm: body.integrity_algorithm,
        section: request.section,
        header,
        returned: items.len(),
        items,
        has_more: next_cursor.is_some(),
        next_cursor,
        observed_at_unix_ms: crate::observer::now()?,
    })
}
