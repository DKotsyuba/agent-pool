//! P3 owner-authorized managed enrollment (P3-E) and conditioned replacement (P3-X).
//!
//! Only the authenticated pool owner reaches the reservation functions, from the
//! existing leader-checked domain transaction. Every Run request ID, complete
//! parameter object and fingerprint is durable before Run I/O; recovery uses the
//! original key only (same-key submit, lookup, abort) and never a new start.
//! Admission, generation-1 binding, onboarding delivery and join remain separate
//! recorded facts; only an authenticated managed `pool_join` activates a member.
use crate::{
    domain::{
        Binding, EnrollmentGet, EnrollmentJobView, EnrollmentResolve, EnrollmentView, Fault,
        MemberState, Reply, identifier,
    },
    managed_state::{
        CurrentReceipt, Incarnation, ManagedBinding, Route, RunEndpointPin, receipt_matches,
        valid_ingress_receipt,
    },
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Fingerprint domain of `run-p3-wire.md`, including its NUL separator.
pub(crate) const FINGERPRINT_DOMAIN: &[u8] = b"agent-mcp/enrollment/start/v1\0";
/// Run capability that must be advertised before any NEW admission.
pub(crate) const CAPABILITY: &str = "managed_enrollment_v1";
/// Enrollment states that can still change Run admission or the frozen roster.
const OPEN_STATES: &str = "'reserved','submit_possible','admitted'";

/// Version 15 adds the private owner enrollment journal and its per-job facts.
pub(crate) fn migrate(db: &Connection) -> Result<(), Fault> {
    db.execute_batch("\
CREATE TABLE managed_enrollments(id TEXT PRIMARY KEY,pool TEXT NOT NULL REFERENCES pools(id),owner TEXT NOT NULL,mode TEXT NOT NULL CHECK(mode IN ('start','replace')),domain_scope TEXT NOT NULL,domain_key TEXT NOT NULL,domain_digest TEXT NOT NULL,request_id TEXT NOT NULL UNIQUE,route TEXT NOT NULL,params TEXT,fingerprint TEXT,replacement TEXT,state TEXT NOT NULL CHECK(state IN ('reserved','submit_possible','admitted','refused','aborted','switched','abandoned','resolved')),submit_attempts INTEGER NOT NULL DEFAULT 0 CHECK(submit_attempts>=0),abort_requested INTEGER NOT NULL DEFAULT 0 CHECK(abort_requested IN (0,1)),receipt TEXT,revision INTEGER NOT NULL DEFAULT 1 CHECK(revision>0),attention TEXT,UNIQUE(domain_scope,domain_key));\
CREATE INDEX managed_enrollment_state ON managed_enrollments(state,pool);\
CREATE TABLE managed_enrollment_jobs(enrollment TEXT NOT NULL REFERENCES managed_enrollments(id),idx INTEGER NOT NULL CHECK(idx>=0 AND idx<20),member TEXT NOT NULL UNIQUE,original_spec TEXT NOT NULL,admission TEXT,lineage_root_id TEXT UNIQUE,state TEXT NOT NULL CHECK(state IN ('reserved','admitted','bound_pending_join','active','unassigned','retired')),current_request_id TEXT UNIQUE,current_sent INTEGER NOT NULL DEFAULT 0 CHECK(current_sent IN (0,1)),current_receipt TEXT,qualification TEXT,bound_generation INTEGER,attention TEXT,PRIMARY KEY(enrollment,idx));\
CREATE TRIGGER managed_enrollment_frozen BEFORE UPDATE OF id,pool,owner,mode,domain_scope,domain_key,domain_digest,request_id,route,replacement ON managed_enrollments WHEN OLD.id IS NOT NEW.id OR OLD.pool IS NOT NEW.pool OR OLD.owner IS NOT NEW.owner OR OLD.mode IS NOT NEW.mode OR OLD.domain_scope IS NOT NEW.domain_scope OR OLD.domain_key IS NOT NEW.domain_key OR OLD.domain_digest IS NOT NEW.domain_digest OR OLD.request_id IS NOT NEW.request_id OR OLD.route IS NOT NEW.route OR OLD.replacement IS NOT NEW.replacement BEGIN SELECT RAISE(ABORT,'immutable managed enrollment'); END;\
CREATE TRIGGER managed_enrollment_key_frozen BEFORE UPDATE OF params,fingerprint,receipt ON managed_enrollments WHEN (OLD.params IS NOT NULL AND OLD.params IS NOT NEW.params) OR (OLD.fingerprint IS NOT NULL AND OLD.fingerprint IS NOT NEW.fingerprint) OR (OLD.receipt IS NOT NULL AND OLD.receipt IS NOT NEW.receipt) OR (OLD.params IS NOT NEW.params AND OLD.state!='reserved') BEGIN SELECT RAISE(ABORT,'immutable managed enrollment key'); END;\
CREATE TRIGGER managed_enrollment_terminal BEFORE UPDATE OF state ON managed_enrollments WHEN OLD.state IN ('refused','aborted','switched','abandoned','resolved') AND NEW.state IS NOT OLD.state BEGIN SELECT RAISE(ABORT,'terminal managed enrollment'); END;\
CREATE TRIGGER managed_enrollment_retained BEFORE DELETE ON managed_enrollments BEGIN SELECT RAISE(ABORT,'retained managed enrollment'); END;\
CREATE TRIGGER managed_enrollment_job_frozen BEFORE UPDATE OF enrollment,idx,member,original_spec,admission,lineage_root_id ON managed_enrollment_jobs WHEN OLD.enrollment IS NOT NEW.enrollment OR OLD.idx IS NOT NEW.idx OR OLD.member IS NOT NEW.member OR OLD.original_spec IS NOT NEW.original_spec OR (OLD.admission IS NOT NULL AND OLD.admission IS NOT NEW.admission) OR (OLD.lineage_root_id IS NOT NULL AND OLD.lineage_root_id IS NOT NEW.lineage_root_id) BEGIN SELECT RAISE(ABORT,'immutable managed enrollment job'); END;\
CREATE TRIGGER managed_enrollment_job_retained BEFORE DELETE ON managed_enrollment_jobs BEGIN SELECT RAISE(ABORT,'retained managed enrollment job'); END;")?;
    // Owner-visible facts advance the source revision; per-attempt observation
    // and recovery counters do not, so a waiting enrollment cannot churn cursors.
    for (table, columns) in [
        (
            "managed_enrollments",
            "state,params,fingerprint,receipt,revision,attention,abort_requested",
        ),
        (
            "managed_enrollment_jobs",
            "state,admission,lineage_root_id,bound_generation,attention,qualification,current_receipt",
        ),
    ] {
        db.execute_batch(&format!(
            "CREATE TRIGGER inventory_rev_{table}_INSERT AFTER INSERT ON {table} BEGIN UPDATE inventory_source SET revision=revision+1 WHERE singleton=1; END;\
CREATE TRIGGER inventory_rev_{table}_UPDATE AFTER UPDATE OF {columns} ON {table} BEGIN UPDATE inventory_source SET revision=revision+1 WHERE singleton=1; END;\
CREATE TRIGGER inventory_rev_{table}_DELETE AFTER DELETE ON {table} BEGIN UPDATE inventory_source SET revision=revision+1 WHERE singleton=1; END;"
        ))?;
    }
    Ok(())
}

/// Configured private transport frozen into every new enrollment before I/O.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnrollmentRoute {
    /// Pinned Run `attempt.sock` endpoint and build.
    pub run: RunEndpointPin,
    /// Authenticated Pool route registered in Run.
    pub pool_route: Route,
    /// Bridge route used for current attestations.
    pub bridge_route: Route,
    /// Bridge producer pinned on both sides.
    pub producer: String,
    /// Exact managed role selected for every job.
    pub role: String,
    /// Public Run status route, required only for conditioned replacement.
    pub status: Option<crate::domain::RunRoute>,
}
impl EnrollmentRoute {
    /// Same configured routes and endpoint; an approved re-pin of the build or a
    /// changed role for new keys does not retarget an existing key.
    pub(crate) fn same_identity(&self, other: &Self) -> bool {
        self.run.route == other.run.route
            && self.run.socket == other.run.socket
            && self.pool_route == other.pool_route
            && self.bridge_route == other.bridge_route
            && self.producer == other.producer
    }
}

/// Frozen replacement source; the old member stays current until the switch commits.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReplacementFreeze {
    /// Exact old membership incarnation.
    pub old: Binding,
    /// Old managed binding generation, absent for an unbound Run member.
    pub generation: Option<u64>,
    /// Stable roster slot inherited by the candidate.
    pub slot: String,
    /// Reserved candidate membership, inserted only by the switch transaction.
    pub candidate: Binding,
    /// Old lineage selector for Run status, built from the retained admission.
    pub target: crate::run_status::Target,
    /// Run store of the old lineage.
    pub store_id: String,
    /// Exact task-enriched managed spec submitted for the candidate.
    pub submitted: Value,
}

/// One Run admission; durable facts, not attempt/launch/qualification evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Admission {
    pub index: usize,
    pub member_id: String,
    pub lineage_root_id: String,
    pub execution_id: String,
    pub sequence: u32,
    pub execution_ref: String,
    pub pin_id: String,
    pub managed_role_name: String,
    pub role_digest: String,
}
/// Immutable batch admission receipt, replayed unchanged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StartReceipt {
    pub version: u8,
    pub store_id: String,
    pub request_id: String,
    pub receipt_id: String,
    pub fingerprint: String,
    pub state: String,
    pub jobs: Vec<Admission>,
}
/// Run supervisor qualification for one exact current launch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Qualification {
    pub launch_id: String,
    pub role_digest: String,
    pub config_digest: String,
    pub inventory_digest: String,
}
/// Diagnostic per-job snapshot; never binding authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JobState {
    pub index: usize,
    pub member_id: String,
    pub state: String,
    #[serde(deserialize_with = "crate::managed_state::required_option")]
    pub failure_code: Option<String>,
    #[serde(deserialize_with = "crate::managed_state::required_option")]
    pub last_attempt: Option<crate::managed_state::AttemptRef>,
    #[serde(deserialize_with = "crate::managed_state::required_option")]
    pub incarnation: Option<Incarnation>,
    #[serde(deserialize_with = "crate::managed_state::required_option")]
    pub qualification: Option<Qualification>,
}
/// Exact-key lookup or abort result; `absent` is a snapshot, never a fence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Lookup {
    pub version: u8,
    pub store_id: String,
    pub request_id: String,
    pub fingerprint: String,
    pub state: String,
    #[serde(deserialize_with = "crate::managed_state::required_option")]
    pub receipt: Option<StartReceipt>,
    pub jobs_state: Vec<JobState>,
}
/// Permanent exact key of one enrollment under its original Pool route.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Key {
    pub expected_store_id: String,
    pub pool_store_id: String,
    pub request_id: String,
    pub fingerprint: String,
}
impl Key {
    /// Closed lookup/abort parameter object.
    pub(crate) fn params(&self) -> Value {
        json!({"version":1,"expected_store_id":self.expected_store_id,"pool_store_id":self.pool_store_id,"request_id":self.request_id,"fingerprint":self.fingerprint})
    }
}

/// Typed Run enrollment outcome classes; diagnostics stay fixed and bounded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    /// Definitive typed refusal before admission, when correlated with the first submission.
    Refused(&'static str),
    /// `attempt_not_ready`: retry the same current observation later.
    NotReady,
    /// `request_in_progress` or `outcome_unknown`: original-key lookup/replay.
    InProgress,
    /// Durable abort tombstone.
    Aborted,
    /// The observation key is pinned to a stale launch; use a fresh current key.
    Stale,
    /// Missing/changed route, provenance or capacity needs operator recovery.
    Operator(&'static str),
    /// Transport or correlation uncertainty; never proof of no effect.
    Unknown,
}
impl Failure {
    /// Classifies one authenticated closed Run error envelope.
    pub(crate) fn classify(code: &str, recovery: &str) -> Self {
        const DEFINITIVE: [&str; 10] = [
            "unsupported_version",
            "capability_missing",
            "peer_not_authorized",
            "role_mismatch",
            "role_unqualified",
            "precondition_failed",
            "intent_conflict",
            "route_mismatch",
            "attempt_mismatch",
            "invalid",
        ];
        match (code, recovery) {
            ("enrollment_aborted", "none") => Self::Aborted,
            ("attempt_not_ready", "same_key_lookup") => Self::NotReady,
            ("request_in_progress" | "outcome_unknown", "same_key_lookup") => Self::InProgress,
            ("binding_stale", "fresh_invocation") => Self::Stale,
            // Not a definitive refusal in the P3 wire contract: Run keeps the
            // key prepared, so Pool keeps it submit_possible and replays it.
            ("capacity_exhausted", _) => Self::Operator("capacity_exhausted"),
            ("recovery_required", "operator") => Self::Operator("recovery_required"),
            (_, "operator") => Self::Operator("binding_unavailable"),
            (code, "none") => DEFINITIVE
                .iter()
                .find(|known| **known == code)
                .map_or(Self::Unknown, |known| Self::Refused(known)),
            _ => Self::Unknown,
        }
    }
    /// Stable owner-visible attention code.
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Refused(code) | Self::Operator(code) => code,
            Self::NotReady => "attempt_not_ready",
            Self::InProgress => "outcome_unknown",
            Self::Aborted => "enrollment_aborted",
            Self::Stale => "binding_stale",
            Self::Unknown => "outcome_unknown",
        }
    }
}

/// Fresh Run attestation of a member's current launch, verified by receipt lookup.
pub(crate) struct Attested {
    pub authority: crate::managed_run::CurrentAuthority,
    pub qualification: Qualification,
    pub admission_receipt_id: String,
}

/// Classification of an old lineage read through Run status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum OldStatus {
    /// Exact terminal, cleaned latest execution with active pin and coverage.
    Ready(crate::run_status::Target),
    /// Proven busy, unclean or otherwise not replaceable.
    NotReady,
    /// Missing evidence; retry later.
    Unavailable,
}

fn encoded<T: Serialize>(value: &T) -> Result<String, Fault> {
    serde_json::to_string(value).map_err(|_| Fault::Internal)
}
fn decoded<T: for<'a> Deserialize<'a>>(text: &str) -> Result<T, Fault> {
    serde_json::from_str(text).map_err(|_| Fault::Internal)
}
fn pool_store_id(db: &Connection) -> Result<String, Fault> {
    Ok(db.query_row(
        "SELECT store_id FROM inventory_source WHERE singleton=1",
        [],
        |row| row.get(0),
    )?)
}

/// Lowercase SHA-256 over the published domain and canonical tagged encoding.
pub(crate) fn fingerprint(params: &Value) -> Result<String, Fault> {
    Ok(crate::managed_codec::digest(FINGERPRINT_DOMAIN, params)?.1)
}

/// Normalize one owner spec for the exact managed role, without choosing anything implicitly.
/// Returns the original spec (retained for replacement) and the task-enriched submitted spec.
pub(crate) fn managed_spec(spec: &Value, role: &str, intro: &str) -> Result<Value, Fault> {
    let mut submitted = spec.clone();
    let object = submitted.as_object_mut().ok_or(Fault::Invalid)?;
    if object.get("profile").and_then(Value::as_str) != Some(role)
        || object.contains_key("request_id")
        || object.contains_key("orchestrator")
        || object.contains_key("required_mcp")
        || object
            .get("explicit_finish")
            .is_some_and(|value| value != &json!(true))
        || object
            .get("write")
            .is_some_and(|value| value != &json!(false))
    {
        return Err(Fault::Invalid);
    }
    let task = object
        .get("task")
        .and_then(Value::as_str)
        .ok_or(Fault::Invalid)?
        .to_owned();
    object.insert("task".into(), Value::String(format!("{task}\n\n{intro}")));
    object.insert("explicit_finish".into(), Value::Bool(true));
    object.insert("write".into(), Value::Bool(false));
    Ok(submitted)
}

/// One owner job: reserved member, retained original spec and submitted spec.
pub(crate) struct ReservedJob {
    pub member_id: String,
    pub original: Value,
    pub submitted: Value,
}

/// Build the complete closed `_managed_start_batch_v1` parameter object.
fn start_params(
    route: &EnrollmentRoute,
    store: &str,
    pool_id: &str,
    request_id: &str,
    mode: &str,
    jobs: &[(&str, &Value)],
    preconditions: &[crate::run_status::Target],
) -> Result<Value, Fault> {
    let params = json!({
        "version":1,
        "expected_store_id":route.run.route.component_store_id,
        "pool_store_id":store,
        "pool_id":pool_id,
        "request_id":request_id,
        "mode":mode,
        "jobs":jobs.iter().map(|(member, spec)| json!({"member_id":member,"selector":{"version":1,"role_name":route.role},"spec":spec})).collect::<Vec<_>>(),
        "preconditions":preconditions,
    });
    let envelope = json!({"id":"f".repeat(256),"method":"_managed_start_batch_v1","params":params});
    if serde_json::to_vec(&envelope)
        .map_err(|_| Fault::Invalid)?
        .len()
        + 1
        >= crate::integrations::MAX_FRAME
    {
        return Err(Fault::Invalid);
    }
    Ok(params)
}

/// Inside the owner's authorized domain transaction: persist the complete
/// enrollment intent and route before any Run I/O can occur.
#[allow(
    clippy::too_many_arguments,
    reason = "The owner scope, replay key and frozen route are separate durable facts"
)]
pub(crate) fn reserve(
    db: &Connection,
    route: &EnrollmentRoute,
    pool_id: &str,
    owner: &str,
    scope: &str,
    request_key: &str,
    digest: &str,
    jobs: &[ReservedJob],
    replacement: Option<&ReplacementFreeze>,
) -> Result<String, Fault> {
    if db.is_autocommit()
        || jobs.is_empty()
        || jobs.len() > 20
        || (replacement.is_some() && jobs.len() != 1)
    {
        return Err(Fault::Internal);
    }
    let store = pool_store_id(db)?;
    if route.pool_route.component_store_id != store {
        return Err(Fault::Unavailable);
    }
    let id = crate::domain::id();
    let request_id = format!("agent-pool.enroll.{}", crate::domain::id());
    let ordered: Vec<_> = jobs
        .iter()
        .map(|job| (job.member_id.as_str(), &job.submitted))
        .collect();
    // A replacement freezes its exact Run precondition before the first possible
    // submission; its complete parameters and fingerprint are frozen with it.
    let (mode, params, fingerprint) = match replacement {
        None => {
            let params = start_params(route, &store, pool_id, &request_id, "start", &ordered, &[])?;
            let fingerprint = fingerprint(&params)?;
            ("start", Some(encoded(&params)?), Some(fingerprint))
        }
        Some(_) => {
            let bound = crate::run_status::Target {
                agent_id: "ag-20260101-000000-0000000000".into(),
                sequence: u32::MAX,
                execution_ref: format!("ex1_{}", "0".repeat(64)),
                pin_id: format!("pin_{}", "0".repeat(32)),
            };
            start_params(
                route,
                &store,
                pool_id,
                &request_id,
                "replace",
                &ordered,
                &[bound],
            )?;
            ("replace", None, None)
        }
    };
    db.execute(
        "INSERT INTO managed_enrollments(id,pool,owner,mode,domain_scope,domain_key,domain_digest,request_id,route,params,fingerprint,replacement,state) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,'reserved')",
        params![
            id,
            pool_id,
            owner,
            mode,
            scope,
            request_key,
            digest,
            request_id,
            encoded(route)?,
            params,
            fingerprint,
            replacement.map(encoded).transpose()?
        ],
    )?;
    for (index, job) in jobs.iter().enumerate() {
        identifier(&job.member_id)?;
        db.execute(
            "INSERT INTO managed_enrollment_jobs(enrollment,idx,member,original_spec,state) VALUES(?1,?2,?3,?4,'reserved')",
            params![id, i64::try_from(index).map_err(|_| Fault::Internal)?, job.member_id, encoded(&job.original)?],
        )?;
    }
    Ok(id)
}

/// One durable enrollment row.
#[derive(Clone)]
pub(crate) struct Enrollment {
    pub id: String,
    pub pool: String,
    pub mode: String,
    pub request_id: String,
    pub route: EnrollmentRoute,
    pub params: Option<Value>,
    pub fingerprint: Option<String>,
    pub replacement: Option<ReplacementFreeze>,
    pub state: String,
    pub abort_requested: bool,
    pub receipt: Option<StartReceipt>,
    pub revision: u64,
    pub attention: Option<String>,
}
impl Enrollment {
    /// Exact original Run key; available only after params are frozen.
    pub(crate) fn key(&self) -> Result<Key, Fault> {
        Ok(Key {
            expected_store_id: self.route.run.route.component_store_id.clone(),
            pool_store_id: self.route.pool_route.component_store_id.clone(),
            request_id: self.request_id.clone(),
            fingerprint: self.fingerprint.clone().ok_or(Fault::Unavailable)?,
        })
    }
}
/// One durable per-member job row.
#[derive(Clone)]
pub(crate) struct Job {
    pub index: usize,
    pub member: String,
    pub admission: Option<Admission>,
    pub state: String,
    pub bound_generation: Option<u64>,
    pub attention: Option<String>,
}

pub(crate) fn load(db: &Connection, id: &str) -> Result<(Enrollment, Vec<Job>), Fault> {
    type Row = (
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
        bool,
        Option<String>,
        i64,
        Option<String>,
    );
    let row: Option<Row> = db
        .query_row(
            "SELECT id,pool,mode,request_id,route,params,fingerprint,replacement,state,abort_requested,receipt,revision,attention FROM managed_enrollments WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?, r.get(10)?, r.get(11)?, r.get(12)?)),
        )
        .optional()?;
    let (
        id,
        pool,
        mode,
        request_id,
        route,
        params,
        fingerprint,
        replacement,
        state,
        abort_requested,
        receipt,
        revision,
        attention,
    ) = row.ok_or(Fault::Forbidden)?;
    let enrollment = Enrollment {
        id,
        pool,
        mode,
        request_id,
        route: decoded(&route)?,
        params: params.as_deref().map(decoded).transpose()?,
        fingerprint,
        replacement: replacement.as_deref().map(decoded).transpose()?,
        state,
        abort_requested,
        receipt: receipt.as_deref().map(decoded).transpose()?,
        revision: u64::try_from(revision).map_err(|_| Fault::Internal)?,
        attention,
    };
    let mut stmt = db.prepare("SELECT idx,member,admission,state,bound_generation,attention FROM managed_enrollment_jobs WHERE enrollment=?1 ORDER BY idx")?;
    let jobs = stmt
        .query_map([&enrollment.id], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<i64>>(4)?,
                r.get::<_, Option<String>>(5)?,
            ))
        })?
        .map(|row| {
            let (index, member, admission, state, generation, attention) = row?;
            Ok(Job {
                index: usize::try_from(index).map_err(|_| Fault::Internal)?,
                member,
                admission: admission.as_deref().map(decoded).transpose()?,
                state,
                bound_generation: generation
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|_| Fault::Internal)?,
                attention,
            })
        })
        .collect::<Result<Vec<_>, Fault>>()?;
    Ok((enrollment, jobs))
}

/// One enrollment that still needs Run I/O, with its keyset position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Pending {
    pub rowid: i64,
    pub id: String,
    pub state: String,
    pub revision: u64,
}

/// Enrollments that still need Run I/O (unsubmitted, uncertain or
/// admitted-unbound), one keyset page from `from` (inclusive) in journal order.
/// The caller rotates `from` so no enrollment past the first page starves.
pub(crate) fn pending(db: &Connection, from: i64, limit: u32) -> Result<Vec<Pending>, Fault> {
    let mut stmt = db.prepare("SELECT e.rowid,e.id,e.state,e.revision FROM managed_enrollments e WHERE e.rowid>=?1 AND (e.state IN ('reserved','submit_possible') OR (e.state='admitted' AND EXISTS(SELECT 1 FROM managed_enrollment_jobs j WHERE j.enrollment=e.id AND j.state='admitted'))) ORDER BY e.rowid LIMIT ?2")?;
    stmt.query_map(params![from, limit], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
        ))
    })?
    .map(|row| {
        let (rowid, id, state, revision) = row?;
        Ok(Pending {
            rowid,
            id,
            state,
            revision: u64::try_from(revision).map_err(|_| Fault::Internal)?,
        })
    })
    .collect()
}

/// A start or replacement that may still change the frozen roster blocks roster edits and close.
pub(crate) fn replacement_open(db: &Connection, pool: &str) -> Result<bool, Fault> {
    Ok(db.query_row(
        &format!("SELECT EXISTS(SELECT 1 FROM managed_enrollments WHERE pool=?1 AND mode='replace' AND state IN ({OPEN_STATES}))"),
        [pool],
        |row| row.get(0),
    )?)
}

/// Any enrollment whose admission or first binding is unresolved fences completion.
pub(crate) fn admission_open(db: &Connection, pool: &str) -> Result<bool, Fault> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM managed_enrollments e WHERE e.pool=?1 AND (e.state IN ('reserved','submit_possible') OR (e.state='admitted' AND (e.mode='replace' OR EXISTS(SELECT 1 FROM managed_enrollment_jobs j WHERE j.enrollment=e.id AND j.state='admitted')))))",
        [pool],
        |row| row.get(0),
    )?)
}

fn bump(db: &Connection, id: &str) -> Result<(), Fault> {
    db.execute(
        "UPDATE managed_enrollments SET revision=revision+1 WHERE id=?1",
        [id],
    )?;
    Ok(())
}

/// Record a fixed attention code only when it changes.
pub(crate) fn note(db: &mut Connection, id: &str, attention: &str) -> Result<(), Fault> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if tx.execute(
        "UPDATE managed_enrollments SET attention=?2 WHERE id=?1 AND attention IS NOT ?2",
        params![id, attention],
    )? == 1
    {
        bump(&tx, id)?;
    }
    tx.commit()?;
    Ok(())
}

/// Record a per-job qualification or recovery reason only when it changes.
pub(crate) fn note_job(
    db: &mut Connection,
    id: &str,
    index: usize,
    attention: &str,
) -> Result<(), Fault> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if tx.execute(
        "UPDATE managed_enrollment_jobs SET attention=?3 WHERE enrollment=?1 AND idx=?2 AND attention IS NOT ?3",
        params![id, i64::try_from(index).map_err(|_| Fault::Internal)?, attention],
    )? == 1
    {
        bump(&tx, id)?;
    }
    tx.commit()?;
    Ok(())
}

/// Definitive unadmission before any submission (switch off, capability missing,
/// unreplaceable old lineage). No Run request has left Pool for this key.
pub(crate) fn refuse_unsubmitted(db: &mut Connection, id: &str, code: &str) -> Result<(), Fault> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if tx.execute(
        "UPDATE managed_enrollments SET state='refused',attention=?2,revision=revision+1 WHERE id=?1 AND state='reserved' AND submit_attempts=0",
        params![id, code],
    )? != 1
    {
        return Err(Fault::Conflict);
    }
    release_refused(&tx, id)?;
    tx.commit()?;
    Ok(())
}

/// Freeze the exact conditioned replacement request after a proven terminal tip.
pub(crate) fn freeze_precondition(
    db: &mut Connection,
    id: &str,
    precondition: &crate::run_status::Target,
) -> Result<(), Fault> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (enrollment, jobs) = load(&tx, id)?;
    let replacement = enrollment.replacement.as_ref().ok_or(Fault::Invalid)?;
    if enrollment.state != "reserved" || enrollment.params.is_some() || jobs.len() != 1 {
        return Err(Fault::Conflict);
    }
    crate::run_status::validate_request(&replacement.store_id, std::slice::from_ref(precondition))
        .map_err(|_| Fault::Invalid)?;
    if precondition.pin_id != replacement.target.pin_id
        || precondition.sequence < replacement.target.sequence
    {
        return Err(Fault::Conflict);
    }
    let store = pool_store_id(&tx)?;
    let params = start_params(
        &enrollment.route,
        &store,
        &enrollment.pool,
        &enrollment.request_id,
        "replace",
        &[(jobs[0].member.as_str(), &replacement.submitted)],
        std::slice::from_ref(precondition),
    )?;
    let fingerprint = fingerprint(&params)?;
    tx.execute(
        "UPDATE managed_enrollments SET params=?2,fingerprint=?3,attention=NULL,revision=revision+1 WHERE id=?1 AND state='reserved' AND params IS NULL",
        params![id, encoded(&params)?, fingerprint],
    )?;
    tx.commit()?;
    Ok(())
}

/// Persist `submit_possible` before the first possible Run request.
pub(crate) fn begin_submit(db: &mut Connection, id: &str) -> Result<(), Fault> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if tx.execute(
        "UPDATE managed_enrollments SET state='submit_possible',submit_attempts=1,attention=NULL,revision=revision+1 WHERE id=?1 AND state='reserved' AND params IS NOT NULL AND submit_attempts=0",
        [id],
    )? != 1
    {
        return Err(Fault::Conflict);
    }
    tx.commit()?;
    Ok(())
}

/// Count each later exact-key recovery attempt before its I/O.
pub(crate) fn begin_recovery(db: &mut Connection, id: &str) -> Result<(), Fault> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if tx.execute(
        "UPDATE managed_enrollments SET submit_attempts=submit_attempts+1 WHERE id=?1 AND state='submit_possible'",
        [id],
    )? != 1
    {
        return Err(Fault::Conflict);
    }
    tx.commit()?;
    Ok(())
}

/// Retire the reserved, never-admitted members of a refused start enrollment
/// and release their roster slots; replacements keep their old member.
fn release_refused(tx: &Connection, id: &str) -> Result<(), Fault> {
    use crate::domain::Author;
    let (enrollment, jobs) = load(tx, id)?;
    if enrollment.mode != "start" {
        return Ok(());
    }
    let (mut pool, _) = crate::store::pool(tx, &enrollment.pool)?;
    let mut removed = Vec::new();
    for job in &jobs {
        let (member, current) = crate::store::binding_any(tx, &job.member)?;
        if current && member.run_id.is_none() {
            crate::store::save_binding(tx, &member, false)?;
            tx.execute(
                "UPDATE effects SET state='cancelled' WHERE member=?1 AND state IN ('queued','awaiting_binding')",
                [&member.member.member_id],
            )?;
            crate::managed_egress::retire_member_scope(
                tx,
                &pool.pool_id,
                &member.member.member_id,
            )?;
            removed.push(member.member.member_id.clone());
        }
    }
    if removed.is_empty() {
        return Ok(());
    }
    pool.revision = pool.revision.checked_add(1).ok_or(Fault::Internal)?;
    crate::store::stale(&mut pool);
    crate::store::save_pool(tx, &pool)?;
    let event = crate::store::append_event(
        tx,
        &pool,
        "enrollment_refused",
        Author::Leader,
        format!(
            "Enrollment {} was refused by Run; its {} reserved member(s) were released.",
            enrollment.id,
            removed.len()
        ),
        None,
    )?;
    let roster = crate::store::bindings(tx, &pool.pool_id)?;
    crate::store::system_deliveries(tx, &pool, &event, &roster, None)?;
    Ok(())
}

/// A correlated definitive refusal settles only the first possible submission;
/// after any earlier uncertainty it is merely recorded as attention.
pub(crate) fn record_refusal(
    db: &mut Connection,
    id: &str,
    code: &str,
    first: bool,
) -> Result<(), Fault> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let settled = first
        && tx.execute(
            "UPDATE managed_enrollments SET state='refused',attention=?2,revision=revision+1 WHERE id=?1 AND state='submit_possible' AND submit_attempts=1",
            params![id, code],
        )? == 1;
    if settled {
        release_refused(&tx, id)?;
    } else {
        tx.execute(
            "UPDATE managed_enrollments SET attention=?2,revision=revision+1 WHERE id=?1 AND attention IS NOT ?2",
            params![id, code],
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// Install a durable abort tombstone result; never after a known admission.
pub(crate) fn record_aborted(db: &mut Connection, id: &str) -> Result<(), Fault> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let state: String = tx.query_row(
        "SELECT state FROM managed_enrollments WHERE id=?1",
        [id],
        |row| row.get(0),
    )?;
    match state.as_str() {
        "aborted" => return Ok(()),
        "reserved" | "submit_possible" => {}
        _ => return Err(Fault::Conflict),
    }
    tx.execute(
        "UPDATE managed_enrollments SET state='aborted',attention='enrollment_aborted',revision=revision+1 WHERE id=?1",
        [id],
    )?;
    tx.commit()?;
    Ok(())
}

/// Owner request to fence an uncertain replacement by exact-key abort.
pub(crate) fn request_abort(db: &Connection, id: &str) -> Result<(), Fault> {
    db.execute(
        "UPDATE managed_enrollments SET abort_requested=1,revision=revision+1 WHERE id=?1 AND state='submit_possible' AND abort_requested=0",
        [id],
    )?;
    Ok(())
}

fn valid_admission(admission: &Admission, index: usize, member: &str, role: &str) -> bool {
    admission.index == index
        && admission.member_id == member
        && admission.managed_role_name == role
        && crate::run_status::valid_agent_id(&admission.lineage_root_id)
        && crate::run_status::valid_agent_id(&admission.execution_id)
        && admission.sequence > 0
        && crate::domain::execution_ref(&admission.execution_ref).is_ok()
        && crate::domain::pin_id(&admission.pin_id).is_ok()
        && admission.role_digest.len() == 64
        && admission
            .role_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Verify and install one correlated original admission receipt in one Pool
/// transaction. An identical replay is harmless; a different one conflicts.
pub(crate) fn record_admission(
    db: &mut Connection,
    id: &str,
    receipt: &StartReceipt,
) -> Result<(), Fault> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (enrollment, jobs) = load(&tx, id)?;
    let params = enrollment.params.as_ref().ok_or(Fault::Conflict)?;
    if let Some(prior) = &enrollment.receipt {
        return if prior == receipt {
            Ok(())
        } else {
            Err(Fault::Conflict)
        };
    }
    if !matches!(enrollment.state.as_str(), "submit_possible" | "reserved")
        || receipt.version != 1
        || receipt.store_id != enrollment.route.run.route.component_store_id
        || receipt.request_id != enrollment.request_id
        || Some(&receipt.fingerprint) != enrollment.fingerprint.as_ref()
        || receipt.state != "admitted"
        || receipt.receipt_id.is_empty()
        || receipt.receipt_id.len() > 256
        || receipt.jobs.len() != jobs.len()
        || params["jobs"].as_array().map(Vec::len) != Some(jobs.len())
    {
        return Err(Fault::Conflict);
    }
    let mut roots = std::collections::BTreeSet::new();
    let mut pins = std::collections::BTreeSet::new();
    let mut refs = std::collections::BTreeSet::new();
    for (job, admission) in jobs.iter().zip(&receipt.jobs) {
        if !valid_admission(admission, job.index, &job.member, &enrollment.route.role)
            || !roots.insert(&admission.lineage_root_id)
            || !pins.insert(&admission.pin_id)
            || !refs.insert(&admission.execution_ref)
        {
            return Err(Fault::Conflict);
        }
        if let Some(replacement) = &enrollment.replacement {
            let old = &replacement.old;
            if old.run_id.as_deref() == Some(admission.lineage_root_id.as_str())
                || old.run_id.as_deref() == Some(admission.execution_id.as_str())
                || replacement.target.agent_id == admission.lineage_root_id
                || old.run_pin_id.as_deref() == Some(admission.pin_id.as_str())
                || old.run_execution_ref.as_deref() == Some(admission.execution_ref.as_str())
            {
                return Err(Fault::Conflict);
            }
        }
        let reused: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM managed_enrollment_jobs WHERE lineage_root_id=?1) OR EXISTS(SELECT 1 FROM members WHERE json_extract(data,'$.run_pin_id')=?2 OR (json_extract(data,'$.run_store_id')=?3 AND json_extract(data,'$.run_id')=?4))",
            params![admission.lineage_root_id, admission.pin_id, receipt.store_id, admission.execution_id],
            |row| row.get(0),
        )?;
        if reused {
            return Err(Fault::Conflict);
        }
    }
    let completed = crate::completion::completed(&tx, &enrollment.pool)?;
    tx.execute(
        "UPDATE managed_enrollments SET state='admitted',receipt=?2,attention=NULL,revision=revision+1 WHERE id=?1",
        params![id, encoded(receipt)?],
    )?;
    for (job, admission) in jobs.iter().zip(&receipt.jobs) {
        let mut state = "admitted";
        let mut attention: Option<&str> = None;
        if completed {
            state = "unassigned";
            attention = Some("pool_completed");
        } else if enrollment.mode == "start" {
            let (mut member, current) = crate::store::binding_any(&tx, &job.member)?;
            if !current || member.pool_id != enrollment.pool || member.run_id.is_some() {
                state = "unassigned";
                attention = Some("member_removed");
            } else {
                member.run_id = Some(admission.execution_id.clone());
                member.run_sequence = Some(u64::from(admission.sequence));
                member.run_execution_ref = Some(admission.execution_ref.clone());
                member.run_pin_id = Some(admission.pin_id.clone());
                member.run_store_id = Some(receipt.store_id.clone());
                crate::store::save_binding(&tx, &member, true)?;
            }
        }
        tx.execute(
            "UPDATE managed_enrollment_jobs SET admission=?3,lineage_root_id=?4,state=?5,attention=?6 WHERE enrollment=?1 AND idx=?2",
            params![
                id,
                i64::try_from(job.index).map_err(|_| Fault::Internal)?,
                encoded(admission)?,
                admission.lineage_root_id,
                state,
                attention
            ],
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// Stage one current observation before I/O. A previously sent key is
/// recovered only to resolve it; its replayed receipt is never fresh authority.
pub(crate) fn stage_observation(
    db: &mut Connection,
    id: &str,
    index: usize,
) -> Result<Option<(String, bool)>, Fault> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let row: Option<(String, Option<String>, bool, String)> = tx
        .query_row(
            "SELECT j.state,j.current_request_id,j.current_sent,e.state FROM managed_enrollment_jobs j JOIN managed_enrollments e ON e.id=j.enrollment WHERE j.enrollment=?1 AND j.idx=?2",
            params![id, i64::try_from(index).map_err(|_| Fault::Internal)?],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let Some((state, current, sent, enrollment_state)) = row else {
        return Err(Fault::Forbidden);
    };
    if state != "admitted" || enrollment_state != "admitted" {
        return Ok(None);
    }
    let staged = match current {
        Some(current) if sent => (current, false),
        Some(current) => (current, true),
        None => (crate::domain::id(), true),
    };
    tx.execute(
        "UPDATE managed_enrollment_jobs SET current_request_id=?3,current_sent=1 WHERE enrollment=?1 AND idx=?2",
        params![id, i64::try_from(index).map_err(|_| Fault::Internal)?, staged.0],
    )?;
    tx.commit()?;
    Ok(Some(staged))
}

/// Settle a staged observation key: `retain` keeps it for a definitive not-ready retry.
pub(crate) fn settle_observation(
    db: &mut Connection,
    id: &str,
    index: usize,
    request_id: &str,
    retain: bool,
) -> Result<(), Fault> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if retain {
        tx.execute(
            "UPDATE managed_enrollment_jobs SET current_sent=0 WHERE enrollment=?1 AND idx=?2 AND current_request_id=?3",
            params![id, i64::try_from(index).map_err(|_| Fault::Internal)?, request_id],
        )?;
    } else {
        tx.execute(
            "UPDATE managed_enrollment_jobs SET current_request_id=NULL,current_sent=0 WHERE enrollment=?1 AND idx=?2 AND current_request_id=?3",
            params![id, i64::try_from(index).map_err(|_| Fault::Internal)?, request_id],
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// Outcome of a generation-1 CAS.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Bound {
    /// This transaction installed generation 1.
    Installed(Box<ManagedBinding>),
    /// Another bootstrap or reconciliation already installed it.
    Already,
}

/// Shared generation-1 CAS for owner reconciliation and the first protected
/// hook. Exactly one caller installs generation 1 for one admitted root.
#[allow(
    clippy::too_many_arguments,
    reason = "Receipt, incarnation and qualification are independent verified facts"
)]
fn install_first(
    tx: &Connection,
    enrollment: &Enrollment,
    job: &Job,
    receipt: &CurrentReceipt,
    qualification: Option<&Qualification>,
    purpose: &str,
    member_pool: &str,
    address_owner: Option<&str>,
) -> Result<Bound, Fault> {
    let admission = job.admission.as_ref().ok_or(Fault::Conflict)?;
    if job.bound_generation.is_some() || job.state != "admitted" {
        return Ok(Bound::Already);
    }
    let store = pool_store_id(tx)?;
    let run_route = &enrollment.route.run.route;
    let binding = ManagedBinding {
        pool_store_id: store,
        pool_id: member_pool.to_owned(),
        member_id: job.member.clone(),
        binding_generation: 1,
        attempt: receipt.attempt.clone(),
        actor: receipt.actor.clone(),
        run_route: run_route.clone(),
        bridge_route: enrollment.route.bridge_route.clone(),
    };
    let mut original = binding.clone();
    original.attempt.execution_id = admission.execution_id.clone();
    original.attempt.sequence = admission.sequence;
    let anchored = match purpose {
        "egress" => {
            receipt.bound_execution_id == admission.execution_id
                && receipt_matches(receipt, &original, &binding, &receipt.incarnation, "egress")
        }
        "ingress" => {
            valid_ingress_receipt(receipt, run_route)
                && receipt_matches(
                    receipt,
                    &original,
                    &binding,
                    &receipt.incarnation,
                    "ingress",
                )
        }
        _ => false,
    };
    if !anchored
        || receipt.lineage_root_id != admission.lineage_root_id
        || receipt.attempt.run_store_id != run_route.component_store_id
        || qualification.is_some_and(|qualification| {
            qualification.launch_id != receipt.attempt.launch_id
                || qualification.role_digest != admission.role_digest
        })
    {
        return Err(Fault::Forbidden);
    }
    let bound: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM managed_bindings WHERE member=?1)",
        [&job.member],
        |row| row.get(0),
    )?;
    if bound {
        return Ok(Bound::Already);
    }
    let address = &receipt.actor.address;
    let busy: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM leaders WHERE address=?1) OR EXISTS(SELECT 1 FROM members WHERE current=1 AND address=?1 AND id<>?2 AND id IS NOT ?3)",
        params![address, job.member, address_owner],
        |row| row.get(0),
    )?;
    if busy {
        return Err(Fault::Conflict);
    }
    tx.execute(
        "INSERT INTO managed_bindings(member,pool,generation,binding,incarnation) VALUES(?1,?2,?3,?4,?5)",
        params![
            job.member,
            member_pool,
            1_u64.to_be_bytes().to_vec(),
            encoded(&binding)?,
            encoded(&receipt.incarnation)?
        ],
    )?;
    tx.execute("INSERT INTO managed_pool_epochs(pool,epoch) VALUES(?1,1) ON CONFLICT(pool) DO UPDATE SET epoch=epoch+1",[member_pool])?;
    tx.execute("INSERT INTO managed_rebinds(receipt_id,member,old_binding,new_binding,generation_before,generation_after) VALUES(?1,?2,'null',?3,?4,?5)",params![receipt.receipt_id,job.member,encoded(&binding)?,0_u64.to_be_bytes().to_vec(),1_u64.to_be_bytes().to_vec()])?;
    tx.execute(
        "UPDATE managed_enrollment_jobs SET state='bound_pending_join',bound_generation=1,current_receipt=?3,qualification=?4,current_request_id=NULL,current_sent=0,attention=NULL WHERE enrollment=?1 AND idx=?2 AND state='admitted' AND bound_generation IS NULL",
        params![
            enrollment.id,
            i64::try_from(job.index).map_err(|_| Fault::Internal)?,
            encoded(receipt)?,
            qualification.map(encoded).transpose()?
        ],
    )?;
    bump(tx, &enrollment.id)?;
    Ok(Bound::Installed(Box::new(binding)))
}

/// Check a start-mode member's reserved slot before the shared CAS.
fn start_member(
    tx: &Connection,
    enrollment: &Enrollment,
    job: &Job,
) -> Result<Option<Binding>, Fault> {
    let admission = job.admission.as_ref().ok_or(Fault::Conflict)?;
    let (member, current) = crate::store::binding_any(tx, &job.member)?;
    let (pool, _) = crate::store::pool(tx, &enrollment.pool)?;
    if !current
        || pool.closed
        || crate::completion::completed(tx, &enrollment.pool)?
        || member.pool_id != enrollment.pool
        || member.member.state != MemberState::Pending
        || member.actor.is_some()
        || member.run_id.as_deref() != Some(admission.execution_id.as_str())
        || member.run_sequence != Some(u64::from(admission.sequence))
        || member.run_store_id.as_deref()
            != Some(enrollment.route.run.route.component_store_id.as_str())
        || member.run_pin_id.as_deref() != Some(admission.pin_id.as_str())
    {
        return Ok(None);
    }
    Ok(Some(member))
}

/// Owner-side reconciliation: bind generation 1 from a fresh qualified current
/// attestation obtained under the original admission key.
pub(crate) fn bind_attested(
    db: &mut Connection,
    id: &str,
    index: usize,
    attested: &Attested,
) -> Result<Bound, Fault> {
    let receipt = attested.authority.receipt();
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (enrollment, jobs) = load(&tx, id)?;
    let job = jobs.get(index).ok_or(Fault::Forbidden)?;
    if enrollment.mode != "start"
        || enrollment.state != "admitted"
        || attested.authority.route() != &enrollment.route.run.route
        || receipt.purpose != "egress"
        || enrollment.receipt.as_ref().map(|r| r.receipt_id.as_str())
            != Some(attested.admission_receipt_id.as_str())
    {
        return Err(Fault::Forbidden);
    }
    let Some(mut member) = start_member(&tx, &enrollment, job)? else {
        return Ok(Bound::Already);
    };
    let bound = install_first(
        &tx,
        &enrollment,
        job,
        receipt,
        Some(&attested.qualification),
        "egress",
        &enrollment.pool,
        None,
    )?;
    if matches!(bound, Bound::Installed(_)) {
        member.address = Some(receipt.actor.address.clone());
        crate::store::save_binding(&tx, &member, true)?;
        tx.commit()?;
    }
    Ok(bound)
}

/// First protected Pool hook: a staged rootless ingress receipt whose root is
/// an owner-admitted, still pending start member installs generation 1.
/// `None` means no admitted enrollment owns that root (or it is already bound).
pub(crate) fn bootstrap_ingress(
    db: &mut Connection,
    authority: &crate::managed_run::CurrentAuthority,
    bridge_route: &Route,
    target_pool: Option<&str>,
) -> Result<Option<ManagedBinding>, Fault> {
    let receipt = authority.receipt();
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let owner: Option<(String, i64)> = tx
        .query_row(
            "SELECT enrollment,idx FROM managed_enrollment_jobs WHERE lineage_root_id=?1",
            [&receipt.lineage_root_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((id, index)) = owner else {
        return if early_root(&tx, authority, bridge_route, target_pool)? {
            // §4 bootstrap race: Run may have admitted this root while Pool has
            // not yet journaled the receipt (ACK loss). Retryable not_ready.
            Err(Fault::Unavailable)
        } else {
            Ok(None)
        };
    };
    let (enrollment, jobs) = load(&tx, &id)?;
    let job = jobs
        .get(usize::try_from(index).map_err(|_| Fault::Internal)?)
        .ok_or(Fault::Internal)?;
    if job.state != "admitted" || job.bound_generation.is_some() {
        return Ok(None);
    }
    if enrollment.mode != "start"
        || enrollment.state != "admitted"
        || target_pool.is_some_and(|pool| pool != enrollment.pool)
        || authority.route() != &enrollment.route.run.route
        || bridge_route != &enrollment.route.bridge_route
    {
        // A replacement candidate becomes a member only by the owner switch.
        return Err(Fault::Unavailable);
    }
    let Some(mut member) = start_member(&tx, &enrollment, job)? else {
        return Err(Fault::Forbidden);
    };
    crate::managed_state::require_staged_current(
        &tx,
        authority,
        receipt,
        authority.route(),
        false,
    )?;
    match install_first(
        &tx,
        &enrollment,
        job,
        receipt,
        None,
        "ingress",
        &enrollment.pool,
        None,
    )? {
        Bound::Installed(binding) => {
            member.address = Some(receipt.actor.address.clone());
            crate::store::save_binding(&tx, &member, true)?;
            tx.commit()?;
            Ok(Some(*binding))
        }
        Bound::Already => Ok(None),
    }
}

/// Whether an unknown root may still be an admitted root of a submitted
/// enrollment whose Run receipt Pool has not journaled yet: a `submit_possible`
/// key on the same Run and Bridge routes, in the hook's target pool. It grants
/// nothing; with no such key a manual or foreign root stays `Forbidden`.
fn early_root(
    tx: &Connection,
    authority: &crate::managed_run::CurrentAuthority,
    bridge_route: &Route,
    target_pool: Option<&str>,
) -> Result<bool, Fault> {
    let receipt = authority.receipt();
    let known: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM members WHERE json_extract(data,'$.run_id')=?1)",
        [&receipt.lineage_root_id],
        |row| row.get(0),
    )?;
    if known {
        return Ok(false);
    }
    // Keyset-page in row order so a match is never hidden behind a page of
    // unrelated routes.
    let mut stmt = tx.prepare(
        "SELECT rowid,route FROM managed_enrollments WHERE state='submit_possible' AND (?1 IS NULL OR pool=?1) AND rowid>?2 ORDER BY rowid LIMIT 64",
    )?;
    let mut after = 0_i64;
    loop {
        let page = stmt
            .query_map(params![target_pool, after], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let Some(&(last, _)) = page.last() else {
            return Ok(false);
        };
        for (_, route) in &page {
            let route: EnrollmentRoute = decoded(route)?;
            if &route.run.route == authority.route()
                && &route.bridge_route == bridge_route
                && receipt.attempt.run_store_id == route.run.route.component_store_id
            {
                return Ok(true);
            }
        }
        after = last;
    }
}

/// Outcome of the conditioned replacement switch.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Switch {
    /// Old member retired; candidate is current, pending join, generation 1.
    Switched,
    /// Already switched by an earlier identical commit.
    Already,
    /// The old roster changed; the qualified candidate is retained unassigned.
    Abandoned,
    /// A conditioned old fact moved; owner attention, nothing changed.
    Attention(&'static str),
}

/// Atomically retire the old member and install the qualified candidate in its slot.
pub(crate) fn switch(db: &mut Connection, id: &str, attested: &Attested) -> Result<Switch, Fault> {
    use crate::domain::Author;
    let receipt = attested.authority.receipt();
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (enrollment, jobs) = load(&tx, id)?;
    if enrollment.state == "switched" {
        return Ok(Switch::Already);
    }
    let replacement = enrollment.replacement.clone().ok_or(Fault::Invalid)?;
    let job = jobs.first().ok_or(Fault::Internal)?;
    if enrollment.mode != "replace"
        || enrollment.state != "admitted"
        || job.state != "admitted"
        || attested.authority.route() != &enrollment.route.run.route
        || receipt.purpose != "egress"
        || enrollment.receipt.as_ref().map(|r| r.receipt_id.as_str())
            != Some(attested.admission_receipt_id.as_str())
    {
        return Err(Fault::Forbidden);
    }
    let old_id = replacement.old.member.member_id.clone();
    let (mut current_old, old_current) = crate::store::binding_any(&tx, &old_id)?;
    current_old.member.runtime = replacement.old.member.runtime.clone();
    let (mut pool, _) = crate::store::pool(&tx, &enrollment.pool)?;
    let abandon = |tx: rusqlite::Transaction<'_>, reason: &str| -> Result<Switch, Fault> {
        tx.execute(
            "UPDATE managed_enrollment_jobs SET state='unassigned',attention=?2 WHERE enrollment=?1 AND state='admitted'",
            params![id, reason],
        )?;
        tx.execute(
            "UPDATE managed_enrollments SET state='abandoned',attention=?2,revision=revision+1 WHERE id=?1",
            params![id, reason],
        )?;
        tx.commit()?;
        Ok(Switch::Abandoned)
    };
    if crate::completion::completed(&tx, &enrollment.pool)? {
        return abandon(tx, "pool_completed");
    }
    if !old_current || pool.closed || current_old != replacement.old {
        return abandon(tx, "roster_stale");
    }
    let generation: Option<Vec<u8>> = tx
        .query_row(
            "SELECT generation FROM managed_bindings WHERE member=?1",
            [&old_id],
            |row| row.get(0),
        )
        .optional()?;
    let generation = generation
        .map(|value| {
            <[u8; 8]>::try_from(value.as_slice())
                .map(u64::from_be_bytes)
                .map_err(|_| Fault::Internal)
        })
        .transpose()?;
    if generation != replacement.generation {
        tx.execute(
            "UPDATE managed_enrollments SET attention='old_rebound',revision=revision+1 WHERE id=?1 AND attention IS NOT 'old_rebound'",
            [id],
        )?;
        tx.commit()?;
        return Ok(Switch::Attention("old_rebound"));
    }
    let occupied: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM members m LEFT JOIN member_slots s ON s.member=m.id WHERE m.pool=?1 AND m.current=1 AND m.id<>?2 AND COALESCE(s.slot,m.id)=?3)",
        params![enrollment.pool, old_id, replacement.slot],
        |row| row.get(0),
    )?;
    let candidate_exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM members WHERE id=?1)",
        [&replacement.candidate.member.member_id],
        |row| row.get(0),
    )?;
    if occupied || candidate_exists {
        return abandon(tx, "roster_stale");
    }
    let admission = job.admission.clone().ok_or(Fault::Conflict)?;
    pool.revision = pool.revision.checked_add(1).ok_or(Fault::Internal)?;
    crate::store::stale(&mut pool);
    crate::store::remove_binding(&tx, &replacement.old, &pool)?;
    let mut candidate = replacement.candidate.clone();
    candidate.run_id = Some(admission.execution_id.clone());
    candidate.run_sequence = Some(u64::from(admission.sequence));
    candidate.run_execution_ref = Some(admission.execution_ref.clone());
    candidate.run_pin_id = Some(admission.pin_id.clone());
    candidate.run_store_id = Some(enrollment.route.run.route.component_store_id.clone());
    candidate.member.state = MemberState::Pending;
    candidate.actor = None;
    candidate.address = None;
    crate::store::save_binding(&tx, &candidate, true)?;
    tx.execute(
        "INSERT INTO member_slots(member,slot) VALUES(?1,?2)",
        params![candidate.member.member_id, replacement.slot],
    )?;
    match install_first(
        &tx,
        &enrollment,
        job,
        receipt,
        Some(&attested.qualification),
        "egress",
        &enrollment.pool,
        Some(&old_id),
    )? {
        Bound::Installed(_) => {}
        Bound::Already => return Err(Fault::Conflict),
    }
    candidate.address = Some(receipt.actor.address.clone());
    crate::store::save_binding(&tx, &candidate, true)?;
    crate::store::save_pool(&tx, &pool)?;
    let event = crate::store::append_event(
        &tx,
        &pool,
        "member_replaced",
        Author::Service,
        format!(
            "Member {old_id} replaced by {} after qualified Run attestation; the new member must join.",
            candidate.member.member_id
        ),
        Some(candidate.member.member_id.clone()),
    )?;
    let roster = crate::store::bindings(&tx, &enrollment.pool)?;
    crate::store::system_deliveries(
        &tx,
        &pool,
        &event,
        &roster,
        Some(&candidate.member.member_id),
    )?;
    crate::store::final_notice(&tx, &pool, &replacement.old, event.event_id)?;
    let intro = crate::store::onboarding(&pool, &roster, &candidate.member)?;
    crate::store::queue_delivery(
        &tx,
        &pool.pool_id,
        Some(&candidate.member.member_id),
        "",
        &crate::store::scope(&candidate.member.member_id),
        intro,
        Some(event.event_id),
    )?;
    tx.execute(
        "UPDATE managed_enrollment_jobs SET state='retired' WHERE member=?1 AND state IN ('bound_pending_join','active')",
        [&old_id],
    )?;
    tx.execute(
        "UPDATE managed_enrollments SET state='switched',attention=NULL,revision=revision+1 WHERE id=?1",
        [id],
    )?;
    tx.commit()?;
    Ok(Switch::Switched)
}

/// P3 join gate: the owner enrollment maps this exact root to a pending member
/// whose qualified binding was installed from enrollment evidence. Eligibility
/// is the job's own `bound_pending_join` fact: an owner `retain_unassigned` that
/// resolved unbound siblings leaves an already-bound job joinable.
pub(crate) fn join_gate(db: &Connection, binding: &ManagedBinding) -> Result<(), Fault> {
    let allowed: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM managed_enrollment_jobs j JOIN managed_enrollments e ON e.id=j.enrollment JOIN pools p ON p.id=e.pool JOIN managed_bindings b ON b.member=j.member WHERE j.member=?1 AND e.pool=?2 AND j.lineage_root_id=?3 AND j.state='bound_pending_join' AND j.bound_generation IS NOT NULL AND e.state IN ('admitted','switched','resolved') AND e.owner=p.owner AND e.receipt IS NOT NULL)",
        params![binding.member_id, binding.pool_id, binding.attempt.lineage_root_id],
        |row| row.get(0),
    )?;
    if allowed {
        Ok(())
    } else {
        Err(Fault::Forbidden)
    }
}

/// Record the separate join fact after the pending->active domain CAS.
pub(crate) fn mark_joined(db: &Connection, member: &str) -> Result<(), Fault> {
    let enrollment: Option<String> = db
        .query_row(
            "SELECT enrollment FROM managed_enrollment_jobs WHERE member=?1 AND state='bound_pending_join'",
            [member],
            |row| row.get(0),
        )
        .optional()?;
    let enrollment = enrollment.ok_or(Fault::Forbidden)?;
    db.execute(
        "UPDATE managed_enrollment_jobs SET state='active' WHERE member=?1 AND state='bound_pending_join'",
        [member],
    )?;
    bump(db, &enrollment)
}

/// Whether a member is a P3 enrollee still awaiting its verified join.
pub(crate) fn pending_enrollee(db: &Connection, member: &str) -> Result<bool, Fault> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM managed_enrollment_jobs WHERE member=?1 AND state IN ('reserved','admitted','bound_pending_join'))",
        [member],
        |row| row.get(0),
    )?)
}

/// Bounded owner projection; private keys, payloads, sockets and sessions excluded.
pub(crate) fn view(db: &Connection, pool_id: &str, id: &str) -> Result<EnrollmentView, Fault> {
    let (enrollment, jobs) = load(db, id)?;
    if enrollment.pool != pool_id {
        return Err(Fault::Forbidden);
    }
    Ok(EnrollmentView {
        pool_id: enrollment.pool.clone(),
        enrollment_id: enrollment.id.clone(),
        mode: enrollment.mode.clone(),
        revision: enrollment.revision,
        state: enrollment.state.clone(),
        attention: enrollment.attention.clone(),
        replaces: enrollment
            .replacement
            .as_ref()
            .map(|replacement| replacement.old.member.member_id.clone()),
        jobs: jobs
            .into_iter()
            .map(|job| EnrollmentJobView {
                index: job.index,
                member_id: job.member,
                state: job.state,
                lineage_root_id: job.admission.as_ref().map(|a| a.lineage_root_id.clone()),
                pin_id: job.admission.as_ref().map(|a| a.pin_id.clone()),
                binding_generation: job.bound_generation,
                attention: job.attention,
            })
            .collect(),
    })
}

/// Owner-only read; authorization precedes any enrollment lookup.
pub(crate) fn owner_get(
    db: &Connection,
    actor: &crate::domain::Actor,
    request: &EnrollmentGet,
) -> Result<Reply, Fault> {
    let (_, owner) = crate::store::pool(db, &request.pool_id)?;
    if owner != actor.key {
        return Err(Fault::Forbidden);
    }
    Ok(Reply::Enrollment(Box::new(view(
        db,
        &request.pool_id,
        &request.enrollment_id,
    )?)))
}

/// Owner `retain_unassigned`: close a definitively admitted enrollment. Only its
/// still-unbound (`admitted`) jobs become unassigned; jobs already bound keep
/// their pending member, binding and join eligibility (`join_gate`). No process
/// is cancelled and no pin is released.
pub(crate) fn owner_resolve(
    db: &Connection,
    actor: &crate::domain::Actor,
    request: &EnrollmentResolve,
    command: &crate::domain::Command,
) -> Result<Reply, Fault> {
    use crate::domain::{Author, Receipt};
    let (mut pool, owner) = crate::store::pool(db, &request.pool_id)?;
    if owner != actor.key {
        return Err(Fault::Forbidden);
    }
    let scope = format!("owner:{}:{}", actor.key, request.pool_id);
    let digest = command.digest()?;
    if let Some(reply) = crate::store::replay(db, &scope, &request.request_key, &digest)? {
        return Ok(reply);
    }
    let (enrollment, jobs) = load(db, &request.enrollment_id)?;
    if enrollment.pool != request.pool_id {
        return Err(Fault::Forbidden);
    }
    if enrollment.revision != request.expected_enrollment_revision {
        return Err(Fault::Stale);
    }
    if enrollment.state != "admitted" || enrollment.receipt.is_none() {
        return Err(Fault::Conflict);
    }
    let mut removed = Vec::new();
    for job in jobs.iter().filter(|job| job.state == "admitted") {
        if enrollment.mode == "start" {
            let (member, current) = crate::store::binding_any(db, &job.member)?;
            let bound: bool = db.query_row(
                "SELECT EXISTS(SELECT 1 FROM managed_bindings WHERE member=?1)",
                [&job.member],
                |row| row.get(0),
            )?;
            if bound {
                return Err(Fault::Conflict);
            }
            if current {
                crate::store::save_binding(db, &member, false)?;
                db.execute(
                    "UPDATE effects SET state='cancelled' WHERE member=?1 AND state IN ('queued','awaiting_binding')",
                    [&member.member.member_id],
                )?;
                crate::managed_egress::retire_member_scope(
                    db,
                    &pool.pool_id,
                    &member.member.member_id,
                )?;
                removed.push(member.member.member_id.clone());
            }
        }
        db.execute(
            "UPDATE managed_enrollment_jobs SET state='unassigned',attention='retained_unassigned' WHERE enrollment=?1 AND idx=?2",
            params![enrollment.id, i64::try_from(job.index).map_err(|_| Fault::Internal)?],
        )?;
    }
    db.execute(
        "UPDATE managed_enrollments SET state='resolved',attention='retained_unassigned',revision=revision+1 WHERE id=?1",
        [&enrollment.id],
    )?;
    pool.revision = pool.revision.checked_add(1).ok_or(Fault::Internal)?;
    if !removed.is_empty() {
        crate::store::stale(&mut pool);
    }
    crate::store::save_pool(db, &pool)?;
    let event = crate::store::append_event(
        db,
        &pool,
        "enrollment_resolved",
        Author::Leader,
        format!(
            "Enrollment {} resolved as retained unassigned; admitted processes were not stopped and pins were retained.",
            enrollment.id
        ),
        None,
    )?;
    let roster = crate::store::bindings(db, &pool.pool_id)?;
    if !removed.is_empty() {
        crate::store::system_deliveries(db, &pool, &event, &roster, None)?;
    }
    let reply = Reply::Receipt(Box::new(Receipt {
        pool_id: pool.pool_id.clone(),
        revision: pool.revision,
        created_id: Some(enrollment.id.clone()),
        created_ids: removed,
        event,
        status: "committed; enrollment resolved".into(),
    }));
    crate::store::remember(db, &scope, &request.request_key, &digest, &reply)?;
    Ok(reply)
}

/// Cancel an owner replacement before any possible submission, or request a
/// same-key abort while its Run outcome is uncertain. Returns the old member ID
/// and whether the cancellation is already definitive.
pub(crate) fn cancel_replacement(
    db: &Connection,
    pool_id: &str,
    id: &str,
) -> Result<Option<(String, bool)>, Fault> {
    let row: Option<(String, String, String, i64)> = db
        .query_row(
            "SELECT pool,mode,state,submit_attempts FROM managed_enrollments WHERE id=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((pool, mode, state, attempts)) = row else {
        return Ok(None);
    };
    if pool != pool_id || mode != "replace" {
        return Err(Fault::Forbidden);
    }
    let (enrollment, _) = load(db, id)?;
    let old = enrollment
        .replacement
        .as_ref()
        .ok_or(Fault::Internal)?
        .old
        .member
        .member_id
        .clone();
    match (state.as_str(), attempts) {
        ("reserved", 0) => {
            db.execute(
                "UPDATE managed_enrollments SET state='resolved',attention='cancelled',revision=revision+1 WHERE id=?1 AND state='reserved' AND submit_attempts=0",
                [id],
            )?;
            Ok(Some((old, true)))
        }
        ("submit_possible", _) => {
            request_abort(db, id)?;
            Ok(Some((old, false)))
        }
        _ => Err(Fault::Conflict),
    }
}
