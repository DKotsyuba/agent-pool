//! Single-writer SQLite state machine. Transactions commit business state and delivery intents together.
use crate::domain::*;
use fs2::FileExt;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    time::Duration,
};

/// Resident-owned connection and exclusive lifetime lease; never held across network operations.
pub struct Store {
    /// SQLite connection; callers serialize access with the resident's short-lived mutex.
    db: Connection,
    /// Exclusive lock remains open until the resident releases the store.
    _lease: File,
    /// Round-robin reconciliation cursor, preventing a permanently unknown head from starving later work.
    unknown_cursor: i64,
    /// Rotating cursors prevent unresolved managed work from starving later records.
    managed_recovery_cursor: i64,
    /// Independent cursor for bootstrap recovery.
    managed_bootstrap_cursor: i64,
    /// Round-robin retirement cursor for managed egress scopes.
    managed_scope_cursor: i64,
    /// Changes on every store open, invalidating cursors across resident restarts.
    read_epoch: String,
    /// Configured P3 enrollment route; absent keeps owner starts on the legacy path.
    enrollment: Option<crate::managed_enrollment::EnrollmentRoute>,
}
/// Durable result of recording one verified Run admission receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admitted {
    /// The receipt is installed (or an identical replay of an installed receipt).
    Installed,
    /// The pool completed first: the exact receipt was retained, the effect is
    /// terminal `reconciliation_needed` and one owner notice is queued.
    ReconciliationNeeded,
}
/// One owner-selected binding and its original route read at a single Pool revision.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RunProofBinding {
    /// Pool revision fencing this projection.
    pub revision: u64,
    /// Exact retained membership and its private Run mapping.
    pub binding: Binding,
    /// Whether this membership is currently in the roster.
    pub current: bool,
    /// Proven unique admission route when the binding has one.
    pub route: Option<RunRoute>,
}
/// Install a durable store identity and transactional revision triggers with the v6 migration.
fn migrate_inventory_source(db: &Connection) -> Result<(), Fault> {
    db.execute_batch("CREATE TABLE inventory_source(singleton INTEGER PRIMARY KEY CHECK(singleton=1), store_id TEXT NOT NULL, revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision>=0));")?;
    db.execute(
        "INSERT INTO inventory_source(singleton,store_id,revision) VALUES(1,?1,0)",
        [id()],
    )?;
    // Every durable state table participates: private/background changes also fence a continuation.
    inventory_revision_triggers(
        db,
        &[
            "leaders",
            "pools",
            "proposals",
            "members",
            "member_slots",
            "requests",
            "events",
            "effects",
            "publications",
            "alerts",
        ],
    )?;
    Ok(())
}

/// New durable tables participate in the same source-wide revision fence.
fn inventory_revision_triggers(db: &Connection, tables: &[&str]) -> Result<(), Fault> {
    for table in tables {
        for action in ["INSERT", "UPDATE", "DELETE"] {
            db.execute_batch(&format!(
                "CREATE TRIGGER inventory_rev_{table}_{action} AFTER {action} ON {table} BEGIN UPDATE inventory_source SET revision=revision+1 WHERE singleton=1; END;"
            ))?;
        }
    }
    Ok(())
}

/// Scope pins from v12 were delivery pins until retirement was prepared.
/// Keep prepared retirement pins, but allow undrained scopes to select the
/// currently approved pin when their retirement is first prepared.
fn migrate_review_v13(db: &Connection) -> Result<(), Fault> {
    db.execute_batch("\
DROP TRIGGER managed_delivery_scope_immutable;\
UPDATE managed_delivery_scopes SET bridge_pin=NULL,audience=NULL WHERE state IN ('open','draining');\
CREATE TRIGGER managed_delivery_scope_immutable BEFORE UPDATE OF producer_scope,pool_id,member_id,retire_request_id,bridge_pin,audience ON managed_delivery_scopes WHEN OLD.producer_scope IS NOT NEW.producer_scope OR OLD.pool_id IS NOT NEW.pool_id OR OLD.member_id IS NOT NEW.member_id OR OLD.retire_request_id IS NOT NEW.retire_request_id OR (OLD.bridge_pin IS NOT NULL AND OLD.bridge_pin IS NOT NEW.bridge_pin) OR (OLD.audience IS NOT NULL AND OLD.audience IS NOT NEW.audience) BEGIN SELECT RAISE(ABORT,'immutable managed delivery scope'); END;\
DROP TRIGGER inventory_rev_completion_sagas_INSERT;\
DROP TRIGGER inventory_rev_completion_sagas_UPDATE;\
DROP TRIGGER inventory_rev_completion_sagas_DELETE;\
DROP TRIGGER inventory_rev_completion_observations_INSERT;\
DROP TRIGGER inventory_rev_completion_observations_UPDATE;\
DROP TRIGGER inventory_rev_completion_observations_DELETE;")?;
    Ok(())
}

/// Version 14 retains the exact Run receipt of an admission that arrived after
/// pool completion. The receipt is immutable evidence for owner reconciliation.
fn migrate_completed_admissions(db: &Connection) -> Result<(), Fault> {
    db.execute_batch("\
CREATE TABLE completed_admissions(effect TEXT PRIMARY KEY REFERENCES effects(id),receipt TEXT NOT NULL);\
CREATE TRIGGER completed_admission_immutable BEFORE UPDATE ON completed_admissions BEGIN SELECT RAISE(ABORT,'immutable completed admission'); END;\
CREATE TRIGGER completed_admission_retained BEFORE DELETE ON completed_admissions BEGIN SELECT RAISE(ABORT,'retained completed admission'); END;")?;
    Ok(())
}

/// Version 7 persists binding generations, pool binding epochs, contexts and verified rebinds.
fn migrate_managed_context(db: &Connection) -> Result<(), Fault> {
    db.execute_batch("\
CREATE TABLE managed_pool_epochs(pool TEXT PRIMARY KEY REFERENCES pools(id), epoch INTEGER NOT NULL CHECK(typeof(epoch)='integer' AND epoch>=0));\
CREATE TABLE managed_bindings(member TEXT PRIMARY KEY REFERENCES members(id), pool TEXT NOT NULL REFERENCES pools(id), generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=8), binding TEXT NOT NULL);\
CREATE TABLE managed_rebinds(receipt_id TEXT PRIMARY KEY, member TEXT NOT NULL REFERENCES members(id), old_binding TEXT NOT NULL, new_binding TEXT NOT NULL, generation_before BLOB NOT NULL CHECK(typeof(generation_before)='blob' AND length(generation_before)=8), generation_after BLOB NOT NULL CHECK(typeof(generation_after)='blob' AND length(generation_after)=8));\
CREATE TABLE managed_bridge_routes(route TEXT PRIMARY KEY, pin TEXT NOT NULL);\
CREATE TABLE managed_run_routes(route TEXT PRIMARY KEY, pin TEXT NOT NULL);\
CREATE TABLE managed_namespaces(id TEXT PRIMARY KEY, bridge_route TEXT NOT NULL, bridge_pin TEXT, producer TEXT NOT NULL, issuer_epoch TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('open','draining','sealed')), request_id TEXT UNIQUE, retirement_key TEXT UNIQUE, seal_id TEXT UNIQUE, UNIQUE(bridge_route,producer,issuer_epoch));\
CREATE TABLE managed_bootstrap(id TEXT PRIMARY KEY, namespace_id TEXT NOT NULL REFERENCES managed_namespaces(id), invocation_key TEXT NOT NULL, command TEXT NOT NULL, proof_hash TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('prepared','submitted','terminal','stale_epoch')), bridge_context_ref TEXT, registration_request_id TEXT, registration_digest TEXT, consume_request_id TEXT, consume_submitted INTEGER NOT NULL DEFAULT 0 CHECK(consume_submitted IN (0,1)), consumed_ref TEXT, consumed_receipt TEXT, bridge_abort_request_id TEXT, abort_receipt TEXT);\
CREATE UNIQUE INDEX managed_bootstrap_invocation ON managed_bootstrap(invocation_key) WHERE state!='stale_epoch';\
CREATE UNIQUE INDEX managed_bootstrap_registration ON managed_bootstrap(registration_request_id) WHERE registration_request_id IS NOT NULL;\
CREATE UNIQUE INDEX managed_bootstrap_consume ON managed_bootstrap(consume_request_id) WHERE consume_request_id IS NOT NULL;\
CREATE UNIQUE INDEX managed_bootstrap_abort ON managed_bootstrap(bridge_abort_request_id) WHERE bridge_abort_request_id IS NOT NULL;\
CREATE TABLE managed_contexts(id TEXT PRIMARY KEY, namespace_id TEXT NOT NULL REFERENCES managed_namespaces(id), intent_id TEXT NOT NULL UNIQUE, invocation_key TEXT NOT NULL UNIQUE, command TEXT NOT NULL, context TEXT NOT NULL, digest TEXT NOT NULL, snapshot TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('prepared','invalidated')));\
CREATE TABLE managed_context_bindings(context_id TEXT NOT NULL REFERENCES managed_contexts(id), member TEXT NOT NULL REFERENCES members(id), generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=8), PRIMARY KEY(context_id,member));\
CREATE TABLE managed_context_epochs(context_id TEXT NOT NULL REFERENCES managed_contexts(id), pool TEXT NOT NULL REFERENCES pools(id), epoch INTEGER NOT NULL, PRIMARY KEY(context_id,pool));")?;
    db.execute_batch("CREATE TABLE managed_current_requests(id TEXT PRIMARY KEY, namespace_id TEXT REFERENCES managed_namespaces(id), run_pin TEXT NOT NULL, request TEXT NOT NULL, digest TEXT NOT NULL, after_consume INTEGER NOT NULL CHECK(after_consume IN (0,1)), state TEXT NOT NULL CHECK(state IN ('prepared','received','used','aborted')), receipt_id TEXT UNIQUE, receipt TEXT);")?;
    inventory_revision_triggers(
        db,
        &[
            "managed_pool_epochs",
            "managed_bindings",
            "managed_rebinds",
            "managed_bridge_routes",
            "managed_run_routes",
            "managed_contexts",
            "managed_context_bindings",
            "managed_context_epochs",
            "managed_namespaces",
            "managed_bootstrap",
            "managed_current_requests",
        ],
    )
}

/// Version 8 adds durable intent/active-domain keys and additive verified ballot provenance.
fn migrate_managed_intents(db: &Connection) -> Result<(), Fault> {
    db.execute_batch("\
CREATE TABLE managed_intents(id TEXT PRIMARY KEY, context_id TEXT NOT NULL UNIQUE REFERENCES managed_contexts(id), scope TEXT NOT NULL, request_key TEXT NOT NULL, domain_digest TEXT NOT NULL, security_digest TEXT NOT NULL, command TEXT NOT NULL, pool_route TEXT NOT NULL, run_route TEXT NOT NULL, run_pin TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('prepared','consuming','admitting','admitted','committed','aborted')), consumed_ref TEXT, consumed_receipt TEXT, admission_id TEXT, admission TEXT, admission_fingerprint TEXT, terminal_receipt TEXT, bridge_abort_receipt TEXT, run_resolution_receipt TEXT, bridge_resolved INTEGER NOT NULL DEFAULT 0 CHECK(bridge_resolved IN (0,1)), run_resolved INTEGER NOT NULL DEFAULT 0 CHECK(run_resolved IN (0,1)), effect_free INTEGER NOT NULL DEFAULT 0 CHECK(effect_free IN (0,1)));\
CREATE TABLE managed_domain_keys(scope TEXT NOT NULL, request_key TEXT NOT NULL, domain_digest TEXT NOT NULL, intent_id TEXT NOT NULL UNIQUE REFERENCES managed_intents(id), PRIMARY KEY(scope,request_key));\
CREATE TABLE managed_ballot_provenance(pool TEXT NOT NULL REFERENCES pools(id), proposal TEXT NOT NULL REFERENCES proposals(id), member TEXT NOT NULL REFERENCES members(id), event_id INTEGER NOT NULL REFERENCES events(id), generation BLOB NOT NULL CHECK(typeof(generation)='blob' AND length(generation)=8), attempt TEXT NOT NULL, incarnation TEXT NOT NULL, admission_id TEXT NOT NULL, security_digest TEXT NOT NULL, PRIMARY KEY(pool,proposal,member,event_id));")?;
    inventory_revision_triggers(
        db,
        &[
            "managed_intents",
            "managed_domain_keys",
            "managed_ballot_provenance",
        ],
    )
}

/// Version 9 retains open-ballot invalidations without changing the pool revision.
fn migrate_managed_review_fixes(db: &Connection) -> Result<(), Fault> {
    db.execute_batch("\
CREATE TABLE managed_invalidated_ballots(pool TEXT NOT NULL REFERENCES pools(id), proposal TEXT NOT NULL REFERENCES proposals(id), member TEXT NOT NULL REFERENCES members(id), PRIMARY KEY(pool,proposal,member));\
ALTER TABLE managed_bindings ADD COLUMN incarnation TEXT;\
ALTER TABLE managed_current_requests ADD COLUMN owner_intent TEXT REFERENCES managed_intents(id);\
UPDATE managed_bindings AS b SET incarnation=(SELECT json_extract(r.receipt,'$.incarnation') FROM managed_rebinds x JOIN managed_current_requests r ON r.receipt_id=x.receipt_id WHERE x.member=b.member AND x.generation_after=b.generation AND r.receipt IS NOT NULL ORDER BY x.rowid DESC LIMIT 1);\
UPDATE managed_current_requests SET state='aborted' WHERE namespace_id IS NULL AND state IN ('prepared','received');\
CREATE INDEX managed_bootstrap_state ON managed_bootstrap(state);\
CREATE INDEX managed_current_state_owner ON managed_current_requests(state,owner_intent,namespace_id);\
CREATE INDEX managed_intent_state ON managed_intents(state,bridge_resolved,run_resolved);")?;
    inventory_revision_triggers(db, &["managed_invalidated_ballots"])?;
    let mut after = String::new();
    loop {
        let next: Option<String> = db.query_row("SELECT id FROM managed_namespaces WHERE state='sealed' AND id>?1 ORDER BY id LIMIT 1",[&after],|row|row.get(0)).optional()?;
        let Some(id) = next else { break };
        crate::managed_state::compact_sealed(db, &id)?;
        after = id;
    }
    Ok(())
}

/// Version 10 separates immutable event seeds from receipt-bound owner outbox work.
fn migrate_managed_egress(db: &Connection) -> Result<(), Fault> {
    db.execute_batch("\
CREATE TABLE managed_delivery_seeds(effect_id TEXT PRIMARY KEY REFERENCES effects(id),pool_id TEXT NOT NULL REFERENCES pools(id),member_id TEXT NOT NULL REFERENCES members(id),event_key TEXT NOT NULL,payload_sha256 TEXT NOT NULL,payload_length INTEGER NOT NULL CHECK(payload_length>=0),producer_scope TEXT NOT NULL,final_notice INTEGER NOT NULL CHECK(final_notice IN (0,1)));\
CREATE TRIGGER managed_delivery_seeds_immutable BEFORE UPDATE ON managed_delivery_seeds BEGIN SELECT RAISE(ABORT,'immutable managed delivery seed'); END;\
CREATE TABLE managed_delivery_outbox(effect_id TEXT PRIMARY KEY REFERENCES managed_delivery_seeds(effect_id),state TEXT NOT NULL CHECK(state IN ('pending','frozen','publishing','known_unsent','unknown','accepted','abort_pending','aborted','not_delivered')),probe_request_id TEXT,probe_pin TEXT,probe_binding TEXT,probe_uncertain INTEGER NOT NULL DEFAULT 0 CHECK(probe_uncertain IN (0,1)),run_pin TEXT,bridge_pin TEXT,audience TEXT,run_receipt_id TEXT,target_binding TEXT,incarnation TEXT,intent TEXT,effect_digest TEXT,dispatch_id TEXT,abort_request_id TEXT,result TEXT,attention TEXT);\
CREATE TRIGGER managed_delivery_target_immutable BEFORE UPDATE OF run_pin,bridge_pin,audience,run_receipt_id,target_binding,incarnation,intent,effect_digest ON managed_delivery_outbox WHEN OLD.state!='pending' AND (OLD.run_pin IS NOT NEW.run_pin OR OLD.bridge_pin IS NOT NEW.bridge_pin OR OLD.audience IS NOT NEW.audience OR OLD.run_receipt_id IS NOT NEW.run_receipt_id OR OLD.target_binding IS NOT NEW.target_binding OR OLD.incarnation IS NOT NEW.incarnation OR OLD.intent IS NOT NEW.intent OR OLD.effect_digest IS NOT NEW.effect_digest) BEGIN SELECT RAISE(ABORT,'immutable managed delivery target'); END;\
CREATE TRIGGER managed_delivery_abort_key_immutable BEFORE UPDATE OF abort_request_id ON managed_delivery_outbox WHEN OLD.abort_request_id IS NOT NULL AND OLD.abort_request_id IS NOT NEW.abort_request_id BEGIN SELECT RAISE(ABORT,'immutable managed abort key'); END;\
CREATE INDEX managed_delivery_outbox_state ON managed_delivery_outbox(state);\
CREATE TABLE managed_delivery_scopes(producer_scope TEXT PRIMARY KEY,pool_id TEXT NOT NULL REFERENCES pools(id),member_id TEXT REFERENCES members(id),state TEXT NOT NULL CHECK(state IN ('open','draining','retiring','retired','compacting','compacted')),retire_request_id TEXT NOT NULL,bridge_pin TEXT,audience TEXT,retire_receipt TEXT,compact_result TEXT,compact_remaining INTEGER);\
CREATE TRIGGER managed_delivery_scope_immutable BEFORE UPDATE OF producer_scope,pool_id,member_id,retire_request_id,bridge_pin,audience ON managed_delivery_scopes WHEN OLD.producer_scope IS NOT NEW.producer_scope OR OLD.pool_id IS NOT NEW.pool_id OR OLD.member_id IS NOT NEW.member_id OR OLD.retire_request_id IS NOT NEW.retire_request_id OR (OLD.bridge_pin IS NOT NULL AND OLD.bridge_pin IS NOT NEW.bridge_pin) OR (OLD.audience IS NOT NULL AND OLD.audience IS NOT NEW.audience) BEGIN SELECT RAISE(ABORT,'immutable managed delivery scope'); END;\
CREATE INDEX managed_delivery_scopes_state ON managed_delivery_scopes(state);")?;
    inventory_revision_triggers(
        db,
        &[
            "managed_delivery_seeds",
            "managed_delivery_outbox",
            "managed_delivery_scopes",
        ],
    )
}

/// Version 11 retains every route pin and freezes the Bridge pin per bootstrap.
fn migrate_managed_route_pins(db: &Connection) -> Result<(), Fault> {
    db.execute_batch("\
CREATE TABLE managed_route_pin_history(kind TEXT NOT NULL CHECK(kind IN ('run','bridge')),route TEXT NOT NULL,generation INTEGER NOT NULL CHECK(generation>0),pin TEXT NOT NULL,PRIMARY KEY(kind,route,generation));\
INSERT INTO managed_route_pin_history SELECT 'run',route,1,pin FROM managed_run_routes;\
INSERT INTO managed_route_pin_history SELECT 'bridge',route,1,pin FROM managed_bridge_routes;\
ALTER TABLE managed_run_routes ADD COLUMN pool_route TEXT;\
UPDATE managed_run_routes SET pool_route=(SELECT MIN(pool_route) FROM managed_intents WHERE run_route=managed_run_routes.route HAVING COUNT(DISTINCT pool_route)=1);\
ALTER TABLE managed_bootstrap ADD COLUMN bridge_pin TEXT;\
UPDATE managed_bootstrap SET bridge_pin=(SELECT bridge_pin FROM managed_namespaces WHERE id=managed_bootstrap.namespace_id);\
ALTER TABLE managed_delivery_seeds ADD COLUMN issuer_namespace TEXT;\
CREATE TABLE managed_namespace_retirements(namespace_id TEXT PRIMARY KEY REFERENCES managed_namespaces(id),plan TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('requested','retired')),attempts INTEGER NOT NULL CHECK(attempts>0),next_attempt INTEGER NOT NULL CHECK(next_attempt>=0));")?;
    Ok(())
}

/// Read totals, page, roster and its revision from one SQLite snapshot.
fn inventory_snapshot(
    db: &Connection,
    epoch: &str,
    args: &crate::observer::InventoryRequest,
) -> Result<crate::observer::Data, Fault> {
    inventory_snapshot_inner(db, epoch, args, || Ok(()))
}

/// The hook runs after the snapshot is pinned; tests use it to interleave a separate writer.
fn inventory_snapshot_inner(
    db: &Connection,
    epoch: &str,
    args: &crate::observer::InventoryRequest,
    after_pin: impl FnOnce() -> Result<(), Fault>,
) -> Result<crate::observer::Data, Fault> {
    use crate::observer::{
        Data, InventoryCursor, InventoryFilter, InventoryRow, InventorySnapshot, InventorySource,
        InventoryTotals,
    };
    let tx = db.unchecked_transaction()?;
    let (store_id, revision): (String, i64) = tx.query_row(
        "SELECT store_id,revision FROM inventory_source WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if revision < 0 {
        return Err(Fault::Internal);
    }
    let source = InventorySource {
        store_id,
        read_epoch: epoch.to_owned(),
        revision: revision.to_string(),
    };
    after_pin()?;
    if let Some(cursor) = &args.cursor
        && (cursor.source != source || cursor.filter != args.filter || cursor.limit != args.limit)
    {
        return Err(Fault::Stale);
    }
    let (total, closed, invalid): (i64, i64, i64) = tx.query_row(
        "SELECT count(*), coalesce(sum(CASE WHEN json_type(data,'$.closed')='true' THEN 1 ELSE 0 END),0), coalesce(sum(CASE WHEN json_type(data,'$.closed') IN ('true','false') THEN 0 ELSE 1 END),0) FROM pools", [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if total < 0 || closed < 0 || invalid != 0 {
        return Err(Fault::Internal);
    }
    let predicate = match args.filter {
        InventoryFilter::All => "1",
        InventoryFilter::Closed => "json_type(data,'$.closed')='true'",
        InventoryFilter::NotClosed => "json_type(data,'$.closed')='false'",
    };
    let after = args
        .cursor
        .as_ref()
        .map_or("", |cursor| cursor.after.as_str());
    if args.cursor.is_some() {
        let exists: bool = tx.query_row(
            &format!("SELECT EXISTS(SELECT 1 FROM pools WHERE id=?1 AND {predicate})"),
            [after],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(Fault::Stale);
        }
    }
    let mut stmt = tx.prepare(&format!(
        "SELECT id,data,owner FROM pools WHERE id>?1 AND {predicate} ORDER BY id LIMIT ?2"
    ))?;
    let rows = stmt
        .query_map(params![after, i64::from(args.limit) + 1], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(stmt);
    let has_more = rows.len() > usize::from(args.limit);
    let mut pools = Vec::with_capacity(rows.len().min(usize::from(args.limit)));
    for (pool_id, data, leader_id) in rows.into_iter().take(usize::from(args.limit)) {
        let mut pool: Pool = decode(&data)?;
        if pool.pool_id != pool_id {
            return Err(Fault::Internal);
        }
        pool.proposal = None;
        pool.acceptance = None;
        project_purpose(&mut pool);
        let mut stmt = tx.prepare("SELECT m.data FROM members m LEFT JOIN member_slots s ON s.member=m.id WHERE m.pool=?1 AND m.current=1 ORDER BY COALESCE(s.slot,m.id),m.id LIMIT 21")?;
        let roster = stmt
            .query_map([&pool_id], |row| row.get::<_, String>(0))?
            .map(|row| {
                let mut binding: Binding = decode(&row?)?;
                if binding.pool_id != pool_id {
                    return Err(Fault::Internal);
                }
                if binding.run_id.is_some() {
                    binding.member.runtime = "unknown".into();
                }
                Ok(binding.member)
            })
            .collect::<Result<Vec<_>, Fault>>()?;
        if roster.len() > 20 {
            return Err(Fault::Unavailable);
        }
        pools.push(InventoryRow {
            pool,
            leader_id,
            roster,
        });
    }
    let next_cursor = if has_more {
        let last = pools.last().ok_or(Fault::Internal)?;
        Some(InventoryCursor {
            version: 1,
            source: source.clone(),
            filter: args.filter,
            limit: args.limit,
            after: last.pool.pool_id.clone(),
        })
    } else {
        None
    };
    let returned = pools.len();
    let completed = crate::completion::completed_count(&tx)?;
    if completed < 0 || completed > total {
        return Err(Fault::Internal);
    }
    let totals = InventoryTotals {
        total: total.to_string(),
        open: Some((total - completed).to_string()),
        completed: Some(completed.to_string()),
        unknown: "0".into(),
        closed: closed.to_string(),
    };
    tx.commit()?;
    Ok(Data::Inventory(Box::new(InventorySnapshot { source, totals, coverage: "Retained Pool rows only. Completed counts pools with a committed immutable completion record; every other retained pool is open, including accepted, closed, delivered or Run-succeeded pools without a record and all pools from before the completion ledger. Closed is independent of completion. Pages and totals share one Pool SQLite snapshot; no cross-service or clone/restore anti-rollback guarantee.".into(), pools, returned, has_more, next_cursor, observed_at_unix_ms: crate::observer::now()? })))
}
impl Store {
    pub(crate) fn egress_state(
        &self,
        id: &str,
    ) -> Result<Option<crate::managed_egress::State>, Fault> {
        crate::managed_egress::state(&self.db, id)
    }
    pub(crate) fn egress_scope_draining(&self, id: &str) -> Result<bool, Fault> {
        crate::managed_egress::scope_draining(&self.db, id)
    }
    pub(crate) fn egress_target(
        &self,
        id: &str,
        prefix: &str,
    ) -> Result<crate::managed_egress::Target, Fault> {
        crate::managed_egress::target(&self.db, id, prefix)
    }
    pub(crate) fn egress_attention(&mut self, id: &str, reason: &str) -> Result<(), Fault> {
        crate::managed_egress::attention(&mut self.db, id, reason)
    }
    pub(crate) fn egress_not_delivered(&mut self, id: &str, reason: &str) -> Result<(), Fault> {
        crate::managed_egress::mark_not_delivered(&mut self.db, id, reason)
    }
    pub(crate) fn egress_frozen(&self, id: &str) -> Result<crate::managed_egress::Frozen, Fault> {
        crate::managed_egress::frozen(&self.db, id)
    }
    pub(crate) fn egress_begin_publish(
        &mut self,
        id: &str,
    ) -> Result<(crate::managed_egress::Frozen, String), Fault> {
        crate::managed_egress::begin_publish(&mut self.db, id)
    }
    pub(crate) fn egress_begin_abort(
        &mut self,
        id: &str,
    ) -> Result<(crate::managed_egress::Frozen, String), Fault> {
        crate::managed_egress::begin_abort(&mut self.db, id)
    }
    pub(crate) fn egress_liveness_due(&self, id: &str, now: i64) -> Result<bool, Fault> {
        crate::managed_egress::liveness_due(&self.db, id, now)
    }
    pub(crate) fn egress_liveness_failed(&mut self, id: &str, now: i64) -> Result<i64, Fault> {
        crate::managed_egress::liveness_failed(&mut self.db, id, now)
    }
    pub(crate) fn egress_begin_liveness_abort(&mut self, id: &str) -> Result<(), Fault> {
        crate::managed_egress::begin_liveness_abort(&mut self.db, id)
    }
    pub(crate) fn egress_liveness_aborting(&self, id: &str) -> Result<bool, Fault> {
        crate::managed_egress::liveness_aborting(&self.db, id)
    }
    pub(crate) fn egress_republish(&mut self, id: &str) -> Result<Option<String>, Fault> {
        crate::managed_egress::republish(&mut self.db, id)
    }
    pub(crate) fn egress_not_sent(
        &mut self,
        id: &str,
        dispatch: &str,
        reason: &str,
    ) -> Result<(), Fault> {
        crate::managed_egress::record_not_sent(&mut self.db, id, dispatch, reason)
    }
    pub(crate) fn egress_result(
        &mut self,
        id: &str,
        dispatch: Option<&str>,
        result: &bridge_sdk::bridge_protocol::managed_owner::ManagedOwnerResultV1,
        aborting: bool,
    ) -> Result<crate::managed_egress::State, Fault> {
        crate::managed_egress::record_result(&mut self.db, id, dispatch, result, aborting)
    }
    pub(crate) fn egress_probe(
        &mut self,
        target: &crate::managed_egress::Target,
        pin: &crate::managed_state::RunPin,
    ) -> Result<(String, crate::managed_state::RunPin, bool), Fault> {
        crate::managed_egress::prepare_probe(&mut self.db, target, pin)
    }
    pub(crate) fn egress_probe_inflight(
        &mut self,
        id: &str,
        request: &str,
        uncertain: bool,
    ) -> Result<(), Fault> {
        crate::managed_egress::probe_inflight(&mut self.db, id, request, uncertain)
    }
    pub(crate) fn egress_reset_probe(&mut self, id: &str, request: &str) -> Result<(), Fault> {
        crate::managed_egress::reset_probe(&mut self.db, id, request)
    }
    pub(crate) fn egress_stage(
        &mut self,
        effect: &str,
        pin: &crate::managed_state::RunPin,
        bound: &crate::managed_state::AttemptRef,
        request: &str,
        transport: &str,
    ) -> Result<crate::managed_run::EgressQuery, Fault> {
        let matches: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM managed_delivery_outbox WHERE effect_id=?1 AND state='pending' AND probe_request_id=?2)",
            params![effect, request],
            |row| row.get(0),
        )?;
        if !matches {
            return Err(Fault::Stale);
        }
        crate::managed_run::EgressQuery::stage_recovery(
            &mut self.db,
            pin,
            bound,
            request,
            transport,
        )
    }
    pub(crate) fn egress_freeze(
        &mut self,
        target: &crate::managed_egress::Target,
        authority: &crate::managed_run::CurrentAuthority,
        pin: &crate::managed_state::RunPin,
        bridge: &crate::managed_bridge::BridgePin,
        audience: &str,
    ) -> Result<crate::managed_egress::Frozen, Fault> {
        let request = authority.request_id().ok_or(Fault::Unauthorized)?;
        crate::managed_state::record_current_receipt(&mut self.db, request, authority)?;
        let receipt = authority.receipt();
        let mut successor = target.binding.clone();
        successor.attempt = receipt.attempt.clone();
        successor.actor = receipt.actor.clone();
        let generation = if target.seed.final_notice {
            crate::managed_state::rebind_final_authenticated(
                &mut self.db,
                authority,
                &target.binding,
                &successor,
                &receipt.incarnation,
                &target.seed.effect_id,
            )?
        } else {
            crate::managed_state::rebind_authenticated(
                &mut self.db,
                authority,
                &target.binding,
                &successor,
                &receipt.incarnation,
                "egress",
            )?
        };
        crate::managed_egress::freeze(
            &mut self.db,
            target,
            authority,
            pin,
            bridge,
            audience,
            generation,
        )
    }
    pub(crate) fn egress_next_scope(&mut self) -> Result<Option<(String, String)>, Fault> {
        let rows = crate::managed_egress::pending_scopes(&self.db, self.managed_scope_cursor)?;
        self.managed_scope_cursor = rows.last().map_or(0, |row| row.0);
        Ok(rows.into_iter().next().map(|row| (row.1, row.2)))
    }
    pub(crate) fn egress_prepare_scope(
        &mut self,
        scope: &str,
        pin: &crate::managed_bridge::BridgePin,
        audience: &str,
    ) -> Result<crate::managed_egress::ScopePlan, Fault> {
        crate::managed_egress::prepare_scope(&mut self.db, scope, pin, audience)
    }
    pub(crate) fn egress_scope_retired(
        &mut self,
        plan: &crate::managed_egress::ScopePlan,
        result: &bridge_sdk::bridge_protocol::RetireResult,
    ) -> Result<(), Fault> {
        crate::managed_egress::record_scope_retired(&mut self.db, plan, result)
    }
    pub(crate) fn egress_scope_compacted(
        &mut self,
        plan: &crate::managed_egress::ScopePlan,
        result: &bridge_sdk::bridge_protocol::managed_owner::CompactManagedOwnerScopeResultV1,
    ) -> Result<(), Fault> {
        crate::managed_egress::record_scope_compaction(&mut self.db, plan, result)
    }
    pub(crate) fn managed_pin_routes(
        &mut self,
        bridge: &crate::managed_bridge::BridgePin,
        run: &crate::managed_state::RunEndpointPin,
        pool_route: &crate::managed_state::Route,
    ) -> Result<(), Fault> {
        crate::managed_state::persist_bridge_route(&mut self.db, bridge)?;
        crate::managed_state::persist_run_route(&mut self.db, run)?;
        crate::managed_state::persist_pool_route(&mut self.db, run, pool_route)
    }
    /// Check or atomically install an operator-verified pair of existing route pins.
    pub(crate) fn managed_repin_routes(
        &mut self,
        bridge: &crate::managed_bridge::BridgePin,
        run: &crate::managed_state::RunEndpointPin,
        pool_route: &crate::managed_state::Route,
        apply: bool,
    ) -> Result<(i64, i64), Fault> {
        crate::managed_state::repin_routes(&mut self.db, bridge, run, pool_route, apply)
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "The bootstrap identities are independent wire fields"
    )]
    pub(crate) fn managed_begin_bootstrap(
        &mut self,
        bootstrap_id: &str,
        invocation_key: &str,
        issuer_epoch: &str,
        command: &Command,
        proof: &bridge_sdk::bridge_protocol::CallEvidence,
        pin: &crate::managed_bridge::BridgePin,
    ) -> Result<(String, crate::managed_state::BootstrapDispatch), Fault> {
        let route = encode(&pin.route)?;
        let namespace: Option<String> = self.db.query_row(
            "SELECT id FROM managed_namespaces WHERE bridge_route=?1 AND producer=?2 AND issuer_epoch=?3",
            params![route, pin.producer, issuer_epoch],
            |row| row.get(0),
        ).optional()?;
        let namespace = namespace.unwrap_or_else(id);
        crate::managed_state::reserve_bootstrap(
            &mut self.db,
            &crate::managed_state::BootstrapRequest {
                namespace_id: &namespace,
                bootstrap_id,
                route: &pin.route,
                bridge_pin: pin,
                producer: &pin.producer,
                issuer_epoch,
                invocation_key,
                command,
                native_proof: proof,
            },
        )?;
        let dispatch = crate::managed_state::mark_bootstrap_submitted(&mut self.db, bootstrap_id)?;
        Ok((namespace, dispatch))
    }
    pub(crate) fn managed_stale_bootstrap(
        &mut self,
        dispatch: crate::managed_state::BootstrapDispatch,
    ) -> Result<(), Fault> {
        crate::managed_state::mark_bootstrap_stale_epoch(
            &mut self.db,
            dispatch,
            crate::managed_bridge::BridgeFailure::StaleEpoch,
        )
    }
    pub(crate) fn managed_record_bootstrap_ref(
        &mut self,
        dispatch: crate::managed_state::BootstrapDispatch,
        prepared: &crate::managed_bridge::Prepared,
        pin: &crate::managed_bridge::BridgePin,
    ) -> Result<(), Fault> {
        crate::managed_state::record_bootstrap_ref(&mut self.db, dispatch, prepared, pin)
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "Exact staged context and registration identities"
    )]
    pub(crate) fn managed_prepare_context(
        &mut self,
        context_id: &str,
        namespace_id: &str,
        bootstrap_id: &str,
        command: &Command,
        context: &crate::managed_state::SecurityContext,
        authority: &crate::managed_run::CurrentAuthority,
        registration_id: &str,
        pin: &crate::managed_bridge::BridgePin,
    ) -> Result<String, Fault> {
        let receipt = authority.receipt();
        let digest = crate::managed_state::prepare_context(
            &mut self.db,
            authority,
            context_id,
            namespace_id,
            command,
            context,
            &[(&receipt.receipt_id, receipt.incarnation.clone())],
        )?;
        crate::managed_state::mark_registration_submitted(
            &mut self.db,
            bootstrap_id,
            context_id,
            registration_id,
            &digest,
            pin,
        )?;
        Ok(digest)
    }
    pub(crate) fn managed_mark_consume(
        &mut self,
        context_id: &str,
        intent_id: &str,
        digest: &str,
        pin: &crate::managed_bridge::BridgePin,
    ) -> Result<(), Fault> {
        crate::managed_state::mark_bootstrap_consume_submitted(
            &mut self.db,
            context_id,
            intent_id,
            digest,
            pin,
        )
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "Exact authenticated consume association"
    )]
    pub(crate) fn managed_record_consumption(
        &mut self,
        context_id: &str,
        key: &crate::managed_bridge::ConsumeKey<'_>,
        consumed: &crate::managed_bridge::Consumed,
        server: &str,
        command: &Command,
        epoch: &str,
        pin: &crate::managed_bridge::BridgePin,
    ) -> Result<(), Fault> {
        crate::managed_state::record_bootstrap_consumption(
            &mut self.db,
            context_id,
            key,
            consumed,
            server,
            command,
            epoch,
            pin,
        )
    }
    pub(crate) fn managed_stage_ingress(
        &mut self,
        bootstrap_id: &str,
        pin: &crate::managed_state::RunPin,
        input: crate::managed_run::IngressInput,
    ) -> Result<crate::managed_run::IngressQuery, Fault> {
        let linked: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM managed_bootstrap b JOIN managed_namespaces n ON n.id=b.namespace_id WHERE b.id=?1 AND b.invocation_key=?2 AND b.state='submitted' AND n.bridge_route=?3 AND n.producer=?4)",
            params![bootstrap_id, input.invocation_key, encode(&input.bridge_route)?, input.producer],
            |row| row.get(0),
        )?;
        if !linked {
            return Err(Fault::Conflict);
        }
        crate::managed_run::IngressQuery::stage(&mut self.db, pin, input)
    }
    pub(crate) fn managed_record_current(
        &mut self,
        request_id: &str,
        authority: &crate::managed_run::CurrentAuthority,
    ) -> Result<(), Fault> {
        crate::managed_state::record_current_receipt(&mut self.db, request_id, authority)
    }
    /// Resolve the authenticated Run lineage to exactly one current member.
    #[allow(dead_code, reason = "Managed frontend wiring is in progress")]
    pub(crate) fn managed_select_ingress_binding(
        &mut self,
        authority: &crate::managed_run::CurrentAuthority,
        bridge_route: &crate::managed_state::Route,
        producer: &str,
        command: &Command,
    ) -> Result<crate::managed_state::ManagedBinding, Fault> {
        crate::managed_state::select_ingress_binding(
            &mut self.db,
            authority,
            bridge_route,
            producer,
            command,
        )
    }
    /// Install only a staged, pinned Run-authorized initial binding.
    #[allow(
        dead_code,
        reason = "Managed stdio ingress awaits the original-observation interface"
    )]
    pub(crate) fn managed_bind_initial(
        &mut self,
        authority: &crate::managed_run::CurrentAuthority,
        binding: &crate::managed_state::ManagedBinding,
        incarnation: &crate::managed_state::Incarnation,
    ) -> Result<(), Fault> {
        crate::managed_state::bind_initial_authenticated(
            &mut self.db,
            authority,
            binding,
            incarnation,
        )
    }
    /// Install a same-lineage successor under its original generation and Run pin.
    #[allow(
        dead_code,
        reason = "Managed stdio ingress awaits the original-observation interface"
    )]
    pub(crate) fn managed_rebind(
        &mut self,
        authority: &crate::managed_run::CurrentAuthority,
        old: &crate::managed_state::ManagedBinding,
        new: &crate::managed_state::ManagedBinding,
        incarnation: &crate::managed_state::Incarnation,
        purpose: &str,
    ) -> Result<u64, Fault> {
        crate::managed_state::rebind_authenticated(
            &mut self.db,
            authority,
            old,
            new,
            incarnation,
            purpose,
        )
    }
    /// Serve an immediate managed read only for its exact staged bootstrap.
    pub(crate) fn managed_read(
        &mut self,
        bootstrap_id: &str,
        context_id: &str,
        command: &Command,
        digest: &str,
        authorities: &[crate::managed_run::CurrentAuthority],
        consumed: &crate::managed_bridge::Consumed,
    ) -> Result<Reply, Fault> {
        let linked: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM managed_contexts c JOIN managed_bootstrap b ON b.invocation_key=c.invocation_key AND b.namespace_id=c.namespace_id WHERE c.id=?1 AND b.id=?2)",
            params![context_id, bootstrap_id],
            |row| row.get(0),
        )?;
        if !linked {
            return Err(Fault::Conflict);
        }
        crate::managed_state::execute_read(
            &mut self.db,
            context_id,
            command,
            digest,
            authorities,
            consumed,
        )
    }
    /// Reserve an authenticated invocation and recover its exact Run admission inputs.
    #[allow(
        clippy::too_many_arguments,
        reason = "The frozen identities are distinct protocol fields"
    )]
    pub(crate) fn managed_reserve(
        &mut self,
        bootstrap_id: &str,
        context_id: &str,
        intent_id: &str,
        member_id: &str,
        command: &Command,
        digest: &str,
        authority: crate::managed_run::CurrentAuthority,
        consumed: &crate::managed_bridge::Consumed,
        pool_route: &crate::managed_state::Route,
    ) -> Result<
        (
            crate::managed_state::IntentReservation,
            Option<crate::managed_state::AdmissionPlan>,
        ),
        Fault,
    > {
        let stored: String = self.db.query_row(
            "SELECT c.intent_id FROM managed_contexts c JOIN managed_bootstrap b ON b.invocation_key=c.invocation_key AND b.namespace_id=c.namespace_id WHERE c.id=?1 AND b.id=?2",
            params![context_id, bootstrap_id],
            |row| row.get(0),
        )?;
        if stored != intent_id {
            return Err(Fault::Conflict);
        }
        let result = crate::managed_state::reserve_intent(
            &mut self.db,
            context_id,
            member_id,
            command,
            digest,
            authority,
            consumed,
            pool_route,
        )?;
        let plan = if result == crate::managed_state::IntentReservation::Created {
            Some(crate::managed_state::admission_plan(
                &self.db, intent_id, digest,
            )?)
        } else {
            None
        };
        Ok((result, plan))
    }
    pub(crate) fn managed_mark_admitted(
        &mut self,
        id: &str,
        digest: &str,
        admission: &crate::managed_run::Admission,
    ) -> Result<(), Fault> {
        crate::managed_state::mark_admitted(&mut self.db, id, digest, admission)
    }
    pub(crate) fn managed_commit_domain(
        &mut self,
        id: &str,
        digest: &str,
    ) -> Result<String, Fault> {
        crate::managed_state::commit_domain(&mut self.db, id, digest)
    }
    pub(crate) fn managed_snapshot_consensus(
        &self,
        id: &str,
        digest: &str,
    ) -> Result<crate::managed_state::PendingConsensus, Fault> {
        crate::managed_state::snapshot_consensus(&self.db, id, digest)
    }
    pub(crate) fn managed_refresh_consensus(
        &self,
        pending: crate::managed_state::PendingConsensus,
    ) -> Result<crate::managed_state::PendingConsensus, Fault> {
        pending.refresh_after_rebind(&self.db)
    }
    pub(crate) fn managed_commit_vote(
        &mut self,
        id: &str,
        digest: &str,
        fence: crate::managed_state::ConsensusFence,
    ) -> Result<String, Fault> {
        crate::managed_state::commit_domain_vote(&mut self.db, id, digest, fence)
    }
    pub(crate) fn managed_require_run_pin(
        &mut self,
        pin: &crate::managed_state::RunEndpointPin,
    ) -> Result<(), Fault> {
        crate::managed_state::require_run_route(&self.db, pin)
    }
    pub(crate) fn managed_stage_voter(
        &mut self,
        pin: &crate::managed_state::RunPin,
        voter: &crate::managed_state::VerifiedBallot,
        request_id: &str,
        transport_id: &str,
        owner_intent: &str,
    ) -> Result<crate::managed_run::VoterQuery, Fault> {
        let query = crate::managed_run::VoterQuery::stage(
            &mut self.db,
            pin,
            voter,
            request_id,
            transport_id,
        )?;
        self.managed_own_current(request_id, owner_intent)?;
        Ok(query)
    }
    pub(crate) fn managed_stage_egress(
        &mut self,
        pin: &crate::managed_state::RunPin,
        bound: &crate::managed_state::AttemptRef,
        request_id: &str,
        transport_id: &str,
        owner_intent: &str,
    ) -> Result<crate::managed_run::EgressQuery, Fault> {
        let query = crate::managed_run::EgressQuery::stage(
            &mut self.db,
            pin,
            bound,
            request_id,
            transport_id,
        )?;
        self.managed_own_current(request_id, owner_intent)?;
        Ok(query)
    }
    fn managed_own_current(&mut self, request_id: &str, owner_intent: &str) -> Result<(), Fault> {
        let changed = self.db.execute("UPDATE managed_current_requests SET owner_intent=?2 WHERE id=?1 AND namespace_id IS NULL AND state='prepared' AND (owner_intent IS NULL OR owner_intent=?2) AND EXISTS(SELECT 1 FROM managed_intents WHERE id=?2 AND state='admitted')",params![request_id,owner_intent])?;
        if changed != 1 {
            self.db.execute("UPDATE managed_current_requests SET state='aborted' WHERE id=?1 AND namespace_id IS NULL AND owner_intent IS NULL AND state='prepared'",[request_id])?;
            return Err(Fault::Stale);
        }
        Ok(())
    }
    pub(crate) fn managed_terminal_abort(&mut self, id: &str, digest: &str) -> Result<(), Fault> {
        crate::managed_state::terminal_abort(&mut self.db, id, digest, "managed_aborted")
    }
    /// Lists a bounded batch of unresolved managed intents for exact-key recovery.
    pub(crate) fn managed_pending(&mut self) -> Result<Vec<(String, String)>, Fault> {
        let rows =
            crate::managed_state::pending_recovery(&self.db, 1, self.managed_recovery_cursor)?;
        self.managed_recovery_cursor = if rows.is_empty() {
            0
        } else {
            rows.last().map_or(0, |row| row.0)
        };
        Ok(rows
            .into_iter()
            .map(|(_, id, digest)| (id, digest))
            .collect())
    }
    /// Stages one managed intent recovery action without external I/O.
    pub(crate) fn managed_stage_recovery(
        &mut self,
        id: &str,
        digest: &str,
    ) -> Result<crate::managed_state::RecoveryAction, Fault> {
        crate::managed_state::stage_recovery(&mut self.db, id, digest)
    }
    /// Lists a bounded batch of unresolved bootstrap reservations.
    pub(crate) fn managed_pending_bootstraps(&mut self) -> Result<Vec<String>, Fault> {
        let rows =
            crate::managed_state::pending_bootstraps(&self.db, 1, self.managed_bootstrap_cursor)?;
        self.managed_bootstrap_cursor = if rows.is_empty() {
            0
        } else {
            rows.last().map_or(0, |row| row.0)
        };
        Ok(rows.into_iter().map(|(_, id)| id).collect())
    }
    /// Stages one bootstrap recovery action without external I/O.
    pub(crate) fn managed_stage_bootstrap(
        &mut self,
        id: &str,
    ) -> Result<crate::managed_state::BootstrapRecoveryAction, Fault> {
        crate::managed_state::stage_bootstrap_recovery(&mut self.db, id)
    }
    /// Records a verified Bridge abort for one exact original intent.
    pub(crate) fn managed_record_bridge_abort(
        &mut self,
        id: &str,
        digest: &str,
        key: &crate::managed_state::RecoveryBridgeKey,
        pin: &crate::managed_bridge::BridgePin,
        result: &crate::managed_bridge::Abort,
    ) -> Result<bool, Fault> {
        crate::managed_state::record_bridge_abort(
            &mut self.db,
            id,
            digest,
            &key.borrowed(),
            result,
            pin,
        )
    }
    /// Records a verified Bridge abort for a bootstrap with no Pool intent.
    pub(crate) fn managed_record_bootstrap_abort(
        &mut self,
        context: &str,
        key: &crate::managed_state::RecoveryBridgeKey,
        pin: &crate::managed_bridge::BridgePin,
        result: &crate::managed_bridge::Abort,
    ) -> Result<(), Fault> {
        crate::managed_state::record_bootstrap_abort(
            &mut self.db,
            context,
            &key.borrowed(),
            result,
            pin,
        )
    }
    /// Records a correlated Run abort fence for one exact original intent.
    pub(crate) fn managed_record_run_abort(
        &mut self,
        id: &str,
        digest: &str,
        result: &crate::managed_run::Lookup,
    ) -> Result<bool, Fault> {
        crate::managed_state::record_run_abort(&mut self.db, id, digest, result)
    }
    /// Records a correlated Run settlement for one committed intent.
    pub(crate) fn managed_record_run_settlement(
        &mut self,
        id: &str,
        digest: &str,
        result: &crate::managed_run::Lookup,
    ) -> Result<(), Fault> {
        crate::managed_state::record_run_settlement(&mut self.db, id, digest, result)
    }
    /// Returns this durable Pool source identity to a separately authenticated private reader.
    pub(crate) fn managed_store_id(&self) -> Result<String, Fault> {
        self.db
            .query_row(
                "SELECT store_id FROM inventory_source WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }
    /// Reads a single local outcome without mutating the store.
    pub(crate) fn managed_outcome(
        &self,
        intent: &str,
        digest: &str,
        route: &crate::managed_state::Route,
    ) -> Result<crate::managed_state::ManagedOutcome, Fault> {
        crate::managed_state::authorize_outcome_route(&self.db, intent, route)?;
        crate::managed_state::outcome(&self.db, intent, digest)
    }
    /// Fences and inspects one explicitly authorized Bridge issuer namespace.
    pub(crate) fn managed_seal(
        &mut self,
        route: &crate::managed_state::Route,
        producer: &str,
        issuer: &str,
        request: &str,
        retirement: &str,
    ) -> Result<crate::managed_state::SealStatus, Fault> {
        crate::managed_state::seal_namespace(
            &mut self.db,
            route,
            producer,
            issuer,
            request,
            retirement,
        )
    }
    /// Freeze one superseded namespace request or recover its due exact key.
    pub(crate) fn managed_stage_namespace_retirement(
        &mut self,
        run: &crate::managed_state::RunEndpointPin,
        pool_route: &crate::managed_state::Route,
        bridge_route: &crate::managed_state::Route,
        producer: &str,
        current_issuer: Option<&str>,
        now: i64,
    ) -> Result<Option<crate::managed_state::NamespaceRetirement>, Fault> {
        crate::managed_state::stage_namespace_retirement(
            &mut self.db,
            run,
            pool_route,
            bridge_route,
            producer,
            current_issuer,
            now,
        )
    }
    /// Avoid contacting providers when no namespace can need retirement.
    /// Whether a failed E11 issuer discovery's backoff has elapsed.
    pub(crate) fn managed_discovery_due(&self, now: i64) -> Result<bool, Fault> {
        Ok(self.db.query_row(
            "SELECT NOT EXISTS(SELECT 1 FROM managed_route_attention WHERE subject='namespace_discovery' AND next_attempt>?1)",
            [now],
            |row| row.get(0),
        )?)
    }
    /// Record a durable, owner-visible discovery failure with capped exponential backoff.
    pub(crate) fn managed_discovery_failed(&mut self, code: &str, now: i64) -> Result<(), Fault> {
        let attempts: i64 = self
            .db
            .query_row(
                "SELECT attempts FROM managed_route_attention WHERE subject='namespace_discovery'",
                [],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0_i64)
            .saturating_add(1);
        let shift = u32::try_from((attempts - 1).clamp(0, 6)).map_err(|_| Fault::Internal)?;
        let delay = 5_i64.saturating_mul(1_i64 << shift).min(300);
        self.db.execute(
            "INSERT INTO managed_route_attention(subject,attention,attempts,next_attempt) VALUES('namespace_discovery',?1,?2,?3) ON CONFLICT(subject) DO UPDATE SET attention=excluded.attention,attempts=excluded.attempts,next_attempt=excluded.next_attempt",
            params![code, attempts, now.saturating_add(delay)],
        )?;
        Ok(())
    }
    /// A successful authenticated discovery clears the attention.
    pub(crate) fn managed_discovery_succeeded(&mut self) -> Result<(), Fault> {
        self.db.execute(
            "DELETE FROM managed_route_attention WHERE subject='namespace_discovery'",
            [],
        )?;
        Ok(())
    }
    pub(crate) fn managed_has_namespace_retirement_work(&self) -> Result<bool, Fault> {
        self.db.query_row("SELECT EXISTS(SELECT 1 FROM managed_namespaces WHERE state='open') OR EXISTS(SELECT 1 FROM managed_namespace_retirements WHERE state='requested')", [], |row| row.get(0)).map_err(Into::into)
    }
    /// Record a fully correlated terminal retirement after Run's authenticated response.
    pub(crate) fn managed_complete_namespace_retirement(
        &mut self,
        plan: &crate::managed_state::NamespaceRetirement,
    ) -> Result<(), Fault> {
        crate::managed_state::complete_namespace_retirement(&self.db, plan)
    }
    /// Keep a failed or uncertain exact-key attempt behind its durable retry time.
    pub(crate) fn managed_defer_namespace_retirement(
        &mut self,
        plan: &crate::managed_state::NamespaceRetirement,
        now: i64,
    ) -> Result<(), Fault> {
        crate::managed_state::defer_namespace_retirement(&mut self.db, plan, now)
    }
    /// P3-C ledger access for one bounded synchronous step; never held across I/O.
    pub(crate) fn completion_db(&mut self) -> &mut Connection {
        &mut self.db
    }
    /// Grants unit fixtures direct access to the isolated SQLite connection.
    #[cfg(test)]
    pub(crate) fn test_db(&mut self) -> &mut Connection {
        &mut self.db
    }
    /// Queries the resident connection only, after the transport verified the separate owner grant.
    /// This path has no write transaction, receipt replay, claims, provider I/O or outbox changes.
    /// Pagination is section-local and uses the existing reviewed typed projections.
    pub fn observe(
        &self,
        request: &crate::observer::Request,
    ) -> Result<crate::observer::Data, Fault> {
        use crate::observer::{Data, Detail, Envelope, Operation, Page, PoolPage, PoolRow};
        request.validate()?;
        match &request.operation {
            Operation::Identity(_) => {
                let mut data = Envelope::identity()?;
                if let Data::Identity(identity) = &mut data {
                    for code in [
                        "key_unavailable",
                        "route_changed",
                        "outcome_unknown",
                        "release_unknown",
                        "hold_unavailable",
                        "run_unavailable",
                        "internal_error",
                    ] {
                        let present: bool = self.db.query_row("SELECT EXISTS(SELECT 1 FROM completion_sagas WHERE stage!='released' AND attention=?1)", [code], |row| row.get(0))?;
                        if present {
                            identity
                                .capabilities
                                .push(format!("completion_attention_{code}"));
                        }
                    }
                    let discovery: Option<String> = self
                        .db
                        .query_row(
                            "SELECT attention FROM managed_route_attention WHERE subject='namespace_discovery'",
                            [],
                            |row| row.get(0),
                        )
                        .optional()?;
                    if let Some(code) = discovery.filter(|code| {
                        matches!(
                            code.as_str(),
                            "route_unavailable" | "route_changed" | "relaunch_required"
                        )
                    }) {
                        identity
                            .capabilities
                            .push(format!("namespace_retirement_attention_{code}"));
                    }
                }
                Ok(data)
            }
            Operation::ManagedCapacity(_) => Ok(Data::ManagedCapacity(Box::new(
                crate::managed_state::managed_capacity(&self.db)?,
            ))),
            Operation::InventorySnapshot(args) => {
                inventory_snapshot(&self.db, &self.read_epoch, args)
            }
            Operation::CompletionGet(args) => Ok(Data::Completion(Box::new(
                crate::completion::page(&self.db, args)?,
            ))),
            Operation::EnrollmentGet(args) => Ok(Data::Enrollment(Box::new(
                crate::managed_enrollment::view(&self.db, &args.pool_id, &args.enrollment_id)?,
            ))),
            Operation::List(args) => {
                let mut stmt = self
                    .db
                    .prepare("SELECT data,owner FROM pools WHERE id>?1 ORDER BY id LIMIT 11")?;
                let mut pools = stmt
                    .query_map([args.after.as_deref().unwrap_or("")], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?
                    .map(|row| {
                        let (data, leader_id) = row?;
                        let mut pool: Pool = decode(&data)?;
                        pool.proposal = None;
                        pool.acceptance = None;
                        project_purpose(&mut pool);
                        Ok(PoolRow { pool, leader_id })
                    })
                    .collect::<Result<Vec<_>, Fault>>()?;
                let more = pools.len() > 10;
                pools.truncate(10);
                let page = Page::new(
                    pools
                        .last()
                        .map(|row| row.pool.pool_id.clone())
                        .or_else(|| args.after.clone()),
                    more,
                    pools.len(),
                )?;
                Ok(Data::Pools(PoolPage { pools, page }))
            }
            Operation::Get(args) => {
                if args.direction.is_some() {
                    return observe_history(&self.db, args);
                }
                let (pool, leader_id) = pool(&self.db, &args.pool_id)?;
                if args
                    .expected_revision
                    .is_some_and(|revision| revision != pool.revision)
                {
                    return Err(Fault::Stale);
                }
                if args.section == "decisions" {
                    let mut stmt = self.db.prepare(
                        "SELECT rowid,data FROM proposals WHERE pool=?1 AND rowid>?2 ORDER BY rowid LIMIT 3",
                    )?;
                    let mut rows = stmt
                        .query_map(
                            params![
                                args.pool_id,
                                i64::try_from(args.after).map_err(|_| Fault::Invalid)?
                            ],
                            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                        )?
                        .map(|row| {
                            let (cursor, data) = row?;
                            let cursor = u64::try_from(cursor).map_err(|_| Fault::Internal)?;
                            let mut proposal: Proposal = decode(&data)?;
                            proposal.votes.clear();
                            proposal.snapshot = None;
                            Ok((cursor, proposal))
                        })
                        .collect::<Result<Vec<_>, Fault>>()?;
                    let more = rows.len() > 2;
                    rows.truncate(2);
                    let next = rows.last().map_or(args.after, |(cursor, _)| *cursor);
                    let decisions: Vec<_> =
                        rows.into_iter().map(|(_, proposal)| proposal).collect();
                    let page = Page::new(Some(next.to_string()), more, decisions.len())?;
                    return Ok(Data::Detail(Box::new(Detail {
                        section: args.section.clone(),
                        view: None,
                        leader_id,
                        bindings: None,
                        decisions,
                        history_watermark: None,
                        page,
                    })));
                }
                let get = args.projection()?;
                let mappings = args.include_bindings || get.section == Section::Binding;
                let reply = view(
                    &self.db,
                    pool,
                    bindings(&self.db, &args.pool_id)?,
                    &get,
                    mappings,
                )?;
                let (mut view, private) = match reply {
                    Reply::View(view) => (view, None),
                    Reply::OwnerView { view, bindings } => (view, Some(bindings)),
                    _ => return Err(Fault::Internal),
                };
                if !mappings && get.section == Section::Deliveries {
                    for delivery in &mut view.deliveries {
                        (delivery.attention, delivery.attention_subject) =
                            crate::managed_egress::owner_attention(
                                &self.db,
                                &delivery.operation_id,
                            )?;
                    }
                }
                let returned = match get.section {
                    Section::Overview | Section::Members | Section::Binding => view.members.len(),
                    Section::History => view.events.len(),
                    Section::Deliveries => view.deliveries.len(),
                    Section::Votes => view.pool.proposal.as_ref().map_or(0, |p| p.votes.len()),
                    Section::Criteria => view.pool.acceptance.as_ref().map_or(0, Vec::len),
                    Section::Content => usize::from(view.content.is_some()),
                    Section::Proposal => usize::from(view.pool.proposal.is_some()),
                };
                let page = Page::new(Some(view.next_after.to_string()), view.has_more, returned)?;
                Ok(Data::Detail(Box::new(Detail {
                    section: args.section.clone(),
                    view: Some(view),
                    leader_id,
                    bindings: private,
                    decisions: Vec::new(),
                    history_watermark: None,
                    page,
                })))
            }
        }
    }
    /// Opens one private database, takes a nonblocking writer lease and migrates to the current schema.
    /// The existing parent must be a real 0700 directory; future schemas and second writers refuse.
    pub fn open(path: &Path) -> Result<Self, Fault> {
        let parent = path.parent().ok_or(Fault::Invalid)?;
        let meta = std::fs::symlink_metadata(parent).map_err(|_| Fault::Unavailable)?;
        if !meta.is_dir() || meta.permissions().mode() & 0o777 != 0o700 {
            return Err(Fault::Forbidden);
        }
        for p in [path.to_path_buf(), path.with_extension("lock")] {
            if std::fs::symlink_metadata(&p)
                .is_ok_and(|m| !m.is_file() || m.permissions().mode() & 0o077 != 0)
            {
                return Err(Fault::Forbidden);
            }
        }
        let lease = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(path.with_extension("lock"))
            .map_err(|_| Fault::Unavailable)?;
        lease.try_lock_exclusive().map_err(|_| Fault::Conflict)?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| Fault::Unavailable)?;
        drop(file);
        let db = Connection::open(path)?;
        db.busy_timeout(Duration::from_secs(2))?;
        let version: i64 = db.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if !(0..=crate::completion::SCHEMA_VERSION).contains(&version) {
            return Err(Fault::Conflict);
        }
        db.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;",
        )?;
        if version < crate::completion::SCHEMA_VERSION {
            db.execute_batch("BEGIN IMMEDIATE;")?;
        }
        if version == 0 {
            db.execute_batch("
CREATE TABLE leaders(actor TEXT PRIMARY KEY,address TEXT NOT NULL UNIQUE);
CREATE TABLE pools(id TEXT PRIMARY KEY,owner TEXT NOT NULL REFERENCES leaders(actor),data TEXT NOT NULL);
CREATE TABLE proposals(id TEXT PRIMARY KEY,pool TEXT NOT NULL REFERENCES pools(id),state TEXT NOT NULL,data TEXT NOT NULL);
CREATE TABLE members(id TEXT PRIMARY KEY,pool TEXT NOT NULL REFERENCES pools(id),actor TEXT,address TEXT,current INTEGER NOT NULL,data TEXT NOT NULL);
CREATE TABLE member_slots(member TEXT PRIMARY KEY REFERENCES members(id),slot TEXT NOT NULL);
CREATE UNIQUE INDEX member_actor_current ON members(actor) WHERE current=1 AND actor IS NOT NULL;
CREATE UNIQUE INDEX member_address_current ON members(address) WHERE current=1 AND address IS NOT NULL;
CREATE INDEX member_pool ON members(pool,current);
CREATE TABLE requests(scope TEXT NOT NULL,key TEXT NOT NULL,digest TEXT NOT NULL,receipt TEXT NOT NULL,PRIMARY KEY(scope,key));
CREATE TABLE events(id INTEGER PRIMARY KEY AUTOINCREMENT,pool TEXT NOT NULL REFERENCES pools(id),data TEXT NOT NULL);
CREATE INDEX event_pool ON events(pool,id);
CREATE TABLE effects(sequence INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL UNIQUE,pool TEXT NOT NULL REFERENCES pools(id),member TEXT,state TEXT NOT NULL,data TEXT NOT NULL,failure_notice INTEGER NOT NULL DEFAULT 0);
CREATE INDEX effect_state ON effects(state,sequence);
CREATE TABLE publications(effect TEXT PRIMARY KEY REFERENCES effects(id),producer TEXT NOT NULL,params TEXT NOT NULL);
CREATE TABLE alerts(effect TEXT NOT NULL REFERENCES effects(id),kind TEXT NOT NULL,PRIMARY KEY(effect,kind));
PRAGMA user_version=5;")?;
        } else if version < 5 {
            // Older readers cannot safely interpret durable replacement effects.
            db.execute_batch("CREATE TABLE IF NOT EXISTS member_slots(member TEXT PRIMARY KEY REFERENCES members(id),slot TEXT NOT NULL); PRAGMA user_version=5;")?;
        }
        if version < 6 {
            migrate_inventory_source(&db)?;
            db.execute_batch("PRAGMA user_version=6;")?;
        }
        if version < 7 {
            migrate_managed_context(&db)?;
            db.execute_batch("PRAGMA user_version=7;")?;
        }
        if version < 8 {
            migrate_managed_intents(&db)?;
            db.execute_batch("PRAGMA user_version=8;")?;
        }
        if version < 9 {
            migrate_managed_review_fixes(&db)?;
            db.execute_batch("PRAGMA user_version=9;")?;
        }
        if version < 10 {
            migrate_managed_egress(&db)?;
            db.execute_batch("PRAGMA user_version=10;")?;
        }
        if version < 11 {
            migrate_managed_route_pins(&db)?;
            db.execute_batch("PRAGMA user_version=11;")?;
        }
        // Version 12 adds completion and fences changes to v11's durable tables.
        if version < 12 {
            crate::completion::migrate(&db)?;
            inventory_revision_triggers(
                &db,
                &["managed_route_pin_history", "managed_namespace_retirements"],
            )?;
            db.execute_batch("PRAGMA user_version=12;")?;
        }
        if version < 13 {
            migrate_review_v13(&db)?;
            db.execute_batch("PRAGMA user_version=13;")?;
        }
        if version < 14 {
            migrate_completed_admissions(&db)?;
            db.execute_batch("PRAGMA user_version=14;")?;
        }
        // Version 15 adds the P3 owner enrollment journal and per-job facts,
        // plus durable route attention for E11 issuer discovery.
        if version < 15 {
            crate::managed_enrollment::migrate(&db)?;
            db.execute_batch("CREATE TABLE managed_route_attention(subject TEXT PRIMARY KEY CHECK(subject='namespace_discovery'),attention TEXT NOT NULL,attempts INTEGER NOT NULL CHECK(attempts>0),next_attempt INTEGER NOT NULL CHECK(next_attempt>=0));")?;
            crate::managed_egress::migrate_liveness(&db)?;
            db.execute_batch("PRAGMA user_version=15;")?;
        }
        if version < crate::completion::SCHEMA_VERSION {
            db.execute_batch("COMMIT;")?;
        }
        // Transaction-local managed mutation provenance, never retained after restart.
        db.execute_batch("CREATE TEMP TABLE managed_delivery_origin(singleton INTEGER PRIMARY KEY CHECK(singleton=1),namespace_id TEXT NOT NULL);")?;
        // Only a pending, event-bound egress probe can resume its original Run key.
        db.execute("UPDATE managed_current_requests SET state='aborted' WHERE namespace_id IS NULL AND state IN ('prepared','received') AND NOT EXISTS(SELECT 1 FROM managed_delivery_outbox o WHERE o.state='pending' AND o.probe_request_id=managed_current_requests.id)", [])?;
        // A crash may have happened after a provider accepted the work. Never turn these back into queued.
        db.execute(
            "UPDATE effects SET state='unknown' WHERE state='inflight'",
            [],
        )?;
        db.execute("UPDATE managed_delivery_outbox SET state='unknown',attention='outcome_unknown' WHERE state='publishing'",[])?;
        Ok(Self {
            db,
            _lease: lease,
            unknown_cursor: 0,
            managed_recovery_cursor: 0,
            managed_bootstrap_cursor: 0,
            managed_scope_cursor: 0,
            read_epoch: id(),
            enrollment: None,
        })
    }
    /// Selects P3 managed enrollment for later owner start, batch and replacement commands.
    /// The route is frozen into each enrollment; absence keeps new enrollment closed.
    pub(crate) fn configure_enrollment(
        &mut self,
        route: Option<crate::managed_enrollment::EnrollmentRoute>,
    ) {
        self.enrollment = route;
    }
    /// Authenticates current membership before replay lookup, then executes a non-join command.
    /// Joins must use execute_join with the provider-prevalidated binding; no unfenced join path exists.
    /// Errors roll back all local changes. External I/O belongs exclusively to the outbox worker.
    pub fn execute(&mut self, actor: &Actor, command: &Command) -> Result<Reply, Fault> {
        command.validate()?;
        if matches!(command, Command::Join(_)) {
            return Err(Fault::Invalid);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let reply = execute(&tx, actor, command, self.enrollment.as_ref())?;
        tx.commit()?;
        Ok(reply)
    }
    /// Executes a join only against the exact incarnation prevalidated outside provider I/O.
    /// The binding fence and authorization/replay run in one write transaction; any changed
    /// assignment, native tuple or removal refuses even if the caller supplied a newer revision.
    pub fn execute_join(
        &mut self,
        actor: &Actor,
        command: &Command,
        expected: &Binding,
    ) -> Result<Reply, Fault> {
        command.validate()?;
        if !matches!(command,Command::Join(change) if change.pool_id==expected.pool_id) {
            return Err(Fault::Invalid);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (current, active) = binding_any(&tx, &expected.member.member_id)?;
        if !active || current != *expected {
            return Err(Fault::Stale);
        }
        let reply = execute(&tx, actor, command, None)?;
        tx.commit()?;
        Ok(reply)
    }
    /// Reads the exact current incarnation eligible for this authenticated caller's join precheck.
    /// Absence refuses; execute_join rechecks equality transactionally after provider I/O.
    pub fn join_binding(&self, actor: &Actor, pool_id: &str) -> Result<Binding, Fault> {
        bindings(&self.db, pool_id)?
            .into_iter()
            .find(|b| {
                b.actor.as_deref() == Some(&actor.key)
                    || (b.actor.is_none() && b.address.as_deref() == Some(&actor.address))
            })
            .ok_or(Fault::Forbidden)
    }
    /// Claims the oldest queued intent, persisting inflight before the worker can contact a provider.
    pub fn next_effect(&mut self) -> Result<Option<Effect>, Fault> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row: Option<String> = tx
            .query_row(
                "SELECT data FROM effects WHERE state='queued' ORDER BY sequence LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let Some(row) = row else { return Ok(None) };
        let mut effect: Effect = decode(&row)?;
        effect.state = "inflight".into();
        tx.execute(
            "UPDATE effects SET state='inflight',data=?2 WHERE id=?1 AND state='queued'",
            params![effect.effect_id, encode(&effect)?],
        )?;
        tx.commit()?;
        Ok(Some(effect))
    }
    /// A proven managed binding can route a pending effect without a legacy address lookup.
    pub(crate) fn next_bound_managed_egress(&mut self) -> Result<Option<Effect>, Fault> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let row:Option<(String,String)>=tx.query_row("SELECT e.id,e.data FROM effects e JOIN managed_delivery_seeds s ON s.effect_id=e.id JOIN managed_delivery_outbox o ON o.effect_id=e.id JOIN managed_bindings b ON b.member=s.member_id AND b.pool=s.pool_id WHERE e.state='awaiting_binding' AND o.state='pending' ORDER BY e.sequence LIMIT 1",[],|row|Ok((row.get(0)?,row.get(1)?))).optional()?;
        let Some((id, raw)) = row else {
            return Ok(None);
        };
        let mut effect: Effect = decode(&raw)?;
        effect.state = "inflight".into();
        if tx.execute(
            "UPDATE effects SET state='inflight',data=?2 WHERE id=?1 AND state='awaiting_binding'",
            params![id, encode(&effect)?],
        )? != 1
        {
            return Err(Fault::Stale);
        }
        tx.commit()?;
        Ok(Some(effect))
    }
    /// Returns at most 32 uncertain effects for status reconciliation, never automatic new IDs.
    pub fn pending_unknown(&mut self) -> Result<Vec<Effect>, Fault> {
        let mut stmt=self.db.prepare("SELECT sequence,data,state FROM effects WHERE state IN ('unknown','custody') AND sequence>?1 ORDER BY sequence LIMIT 32")?;
        let rows = stmt.query_map([self.unknown_cursor], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (sequence, data, state) = row?;
            let mut e: Effect = decode(&data)?;
            e.state = state;
            out.push(e);
            self.unknown_cursor = sequence;
        }
        if out.len() < 32 {
            self.unknown_cursor = 0;
        }
        Ok(out)
    }
    /// Returns the retained exact membership of an effect, including removal and immediate Run receipt.
    /// This private view lets reconciliation inspect admitted work without starting a removed agent.
    pub fn effect_binding(&self, effect_id: &str) -> Result<Option<(Binding, bool)>, Fault> {
        let e = effect(&self.db, effect_id)?;
        e.member_id
            .as_deref()
            .map(|mid| binding_any(&self.db, mid))
            .transpose()
    }
    /// Reads one exact owner-selected binding and its origin under a single read snapshot.
    pub(crate) fn run_proof_binding(
        &self,
        pool_id: &str,
        member_id: &str,
        expected_revision: Option<u64>,
    ) -> Result<RunProofBinding, Fault> {
        identifier(pool_id)?;
        identifier(member_id)?;
        let tx = self.db.unchecked_transaction()?;
        let (pool, _) = pool(&tx, pool_id)?;
        if expected_revision.is_some_and(|expected| expected != pool.revision) {
            return Err(Fault::Stale);
        }
        let (binding, current) = binding_any(&tx, member_id)?;
        if binding.pool_id != pool_id {
            return Err(Fault::Forbidden);
        }
        let route = match pin_origin_route(&tx, pool_id, member_id, binding.run_store_id.as_deref())
        {
            Ok(route) => route,
            Err(Fault::Conflict | Fault::Invalid | Fault::Unavailable) => None,
            Err(error) => return Err(error),
        };
        tx.commit()?;
        Ok(RunProofBinding {
            revision: pool.revision,
            binding,
            current,
            route,
        })
    }
    /// Reconstructs one pre-v3 scalar intent for compatibility tests only.
    #[cfg(test)]
    pub(crate) fn fixture_legacy_start(&mut self, effect_id: &str) -> Result<Effect, Fault> {
        let mut effect = effect(&self.db, effect_id)?;
        if !effect.is_single_batch()? {
            return Err(Fault::Invalid);
        }
        let Work::StartBatch {
            jobs, request_key, ..
        } = &effect.work
        else {
            return Err(Fault::Invalid);
        };
        effect.work = Work::Start {
            spec: jobs[0].spec.clone(),
            request_key: request_key.clone(),
            route_fence: true,
            route: None,
        };
        self.db.execute(
            "UPDATE effects SET data=?2 WHERE id=?1",
            params![effect_id, encode(&effect)?],
        )?;
        Ok(effect)
    }
    /// Freezes a Run route before I/O, rechecking single-member admission and rejecting drift.
    pub fn freeze_run_route(
        &mut self,
        effect_id: &str,
        expected: &RunRoute,
        reconcile: bool,
    ) -> Result<bool, Fault> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut effect = effect(&tx, effect_id)?;
        if (reconcile && effect.state != "unknown") || (!reconcile && effect.state != "inflight") {
            return Err(Fault::Unavailable);
        }
        if matches!(effect.work, Work::Start { .. }) || effect.is_single_batch()? {
            let member_id = effect.member_id.as_deref().ok_or(Fault::Internal)?;
            let (binding, current) = binding_any(&tx, member_id)?;
            if !current || binding.pool_id != effect.pool_id {
                return Err(Fault::Unavailable);
            }
        }
        let legacy_first_claim = !reconcile && effect.state == "inflight";
        let custody = effect.state == "custody";
        let (route_fence, route) = match &mut effect.work {
            Work::Start {
                route_fence, route, ..
            }
            | Work::StartBatch {
                route_fence, route, ..
            } => (*route_fence, route),
            _ => return Err(Fault::Invalid),
        };
        match route {
            Some(previous)
                if previous.socket != expected.socket
                    || previous.expected_uid != expected.expected_uid
                    || previous.peer_uid != expected.peer_uid =>
            {
                return Err(Fault::Unavailable);
            }
            Some(_) => return Ok(false),
            None if custody || (!route_fence && !legacy_first_claim) => {
                return Err(Fault::Unavailable);
            }
            None => *route = Some(expected.clone()),
        }
        tx.execute(
            "UPDATE effects SET data=?2 WHERE id=?1",
            params![effect_id, encode(&effect)?],
        )?;
        tx.commit()?;
        Ok(true)
    }
    /// Binds only an originally store-fenced batch before any possible admission mutation.
    pub fn record_run_store_id(&mut self, effect_id: &str, id: &str) -> Result<(), Fault> {
        store_id(id)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut effect = effect(&tx, effect_id)?;
        if !matches!(effect.state.as_str(), "inflight" | "unknown") {
            return Err(Fault::Conflict);
        }
        effect.is_single_batch()?;
        let Work::StartBatch {
            store_fence: true,
            route: Some(route),
            ..
        } = &mut effect.work
        else {
            return Err(Fault::Unavailable);
        };
        match &route.store_id {
            Some(previous) if previous != id => return Err(Fault::Unavailable),
            Some(_) => return Ok(()),
            None => route.store_id = Some(id.to_owned()),
        }
        tx.execute(
            "UPDATE effects SET data=?2 WHERE id=?1",
            params![effect_id, encode(&effect)?],
        )?;
        tx.commit()?;
        Ok(())
    }
    /// Claims one replacement dispatch; concurrent dispatches cannot send under the same claim.
    /// An unknown state may replace a claim left behind by an interrupted previous worker.
    pub(crate) fn claim_replacement(
        &mut self,
        effect_id: &str,
    ) -> Result<Option<(Effect, String)>, Fault> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut effect = effect(&tx, effect_id)?;
        if !matches!(effect.state.as_str(), "inflight" | "unknown") {
            return Ok(None);
        }
        validate_replacement_source(&tx, &effect)?;
        let Work::Replace {
            claim, send_first, ..
        } = &mut effect.work
        else {
            return Err(Fault::Invalid);
        };
        if effect.state == "inflight" && claim.is_some() {
            return Ok(None);
        }
        let token = id();
        *claim = Some(token.clone());
        *send_first = None;
        effect.state = "inflight".into();
        tx.execute(
            "UPDATE effects SET state='inflight',data=?2 WHERE id=?1",
            params![effect_id, encode(&effect)?],
        )?;
        tx.commit()?;
        Ok(Some((effect, token)))
    }

    /// Freezes one proven Run tip before any conditioned replacement admission can be sent.
    pub(crate) fn freeze_replacement_condition(
        &mut self,
        effect_id: &str,
        token: &str,
        next: &crate::run_status::Target,
    ) -> Result<(), Fault> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut effect = effect(&tx, effect_id)?;
        if effect.state != "inflight" {
            return Err(Fault::Conflict);
        }
        validate_replacement_source(&tx, &effect)?;
        let Work::Replace {
            old,
            route,
            condition,
            submitted,
            claim,
            send_first,
            ..
        } = &mut effect.work
        else {
            return Err(Fault::Invalid);
        };
        if claim.as_deref() != Some(token) || send_first.is_some() {
            return Err(Fault::Conflict);
        }
        let store = route.store_id.as_deref().ok_or(Fault::Unavailable)?;
        crate::run_status::validate_request(store, std::slice::from_ref(next))
            .map_err(|_| Fault::Invalid)?;
        if old.run_pin_id.as_deref() != Some(next.pin_id.as_str())
            || old
                .run_sequence
                .is_none_or(|sequence| u64::from(next.sequence) < sequence)
        {
            return Err(Fault::Conflict);
        }
        match condition {
            Some(previous) if previous != next => return Err(Fault::Conflict),
            Some(_) => return Ok(()),
            None if *submitted => return Err(Fault::Conflict),
            None => *condition = Some(next.clone()),
        }
        tx.execute(
            "UPDATE effects SET data=?2 WHERE id=?1",
            params![effect_id, encode(&effect)?],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Records the claim's single submission before network I/O and reports whether it is the first attempt.
    /// A concurrent or crashed prior submission can never become a fresh refusal.
    pub(crate) fn begin_replacement_submit(
        &mut self,
        effect_id: &str,
        token: &str,
    ) -> Result<bool, Fault> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut effect = effect(&tx, effect_id)?;
        validate_replacement_source(&tx, &effect)?;
        let Work::Replace {
            condition: Some(_),
            submitted,
            claim,
            send_first,
            ..
        } = &mut effect.work
        else {
            return Err(Fault::Unavailable);
        };
        if effect.state != "inflight" || claim.as_deref() != Some(token) || send_first.is_some() {
            return Err(Fault::Unavailable);
        }
        let first = !*submitted;
        *submitted = true;
        *send_first = Some(first);
        tx.execute(
            "UPDATE effects SET data=?2 WHERE id=?1",
            params![effect_id, encode(&effect)?],
        )?;
        tx.commit()?;
        Ok(first)
    }
    /// Freezes the producer association and exact provider publication before the first write.
    /// Every retry must match the persisted semantic parameters; a changed config cannot redirect work.
    pub fn freeze_publication(
        &mut self,
        effect_id: &str,
        producer: &str,
        params: &serde_json::Value,
    ) -> Result<(String, serde_json::Value), Fault> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let e = effect(&tx, effect_id)?;
        if !matches!(e.work, Work::Deliver { .. }) || producer.is_empty() || !params.is_object() {
            return Err(Fault::Invalid);
        }
        let prior: Option<(String, String)> = tx
            .query_row(
                "SELECT producer,params FROM publications WHERE effect=?1",
                [effect_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((p, s)) = prior {
            let value: serde_json::Value = decode(&s)?;
            if p != producer || value != *params {
                return Err(Fault::Conflict);
            }
            return Ok((p, value));
        }
        tx.execute(
            "INSERT INTO publications(effect,producer,params) VALUES(?1,?2,?3)",
            params![effect_id, producer, encode(params)?],
        )?;
        tx.commit()?;
        Ok((producer.into(), params.clone()))
    }
    /// Records an effect outcome without cancelling an admission that may already have been sent.
    pub fn settle_effect(&mut self, effect_id: &str, state: &str) -> Result<(), Fault> {
        self.settle_effect_checked(effect_id, state, None)
    }
    /// Settles only the matching replacement claim; a late worker cannot overwrite a newer claim.
    pub(crate) fn settle_replacement(
        &mut self,
        effect_id: &str,
        token: &str,
        state: &str,
    ) -> Result<(), Fault> {
        self.settle_effect_checked(effect_id, state, Some(token))
    }
    /// Applies the common effect settlement after checking replacement claim ownership.
    fn settle_effect_checked(
        &mut self,
        effect_id: &str,
        state: &str,
        token: Option<&str>,
    ) -> Result<(), Fault> {
        if !["unknown", "custody", "accepted", "refused", "cancelled"].contains(&state) {
            return Err(Fault::Invalid);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut effect = effect(&tx, effect_id)?;
        if effect.state == RECONCILIATION_NEEDED {
            // A retained late receipt is terminal; no later settlement overwrites it.
            return Ok(());
        }
        let single_batch = effect.is_single_batch()?;
        let replacement_can_refuse = if let Work::Replace {
            claim,
            send_first,
            submitted,
            ..
        } = &mut effect.work
        {
            if effect.state != "inflight"
                || token.is_none()
                || claim.as_deref() != token
                || matches!(state, "accepted" | "custody")
            {
                return Err(Fault::Conflict);
            }
            let first = *send_first == Some(true) || (!*submitted && send_first.is_none());
            *claim = None;
            *send_first = None;
            first
        } else {
            if token.is_some() {
                return Err(Fault::Invalid);
            }
            false
        };
        if ["accepted", "refused", "cancelled"].contains(&effect.state.as_str()) {
            return if effect.state == state
                || (effect.state == "accepted"
                    && (state == "unknown"
                        || state == "refused"
                            && matches!(effect.work, Work::Start { .. } | Work::StartBatch { .. })))
            {
                Ok(())
            } else {
                Err(Fault::Conflict)
            };
        }
        let unsubmitted = match &effect.work {
            Work::Start {
                route_fence: true,
                route: None,
                ..
            } => effect.state == "inflight",
            Work::StartBatch { route, .. } if single_batch => {
                matches!(effect.state.as_str(), "inflight" | "unknown")
                    && route
                        .as_ref()
                        .and_then(|route| route.store_id.as_ref())
                        .is_none()
            }
            _ => false,
        };
        let state = match (&effect.work, state) {
            (Work::Start { .. } | Work::StartBatch { .. }, "cancelled")
                if unsubmitted && (matches!(effect.work, Work::Start { .. }) || single_batch) =>
            {
                let (binding, current) =
                    binding_any(&tx, effect.member_id.as_deref().ok_or(Fault::Internal)?)?;
                if !current
                    && binding.run_id.is_none()
                    && binding.run_sequence.is_none()
                    && binding.address.is_none()
                {
                    "cancelled"
                } else {
                    "unknown"
                }
            }
            (Work::Start { .. }, "cancelled") => "unknown",
            (Work::StartBatch { .. }, "cancelled") if single_batch => "unknown",
            (Work::Start { .. } | Work::StartBatch { .. }, "refused")
                if effect.state != "inflight" =>
            {
                "unknown"
            }
            (Work::Replace { .. }, "cancelled") => "unknown",
            (Work::Replace { .. }, "refused") if !replacement_can_refuse => "unknown",
            _ => state,
        };
        effect.state = state.into();
        tx.execute(
            "UPDATE effects SET state=?2,data=?3 WHERE id=?1",
            params![effect_id, state, encode(&effect)?],
        )?;
        if matches!(state, "refused" | "cancelled") && matches!(effect.work, Work::Start { .. }) {
            let (binding, _) =
                binding_any(&tx, effect.member_id.as_deref().ok_or(Fault::Internal)?)?;
            if binding.run_id.is_none() && binding.address.is_none() {
                // A positively unadmitted start has no native agent to notify. Preserve
                // uncertain starts instead; this branch never handles outcome_unknown.
                tx.execute("UPDATE effects SET state='cancelled' WHERE member=?1 AND state='awaiting_binding'",[&binding.member.member_id])?;
            }
        }
        if matches!(state, "refused" | "cancelled")
            && let Work::StartBatch { jobs, .. } = &effect.work
        {
            for job in jobs {
                tx.execute("UPDATE effects SET state='cancelled' WHERE member=?1 AND state='awaiting_binding'", [&job.member_id])?;
            }
        }
        let failure_notice: bool = tx.query_row(
            "SELECT failure_notice FROM effects WHERE id=?1",
            [effect_id],
            |r| r.get(0),
        )?;
        if !failure_notice
            && matches!(state, "refused" | "unknown")
            && !matches!(effect.work, Work::Retire { .. })
        {
            let inserted = tx.execute(
                "INSERT OR IGNORE INTO alerts(effect,kind) VALUES(?1,?2)",
                params![effect_id, state],
            )?;
            if inserted > 0 {
                failure_event(
                    &tx,
                    &effect.pool_id,
                    effect.member_id.as_deref(),
                    effect.member_id.is_some() || matches!(effect.work, Work::StartBatch { .. }),
                    if matches!(effect.work, Work::Replace { .. }) && state == "unknown" {
                        "Replacement outcome unknown; the roster stays frozen for reconciliation."
                    } else if matches!(effect.work, Work::Replace { .. }) {
                        "Replacement admission refused; the original member remains current."
                    } else if matches!(effect.work, Work::StartBatch { .. }) && state == "unknown" {
                        "Run batch admission outcome unknown; exact request reconciliation required."
                    } else if matches!(effect.work, Work::StartBatch { .. }) {
                        "Run batch admission refused; no member was admitted by this request."
                    } else if state == "unknown" {
                        "Delivery or admission outcome unknown; reconciliation required."
                    } else {
                        "Delivery or admission refused; owner intervention required."
                    },
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }
    /// Persists a successful Run admission immediately, even when its native binding is not ready.
    /// Repeated identical admission is harmless; differing agent or sequence is refused.
    /// After pool completion the receipt is retained, not installed (`ReconciliationNeeded`).
    pub fn record_run_admission(
        &mut self,
        effect_id: &str,
        agent_id: &str,
        sequence: u64,
    ) -> Result<Admitted, Fault> {
        if !crate::run_status::valid_agent_id(agent_id)
            || sequence == 0
            || sequence > u64::from(u32::MAX)
        {
            return Err(Fault::Invalid);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let e = effect(&tx, effect_id)?;
        if !matches!(e.work, Work::Start { .. }) {
            return Err(Fault::Invalid);
        }
        let mid = e.member_id.as_deref().ok_or(Fault::Internal)?;
        let (mut b, current) = binding_any(&tx, mid)?;
        if crate::completion::completed(&tx, &e.pool_id)? {
            if matches!(e.state.as_str(), "custody" | "accepted")
                && b.run_id.as_deref() == Some(agent_id)
                && b.run_sequence == Some(sequence)
            {
                return Ok(Admitted::Installed);
            }
            let receipt = serde_json::json!({
                "kind": "start",
                "agent_id": agent_id,
                "sequence": sequence,
            });
            return completed_commit(tx, |tx| completed_admission(tx, &e, &receipt));
        }
        if b.run_id.as_deref().is_some_and(|v| v != agent_id)
            || b.run_sequence.is_some_and(|v| v != sequence)
        {
            return Err(Fault::Conflict);
        }
        b.run_id = Some(agent_id.into());
        b.run_sequence = Some(sequence);
        save_binding(&tx, &b, current)?;
        // Admission is known; custody remains monitored until native binding or a final removal notice.
        tx.execute("UPDATE effects SET state='custody' WHERE id=?1 AND state NOT IN ('accepted','refused','cancelled')",[effect_id])?;
        tx.commit()?;
        Ok(Admitted::Installed)
    }
    /// Records every batch admission and queues binding reconciliation in one Pool transaction.
    /// Exact replay never creates a second resolver; inconsistent receipts fail closed.
    /// After pool completion the receipt is retained, not installed (`ReconciliationNeeded`).
    pub fn record_batch_admission(
        &mut self,
        effect_id: &str,
        receipt_store_id: Option<&str>,
        admissions: &[(String, u64, String, Option<String>)],
    ) -> Result<Admitted, Fault> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let e = effect(&tx, effect_id)?;
        e.is_single_batch()?;
        let Work::StartBatch {
            jobs,
            retain_history,
            store_fence,
            route,
            ..
        } = &e.work
        else {
            return Err(Fault::Invalid);
        };
        if route.is_none()
            || jobs.len() != admissions.len()
            || jobs.is_empty()
            || matches!(e.state.as_str(), "refused" | "cancelled")
        {
            return Err(Fault::Conflict);
        }
        let recorded_store_id = route.as_ref().and_then(|route| route.store_id.as_deref());
        if *store_fence && (recorded_store_id.is_none() || recorded_store_id != receipt_store_id) {
            return Err(Fault::Conflict);
        }
        if e.state != "accepted" && crate::completion::completed(&tx, &e.pool_id)? {
            if admissions
                .iter()
                .any(|(agent_id, sequence, reference, pin)| {
                    !crate::run_status::valid_agent_id(agent_id)
                        || *sequence == 0
                        || *sequence > u64::from(u32::MAX)
                        || execution_ref(reference).is_err()
                        || *retain_history != pin.is_some()
                        || pin.as_ref().is_some_and(|value| pin_id(value).is_err())
                })
            {
                return Err(Fault::Invalid);
            }
            let receipt = admission_receipt("start_batch", receipt_store_id, admissions);
            return completed_commit(tx, |tx| completed_admission(tx, &e, &receipt));
        }
        let mut seen = BTreeSet::new();
        let mut seen_refs = BTreeSet::new();
        let mut seen_pins = BTreeSet::new();
        for (job, (agent_id, sequence, reference, pin)) in jobs.iter().zip(admissions) {
            if !crate::run_status::valid_agent_id(agent_id)
                || *sequence == 0
                || *sequence > u32::MAX as u64
                || !seen.insert(agent_id)
                || execution_ref(reference).is_err()
                || !seen_refs.insert(reference)
                || (*retain_history != pin.is_some())
                || pin
                    .as_ref()
                    .is_some_and(|value| pin_id(value).is_err() || !seen_pins.insert(value))
            {
                return Err(Fault::Invalid);
            }
            let (mut binding, current) = binding_any(&tx, &job.member_id)?;
            if let Some(pin) = pin
                && pin_owned_by_other_member(&tx, pin, &job.member_id)?
            {
                return Err(Fault::Conflict);
            }
            if binding.pool_id != e.pool_id
                || binding.run_id.as_ref().is_some_and(|id| id != agent_id)
                || binding.run_sequence.is_some_and(|value| value != *sequence)
                || binding
                    .run_execution_ref
                    .as_ref()
                    .is_some_and(|value| value != reference)
                || binding
                    .run_pin_id
                    .as_ref()
                    .is_some_and(|value| Some(value) != pin.as_ref())
                || (*store_fence
                    && binding
                        .run_store_id
                        .as_deref()
                        .is_some_and(|value| Some(value) != recorded_store_id))
            {
                return Err(Fault::Conflict);
            }
            if e.state == "accepted" {
                if binding.run_id.as_ref() != Some(agent_id)
                    || binding.run_sequence != Some(*sequence)
                    || binding.run_execution_ref.as_ref() != Some(reference)
                    || binding.run_pin_id.as_ref() != pin.as_ref()
                    || (*store_fence && binding.run_store_id.as_deref() != recorded_store_id)
                {
                    return Err(Fault::Conflict);
                }
                continue;
            }
            binding.run_id = Some(agent_id.clone());
            binding.run_sequence = Some(*sequence);
            binding.run_execution_ref = Some(reference.clone());
            binding.run_pin_id = pin.clone();
            if *store_fence {
                binding.run_store_id = recorded_store_id.map(str::to_owned);
            }
            save_binding(&tx, &binding, current)?;
            queue(&tx, &e.pool_id, Some(&job.member_id), Work::ResolveRun)?;
        }
        tx.execute(
            "UPDATE effects SET state='accepted' WHERE id=?1",
            [effect_id],
        )?;
        tx.commit()?;
        Ok(Admitted::Installed)
    }
    /// Atomically installs a replacement only after the exact conditioned Run receipt is verified.
    /// A crash before this commit leaves the old roster frozen for receipt reconciliation.
    /// After pool completion the receipt is retained, not installed (`ReconciliationNeeded`).
    pub(crate) fn record_replacement_admission(
        &mut self,
        effect_id: &str,
        token: &str,
        expected_store: &str,
        admission: &(String, u64, String, Option<String>),
    ) -> Result<Admitted, Fault> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut effect = effect(&tx, effect_id)?;
        let Work::Replace {
            old,
            new,
            route,
            condition: Some(condition),
            submitted: true,
            claim,
            ..
        } = &effect.work
        else {
            return Err(Fault::Conflict);
        };
        if !matches!(effect.state.as_str(), "accepted" | RECONCILIATION_NEEDED)
            && (effect.state != "inflight" || claim.as_deref() != Some(token))
        {
            return Err(Fault::Conflict);
        }
        let (agent_id, sequence, reference, pin) = admission;
        let pin = pin.as_deref().ok_or(Fault::Invalid)?;
        if route.store_id.as_deref() != Some(expected_store)
            || store_id(expected_store).is_err()
            || !crate::run_status::valid_agent_id(agent_id)
            || *sequence != 1
            || execution_ref(reference).is_err()
            || pin_id(pin).is_err()
            || old.run_id.as_deref() == Some(agent_id)
            || condition.agent_id == *agent_id
            || old.run_execution_ref.as_deref() == Some(reference)
            || condition.execution_ref == *reference
            || old.run_pin_id.as_deref() == Some(pin)
        {
            return Err(Fault::Invalid);
        }
        if effect.state == "accepted" {
            let (stored, _) = binding_any(&tx, &new.member.member_id)?;
            let (_, old_current) = binding_any(&tx, &old.member.member_id)?;
            return if !old_current
                && stored.pool_id == effect.pool_id
                && stored.run_id.as_ref() == Some(agent_id)
                && stored.run_sequence == Some(*sequence)
                && stored.run_execution_ref.as_ref() == Some(reference)
                && stored.run_pin_id.as_deref() == Some(pin)
                && stored.run_store_id.as_deref() == Some(expected_store)
            {
                Ok(Admitted::Installed)
            } else {
                Err(Fault::Conflict)
            };
        }
        if crate::completion::completed(&tx, &effect.pool_id)? {
            let receipt = admission_receipt(
                "replace",
                Some(expected_store),
                std::slice::from_ref(admission),
            );
            return completed_commit(tx, |tx| completed_admission(tx, &effect, &receipt));
        }
        if effect.state != "inflight" {
            return Err(Fault::Conflict);
        }
        validate_replacement_source(&tx, &effect)?;
        if pin_owned_by_other_member(&tx, pin, &new.member.member_id)?
            || run_execution_owned_by_other_member(
                &tx,
                expected_store,
                agent_id,
                reference,
                &new.member.member_id,
            )?
        {
            return Err(Fault::Conflict);
        }
        let (previous, current) = binding_any(&tx, &old.member.member_id)?;
        if !current {
            return Err(Fault::Stale);
        }
        let slot: String = tx.query_row(
            "SELECT COALESCE((SELECT slot FROM member_slots WHERE member=?1),?1)",
            [&old.member.member_id],
            |row| row.get(0),
        )?;
        let occupied: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM members m LEFT JOIN member_slots s ON s.member=m.id WHERE m.pool=?1 AND m.current=1 AND m.id<>?2 AND COALESCE(s.slot,m.id)=?3)",
            params![effect.pool_id, old.member.member_id, slot], |row| row.get(0),
        )?;
        if occupied {
            return Err(Fault::Conflict);
        }
        let (mut pool, _) = pool(&tx, &effect.pool_id)?;
        pool.revision = pool.revision.checked_add(1).ok_or(Fault::Internal)?;
        stale(&mut pool);
        remove_binding(&tx, &previous, &pool)?;
        let mut installed = new.clone();
        installed.run_id = Some(agent_id.clone());
        installed.run_sequence = Some(*sequence);
        installed.run_execution_ref = Some(reference.clone());
        installed.run_pin_id = Some(pin.to_owned());
        installed.run_store_id = Some(expected_store.to_owned());
        save_binding(&tx, &installed, true)?;
        tx.execute(
            "INSERT INTO member_slots(member,slot) VALUES(?1,?2)",
            params![installed.member.member_id, slot],
        )?;
        save_pool(&tx, &pool)?;
        let event = append_event(
            &tx,
            &pool,
            "member_replaced",
            Author::Service,
            format!(
                "Member {} replaced by {} after confirmed Run admission.",
                old.member.member_id, installed.member.member_id
            ),
            Some(installed.member.member_id.clone()),
        )?;
        system_deliveries(&tx, &pool, &event, &bindings(&tx, &effect.pool_id)?, None)?;
        final_notice(&tx, &pool, &previous, event.event_id)?;
        queue(
            &tx,
            &effect.pool_id,
            Some(&installed.member.member_id),
            Work::ResolveRun,
        )?;
        let Work::Replace {
            claim, send_first, ..
        } = &mut effect.work
        else {
            return Err(Fault::Internal);
        };
        *claim = None;
        *send_first = None;
        effect.state = "accepted".into();
        tx.execute(
            "UPDATE effects SET state='accepted',data=?2 WHERE id=?1",
            params![effect_id, encode(&effect)?],
        )?;
        tx.commit()?;
        Ok(Admitted::Installed)
    }
    /// Storage primitive for a future proof-backed native binding; the runtime does not call it yet.
    /// Global leader and current membership reservations are rechecked; removed members stay removed.
    #[allow(
        dead_code,
        reason = "Storage primitive retained until attempt-bound Run proof is available"
    )]
    pub fn bind_run(&mut self, effect_id: &str, address: &str) -> Result<(), Fault> {
        text(address, 1024)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let e = effect(&tx, effect_id)?;
        // A terminal effect (including a retained late `reconciliation_needed`
        // receipt) or a completed pool is never overwritten by a later binding.
        if matches!(
            e.state.as_str(),
            "refused" | "cancelled" | RECONCILIATION_NEEDED
        ) || crate::completion::completed(&tx, &e.pool_id)?
        {
            return Err(Fault::Conflict);
        }
        let (mut b, current) = binding_any(&tx, e.member_id.as_deref().ok_or(Fault::Internal)?)?;
        if b.run_id.is_none() {
            return Err(Fault::Conflict);
        }
        if b.address.as_deref().is_some_and(|v| v != address) {
            return Err(Fault::Conflict);
        }
        if current {
            reserve(&tx, address, Some(&b.member.member_id))?;
        }
        if b.address.is_none() {
            b.address = Some(address.into());
            save_binding(&tx, &b, current)?;
            let (pool, _) = pool(&tx, &b.pool_id)?;
            let members = bindings(&tx, &b.pool_id)?;
            if current {
                queue_delivery(
                    &tx,
                    &pool.pool_id,
                    Some(&b.member.member_id),
                    address,
                    &scope(&b.member.member_id),
                    onboarding(&pool, &members, &b.member)?,
                    None,
                )?;
            }
            let mut stmt=tx.prepare("SELECT id,data FROM effects WHERE member=?1 AND state='awaiting_binding' ORDER BY sequence")?;
            let rows = stmt
                .query_map([&b.member.member_id], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            drop(stmt);
            for (eid, data) in rows {
                let mut waiting: Effect = decode(&data)?;
                let Work::Deliver {
                    address: destination,
                    ..
                } = &mut waiting.work
                else {
                    return Err(Fault::Internal);
                };
                if !destination.is_empty() {
                    return Err(Fault::Conflict);
                }
                *destination = address.into();
                waiting.state = "queued".into();
                tx.execute(
                    "UPDATE effects SET state='queued',data=?2 WHERE id=?1",
                    params![eid, encode(&waiting)?],
                )?;
            }
        }
        tx.execute(
            "UPDATE effects SET state='accepted' WHERE id=?1",
            [effect_id],
        )?;
        tx.commit()?;
        Ok(())
    }
    /// Returns current private observation targets, bounded by configured roster limits per pool.
    pub fn observation_targets(&self) -> Result<Vec<Binding>, Fault> {
        let mut stmt = self
            .db
            .prepare("SELECT data FROM members WHERE current=1 ORDER BY id")?;
        stmt.query_map([], |r| r.get::<_, String>(0))?
            .map(|r| decode(&r?))
            .collect()
    }
    /// Records changed supported execution observations; unknown never means ended.
    /// Failures also notify the owner separately, without subscribing them to member conversations.
    pub fn observe_member(
        &mut self,
        pool_id: &str,
        member_id: &str,
        runtime: &str,
    ) -> Result<(), Fault> {
        if ![
            "active",
            "inactive",
            "awaiting_input",
            "unknown",
            "succeeded",
            "failed",
            "lost",
            "cancelled",
        ]
        .contains(&runtime)
        {
            return Err(Fault::Invalid);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (mut b, current) = binding_any(&tx, member_id)?;
        if !current || b.pool_id != pool_id || b.member.runtime == runtime {
            return Ok(());
        }
        b.member.runtime = runtime.into();
        save_binding(&tx, &b, true)?;
        let (mut p, owner) = pool(&tx, pool_id)?;
        p.revision += 1;
        save_pool(&tx, &p)?;
        let ev = append_event(
            &tx,
            &p,
            "runtime_changed",
            Author::Service,
            format!("Member {member_id}: execution {runtime}."),
            Some(member_id.into()),
        )?;
        system_deliveries(&tx, &p, &ev, &bindings(&tx, pool_id)?, None)?;
        if matches!(runtime, "failed" | "lost") {
            let addr = owner_address(&tx, &owner)?;
            queue_delivery(
                &tx,
                pool_id,
                None,
                &addr,
                &format!("owner:{pool_id}"),
                notification(&p, &bindings(&tx, pool_id)?, &ev)?,
                Some(ev.event_id),
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}

/// Reads an opt-in history page and its upper boundary in one SQLite read transaction.
/// The append-only event boundary excludes later writes without claiming a pool-wide snapshot.
fn observe_history(
    db: &Connection,
    args: &crate::observer::Get,
) -> Result<crate::observer::Data, Fault> {
    use crate::observer::{Data, Detail, HistoryDirection, Page};

    let tx = db.unchecked_transaction()?;
    let (mut pool, leader_id) = pool(&tx, &args.pool_id)?;
    if args
        .expected_revision
        .is_some_and(|revision| revision != pool.revision)
    {
        return Err(Fault::Stale);
    }
    let latest: i64 = tx.query_row(
        "SELECT COALESCE(MAX(id),0) FROM events WHERE pool=?1",
        [&args.pool_id],
        |row| row.get(0),
    )?;
    let watermark = args
        .through
        .map(i64::try_from)
        .transpose()
        .map_err(|_| Fault::Invalid)?
        .unwrap_or(latest);
    let exists = |id: i64| -> Result<bool, Fault> {
        if id == 0 {
            return Ok(true);
        }
        Ok(tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM events WHERE pool=?1 AND id=?2)",
            params![args.pool_id, id],
            |row| row.get(0),
        )?)
    };
    if watermark > latest || !exists(watermark)? {
        return Err(Fault::Stale);
    }
    let after = i64::try_from(args.after).map_err(|_| Fault::Invalid)?;
    let before = args
        .before
        .map(i64::try_from)
        .transpose()
        .map_err(|_| Fault::Invalid)?;
    if after > watermark || !exists(after)? {
        return Err(Fault::Stale);
    }
    if let Some(before) = before
        && (before > watermark || !exists(before)?)
    {
        return Err(Fault::Stale);
    }
    let direction = args.direction.ok_or(Fault::Invalid)?;
    let query = match direction {
        HistoryDirection::Forward => {
            "SELECT id,data FROM events WHERE pool=?1 AND id>?2 AND id<=?3 ORDER BY id ASC LIMIT 4"
        }
        HistoryDirection::Backward => {
            "SELECT id,data FROM events WHERE pool=?1 AND (?2 IS NULL OR id<?2) AND id<=?3 ORDER BY id DESC LIMIT 4"
        }
    };
    let boundary = match direction {
        HistoryDirection::Forward => Some(after),
        HistoryDirection::Backward => before,
    };
    let mut events = Vec::new();
    let mut budget = 0usize;
    let mut more = false;
    {
        let mut stmt = tx.prepare(query)?;
        let rows = stmt.query_map(params![args.pool_id, boundary, watermark], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (id, data) = row?;
            if events.len() == 3 || budget + data.len() > 10_000 {
                if events.is_empty() {
                    return Err(Fault::Unavailable);
                }
                more = true;
                break;
            }
            let id = u64::try_from(id).map_err(|_| Fault::Internal)?;
            let mut event: Event = decode(&data)?;
            event.event_id = id;
            event.event_id_exact = Some(id.to_string());
            budget += data.len();
            events.push(event);
        }
    }
    if direction == HistoryDirection::Backward {
        events.reverse();
    }
    let cursor = match direction {
        HistoryDirection::Forward => events.last().map_or(args.after, |event| event.event_id),
        HistoryDirection::Backward => events.first().map_or(0, |event| event.event_id),
    };
    let roster = bindings(&tx, &args.pool_id)?;
    let active = roster
        .iter()
        .filter(|binding| binding.member.state == MemberState::Active)
        .count();
    let pending = roster.len() - active;
    pool.proposal = None;
    pool.acceptance = None;
    project_purpose(&mut pool);
    let view = View {
        section: Section::History,
        pool,
        members: Vec::new(),
        active,
        pending,
        events,
        deliveries: Vec::new(),
        next_after: cursor,
        has_more: more,
        next_before: None,
        content: None,
    };
    let page = Page::new(Some(cursor.to_string()), more, view.events.len())?;
    let detail = Detail {
        section: args.section.clone(),
        view: Some(Box::new(view)),
        leader_id,
        bindings: None,
        decisions: Vec::new(),
        history_watermark: Some(watermark.to_string()),
        page,
    };
    tx.commit()?;
    Ok(Data::Detail(Box::new(detail)))
}
/// Applies a typed command inside the caller's single SQLite transaction.
fn execute(
    db: &Connection,
    actor: &Actor,
    command: &Command,
    enrollment: Option<&crate::managed_enrollment::EnrollmentRoute>,
) -> Result<Reply, Fault> {
    execute_authorized(db, actor, command, None, false, enrollment)
}

/// Apply an already admitted participant mutation under its exact frozen binding.
/// The caller has performed the managed context, generation and admission CAS.
pub(crate) fn apply_managed_mutation(
    db: &Connection,
    command: &Command,
    context: &crate::managed_state::SecurityContext,
    checked_consensus: bool,
) -> Result<(String, u64), Fault> {
    if !matches!(
        command,
        Command::Post(_)
            | Command::Send(_)
            | Command::Notify(_)
            | Command::Propose(_)
            | Command::Vote(_)
            | Command::Remove(_)
            | Command::Join(_)
    ) {
        return Err(Fault::Unavailable);
    }
    if checked_consensus && !matches!(command, Command::Vote(_)) {
        return Err(Fault::Invalid);
    }
    let pool_id = &command.change().ok_or(Fault::Invalid)?.pool_id;
    let mut matching = context
        .bindings
        .iter()
        .filter(|binding| &binding.pool_id == pool_id);
    let binding = matching.next().ok_or(Fault::Unauthorized)?;
    if matching.next().is_some() {
        return Err(Fault::Unauthorized);
    }
    let actor = Actor::verified(
        binding.actor.address.clone(),
        &binding.actor.native_id,
        &binding.actor.role,
    )?;
    // P3: only an owner-enrolled root with a qualified enrollment binding may
    // join; a pending enrollee may do nothing else before that join.
    if matches!(command, Command::Join(_)) {
        crate::managed_enrollment::join_gate(db, binding)?;
    } else if crate::managed_enrollment::pending_enrollee(db, &binding.member_id)? {
        return Err(Fault::Forbidden);
    }
    if db.is_autocommit() {
        return Err(Fault::Internal);
    }
    let namespace: String = db.query_row(
        "SELECT namespace_id FROM managed_contexts WHERE intent_id=?1 AND invocation_key=?2",
        params![context.intent_id, context.invocation_key],
        |row| row.get(0),
    )?;
    db.execute(
        "INSERT INTO temp.managed_delivery_origin(singleton,namespace_id) VALUES(1,?1)",
        [&namespace],
    )?;
    let result = execute_authorized(db, &actor, command, Some(binding), checked_consensus, None)
        .and_then(|reply| {
            if matches!(command, Command::Join(_)) {
                crate::managed_enrollment::mark_joined(db, &binding.member_id)?;
            }
            Ok(reply)
        });
    db.execute(
        "DELETE FROM temp.managed_delivery_origin WHERE singleton=1",
        [],
    )?;
    let reply = result?;
    let Reply::Receipt(receipt) = &reply else {
        return Err(Fault::Internal);
    };
    Ok((encode(&reply)?, receipt.event.event_id))
}

/// Legacy callers never receive the managed authorization or consensus permit.
fn execute_authorized(
    db: &Connection,
    actor: &Actor,
    command: &Command,
    managed: Option<&crate::managed_state::ManagedBinding>,
    checked_consensus: bool,
    enrollment: Option<&crate::managed_enrollment::EnrollmentRoute>,
) -> Result<Reply, Fault> {
    if let Command::Create(c) = command {
        return create(db, actor, c, command);
    }
    if managed.is_some()
        && matches!(
            command,
            Command::EnrollmentGet(_) | Command::EnrollmentResolve(_)
        )
    {
        return Err(Fault::Forbidden);
    }
    if let Command::EnrollmentGet(request) = command {
        return crate::managed_enrollment::owner_get(db, actor, request);
    }
    if let Command::EnrollmentResolve(request) = command {
        return crate::managed_enrollment::owner_resolve(db, actor, request, command);
    }
    if let Command::List(c) = command {
        return list(db, actor, c);
    }
    let pid = match command {
        Command::Get(g) => g.pool_id.as_str(),
        _ => command.change().ok_or(Fault::Invalid)?.pool_id.as_str(),
    };
    let (mut p, owner) = pool(db, pid)?;
    let mut roster = bindings(db, pid)?;
    let is_owner = owner == actor.key;
    let caller = roster
        .iter()
        .find(|b| {
            b.actor.as_deref() == Some(&actor.key)
                || (b.actor.is_none() && b.address.as_deref() == Some(&actor.address))
        })
        .cloned();
    if !is_owner && caller.is_none() {
        return Err(Fault::Forbidden);
    }
    if let Some(binding) = managed {
        if is_owner
            || caller.as_ref().is_none_or(|member| {
                member.member.member_id != binding.member_id
                    || member.pool_id != binding.pool_id
                    || member.run_id.is_none()
                    || member.run_store_id.as_deref() != Some(binding.attempt.run_store_id.as_str())
            })
        {
            return Err(Fault::Unauthorized);
        }
    } else if !is_owner
        && caller
            .as_ref()
            .is_some_and(|binding| binding.run_id.is_some())
    {
        return Err(Fault::Unavailable);
    }
    if let Command::Get(g) = command {
        if g.expected_revision
            .is_some_and(|revision| revision != p.revision)
        {
            return Err(Fault::Stale);
        }
        return view(db, p, roster, g, is_owner);
    }
    let c = command.change().ok_or(Fault::Invalid)?;
    authorize(command, is_owner, caller.as_ref())?;
    let replay_scope = if is_owner {
        format!("owner:{}:{pid}", actor.key)
    } else {
        format!(
            "member:{}",
            caller.as_ref().ok_or(Fault::Forbidden)?.member.member_id
        )
    };
    let digest = command.digest()?;
    if let Some(reply) = replay(db, &replay_scope, &c.request_key, &digest)? {
        return Ok(reply);
    }
    if p.closed && !matches!(command, Command::ReleaseHistory(_)) {
        return Err(Fault::Closed);
    }
    // C3: a committed completion freezes goal, roster, assignments, proposals and votes.
    if matches!(
        command,
        Command::Update(_)
            | Command::Add(_)
            | Command::Start(_)
            | Command::StartBatch(_)
            | Command::Replace(_)
            | Command::CancelReplacement(_)
            | Command::MemberUpdate(_)
            | Command::Remove(_)
            | Command::Join(_)
            | Command::Propose(_)
            | Command::Vote(_)
    ) && crate::completion::completed(db, pid)?
    {
        return Err(Fault::Completed);
    }
    if !p.closed && matches!(command, Command::ReleaseHistory(_)) {
        return Err(Fault::Conflict);
    }
    if p.revision != c.expected_revision {
        return Err(Fault::Stale);
    }
    if matches!(
        command,
        Command::Close(_)
            | Command::Add(_)
            | Command::Start(_)
            | Command::StartBatch(_)
            | Command::Replace(_)
            | Command::MemberUpdate(_)
            | Command::Remove(_)
    ) && batch_pending(db, pid)?
    {
        return Err(Fault::Conflict);
    }
    if matches!(
        command,
        Command::Update(_) | Command::Join(_) | Command::Propose(_) | Command::Vote(_)
    ) && replacement_pending(db, pid)?
    {
        return Err(Fault::Conflict);
    }
    p.revision = p.revision.checked_add(1).ok_or(Fault::Internal)?;
    let author = if is_owner {
        Author::Leader
    } else {
        Author::Member(
            caller
                .as_ref()
                .ok_or(Fault::Forbidden)?
                .member
                .member_id
                .clone(),
        )
    };
    let mut created = None;
    let mut managed_created: Option<String> = None;
    let mut created_ids = Vec::new();
    let mut target = None;
    let mut direct_address = None;
    let mut direct_scope = None;
    let mut start_spec = None;
    let mut removed = None;
    let mut closed_members = Vec::new();
    let mut message_parts = Vec::new();
    let mut release_pin = None;
    let mut replacement = None;
    let mut managed_replacement = None;
    let (kind, body, system) = match command {
        Command::Update(x) => {
            p.name = x.name.clone();
            p.purpose = x.purpose.clone();
            p.purpose_bytes = None;
            (
                "pool_updated",
                String::from("Pool name and purpose updated."),
                true,
            )
        }
        Command::Close(_) => {
            p.closed = true;
            stale(&mut p);
            closed_members = roster.clone();
            for b in &roster {
                remove_binding(db, b, &p)?;
            }
            roster.clear();
            (
                "pool_closed",
                String::from("Pool closed; execution processes were not stopped."),
                true,
            )
        }
        Command::Add(x) => {
            if roster.len() >= MAX_MEMBERS {
                return Err(Fault::Conflict);
            }
            reserve(db, &x.address, None)?;
            let b = new_binding(&p, &x.name, &x.role, &x.task, Some(x.address.clone()));
            created = Some(b.member.member_id.clone());
            target = created.clone();
            save_binding(db, &b, true)?;
            roster.push(b);
            stale(&mut p);
            (
                "member_added",
                String::from("Member invited; awaiting verified onboarding acknowledgment."),
                true,
            )
        }
        Command::Start(x) => {
            if roster.len() >= MAX_MEMBERS {
                return Err(Fault::Conflict);
            }
            let b = new_binding(&p, &x.name, &x.role, &x.task, None);
            created = Some(b.member.member_id.clone());
            target = created.clone();
            save_binding(db, &b, true)?;
            roster.push(b);
            stale(&mut p);
            start_spec = Some(x.spec.clone());
            (
                "member_added",
                String::from(
                    "Agent start requested; member awaits native binding and verified join.",
                ),
                true,
            )
        }
        Command::StartBatch(x) => {
            if roster.len() + x.members.len() > MAX_MEMBERS {
                return Err(Fault::Conflict);
            }
            for member in &x.members {
                let b = new_binding(&p, &member.name, &member.role, &member.task, None);
                created_ids.push(b.member.member_id.clone());
                save_binding(db, &b, true)?;
                roster.push(b);
            }
            stale(&mut p);
            (
                "batch_start_requested",
                format!(
                    "Atomic admission requested for {} members; Run outcome pending.",
                    created_ids.len()
                ),
                true,
            )
        }
        Command::Replace(x) if enrollment.is_some() => {
            let route = enrollment.ok_or(Fault::Internal)?;
            let old = roster
                .iter()
                .find(|binding| binding.member.member_id == x.member_id)
                .ok_or(Fault::Forbidden)?
                .clone();
            managed_replacement =
                Some(managed_replacement_freeze(db, &p, &roster, route, &old, x)?);
            target = Some(x.member_id.clone());
            (
                "replacement_requested",
                "Replacement requested; the current member remains until a qualified new lineage is attested and switched.".into(),
                true,
            )
        }
        Command::Replace(x) => {
            let old = roster
                .iter()
                .find(|binding| binding.member.member_id == x.member_id)
                .ok_or(Fault::Forbidden)?
                .clone();
            let store = old.run_store_id.as_deref().ok_or(Fault::Unavailable)?;
            let agent_id = old.run_id.as_deref().ok_or(Fault::Unavailable)?;
            let sequence = old.run_sequence.ok_or(Fault::Unavailable)?;
            let reference = old.run_execution_ref.as_deref().ok_or(Fault::Unavailable)?;
            let pin = old.run_pin_id.as_deref().ok_or(Fault::Unavailable)?;
            if !crate::run_status::valid_agent_id(agent_id)
                || sequence == 0
                || sequence > u64::from(u32::MAX)
                || execution_ref(reference).is_err()
                || pin_id(pin).is_err()
                || store_id(store).is_err()
            {
                return Err(Fault::Unavailable);
            }
            let route =
                pin_origin_route(db, pid, &x.member_id, Some(store))?.ok_or(Fault::Unavailable)?;
            let spec = match &x.spec {
                Some(spec) => spec.clone(),
                None => original_start_spec(db, pid, &x.member_id, Some(store))?
                    .ok_or(Fault::Unavailable)?,
            };
            let new = new_binding(
                &p,
                &old.member.name,
                &old.member.role,
                &old.member.task,
                None,
            );
            let mut next_roster = roster.clone();
            let position = next_roster
                .iter()
                .position(|binding| binding.member.member_id == x.member_id)
                .ok_or(Fault::Internal)?;
            next_roster[position] = new.clone();
            let intro = format!(
                "{}\nA replacement can start before its roster update commits. If this membership is not yet visible, wait and retry with the same member_id; explicit removal ends access.\n",
                onboarding(&p, &next_roster, &new.member)?
            );
            let job = BatchJob {
                member_id: new.member.member_id.clone(),
                spec: prepare_start(spec.clone(), &intro)?,
                original_spec: Some(spec),
            };
            let request_key = format!("agent-pool.replace.{}", id());
            validate_replacement_frame(&request_key, &job, &old)?;
            target = Some(x.member_id.clone());
            created_ids.push(new.member.member_id.clone());
            replacement = Some((request_key, old, new, job, route));
            (
                "replacement_requested",
                "Replacement requested; the current member remains until Run admission is confirmed.".into(),
                true,
            )
        }
        Command::CancelReplacement(x) => {
            match crate::managed_enrollment::cancel_replacement(db, pid, &x.operation_id)? {
                Some((member, false)) => {
                    target = Some(member);
                    created = Some(x.operation_id.clone());
                    (
                        "replacement_cancel_requested",
                        "Replacement outcome is uncertain; Pool requested the original-key Run abort. The roster stays frozen until a tombstone or the original admission is observed."
                            .into(),
                        true,
                    )
                }
                Some((member, true)) => {
                    target = Some(member);
                    (
                        "replacement_cancelled",
                        "Replacement cancelled before Run admission; the original member remains current."
                            .into(),
                        true,
                    )
                }
                None => {
                    target = Some(cancel_unsubmitted_replacement(db, pid, &x.operation_id)?);
                    (
                        "replacement_cancelled",
                        "Replacement cancelled before Run admission; the original member remains current."
                            .into(),
                        true,
                    )
                }
            }
        }
        Command::MemberUpdate(x) => {
            let b = roster
                .iter_mut()
                .find(|b| b.member.member_id == x.member_id)
                .ok_or(Fault::Forbidden)?;
            b.member.name = x.name.clone();
            b.member.role = x.role.clone();
            b.member.task = x.task.clone();
            save_binding(db, b, true)?;
            target = Some(x.member_id.clone());
            stale(&mut p);
            (
                "assignment_changed",
                String::from("Member role, task or name updated."),
                true,
            )
        }
        Command::Remove(x) => {
            let i = roster
                .iter()
                .position(|b| b.member.member_id == x.member_id)
                .ok_or(Fault::Forbidden)?;
            let b = roster.remove(i);
            remove_binding(db, &b, &p)?;
            removed = Some(b);
            target = Some(x.member_id.clone());
            stale(&mut p);
            (
                "member_removed",
                String::from("Membership ended; execution process was not stopped."),
                true,
            )
        }
        Command::ReleaseHistory(x) => {
            let raw: Option<String> = db
                .query_row(
                    "SELECT data FROM members WHERE id=?1 AND pool=?2",
                    params![x.member_id, pid],
                    |row| row.get(0),
                )
                .optional()?;
            let binding: Binding = decode(&raw.ok_or(Fault::Forbidden)?)?;
            let pin = binding
                .run_pin_id
                .as_deref()
                .ok_or(Fault::Invalid)?
                .to_owned();
            pin_id(&pin)?;
            if pin_release_exists(db, pid, &x.member_id, &pin)? {
                return Err(Fault::Conflict);
            }
            target = Some(x.member_id.clone());
            let route = pin_origin_route(db, pid, &x.member_id, binding.run_store_id.as_deref())?;
            release_pin = Some((x.member_id.clone(), pin, route));
            (
                "history_release_requested",
                "Owner requested release of the closed member's retained Run history.".into(),
                false,
            )
        }
        Command::Join(_) => {
            if leader(db, actor)? {
                return Err(Fault::Forbidden);
            }
            let b = roster
                .iter_mut()
                .find(|b| {
                    b.member.member_id
                        == caller
                            .as_ref()
                            .map(|x| x.member.member_id.as_str())
                            .unwrap_or("")
                })
                .ok_or(Fault::Forbidden)?;
            if b.member.state != MemberState::Pending {
                return Err(Fault::Conflict);
            }
            let occupied: bool = db.query_row(
                "SELECT EXISTS(SELECT 1 FROM members WHERE current=1 AND actor=?1 AND id<>?2)",
                params![actor.key, b.member.member_id],
                |r| r.get(0),
            )?;
            if occupied {
                return Err(Fault::Conflict);
            }
            b.actor = Some(actor.key.clone());
            b.member.state = MemberState::Active;
            target = Some(b.member.member_id.clone());
            save_binding(db, b, true)?;
            stale(&mut p);
            (
                "member_joined",
                String::from("Member confirmed the current onboarding snapshot."),
                true,
            )
        }
        Command::Post(x) => (
            "message",
            first_message_part(&x.body, &mut message_parts),
            false,
        ),
        Command::Send(x) => {
            let b = roster
                .iter()
                .find(|b| b.member.member_id == x.member_id)
                .ok_or(Fault::Forbidden)?;
            direct_address = Some(b.address.clone().unwrap_or_default());
            direct_scope = Some(scope(&b.member.member_id));
            target = Some(x.member_id.clone());
            (
                "direct_message",
                first_message_part(&x.body, &mut message_parts),
                false,
            )
        }
        Command::Notify(x) => {
            direct_address = Some(owner_address(db, &owner)?);
            direct_scope = Some(format!("owner:{pid}"));
            (
                "owner_message",
                first_message_part(&x.body, &mut message_parts),
                false,
            )
        }
        Command::Propose(x) => {
            let voters: Vec<_> = roster
                .iter()
                .filter(|b| b.member.state == MemberState::Active)
                .map(|b| b.member.member_id.clone())
                .collect();
            if voters.is_empty() {
                return Err(Fault::Conflict);
            }
            let superseded = if let Some(previous) = p
                .proposal
                .as_mut()
                .filter(|p| p.state == ProposalState::Open)
            {
                previous.state = ProposalState::Stale;
                Some(previous.proposal_id.clone())
            } else {
                None
            };
            if superseded.is_some() {
                save_pool(db, &p)?;
            }
            let frozen: Vec<_> = roster
                .iter()
                .filter(|b| b.member.state == MemberState::Active)
                .map(|b| (&b.member.member_id, &b.member.role, &b.member.task))
                .collect();
            let proposal_id = id();
            created = Some(proposal_id.clone());
            let proposal = Proposal {
                proposal_id,
                roster_key: format!("{:x}", Sha256::digest(encode(&frozen)?.as_bytes())),
                voters,
                result: x.result.clone(),
                criteria: x.criteria.clone(),
                snapshot: x.snapshot.clone(),
                snapshot_bytes: x.snapshot.as_ref().map(String::len),
                state: ProposalState::Open,
                votes: BTreeMap::new(),
            };
            // Archive complete proposal content independently of the current bounded pool snapshot.
            p.proposal = Some(proposal);
            (
                "proposal_opened",
                format!(
                    "{}Result:\n{}\nCriteria:\n{}{}",
                    superseded
                        .map(|id| format!(
                            "Supersedes proposal {id}; its previous votes remain archived.\n"
                        ))
                        .unwrap_or_default(),
                    x.result,
                    x.criteria,
                    if x.snapshot.is_some() {
                        "\nFull snapshot: pool_get section=content field=snapshot."
                    } else {
                        ""
                    }
                ),
                true,
            )
        }
        Command::Vote(x) => {
            let member = &caller.as_ref().ok_or(Fault::Forbidden)?.member.member_id;
            let checks_met = if let Some(criteria) = &p.acceptance {
                if x.choice == Choice::Ready {
                    let required: BTreeSet<_> = criteria.iter().map(|c| c.id.as_str()).collect();
                    let supplied: BTreeSet<_> =
                        x.checks.iter().map(|c| c.criterion_id.as_str()).collect();
                    if supplied != required {
                        return Err(Fault::Invalid);
                    }
                    Some(x.checks.iter().all(|c| c.status == CheckStatus::Met))
                } else {
                    None
                }
            } else {
                if !x.checks.is_empty()
                    || (matches!(x.choice, Choice::Ready | Choice::Block) && x.evidence.is_empty())
                {
                    return Err(Fault::Invalid);
                }
                None
            };
            let proposal = p.proposal.as_mut().ok_or(Fault::Stale)?;
            if proposal.state != ProposalState::Open
                || proposal.proposal_id != x.proposal_id
                || proposal.roster_key != x.roster_key
                || !proposal.voters.contains(member)
            {
                return Err(Fault::Stale);
            }
            proposal.votes.insert(
                member.clone(),
                Ballot {
                    choice: x.choice.clone(),
                    evidence: x.evidence.clone(),
                    checks_met,
                    vote_event_id: None,
                    checks_count: p.acceptance.as_ref().map(|_| x.checks.len()),
                    validity: None,
                },
            );
            let structured = p.acceptance.is_some();
            if proposal.voters.iter().all(|m| {
                let Some(binding) = roster.iter().find(|binding| binding.member.member_id == *m)
                else {
                    return false;
                };
                if (binding.run_id.is_some() && !checked_consensus)
                    || binding.member.state != MemberState::Active
                {
                    return false;
                }
                proposal.votes.get(m).is_some_and(|b| {
                    b.choice == Choice::Ready && (!structured || b.checks_met == Some(true))
                })
            }) {
                proposal.state = ProposalState::Accepted;
            }
            (
                if proposal.state == ProposalState::Accepted {
                    "proposal_accepted"
                } else {
                    "vote_recorded"
                },
                format!(
                    "Proposal {}: {:?}.\n{}",
                    x.proposal_id, x.choice, x.evidence
                ),
                true,
            )
        }
        _ => return Err(Fault::Invalid),
    };
    let mut event = append_event(db, &p, kind, author.clone(), body, target.clone())?;
    if !message_parts.is_empty() {
        append_message_parts(db, &p, &mut event, &message_parts)?;
    }
    if let Command::Vote(x) = command
        && p.acceptance.is_some()
    {
        let member = &caller.as_ref().ok_or(Fault::Forbidden)?.member.member_id;
        let ballot = p
            .proposal
            .as_mut()
            .and_then(|proposal| proposal.votes.get_mut(member))
            .ok_or(Fault::Internal)?;
        ballot.vote_event_id = Some(event.event_id.to_string());
        for check in &x.checks {
            append_check(db, &p, author.clone(), event.event_id, check)?;
        }
    }
    save_pool(db, &p)?;
    if system {
        system_deliveries(
            db,
            &p,
            &event,
            &roster,
            caller.as_ref().map(|b| b.member.member_id.as_str()),
        )?;
    } else if matches!(command, Command::Send(_) | Command::Notify(_)) {
        let own_target = target.as_deref() == caller.as_ref().map(|b| b.member.member_id.as_str());
        if (!own_target || matches!(command, Command::Notify(_)))
            && let Some(address) = direct_address
        {
            queue_delivery(
                db,
                pid,
                target.as_deref(),
                &address,
                direct_scope.as_deref().ok_or(Fault::Internal)?,
                notification(&p, &roster, &event)?,
                Some(event.event_id),
            )?;
        }
    } else {
        system_deliveries(
            db,
            &p,
            &event,
            &roster,
            caller.as_ref().map(|b| b.member.member_id.as_str()),
        )?;
    }
    if let Some(member_id) = created
        .as_deref()
        .filter(|_| matches!(command, Command::Add(_) | Command::Start(_)))
    {
        let b = roster
            .iter()
            .find(|b| b.member.member_id == member_id)
            .ok_or(Fault::Internal)?;
        let intro = onboarding(&p, &roster, &b.member)?;
        if let Some(address) = &b.address {
            queue_delivery(
                db,
                pid,
                Some(member_id),
                address,
                &scope(member_id),
                intro,
                Some(event.event_id),
            )?;
        } else if let (Some(spec), Some(route)) = (start_spec.as_ref(), enrollment) {
            queue_delivery(
                db,
                pid,
                Some(member_id),
                "",
                &scope(member_id),
                intro.clone(),
                Some(event.event_id),
            )?;
            let job = crate::managed_enrollment::ReservedJob {
                member_id: member_id.to_owned(),
                original: spec.clone(),
                submitted: crate::managed_enrollment::managed_spec(spec, &route.role, &intro)?,
            };
            let enrollment_id = crate::managed_enrollment::reserve(
                db,
                route,
                pid,
                &actor.key,
                &replay_scope,
                &c.request_key,
                &digest,
                std::slice::from_ref(&job),
                None,
            )?;
            created_ids.push(member_id.to_owned());
            managed_created = Some(enrollment_id);
        } else if let Some(spec) = start_spec {
            let request_key = format!("agent-pool.{pid}.{member_id}");
            let jobs = vec![BatchJob {
                member_id: member_id.to_owned(),
                spec: prepare_start(spec.clone(), &intro)?,
                original_spec: Some(spec),
            }];
            validate_batch_frame(&request_key, &jobs)?;
            queue(
                db,
                pid,
                Some(member_id),
                Work::StartBatch {
                    request_key,
                    jobs,
                    retain_history: true,
                    store_fence: true,
                    route_fence: true,
                    route: None,
                },
            )?;
        }
    }
    if let (Command::StartBatch(batch), Some(route)) = (command, enrollment) {
        let mut jobs = Vec::with_capacity(batch.members.len());
        for (member_id, member) in created_ids.iter().zip(&batch.members) {
            let binding = roster
                .iter()
                .find(|b| &b.member.member_id == member_id)
                .ok_or(Fault::Internal)?;
            let intro = onboarding(&p, &roster, &binding.member)?;
            queue_delivery(
                db,
                pid,
                Some(member_id),
                "",
                &scope(member_id),
                intro.clone(),
                Some(event.event_id),
            )?;
            jobs.push(crate::managed_enrollment::ReservedJob {
                member_id: member_id.clone(),
                original: member.spec.clone(),
                submitted: crate::managed_enrollment::managed_spec(
                    &member.spec,
                    &route.role,
                    &intro,
                )?,
            });
        }
        created = Some(crate::managed_enrollment::reserve(
            db,
            route,
            pid,
            &actor.key,
            &replay_scope,
            &c.request_key,
            &digest,
            &jobs,
            None,
        )?);
    } else if let Command::StartBatch(batch) = command {
        let request_key = format!("agent-pool.batch.{}", id());
        let mut jobs = Vec::with_capacity(batch.members.len());
        for (member_id, member) in created_ids.iter().zip(&batch.members) {
            let binding = roster
                .iter()
                .find(|b| &b.member.member_id == member_id)
                .ok_or(Fault::Internal)?;
            let intro = onboarding(&p, &roster, &binding.member)?;
            jobs.push(BatchJob {
                member_id: member_id.clone(),
                spec: prepare_start(member.spec.clone(), &intro)?,
                original_spec: Some(member.spec.clone()),
            });
        }
        validate_batch_frame(&request_key, &jobs)?;
        created = Some(queue(
            db,
            pid,
            None,
            Work::StartBatch {
                request_key,
                jobs,
                retain_history: true,
                store_fence: true,
                route_fence: true,
                route: None,
            },
        )?);
    }
    if let (Some(freeze), Some(route)) = (managed_replacement, enrollment) {
        let job = crate::managed_enrollment::ReservedJob {
            member_id: freeze.candidate.member.member_id.clone(),
            original: freeze.original.clone(),
            submitted: freeze.freeze.submitted.clone(),
        };
        created_ids.push(job.member_id.clone());
        created = Some(crate::managed_enrollment::reserve(
            db,
            route,
            pid,
            &actor.key,
            &replay_scope,
            &c.request_key,
            &digest,
            std::slice::from_ref(&job),
            Some(&freeze.freeze),
        )?);
    }
    if let Some(enrollment_id) = managed_created.take() {
        created = Some(enrollment_id);
    }
    if let Some((request_key, old, new, job, route)) = replacement {
        let old_member_id = old.member.member_id.clone();
        created = Some(queue(
            db,
            pid,
            Some(&old_member_id),
            Work::Replace {
                request_key,
                old: Box::new(old),
                new: Box::new(new),
                job,
                route,
                condition: None,
                submitted: false,
                claim: None,
                send_first: None,
            },
        )?);
    }
    if let Some((member_id, pin_id, route)) = release_pin {
        created = Some(queue(
            db,
            pid,
            Some(&member_id),
            Work::ReleasePin { pin_id, route },
        )?);
    }
    // A removed member receives only the independent final service notice, never the remaining roster.
    if let Some(b) = removed {
        final_notice(db, &p, &b, event.event_id)?;
    }
    for b in &closed_members {
        final_notice(db, &p, b, event.event_id)?;
    }
    if p.closed {
        crate::managed_egress::retire_final_scope(db, &p.pool_id)?;
    }
    let managed_status = enrollment.is_some()
        && matches!(
            command,
            Command::Start(_) | Command::StartBatch(_) | Command::Replace(_)
        );
    let reply = Reply::Receipt(Box::new(Receipt {
        pool_id: pid.into(),
        revision: p.revision,
        created_id: created,
        created_ids,
        event,
        status: if managed_status {
            "committed; managed enrollment pending".into()
        } else {
            "committed; delivery pending".into()
        },
    }));
    remember(db, &replay_scope, &c.request_key, &digest, &reply)?;
    Ok(reply)
}
/// Enforces tool-specific owner/member roles, including pending-member read/join restrictions.
pub(crate) fn authorize(
    command: &Command,
    owner: bool,
    caller: Option<&Binding>,
) -> Result<(), Fault> {
    let active = caller.is_some_and(|b| b.member.state == MemberState::Active);
    let allowed = match command {
        Command::Update(_)
        | Command::Close(_)
        | Command::Add(_)
        | Command::Start(_)
        | Command::StartBatch(_)
        | Command::Replace(_)
        | Command::CancelReplacement(_)
        | Command::ReleaseHistory(_)
        | Command::MemberUpdate(_) => owner,
        Command::Join(_) => !owner && caller.is_some(),
        Command::Remove(x) => owner || caller.is_some_and(|b| b.member.member_id == x.member_id),
        Command::Vote(_) | Command::Notify(_) => !owner && active,
        Command::Post(_) | Command::Send(_) | Command::Propose(_) => owner || active,
        _ => false,
    };
    if allowed {
        Ok(())
    } else {
        Err(Fault::Forbidden)
    }
}
/// Creates a permanent global leader and pool atomically, preserving exact creation retries.
fn create(db: &Connection, actor: &Actor, c: &Create, command: &Command) -> Result<Reply, Fault> {
    let member: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM members WHERE current=1 AND (actor=?1 OR address=?2))",
        params![actor.key, actor.address],
        |r| r.get(0),
    )?;
    if member {
        return Err(Fault::Forbidden);
    }
    let scope = format!("create:{}", actor.key);
    let digest = command.digest()?;
    if let Some(reply) = replay(db, &scope, &c.request_key, &digest)? {
        return Ok(reply);
    }
    let address_owner: Option<String> = db
        .query_row(
            "SELECT actor FROM leaders WHERE address=?1",
            [&actor.address],
            |r| r.get(0),
        )
        .optional()?;
    if address_owner.as_ref().is_some_and(|x| x != &actor.key) {
        return Err(Fault::Conflict);
    }
    db.execute(
        "INSERT INTO leaders(actor,address) VALUES(?1,?2) ON CONFLICT(actor) DO NOTHING",
        params![actor.key, actor.address],
    )?;
    let p = Pool {
        pool_id: id(),
        name: c.name.clone(),
        purpose: c.purpose.clone(),
        purpose_bytes: None,
        acceptance: c.acceptance.as_ref().map(|criteria| {
            if criteria.is_empty() {
                vec![Criterion {
                    id: "goal".into(),
                    text: "The stated goal is met.".into(),
                }]
            } else {
                criteria.clone()
            }
        }),
        revision: 1,
        closed: false,
        proposal: None,
    };
    db.execute(
        "INSERT INTO pools(id,owner,data) VALUES(?1,?2,?3)",
        params![p.pool_id, actor.key, encode(&p)?],
    )?;
    let event = append_event(
        db,
        &p,
        "pool_created",
        Author::Leader,
        "Persistent pool created; leader is outside its membership.".into(),
        None,
    )?;
    let reply = Reply::Receipt(Box::new(Receipt {
        pool_id: p.pool_id,
        revision: 1,
        created_id: None,
        created_ids: Vec::new(),
        event,
        status: "committed".into(),
    }));
    remember(db, &scope, &c.request_key, &digest, &reply)?;
    Ok(reply)
}
/// Returns ten accessible pools with an exclusive ID cursor, omitting potentially large proposal data.
fn list(db: &Connection, actor: &Actor, c: &List) -> Result<Reply, Fault> {
    let mut memberships = db.prepare(
        "SELECT data FROM members WHERE current=1 AND (actor=?1 OR (actor IS NULL AND address=?2))",
    )?;
    for row in
        memberships.query_map(params![actor.key, actor.address], |r| r.get::<_, String>(0))?
    {
        let binding: Binding = decode(&row?)?;
        if binding.run_id.is_some() {
            return Err(Fault::Unavailable);
        }
    }
    drop(memberships);
    list_accessible(db, actor, c)
}

/// Shared bounded projection; callers must independently authorize the actor first.
fn list_accessible(db: &Connection, actor: &Actor, c: &List) -> Result<Reply, Fault> {
    let mut stmt=db.prepare("SELECT p.data FROM pools p WHERE p.id>?3 AND (p.owner=?1 OR EXISTS(SELECT 1 FROM members m WHERE m.pool=p.id AND m.current=1 AND (m.actor=?1 OR (m.actor IS NULL AND m.address=?2)))) ORDER BY p.id LIMIT 11")?;
    let mut pools: Vec<Pool> = stmt
        .query_map(
            params![actor.key, actor.address, c.after.as_deref().unwrap_or("")],
            |r| r.get::<_, String>(0),
        )?
        .map(|r| {
            let mut p: Pool = decode(&r?)?;
            p.proposal = None;
            p.acceptance = None;
            project_purpose(&mut p);
            Ok(p)
        })
        .collect::<Result<_, Fault>>()?;
    let more = pools.len() > 10;
    pools.truncate(10);
    let next = pools.last().map(|p| p.pool_id.clone());
    Ok(Reply::List {
        pools,
        next_after: next,
        has_more: more,
    })
}

/// Project a managed participant read only for the complete verified membership set.
pub(crate) fn managed_read_projection(
    db: &Connection,
    command: &Command,
    context: &crate::managed_state::SecurityContext,
) -> Result<Reply, Fault> {
    let first = context.bindings.first().ok_or(Fault::Unauthorized)?;
    if context
        .bindings
        .iter()
        .any(|binding| binding.actor != first.actor)
    {
        return Err(Fault::Unauthorized);
    }
    let actor = Actor::verified(
        first.actor.address.clone(),
        &first.actor.native_id,
        &first.actor.role,
    )?;
    let owner: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM leaders WHERE actor=?1 OR address=?2)",
        params![actor.key, actor.address],
        |row| row.get(0),
    )?;
    if owner {
        return Err(Fault::Forbidden);
    }
    let mut stmt = db.prepare(
        "SELECT data FROM members WHERE current=1 AND (actor=?1 OR (actor IS NULL AND address=?2))",
    )?;
    let memberships = stmt
        .query_map(params![actor.key, actor.address], |row| {
            row.get::<_, String>(0)
        })?
        .map(|row| decode::<Binding>(&row?))
        .collect::<Result<Vec<_>, Fault>>()?;
    if memberships.len() != context.bindings.len()
        || memberships.iter().any(|member| {
            let current_actor = member.actor.as_deref() == Some(actor.key.as_str())
                || (member.actor.is_none()
                    && member.address.as_deref() == Some(actor.address.as_str()));
            member.run_id.is_none()
                || !current_actor
                || !context.bindings.iter().any(|binding| {
                    binding.pool_id == member.pool_id
                        && binding.member_id == member.member.member_id
                        && member.run_store_id.as_deref()
                            == Some(binding.attempt.run_store_id.as_str())
                })
        })
    {
        return Err(Fault::Stale);
    }
    match command {
        Command::List(list) => list_accessible(db, &actor, list),
        Command::Get(get) if get.wait_seconds == 0.0 => {
            if !context
                .bindings
                .iter()
                .any(|binding| binding.pool_id == get.pool_id)
            {
                return Err(Fault::Forbidden);
            }
            let (pool, _) = pool(db, &get.pool_id)?;
            if get
                .expected_revision
                .is_some_and(|revision| revision != pool.revision)
            {
                return Err(Fault::Stale);
            }
            view(db, pool, bindings(db, &get.pool_id)?, get, false)
        }
        Command::Get(_) => Err(Fault::Unavailable),
        _ => Err(Fault::Invalid),
    }
}
/// Projects exactly one bounded section; cursors advance only across returned rows.
fn view(
    db: &Connection,
    mut p: Pool,
    mut roster: Vec<Binding>,
    g: &Get,
    owner: bool,
) -> Result<Reply, Fault> {
    let sql_after = i64::try_from(g.after).map_err(|_| Fault::Invalid)?;
    for binding in &mut roster {
        if binding.run_id.is_some() {
            binding.member.runtime = "unknown".into();
        }
    }
    let acceptance = p.acceptance.take();
    let full_purpose = p.purpose.clone();
    project_purpose(&mut p);
    if let Some(pid) = &g.proposal_id {
        let raw: Option<String> = db
            .query_row(
                "SELECT data FROM proposals WHERE id=?1 AND pool=?2",
                params![pid, p.pool_id],
                |r| r.get(0),
            )
            .optional()?;
        p.proposal = Some(decode(&raw.ok_or(Fault::Forbidden)?)?);
    }
    let snapshot = p
        .proposal
        .as_mut()
        .and_then(|proposal| proposal.snapshot.take());
    let active = roster
        .iter()
        .filter(|b| b.member.state == MemberState::Active)
        .count();
    let pending = roster.len() - active;
    let mut members = Vec::new();
    let mut events = Vec::new();
    let mut deliveries = Vec::new();
    let mut next = g.after;
    let mut next_before = None;
    let mut more = false;
    let mut private = Vec::new();
    let mut content = None;
    match g.section {
        Section::Binding => {
            if !owner {
                return Err(Fault::Forbidden);
            }
            p.proposal = None;
            let mid = g.member_id.as_deref().ok_or(Fault::Invalid)?;
            let row: Option<(String, bool)> = db
                .query_row(
                    "SELECT data,current FROM members WHERE id=?1 AND pool=?2",
                    params![mid, p.pool_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let (data, current) = row.ok_or(Fault::Forbidden)?;
            let mut binding: Binding = decode(&data)?;
            if binding.run_id.is_some() {
                binding.member.runtime = "unknown".into();
            }
            if !current {
                binding.member.state = MemberState::Removed;
            }
            members.push(binding.member.clone());
            private.push(binding);
        }
        Section::Overview | Section::Members => {
            p.proposal = None;
            let offset = usize::try_from(g.after).map_err(|_| Fault::Invalid)?;
            private = roster
                .iter()
                .skip(offset)
                .take(if owner { 2 } else { 5 })
                .cloned()
                .collect();
            members = private.iter().map(|b| b.member.clone()).collect();
            next = g.after + members.len() as u64;
            more = next < (roster.len() as u64);
        }
        Section::History => {
            p.proposal = None;
            let mut budget = 0;
            let sql = if g.reverse {
                "SELECT id,data FROM events WHERE pool=?1 AND (?2 IS NULL OR id<?2) ORDER BY id DESC LIMIT 4"
            } else {
                "SELECT id,data FROM events WHERE pool=?1 AND id>?2 ORDER BY id LIMIT 4"
            };
            let boundary = if g.reverse {
                g.before
                    .as_deref()
                    .map(str::parse::<i64>)
                    .transpose()
                    .map_err(|_| Fault::Invalid)?
            } else {
                Some(sql_after)
            };
            let mut stmt = db.prepare(sql)?;
            let rows = stmt.query_map(params![p.pool_id, boundary], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
            })?;
            for row in rows {
                let (n, s) = row?;
                let n = u64::try_from(n).map_err(|_| Fault::Internal)?;
                if events.len() == 3 || budget + s.len() > 10000 {
                    if events.is_empty() {
                        return Err(Fault::Unavailable);
                    }
                    more = true;
                    break;
                }
                let mut e: Event = decode(&s)?;
                e.event_id = n;
                budget += s.len();
                next = n;
                events.push(e);
            }
            if g.reverse {
                events.reverse();
                next = events.first().map_or(0, |event| event.event_id);
                next_before = Some(next.to_string());
            }
        }
        Section::Proposal => {
            if let Some(proposal) = p.proposal.as_mut() {
                proposal.votes.clear();
            }
        }
        Section::Votes => {
            if let Some(proposal) = p.proposal.as_mut() {
                let offset = usize::try_from(g.after).map_err(|_| Fault::Invalid)?;
                let len = proposal.votes.len();
                proposal.votes = proposal
                    .votes
                    .iter()
                    .skip(offset)
                    .take(3)
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                for (member_id, ballot) in &mut proposal.votes {
                    if binding_any(db, member_id)?.0.run_id.is_some() {
                        ballot.validity = Some(VoteValidity::Unknown);
                    }
                }
                next = g.after + proposal.votes.len() as u64;
                more = next < len as u64;
                proposal.result.clear();
                proposal.criteria.clear();
                proposal.voters.clear();
            }
        }
        Section::Criteria => {
            p.proposal = None;
            if let Some(criteria) = acceptance {
                let offset = usize::try_from(g.after).map_err(|_| Fault::Invalid)?;
                let selected: Vec<_> = criteria.iter().skip(offset).take(3).cloned().collect();
                next = g.after + selected.len() as u64;
                more = next < criteria.len() as u64;
                p.acceptance = Some(selected);
            }
        }
        Section::Content => {
            let field = g.field.clone().ok_or(Fault::Invalid)?;
            let source = match field {
                ContentField::Purpose => &full_purpose,
                ContentField::Snapshot => snapshot.as_ref().ok_or(Fault::Invalid)?,
            };
            let offset = usize::try_from(g.after).map_err(|_| Fault::Invalid)?;
            let (text, end) = content_slice(source, offset)?;
            next = u64::try_from(end).map_err(|_| Fault::Internal)?;
            more = end < source.len();
            content = Some(ContentPage {
                field,
                offset,
                total_bytes: source.len(),
                text,
            });
            p.proposal = None;
        }
        Section::Deliveries => {
            p.proposal = None;
            let mut stmt=db.prepare("SELECT sequence,id,member,state,data FROM effects WHERE pool=?1 AND sequence>?2 ORDER BY sequence LIMIT 21")?;
            let rows = stmt.query_map(params![p.pool_id, sql_after], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })?;
            for row in rows {
                let (sequence, id, member_id, state, data) = row?;
                let sequence = u64::try_from(sequence).map_err(|_| Fault::Internal)?;
                if deliveries.len() == 20 {
                    more = true;
                    break;
                }
                let e: Effect = decode(&data)?;
                let single_batch = e.is_single_batch()?;
                let operation = match e.work {
                    Work::Deliver { .. } => "deliver",
                    Work::Retire { .. } => "retire",
                    Work::Start { .. } | Work::ResolveRun => "start",
                    Work::StartBatch { .. } if single_batch => "start",
                    Work::StartBatch { .. } => "start_batch",
                    Work::Replace { .. } => "replace",
                    Work::ReleasePin { .. } => "release_pin",
                };
                let (attention, attention_subject) = if owner {
                    crate::managed_egress::owner_attention(db, &id)?
                } else {
                    (None, None)
                };
                deliveries.push(Delivery {
                    attention,
                    attention_subject,
                    operation_id: id,
                    member_id,
                    operation: operation.into(),
                    state,
                });
                next = sequence;
            }
        }
    }
    let view = Box::new(View {
        section: g.section.clone(),
        pool: p,
        members,
        active,
        pending,
        events,
        deliveries,
        next_after: next,
        has_more: more,
        next_before,
        content,
    });
    if owner {
        Ok(Reply::OwnerView {
            view,
            bindings: private,
        })
    } else {
        Ok(Reply::View(view))
    }
}
/// Loads a pool and owner without exposing whether an inaccessible identifier exists.
pub(crate) fn pool(db: &Connection, id: &str) -> Result<(Pool, String), Fault> {
    let row: Option<(String, String)> = db
        .query_row("SELECT data,owner FROM pools WHERE id=?1", [id], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .optional()?;
    let (data, owner) = row.ok_or(Fault::Forbidden)?;
    Ok((decode(&data)?, owner))
}
/// Replaces only the bounded current pool snapshot.
pub(crate) fn save_pool(db: &Connection, p: &Pool) -> Result<(), Fault> {
    db.execute(
        "UPDATE pools SET data=?2 WHERE id=?1",
        params![p.pool_id, encode(p)?],
    )?;
    if let Some(proposal) = &p.proposal {
        let state = match proposal.state {
            ProposalState::Open => "open",
            ProposalState::Accepted => "accepted",
            ProposalState::Stale => "stale",
        };
        db.execute("INSERT INTO proposals(id,pool,state,data) VALUES(?1,?2,?3,?4) ON CONFLICT(id) DO UPDATE SET state=excluded.state,data=excluded.data WHERE proposals.state='open'",params![proposal.proposal_id,p.pool_id,state,encode(proposal)?])?;
    }
    Ok(())
}
/// Loads current members in stable slot order, preserving a replaced member's position.
pub(crate) fn bindings(db: &Connection, pool: &str) -> Result<Vec<Binding>, Fault> {
    let mut stmt = db.prepare("SELECT m.data FROM members m LEFT JOIN member_slots s ON s.member=m.id WHERE m.pool=?1 AND m.current=1 ORDER BY COALESCE(s.slot,m.id),m.id")?;
    stmt.query_map([pool], |r| r.get::<_, String>(0))?
        .map(|r| decode(&r?))
        .collect()
}
/// Loads an exact retained incarnation and whether it still has access.
pub(crate) fn binding_any(db: &Connection, id: &str) -> Result<(Binding, bool), Fault> {
    let (s, current): (String, bool) =
        db.query_row("SELECT data,current FROM members WHERE id=?1", [id], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?;
    Ok((decode(&s)?, current))
}
/// Writes private binding and indexed uniqueness columns together.
pub(crate) fn save_binding(db: &Connection, b: &Binding, current: bool) -> Result<(), Fault> {
    db.execute("INSERT INTO members(id,pool,actor,address,current,data) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(id) DO UPDATE SET actor=excluded.actor,address=excluded.address,current=excluded.current,data=excluded.data",params![b.member.member_id,b.pool_id,b.actor,b.address,current,encode(b)?])?;
    Ok(())
}
/// Builds a fresh pending incarnation without claiming the target's actor identity.
fn new_binding(p: &Pool, name: &str, role: &str, task: &str, address: Option<String>) -> Binding {
    Binding {
        member: Member {
            member_id: id(),
            name: name.into(),
            role: role.into(),
            task: task.into(),
            state: MemberState::Pending,
            runtime: "unknown".into(),
        },
        pool_id: p.pool_id.clone(),
        actor: None,
        address,
        run_id: None,
        run_sequence: None,
        run_execution_ref: None,
        run_pin_id: None,
        run_store_id: None,
    }
}
/// Keeps common views bounded while marking long purposes as previews.
fn project_purpose(pool: &mut Pool) {
    let (purpose, length) = purpose_preview(&pool.purpose);
    pool.purpose = purpose;
    pool.purpose_bytes = length;
}
/// Makes a clearly marked bounded preview without losing the retained source text.
fn purpose_preview(purpose: &str) -> (String, Option<usize>) {
    if purpose.len() <= 512 {
        return (purpose.to_owned(), None);
    }
    let mut end = 512;
    while !purpose.is_char_boundary(end) {
        end -= 1;
    }
    (format!("{}…", &purpose[..end]), Some(purpose.len()))
}
/// Returns a bounded exact slice only at valid UTF-8 byte offsets.
fn content_slice(source: &str, offset: usize) -> Result<(String, usize), Fault> {
    if offset > source.len() || !source.is_char_boundary(offset) {
        return Err(Fault::Invalid);
    }
    let mut end = (offset + MAX_TEXT).min(source.len());
    while !source.is_char_boundary(end) {
        end -= 1;
    }
    Ok((source[offset..end].to_owned(), end))
}
/// A managed replacement prepared inside the owner's authorized transaction.
struct ManagedReplacement {
    /// Frozen old source, slot, candidate and submitted spec.
    freeze: crate::managed_enrollment::ReplacementFreeze,
    /// Reserved candidate membership, not yet in the roster.
    candidate: Binding,
    /// Retained owner spec for any later replacement of the candidate.
    original: serde_json::Value,
}
/// Freezes one P3 replacement: the old member stays current; the candidate is a
/// new membership ID for a new lineage that will be conditioned on the old tip.
fn managed_replacement_freeze(
    db: &Connection,
    p: &Pool,
    roster: &[Binding],
    route: &crate::managed_enrollment::EnrollmentRoute,
    old: &Binding,
    x: &Replace,
) -> Result<ManagedReplacement, Fault> {
    let store = route.run.route.component_store_id.as_str();
    if route.status.is_none() || old.run_store_id.as_deref() != Some(store) {
        return Err(Fault::Unavailable);
    }
    let agent_id = old.run_id.as_deref().ok_or(Fault::Unavailable)?;
    let sequence = old.run_sequence.ok_or(Fault::Unavailable)?;
    let reference = old.run_execution_ref.as_deref().ok_or(Fault::Unavailable)?;
    let pin = old.run_pin_id.as_deref().ok_or(Fault::Unavailable)?;
    let sequence = u32::try_from(sequence).map_err(|_| Fault::Unavailable)?;
    if !crate::run_status::valid_agent_id(agent_id)
        || sequence == 0
        || execution_ref(reference).is_err()
        || pin_id(pin).is_err()
    {
        return Err(Fault::Unavailable);
    }
    let spec = match &x.spec {
        Some(spec) => spec.clone(),
        None => {
            let managed: Option<String> = db
                .query_row(
                    "SELECT original_spec FROM managed_enrollment_jobs WHERE member=?1",
                    [&old.member.member_id],
                    |row| row.get(0),
                )
                .optional()?;
            match managed {
                Some(original) => decode(&original)?,
                None => original_start_spec(db, &p.pool_id, &old.member.member_id, Some(store))?
                    .ok_or(Fault::Unavailable)?,
            }
        }
    };
    let candidate = new_binding(
        p,
        &old.member.name,
        &old.member.role,
        &old.member.task,
        None,
    );
    let mut next_roster = roster.to_vec();
    let position = next_roster
        .iter()
        .position(|binding| binding.member.member_id == old.member.member_id)
        .ok_or(Fault::Internal)?;
    next_roster[position] = candidate.clone();
    let intro = format!(
        "{}\nThis replacement member becomes current only after Pool verifies its qualified launch; until then pool_get and pool_join return not ready.\n",
        onboarding(p, &next_roster, &candidate.member)?
    );
    let submitted = crate::managed_enrollment::managed_spec(&spec, &route.role, &intro)?;
    let slot: String = db.query_row(
        "SELECT COALESCE((SELECT slot FROM member_slots WHERE member=?1),?1)",
        [&old.member.member_id],
        |row| row.get(0),
    )?;
    let generation: Option<Vec<u8>> = db
        .query_row(
            "SELECT generation FROM managed_bindings WHERE member=?1",
            [&old.member.member_id],
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
    Ok(ManagedReplacement {
        freeze: crate::managed_enrollment::ReplacementFreeze {
            old: old.clone(),
            generation,
            slot,
            candidate: candidate.clone(),
            target: crate::run_status::Target {
                agent_id: agent_id.to_owned(),
                sequence,
                execution_ref: reference.to_owned(),
                pin_id: pin.to_owned(),
            },
            store_id: store.to_owned(),
            submitted,
        },
        candidate,
        original: spec,
    })
}
/// Keeps roster edits from invalidating a still-recoverable group admission or replacement.
fn batch_pending(db: &Connection, pool_id: &str) -> Result<bool, Fault> {
    if crate::managed_enrollment::replacement_open(db, pool_id)? {
        return Ok(true);
    }
    let mut stmt = db.prepare("SELECT data FROM effects WHERE pool=?1 AND state IN ('queued','inflight','unknown','custody')")?;
    for row in stmt.query_map([pool_id], |r| r.get::<_, String>(0))? {
        let effect: Effect = decode(&row?)?;
        if matches!(effect.work, Work::Replace { .. })
            || matches!(effect.work, Work::StartBatch { .. }) && !effect.is_single_batch()?
        {
            return Ok(true);
        }
    }
    Ok(false)
}
/// An admission that can still change the roster prevents the completion CAS.
pub(crate) fn completion_admission_pending(db: &Connection, pool_id: &str) -> Result<bool, Fault> {
    if crate::managed_enrollment::admission_open(db, pool_id)? {
        return Ok(true);
    }
    let mut stmt = db.prepare("SELECT data FROM effects WHERE pool=?1 AND state IN ('queued','inflight','unknown','custody')")?;
    for row in stmt.query_map([pool_id], |r| r.get::<_, String>(0))? {
        let effect: Effect = decode(&row?)?;
        if matches!(
            effect.work,
            Work::Start { .. } | Work::StartBatch { .. } | Work::Replace { .. }
        ) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Terminal effect state for a Run admission that arrived after pool completion.
const RECONCILIATION_NEEDED: &str = "reconciliation_needed";

/// Resolves an admission receipt that arrived after completion without changing
/// the pool. The exact receipt is retained, the effect becomes terminal
/// `reconciliation_needed` (never redelivered) and one owner notice is queued.
/// An identical replay is harmless; a different receipt for the same effect
/// conflicts. An effect that already reached another terminal state keeps it and
/// is refused as `closed`; the caller commits the notice either way.
fn completed_admission(
    db: &Connection,
    effect: &Effect,
    receipt: &serde_json::Value,
) -> Result<Admitted, Fault> {
    let receipt = serde_json::to_string(receipt).map_err(|_| Fault::Internal)?;
    if effect.state == RECONCILIATION_NEEDED {
        let retained: String = db.query_row(
            "SELECT receipt FROM completed_admissions WHERE effect=?1",
            [&effect.effect_id],
            |r| r.get(0),
        )?;
        return if retained == receipt {
            Ok(Admitted::ReconciliationNeeded)
        } else {
            Err(Fault::Conflict)
        };
    }
    completed_admission_notice(db, effect)?;
    if matches!(effect.state.as_str(), "accepted" | "refused" | "cancelled") {
        return Err(Fault::Closed);
    }
    db.execute(
        "INSERT INTO completed_admissions(effect,receipt) VALUES(?1,?2)",
        params![effect.effect_id, receipt],
    )?;
    let mut settled = effect.clone();
    settled.state = RECONCILIATION_NEEDED.into();
    if let Work::Replace {
        claim, send_first, ..
    } = &mut settled.work
    {
        *claim = None;
        *send_first = None;
    }
    db.execute(
        "UPDATE effects SET state=?2,data=?3 WHERE id=?1",
        params![settled.effect_id, settled.state, encode(&settled)?],
    )?;
    Ok(Admitted::ReconciliationNeeded)
}

/// Canonical retained form of one verified batch or replacement Run receipt.
fn admission_receipt(
    kind: &str,
    store_id: Option<&str>,
    admissions: &[(String, u64, String, Option<String>)],
) -> serde_json::Value {
    serde_json::json!({
        "kind": kind,
        "store_id": store_id,
        "admissions": admissions
            .iter()
            .map(|(agent_id, sequence, execution_ref, pin_id)| serde_json::json!({
                "agent_id": agent_id,
                "sequence": sequence,
                "execution_ref": execution_ref,
                "pin_id": pin_id,
            }))
            .collect::<Vec<_>>(),
    })
}

/// Commits a completed-pool admission outcome together with its owner notice.
/// A `closed` refusal of an already terminal effect still commits the
/// deduplicated notice; any other failure rolls the transaction back.
fn completed_commit(
    tx: rusqlite::Transaction<'_>,
    settle: impl FnOnce(&Connection) -> Result<Admitted, Fault>,
) -> Result<Admitted, Fault> {
    let result = settle(&tx);
    if matches!(result, Ok(_) | Err(Fault::Closed)) {
        tx.commit()?;
    }
    result
}

/// Preserve the external admission evidence and alert the owner without changing a completed pool.
fn completed_admission_notice(db: &Connection, effect: &Effect) -> Result<(), Fault> {
    if db.execute(
        "INSERT OR IGNORE INTO alerts(effect,kind) VALUES(?1,'completed_admission')",
        [&effect.effect_id],
    )? != 0
    {
        let (_, owner) = pool(db, &effect.pool_id)?;
        let address = owner_address(db, &owner)?;
        queue(
            db,
            &effect.pool_id,
            None,
            Work::Deliver {
                address,
                scope: format!("owner:{}", effect.pool_id),
                text: format!(
                    "Pool {} is completed; admission {} needs owner reconciliation and was not installed.",
                    effect.pool_id, effect.effect_id
                ),
            },
        )?;
    }
    Ok(())
}
/// Prevents decisions and enrollment from changing the frozen replacement roster.
fn replacement_pending(db: &Connection, pool_id: &str) -> Result<bool, Fault> {
    if crate::managed_enrollment::replacement_open(db, pool_id)? {
        return Ok(true);
    }
    let mut stmt = db.prepare("SELECT data FROM effects WHERE pool=?1 AND state IN ('queued','inflight','unknown','custody')")?;
    for row in stmt.query_map([pool_id], |row| row.get::<_, String>(0))? {
        let effect: Effect = decode(&row?)?;
        if matches!(effect.work, Work::Replace { .. }) {
            return Ok(true);
        }
    }
    Ok(false)
}
/// Cancels an exact replacement only before any claim or possible Run admission.
fn cancel_unsubmitted_replacement(
    db: &Connection,
    pool_id: &str,
    effect_id: &str,
) -> Result<String, Fault> {
    let belongs: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM effects WHERE id=?1 AND pool=?2)",
        params![effect_id, pool_id],
        |row| row.get(0),
    )?;
    if !belongs {
        return Err(Fault::Forbidden);
    }
    let mut effect = effect(db, effect_id)?;
    if effect.pool_id != pool_id {
        return Err(Fault::Forbidden);
    }
    let Work::Replace {
        old,
        submitted: false,
        claim: None,
        send_first: None,
        ..
    } = &effect.work
    else {
        return Err(Fault::Conflict);
    };
    if !matches!(effect.state.as_str(), "queued" | "inflight" | "unknown")
        || effect.member_id.as_deref() != Some(old.member.member_id.as_str())
    {
        return Err(Fault::Conflict);
    }
    let member = old.member.member_id.clone();
    let (binding, current) = binding_any(db, &member)?;
    if !current || binding.pool_id != pool_id {
        return Err(Fault::Stale);
    }
    effect.state = "cancelled".into();
    if db.execute(
        "UPDATE effects SET state='cancelled',data=?2 WHERE id=?1",
        params![effect_id, encode(&effect)?],
    )? != 1
    {
        return Err(Fault::Conflict);
    }
    Ok(member)
}
/// Rechecks the frozen source and destination before any replacement network or local commit.
fn validate_replacement_source(db: &Connection, effect: &Effect) -> Result<(), Fault> {
    let Work::Replace {
        old,
        new,
        job,
        route,
        ..
    } = &effect.work
    else {
        return Err(Fault::Invalid);
    };
    let (mut current, active) = binding_any(db, &old.member.member_id)?;
    current.member.runtime = old.member.runtime.clone();
    if !active
        || current != **old
        || pool(db, &effect.pool_id)?.0.closed
        || old.pool_id != effect.pool_id
        || new.pool_id != effect.pool_id
        || effect.member_id.as_deref() != Some(old.member.member_id.as_str())
        || new.member.member_id == old.member.member_id
        || job.member_id != new.member.member_id
        || new.member.name != old.member.name
        || new.member.role != old.member.role
        || new.member.task != old.member.task
        || new.member.state != MemberState::Pending
        || new.actor.is_some()
        || new.address.is_some()
        || new.run_id.is_some()
        || new.run_sequence.is_some()
        || new.run_execution_ref.is_some()
        || new.run_pin_id.is_some()
        || new.run_store_id.is_some()
    {
        return Err(Fault::Stale);
    }
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM members WHERE id=?1)",
        [&new.member.member_id],
        |row| row.get(0),
    )?;
    if exists
        || pin_origin_route(
            db,
            &effect.pool_id,
            &old.member.member_id,
            old.run_store_id.as_deref(),
        )?
        .as_ref()
            != Some(route)
    {
        return Err(Fault::Stale);
    }
    validate_original_spec(job.original_spec.as_ref())?;
    if job.original_spec.is_none() {
        return Err(Fault::Unavailable);
    }
    Ok(())
}
/// Prevents a second release intent for the same exact pin under a different request key.
fn pin_release_exists(
    db: &Connection,
    pool_id: &str,
    member_id: &str,
    pin: &str,
) -> Result<bool, Fault> {
    let mut stmt = db.prepare("SELECT data FROM effects WHERE pool=?1 AND member=?2")?;
    for row in stmt.query_map(params![pool_id, member_id], |row| row.get::<_, String>(0))? {
        let effect: Effect = decode(&row?)?;
        if matches!(&effect.work, Work::ReleasePin { pin_id, .. } if pin_id == pin) {
            return Ok(true);
        }
    }
    Ok(false)
}
/// Resolves a member's unique accepted store-fenced admission route, or keeps legacy data unknown.
fn pin_origin_route(
    db: &Connection,
    pool_id: &str,
    member_id: &str,
    store: Option<&str>,
) -> Result<Option<RunRoute>, Fault> {
    let Some(store) = store else { return Ok(None) };
    store_id(store)?;
    let mut stmt = db.prepare("SELECT data FROM effects WHERE pool=?1 AND state='accepted'")?;
    let mut found = None;
    let mut seen = false;
    for row in stmt.query_map([pool_id], |row| row.get::<_, String>(0))? {
        let effect: Effect = decode(&row?)?;
        effect.is_single_batch()?;
        match effect.work {
            Work::StartBatch {
                jobs,
                store_fence,
                route,
                ..
            } => {
                let matches = jobs.iter().filter(|job| job.member_id == member_id).count();
                if matches == 0 {
                    continue;
                }
                if seen || matches != 1 {
                    return Err(Fault::Conflict);
                }
                seen = true;
                found =
                    route.filter(|route| store_fence && route.store_id.as_deref() == Some(store));
            }
            Work::Start { .. } if effect.member_id.as_deref() == Some(member_id) => {
                if seen {
                    return Err(Fault::Conflict);
                }
                seen = true;
            }
            Work::Replace {
                old,
                new,
                job,
                route,
                ..
            } if new.member.member_id == member_id => {
                if seen
                    || new.pool_id != pool_id
                    || job.member_id != member_id
                    || effect.member_id.as_deref() != Some(old.member.member_id.as_str())
                {
                    return Err(Fault::Conflict);
                }
                seen = true;
                found = (route.store_id.as_deref() == Some(store)).then_some(route);
            }
            _ => {}
        }
    }
    Ok(found)
}
/// Finds one accepted origin's original spec without inferring missing legacy data.
/// The caller must independently verify the current binding and Run preconditions.
fn original_start_spec(
    db: &Connection,
    pool_id: &str,
    member_id: &str,
    store: Option<&str>,
) -> Result<Option<serde_json::Value>, Fault> {
    let Some(expected_store) = store else {
        return Ok(None);
    };
    store_id(expected_store)?;
    let mut stmt = db.prepare("SELECT data FROM effects WHERE pool=?1 AND state='accepted'")?;
    let mut found: Option<Option<serde_json::Value>> = None;
    for row in stmt.query_map([pool_id], |row| row.get::<_, String>(0))? {
        let effect: Effect = decode(&row?)?;
        effect.is_single_batch()?;
        match effect.work {
            Work::StartBatch {
                jobs,
                store_fence,
                route,
                ..
            } => {
                for job in jobs.into_iter().filter(|job| job.member_id == member_id) {
                    if found.is_some()
                        || !store_fence
                        || route.as_ref().and_then(|route| route.store_id.as_deref())
                            != Some(expected_store)
                    {
                        return Err(Fault::Conflict);
                    }
                    validate_original_spec(job.original_spec.as_ref())?;
                    found = Some(job.original_spec);
                }
            }
            Work::Start { .. } if effect.member_id.as_deref() == Some(member_id) => {
                if found.is_some() {
                    return Err(Fault::Conflict);
                }
                found = Some(None);
            }
            Work::Replace {
                old,
                new,
                job,
                route,
                ..
            } if new.member.member_id == member_id => {
                if found.is_some()
                    || new.pool_id != pool_id
                    || job.member_id != member_id
                    || effect.member_id.as_deref() != Some(old.member.member_id.as_str())
                    || route.store_id.as_deref() != Some(expected_store)
                {
                    return Err(Fault::Conflict);
                }
                validate_original_spec(job.original_spec.as_ref())?;
                found = Some(job.original_spec);
            }
            _ => {}
        }
    }
    Ok(found.flatten())
}
/// Rejects malformed original specifications without reconstructing enriched prompts.
fn validate_original_spec(spec: Option<&serde_json::Value>) -> Result<(), Fault> {
    if let Some(spec) = spec
        && (!spec.is_object()
            || spec.get("request_id").is_some()
            || spec.get("orchestrator").is_some()
            || spec
                .get("task")
                .and_then(serde_json::Value::as_str)
                .is_none()
            || serde_json::to_vec(spec).map_err(|_| Fault::Invalid)?.len() > 65536)
    {
        return Err(Fault::Invalid);
    }
    Ok(())
}
/// Prevents a malformed Run receipt from assigning one durable pin to different memberships.
fn pin_owned_by_other_member(db: &Connection, pin: &str, member_id: &str) -> Result<bool, Fault> {
    let mut stmt =
        db.prepare("SELECT data FROM members WHERE id<>?1 AND data LIKE '%\"run_pin_id\"%'")?;
    for row in stmt.query_map([member_id], |row| row.get::<_, String>(0))? {
        let binding: Binding = decode(&row?)?;
        if binding.run_pin_id.as_deref() == Some(pin) {
            return Ok(true);
        }
    }
    Ok(false)
}
/// Prevents a replacement receipt from aliasing an existing execution in the same Run store.
fn run_execution_owned_by_other_member(
    db: &Connection,
    store: &str,
    agent: &str,
    reference: &str,
    member_id: &str,
) -> Result<bool, Fault> {
    let mut stmt =
        db.prepare("SELECT data FROM members WHERE id<>?1 AND data LIKE '%\"run_store_id\"%'")?;
    for row in stmt.query_map([member_id], |row| row.get::<_, String>(0))? {
        let binding: Binding = decode(&row?)?;
        if binding.run_store_id.as_deref() == Some(store)
            && (binding.run_id.as_deref() == Some(agent)
                || binding.run_execution_ref.as_deref() == Some(reference))
        {
            return Ok(true);
        }
    }
    Ok(false)
}
/// Rejects enriched admission frames that cannot fit the bounded Run transport.
fn validate_batch_frame(request_key: &str, jobs: &[BatchJob]) -> Result<(), Fault> {
    let specs: Vec<_> = jobs.iter().map(|job| &job.spec).collect();
    let request = serde_json::json!({"jsonrpc":"2.0","id":i64::MAX,"method":"start_batch","params":{"request_id":request_key,"jobs":specs,"retain_history":true,"expected_store_id":format!("store_{}", "f".repeat(32))}});
    if serde_json::to_vec(&request)
        .map_err(|_| Fault::Invalid)?
        .len()
        + 1
        > crate::integrations::MAX_FRAME
    {
        return Err(Fault::Invalid);
    }
    Ok(())
}
/// Bounds the complete replacement request, including its largest possible execution sequence.
fn validate_replacement_frame(
    request_key: &str,
    job: &BatchJob,
    old: &Binding,
) -> Result<(), Fault> {
    let request = serde_json::json!({
        "jsonrpc":"2.0", "id":i64::MAX, "method":"start_batch", "params":{
            "request_id":request_key, "jobs":[job.spec], "retain_history":true,
            "expected_store_id":old.run_store_id, "preconditions":[{
                "agent_id":old.run_id, "sequence":u32::MAX,
                "execution_ref":old.run_execution_ref, "pin_id":old.run_pin_id
            }]
        }
    });
    if serde_json::to_vec(&request)
        .map_err(|_| Fault::Invalid)?
        .len()
        + 1
        > crate::integrations::MAX_FRAME
    {
        return Err(Fault::Invalid);
    }
    Ok(())
}
/// Freezes onboarding and required Pool tools into one ordinary Run request before admission.
fn prepare_start(mut spec: serde_json::Value, intro: &str) -> Result<serde_json::Value, Fault> {
    let obj = spec.as_object_mut().ok_or(Fault::Invalid)?;
    let prompt = obj
        .get("task")
        .and_then(serde_json::Value::as_str)
        .ok_or(Fault::Invalid)?;
    obj.insert(
        "task".into(),
        serde_json::Value::String(format!("{prompt}\n\n{intro}")),
    );
    let required = obj
        .entry("required_mcp")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .ok_or(Fault::Invalid)?;
    let tools = required
        .entry("agent-pool")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut()
        .ok_or(Fault::Invalid)?;
    for name in [
        "pool_join",
        "pool_get",
        "pool_post",
        "pool_send_member",
        "pool_notify_owner",
        "pool_propose",
        "pool_vote",
        "pool_remove",
    ] {
        let value = serde_json::Value::String(name.into());
        if !tools.contains(&value) {
            tools.push(value);
        }
    }
    Ok(spec)
}
/// Detects permanent leader status by verified actor or canonical address.
fn leader(db: &Connection, a: &Actor) -> Result<bool, Fault> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM leaders WHERE actor=?1 OR address=?2)",
        params![a.key, a.address],
        |r| r.get(0),
    )?)
}
/// Rejects any leader address or current reservation, except the same binding being finalized.
fn reserve(db: &Connection, address: &str, except: Option<&str>) -> Result<(), Fault> {
    let busy:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM leaders WHERE address=?1) OR EXISTS(SELECT 1 FROM members WHERE current=1 AND address=?1 AND id<>?2)",params![address,except.unwrap_or("")],|r|r.get(0))?;
    if busy { Err(Fault::Conflict) } else { Ok(()) }
}
/// Resolves an owner privately for the explicit notification and failure-only paths.
fn owner_address(db: &Connection, owner: &str) -> Result<String, Fault> {
    Ok(
        db.query_row("SELECT address FROM leaders WHERE actor=?1", [owner], |r| {
            r.get(0)
        })?,
    )
}
/// Makes only an unfinished proposal stale; accepted results remain immutable.
pub(crate) fn stale(p: &mut Pool) {
    if let Some(x) = p.proposal.as_mut()
        && x.state == ProposalState::Open
    {
        x.state = ProposalState::Stale;
    }
}
/// Retires access and locally queued work without claiming recall of inflight provider effects.
pub(crate) fn remove_binding(db: &Connection, b: &Binding, p: &Pool) -> Result<(), Fault> {
    save_binding(db, b, false)?;
    // A removed P3 enrollee keeps its admitted root and pin as unassigned or
    // retired history; it is never bound or activated afterwards.
    db.execute("UPDATE managed_enrollment_jobs SET state='retired' WHERE member=?1 AND state IN ('bound_pending_join','active')",[&b.member.member_id])?;
    db.execute("UPDATE managed_enrollment_jobs SET state='unassigned',attention='member_removed' WHERE member=?1 AND state='admitted'",[&b.member.member_id])?;
    db.execute(
        "UPDATE effects SET state='cancelled' WHERE member=?1 AND state IN ('queued','awaiting_binding')",
        [&b.member.member_id],
    )?;
    // Managed scopes use the B2 namespace. A legacy fence is needed only for
    // legacy members or when this member actually has a frozen legacy send.
    let has_legacy_publication: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM publications p JOIN effects e ON e.id=p.effect WHERE e.member=?1)",
        [&b.member.member_id],
        |row| row.get(0),
    )?;
    if b.run_id.is_none() || has_legacy_publication {
        queue(
            db,
            &p.pool_id,
            Some(&b.member.member_id),
            Work::Retire {
                scope: scope(&b.member.member_id),
            },
        )?;
    }
    crate::managed_egress::retire_member_scope(db, &p.pool_id, &b.member.member_id)?;
    Ok(())
}
/// P3-C commit side effects inside the caller's completion CAS transaction:
/// advance the pool revision, journal the completion and queue one owner notice.
/// Returns the notice operation ID and its exact payload; delivery is not processing.
pub(crate) fn completion_effects(
    db: &Connection,
    pool_id: &str,
    completion_id: &str,
) -> Result<(String, String), Fault> {
    let (mut p, owner) = pool(db, pool_id)?;
    p.revision = p.revision.checked_add(1).ok_or(Fault::Internal)?;
    save_pool(db, &p)?;
    append_event(
        db,
        &p,
        "pool_completed",
        Author::Service,
        format!(
            "Pool completed. Completion {completion_id}. Goal, roster, assignments, proposals and votes are now frozen; read the record with the owner completion_get operation."
        ),
        None,
    )?;
    let text = format!(
        "Pool {pool_id} completed. Completion {completion_id}. The immutable record is available to the owner; this notice is not proof of processing."
    );
    let address = owner_address(db, &owner)?;
    let effect_id = queue(
        db,
        pool_id,
        None,
        Work::Deliver {
            address,
            scope: format!("owner:{pool_id}"),
            text: text.clone(),
        },
    )?;
    Ok((effect_id, text))
}
/// Sends exactly one independent membership-ending notice, with no remaining roster or private data.
pub(crate) fn final_notice(
    db: &Connection,
    p: &Pool,
    b: &Binding,
    event_id: u64,
) -> Result<(), Fault> {
    let possible_start:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM effects WHERE member=?1 AND state IN ('inflight','unknown','custody'))",[&b.member.member_id],|r|r.get(0))?;
    if b.address.is_some() || b.run_id.is_some() || possible_start {
        let address = b.address.as_deref().unwrap_or("");
        queue_delivery(
            db,
            &p.pool_id,
            Some(&b.member.member_id),
            address,
            &format!("final:{}", b.member.member_id),
            format!(
                "Membership ended. Pool {}. Member {}. Access revoked; process not stopped.",
                p.pool_id, b.member.member_id
            ),
            Some(event_id),
        )?;
    }
    Ok(())
}
/// Stable producer-private Bridge scope for one never-reused membership incarnation.
pub(crate) fn scope(member: &str) -> String {
    format!("agent-pool:member:{member}")
}
/// Appends safe event data and returns its actual monotonic SQLite cursor.
pub(crate) fn append_event(
    db: &Connection,
    p: &Pool,
    kind: &str,
    author: Author,
    body: String,
    recipient: Option<String>,
) -> Result<Event, Fault> {
    let mut e = Event {
        event_id: 0,
        event_id_exact: None,
        revision: p.revision,
        kind: kind.into(),
        author,
        body,
        recipient,
        check: None,
        vote_event_id: None,
        message_event_id: None,
        part_index: None,
        part_count: None,
    };
    db.execute(
        "INSERT INTO events(pool,data) VALUES(?1,?2)",
        params![p.pool_id, encode(&e)?],
    )?;
    e.event_id = db.last_insert_rowid() as u64;
    Ok(e)
}
/// Splits long messages at UTF-8 boundaries without changing or discarding bytes.
fn first_message_part(body: &str, rest: &mut Vec<String>) -> String {
    let mut end = MAX_TEXT.min(body.len());
    while !body.is_char_boundary(end) {
        end -= 1;
    }
    let first = body[..end].to_owned();
    let mut start = end;
    while start < body.len() {
        let mut end = (start + MAX_TEXT).min(body.len());
        while !body.is_char_boundary(end) {
            end -= 1;
        }
        rest.push(body[start..end].to_owned());
        start = end;
    }
    first
}
/// Appends all remaining parts and their exact parent identity in the same transaction.
fn append_message_parts(
    db: &Connection,
    p: &Pool,
    event: &mut Event,
    parts: &[String],
) -> Result<(), Fault> {
    let message_id = event.event_id.to_string();
    let count = parts.len() + 1;
    event.message_event_id = Some(message_id.clone());
    event.part_index = Some(1);
    event.part_count = Some(count);
    let mut stored = event.clone();
    stored.event_id = 0;
    if db.execute(
        "UPDATE events SET data=?2 WHERE id=?1 AND pool=?3",
        params![
            i64::try_from(event.event_id).map_err(|_| Fault::Internal)?,
            encode(&stored)?,
            p.pool_id
        ],
    )? != 1
    {
        return Err(Fault::Internal);
    }
    for (index, body) in parts.iter().enumerate() {
        let part = Event {
            event_id: 0,
            event_id_exact: None,
            revision: p.revision,
            kind: "message_part".into(),
            author: event.author.clone(),
            body: body.clone(),
            recipient: event.recipient.clone(),
            check: None,
            vote_event_id: None,
            message_event_id: Some(message_id.clone()),
            part_index: Some(index + 2),
            part_count: Some(count),
        };
        db.execute(
            "INSERT INTO events(pool,data) VALUES(?1,?2)",
            params![p.pool_id, encode(&part)?],
        )?;
    }
    Ok(())
}
/// Appends one bounded, typed check directly after its owning vote in the same transaction.
fn append_check(
    db: &Connection,
    p: &Pool,
    author: Author,
    vote_id: u64,
    check: &CriterionCheck,
) -> Result<(), Fault> {
    let e = Event {
        event_id: 0,
        event_id_exact: None,
        revision: p.revision,
        kind: "vote_check".into(),
        author,
        body: format!(
            "Vote {vote_id}; criterion {}: {:?}.\n{}",
            check.criterion_id, check.status, check.evidence
        ),
        recipient: None,
        check: Some(Box::new(check.clone())),
        vote_event_id: Some(vote_id.to_string()),
        message_event_id: None,
        part_index: None,
        part_count: None,
    };
    db.execute(
        "INSERT INTO events(pool,data) VALUES(?1,?2)",
        params![p.pool_id, encode(&e)?],
    )?;
    Ok(())
}
/// Enqueues one immutable provider intent within the surrounding business transaction.
fn queue(db: &Connection, pool: &str, member: Option<&str>, work: Work) -> Result<String, Fault> {
    let state = if matches!(&work,Work::Deliver{address,..}if address.is_empty()) {
        "awaiting_binding"
    } else if matches!(&work, Work::ResolveRun) {
        "custody"
    } else {
        "queued"
    };
    let e = Effect {
        effect_id: id(),
        pool_id: pool.into(),
        member_id: member.map(str::to_owned),
        work,
        state: state.into(),
    };
    db.execute(
        "INSERT INTO effects(id,pool,member,state,data) VALUES(?1,?2,?3,?4,?5)",
        params![e.effect_id, pool, member, state, encode(&e)?],
    )?;
    Ok(e.effect_id)
}
/// Enqueues a bounded exact payload; over-budget output aborts the entire originating transaction.
pub(crate) fn queue_delivery(
    db: &Connection,
    pool: &str,
    member: Option<&str>,
    address: &str,
    scope: &str,
    text: String,
    event_id: Option<u64>,
) -> Result<(), Fault> {
    if text.len() > 16384 {
        return Err(Fault::Invalid);
    }
    let effect_id = queue(
        db,
        pool,
        member,
        Work::Deliver {
            address: address.into(),
            scope: scope.into(),
            text,
        },
    )?;
    if let (Some(member), Some(event_id)) = (member, event_id) {
        let binding = binding_any(db, member)?.0;
        if binding.run_id.is_some() || binding.address.is_none() {
            crate::managed_egress::insert_seed(
                db,
                &effect_id,
                pool,
                member,
                event_id,
                scope.starts_with("final:"),
            )?;
        }
    }
    Ok(())
}
/// Sends safe system/message events to current members, excluding the caller's redundant wakeup.
pub(crate) fn system_deliveries(
    db: &Connection,
    p: &Pool,
    e: &Event,
    roster: &[Binding],
    skip: Option<&str>,
) -> Result<(), Fault> {
    let text = notification(p, roster, e)?;
    for b in roster {
        if skip == Some(b.member.member_id.as_str()) {
            continue;
        }
        {
            let address = b.address.as_deref().unwrap_or("");
            queue_delivery(
                db,
                &p.pool_id,
                Some(&b.member.member_id),
                address,
                &scope(&b.member.member_id),
                text.clone(),
                Some(e.event_id),
            )?;
        }
    }
    Ok(())
}
/// Builds a bounded safe roster summary; complete tasks are available through paged pool_get.
fn roster_text(roster: &[Binding]) -> String {
    let mut out = String::from(
        "Brief roster; abbreviated labels/tasks have …; full assignments: pool_get section=members.\n",
    );
    for b in roster {
        out.push_str(&format!(
            "{} | {} | role={} | task={} | {:?}\n",
            b.member.member_id,
            brief(&b.member.name, 24),
            brief(&b.member.role, 40),
            brief(&b.member.task, 48),
            b.member.state
        ));
    }
    out
}
/// Quotes a descriptive notification preview on a UTF-8 boundary; exact content stays retrievable.
fn brief(s: &str, limit: usize) -> String {
    let mut end = s.len().min(limit);
    while !s.is_char_boundary(end) {
        end -= 1
    }
    let value = if end < s.len() {
        format!("{}…", &s[..end])
    } else {
        s.into()
    };
    serde_json::to_string(&value).unwrap_or_else(|_| String::from("\"unavailable\""))
}
/// Produces a safe notification with the current roster and version; never includes private bindings.
fn notification(p: &Pool, roster: &[Binding], e: &Event) -> Result<String, Fault> {
    let active = roster
        .iter()
        .filter(|b| b.member.state == MemberState::Active)
        .count();
    let body = encode(&e.body)?;
    let parts = e.part_count.map_or_else(String::new, |count| {
        format!(
            "Message {} part 1/{count}; read the following history parts for the full text.\n",
            e.event_id
        )
    });
    let text = format!(
        "Pool {} revision {}. Event {}: {}\nBody: {}\n{parts}Confirmed {}; pending {}.\n{}Use pool_get for current details; older events never replace newer state.",
        p.pool_id,
        p.revision,
        e.event_id,
        e.kind,
        body,
        active,
        roster.len() - active,
        roster_text(roster)
    );
    if text.len() > 16384 {
        Err(Fault::Invalid)
    } else {
        Ok(text)
    }
}
/// Creates mandatory onboarding with communication rules and a version-specific join instruction.
pub(crate) fn onboarding(p: &Pool, roster: &[Binding], member: &Member) -> Result<String, Fault> {
    let (preview, length) = purpose_preview(&p.purpose);
    let purpose = if length.is_some() {
        format!("{preview} (full purpose: pool_get section=content field=purpose)")
    } else {
        preview
    };
    let criteria = if p.acceptance.is_some() {
        "Structured acceptance is enabled: read pool_get section=criteria; ready votes must check every criterion. "
    } else {
        ""
    };
    let text = format!(
        "Agent Pool onboarding\nPool {}: {}\nPurpose: {}\nYour member_id: {}\nRole: {}\nTask: {}\nCurrent revision: {}\n{}\nLeader is external and is not a member or voter. pool_post reaches members only; pool_send_member reaches one current peer; pool_notify_owner reaches the hidden owner. All messages share history. Use local member IDs only. Read pool_get then confirm the current revision with pool_join. {criteria}Pending members cannot vote. Removed membership loses access. Completion or consensus does not close the pool. Separate Bridge remains independent.\n",
        p.pool_id,
        p.name,
        purpose,
        member.member_id,
        member.role,
        member.task,
        p.revision,
        roster_text(roster)
    );
    if text.len() > 16384 {
        Err(Fault::Invalid)
    } else {
        Ok(text)
    }
}
/// Records a delivery failure and separately wakes the external owner with a safe intervention request.
fn failure_event(
    db: &Connection,
    pool_id: &str,
    member: Option<&str>,
    notify_owner: bool,
    body: &str,
) -> Result<(), Fault> {
    let before: i64 = db.query_row("SELECT COALESCE(MAX(sequence),0) FROM effects", [], |r| {
        r.get(0)
    })?;
    let (mut p, owner) = pool(db, pool_id)?;
    p.revision += 1;
    save_pool(db, &p)?;
    let e = append_event(
        db,
        &p,
        "delivery_failed",
        Author::Service,
        body.into(),
        member.map(str::to_owned),
    )?;
    let roster = bindings(db, pool_id)?;
    system_deliveries(db, &p, &e, &roster, None)?;
    if notify_owner {
        let address = owner_address(db, &owner)?;
        queue_delivery(
            db,
            pool_id,
            None,
            &address,
            &format!("owner:{pool_id}"),
            notification(&p, &roster, &e)?,
            Some(e.event_id),
        )?;
    }
    db.execute(
        "UPDATE effects SET failure_notice=1 WHERE sequence>?1",
        [before],
    )?;
    Ok(())
}
/// Loads private effect data with authoritative SQL state, including after crash recovery.
fn effect(db: &Connection, id: &str) -> Result<Effect, Fault> {
    let (data, state): (String, String) =
        db.query_row("SELECT data,state FROM effects WHERE id=?1", [id], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?;
    let mut e: Effect = decode(&data)?;
    e.state = state;
    Ok(e)
}
/// Returns an exact retained receipt or rejects idempotency-key reuse with different intent.
pub(crate) fn replay(
    db: &Connection,
    scope: &str,
    key: &str,
    digest: &str,
) -> Result<Option<Reply>, Fault> {
    let row: Option<(String, String)> = db
        .query_row(
            "SELECT digest,receipt FROM requests WHERE scope=?1 AND key=?2",
            params![scope, key],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    match row {
        None => Ok(None),
        Some((d, r)) if d == digest => Ok(Some(decode(&r)?)),
        Some(_) => Err(Fault::Conflict),
    }
}
/// Saves one complete safe receipt in the same transaction as its effect intents.
pub(crate) fn remember(
    db: &Connection,
    scope: &str,
    key: &str,
    digest: &str,
    reply: &Reply,
) -> Result<(), Fault> {
    db.execute(
        "INSERT INTO requests(scope,key,digest,receipt) VALUES(?1,?2,?3,?4)",
        params![scope, key, digest, encode(reply)?],
    )?;
    Ok(())
}
/// Encodes trusted typed durable state; serialization errors never expose source data.
fn encode<T: Serialize>(value: &T) -> Result<String, Fault> {
    serde_json::to_string(value).map_err(|_| Fault::Internal)
}
/// Decodes trusted database state; corruption is an internal error rather than an empty result.
fn decode<T: DeserializeOwned>(value: &str) -> Result<T, Fault> {
    serde_json::from_str(value).map_err(|_| Fault::Internal)
}

/// Isolated state-machine regressions; authenticated actors here are synthetic fixtures only.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "Assertions in isolated temporary SQLite fixtures"
)]
mod tests {
    use super::*;
    /// Isolated store fixture rooted exclusively in the task's approved TMPDIR.
    fn fixture() -> (tempfile::TempDir, Store) {
        let root = std::env::var_os("TMPDIR").expect("task TMPDIR required");
        let d = tempfile::tempdir_in(root).unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let s = Store::open(&d.path().join("pool.sqlite")).unwrap();
        (d, s)
    }
    /// Decode and execute an inventory request through the public owner dispatch.
    fn inventory(store: &Store, params: serde_json::Value) -> Result<serde_json::Value, Fault> {
        let request: crate::observer::Request = serde_json::from_value(serde_json::json!({
            "schema_version":1, "operation":"inventory_snapshot", "params":params
        }))
        .map_err(|_| Fault::Invalid)?;
        let data = store.observe(&request)?;
        let bytes = crate::observer::encode(&crate::observer::Envelope::success(
            "inventory_snapshot",
            data,
        ))?;
        let envelope: crate::observer::Envelope =
            serde_json::from_slice(&bytes).map_err(|_| Fault::Internal)?;
        serde_json::to_value(envelope).map_err(|_| Fault::Internal)
    }
    /// The source-wide counts, filter, complete roster, closure and empty terminal page are independent.
    #[test]
    fn inventory_empty_closed_and_roster() {
        use serde_json::json;
        let (_dir, mut store) = fixture();
        let empty = inventory(&store, json!({"filter":"all","limit":1})).unwrap();
        assert_eq!(
            empty["data"]["totals"],
            json!({"total":"0","open":"0","completed":"0","unknown":"0","closed":"0"})
        );
        assert_eq!(empty["data"]["returned"], 0);
        assert_eq!(empty["data"]["has_more"], false);
        assert!(empty["data"]["next_cursor"].is_null());
        let owner = actor("inventory-owner");
        let member = actor("inventory-member");
        let closed = make(&mut store, &owner, "closed");
        let change = change(&store, &closed);
        store.execute(&owner, &Command::Close(change)).unwrap();
        let other = make(&mut store, &owner, "other");
        let member_id = add(&mut store, &owner, &other, &member);
        let page = inventory(&store, json!({"filter":"closed","limit":10})).unwrap();
        assert_eq!(
            page["data"]["totals"],
            json!({"total":"2","open":"2","completed":"0","unknown":"0","closed":"1"})
        );
        assert_eq!(page["data"]["returned"], 1);
        assert_eq!(page["data"]["pools"][0]["pool"]["closed"], true);
        assert_eq!(page["data"]["pools"][0]["roster"], json!([]));
        let page = inventory(&store, json!({"filter":"not_closed","limit":10})).unwrap();
        assert_eq!(
            page["data"]["pools"][0]["roster"][0]["member_id"],
            member_id
        );
        assert_eq!(page["data"]["pools"][0]["leader_id"], owner.key);
        assert!(
            page["data"]["pools"][0]["roster"][0]
                .get("address")
                .is_none()
        );
        assert!(page["data"]["next_cursor"].is_null());
    }
    /// Any source write, epoch change, selector change or invalid boundary refuses continuation.
    #[test]
    fn inventory_cursor_fences_source_and_selection() {
        use serde_json::json;
        let (dir, mut store) = fixture();
        let owner = actor("cursor-owner");
        make(&mut store, &owner, "one");
        make(&mut store, &owner, "two");
        let first = inventory(&store, json!({"filter":"all","limit":1})).unwrap();
        let cursor = first["data"]["next_cursor"].clone();
        assert!(cursor.is_object());
        let second = inventory(&store, json!({"filter":"all","limit":1,"cursor":cursor})).unwrap();
        assert_eq!(second["data"]["returned"], 1);
        assert_eq!(second["data"]["has_more"], false);
        assert!(second["data"]["next_cursor"].is_null());
        for key in ["store_id", "read_epoch", "revision"] {
            let mut changed = cursor.clone();
            changed["source"][key] = json!("different");
            assert_eq!(
                inventory(&store, json!({"filter":"all","limit":1,"cursor":changed})).err(),
                Some(Fault::Stale)
            );
        }
        assert_eq!(
            inventory(&store, json!({"filter":"closed","limit":1,"cursor":cursor})).err(),
            Some(Fault::Stale)
        );
        assert_eq!(
            inventory(&store, json!({"filter":"all","limit":2,"cursor":cursor})).err(),
            Some(Fault::Stale)
        );
        let mut missing = cursor.clone();
        missing["after"] = json!("absent");
        assert_eq!(
            inventory(&store, json!({"filter":"all","limit":1,"cursor":missing})).err(),
            Some(Fault::Stale)
        );
        // A private table update also advances the source fence even when rows are unchanged.
        assert_eq!(store.db.execute("UPDATE requests SET digest=digest WHERE rowid=(SELECT min(rowid) FROM requests)", []).unwrap(), 1);
        assert_eq!(
            inventory(&store, json!({"filter":"all","limit":1,"cursor":cursor})).err(),
            Some(Fault::Stale)
        );
        let new_first = inventory(&store, json!({"filter":"all","limit":1})).unwrap();
        let new_cursor = new_first["data"]["next_cursor"].clone();
        drop(store);
        let reopened = Store::open(&dir.path().join("pool.sqlite")).unwrap();
        assert_eq!(
            inventory(
                &reopened,
                json!({"filter":"all","limit":1,"cursor":new_cursor})
            )
            .err(),
            Some(Fault::Stale)
        );
        let after = inventory(&reopened, json!({"filter":"all","limit":1})).unwrap();
        assert_eq!(
            new_first["data"]["source"]["store_id"],
            after["data"]["source"]["store_id"]
        );
        assert_ne!(
            new_first["data"]["source"]["read_epoch"],
            after["data"]["source"]["read_epoch"]
        );
    }
    /// A writer committing after the first SELECT cannot mix newer pool data with older totals/revision.
    #[test]
    fn inventory_snapshot_consistent_with_concurrent_commit() {
        use crate::observer::{Data, InventoryFilter, InventoryRequest};
        let (dir, mut store) = fixture();
        let owner = actor("snapshot-owner");
        let pool_id = make(&mut store, &owner, "one");
        let writer = Connection::open(dir.path().join("pool.sqlite")).unwrap();
        let args = InventoryRequest {
            filter: InventoryFilter::All,
            limit: 10,
            cursor: None,
        };
        let result = inventory_snapshot_inner(&store.db, &store.read_epoch, &args, || {
            let (mut changed, _) = pool(&writer, &pool_id)?;
            changed.closed = true;
            save_pool(&writer, &changed)?;
            Ok(())
        })
        .unwrap();
        let Data::Inventory(page) = result else {
            panic!("inventory")
        };
        assert_eq!(page.totals.closed, "0");
        assert!(!page.pools[0].pool.closed);
        let current = inventory(&store, serde_json::json!({"filter":"all","limit":10})).unwrap();
        assert_eq!(current["data"]["totals"]["closed"], "1");
        assert_eq!(current["data"]["pools"][0]["pool"]["closed"], true);
        assert_ne!(current["data"]["source"]["revision"], page.source.revision);
    }
    /// The entire maximum roster is returned in slot order; corrupt over-capacity data refuses.
    #[test]
    fn inventory_full_roster_and_capacity_overflow() {
        use serde_json::json;
        let (_dir, mut store) = fixture();
        let owner = actor("roster-owner");
        let pid = make(&mut store, &owner, "roster");
        let mut expected = Vec::new();
        for index in 0..20 {
            expected.push(add(
                &mut store,
                &owner,
                &pid,
                &actor(&format!("roster-{index}")),
            ));
        }
        expected.sort();
        let page = inventory(&store, json!({"filter":"all","limit":1})).unwrap();
        let ids: Vec<_> = page["data"]["pools"][0]["roster"]
            .as_array()
            .unwrap()
            .iter()
            .map(|member| member["member_id"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(ids, expected);
        let (pool, _) = pool(&store.db, &pid).unwrap();
        let extra = new_binding(&pool, "extra", "extra", "extra", None);
        save_binding(&store.db, &extra, true).unwrap();
        assert_eq!(
            inventory(&store, json!({"filter":"all","limit":1})).err(),
            Some(Fault::Unavailable)
        );
    }
    /// Oversized envelopes and a revision counter overflow fail atomically instead of truncating.
    #[test]
    fn inventory_overflow_refuses_without_partial_result() {
        let (_dir, mut store) = fixture();
        let owner = actor("overflow-owner");
        let pid = make(&mut store, &owner, "one");
        let (mut p, _) = pool(&store.db, &pid).unwrap();
        p.name = "x".repeat(crate::integrations::MAX_FRAME);
        save_pool(&store.db, &p).unwrap();
        assert_eq!(
            inventory(&store, serde_json::json!({"filter":"all","limit":1})).err(),
            Some(Fault::Unavailable)
        );
        store
            .db
            .execute("UPDATE inventory_source SET revision=?1", [i64::MAX])
            .unwrap();
        p.name = "small".into();
        assert!(save_pool(&store.db, &p).is_err());
        assert_eq!(
            pool(&store.db, &pid).unwrap().0.name.len(),
            crate::integrations::MAX_FRAME
        );
        let revision: i64 = store
            .db
            .query_row("SELECT revision FROM inventory_source", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(revision, i64::MAX);
    }
    /// SQLite state and sidecars inherit the private owner-only storage boundary.
    #[test]
    fn sqlite_state_and_sidecars_are_private() {
        use std::os::unix::fs::MetadataExt;
        let (directory, mut store) = fixture();
        let owner = actor("private-storage");
        make(&mut store, &owner, "private-storage");
        let uid = std::fs::metadata(directory.path()).unwrap().uid();
        for name in [
            "pool.sqlite",
            "pool.lock",
            "pool.sqlite-wal",
            "pool.sqlite-shm",
        ] {
            let metadata = std::fs::symlink_metadata(directory.path().join(name)).unwrap();
            assert!(metadata.is_file(), "{name}");
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600, "{name}");
            assert_eq!(metadata.uid(), uid, "{name}");
        }
    }
    /// Optional extensions preserve the canonical digests of already-stored legacy intents.
    #[test]
    fn legacy_mutation_digests_remain_stable() {
        let change = Change {
            pool_id: "pool".into(),
            expected_revision: 7,
            request_key: "key".into(),
        };
        let create = Command::Create(Create {
            request_key: "key".into(),
            name: "Pool".into(),
            purpose: "Goal".into(),
            acceptance: None,
        });
        let propose = Command::Propose(Propose {
            change: change.clone(),
            result: "R".into(),
            criteria: "C".into(),
            snapshot: None,
        });
        let vote = Command::Vote(Vote {
            change,
            proposal_id: "proposal".into(),
            roster_key: "roster".into(),
            choice: Choice::Ready,
            evidence: "proof".into(),
            checks: Vec::new(),
        });
        assert_eq!(
            create.digest().unwrap(),
            "5292edc67998317e9203381ac2eba35093ba270e47e070fecc470410f627f537"
        );
        assert_eq!(
            propose.digest().unwrap(),
            "b2f1e35c5456b4da01cdc3b2faef28448651cf7eb84c7b016290a1299ae1dbbf"
        );
        assert_eq!(
            vote.digest().unwrap(),
            "632726a9e4ca7c88a30e1a87149ab73ee8ef29b874ff3fc8e46df68662736cea"
        );
    }
    /// Only the exact versioned lowercase opaque reference is accepted from Run.
    #[test]
    fn execution_reference_validation_is_strict() {
        assert!(execution_ref(&format!("ex1_{}", "a1".repeat(32))).is_ok());
        for invalid in [
            format!("ex1_{}", "A".repeat(64)),
            format!("ex1_{}", "a".repeat(63)),
            format!("ex2_{}", "a".repeat(64)),
            format!("ex1_{}g", "a".repeat(63)),
        ] {
            assert!(matches!(execution_ref(&invalid), Err(Fault::Invalid)));
        }
        let pin = format!("pin_{}", uuid::Uuid::new_v4().simple());
        assert!(pin_id(&pin).is_ok());
        for invalid in [
            pin.to_uppercase(),
            "pin_00000000000010008000000000000000".into(),
            "pin_short".into(),
        ] {
            assert!(matches!(pin_id(&invalid), Err(Fault::Invalid)));
        }
        assert!(store_id(&format!("store_{}", "1a".repeat(16))).is_ok());
        for invalid in [
            format!("store_{}", "A".repeat(32)),
            format!("store_{}", "a".repeat(31)),
            "other_123".into(),
        ] {
            assert!(matches!(store_id(&invalid), Err(Fault::Invalid)));
        }
    }
    /// Authenticated synthetic actor used only at the domain test boundary, never a production bypass.
    fn actor(label: &str) -> Actor {
        Actor::verified(format!("codex:test:store:{label}"), label, "root").unwrap()
    }
    /// Creates a pool and returns its opaque ID.
    fn make(s: &mut Store, a: &Actor, key: &str) -> String {
        match s
            .execute(
                a,
                &Command::Create(Create {
                    request_key: key.into(),
                    name: "Pool".into(),
                    purpose: "Joint work".into(),
                    acceptance: None,
                }),
            )
            .unwrap()
        {
            Reply::Receipt(r) => r.pool_id,
            _ => panic!("receipt"),
        }
    }
    /// Builds current-version mutation preconditions with a fresh idempotency key.
    fn change(s: &Store, pid: &str) -> Change {
        Change {
            pool_id: pid.into(),
            expected_revision: pool(&s.db, pid).unwrap().0.revision,
            request_key: id(),
        }
    }
    /// Invites an actor and returns its unique pending incarnation.
    fn add(s: &mut Store, owner: &Actor, pid: &str, a: &Actor) -> String {
        let c = change(s, pid);
        match s
            .execute(
                owner,
                &Command::Add(Add {
                    change: c,
                    address: a.address.clone(),
                    name: "Member".into(),
                    role: "Implement".into(),
                    task: "Check the result".into(),
                }),
            )
            .unwrap()
        {
            Reply::Receipt(r) => r.created_id.unwrap(),
            _ => panic!("receipt"),
        }
    }
    /// Confirms an invitation using the latest snapshot revision.
    fn join(s: &mut Store, a: &Actor, pid: &str) {
        let c = change(s, pid);
        let checked = s.join_binding(a, pid).unwrap();
        s.execute_join(a, &Command::Join(c), &checked).unwrap();
    }
    /// Reads a member-safe snapshot without asserting owner-only shape.
    fn get(s: &mut Store, a: &Actor, pid: &str) -> Result<Reply, Fault> {
        s.execute(
            a,
            &Command::Get(Get {
                pool_id: pid.into(),
                after: 0,
                section: Section::Overview,
                proposal_id: None,
                member_id: None,
                wait_seconds: 0.0,
                reverse: false,
                before: None,
                field: None,
                expected_revision: None,
            }),
        )
    }
    /// Counts durable rows in a test-selected closed table name.
    fn count(s: &Store, table: &str) -> i64 {
        s.db.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }
    /// Exercises the complete owner envelope, including the frontend's typed round trip.
    fn history_page(s: &Store, params: serde_json::Value) -> Result<serde_json::Value, Fault> {
        use crate::observer::{Envelope, Request};
        let request: Request = serde_json::from_value(serde_json::json!({
            "schema_version": 1, "operation": "get", "params": params
        }))
        .map_err(|_| Fault::Invalid)?;
        let envelope = Envelope::success("pool_detail", s.observe(&request)?);
        let bytes = crate::observer::encode(&envelope)?;
        let decoded: Envelope = serde_json::from_slice(&bytes).map_err(|_| Fault::Internal)?;
        serde_json::to_value(decoded).map_err(|_| Fault::Internal)
    }
    /// Extracts exact event IDs from one opt-in observer page.
    fn history_ids(page: &serde_json::Value) -> Vec<String> {
        page["data"]["view"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| event["event_id_exact"].as_str().unwrap().to_owned())
            .collect()
    }
    /// Posts a synthetic owner message so the test can interleave writes between reads.
    fn post_history(s: &mut Store, owner: &Actor, pool_id: &str, text: &str) {
        let change = change(s, pool_id);
        s.execute(
            owner,
            &Command::Post(Message {
                change,
                body: text.into(),
            }),
        )
        .unwrap();
    }
    /// Backward pages and forward export keep one event boundary while new events arrive.
    #[test]
    fn observer_history_pages_keep_fixed_boundary_and_legacy_shape() {
        use serde_json::json;
        let (_directory, mut store) = fixture();
        let owner = actor("history-owner");
        let pool_id = make(&mut store, &owner, "history-create");
        for n in 1..8 {
            post_history(&mut store, &owner, &pool_id, &format!("message-{n}"));
        }
        let legacy = history_page(&store, json!({"pool_id":pool_id,"section":"history"})).unwrap();
        assert!(legacy["data"].get("history_watermark").is_none());
        assert!(
            legacy["data"]["view"]["events"]
                .as_array()
                .unwrap()
                .iter()
                .all(|event| event.get("event_id_exact").is_none())
        );
        assert_eq!(legacy["data"]["cursor"], "3");

        let tail_params = json!({"pool_id":pool_id,"section":"history","direction":"backward"});
        let tail = history_page(&store, tail_params.clone()).unwrap();
        assert_eq!(tail["data"]["history_watermark"], "8");
        assert_eq!(tail["data"]["cursor"], "6");
        assert_eq!(history_ids(&tail), ["6", "7", "8"]);
        assert_eq!(tail["data"]["has_more"], true);
        post_history(&mut store, &owner, &pool_id, "new-after-watermark");

        let middle_params = json!({"pool_id":pool_id,"section":"history","direction":"backward","before":"6","through":"8"});
        let middle = history_page(&store, middle_params.clone()).unwrap();
        assert_eq!(history_ids(&middle), ["3", "4", "5"]);
        assert_eq!(middle["data"]["cursor"], "3");
        assert_eq!(middle["data"]["history_watermark"], "8");
        post_history(&mut store, &owner, &pool_id, "another-new-event");
        let repeated = history_page(&store, middle_params).unwrap();
        assert_eq!(history_ids(&middle), history_ids(&repeated));
        assert_eq!(repeated["data"]["history_watermark"], "8");
        let oldest = history_page(&store, json!({"pool_id":pool_id,"section":"history","direction":"backward","before":"3","through":"8"})).unwrap();
        assert_eq!(history_ids(&oldest), ["1", "2"]);
        assert_eq!(oldest["data"]["has_more"], false);
        let exhausted = history_page(&store, json!({"pool_id":pool_id,"section":"history","direction":"backward","before":"1","through":"8"})).unwrap();
        assert!(history_ids(&exhausted).is_empty());
        assert_eq!(exhausted["data"]["cursor"], "0");
        assert_eq!(exhausted["data"]["view"]["next_after"], 0);
        assert_eq!(exhausted["data"]["has_more"], false);

        let mut after = "0".to_owned();
        let mut exported = Vec::new();
        loop {
            let page = history_page(&store, json!({"pool_id":pool_id,"section":"history","direction":"forward","after":after,"through":"8"})).unwrap();
            exported.extend(history_ids(&page));
            assert_eq!(page["data"]["history_watermark"], "8");
            after = page["data"]["cursor"].as_str().unwrap().to_owned();
            if !page["data"]["has_more"].as_bool().unwrap() {
                break;
            }
        }
        assert_eq!(exported, ["1", "2", "3", "4", "5", "6", "7", "8"]);
        let follow = history_page(
            &store,
            json!({"pool_id":pool_id,"section":"history","direction":"forward","after":"8"}),
        )
        .unwrap();
        assert_eq!(history_ids(&follow), ["9", "10"]);
        assert_eq!(follow["data"]["history_watermark"], "10");
    }
    /// Participant reverse pages exclude later appends and never duplicate page boundaries.
    #[test]
    fn participant_history_reverse_pages_survive_concurrent_appends() {
        let (_directory, mut s) = fixture();
        let owner = actor("reverse-owner");
        let p = make(&mut s, &owner, "reverse");
        for n in 1..8 {
            post_history(&mut s, &owner, &p, &format!("message-{n}"));
        }
        let mut get = Get {
            pool_id: p.clone(),
            after: 0,
            section: Section::History,
            proposal_id: None,
            member_id: None,
            wait_seconds: 0.0,
            reverse: true,
            before: None,
            field: None,
            expected_revision: None,
        };
        let page =
            |s: &mut Store, get: &Get| match s.execute(&owner, &Command::Get(get.clone())).unwrap()
            {
                Reply::OwnerView { view, .. } => view,
                _ => panic!("owner view"),
            };
        let tail = page(&mut s, &get);
        assert_eq!(
            tail.events
                .iter()
                .map(|event| event.event_id)
                .collect::<Vec<_>>(),
            [6, 7, 8]
        );
        assert_eq!(tail.next_before.as_deref(), Some("6"));
        assert!(tail.has_more);
        let templates = crate::response::Templates::new(&crate::tools::templates()).unwrap();
        assert!(
            templates
                .render("pool_view", &tail)
                .unwrap()
                .contains("next_before=6")
        );
        post_history(&mut s, &owner, &p, "later-one");
        post_history(&mut s, &owner, &p, "later-two");
        get.before = tail.next_before;
        let middle = page(&mut s, &get);
        assert_eq!(
            middle
                .events
                .iter()
                .map(|event| event.event_id)
                .collect::<Vec<_>>(),
            [3, 4, 5]
        );
        get.before = middle.next_before;
        let first = page(&mut s, &get);
        assert_eq!(
            first
                .events
                .iter()
                .map(|event| event.event_id)
                .collect::<Vec<_>>(),
            [1, 2]
        );
        assert!(!first.has_more);
        get.before = first.next_before;
        let empty = page(&mut s, &get);
        assert!(empty.events.is_empty());
        assert_eq!(empty.next_before.as_deref(), Some("0"));
        assert!(!empty.has_more);
        for invalid in ["0", "01", "-1", "9223372036854775808", "x"] {
            get.before = Some(invalid.into());
            assert!(matches!(
                Command::Get(get.clone()).validate(),
                Err(Fault::Invalid)
            ));
        }
        get.before = None;
        get.wait_seconds = 1.0;
        assert!(matches!(
            Command::Get(get.clone()).validate(),
            Err(Fault::Invalid)
        ));
        get.wait_seconds = 0.0;
        get.after = 1;
        assert!(matches!(Command::Get(get).validate(), Err(Fault::Invalid)));
    }
    /// Long UTF-8 messages retain exact bytes and replay identity across bounded history pages.
    #[test]
    fn multipart_message_is_atomic_and_exact_across_history_pages() {
        let (directory, mut s) = fixture();
        let owner = actor("message-owner");
        let member = actor("message-member");
        let p = make(&mut s, &owner, "messages");
        let member_id = add(&mut s, &owner, &p, &member);
        join(&mut s, &member, &p);
        let prior: i64 =
            s.db.query_row("SELECT MAX(id) FROM events WHERE pool=?1", [&p], |row| {
                row.get(0)
            })
            .unwrap();
        s.db.execute(
            "UPDATE sqlite_sequence SET seq=9007199254740992 WHERE name='events'",
            [],
        )
        .unwrap();
        let body = format!("{}🦀{}", "x".repeat(2047), "\\".repeat(6141));
        assert_eq!(body.len(), MAX_MESSAGE);
        let command = Command::Send(Direct {
            change: change(&s, &p),
            member_id: member_id.clone(),
            body: body.clone(),
        });
        let before = (
            count(&s, "events"),
            count(&s, "effects"),
            count(&s, "requests"),
        );
        s.db.execute_batch(
            r#"CREATE TEMP TRIGGER fail_message_part BEFORE INSERT ON events
            WHEN NEW.data LIKE '%"kind":"message_part"%' AND NEW.data LIKE '%"part_index":3%'
            BEGIN SELECT RAISE(ABORT, 'synthetic message failure'); END;"#,
        )
        .unwrap();
        assert!(matches!(s.execute(&owner, &command), Err(Fault::Internal)));
        assert_eq!(
            (
                count(&s, "events"),
                count(&s, "effects"),
                count(&s, "requests")
            ),
            before
        );
        s.db.execute_batch("DROP TRIGGER fail_message_part")
            .unwrap();
        let Reply::Receipt(receipt) = s.execute(&owner, &command).unwrap() else {
            panic!("receipt")
        };
        let parent = receipt.event.event_id.to_string();
        assert_eq!(parent, "9007199254740993");
        assert_eq!(receipt.event.part_index, Some(1));
        assert_eq!(receipt.event.part_count, Some(5));
        let after_first = count(&s, "events");
        assert_eq!(
            encode(&Reply::Receipt(receipt.clone())).unwrap(),
            encode(&s.execute(&owner, &command).unwrap()).unwrap()
        );
        assert_eq!(count(&s, "events"), after_first);
        let mut cursor = prior.to_string();
        let mut assembled = String::new();
        let mut index = 0;
        loop {
            let page = history_page(&s, serde_json::json!({"pool_id":p,"section":"history","direction":"forward","after":cursor})).unwrap();
            for event in page["data"]["view"]["events"].as_array().unwrap() {
                index += 1;
                assert_eq!(event["part_index"], index);
                assert_eq!(event["part_count"], 5);
                assert_eq!(event["message_event_id"], parent);
                assert_eq!(event["recipient"], member_id);
                assert!(event["event_id_exact"].as_str().is_some());
                assembled.push_str(event["body"].as_str().unwrap());
            }
            cursor = page["data"]["cursor"].as_str().unwrap().to_owned();
            if page["data"]["has_more"] == false {
                break;
            }
        }
        assert_eq!(index, 5);
        assert_eq!(assembled, body);
        drop(s);
        let mut s = Store::open(&directory.path().join("pool.sqlite")).unwrap();
        assert_eq!(
            encode(&Reply::Receipt(receipt)).unwrap(),
            encode(&s.execute(&owner, &command).unwrap()).unwrap()
        );
        assert_eq!(count(&s, "events"), after_first);
        let too_long = Command::Send(Direct {
            change: change(&s, &p),
            member_id,
            body: "x".repeat(MAX_MESSAGE + 1),
        });
        assert!(matches!(s.execute(&owner, &too_long), Err(Fault::Invalid)));
    }
    /// Large purposes and proposal snapshots remain exact, fenced and bounded across all projections.
    #[test]
    fn content_pages_preserve_large_utf8_and_revision_fences() {
        let (directory, mut s) = fixture();
        let owner = actor("content-owner");
        let member = actor("content-member");
        let purpose = format!("{}🦀{}", "x".repeat(511), "\\".repeat(7677));
        let snapshot = format!("{}🦀{}", "x".repeat(2047), "\\".repeat(63485));
        assert_eq!(purpose.len(), 8192);
        assert_eq!(snapshot.len(), 65536);
        let Reply::Receipt(created) = s
            .execute(
                &owner,
                &Command::Create(Create {
                    request_key: "content".into(),
                    name: "Content".into(),
                    purpose: purpose.clone(),
                    acceptance: None,
                }),
            )
            .unwrap()
        else {
            panic!("receipt")
        };
        let p = created.pool_id.clone();
        assert!(matches!(
            s.execute(
                &owner,
                &Command::Create(Create {
                    request_key: "too-long".into(),
                    name: "Bad".into(),
                    purpose: "x".repeat(8193),
                    acceptance: None,
                })
            ),
            Err(Fault::Invalid)
        ));
        for index in 0..9 {
            s.execute(
                &owner,
                &Command::Create(Create {
                    request_key: format!("extra-{index}"),
                    name: "Extra".into(),
                    purpose: "\\".repeat(8192),
                    acceptance: None,
                }),
            )
            .unwrap();
        }
        let listing = s
            .execute(&owner, &Command::List(List { after: None }))
            .unwrap();
        let list_templates = crate::response::Templates::new(&crate::tools::templates()).unwrap();
        let listing =
            serde_json::to_value(crate::tools::present(Ok(listing), &list_templates)).unwrap();
        let listing = listing["content"][0]["text"].as_str().unwrap();
        assert!(!listing.contains("presentation degraded"));
        assert!(listing.len() <= 16384);
        add(&mut s, &owner, &p, &member);
        join(&mut s, &member, &p);
        let c = change(&s, &p);
        let too_large = Command::Propose(Propose {
            change: c.clone(),
            result: "Bad".into(),
            criteria: "Criteria".into(),
            snapshot: Some("x".repeat(65537)),
        });
        assert!(matches!(s.execute(&owner, &too_large), Err(Fault::Invalid)));
        let Reply::Receipt(opened) = s
            .execute(
                &owner,
                &Command::Propose(Propose {
                    change: c,
                    result: "Result".into(),
                    criteria: "Criteria".into(),
                    snapshot: Some(snapshot.clone()),
                }),
            )
            .unwrap()
        else {
            panic!("receipt")
        };
        let proposal_id = opened.created_id.clone().unwrap();
        let templates = crate::response::Templates::new(&crate::tools::templates()).unwrap();
        let overview = get(&mut s, &member, &p).unwrap();
        let Reply::View(view) = &overview else {
            panic!("member view")
        };
        assert_eq!(view.pool.purpose_bytes, Some(8192));
        assert!(view.pool.purpose.ends_with('…'));
        assert!(view.pool.purpose.len() <= 515);
        let rendered =
            serde_json::to_value(crate::tools::present(Ok(overview), &templates)).unwrap();
        assert!(
            !rendered["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("presentation degraded")
        );
        let proposal_view = s
            .execute(
                &member,
                &Command::Get(Get {
                    pool_id: p.clone(),
                    after: 0,
                    section: Section::Proposal,
                    proposal_id: None,
                    member_id: None,
                    wait_seconds: 0.0,
                    reverse: false,
                    before: None,
                    field: None,
                    expected_revision: None,
                }),
            )
            .unwrap();
        let Reply::View(proposal_view) = proposal_view else {
            panic!("member view")
        };
        let projected = proposal_view.pool.proposal.unwrap();
        assert_eq!(projected.snapshot_bytes, Some(65536));
        assert!(projected.snapshot.is_none());
        for (field, expected) in [
            (ContentField::Purpose, &purpose),
            (ContentField::Snapshot, &snapshot),
        ] {
            let mut offset = 0;
            let mut assembled = String::new();
            loop {
                let request = Command::Get(Get {
                    pool_id: p.clone(),
                    after: offset,
                    section: Section::Content,
                    proposal_id: None,
                    member_id: None,
                    wait_seconds: 0.0,
                    reverse: false,
                    before: None,
                    field: Some(field.clone()),
                    expected_revision: (offset > 0).then_some(opened.revision),
                });
                let reply = s.execute(&member, &request).unwrap();
                let Reply::View(view) = &reply else {
                    panic!("member view")
                };
                let content = view.content.as_ref().unwrap();
                assert_eq!(content.field, field);
                assert_eq!(content.offset as u64, offset);
                assert_eq!(content.total_bytes, expected.len());
                assembled.push_str(&content.text);
                let more = view.has_more;
                let next = view.next_after;
                let rendered =
                    serde_json::to_value(crate::tools::present(Ok(reply), &templates)).unwrap();
                let text = rendered["content"][0]["text"].as_str().unwrap();
                assert!(!text.contains("presentation degraded"));
                assert!(text.len() <= 16384);
                if !more {
                    break;
                }
                assert!(next > offset);
                offset = next;
            }
            assert_eq!(&assembled, expected);
        }
        let invalid_boundary = Command::Get(Get {
            pool_id: p.clone(),
            after: 512,
            section: Section::Content,
            proposal_id: None,
            member_id: None,
            wait_seconds: 0.0,
            reverse: false,
            before: None,
            field: Some(ContentField::Purpose),
            expected_revision: Some(opened.revision),
        });
        assert!(matches!(
            s.execute(&member, &invalid_boundary),
            Err(Fault::Invalid)
        ));
        let Command::Get(mut without_fence) = invalid_boundary else {
            panic!("get")
        };
        without_fence.after = 2047;
        without_fence.expected_revision = None;
        assert!(matches!(
            Command::Get(without_fence).validate(),
            Err(Fault::Invalid)
        ));
        let first = history_page(
            &s,
            serde_json::json!({"pool_id":p,"section":"content","field":"snapshot"}),
        )
        .unwrap();
        assert_eq!(first["data"]["view"]["content"]["total_bytes"], 65536);
        assert_eq!(first["data"]["cursor"], "2047");
        assert!(first["data"]["view"]["pool"]["proposal"].is_null());
        let c = change(&s, &p);
        s.execute(
            &owner,
            &Command::Propose(Propose {
                change: c,
                result: "Next".into(),
                criteria: "Criteria".into(),
                snapshot: None,
            }),
        )
        .unwrap();
        let continuation = Command::Get(Get {
            pool_id: p.clone(),
            after: 2047,
            section: Section::Content,
            proposal_id: Some(proposal_id.clone()),
            member_id: None,
            wait_seconds: 0.0,
            reverse: false,
            before: None,
            field: Some(ContentField::Snapshot),
            expected_revision: Some(opened.revision),
        });
        assert!(matches!(
            s.execute(&member, &continuation),
            Err(Fault::Stale)
        ));
        let revision = pool(&s.db, &p).unwrap().0.revision;
        drop(s);
        let s = Store::open(&directory.path().join("pool.sqlite")).unwrap();
        let archived = history_page(&s, serde_json::json!({"pool_id":p,"section":"content","field":"snapshot","proposal_id":proposal_id,"after":2047,"expected_revision":revision})).unwrap();
        assert_eq!(archived["data"]["view"]["content"]["offset"], 2047);
        assert_eq!(archived["data"]["view"]["content"]["total_bytes"], 65536);
    }
    /// Empty snapshots stay empty after later writes; invalid and foreign cursors fail closed.
    #[test]
    fn observer_history_empty_and_cursor_boundaries() {
        use serde_json::json;
        let (_directory, mut store) = fixture();
        let owner = actor("empty-history-owner");
        let pool_id = make(&mut store, &owner, "empty-history-create");
        store
            .db
            .execute("DELETE FROM events WHERE pool=?1", [&pool_id])
            .unwrap();
        let empty = history_page(
            &store,
            json!({"pool_id":pool_id,"section":"history","direction":"backward"}),
        )
        .unwrap();
        assert_eq!(empty["data"]["history_watermark"], "0");
        assert_eq!(empty["data"]["cursor"], "0");
        assert_eq!(empty["data"]["view"]["next_after"], 0);
        assert_eq!(empty["data"]["has_more"], false);
        post_history(&mut store, &owner, &pool_id, "later");
        let snapshot = history_page(
            &store,
            json!({"pool_id":pool_id,"section":"history","direction":"forward","through":"0"}),
        )
        .unwrap();
        assert!(history_ids(&snapshot).is_empty());
        assert_eq!(snapshot["data"]["cursor"], "0");
        assert_eq!(snapshot["data"]["history_watermark"], "0");

        for params in [
            json!({"pool_id":pool_id,"section":"history","direction":"backward","before":"0"}),
            json!({"pool_id":pool_id,"section":"history","direction":"forward","before":"2"}),
            json!({"pool_id":pool_id,"section":"history","direction":"backward","after":1}),
            json!({"pool_id":pool_id,"section":"history","through":"2"}),
            json!({"pool_id":pool_id,"section":"members","direction":"forward"}),
            json!({"pool_id":pool_id,"section":"history","direction":"forward","after":"01"}),
            json!({"pool_id":pool_id,"section":"history","direction":"forward","through":"9223372036854775808"}),
        ] {
            assert!(matches!(history_page(&store, params), Err(Fault::Invalid)));
        }
        for params in [
            json!({"pool_id":pool_id,"section":"history","direction":"forward","through":"999"}),
            json!({"pool_id":pool_id,"section":"history","direction":"forward","after":"1"}),
            json!({"pool_id":pool_id,"section":"history","direction":"backward","before":"999"}),
            json!({"pool_id":pool_id,"section":"history","direction":"forward","after":"2","through":"0"}),
        ] {
            assert!(matches!(history_page(&store, params), Err(Fault::Stale)));
        }
    }
    /// The optional exact fields retain SQLite IDs beyond JavaScript's integer precision.
    #[test]
    fn observer_history_preserves_large_decimal_ids() {
        use serde_json::json;
        let (_directory, store) = fixture();
        let mut store = store;
        let owner = actor("large-history-owner");
        let pool_id = make(&mut store, &owner, "large-history-create");
        let raw: String = store
            .db
            .query_row("SELECT data FROM events WHERE pool=?1", [&pool_id], |row| {
                row.get(0)
            })
            .unwrap();
        store
            .db
            .execute(
                "INSERT INTO events(id,pool,data) VALUES(?1,?2,?3)",
                params![9_007_199_254_740_993_i64, pool_id, raw],
            )
            .unwrap();
        let page = history_page(
            &store,
            json!({"pool_id":pool_id,"section":"history","direction":"forward","after":"1"}),
        )
        .unwrap();
        assert_eq!(page["data"]["history_watermark"], "9007199254740993");
        assert_eq!(page["data"]["cursor"], "9007199254740993");
        assert_eq!(history_ids(&page), ["9007199254740993"]);
    }
    /// Exercises owner inventory and every section over multiple pages without any read-side writes.
    /// Synthetic actors and private SQLite files never contact Bridge, Run or a model.
    #[test]
    fn observer_pages_are_complete_redacted_and_read_only() {
        use crate::observer::{Data, Envelope, Request};
        let (_directory, mut store) = fixture();
        let owner = actor("observer-owner");
        let pid = make(&mut store, &owner, "primary");
        for n in 0..11 {
            make(
                &mut store,
                &actor(&format!("other-owner-{n}")),
                &format!("pool-{n}"),
            );
        }
        let members: Vec<_> = (0..7)
            .map(|n| actor(&format!("observer-member-{n}")))
            .collect();
        let mut ids = Vec::new();
        for member in &members {
            ids.push(add(&mut store, &owner, &pid, member));
            join(&mut store, member, &pid);
        }
        for n in 0..4 {
            let c = change(&store, &pid);
            store
                .execute(
                    &owner,
                    &Command::Propose(Propose {
                        change: c,
                        result: format!("result-{n}"),
                        criteria: "evidence".into(),
                        snapshot: None,
                    }),
                )
                .unwrap();
            for member in &members {
                let proposal = pool(&store.db, &pid).unwrap().0.proposal.unwrap();
                let c = change(&store, &pid);
                store
                    .execute(
                        member,
                        &Command::Vote(Vote {
                            change: c,
                            proposal_id: proposal.proposal_id,
                            roster_key: proposal.roster_key,
                            choice: Choice::Ready,
                            evidence: "🦀".repeat(512),
                            checks: Vec::new(),
                        }),
                    )
                    .unwrap();
            }
        }
        let removed = ids[0].clone();
        let c = change(&store, &pid);
        store
            .execute(
                &owner,
                &Command::Remove(Remove {
                    change: c,
                    member_id: removed.clone(),
                }),
            )
            .unwrap();
        let before: i64 = store
            .db
            .query_row("SELECT total_changes()", [], |row| row.get(0))
            .unwrap();
        let counts: Vec<_> = [
            "pools",
            "leaders",
            "members",
            "requests",
            "events",
            "effects",
            "publications",
            "alerts",
        ]
        .iter()
        .map(|table| count(&store, table))
        .collect();
        let mut after = None;
        let mut pools = Vec::new();
        loop {
            let request: Request = serde_json::from_value(
                serde_json::json!({"schema_version":1,"operation":"list","params":{"after":after}}),
            )
            .unwrap();
            let Data::Pools(page) = store.observe(&request).unwrap() else {
                panic!("inventory");
            };
            assert!(page.page.source_timestamp.is_none());
            assert_eq!(page.page.returned, page.pools.len());
            assert!(page.pools.iter().all(|row| !row.leader_id.is_empty()));
            after = page.page.cursor;
            pools.extend(page.pools.into_iter().map(|row| row.pool.pool_id));
            if !page.page.has_more {
                break;
            }
        }
        assert_eq!(pools.len(), 12);
        assert!(pools.windows(2).all(|rows| rows[0] < rows[1]));
        for section in ["members", "history", "votes", "deliveries", "decisions"] {
            let mut cursor = 0;
            let mut pages = 0;
            let mut total = 0;
            loop {
                let request: Request = serde_json::from_value(serde_json::json!({"schema_version":1,"operation":"get","params":{"pool_id":pid,"section":section,"after":cursor,"expected_revision":pool(&store.db,&pid).unwrap().0.revision}})).unwrap();
                let data = store.observe(&request).unwrap();
                let encoded =
                    crate::observer::encode(&Envelope::success("pool_detail", data)).unwrap();
                assert!(encoded.len() <= crate::integrations::MAX_FRAME);
                let envelope: Envelope = serde_json::from_slice(&encoded).unwrap();
                let Some(Data::Detail(detail)) = envelope.data else {
                    panic!("detail");
                };
                assert!(detail.bindings.is_none());
                total += detail.page.returned;
                pages += 1;
                let next: u64 = detail.page.cursor.unwrap().parse().unwrap();
                if !detail.page.has_more {
                    break;
                }
                assert!(next > cursor, "continuation must make progress: {section}");
                cursor = next;
            }
            assert!(pages > 1, "fixture must page {section}");
            let expected = match section {
                "members" => 6,
                "votes" => 7,
                "decisions" => 4,
                _ => {
                    let table = if section == "history" {
                        "events"
                    } else {
                        "effects"
                    };
                    store
                        .db
                        .query_row(
                            &format!("SELECT count(*) FROM {table} WHERE pool=?1"),
                            [&pid],
                            |row| row.get::<_, i64>(0),
                        )
                        .map(|count| usize::try_from(count).unwrap())
                        .unwrap()
                }
            };
            assert_eq!(
                total, expected,
                "every source row must be returned exactly once for {section}"
            );
        }
        for params in [
            serde_json::json!({"pool_id":pid,"section":"members","include_bindings":true}),
            serde_json::json!({"pool_id":pid,"section":"binding","member_id":removed}),
        ] {
            let request: Request = serde_json::from_value(
                serde_json::json!({"schema_version":1,"operation":"get","params":params}),
            )
            .unwrap();
            let Data::Detail(detail) = store.observe(&request).unwrap() else {
                panic!("detail");
            };
            assert!(!detail.bindings.unwrap().is_empty());
        }
        for section in ["members", "votes"] {
            let request: Request = serde_json::from_value(serde_json::json!({"schema_version":1,"operation":"get","params":{"pool_id":pid,"section":section,"after":1,"expected_revision":1}})).unwrap();
            assert!(matches!(store.observe(&request), Err(Fault::Stale)));
            let request: Request = serde_json::from_value(serde_json::json!({"schema_version":1,"operation":"get","params":{"pool_id":pid,"section":section,"after":1}})).unwrap();
            assert!(matches!(store.observe(&request), Err(Fault::Invalid)));
        }
        let request: Request = serde_json::from_value(serde_json::json!({"schema_version":1,"operation":"get","params":{"pool_id":"missing"}})).unwrap();
        assert!(matches!(store.observe(&request), Err(Fault::Forbidden)));
        let after: i64 = store
            .db
            .query_row("SELECT total_changes()", [], |row| row.get(0))
            .unwrap();
        assert_eq!(before, after);
        assert_eq!(
            counts,
            [
                "pools",
                "leaders",
                "members",
                "requests",
                "events",
                "effects",
                "publications",
                "alerts"
            ]
            .iter()
            .map(|table| count(&store, table))
            .collect::<Vec<_>>()
        );
        assert_eq!(store.unknown_cursor, 0);
        let participant = get(&mut store, &members[1], &pid).unwrap();
        let json = encode(&participant).unwrap();
        assert!(
            !json.contains("address") && !json.contains("run_id") && !json.contains(&owner.key)
        );
    }
    /// Missing/corrupt source tables yield typed unavailable source errors instead of empty success.
    #[test]
    fn observer_missing_source_fails_closed() {
        let (_directory, store) = fixture();
        store.db.execute_batch("DROP TABLE pools").unwrap();
        let request = crate::observer::Request {
            schema_version: 1,
            operation: crate::observer::Operation::List(List { after: None }),
        };
        assert!(matches!(store.observe(&request), Err(Fault::Internal)));
    }
    /// One global leader owns multiple pools and can never join any, including another owner's pool.
    #[test]
    fn global_leader_survives_three_pools_and_close() {
        let (_d, mut s) = fixture();
        let lead = actor("lead");
        let other = actor("other");
        let pools: Vec<_> = (0..3)
            .map(|i| make(&mut s, &lead, &format!("create{i}")))
            .collect();
        let foreign = make(&mut s, &other, "foreign");
        for p in pools.iter().chain([&foreign]) {
            let own = if p == &foreign { &other } else { &lead };
            let c = change(&s, p);
            assert!(matches!(
                s.execute(
                    own,
                    &Command::Add(Add {
                        change: c,
                        address: lead.address.clone(),
                        name: "Alias".into(),
                        role: "Role".into(),
                        task: "Task".into()
                    })
                ),
                Err(Fault::Conflict)
            ));
        }
        let c = change(&s, &pools[0]);
        s.execute(&lead, &Command::Close(c)).unwrap();
        assert!(leader(&s.db, &lead).unwrap());
        assert_eq!(count(&s, "leaders"), 2);
    }
    /// Pending reservation and confirmed membership both exclude concurrent membership and leadership.
    #[test]
    fn member_reservations_are_global() {
        let (_d, mut s) = fixture();
        let lead = actor("lead");
        let a = actor("a");
        let p = make(&mut s, &lead, "one");
        let p2 = make(&mut s, &lead, "two");
        add(&mut s, &lead, &p, &a);
        let c = change(&s, &p2);
        assert!(matches!(
            s.execute(
                &lead,
                &Command::Add(Add {
                    change: c,
                    address: a.address.clone(),
                    name: "Alias".into(),
                    role: "Role".into(),
                    task: "Task".into()
                })
            ),
            Err(Fault::Conflict)
        ));
        let create = Command::Create(Create {
            request_key: "own".into(),
            name: "Own".into(),
            purpose: "Own".into(),
            acceptance: None,
        });
        assert!(matches!(s.execute(&a, &create), Err(Fault::Forbidden)));
        join(&mut s, &a, &p);
        assert!(matches!(s.execute(&a, &create), Err(Fault::Forbidden)));
    }
    /// Post wakes peers only; explicit owner notification uses the hidden owner binding.
    #[test]
    fn audiences_and_public_views_exclude_native_addresses() {
        let (_d, mut s) = fixture();
        let lead = actor("SECRET_OWNER");
        let a = actor("SECRET_A");
        let b = actor("SECRET_B");
        let p = make(&mut s, &lead, "one");
        let amid = add(&mut s, &lead, &p, &a);
        join(&mut s, &a, &p);
        add(&mut s, &lead, &p, &b);
        join(&mut s, &b, &p);
        s.db.execute("UPDATE effects SET state='accepted'", [])
            .unwrap();
        let c = change(&s, &p);
        let reply = s
            .execute(
                &a,
                &Command::Post(Message {
                    change: c,
                    body: "hello".into(),
                }),
            )
            .unwrap();
        let e = s.next_effect().unwrap().unwrap();
        assert!(matches!(e.work,Work::Deliver{ref address,..}if address==&b.address));
        assert!(s.next_effect().unwrap().is_none());
        for reply in [reply, get(&mut s, &a, &p).unwrap()] {
            let text = encode(&reply).unwrap();
            assert!(!text.contains("SECRET_"));
            assert!(text.contains(&p));
        }
        let c = change(&s, &p);
        s.execute(
            &a,
            &Command::Notify(Message {
                change: c,
                body: "Need owner".into(),
            }),
        )
        .unwrap();
        let e = s.next_effect().unwrap().unwrap();
        assert!(matches!(e.work,Work::Deliver{ref address,..}if address==&lead.address));
        assert_ne!(amid, lead.key);
    }
    /// Removal revokes reads/actions before replay and readmission never reuses membership IDs.
    #[test]
    fn removal_cancels_queued_but_preserves_unknown_and_retires_scope() {
        let (_d, mut s) = fixture();
        let lead = actor("lead");
        let a = actor("a");
        let p = make(&mut s, &lead, "one");
        let m = add(&mut s, &lead, &p, &a);
        join(&mut s, &a, &p);
        let held = s.next_effect().unwrap().unwrap();
        let c = change(&s, &p);
        let post = Command::Post(Message {
            change: c,
            body: "saved".into(),
        });
        s.execute(&a, &post).unwrap();
        let c = change(&s, &p);
        s.execute(
            &lead,
            &Command::Remove(Remove {
                change: c,
                member_id: m.clone(),
            }),
        )
        .unwrap();
        assert!(matches!(get(&mut s, &a, &p), Err(Fault::Forbidden)));
        assert!(matches!(s.execute(&a, &post), Err(Fault::Forbidden)));
        assert_eq!(effect(&s.db, &held.effect_id).unwrap().state, "inflight");
        let queued: Vec<_> = {
            let mut v = Vec::new();
            while let Some(e) = s.next_effect().unwrap() {
                v.push(e)
            }
            v
        };
        assert_eq!(
            queued
                .iter()
                .filter(|e| matches!(e.work, Work::Retire { .. }))
                .count(),
            1
        );
        assert_eq!(
            queued
                .iter()
                .filter(
                    |e| matches!(e.work,Work::Deliver{ref scope,..}if scope.starts_with("final:"))
                )
                .count(),
            1
        );
        let next = add(&mut s, &lead, &p, &a);
        assert_ne!(m, next);
    }
    /// Exact mutation replay returns the original receipt; changed intent cannot reuse its key.
    #[test]
    fn idempotency_and_join_replay_precede_revision_fence() {
        let (_d, mut s) = fixture();
        let lead = actor("lead");
        let a = actor("a");
        let p = make(&mut s, &lead, "one");
        add(&mut s, &lead, &p, &a);
        let join = Command::Join(change(&s, &p));
        let checked = s.join_binding(&a, &p).unwrap();
        let first = s.execute_join(&a, &join, &checked).unwrap();
        let before = count(&s, "events");
        let checked = s.join_binding(&a, &p).unwrap();
        assert_eq!(
            encode(&first).unwrap(),
            encode(&s.execute_join(&a, &join, &checked).unwrap()).unwrap()
        );
        assert_eq!(count(&s, "events"), before);
        let c = change(&s, &p);
        let mut msg = Message {
            change: c,
            body: "first".into(),
        };
        let cmd = Command::Post(msg.clone());
        let first = s.execute(&a, &cmd).unwrap();
        assert_eq!(
            encode(&first).unwrap(),
            encode(&s.execute(&a, &cmd).unwrap()).unwrap()
        );
        msg.body = "different".into();
        assert!(matches!(
            s.execute(&a, &Command::Post(msg)),
            Err(Fault::Conflict)
        ));
    }
    /// Consensus requires every frozen confirmed member, excludes leader, and leaves accepted data immutable.
    #[test]
    fn consensus_blocks_revokes_and_survives_assignment_change() {
        let (_d, mut s) = fixture();
        let lead = actor("lead");
        let a = actor("a");
        let b = actor("b");
        let p = make(&mut s, &lead, "one");
        let aid = add(&mut s, &lead, &p, &a);
        join(&mut s, &a, &p);
        add(&mut s, &lead, &p, &b);
        join(&mut s, &b, &p);
        let c = change(&s, &p);
        s.execute(
            &lead,
            &Command::Propose(Propose {
                change: c,
                result: "Result".into(),
                criteria: "Evidence".into(),
                snapshot: None,
            }),
        )
        .unwrap();
        let pr = pool(&s.db, &p).unwrap().0.proposal.unwrap();
        for (who, choice) in [
            (&lead, Choice::Ready),
            (&a, Choice::Ready),
            (&b, Choice::Block),
            (&a, Choice::Revoke),
            (&b, Choice::Ready),
            (&a, Choice::Ready),
        ] {
            let c = change(&s, &p);
            let cmd = Command::Vote(Vote {
                change: c,
                proposal_id: pr.proposal_id.clone(),
                roster_key: pr.roster_key.clone(),
                choice,
                evidence: "checked".into(),
                checks: Vec::new(),
            });
            if who.key == lead.key {
                assert!(matches!(s.execute(who, &cmd), Err(Fault::Forbidden)));
            } else {
                s.execute(who, &cmd).unwrap();
            }
        }
        let accepted = pool(&s.db, &p).unwrap().0.proposal.unwrap();
        assert_eq!(accepted.state, ProposalState::Accepted);
        let c = change(&s, &p);
        s.execute(
            &lead,
            &Command::MemberUpdate(MemberUpdate {
                change: c,
                member_id: aid,
                name: "A".into(),
                role: "New role".into(),
                task: "New task".into(),
            }),
        )
        .unwrap();
        let current = pool(&s.db, &p).unwrap().0;
        assert!(!current.closed);
        assert_eq!(
            encode(&accepted).unwrap(),
            encode(&current.proposal.unwrap()).unwrap()
        );
    }
    /// An old unverified Run ballot cannot combine with a new Bridge vote to accept a proposal.
    #[test]
    fn cached_managed_vote_stays_unknown_and_cannot_accept() {
        let (_directory, mut s) = fixture();
        let owner = actor("owner");
        let managed = actor("managed");
        let bridge = actor("bridge");
        let p = make(&mut s, &owner, "legacy-ballot");
        let managed_id = add(&mut s, &owner, &p, &managed);
        join(&mut s, &managed, &p);
        let bridge_id = add(&mut s, &owner, &p, &bridge);
        join(&mut s, &bridge, &p);
        let c = change(&s, &p);
        s.execute(
            &owner,
            &Command::Propose(Propose {
                change: c,
                result: "Result".into(),
                criteria: "Criteria".into(),
                snapshot: None,
            }),
        )
        .unwrap();
        let mut saved = pool(&s.db, &p).unwrap().0;
        let proposal = saved.proposal.as_mut().unwrap();
        proposal.votes.insert(
            managed_id.clone(),
            Ballot {
                choice: Choice::Ready,
                evidence: "Old evidence".into(),
                checks_met: None,
                vote_event_id: None,
                checks_count: None,
                validity: None,
            },
        );
        let proposal_id = proposal.proposal_id.clone();
        let roster_key = proposal.roster_key.clone();
        save_pool(&s.db, &saved).unwrap();
        let (mut binding, current) = binding_any(&s.db, &managed_id).unwrap();
        binding.run_id = Some("old-run".into());
        binding.run_sequence = Some(1);
        save_binding(&s.db, &binding, current).unwrap();
        let c = change(&s, &p);
        s.execute(
            &bridge,
            &Command::Vote(Vote {
                change: c,
                proposal_id: proposal_id.clone(),
                roster_key,
                choice: Choice::Ready,
                evidence: "New evidence".into(),
                checks: Vec::new(),
            }),
        )
        .unwrap();
        let current = pool(&s.db, &p).unwrap().0.proposal.unwrap();
        assert_eq!(current.state, ProposalState::Open);
        assert_eq!(current.votes[&bridge_id].choice, Choice::Ready);
        let view = s
            .execute(
                &owner,
                &Command::Get(Get {
                    pool_id: p.clone(),
                    after: 0,
                    section: Section::Votes,
                    proposal_id: Some(proposal_id.clone()),
                    member_id: None,
                    wait_seconds: 0.0,
                    reverse: false,
                    before: None,
                    field: None,
                    expected_revision: None,
                }),
            )
            .unwrap();
        let Reply::OwnerView { view, .. } = view else {
            panic!("owner view")
        };
        let ballots = &view.pool.proposal.as_ref().unwrap().votes;
        assert_eq!(ballots[&managed_id].choice, Choice::Ready);
        assert_eq!(ballots[&managed_id].validity, Some(VoteValidity::Unknown));
        assert_eq!(ballots[&bridge_id].validity, None);
        let observed = history_page(
            &s,
            serde_json::json!({"pool_id":p,"section":"votes","proposal_id":proposal_id}),
        )
        .unwrap();
        assert_eq!(
            observed["data"]["view"]["pool"]["proposal"]["votes"][&managed_id]["validity"],
            "unknown"
        );
        let mut historical = pool(&s.db, &p).unwrap().0;
        historical.proposal.as_mut().unwrap().state = ProposalState::Accepted;
        save_pool(&s.db, &historical).unwrap();
        let observed = history_page(
            &s,
            serde_json::json!({"pool_id":p,"section":"votes","proposal_id":proposal_id}),
        )
        .unwrap();
        assert_eq!(
            observed["data"]["view"]["pool"]["proposal"]["state"],
            "accepted"
        );
        assert_eq!(
            observed["data"]["view"]["pool"]["proposal"]["votes"][&managed_id]["validity"],
            "unknown"
        );
    }
    #[test]
    fn managed_seed_is_atomic_with_event_and_removed_before_freeze_is_not_delivered() {
        let (_directory, mut store) = fixture();
        let owner = actor("seed-owner");
        let participant = actor("seed-member");
        let pool_id = make(&mut store, &owner, "seed-pool");
        let member_id = add(&mut store, &owner, &pool_id, &participant);
        join(&mut store, &participant, &pool_id);
        let (mut binding, current) = binding_any(&store.db, &member_id).unwrap();
        binding.run_id = Some("execution".into());
        binding.run_sequence = Some(1);
        binding.run_store_id = Some(format!("store_{}", "a".repeat(32)));
        save_binding(&store.db, &binding, current).unwrap();
        let post = Command::Post(Message {
            change: change(&store, &pool_id),
            body: "immutable seed".into(),
        });
        let before = (
            pool(&store.db, &pool_id).unwrap().0.revision,
            count(&store, "events"),
            count(&store, "effects"),
        );
        store.db.execute_batch("CREATE TRIGGER test_seed_failure BEFORE INSERT ON managed_delivery_seeds BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
        assert!(store.execute(&owner, &post).is_err());
        store
            .db
            .execute_batch("DROP TRIGGER test_seed_failure;")
            .unwrap();
        assert_eq!(
            (
                pool(&store.db, &pool_id).unwrap().0.revision,
                count(&store, "events"),
                count(&store, "effects")
            ),
            before
        );
        let Reply::Receipt(receipt) = store.execute(&owner, &post).unwrap() else {
            panic!("post receipt")
        };
        let source: String = store
            .db
            .query_row("SELECT store_id FROM inventory_source", [], |row| {
                row.get(0)
            })
            .unwrap();
        let (effect_id,event_key,scope,hash,length):(String,String,String,String,i64)=store.db.query_row("SELECT effect_id,event_key,producer_scope,payload_sha256,payload_length FROM managed_delivery_seeds WHERE member_id=?1 AND final_notice=0 ORDER BY rowid DESC LIMIT 1",[&member_id],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?))).unwrap();
        assert_eq!(event_key, format!("event/{}", receipt.event.event_id));
        assert_eq!(scope, format!("pool/{source}/{pool_id}/{member_id}"));
        let effect = effect(&store.db, &effect_id).unwrap();
        let Work::Deliver { text, .. } = effect.work else {
            panic!("delivery")
        };
        assert_eq!(hash, format!("{:x}", Sha256::digest(text.as_bytes())));
        assert_eq!(length, i64::try_from(text.len()).unwrap());
        assert!(
            store
                .db
                .execute(
                    "UPDATE managed_delivery_seeds SET event_key='different' WHERE effect_id=?1",
                    [&effect_id]
                )
                .is_err()
        );
        let remove = Command::Remove(Remove {
            change: change(&store, &pool_id),
            member_id: member_id.clone(),
        });
        let Reply::Receipt(removed) = store.execute(&owner, &remove).unwrap() else {
            panic!("remove receipt")
        };
        assert_eq!(
            store
                .db
                .query_row::<String, _, _>(
                    "SELECT state FROM managed_delivery_outbox WHERE effect_id=?1",
                    [&effect_id],
                    |row| row.get(0)
                )
                .unwrap(),
            "not_delivered"
        );
        let (final_key,final_scope):(String,String)=store.db.query_row("SELECT event_key,producer_scope FROM managed_delivery_seeds WHERE member_id=?1 AND final_notice=1",[&member_id],|row|Ok((row.get(0)?,row.get(1)?))).unwrap();
        assert_eq!(final_key, format!("event/{}", removed.event.event_id));
        assert_eq!(final_scope, format!("pool/{source}/{pool_id}/final-notice"));
        assert_eq!(
            crate::managed_egress::producer_scope(&source, &pool_id, "final-notice", false).err(),
            Some(Fault::Invalid)
        );
    }

    #[test]
    fn managed_removal_retires_legacy_scope_only_for_a_legacy_publication() {
        for legacy_publication in [false, true] {
            let (_directory, mut store) = fixture();
            let owner = actor("retirement-owner");
            let participant = actor("retirement-member");
            let pool_id = make(&mut store, &owner, "retirement-pool");
            let member_id = add(&mut store, &owner, &pool_id, &participant);
            join(&mut store, &participant, &pool_id);
            if legacy_publication {
                let effect_id: String = store
                    .db
                    .query_row(
                        "SELECT id FROM effects WHERE member=?1 ORDER BY sequence LIMIT 1",
                        [&member_id],
                        |row| row.get(0),
                    )
                    .unwrap();
                store
                    .freeze_publication(&effect_id, "legacy", &serde_json::json!({}))
                    .unwrap();
            }
            let (mut binding, current) = binding_any(&store.db, &member_id).unwrap();
            binding.run_id = Some("execution".into());
            binding.run_sequence = Some(1);
            save_binding(&store.db, &binding, current).unwrap();
            store
                .execute(
                    &owner,
                    &Command::Remove(Remove {
                        change: change(&store, &pool_id),
                        member_id: member_id.clone(),
                    }),
                )
                .unwrap();
            let retirements: i64 = store.db.query_row(
                "SELECT count(*) FROM effects WHERE member=?1 AND json_extract(data,'$.work.kind')='retire'",
                [&member_id],
                |row| row.get(0),
            ).unwrap();
            assert_eq!(retirements, i64::from(legacy_publication));
        }
    }

    /// Managed membership cannot read, write or replay a formerly valid participant receipt.
    #[test]
    fn managed_member_cannot_replay_or_read_without_attempt_proof() {
        let (_directory, mut store) = fixture();
        let owner = actor("owner");
        let managed = actor("managed");
        let bridge = actor("bridge");
        let pool_id = make(&mut store, &owner, "managed-replay");
        let member_id = add(&mut store, &owner, &pool_id, &managed);
        join(&mut store, &managed, &pool_id);
        add(&mut store, &owner, &pool_id, &bridge);
        join(&mut store, &bridge, &pool_id);
        let posted = Command::Post(Message {
            change: change(&store, &pool_id),
            body: "Prior participant message".into(),
        });
        store.execute(&managed, &posted).unwrap();
        let (mut binding, current) = binding_any(&store.db, &member_id).unwrap();
        binding.run_id = Some("ag-20261107-010101-0123456789".into());
        binding.run_sequence = Some(1);
        save_binding(&store.db, &binding, current).unwrap();
        let before = (
            pool(&store.db, &pool_id).unwrap().0.revision,
            count(&store, "events"),
            count(&store, "effects"),
            count(&store, "requests"),
        );
        assert!(matches!(
            store.execute(&managed, &posted),
            Err(Fault::Unavailable)
        ));
        assert!(matches!(
            get(&mut store, &managed, &pool_id),
            Err(Fault::Unavailable)
        ));
        assert!(matches!(
            store.execute(&managed, &Command::List(List { after: None })),
            Err(Fault::Unavailable)
        ));
        let fresh = Command::Post(Message {
            change: change(&store, &pool_id),
            body: "Must not commit".into(),
        });
        assert!(matches!(
            store.execute(&managed, &fresh),
            Err(Fault::Unavailable)
        ));
        let join = Command::Join(change(&store, &pool_id));
        let checked = store.join_binding(&managed, &pool_id).unwrap();
        assert!(matches!(
            store.execute_join(&managed, &join, &checked),
            Err(Fault::Unavailable)
        ));
        let remove = Command::Remove(Remove {
            change: change(&store, &pool_id),
            member_id,
        });
        assert!(matches!(
            store.execute(&managed, &remove),
            Err(Fault::Unavailable)
        ));
        assert!(get(&mut store, &owner, &pool_id).is_ok());
        assert!(get(&mut store, &bridge, &pool_id).is_ok());
        assert_eq!(
            before,
            (
                pool(&store.db, &pool_id).unwrap().0.revision,
                count(&store, "events"),
                count(&store, "effects"),
                count(&store, "requests"),
            )
        );
    }
    /// Structured votes reject incomplete coverage and retain unmet checks across later votes.
    #[test]
    fn structured_acceptance_votes_record_checks_and_require_all_met() {
        let (directory, mut s) = fixture();
        let lead = actor("lead");
        let a = actor("a");
        let b = actor("b");
        let criteria: Vec<_> = ["first", "second"]
            .into_iter()
            .map(|id| Criterion {
                id: id.into(),
                text: format!("Check {id}"),
            })
            .collect();
        let Reply::Receipt(created) = s
            .execute(
                &lead,
                &Command::Create(Create {
                    request_key: "structured".into(),
                    name: "Pool".into(),
                    purpose: "Verify".into(),
                    acceptance: Some(criteria),
                }),
            )
            .unwrap()
        else {
            panic!("receipt")
        };
        let p = created.pool_id;
        let aid = add(&mut s, &lead, &p, &a);
        join(&mut s, &a, &p);
        add(&mut s, &lead, &p, &b);
        join(&mut s, &b, &p);
        let c = change(&s, &p);
        s.execute(
            &lead,
            &Command::Propose(Propose {
                change: c,
                result: "Done".into(),
                criteria: "See structured criteria".into(),
                snapshot: None,
            }),
        )
        .unwrap();
        let proposal = pool(&s.db, &p).unwrap().0.proposal.unwrap();
        let check = |id: &str, status| CriterionCheck {
            criterion_id: id.into(),
            status,
            evidence: format!("Evidence {id}"),
        };
        let valid = vec![
            check("first", CheckStatus::Met),
            check("second", CheckStatus::Unmet),
        ];
        let vote = |change, checks| Vote {
            change,
            proposal_id: proposal.proposal_id.clone(),
            roster_key: proposal.roster_key.clone(),
            choice: Choice::Ready,
            evidence: String::new(),
            checks,
        };
        let before = count(&s, "events");
        let revision = pool(&s.db, &p).unwrap().0.revision;
        for checks in [
            vec![valid[0].clone()],
            vec![valid[0].clone(), check("extra", CheckStatus::Met)],
            vec![valid[0].clone(), valid[0].clone()],
        ] {
            let c = change(&s, &p);
            assert!(matches!(
                s.execute(&a, &Command::Vote(vote(c, checks))),
                Err(Fault::Invalid)
            ));
        }
        assert_eq!(count(&s, "events"), before);
        assert_eq!(pool(&s.db, &p).unwrap().0.revision, revision);
        let c = change(&s, &p);
        let mut revoke_with_checks = vote(c, valid.clone());
        revoke_with_checks.choice = Choice::Revoke;
        assert!(matches!(
            s.execute(&a, &Command::Vote(revoke_with_checks)),
            Err(Fault::Invalid)
        ));
        for choice in [Choice::Block, Choice::Revoke] {
            let c = change(&s, &p);
            let mut control = vote(c, Vec::new());
            control.choice = choice;
            s.execute(&a, &Command::Vote(control)).unwrap();
        }
        let c = change(&s, &p);
        let first = Command::Vote(vote(c, valid));
        let before = count(&s, "events");
        let revision = pool(&s.db, &p).unwrap().0.revision;
        s.db.execute_batch(
            r#"CREATE TEMP TRIGGER fail_second_check BEFORE INSERT ON events
            WHEN NEW.data LIKE '%"kind":"vote_check"%' AND NEW.data LIKE '%"criterion_id":"second"%'
            BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END;"#,
        )
        .unwrap();
        assert!(matches!(s.execute(&a, &first), Err(Fault::Internal)));
        assert_eq!(count(&s, "events"), before);
        assert_eq!(pool(&s.db, &p).unwrap().0.revision, revision);
        s.db.execute_batch("DROP TRIGGER fail_second_check")
            .unwrap();
        let Reply::Receipt(receipt) = s.execute(&a, &first).unwrap() else {
            panic!("receipt")
        };
        let current = pool(&s.db, &p).unwrap().0.proposal.unwrap();
        assert_eq!(current.state, ProposalState::Open);
        assert_eq!(current.votes[&aid].checks_met, Some(false));
        assert_eq!(
            current.votes[&aid].vote_event_id.as_deref(),
            Some(receipt.event.event_id.to_string().as_str())
        );
        let history = s
            .execute(
                &a,
                &Command::Get(Get {
                    pool_id: p.clone(),
                    after: receipt.event.event_id,
                    section: Section::History,
                    proposal_id: None,
                    member_id: None,
                    wait_seconds: 0.0,
                    reverse: false,
                    before: None,
                    field: None,
                    expected_revision: None,
                }),
            )
            .unwrap();
        let Reply::View(history) = history else {
            panic!("member view")
        };
        assert_eq!(history.events.len(), 2);
        assert_eq!(
            history.events[1].check.as_ref().unwrap().status,
            CheckStatus::Unmet
        );
        assert_eq!(
            history.events[1].vote_event_id.as_deref(),
            Some(receipt.event.event_id.to_string().as_str())
        );
        let met = vec![
            check("first", CheckStatus::Met),
            check("second", CheckStatus::Met),
        ];
        let c = change(&s, &p);
        s.execute(&b, &Command::Vote(vote(c, met.clone()))).unwrap();
        assert_eq!(
            pool(&s.db, &p).unwrap().0.proposal.unwrap().state,
            ProposalState::Open
        );
        let c = change(&s, &p);
        let final_vote = Command::Vote(vote(c, met));
        let accepted = s.execute(&a, &final_vote).unwrap();
        assert_eq!(
            pool(&s.db, &p).unwrap().0.proposal.unwrap().state,
            ProposalState::Accepted
        );
        assert_eq!(
            encode(&accepted).unwrap(),
            encode(&s.execute(&a, &final_vote).unwrap()).unwrap()
        );
        let history_again = s
            .execute(
                &a,
                &Command::Get(Get {
                    pool_id: p.clone(),
                    after: receipt.event.event_id,
                    section: Section::History,
                    proposal_id: None,
                    member_id: None,
                    wait_seconds: 0.0,
                    reverse: false,
                    before: None,
                    field: None,
                    expected_revision: None,
                }),
            )
            .unwrap();
        let Reply::View(history_again) = history_again else {
            panic!("member view")
        };
        assert_eq!(
            history_again.events[1].check.as_ref().unwrap().status,
            CheckStatus::Unmet
        );
        let c = change(&s, &p);
        s.execute(
            &lead,
            &Command::Propose(Propose {
                change: c,
                result: "Next".into(),
                criteria: "Next decision".into(),
                snapshot: None,
            }),
        )
        .unwrap();
        drop(s);
        let mut s = Store::open(&directory.path().join("pool.sqlite")).unwrap();
        assert_eq!(
            encode(&accepted).unwrap(),
            encode(&s.execute(&a, &final_vote).unwrap()).unwrap()
        );
        let archived = s
            .execute(
                &a,
                &Command::Get(Get {
                    pool_id: p.clone(),
                    after: 0,
                    section: Section::Votes,
                    proposal_id: Some(proposal.proposal_id.clone()),
                    member_id: None,
                    wait_seconds: 0.0,
                    reverse: false,
                    before: None,
                    field: None,
                    expected_revision: None,
                }),
            )
            .unwrap();
        let Reply::View(archived) = archived else {
            panic!("member view")
        };
        let archived = archived.pool.proposal.unwrap();
        assert_eq!(archived.state, ProposalState::Accepted);
        assert_eq!(archived.votes[&aid].checks_met, Some(true));
        let retained = s
            .execute(
                &a,
                &Command::Get(Get {
                    pool_id: p,
                    after: receipt.event.event_id,
                    section: Section::History,
                    proposal_id: None,
                    member_id: None,
                    wait_seconds: 0.0,
                    reverse: false,
                    before: None,
                    field: None,
                    expected_revision: None,
                }),
            )
            .unwrap();
        let Reply::View(retained) = retained else {
            panic!("member view")
        };
        assert_eq!(
            retained.events[1].check.as_ref().unwrap().status,
            CheckStatus::Unmet
        );
    }
    /// Maximum valid structured content remains paged and renderable without omitting checks.
    #[test]
    fn structured_acceptance_limits_and_paged_evidence() {
        let (_d, mut s) = fixture();
        let lead = actor("lead");
        let a = actor("a");
        let base = Create {
            request_key: "default".into(),
            name: "Pool".into(),
            purpose: "Verify".into(),
            acceptance: Some(Vec::new()),
        };
        let Reply::Receipt(default) = s.execute(&lead, &Command::Create(base.clone())).unwrap()
        else {
            panic!("receipt")
        };
        let saved = pool(&s.db, &default.pool_id).unwrap().0.acceptance.unwrap();
        assert_eq!(
            saved,
            vec![Criterion {
                id: "goal".into(),
                text: "The stated goal is met.".into()
            }]
        );
        let invalids = [
            vec![Criterion {
                id: "bad:id".into(),
                text: "x".into(),
            }],
            vec![Criterion {
                id: "a".into(),
                text: "x".repeat(1025),
            }],
            vec![
                Criterion {
                    id: "duplicate".into(),
                    text: "x".into()
                };
                2
            ],
            vec![
                Criterion {
                    id: "x".into(),
                    text: "x".into()
                };
                11
            ],
        ];
        for acceptance in invalids {
            let mut invalid = base.clone();
            invalid.request_key = id();
            invalid.acceptance = Some(acceptance);
            assert!(matches!(
                s.execute(&lead, &Command::Create(invalid)),
                Err(Fault::Invalid)
            ));
        }
        let criteria: Vec<_> = (0..10)
            .map(|i| Criterion {
                id: format!("c{i}"),
                text: "\\".repeat(1024),
            })
            .collect();
        let mut create = base;
        create.request_key = "maximum".into();
        create.acceptance = Some(criteria.clone());
        let Reply::Receipt(created) = s.execute(&lead, &Command::Create(create)).unwrap() else {
            panic!("receipt")
        };
        let p = created.pool_id;
        add(&mut s, &lead, &p, &a);
        join(&mut s, &a, &p);
        let c = change(&s, &p);
        s.execute(
            &lead,
            &Command::Propose(Propose {
                change: c,
                result: "Done".into(),
                criteria: "See structured criteria".into(),
                snapshot: None,
            }),
        )
        .unwrap();
        let proposal = pool(&s.db, &p).unwrap().0.proposal.unwrap();
        let checks: Vec<_> = criteria
            .iter()
            .enumerate()
            .map(|(i, criterion)| CriterionCheck {
                criterion_id: criterion.id.clone(),
                status: CheckStatus::Met,
                evidence: if i < 5 {
                    "\\".repeat(1024)
                } else {
                    "x".repeat(1024)
                },
            })
            .collect();
        let mut boundary: Vec<_> = (0..8)
            .map(|i| CriterionCheck {
                criterion_id: format!("c{i}"),
                status: CheckStatus::Met,
                evidence: "\\".repeat(1024),
            })
            .collect();
        let exact = (0..=1024)
            .find(|escaped| {
                boundary[7].evidence =
                    format!("{}{}", "\\".repeat(*escaped), "x".repeat(1024 - *escaped));
                serde_json::to_vec(&boundary).unwrap().len() == 16384
            })
            .unwrap();
        let c = change(&s, &p);
        let boundary_vote = Vote {
            change: c,
            proposal_id: proposal.proposal_id.clone(),
            roster_key: proposal.roster_key.clone(),
            choice: Choice::Ready,
            evidence: String::new(),
            checks: boundary.clone(),
        };
        assert!(Command::Vote(boundary_vote.clone()).validate().is_ok());
        assert!(exact < 1024);
        boundary[7].evidence = format!("{}{}", "\\".repeat(exact + 1), "x".repeat(1023 - exact));
        let mut too_large = boundary_vote;
        too_large.checks = boundary;
        assert!(matches!(
            Command::Vote(too_large).validate(),
            Err(Fault::Invalid)
        ));
        let c = change(&s, &p);
        let Reply::Receipt(vote) = s
            .execute(
                &a,
                &Command::Vote(Vote {
                    change: c,
                    proposal_id: proposal.proposal_id,
                    roster_key: proposal.roster_key,
                    choice: Choice::Ready,
                    evidence: String::new(),
                    checks: checks.clone(),
                }),
            )
            .unwrap()
        else {
            panic!("receipt")
        };
        let templates = crate::response::Templates::new(&crate::tools::templates()).unwrap();
        for (section, initial, expected) in [
            (Section::Criteria, 0, 10),
            (Section::History, vote.event.event_id, 10),
            (Section::Votes, 0, 1),
        ] {
            let mut cursor = initial;
            let mut found = 0;
            loop {
                let reply = s
                    .execute(
                        &a,
                        &Command::Get(Get {
                            pool_id: p.clone(),
                            after: cursor,
                            section: section.clone(),
                            proposal_id: None,
                            member_id: None,
                            wait_seconds: 0.0,
                            reverse: false,
                            before: None,
                            field: None,
                            expected_revision: None,
                        }),
                    )
                    .unwrap();
                let Reply::View(view) = &reply else {
                    panic!("member view")
                };
                if section == Section::Criteria {
                    found += view.pool.acceptance.as_ref().unwrap().len();
                } else if section == Section::History {
                    assert!(view.pool.acceptance.is_none());
                    found += view.events.iter().filter(|e| e.check.is_some()).count();
                    assert!(view.events.iter().all(|e| e.vote_event_id.as_deref()
                        == Some(vote.event.event_id.to_string().as_str())));
                } else {
                    assert!(view.pool.acceptance.is_none());
                    let ballots = &view.pool.proposal.as_ref().unwrap().votes;
                    found += ballots.len();
                    let ballot = ballots.values().next().unwrap();
                    assert_eq!(ballot.checks_met, Some(true));
                    assert_eq!(ballot.checks_count, Some(10));
                    assert_eq!(
                        ballot.vote_event_id.as_deref(),
                        Some(vote.event.event_id.to_string().as_str())
                    );
                }
                let more = view.has_more;
                let next = view.next_after;
                let result = crate::tools::present(Ok(reply), &templates);
                let encoded = serde_json::to_value(result).unwrap();
                let body = encoded["content"][0]["text"].as_str().unwrap();
                assert!(
                    !body.contains("presentation degraded"),
                    "{section:?} after {cursor}: {body}"
                );
                assert!(body.len() <= 16384);
                if !more {
                    break;
                }
                assert!(next > cursor);
                cursor = next;
            }
            assert_eq!(found, expected);
        }
        let page = history_page(&s, serde_json::json!({"pool_id":p,"section":"criteria"})).unwrap();
        assert_eq!(page["data"]["cursor"], "3");
        assert_eq!(
            page["data"]["view"]["pool"]["acceptance"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        let page = history_page(&s, serde_json::json!({"pool_id":p,"section":"history","direction":"forward","after":vote.event.event_id.to_string()})).unwrap();
        let events = page["data"]["view"]["events"].as_array().unwrap();
        assert_eq!(events[0]["vote_event_id"], vote.event.event_id.to_string());
        assert_eq!(events[0]["check"]["criterion_id"], "c0");
    }
    /// Pending members cannot vote; membership changes stale unfinished proposals.
    #[test]
    fn pending_member_and_stale_roster_cannot_vote() {
        let (_d, mut s) = fixture();
        let lead = actor("lead");
        let a = actor("a");
        let b = actor("b");
        let p = make(&mut s, &lead, "one");
        add(&mut s, &lead, &p, &a);
        join(&mut s, &a, &p);
        let c = change(&s, &p);
        s.execute(
            &a,
            &Command::Propose(Propose {
                change: c,
                result: "R".into(),
                criteria: "C".into(),
                snapshot: None,
            }),
        )
        .unwrap();
        let pr = pool(&s.db, &p).unwrap().0.proposal.unwrap();
        add(&mut s, &lead, &p, &b);
        assert_eq!(
            pool(&s.db, &p).unwrap().0.proposal.unwrap().state,
            ProposalState::Stale
        );
        let c = change(&s, &p);
        let vote = Command::Vote(Vote {
            change: c,
            proposal_id: pr.proposal_id,
            roster_key: pr.roster_key,
            choice: Choice::Ready,
            evidence: "checked".into(),
            checks: Vec::new(),
        });
        assert!(matches!(s.execute(&b, &vote), Err(Fault::Forbidden)));
        assert!(matches!(s.execute(&a, &vote), Err(Fault::Stale)));
    }
    /// Original Run specs stay private and survive a resident restart without reconstructing onboarding.
    #[test]
    fn original_start_spec_survives_restart_without_entering_views() {
        for grouped in [false, true] {
            let (directory, mut s) = fixture();
            let owner = actor("original-spec-owner");
            let pool = make(&mut s, &owner, "original-spec");
            let raw = serde_json::json!({"task":"private-original-canary","provider":"fixture"});
            let c = change(&s, &pool);
            let command = if grouped {
                Command::StartBatch(StartBatch {
                    change: c,
                    members: vec![StartMember {
                        name: "One".into(),
                        role: "Test".into(),
                        task: "Public assignment".into(),
                        spec: raw.clone(),
                    }],
                })
            } else {
                Command::Start(Start {
                    change: c,
                    name: "One".into(),
                    role: "Test".into(),
                    task: "Public assignment".into(),
                    spec: raw.clone(),
                })
            };
            s.execute(&owner, &command).unwrap();
            let claimed = s.next_effect().unwrap().unwrap();
            let Work::StartBatch { jobs, .. } = &claimed.work else {
                panic!("batch")
            };
            assert_eq!(jobs[0].original_spec.as_ref(), Some(&raw));
            assert!(jobs[0].spec["task"].as_str().unwrap().contains("pool_join"));
            let view = history_page(
                &s,
                serde_json::json!({"pool_id":pool,"section":"deliveries"}),
            )
            .unwrap();
            assert!(!view.to_string().contains("private-original-canary"));
            drop(s);
            let reopened = Store::open(&directory.path().join("pool.sqlite")).unwrap();
            let recovered = effect(&reopened.db, &claimed.effect_id).unwrap();
            assert_eq!(recovered.state, "unknown");
            let Work::StartBatch { jobs, .. } = recovered.work else {
                panic!("batch")
            };
            assert_eq!(jobs[0].original_spec.as_ref(), Some(&raw));
        }
    }
    /// Single starts retain the old receipt while persisting the pin and its exact release route.
    #[test]
    fn single_start_preserves_receipt_and_releases_its_fenced_pin() {
        let (_directory, mut s) = fixture();
        let owner = actor("single-owner");
        let pool = make(&mut s, &owner, "single");
        let command = Command::Start(Start {
            change: change(&s, &pool),
            name: "One".into(),
            role: "Test".into(),
            task: "Verify".into(),
            spec: serde_json::json!({"task":"Verify"}),
        });
        let Reply::Receipt(receipt) = s.execute(&owner, &command).unwrap() else {
            panic!("receipt")
        };
        let member = receipt.created_id.clone().unwrap();
        assert!(receipt.created_ids.is_empty());
        assert_eq!(
            encode(&Reply::Receipt(receipt.clone())).unwrap(),
            encode(&s.execute(&owner, &command).unwrap()).unwrap()
        );
        let start = s.next_effect().unwrap().unwrap();
        assert_eq!(start.member_id.as_deref(), Some(member.as_str()));
        assert!(start.is_single_batch().unwrap());
        let page = history_page(
            &s,
            serde_json::json!({"pool_id":pool,"section":"deliveries"}),
        )
        .unwrap();
        let row = page["data"]["view"]["deliveries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["operation_id"] == start.effect_id)
            .unwrap();
        assert_eq!(row["operation"], "start");
        assert_eq!(row["member_id"], member);
        let route = RunRoute {
            socket: "/fixture/run.sock".into(),
            expected_uid: 7,
            peer_uid: None,
            store_id: None,
        };
        assert!(s.freeze_run_route(&start.effect_id, &route, false).unwrap());
        let store = format!("store_{}", "1".repeat(32));
        s.record_run_store_id(&start.effect_id, &store).unwrap();
        let reference = format!("ex1_{}", "a".repeat(64));
        let pin = format!("pin_{}", uuid::Uuid::new_v4().simple());
        s.record_batch_admission(
            &start.effect_id,
            Some(&store),
            &[(
                "ag-20261107-010101-0000000001".into(),
                1,
                reference.clone(),
                Some(pin.clone()),
            )],
        )
        .unwrap();
        let (binding, current) = binding_any(&s.db, &member).unwrap();
        assert!(current);
        assert_eq!(
            binding.run_execution_ref.as_deref(),
            Some(reference.as_str())
        );
        assert_eq!(binding.run_pin_id.as_deref(), Some(pin.as_str()));
        assert_eq!(binding.run_store_id.as_deref(), Some(store.as_str()));
        assert_eq!(
            original_start_spec(&s.db, &pool, &member, Some(&store)).unwrap(),
            Some(serde_json::json!({"task":"Verify"}))
        );
        assert!(matches!(
            original_start_spec(
                &s.db,
                &pool,
                &member,
                Some(&format!("store_{}", "2".repeat(32)))
            ),
            Err(Fault::Conflict)
        ));
        let mut stored = effect(&s.db, &start.effect_id).unwrap();
        let saved_data = encode(&stored).unwrap();
        let Work::StartBatch { jobs, .. } = &mut stored.work else {
            panic!("batch")
        };
        jobs[0].original_spec = None;
        s.db.execute(
            "UPDATE effects SET data=?2 WHERE id=?1",
            params![start.effect_id, encode(&stored).unwrap()],
        )
        .unwrap();
        assert_eq!(
            original_start_spec(&s.db, &pool, &member, Some(&store)).unwrap(),
            None
        );
        let replace = Command::Replace(Replace {
            change: change(&s, &pool),
            member_id: member.clone(),
            spec: None,
        });
        assert!(matches!(
            s.execute(&owner, &replace),
            Err(Fault::Unavailable)
        ));
        let explicit = Command::Replace(Replace {
            change: change(&s, &pool),
            member_id: member.clone(),
            spec: Some(serde_json::json!({"task":"explicit replacement"})),
        });
        let tx =
            s.db.transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
        assert!(matches!(
            execute(&tx, &owner, &explicit, None),
            Ok(Reply::Receipt(_))
        ));
        tx.rollback().unwrap();
        s.db.execute(
            "UPDATE effects SET data=?2 WHERE id=?1",
            params![start.effect_id, saved_data],
        )
        .unwrap();
        let duplicate_work = effect(&s.db, &start.effect_id).unwrap().work;
        let duplicate = queue(&s.db, &pool, Some(&member), duplicate_work).unwrap();
        s.db.execute(
            "UPDATE effects SET state='accepted' WHERE id=?1",
            [&duplicate],
        )
        .unwrap();
        assert!(matches!(
            original_start_spec(&s.db, &pool, &member, Some(&store)),
            Err(Fault::Conflict)
        ));
        assert!(matches!(
            pin_origin_route(&s.db, &pool, &member, Some(&store)),
            Err(Fault::Conflict)
        ));
        let mut other_origin = effect(&s.db, &duplicate).unwrap();
        let Work::StartBatch {
            route: Some(other_route),
            ..
        } = &mut other_origin.work
        else {
            panic!("origin route")
        };
        other_route.store_id = Some(format!("store_{}", "2".repeat(32)));
        s.db.execute(
            "UPDATE effects SET data=?2 WHERE id=?1",
            params![duplicate, encode(&other_origin).unwrap()],
        )
        .unwrap();
        assert!(matches!(
            pin_origin_route(&s.db, &pool, &member, Some(&store)),
            Err(Fault::Conflict)
        ));
        s.db.execute("DELETE FROM effects WHERE id=?1", [&duplicate])
            .unwrap();
        let c = change(&s, &pool);
        s.execute(&owner, &Command::Close(c)).unwrap();
        let c = change(&s, &pool);
        let Reply::Receipt(release) = s
            .execute(
                &owner,
                &Command::ReleaseHistory(ReleaseHistory {
                    change: c,
                    member_id: member,
                }),
            )
            .unwrap()
        else {
            panic!("release receipt")
        };
        let release = effect(&s.db, release.created_id.as_deref().unwrap()).unwrap();
        let Work::ReleasePin {
            pin_id,
            route: Some(saved),
        } = release.work
        else {
            panic!("fenced release")
        };
        assert_eq!(pin_id, pin);
        assert_eq!(saved.socket, route.socket);
        assert_eq!(saved.store_id.as_deref(), Some(store.as_str()));
    }

    /// Replacement holds the original roster through crashes and only installs a verified receipt once.
    #[test]
    fn replacement_recovers_unknown_and_atomically_preserves_slot() {
        let (directory, mut store) = fixture();
        let owner = actor("replacement-owner");
        let pool_id = make(&mut store, &owner, "replacement-create");
        let start = Command::Start(Start {
            change: change(&store, &pool_id),
            name: "Old".into(),
            role: "Reviewer".into(),
            task: "Review".into(),
            spec: serde_json::json!({"task":"original","provider":"fixture"}),
        });
        let Reply::Receipt(started) = store.execute(&owner, &start).unwrap() else {
            panic!("start receipt")
        };
        let old_id = started.created_id.clone().unwrap();
        let start_effect = store.next_effect().unwrap().unwrap();
        let route = RunRoute {
            socket: "/fixture/run.sock".into(),
            expected_uid: 7,
            peer_uid: None,
            store_id: None,
        };
        assert!(
            store
                .freeze_run_route(&start_effect.effect_id, &route, false)
                .unwrap()
        );
        let store_id = format!("store_{}", "1".repeat(32));
        let old_ref = format!("ex1_{}", "a".repeat(64));
        let old_pin = format!("pin_{}", uuid::Uuid::new_v4().simple());
        store
            .record_run_store_id(&start_effect.effect_id, &store_id)
            .unwrap();
        store
            .record_batch_admission(
                &start_effect.effect_id,
                Some(&store_id),
                &[(
                    "ag-20261107-010101-0000000001".into(),
                    1,
                    old_ref.clone(),
                    Some(old_pin.clone()),
                )],
            )
            .unwrap();
        let (pool, _) = pool(&store.db, &pool_id).unwrap();
        let other_actor = actor("replacement-other");
        let mut other = new_binding(&pool, "Other", "Tester", "Check", None);
        other.actor = Some(other_actor.key.clone());
        other.member.state = MemberState::Active;
        save_binding(&store.db, &other, true).unwrap();
        let before: Vec<_> = bindings(&store.db, &pool_id)
            .unwrap()
            .into_iter()
            .map(|b| b.member.member_id)
            .collect();
        let command = Command::Replace(Replace {
            change: change(&store, &pool_id),
            member_id: old_id.clone(),
            spec: None,
        });
        assert!(matches!(
            store.execute(&other_actor, &command),
            Err(Fault::Forbidden)
        ));
        let Reply::Receipt(requested) = store.execute(&owner, &command).unwrap() else {
            panic!("replace receipt")
        };
        let effect_id = requested.created_id.clone().unwrap();
        let new_id = requested.created_ids[0].clone();
        assert_eq!(
            encode(&store.execute(&owner, &command).unwrap()).unwrap(),
            encode(&Reply::Receipt(requested)).unwrap()
        );
        assert!(binding_any(&store.db, &old_id).unwrap().1);
        assert!(binding_any(&store.db, &new_id).is_err());
        assert!(matches!(
            store.execute(&owner, &Command::Close(change(&store, &pool_id))),
            Err(Fault::Conflict)
        ));
        let update = Command::Update(Update {
            change: change(&store, &pool_id),
            name: "Changed".into(),
            purpose: "Changed".into(),
        });
        assert!(matches!(
            store.execute(&owner, &update),
            Err(Fault::Conflict)
        ));
        let queued = store.next_effect().unwrap().unwrap();
        assert_eq!(queued.effect_id, effect_id);
        let Work::Replace { job, .. } = &queued.work else {
            panic!("replacement work")
        };
        assert!(
            job.spec["task"]
                .as_str()
                .unwrap()
                .contains("before its roster update commits")
        );
        let (_, first_claim) = store.claim_replacement(&effect_id).unwrap().unwrap();
        assert!(store.claim_replacement(&effect_id).unwrap().is_none());
        let condition = crate::run_status::Target {
            agent_id: "ag-20261107-010101-0000000001".into(),
            sequence: 1,
            execution_ref: old_ref,
            pin_id: old_pin,
        };
        store
            .freeze_replacement_condition(&effect_id, &first_claim, &condition)
            .unwrap();
        assert!(
            store
                .begin_replacement_submit(&effect_id, &first_claim)
                .unwrap()
        );
        assert!(matches!(
            store.settle_replacement(&effect_id, "wrong-claim", "refused"),
            Err(Fault::Conflict)
        ));
        drop(store);
        let mut store = Store::open(&directory.path().join("pool.sqlite")).unwrap();
        let (_, second_claim) = store.claim_replacement(&effect_id).unwrap().unwrap();
        assert_ne!(first_claim, second_claim);
        assert!(
            !store
                .begin_replacement_submit(&effect_id, &second_claim)
                .unwrap()
        );
        store
            .settle_replacement(&effect_id, &second_claim, "refused")
            .unwrap();
        assert_eq!(effect(&store.db, &effect_id).unwrap().state, "unknown");
        assert!(binding_any(&store.db, &old_id).unwrap().1);
        let (_, third_claim) = store.claim_replacement(&effect_id).unwrap().unwrap();
        let admission = (
            "ag-20261107-010102-0000000002".into(),
            1,
            format!("ex1_{}", "b".repeat(64)),
            Some(format!("pin_{}", uuid::Uuid::new_v4().simple())),
        );
        store.db.execute_batch("CREATE TRIGGER fail_replacement_slot BEFORE INSERT ON member_slots BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
        assert!(
            store
                .record_replacement_admission(&effect_id, &third_claim, &store_id, &admission)
                .is_err()
        );
        assert!(binding_any(&store.db, &old_id).unwrap().1);
        assert!(binding_any(&store.db, &new_id).is_err());
        store
            .db
            .execute_batch("DROP TRIGGER fail_replacement_slot;")
            .unwrap();
        drop(store);
        let mut store = Store::open(&directory.path().join("pool.sqlite")).unwrap();
        let (_, fourth_claim) = store.claim_replacement(&effect_id).unwrap().unwrap();
        store
            .record_replacement_admission(&effect_id, &fourth_claim, &store_id, &admission)
            .unwrap();
        assert!(!binding_any(&store.db, &old_id).unwrap().1);
        assert!(binding_any(&store.db, &new_id).unwrap().1);
        assert_eq!(effect(&store.db, &effect_id).unwrap().state, "accepted");
        let expected: Vec<_> = before
            .into_iter()
            .map(|id| if id == old_id { new_id.clone() } else { id })
            .collect();
        let actual: Vec<_> = bindings(&store.db, &pool_id)
            .unwrap()
            .into_iter()
            .map(|b| b.member.member_id)
            .collect();
        assert_eq!(actual, expected);
        assert_eq!(
            original_start_spec(&store.db, &pool_id, &new_id, Some(&store_id)).unwrap(),
            Some(serde_json::json!({"task":"original","provider":"fixture"}))
        );
        store
            .record_replacement_admission(&effect_id, &fourth_claim, &store_id, &admission)
            .unwrap();
        let c = change(&store, &pool_id);
        store.execute(&owner, &Command::Close(c)).unwrap();
        store
            .record_replacement_admission(&effect_id, &fourth_claim, &store_id, &admission)
            .unwrap();
    }
    /// Builds one pending replacement against an already accepted, pinned synthetic member.
    fn cancellation_fixture(
        store: &mut Store,
        owner: &Actor,
    ) -> (String, String, String, crate::run_status::Target) {
        let pool_id = make(store, owner, "cancel-create");
        let start = Command::Start(Start {
            change: change(store, &pool_id),
            name: "Old".into(),
            role: "Tester".into(),
            task: "Verify".into(),
            spec: serde_json::json!({"task":"fixture"}),
        });
        let Reply::Receipt(started) = store.execute(owner, &start).unwrap() else {
            panic!("start")
        };
        let old_id = started.created_id.clone().unwrap();
        let start = store.next_effect().unwrap().unwrap();
        let route = RunRoute {
            socket: "/fixture/run.sock".into(),
            expected_uid: 7,
            peer_uid: None,
            store_id: None,
        };
        store
            .freeze_run_route(&start.effect_id, &route, false)
            .unwrap();
        let store_id = format!("store_{}", "1".repeat(32));
        let target = crate::run_status::Target {
            agent_id: "ag-20261107-010101-0000000001".into(),
            sequence: 1,
            execution_ref: format!("ex1_{}", "a".repeat(64)),
            pin_id: format!("pin_{}", uuid::Uuid::new_v4().simple()),
        };
        store
            .record_run_store_id(&start.effect_id, &store_id)
            .unwrap();
        store
            .record_batch_admission(
                &start.effect_id,
                Some(&store_id),
                &[(
                    target.agent_id.clone(),
                    1,
                    target.execution_ref.clone(),
                    Some(target.pin_id.clone()),
                )],
            )
            .unwrap();
        let replace = Command::Replace(Replace {
            change: change(store, &pool_id),
            member_id: old_id.clone(),
            spec: None,
        });
        let Reply::Receipt(receipt) = store.execute(owner, &replace).unwrap() else {
            panic!("replace")
        };
        (pool_id, old_id, receipt.created_id.clone().unwrap(), target)
    }

    /// Cancellation wins only before a claim/send; restart cannot turn a possible send into no admission.
    #[test]
    fn replacement_cancellation_fences_claims_and_possible_sends() {
        for phase in [
            "queued",
            "selected",
            "claimed",
            "sent",
            "crashed_claim",
            "crashed_send",
        ] {
            let (directory, mut store) = fixture();
            let owner = actor("cancel-owner");
            let outsider = actor("cancel-outsider");
            let (pool_id, old_id, effect_id, target) = cancellation_fixture(&mut store, &owner);
            let cancel = |store: &Store, key: &str| {
                Command::CancelReplacement(CancelReplacement {
                    change: Change {
                        pool_id: pool_id.clone(),
                        expected_revision: pool(&store.db, &pool_id).unwrap().0.revision,
                        request_key: key.into(),
                    },
                    operation_id: effect_id.clone(),
                })
            };
            let denied = cancel(&store, "unauthorized");
            assert!(matches!(
                store.execute(&outsider, &denied),
                Err(Fault::Forbidden)
            ));
            let missing = Command::CancelReplacement(CancelReplacement {
                change: change(&store, &pool_id),
                operation_id: "missing-operation".into(),
            });
            assert!(matches!(
                store.execute(&owner, &missing),
                Err(Fault::Forbidden)
            ));
            let mut claim = None;
            if phase != "queued" {
                assert_eq!(store.next_effect().unwrap().unwrap().effect_id, effect_id);
            }
            if matches!(phase, "claimed" | "sent" | "crashed_claim" | "crashed_send") {
                claim = Some(store.claim_replacement(&effect_id).unwrap().unwrap().1);
            }
            if matches!(phase, "sent" | "crashed_send") {
                let token = claim.as_deref().unwrap();
                store
                    .freeze_replacement_condition(&effect_id, token, &target)
                    .unwrap();
                assert!(store.begin_replacement_submit(&effect_id, token).unwrap());
            }
            if matches!(phase, "crashed_claim" | "crashed_send") {
                drop(store);
                store = Store::open(&directory.path().join("pool.sqlite")).unwrap();
                assert_eq!(effect(&store.db, &effect_id).unwrap().state, "unknown");
            }
            let attempt = cancel(&store, "cancel");
            if matches!(phase, "claimed" | "sent" | "crashed_claim" | "crashed_send") {
                assert!(
                    matches!(store.execute(&owner, &attempt), Err(Fault::Conflict)),
                    "{phase}"
                );
                let token = if phase.starts_with("crashed") {
                    store.claim_replacement(&effect_id).unwrap().unwrap().1
                } else {
                    claim.unwrap()
                };
                store
                    .settle_replacement(&effect_id, &token, "unknown")
                    .unwrap();
                if matches!(phase, "sent" | "crashed_send") {
                    let retry = cancel(&store, "cancel-after-send");
                    assert!(
                        matches!(store.execute(&owner, &retry), Err(Fault::Conflict)),
                        "{phase}"
                    );
                    assert!(binding_any(&store.db, &old_id).unwrap().1);
                    continue;
                }
            }
            let attempt = cancel(&store, "cancel-final");
            let result = store.execute(&owner, &attempt).unwrap();
            assert_eq!(
                encode(&result).unwrap(),
                encode(&store.execute(&owner, &attempt).unwrap()).unwrap()
            );
            assert_eq!(effect(&store.db, &effect_id).unwrap().state, "cancelled");
            assert!(store.claim_replacement(&effect_id).unwrap().is_none());
            assert!(binding_any(&store.db, &old_id).unwrap().1);
            let different_key = cancel(&store, "different-cancel");
            assert!(matches!(
                store.execute(&owner, &different_key),
                Err(Fault::Conflict)
            ));
            let close = Command::Close(change(&store, &pool_id));
            assert!(store.execute(&owner, &close).is_ok());
        }
    }

    /// Removal before dispatch cancels a queued singleton without contacting Run.
    #[test]
    fn queued_single_start_is_cancelled_on_removal() {
        let (_directory, mut s) = fixture();
        let owner = actor("queued-single-owner");
        let pool = make(&mut s, &owner, "queued-single");
        let c = change(&s, &pool);
        let Reply::Receipt(receipt) = s
            .execute(
                &owner,
                &Command::Start(Start {
                    change: c,
                    name: "One".into(),
                    role: "Test".into(),
                    task: "Verify".into(),
                    spec: serde_json::json!({"task":"Verify"}),
                }),
            )
            .unwrap()
        else {
            panic!("receipt")
        };
        let member = receipt.created_id.unwrap();
        let id: String =
            s.db.query_row(
                "SELECT id FROM effects WHERE member=?1 AND data LIKE '%\"kind\":\"start_batch\"%'",
                [&member],
                |row| row.get(0),
            )
            .unwrap();
        let c = change(&s, &pool);
        s.execute(
            &owner,
            &Command::Remove(Remove {
                change: c,
                member_id: member,
            }),
        )
        .unwrap();
        assert_eq!(effect(&s.db, &id).unwrap().state, "cancelled");
        let c = change(&s, &pool);
        s.execute(&owner, &Command::Close(c)).unwrap();
    }
    /// A malformed single marker cannot be sent or used to bypass the grouped roster fence.
    #[test]
    fn malformed_single_batch_cannot_send_or_change_roster() {
        let (_directory, mut s) = fixture();
        let owner = actor("malformed-single-owner");
        let pool = make(&mut s, &owner, "malformed-single");
        let c = change(&s, &pool);
        let Reply::Receipt(receipt) = s
            .execute(
                &owner,
                &Command::Start(Start {
                    change: c,
                    name: "One".into(),
                    role: "Test".into(),
                    task: "Verify".into(),
                    spec: serde_json::json!({"task":"Verify"}),
                }),
            )
            .unwrap()
        else {
            panic!("receipt")
        };
        let member = receipt.created_id.unwrap();
        let mut start = s.next_effect().unwrap().unwrap();
        let Work::StartBatch { jobs, .. } = &mut start.work else {
            panic!("batch")
        };
        jobs[0].member_id = "different-member".into();
        s.db.execute(
            "UPDATE effects SET data=?2 WHERE id=?1",
            params![start.effect_id, encode(&start).unwrap()],
        )
        .unwrap();
        let route = RunRoute {
            socket: "/fixture/run.sock".into(),
            expected_uid: 7,
            peer_uid: None,
            store_id: None,
        };
        assert!(matches!(
            s.freeze_run_route(&start.effect_id, &route, false),
            Err(Fault::Internal)
        ));
        let c = change(&s, &pool);
        assert!(matches!(
            s.execute(
                &owner,
                &Command::Remove(Remove {
                    change: c,
                    member_id: member
                })
            ),
            Err(Fault::Internal)
        ));
    }
    /// Group reservation and receipt mapping are atomic across failures and resident restart.
    #[test]
    fn batch_admission_rolls_back_and_reconciles_as_one_group() {
        let (directory, mut s) = fixture();
        let lead = actor("lead");
        let p = make(&mut s, &lead, "batch");
        let member = |label: &str| StartMember {
            name: label.into(),
            role: "Implement".into(),
            task: "Verify".into(),
            spec: serde_json::json!({"task":format!("Work {label}"),"provider":"codex"}),
        };
        let before = (
            count(&s, "members"),
            count(&s, "events"),
            count(&s, "effects"),
        );
        let mut invalid = member("second");
        invalid.spec = serde_json::json!({"provider":"codex"});
        let c = change(&s, &p);
        assert!(matches!(
            s.execute(
                &lead,
                &Command::StartBatch(StartBatch {
                    change: c,
                    members: vec![member("first"), invalid],
                })
            ),
            Err(Fault::Invalid)
        ));
        assert_eq!(
            (
                count(&s, "members"),
                count(&s, "events"),
                count(&s, "effects")
            ),
            before
        );
        assert_eq!(pool(&s.db, &p).unwrap().0.revision, 1);
        let c = change(&s, &p);
        let command = Command::StartBatch(StartBatch {
            change: c,
            members: vec![member("first"), member("second")],
        });
        let Reply::Receipt(receipt) = s.execute(&lead, &command).unwrap() else {
            panic!("receipt")
        };
        assert_eq!(receipt.created_ids.len(), 2);
        let page =
            history_page(&s, serde_json::json!({"pool_id":p,"section":"deliveries"})).unwrap();
        let operations = page["data"]["view"]["deliveries"].as_array().unwrap();
        let batch = operations
            .iter()
            .find(|operation| operation["operation"] == "start_batch")
            .unwrap();
        assert_eq!(
            batch["operation_id"].as_str(),
            receipt.created_id.as_deref()
        );
        assert_eq!(batch["state"], "queued");
        assert!(!batch.to_string().contains("Work first"));
        assert_eq!(
            encode(&Reply::Receipt(receipt.clone())).unwrap(),
            encode(&s.execute(&lead, &command).unwrap()).unwrap()
        );
        let c = change(&s, &p);
        assert!(matches!(
            s.execute(
                &lead,
                &Command::Remove(Remove {
                    change: c,
                    member_id: receipt.created_ids[0].clone()
                })
            ),
            Err(Fault::Conflict)
        ));
        let c = change(&s, &p);
        assert!(matches!(
            s.execute(&lead, &Command::Close(c)),
            Err(Fault::Conflict)
        ));
        let claimed = s.next_effect().unwrap().unwrap();
        assert!(matches!(claimed.work, Work::StartBatch { .. }));
        let effect_id = claimed.effect_id;
        assert_eq!(receipt.created_id.as_deref(), Some(effect_id.as_str()));
        drop(s);
        let mut s = Store::open(&directory.path().join("pool.sqlite")).unwrap();
        assert!(
            s.pending_unknown()
                .unwrap()
                .iter()
                .any(|effect| effect.effect_id == effect_id && effect.state == "unknown")
        );
        let route = RunRoute {
            socket: "/fixture/run.sock".into(),
            expected_uid: 7,
            peer_uid: None,
            store_id: None,
        };
        assert!(s.freeze_run_route(&effect_id, &route, true).unwrap());
        assert!(!s.freeze_run_route(&effect_id, &route, true).unwrap());
        let store_identity = format!("store_{}", "1".repeat(32));
        s.record_run_store_id(&effect_id, &store_identity).unwrap();
        let mut changed_route = route.clone();
        changed_route.socket = "/different/run.sock".into();
        assert!(matches!(
            s.freeze_run_route(&effect_id, &changed_route, true),
            Err(Fault::Unavailable)
        ));
        let first_ref = format!("ex1_{}", "a".repeat(64));
        let second_ref = format!("ex1_{}", "b".repeat(64));
        let pin_one = format!("pin_{}", uuid::Uuid::new_v4().simple());
        let pin_two = format!("pin_{}", uuid::Uuid::new_v4().simple());
        assert!(matches!(
            s.record_batch_admission(
                &effect_id,
                Some(&store_identity),
                &[
                    (
                        "ag-20260230-010101-0123456789".into(),
                        1,
                        first_ref.clone(),
                        Some(pin_one.clone()),
                    ),
                    (
                        "ag-20261107-010101-0000000002".into(),
                        2,
                        second_ref.clone(),
                        Some(pin_two.clone()),
                    ),
                ],
            ),
            Err(Fault::Invalid)
        ));
        assert!(matches!(
            s.record_batch_admission(
                &effect_id,
                Some(&store_identity),
                &[(
                    "ag-20261107-010101-0000000001".into(),
                    1,
                    first_ref.clone(),
                    Some(pin_one.clone())
                )]
            ),
            Err(Fault::Conflict)
        ));
        assert!(matches!(
            s.record_batch_admission(
                &effect_id,
                Some(&store_identity),
                &[
                    (
                        "ag-20261107-010101-0000000001".into(),
                        1,
                        first_ref.clone(),
                        Some(pin_one.clone())
                    ),
                    (
                        "ag-20261107-010101-0000000001".into(),
                        2,
                        second_ref.clone(),
                        Some(pin_two.clone())
                    )
                ]
            ),
            Err(Fault::Invalid)
        ));
        assert!(matches!(
            s.record_batch_admission(
                &effect_id,
                Some(&store_identity),
                &[
                    (
                        "ag-20261107-010101-0000000001".into(),
                        1,
                        first_ref.clone(),
                        Some(pin_one.clone())
                    ),
                    (
                        "ag-20261107-010101-0000000002".into(),
                        2,
                        second_ref.clone(),
                        Some(pin_one.clone())
                    )
                ]
            ),
            Err(Fault::Invalid)
        ));
        assert!(matches!(
            s.record_batch_admission(
                &effect_id,
                Some(&store_identity),
                &[
                    (
                        "ag-20261107-010101-0000000001".into(),
                        1,
                        first_ref.clone(),
                        Some(pin_one.clone())
                    ),
                    (
                        "ag-20261107-010101-0000000002".into(),
                        2,
                        second_ref.clone(),
                        None
                    )
                ]
            ),
            Err(Fault::Invalid)
        ));
        assert!(matches!(
            s.record_batch_admission(
                &effect_id,
                Some(&store_identity),
                &[
                    (
                        "ag-20261107-010101-0000000001".into(),
                        1,
                        first_ref.clone(),
                        Some(pin_one.clone())
                    ),
                    (
                        "ag-20261107-010101-0000000002".into(),
                        2,
                        first_ref.clone(),
                        Some(pin_two.clone())
                    )
                ]
            ),
            Err(Fault::Invalid)
        ));
        for member_id in &receipt.created_ids {
            assert!(binding_any(&s.db, member_id).unwrap().0.run_id.is_none());
        }
        let admissions = [
            (
                "ag-20261107-010101-0000000001".into(),
                1,
                first_ref.clone(),
                Some(pin_one.clone()),
            ),
            (
                "ag-20261107-010101-0000000002".into(),
                2,
                second_ref.clone(),
                Some(pin_two.clone()),
            ),
        ];
        let effects_before = count(&s, "effects");
        s.db.execute_batch(r#"
            CREATE TABLE synthetic_commit_fault(id TEXT REFERENCES leaders(actor) DEFERRABLE INITIALLY DEFERRED);
            CREATE TRIGGER synthetic_fail_batch_commit AFTER INSERT ON effects
            WHEN NEW.data LIKE '%"kind":"resolve_run"%'
            BEGIN INSERT INTO synthetic_commit_fault(id) VALUES('missing-synthetic-leader'); END;
        "#).unwrap();
        assert!(matches!(
            s.record_batch_admission(&effect_id, Some(&store_identity), &admissions),
            Err(Fault::Internal)
        ));
        assert_eq!(effect(&s.db, &effect_id).unwrap().state, "unknown");
        assert_eq!(count(&s, "effects"), effects_before);
        for member_id in &receipt.created_ids {
            assert!(binding_any(&s.db, member_id).unwrap().0.run_id.is_none());
        }
        s.db.execute_batch(
            "DROP TRIGGER synthetic_fail_batch_commit; DROP TABLE synthetic_commit_fault;",
        )
        .unwrap();
        s.record_batch_admission(&effect_id, Some(&store_identity), &admissions)
            .unwrap();
        assert_eq!(effect(&s.db, &effect_id).unwrap().state, "accepted");
        assert_eq!(
            original_start_spec(&s.db, &p, &receipt.created_ids[0], Some(&store_identity)).unwrap(),
            Some(serde_json::json!({"task":"Work first","provider":"codex"}))
        );
        assert_eq!(
            original_start_spec(&s.db, &p, &receipt.created_ids[1], Some(&store_identity)).unwrap(),
            Some(serde_json::json!({"task":"Work second","provider":"codex"}))
        );
        s.settle_effect(&effect_id, "unknown").unwrap();
        assert_eq!(effect(&s.db, &effect_id).unwrap().state, "accepted");
        s.settle_effect(&effect_id, "refused").unwrap();
        assert_eq!(effect(&s.db, &effect_id).unwrap().state, "accepted");
        let before = count(&s, "effects");
        s.record_batch_admission(&effect_id, Some(&store_identity), &admissions)
            .unwrap();
        assert_eq!(count(&s, "effects"), before);
        assert!(matches!(
            s.record_batch_admission(
                &effect_id,
                Some(&store_identity),
                &[
                    (
                        "ag-20261107-010101-0000000001".into(),
                        1,
                        format!("ex1_{}", "c".repeat(64)),
                        Some(pin_one.clone())
                    ),
                    (
                        "ag-20261107-010101-0000000002".into(),
                        2,
                        second_ref.clone(),
                        Some(pin_two.clone())
                    )
                ]
            ),
            Err(Fault::Conflict)
        ));
        for (member_id, (agent_id, sequence, reference, pin)) in
            receipt.created_ids.iter().zip(&admissions)
        {
            let (binding, current) = binding_any(&s.db, member_id).unwrap();
            assert!(current);
            assert_eq!(binding.run_id.as_ref(), Some(agent_id));
            assert_eq!(binding.run_sequence, Some(*sequence));
            assert_eq!(binding.run_execution_ref.as_ref(), Some(reference));
            assert_eq!(&binding.run_pin_id, pin);
            assert!(
                s.pending_unknown()
                    .unwrap()
                    .iter()
                    .any(|effect| effect.member_id.as_ref() == Some(member_id)
                        && matches!(effect.work, Work::ResolveRun))
            );
        }
        let other_pool = make(&mut s, &lead, "other-pool");
        let c = change(&s, &other_pool);
        let Reply::Receipt(other) = s
            .execute(
                &lead,
                &Command::StartBatch(StartBatch {
                    change: c,
                    members: vec![member("other")],
                }),
            )
            .unwrap()
        else {
            panic!("receipt")
        };
        let other_effect = other.created_id.clone().unwrap();
        assert_eq!(s.next_effect().unwrap().unwrap().effect_id, other_effect);
        s.freeze_run_route(&other_effect, &route, false).unwrap();
        s.record_run_store_id(&other_effect, &store_identity)
            .unwrap();
        assert!(matches!(
            s.record_batch_admission(
                &other_effect,
                Some(&store_identity),
                &[(
                    "ag-20261107-010101-0000000005".into(),
                    1,
                    format!("ex1_{}", "d".repeat(64)),
                    Some(pin_one.clone())
                )]
            ),
            Err(Fault::Conflict)
        ));
        assert!(
            binding_any(&s.db, &other.created_ids[0])
                .unwrap()
                .0
                .run_pin_id
                .is_none()
        );
        assert!(matches!(
            s.record_batch_admission(
                &effect_id,
                Some(&store_identity),
                &[
                    (
                        "ag-20261107-010101-0000000009".into(),
                        1,
                        first_ref,
                        Some(pin_one)
                    ),
                    (
                        "ag-20261107-010101-0000000002".into(),
                        2,
                        second_ref,
                        Some(pin_two)
                    )
                ]
            ),
            Err(Fault::Conflict)
        ));
        let c = change(&s, &p);
        s.execute(
            &lead,
            &Command::Remove(Remove {
                change: c,
                member_id: receipt.created_ids[0].clone(),
            }),
        )
        .unwrap();
        assert!(
            s.pending_unknown()
                .unwrap()
                .iter()
                .any(
                    |effect| effect.member_id.as_ref() == Some(&receipt.created_ids[0])
                        && matches!(effect.work, Work::ResolveRun)
                )
        );
        let c = change(&s, &p);
        assert!(matches!(
            s.execute(
                &lead,
                &Command::ReleaseHistory(ReleaseHistory {
                    change: c,
                    member_id: receipt.created_ids[0].clone()
                })
            ),
            Err(Fault::Conflict)
        ));
        let c = change(&s, &p);
        s.execute(&lead, &Command::Close(c)).unwrap();
        let c = change(&s, &p);
        let release = Command::ReleaseHistory(ReleaseHistory {
            change: c,
            member_id: receipt.created_ids[0].clone(),
        });
        let first = s.execute(&lead, &release).unwrap();
        let Reply::Receipt(release_receipt) = &first else {
            panic!("receipt")
        };
        let release_effect = effect(&s.db, release_receipt.created_id.as_deref().unwrap()).unwrap();
        assert!(
            matches!(release_effect.work, Work::ReleasePin { ref pin_id, .. } if Some(pin_id) == admissions[0].3.as_ref())
        );
        assert_eq!(release_effect.state, "queued");
        assert!(
            !encode(&first)
                .unwrap()
                .contains(admissions[0].3.as_deref().unwrap())
        );
        assert_eq!(
            encode(&first).unwrap(),
            encode(&s.execute(&lead, &release).unwrap()).unwrap()
        );
        let c = change(&s, &p);
        assert!(matches!(
            s.execute(
                &lead,
                &Command::ReleaseHistory(ReleaseHistory {
                    change: c,
                    member_id: receipt.created_ids[0].clone()
                })
            ),
            Err(Fault::Conflict)
        ));
    }
    /// A definite refusal releases the roster fence without claiming any Run IDs.
    #[test]
    fn batch_refusal_notifies_owner_and_unblocks_roster() {
        let (_directory, mut s) = fixture();
        let lead = actor("lead");
        let p = make(&mut s, &lead, "refused");
        let c = change(&s, &p);
        let Reply::Receipt(receipt) = s
            .execute(
                &lead,
                &Command::StartBatch(StartBatch {
                    change: c,
                    members: vec![StartMember {
                        name: "Member".into(),
                        role: "Tester".into(),
                        task: "Check".into(),
                        spec: serde_json::json!({"task":"Check"}),
                    }],
                }),
            )
            .unwrap()
        else {
            panic!("receipt")
        };
        let effect = s.next_effect().unwrap().unwrap();
        s.settle_effect(&effect.effect_id, "refused").unwrap();
        let events = count(&s, "events");
        assert!(matches!(
            s.settle_effect(&effect.effect_id, "unknown"),
            Err(Fault::Conflict)
        ));
        assert_eq!(count(&s, "events"), events);
        assert_eq!(
            super::effect(&s.db, &effect.effect_id).unwrap().state,
            "refused"
        );
        assert!(matches!(
            s.settle_effect(&effect.effect_id, "accepted"),
            Err(Fault::Conflict)
        ));
        assert!(!batch_pending(&s.db, &p).unwrap());
        assert!(
            binding_any(&s.db, &receipt.created_ids[0])
                .unwrap()
                .0
                .run_id
                .is_none()
        );
        let owner_notified: bool = s.db.query_row("SELECT EXISTS(SELECT 1 FROM effects WHERE pool=?1 AND member IS NULL AND data LIKE '%Run batch admission refused%')", [&p], |row| row.get(0)).unwrap();
        assert!(owner_notified);
        let c = change(&s, &p);
        s.execute(&lead, &Command::Close(c)).unwrap();
    }
    /// A legacy unknown admission without a frozen route is never assigned a guessed destination.
    #[test]
    fn legacy_unknown_batch_does_not_invent_run_route() {
        let (directory, mut s) = fixture();
        let owner = actor("legacy-route-owner");
        let p = make(&mut s, &owner, "legacy-route");
        let c = change(&s, &p);
        s.execute(
            &owner,
            &Command::StartBatch(StartBatch {
                change: c,
                members: vec![StartMember {
                    name: "Member".into(),
                    role: "Tester".into(),
                    task: "Check".into(),
                    spec: serde_json::json!({"task":"Check"}),
                }],
            }),
        )
        .unwrap();
        let mut old_effect = s.next_effect().unwrap().unwrap();
        let Work::StartBatch {
            route_fence,
            route,
            retain_history,
            store_fence,
            ..
        } = &mut old_effect.work
        else {
            panic!("batch")
        };
        *route_fence = false;
        *retain_history = false;
        *store_fence = false;
        *route = None;
        s.db.execute(
            "UPDATE effects SET data=?2 WHERE id=?1",
            params![old_effect.effect_id, encode(&old_effect).unwrap()],
        )
        .unwrap();
        let id = old_effect.effect_id.clone();
        drop(s);
        let mut s = Store::open(&directory.path().join("pool.sqlite")).unwrap();
        s.settle_effect(&id, "refused").unwrap();
        assert_eq!(effect(&s.db, &id).unwrap().state, "unknown");
        let route = RunRoute {
            socket: "/fixture/run.sock".into(),
            expected_uid: 7,
            peer_uid: None,
            store_id: None,
        };
        assert!(matches!(
            s.freeze_run_route(&id, &route, true),
            Err(Fault::Unavailable)
        ));
        assert!(matches!(
            s.freeze_run_route(&id, &route, false),
            Err(Fault::Unavailable)
        ));
        let recovered = effect(&s.db, &id).unwrap();
        assert!(matches!(
            recovered.work,
            Work::StartBatch { route: None, .. }
        ));
        assert_eq!(recovered.state, "unknown");
        let mut old = recovered;
        let Work::StartBatch {
            route: old_route, ..
        } = &mut old.work
        else {
            panic!("batch")
        };
        *old_route = Some(route);
        s.db.execute(
            "UPDATE effects SET data=?2 WHERE id=?1",
            params![id, encode(&old).unwrap()],
        )
        .unwrap();
        let frozen = encode(&old.work).unwrap();
        assert!(matches!(
            s.record_run_store_id(&old.effect_id, &format!("store_{}", "1".repeat(32))),
            Err(Fault::Unavailable)
        ));
        let unchanged = effect(&s.db, &old.effect_id).unwrap();
        assert_eq!(unchanged.state, "unknown");
        assert_eq!(encode(&unchanged.work).unwrap(), frozen);
    }
    /// A legacy pin without a proven origin records a release intent but no callable Run route.
    #[test]
    fn legacy_pin_release_remains_unroutable() {
        let (_directory, mut s) = fixture();
        let owner = actor("legacy-pin-owner");
        let member = actor("legacy-pin-member");
        let p = make(&mut s, &owner, "legacy-pin");
        let member_id = add(&mut s, &owner, &p, &member);
        let (mut binding, current) = binding_any(&s.db, &member_id).unwrap();
        binding.run_id = Some("legacy-run".into());
        binding.run_sequence = Some(1);
        binding.run_pin_id = Some(format!("pin_{}", uuid::Uuid::new_v4().simple()));
        binding.run_store_id = None;
        save_binding(&s.db, &binding, current).unwrap();
        let c = change(&s, &p);
        s.execute(&owner, &Command::Close(c)).unwrap();
        let c = change(&s, &p);
        let Reply::Receipt(receipt) = s
            .execute(
                &owner,
                &Command::ReleaseHistory(ReleaseHistory {
                    change: c,
                    member_id,
                }),
            )
            .unwrap()
        else {
            panic!("receipt")
        };
        let intent = effect(&s.db, receipt.created_id.as_deref().unwrap()).unwrap();
        assert!(matches!(intent.work, Work::ReleasePin { route: None, .. }));
    }
    /// A scalar start rechecks membership atomically before its first send and every retry.
    #[test]
    fn run_start_route_freeze_rechecks_current_member() {
        for (legacy, freeze_before_removal) in
            [(false, false), (false, true), (true, false), (true, true)]
        {
            let (_directory, mut s) = fixture();
            let owner = actor("route-member-owner");
            let pool = make(&mut s, &owner, "route-member");
            let c = change(&s, &pool);
            let Reply::Receipt(receipt) = s
                .execute(
                    &owner,
                    &Command::Start(Start {
                        change: c,
                        name: "Pending".into(),
                        role: "Test".into(),
                        task: "Verify".into(),
                        spec: serde_json::json!({"task":"Verify"}),
                    }),
                )
                .unwrap()
            else {
                panic!("receipt")
            };
            let member = receipt.created_id.unwrap();
            let start = s.next_effect().unwrap().unwrap();
            let start = if legacy {
                s.fixture_legacy_start(&start.effect_id).unwrap()
            } else {
                start
            };
            assert!(s.effect_binding(&start.effect_id).unwrap().unwrap().1);
            let route = RunRoute {
                socket: "/fixture/run.sock".into(),
                expected_uid: 7,
                peer_uid: None,
                store_id: None,
            };
            if freeze_before_removal {
                assert!(s.freeze_run_route(&start.effect_id, &route, false).unwrap());
                s.settle_effect(&start.effect_id, "unknown").unwrap();
            }
            let c = change(&s, &pool);
            s.execute(
                &owner,
                &Command::Remove(Remove {
                    change: c,
                    member_id: member,
                }),
            )
            .unwrap();
            assert!(matches!(
                s.freeze_run_route(&start.effect_id, &route, freeze_before_removal),
                Err(Fault::Unavailable)
            ));
            let stored = effect(&s.db, &start.effect_id).unwrap();
            assert_eq!(
                stored.state,
                if freeze_before_removal {
                    "unknown"
                } else {
                    "inflight"
                }
            );
            let route = match &stored.work {
                Work::Start { route, .. } | Work::StartBatch { route, .. } => route,
                _ => panic!("start"),
            };
            assert_eq!(route.is_some(), freeze_before_removal);
        }
    }
    /// Concurrent dispatchers can reserve the first external transmission only once.
    #[test]
    fn concurrent_route_freeze_has_one_fresh_winner() {
        let (_directory, mut s) = fixture();
        let owner = actor("route-owner");
        let p = make(&mut s, &owner, "route");
        let c = change(&s, &p);
        s.execute(
            &owner,
            &Command::StartBatch(StartBatch {
                change: c,
                members: vec![StartMember {
                    name: "Member".into(),
                    role: "Tester".into(),
                    task: "Check".into(),
                    spec: serde_json::json!({"task":"Check"}),
                }],
            }),
        )
        .unwrap();
        let id = s.next_effect().unwrap().unwrap().effect_id;
        let route = RunRoute {
            socket: "/fixture/run.sock".into(),
            expected_uid: 7,
            peer_uid: None,
            store_id: None,
        };
        let store = std::sync::Arc::new(std::sync::Mutex::new(s));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut results = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..2)
                .map(|_| {
                    let store = store.clone();
                    let barrier = barrier.clone();
                    let id = id.clone();
                    let route = route.clone();
                    scope.spawn(move || {
                        barrier.wait();
                        store
                            .lock()
                            .unwrap()
                            .freeze_run_route(&id, &route, false)
                            .unwrap()
                    })
                })
                .collect();
            barrier.wait();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });
        results.sort_unstable();
        assert_eq!(results, [false, true]);
    }
    /// Enrichment cannot push a group beyond the Run frame and leave local reservations behind.
    #[test]
    fn batch_enrichment_over_frame_limit_rolls_back() {
        let (_directory, mut s) = fixture();
        let lead = actor("lead");
        let p = make(&mut s, &lead, "frame");
        let members = (0..17)
            .map(|index| StartMember {
                name: format!("member-{index}"),
                role: "Tester".into(),
                task: "Verify".into(),
                spec: serde_json::json!({"task":"x".repeat(61000)}),
            })
            .collect();
        let command = Command::StartBatch(StartBatch {
            change: change(&s, &p),
            members,
        });
        assert!(serde_json::to_vec(&command).unwrap().len() < crate::integrations::MAX_FRAME);
        let before = (
            count(&s, "members"),
            count(&s, "events"),
            count(&s, "effects"),
        );
        assert!(matches!(s.execute(&lead, &command), Err(Fault::Invalid)));
        assert_eq!(
            (
                count(&s, "members"),
                count(&s, "events"),
                count(&s, "effects")
            ),
            before
        );
        assert_eq!(pool(&s.db, &p).unwrap().0.revision, 1);
    }
    /// Crash recovery preserves uncertain effects and a second resident cannot take the writer lease.
    #[test]
    fn crash_recovery_and_frozen_publication_are_fail_closed() {
        let (d, mut s) = fixture();
        assert!(matches!(
            Store::open(&d.path().join("pool.sqlite")),
            Err(Fault::Conflict)
        ));
        let lead = actor("lead");
        let a = actor("a");
        let p = make(&mut s, &lead, "one");
        add(&mut s, &lead, &p, &a);
        let e = s.next_effect().unwrap().unwrap();
        let original =
            serde_json::json!({"destination":a.address,"event_id":e.effect_id,"payload":"frozen"});
        s.freeze_publication(&e.effect_id, "pool", &original)
            .unwrap();
        assert!(matches!(
            s.freeze_publication(&e.effect_id, "other", &original),
            Err(Fault::Conflict)
        ));
        drop(s);
        let mut s = Store::open(&d.path().join("pool.sqlite")).unwrap();
        let unknown = s.pending_unknown().unwrap();
        assert!(unknown.iter().any(|x| x.effect_id == e.effect_id));
        assert_eq!(
            s.freeze_publication(&e.effect_id, "pool", &original)
                .unwrap()
                .1,
            original
        );
    }
    /// Run intent keeps the original enriched specification and immediate admission across removal.
    #[test]
    fn run_admission_is_durable_before_native_binding() {
        let (_d, mut s) = fixture();
        let lead = actor("lead");
        let p = make(&mut s, &lead, "one");
        let c = change(&s, &p);
        let reply=s.execute(&lead,&Command::Start(Start{change:c,name:"Run member".into(),role:"Tester".into(),task:"Verify".into(),spec:serde_json::json!({"task":"Original","workdir":"/known","provider":"codex"})})).unwrap();
        let mid = match reply {
            Reply::Receipt(r) => r.created_id.unwrap(),
            _ => panic!("receipt"),
        };
        let effect = s.next_effect().unwrap().unwrap();
        let effect = s.fixture_legacy_start(&effect.effect_id).unwrap();
        let Work::Start {
            ref spec,
            ref request_key,
            ..
        } = effect.work
        else {
            panic!("start")
        };
        assert!(request_key.starts_with("agent-pool."));
        assert!(spec["task"].as_str().unwrap().starts_with("Original"));
        assert!(spec["task"].as_str().unwrap().contains("pool_join"));
        assert!(
            spec["required_mcp"]["agent-pool"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("pool_join"))
        );
        assert!(matches!(
            s.record_run_admission(&effect.effect_id, "agent-new", 1),
            Err(Fault::Invalid)
        ));
        assert!(binding_any(&s.db, &mid).unwrap().0.run_id.is_none());
        s.record_run_admission(&effect.effect_id, "ag-20261107-010101-0000000006", 1)
            .unwrap();
        assert_eq!(
            binding_any(&s.db, &mid).unwrap().0.run_id.as_deref(),
            Some("ag-20261107-010101-0000000006")
        );
        let c = change(&s, &p);
        s.execute(
            &lead,
            &Command::Remove(Remove {
                change: c,
                member_id: mid.clone(),
            }),
        )
        .unwrap();
        s.bind_run(&effect.effect_id, "codex:test:store:new")
            .unwrap();
        assert!(!binding_any(&s.db, &mid).unwrap().1);
        assert!(s.observation_targets().unwrap().is_empty());
        let mut final_count = 0;
        while let Some(e) = s.next_effect().unwrap() {
            if let Work::Deliver { scope, text, .. } = e.work {
                assert!(scope.starts_with("final:"));
                assert!(text.contains("Access revoked"));
                final_count += 1;
            }
        }
        assert_eq!(final_count, 1);
        s.bind_run(&effect.effect_id, "codex:test:store:new")
            .unwrap();
        assert!(s.next_effect().unwrap().is_none());
    }
    /// Pending Run recipients keep messages until their exact private binding becomes available.
    #[test]
    fn pending_messages_wait_for_binding_and_never_change_payload() {
        let (_d, mut s) = fixture();
        let lead = actor("lead");
        let p = make(&mut s, &lead, "one");
        let c = change(&s, &p);
        let reply=s.execute(&lead,&Command::Start(Start{change:c,name:"Run".into(),role:"Test".into(),task:"Verify".into(),spec:serde_json::json!({"task":"Original","provider":"codex","model":"test","profile":"implement","workdir":"/known"})})).unwrap();
        let mid = match reply {
            Reply::Receipt(r) => r.created_id.unwrap(),
            _ => panic!("receipt"),
        };
        let start = s.next_effect().unwrap().unwrap();
        let start = s.fixture_legacy_start(&start.effect_id).unwrap();
        assert!(matches!(start.work, Work::Start { .. }));
        let c = change(&s, &p);
        s.execute(
            &lead,
            &Command::Send(Direct {
                change: c,
                member_id: mid.clone(),
                body: "Do not lose this".into(),
            }),
        )
        .unwrap();
        assert!(s.next_effect().unwrap().is_none());
        s.record_run_admission(&start.effect_id, "ag-20261107-010101-0000000007", 1)
            .unwrap();
        s.bind_run(&start.effect_id, "native:exact").unwrap();
        let mut delivered = false;
        while let Some(e) = s.next_effect().unwrap() {
            if let Work::Deliver { address, text, .. } = e.work {
                assert_eq!(address, "native:exact");
                delivered |= text.contains("Do not lose this");
            }
        }
        assert!(delivered);
    }
    /// Twenty maximum-size assignments and quoted proposal data remain retrievable without skipping rows.
    #[test]
    fn maximum_content_fits_notifications_and_paginated_presentation() {
        let (_d, mut s) = fixture();
        let lead = actor("lead");
        let p = make(&mut s, &lead, "one");
        let a = actor("member0");
        for index in 0..MAX_MEMBERS {
            let c = change(&s, &p);
            s.execute(
                &lead,
                &Command::Add(Add {
                    change: c,
                    address: actor(&format!("member{index}")).address,
                    name: "\\".repeat(80),
                    role: "\\".repeat(160),
                    task: "\\".repeat(512),
                }),
            )
            .unwrap();
        }
        join(&mut s, &a, &p);
        let c = change(&s, &p);
        s.execute(
            &lead,
            &Command::Propose(Propose {
                change: c,
                result: "\\".repeat(MAX_TEXT),
                criteria: "\\".repeat(MAX_TEXT),
                snapshot: None,
            }),
        )
        .unwrap();
        let templates = crate::response::Templates::new(&crate::tools::templates()).unwrap();
        let c = change(&s, &p);
        let message = s
            .execute(
                &lead,
                &Command::Post(Message {
                    change: c,
                    body: "\\".repeat(MAX_MESSAGE),
                }),
            )
            .unwrap();
        let preview = serde_json::to_value(crate::tools::present(Ok(message), &templates)).unwrap();
        let preview = preview["content"][0]["text"].as_str().unwrap();
        assert!(!preview.contains("presentation degraded"));
        assert!(preview.contains("has 4 history parts"));
        let delivery: String =
            s.db.query_row(
                "SELECT data FROM effects WHERE pool=?1 ORDER BY sequence DESC LIMIT 1",
                [&p],
                |row| row.get(0),
            )
            .unwrap();
        let delivery: Effect = decode(&delivery).unwrap();
        let Work::Deliver { text, .. } = delivery.work else {
            panic!("delivery")
        };
        assert!(text.contains("part 1/4"));
        assert!(text.len() <= 16384);
        for who in [&lead, &a] {
            for section in [
                Section::Overview,
                Section::Members,
                Section::History,
                Section::Proposal,
                Section::Votes,
                Section::Deliveries,
            ] {
                let mut cursor = 0;
                loop {
                    let reply = s
                        .execute(
                            who,
                            &Command::Get(Get {
                                pool_id: p.clone(),
                                after: cursor,
                                section: section.clone(),
                                proposal_id: None,
                                member_id: None,
                                wait_seconds: 0.0,
                                reverse: false,
                                before: None,
                                field: None,
                                expected_revision: None,
                            }),
                        )
                        .unwrap();
                    let view = match &reply {
                        Reply::View(v) | Reply::OwnerView { view: v, .. } => v,
                        _ => panic!("view"),
                    };
                    let more = view.has_more;
                    let next = view.next_after;
                    let result = crate::tools::present(Ok(reply), &templates);
                    let encoded = serde_json::to_value(result).unwrap();
                    let text = encoded["content"][0]["text"].as_str().unwrap();
                    assert!(!text.contains("presentation degraded"), "{text}");
                    assert!(text.len() <= 16384);
                    if !more {
                        break;
                    }
                    assert!(next > cursor);
                    cursor = next;
                }
            }
        }
    }
    /// A permanent unknown head cannot starve later custody work, and owner failures stay inspectable.
    #[test]
    fn reconciliation_rotates_and_owner_failures_do_not_recurse() {
        let (_d, mut s) = fixture();
        let lead = actor("lead");
        let p = make(&mut s, &lead, "one");
        for _ in 0..40 {
            queue_delivery(&s.db, &p, None, &lead.address, "owner", "test".into(), None).unwrap();
        }
        s.db.execute("UPDATE effects SET state='custody'", [])
            .unwrap();
        let first = s.pending_unknown().unwrap();
        let second = s.pending_unknown().unwrap();
        assert_eq!(first.len(), 32);
        assert_eq!(second.len(), 8);
        assert!(
            !first
                .iter()
                .any(|a| second.iter().any(|b| a.effect_id == b.effect_id))
        );
        let before = count(&s, "events");
        s.settle_effect(&first[0].effect_id, "refused").unwrap();
        assert_eq!(count(&s, "events"), before + 1);
        assert_eq!(count(&s, "effects"), 40);
        s.settle_effect(&first[1].effect_id, "refused").unwrap();
        assert_eq!(count(&s, "events"), before + 2);
    }
    /// Accepted decisions remain independently readable after a later proposal replaces the current one.
    #[test]
    fn accepted_decision_archive_is_immutable_and_scoped() {
        let (_d, mut s) = fixture();
        let lead = actor("lead");
        let a = actor("a");
        let p = make(&mut s, &lead, "one");
        add(&mut s, &lead, &p, &a);
        join(&mut s, &a, &p);
        let c = change(&s, &p);
        s.execute(
            &a,
            &Command::Propose(Propose {
                change: c,
                result: "First".into(),
                criteria: "Exact".into(),
                snapshot: None,
            }),
        )
        .unwrap();
        let pr = pool(&s.db, &p).unwrap().0.proposal.unwrap();
        let c = change(&s, &p);
        s.execute(
            &a,
            &Command::Vote(Vote {
                change: c,
                proposal_id: pr.proposal_id.clone(),
                roster_key: pr.roster_key,
                choice: Choice::Ready,
                evidence: "proof".into(),
                checks: Vec::new(),
            }),
        )
        .unwrap();
        let c = change(&s, &p);
        s.execute(
            &a,
            &Command::Propose(Propose {
                change: c,
                result: "Second".into(),
                criteria: "New".into(),
                snapshot: None,
            }),
        )
        .unwrap();
        let reply = s
            .execute(
                &a,
                &Command::Get(Get {
                    pool_id: p,
                    after: 0,
                    section: Section::Proposal,
                    proposal_id: Some(pr.proposal_id),
                    member_id: None,
                    wait_seconds: 0.0,
                    reverse: false,
                    before: None,
                    field: None,
                    expected_revision: None,
                }),
            )
            .unwrap();
        let Reply::View(v) = reply else {
            panic!("view")
        };
        let old = v.pool.proposal.unwrap();
        assert_eq!(old.state, ProposalState::Accepted);
        assert_eq!(old.result, "First");
    }
    /// A changed binding cannot join using an earlier provider precheck, even with a current revision.
    #[test]
    fn join_fence_rejects_changed_binding_before_committing() {
        let (_d, mut s) = fixture();
        let lead = actor("lead");
        let a = actor("a");
        let p = make(&mut s, &lead, "one");
        let mid = add(&mut s, &lead, &p, &a);
        let checked = s.join_binding(&a, &p).unwrap();
        let c = change(&s, &p);
        s.execute(
            &lead,
            &Command::MemberUpdate(MemberUpdate {
                change: c,
                member_id: mid.clone(),
                name: "Changed".into(),
                role: "Changed role".into(),
                task: "Changed task".into(),
            }),
        )
        .unwrap();
        let join = Command::Join(change(&s, &p));
        let events = count(&s, "events");
        assert!(matches!(
            s.execute_join(&a, &join, &checked),
            Err(Fault::Stale)
        ));
        assert_eq!(count(&s, "events"), events);
        assert_eq!(
            binding_any(&s.db, &mid).unwrap().0.member.state,
            MemberState::Pending
        );
        let checked = s.join_binding(&a, &p).unwrap();
        s.execute_join(&a, &join, &checked).unwrap();
        assert_eq!(
            binding_any(&s.db, &mid).unwrap().0.member.state,
            MemberState::Active
        );
    }
    /// A start provably cancelled before admission leaves no impossible final-notice delivery pending.
    #[test]
    fn removed_unadmitted_start_cancels_unresolvable_final_notice() {
        let (_d, mut s) = fixture();
        let lead = actor("lead");
        let p = make(&mut s, &lead, "one");
        let c = change(&s, &p);
        let reply=s.execute(&lead,&Command::Start(Start{change:c,name:"Pending".into(),role:"Test".into(),task:"Verify".into(),spec:serde_json::json!({"task":"Original","provider":"codex","model":"test","profile":"implement","workdir":"/known"})})).unwrap();
        let mid = match reply {
            Reply::Receipt(r) => r.created_id.unwrap(),
            _ => panic!("receipt"),
        };
        let effect = s.next_effect().unwrap().unwrap();
        let c = change(&s, &p);
        s.execute(
            &lead,
            &Command::Remove(Remove {
                change: c,
                member_id: mid.clone(),
            }),
        )
        .unwrap();
        let before: i64 =
            s.db.query_row(
                "SELECT count(*) FROM effects WHERE member=?1 AND state='awaiting_binding'",
                [&mid],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(before, 1);
        s.settle_effect(&effect.effect_id, "cancelled").unwrap();
        let events = count(&s, "events");
        assert!(matches!(
            s.settle_effect(&effect.effect_id, "unknown"),
            Err(Fault::Conflict)
        ));
        assert_eq!(count(&s, "events"), events);
        assert_eq!(
            super::effect(&s.db, &effect.effect_id).unwrap().state,
            "cancelled"
        );
        assert!(matches!(
            s.settle_effect(&effect.effect_id, "refused"),
            Err(Fault::Conflict)
        ));
        let route = RunRoute {
            socket: "/fixture/run.sock".into(),
            expected_uid: 7,
            peer_uid: None,
            store_id: None,
        };
        assert!(matches!(
            s.freeze_run_route(&effect.effect_id, &route, false),
            Err(Fault::Unavailable)
        ));
        let after: i64 =
            s.db.query_row(
                "SELECT count(*) FROM effects WHERE member=?1 AND state='awaiting_binding'",
                [&mid],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(after, 0);
        while let Some(e) = s.next_effect().unwrap() {
            assert!(!matches!(e.work, Work::Deliver { .. }));
        }
    }
    /// A legacy start without a saved route cannot become a proven cancellation or refusal.
    #[test]
    fn unknown_legacy_start_cannot_be_cancelled_or_refused() {
        let (_directory, mut s) = fixture();
        let lead = actor("lead");
        let p = make(&mut s, &lead, "legacy-unknown-start");
        let c = change(&s, &p);
        s.execute(
            &lead,
            &Command::Start(Start {
                change: c,
                name: "Pending".into(),
                role: "Test".into(),
                task: "Verify".into(),
                spec: serde_json::json!({"task":"Verify"}),
            }),
        )
        .unwrap();
        let pending = s.next_effect().unwrap().unwrap();
        let mut pending = s.fixture_legacy_start(&pending.effect_id).unwrap();
        let Work::Start { route_fence, .. } = &mut pending.work else {
            panic!("expected start");
        };
        *route_fence = false;
        s.db.execute(
            "UPDATE effects SET data=?2 WHERE id=?1",
            params![pending.effect_id, encode(&pending).unwrap()],
        )
        .unwrap();
        s.settle_effect(&pending.effect_id, "cancelled").unwrap();
        assert_eq!(effect(&s.db, &pending.effect_id).unwrap().state, "unknown");
        s.settle_effect(&pending.effect_id, "refused").unwrap();
        assert_eq!(effect(&s.db, &pending.effect_id).unwrap().state, "unknown");
    }
    /// Revising an open proposal archives its evidence as stale and requires fresh unanimous votes.
    #[test]
    fn proposal_revision_preserves_previous_votes_and_resets_readiness() {
        let (_d, mut s) = fixture();
        let lead = actor("lead");
        let a = actor("a");
        let b = actor("b");
        let p = make(&mut s, &lead, "one");
        add(&mut s, &lead, &p, &a);
        join(&mut s, &a, &p);
        add(&mut s, &lead, &p, &b);
        join(&mut s, &b, &p);
        let c = change(&s, &p);
        s.execute(
            &a,
            &Command::Propose(Propose {
                change: c,
                result: "First".into(),
                criteria: "Original".into(),
                snapshot: None,
            }),
        )
        .unwrap();
        let old = pool(&s.db, &p).unwrap().0.proposal.unwrap();
        let c = change(&s, &p);
        s.execute(
            &a,
            &Command::Vote(Vote {
                change: c,
                proposal_id: old.proposal_id.clone(),
                roster_key: old.roster_key.clone(),
                choice: Choice::Ready,
                evidence: "original proof".into(),
                checks: Vec::new(),
            }),
        )
        .unwrap();
        let c = change(&s, &p);
        s.execute(
            &b,
            &Command::Propose(Propose {
                change: c,
                result: "Revised".into(),
                criteria: "Corrected".into(),
                snapshot: None,
            }),
        )
        .unwrap();
        let latest = pool(&s.db, &p).unwrap().0.proposal.unwrap();
        assert_ne!(latest.proposal_id, old.proposal_id);
        assert_eq!(latest.state, ProposalState::Open);
        assert!(latest.votes.is_empty());
        let old_json: String =
            s.db.query_row(
                "SELECT data FROM proposals WHERE id=?1",
                [&old.proposal_id],
                |r| r.get(0),
            )
            .unwrap();
        let archived: Proposal = decode(&old_json).unwrap();
        assert_eq!(archived.state, ProposalState::Stale);
        assert_eq!(
            archived.votes.values().next().unwrap().evidence,
            "original proof"
        );
        let c = change(&s, &p);
        assert!(matches!(
            s.execute(
                &a,
                &Command::Vote(Vote {
                    change: c,
                    proposal_id: old.proposal_id,
                    roster_key: old.roster_key,
                    choice: Choice::Ready,
                    evidence: "old".into(),
                    checks: Vec::new(),
                })
            ),
            Err(Fault::Stale)
        ));
    }
    /// The owner retains exact removed mappings for independent process control; peers never receive them.
    #[test]
    fn historical_binding_is_owner_only_after_removal() {
        let (_d, mut s) = fixture();
        let lead = actor("lead");
        let a = actor("private-native-address");
        let b = actor("peer");
        let p = make(&mut s, &lead, "one");
        let mid = add(&mut s, &lead, &p, &a);
        join(&mut s, &a, &p);
        add(&mut s, &lead, &p, &b);
        join(&mut s, &b, &p);
        let c = change(&s, &p);
        s.execute(
            &lead,
            &Command::Remove(Remove {
                change: c,
                member_id: mid.clone(),
            }),
        )
        .unwrap();
        let query = Command::Get(Get {
            pool_id: p,
            after: 0,
            section: Section::Binding,
            proposal_id: None,
            member_id: Some(mid),
            wait_seconds: 0.0,
            reverse: false,
            before: None,
            field: None,
            expected_revision: None,
        });
        assert!(matches!(s.execute(&b, &query), Err(Fault::Forbidden)));
        assert!(matches!(s.execute(&a, &query), Err(Fault::Forbidden)));
        let Reply::OwnerView { bindings, .. } = s.execute(&lead, &query).unwrap() else {
            panic!("owner view")
        };
        assert_eq!(bindings[0].address.as_deref(), Some(a.address.as_str()));
        assert_eq!(bindings[0].member.state, MemberState::Removed);
    }
    /// Refusing a future database must leave its bytes and journal mode unchanged.
    #[test]
    fn future_schema_refuses_before_mutating_database() {
        let (d, s) = fixture();
        drop(s);
        let path = d.path().join("future.sqlite");
        let db = Connection::open(&path).unwrap();
        db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA user_version=999; CREATE TABLE retained(value TEXT);").unwrap();
        drop(db);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(matches!(Store::open(&path), Err(Fault::Conflict)));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
    /// V1–v5 data and their original receipts survive all semantic-schema upgrades.
    #[test]
    fn older_schema_upgrade_preserves_pool_and_receipts() {
        for prior_version in [1, 2, 3, 4, 5] {
            let (directory, mut store) = fixture();
            let owner = actor("upgrade-owner");
            let command = Command::Create(Create {
                request_key: "upgrade".into(),
                name: "Pool".into(),
                purpose: "Existing".into(),
                acceptance: None,
            });
            let before = store.execute(&owner, &command).unwrap();
            let Reply::Receipt(created) = &before else {
                panic!("create receipt")
            };
            let start = Command::Start(Start {
                change: Change {
                    pool_id: created.pool_id.clone(),
                    expected_revision: created.revision,
                    request_key: "old-start".into(),
                },
                name: "Legacy".into(),
                role: "Test".into(),
                task: "Verify".into(),
                spec: serde_json::json!({"task":"Verify"}),
            });
            let start_receipt = store.execute(&owner, &start).unwrap();
            let claimed = store.next_effect().unwrap().unwrap();
            let mut legacy = if prior_version >= 3 {
                claimed
            } else {
                store.fixture_legacy_start(&claimed.effect_id).unwrap()
            };
            if prior_version == 1 {
                let Work::Start { route_fence, .. } = &mut legacy.work else {
                    panic!("legacy start")
                };
                *route_fence = false;
            } else if prior_version == 3 {
                let Work::StartBatch { jobs, .. } = &mut legacy.work else {
                    panic!("legacy batch")
                };
                jobs[0].original_spec = None;
            }
            store
                .db
                .execute(
                    "UPDATE effects SET data=?2 WHERE id=?1",
                    params![legacy.effect_id, encode(&legacy).unwrap()],
                )
                .unwrap();
            let frozen = encode(&legacy.work).unwrap();
            // Remove newer objects to construct the corresponding old-schema fixture.
            crate::managed_egress::drop_test_schema(&store.db).unwrap();
            store.db.execute_batch("DROP TABLE managed_invalidated_ballots; DROP TABLE managed_ballot_provenance; DROP TABLE managed_domain_keys; DROP TABLE managed_intents; DROP TABLE managed_current_requests; DROP TABLE managed_context_epochs; DROP TABLE managed_context_bindings; DROP TABLE managed_contexts; DROP TABLE managed_bootstrap; DROP TABLE managed_namespaces; DROP TABLE managed_run_routes; DROP TABLE managed_bridge_routes; DROP TABLE managed_rebinds; DROP TABLE managed_bindings; DROP TABLE managed_pool_epochs;").unwrap();
            let mut stmt = store.db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE 'inventory_rev_%'").unwrap();
            let triggers: Vec<String> = stmt
                .query_map([], |row| row.get(0))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            drop(stmt);
            for trigger in triggers {
                store
                    .db
                    .execute_batch(&format!("DROP TRIGGER {trigger}"))
                    .unwrap();
            }
            store
                .db
                .execute_batch("DROP TABLE inventory_source")
                .unwrap();
            if prior_version < 5 {
                store.db.execute_batch("DROP TABLE member_slots").unwrap();
            }
            store
                .db
                .execute_batch(crate::completion::TEST_DROP_SCHEMA)
                .unwrap();
            store
                .db
                .execute_batch(&format!("PRAGMA user_version={prior_version}"))
                .unwrap();
            drop(store);
            let mut upgraded = Store::open(&directory.path().join("pool.sqlite")).unwrap();
            let version: i64 = upgraded
                .db
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap();
            assert_eq!(version, crate::completion::SCHEMA_VERSION);
            assert_eq!(
                encode(&before).unwrap(),
                encode(&upgraded.execute(&owner, &command).unwrap()).unwrap()
            );
            assert_eq!(
                encode(&start_receipt).unwrap(),
                encode(&upgraded.execute(&owner, &start).unwrap()).unwrap()
            );
            let recovered = effect(&upgraded.db, &legacy.effect_id).unwrap();
            assert_eq!(recovered.state, "unknown");
            assert_eq!(encode(&recovered.work).unwrap(), frozen);
            assert_eq!(count(&upgraded, "pools"), 1);
            assert_eq!(count(&upgraded, "events"), 2);
        }
    }
    /// Version 6/7 upgrades retain source identity, do not promote old members, and survive reopen.
    #[test]
    fn managed_schema_migration_preserves_v6_v7_source() {
        for prior in [6, 7] {
            let (directory, mut store) = fixture();
            let owner = actor("migration-managed");
            let pool_id = make(&mut store, &owner, "existing");
            let member = actor("migration-member");
            add(&mut store, &owner, &pool_id, &member);
            let source: String = store
                .db
                .query_row("SELECT store_id FROM inventory_source", [], |row| {
                    row.get(0)
                })
                .unwrap();
            crate::managed_egress::drop_test_schema(&store.db).unwrap();
            store.db.execute_batch("DROP TABLE managed_invalidated_ballots; DROP INDEX managed_current_state_owner; ALTER TABLE managed_current_requests DROP COLUMN owner_intent; ALTER TABLE managed_bindings DROP COLUMN incarnation; DROP INDEX managed_bootstrap_state; DROP INDEX managed_intent_state; DROP TABLE managed_ballot_provenance; DROP TABLE managed_domain_keys; DROP TABLE managed_intents;").unwrap();
            if prior == 6 {
                store.db.execute_batch("DROP TABLE managed_current_requests; DROP TABLE managed_context_epochs; DROP TABLE managed_context_bindings; DROP TABLE managed_contexts; DROP TABLE managed_bootstrap; DROP TABLE managed_namespaces; DROP TABLE managed_run_routes; DROP TABLE managed_bridge_routes; DROP TABLE managed_rebinds; DROP TABLE managed_bindings; DROP TABLE managed_pool_epochs;").unwrap();
            }
            store
                .db
                .execute_batch(crate::completion::TEST_DROP_SCHEMA)
                .unwrap();
            store
                .db
                .execute_batch(&format!("PRAGMA user_version={prior}"))
                .unwrap();
            drop(store);
            let upgraded = Store::open(&directory.path().join("pool.sqlite")).unwrap();
            let version: i64 = upgraded
                .db
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap();
            assert_eq!(version, crate::completion::SCHEMA_VERSION);
            let retained: String = upgraded
                .db
                .query_row("SELECT store_id FROM inventory_source", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(source, retained);
            assert_eq!(count(&upgraded, "managed_bindings"), 0);
            assert_eq!(count(&upgraded, "managed_ballot_provenance"), 0);
            assert_eq!(count(&upgraded, "pools"), 1);
            drop(upgraded);
            assert!(Store::open(&directory.path().join("pool.sqlite")).is_ok());
        }
    }
    /// A failed numbered migration rolls back its intermediate schema and version.
    #[test]
    fn managed_migration_failure_rolls_back_v6() {
        let (directory, mut store) = fixture();
        let owner = actor("migration-rollback");
        make(&mut store, &owner, "retained");
        let source: String = store
            .db
            .query_row("SELECT store_id FROM inventory_source", [], |row| {
                row.get(0)
            })
            .unwrap();
        crate::managed_egress::drop_test_schema(&store.db).unwrap();
        store.db.execute_batch("DROP TABLE managed_invalidated_ballots; DROP TABLE managed_ballot_provenance; DROP TABLE managed_domain_keys; DROP TABLE managed_intents; DROP TABLE managed_current_requests; DROP TABLE managed_context_epochs; DROP TABLE managed_context_bindings; DROP TABLE managed_contexts; DROP TABLE managed_bootstrap; DROP TABLE managed_namespaces; DROP TABLE managed_run_routes; DROP TABLE managed_bridge_routes; DROP TABLE managed_rebinds; DROP TABLE managed_bindings; DROP TABLE managed_pool_epochs; CREATE TABLE managed_contexts(sentinel TEXT); INSERT INTO managed_contexts VALUES('retained'); PRAGMA user_version=6;").unwrap();
        drop(store);
        assert!(Store::open(&directory.path().join("pool.sqlite")).is_err());
        let db = Connection::open(directory.path().join("pool.sqlite")).unwrap();
        let version: i64 = db
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        let retained: String = db
            .query_row("SELECT store_id FROM inventory_source", [], |row| {
                row.get(0)
            })
            .unwrap();
        let sentinel: String = db
            .query_row("SELECT sentinel FROM managed_contexts", [], |row| {
                row.get(0)
            })
            .unwrap();
        let intermediate:i64=db.query_row("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='managed_pool_epochs'",[],|row|row.get(0)).unwrap();
        let pools: i64 = db
            .query_row("SELECT count(*) FROM pools", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            (version, retained, sentinel, intermediate, pools),
            (6, source, "retained".into(), 0, 1)
        );
    }
    /// A v7-to-v8 failure rolls back the newly created intent table and preserves old data.
    #[test]
    fn managed_migration_failure_rolls_back_v7() {
        let (directory, mut store) = fixture();
        let owner = actor("migration-v7");
        make(&mut store, &owner, "retained");
        crate::managed_egress::drop_test_schema(&store.db).unwrap();
        store.db.execute_batch("DROP TABLE managed_invalidated_ballots; DROP INDEX managed_current_state_owner; ALTER TABLE managed_current_requests DROP COLUMN owner_intent; ALTER TABLE managed_bindings DROP COLUMN incarnation; DROP INDEX managed_bootstrap_state; DROP INDEX managed_intent_state; DROP TABLE managed_ballot_provenance; DROP TABLE managed_domain_keys; DROP TABLE managed_intents; CREATE TABLE managed_domain_keys(sentinel TEXT); INSERT INTO managed_domain_keys VALUES('retained'); PRAGMA user_version=7;").unwrap();
        drop(store);
        assert!(Store::open(&directory.path().join("pool.sqlite")).is_err());
        let db = Connection::open(directory.path().join("pool.sqlite")).unwrap();
        let version: i64 = db
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        let sentinel: String = db
            .query_row("SELECT sentinel FROM managed_domain_keys", [], |row| {
                row.get(0)
            })
            .unwrap();
        let intents: i64 = db
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='managed_intents'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let pools: i64 = db
            .query_row("SELECT count(*) FROM pools", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            (version, sentinel.as_str(), intents, pools),
            (7, "retained", 0, 1)
        );
    }

    /// A failed v8-to-v9 migration preserves the v8 version and all terminal state.
    #[test]
    fn managed_migration_failure_rolls_back_v8() {
        let (directory, store) = fixture();
        crate::managed_egress::drop_test_schema(&store.db).unwrap();
        store.db.execute_batch("DROP TABLE managed_invalidated_ballots; DROP INDEX managed_current_state_owner; ALTER TABLE managed_current_requests DROP COLUMN owner_intent; ALTER TABLE managed_bindings DROP COLUMN incarnation; DROP INDEX managed_bootstrap_state; DROP INDEX managed_intent_state; CREATE TABLE managed_invalidated_ballots(sentinel TEXT); INSERT INTO managed_invalidated_ballots VALUES('retained'); PRAGMA user_version=8;").unwrap();
        drop(store);
        assert!(Store::open(&directory.path().join("pool.sqlite")).is_err());
        let db = Connection::open(directory.path().join("pool.sqlite")).unwrap();
        let version: i64 = db
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        let sentinel: String = db
            .query_row(
                "SELECT sentinel FROM managed_invalidated_ballots",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let owner_column: i64 = db.query_row("SELECT count(*) FROM pragma_table_info('managed_current_requests') WHERE name='owner_intent'", [], |row| row.get(0)).unwrap();
        assert_eq!(
            (version, sentinel.as_str(), owner_column),
            (8, "retained", 0)
        );
    }

    /// A v9-to-v10 failure rolls back the seed schema and preserves retained work.
    #[test]
    fn managed_egress_migration_failure_rolls_back_v9() {
        let (directory, mut store) = fixture();
        let owner = actor("egress-migration-owner");
        let pool_id = make(&mut store, &owner, "egress-migration");
        crate::managed_egress::drop_test_schema(&store.db).unwrap();
        store.db.execute_batch("CREATE TABLE managed_delivery_outbox(sentinel TEXT); INSERT INTO managed_delivery_outbox VALUES('retained'); PRAGMA user_version=9;").unwrap();
        drop(store);
        assert!(Store::open(&directory.path().join("pool.sqlite")).is_err());
        let db = Connection::open(directory.path().join("pool.sqlite")).unwrap();
        assert_eq!(
            db.query_row::<i64, _, _>("PRAGMA user_version", [], |row| row.get(0))
                .unwrap(),
            9
        );
        assert_eq!(
            db.query_row::<String, _, _>(
                "SELECT sentinel FROM managed_delivery_outbox",
                [],
                |row| row.get(0)
            )
            .unwrap(),
            "retained"
        );
        assert_eq!(db.query_row::<i64,_,_>("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='managed_delivery_seeds'",[],|row|row.get(0)).unwrap(),0);
        assert_eq!(
            db.query_row::<i64, _, _>("SELECT count(*) FROM pools WHERE id=?1", [pool_id], |row| {
                row.get(0)
            })
            .unwrap(),
            1
        );
    }
    /// A confirmed lost execution wakes the owner without closing the pool or removing membership.
    #[test]
    fn lost_execution_is_actionable_without_claiming_process_exit() {
        let (_d, mut s) = fixture();
        let lead = actor("lead");
        let a = actor("a");
        let p = make(&mut s, &lead, "one");
        let mid = add(&mut s, &lead, &p, &a);
        join(&mut s, &a, &p);
        s.db.execute("UPDATE effects SET state='accepted'", [])
            .unwrap();
        s.observe_member(&p, &mid, "lost").unwrap();
        assert!(!pool(&s.db, &p).unwrap().0.closed);
        assert_eq!(bindings(&s.db, &p).unwrap()[0].member.runtime, "lost");
        let mut owner_notified = false;
        while let Some(e) = s.next_effect().unwrap() {
            if let Work::Deliver { address, text, .. } = e.work {
                owner_notified |= address == lead.address && text.contains("lost");
            }
        }
        assert!(owner_notified);
    }
    /// Typed flat wire arguments accept only their documented fields and preserve literal message data.
    #[test]
    fn flat_commands_are_strict_and_validate_unicode_bytes() {
        let value = serde_json::json!({"name":"pool_post","arguments":{"pool_id":"pool","expected_revision":1,"request_key":"key","body":"Привет {{literal}}"}});
        let c: Command = serde_json::from_value(value.clone()).unwrap();
        c.validate().unwrap();
        let mut invalid = value;
        invalid["arguments"]["actor_id"] = serde_json::json!("fake");
        assert!(serde_json::from_value::<Command>(invalid).is_err());
        assert!(text(&"я".repeat(MAX_TEXT), MAX_TEXT).is_err());
    }
    /// Omitted and null replacement specs are the same replay intent; foreign fields refuse.
    #[test]
    fn replacement_command_keeps_null_and_omission_compatible() {
        let omitted = serde_json::json!({"name":"pool_replace","arguments":{"pool_id":"pool","expected_revision":1,"request_key":"key","member_id":"member"}});
        let mut explicit_null = omitted.clone();
        explicit_null["arguments"]["spec"] = serde_json::Value::Null;
        let a: Command = serde_json::from_value(omitted.clone()).unwrap();
        let b: Command = serde_json::from_value(explicit_null).unwrap();
        a.validate().unwrap();
        b.validate().unwrap();
        assert_eq!(a.digest().unwrap(), b.digest().unwrap());
        let mut invalid = omitted;
        invalid["arguments"]["actor_id"] = serde_json::json!("forged");
        assert!(serde_json::from_value::<Command>(invalid).is_err());
    }
}
