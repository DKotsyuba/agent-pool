//! Durable, fail-closed Pool-side primitives for managed-attempt admission.
//!
//! The managed frontend reaches these primitives through the resident. Only an
//! authenticated Run adapter constructs receipts; managed enrollment stays closed.
use crate::domain::{Command, Fault, identifier};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Run-owned immutable execution and launch correlation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AttemptRef {
    pub run_store_id: String,
    pub lineage_root_id: String,
    pub execution_id: String,
    pub sequence: u32,
    pub attempt_id: String,
    pub launch_id: String,
}
/// Full kernel process incarnation, never a PID or launch ID alone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Incarnation {
    pub host_id: String,
    pub boot_id: String,
    pub pid_namespace_inode: u64,
    pub uid: u32,
    pub pid: u32,
    pub start_ticks: u64,
}
/// Run-verified native root actor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedActor {
    pub address: String,
    pub role: String,
    pub native_id: String,
    pub epoch: u64,
}
/// Pinned local component route, independent of endpoint discovery.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Route {
    pub component_store_id: String,
    pub route_id: String,
    pub worker_uid: u32,
}
/// Security-context binding; generation is Pool-owned and not a pool revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedBinding {
    pub pool_store_id: String,
    pub pool_id: String,
    pub member_id: String,
    pub binding_generation: u64,
    pub attempt: AttemptRef,
    pub actor: ManagedActor,
    pub run_route: Route,
    pub bridge_route: Route,
}
/// Frozen security context. Ordered bindings prevent ambiguous hashing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SecurityContext {
    pub version: u8,
    pub command_schema: String,
    pub pool_store_id: String,
    pub audience: String,
    pub producer: String,
    pub intent_id: String,
    pub invocation_key: String,
    pub nonce: String,
    pub bindings: Vec<ManagedBinding>,
}
/// Link of the authenticated Run-checked same-lineage successor proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SuccessorLink {
    pub execution_id: String,
    #[serde(deserialize_with = "required_option")]
    pub parent_execution_id: Option<String>,
    pub sequence: u32,
}
/// Optional data remains required on the wire, where null has explicit meaning.
pub(crate) fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
/// Run's durable current receipt; a receipt alone is not authority without lookup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CurrentReceipt {
    pub receipt_id: String,
    pub purpose: String,
    pub lineage_root_id: String,
    pub bound_execution_id: String,
    pub attempt: AttemptRef,
    pub incarnation: Incarnation,
    pub actor: ManagedActor,
    pub successor_proof: SuccessorProof,
}
/// Displayed chain has a bound-to-current segment; Run verifies the full lineage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SuccessorProof {
    pub lineage_root_id: String,
    pub bound_execution_id: String,
    pub current_execution_id: String,
    pub chain: Vec<SuccessorLink>,
}
/// A typed consensus classification, relative to the expected ballot provenance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum VoterState {
    Live,
    TerminalNoSuccessor,
    Superseded,
    Unavailable,
}
/// Matching currentness response from the authenticated Run reader.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VoterObservation {
    pub state: VoterState,
    pub last_attempt: Option<AttemptRef>,
    pub last_incarnation: Option<Incarnation>,
    pub successor_proof: Option<SuccessorProof>,
}
/// Adapter must verify peer, pinned route and Run receipt; JSON is never authority.
pub(crate) trait RunAuthority {
    fn current_receipt(&self, route: &Route, receipt_id: &str) -> Result<CurrentReceipt, Fault>;
    fn consensus(
        &self,
        route: &Route,
        attempt: &AttemptRef,
        incarnation: &Incarnation,
    ) -> Result<VoterObservation, Fault>;
}

fn encoded<T: Serialize>(value: &T) -> Result<String, Fault> {
    serde_json::to_string(value).map_err(|_| Fault::Internal)
}
fn decoded<T: for<'a> Deserialize<'a>>(text: &str) -> Result<T, Fault> {
    serde_json::from_str(text).map_err(|_| Fault::Internal)
}
/// A known consume must be returned byte-for-byte by its pre-retirement abort.
fn require_original_consume(
    expected: Option<&str>,
    actual: Option<&crate::managed_bridge::ConsumeReceipt>,
) -> Result<(), Fault> {
    if let Some(expected) = expected {
        let actual = actual.ok_or(Fault::Unavailable)?;
        if encoded(actual)? != expected {
            return Err(Fault::Conflict);
        }
    }
    Ok(())
}
/// Every Bridge operation stays on the immutable endpoint/build/credential pin.
fn verify_bridge_pin(
    db: &Connection,
    context_id: &str,
    pin: &crate::managed_bridge::BridgePin,
) -> Result<(), Fault> {
    let stored:Option<String>=db.query_row("SELECT n.bridge_pin FROM managed_contexts c JOIN managed_namespaces n ON n.id=c.namespace_id WHERE c.id=?1",[context_id],|row|row.get(0))?;
    if stored.as_deref() != Some(encoded(pin)?.as_str()) {
        return Err(Fault::Conflict);
    }
    Ok(())
}
/// Durably pin a Bridge endpoint and credential identity before any discovery or mutation.
pub(crate) fn persist_bridge_route(
    db: &mut Connection,
    pin: &crate::managed_bridge::BridgePin,
) -> Result<(), Fault> {
    let route = encoded(&pin.route)?;
    let encoded_pin = encoded(pin)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let prior: Option<String> = tx
        .query_row(
            "SELECT pin FROM managed_bridge_routes WHERE route=?1",
            [&route],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(prior) = prior {
        return if prior == encoded_pin {
            Ok(())
        } else {
            Err(Fault::Conflict)
        };
    }
    tx.execute(
        "INSERT INTO managed_bridge_routes(route,pin) VALUES(?1,?2)",
        params![route, encoded_pin],
    )?;
    tx.commit()?;
    Ok(())
}
fn sqlite_generation(value: u64) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}
/// Decode a fixed-width generation without narrowing the wire's u64 range.
fn read_generation(value: &[u8]) -> Result<u64, Fault> {
    let bytes: [u8; 8] = value.try_into().map_err(|_| Fault::Internal)?;
    Ok(u64::from_be_bytes(bytes))
}

const MANAGED_CAPACITY: u64 = 100_000;

/// One capacity gauge; retained includes permanent rejecting keys and terminal evidence.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapacityGauge {
    /// Active operations consuming the admission budget.
    pub active: u64,
    /// All retained records, including permanent terminal fences.
    pub retained: u64,
    /// Slots reserved for earlier stages that have not created this record yet.
    pub reserved: u64,
    /// Configured fixed active-operation limit.
    pub limit: u64,
    /// Remaining active slots after outstanding reservations.
    pub headroom: u64,
}
/// Point-in-time owner diagnostics, not a promise that a future reservation fits.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedCapacity {
    /// Open or draining namespaces and retained namespace fences.
    pub namespaces: CapacityGauge,
    /// Active bootstrap reservations and retained invocation keys.
    pub bootstraps: CapacityGauge,
    /// Active contexts and retained context keys.
    pub contexts: CapacityGauge,
    /// Unresolved intents and retained terminal outcomes.
    pub intents: CapacityGauge,
    /// Active currentness reads and retained rejecting keys.
    pub current_requests: CapacityGauge,
    /// Active bootstrap slots reserved for later context and intent creation.
    pub bootstrap_reservations: u64,
    /// Active contexts reserving a later intent slot.
    pub contexts_without_intent: u64,
}
impl ManagedCapacity {
    pub(crate) fn valid(&self) -> bool {
        [
            &self.namespaces,
            &self.bootstraps,
            &self.contexts,
            &self.intents,
            &self.current_requests,
        ]
        .iter()
        .all(|g| {
            g.limit == MANAGED_CAPACITY
                && g.active <= g.retained
                && g.headroom == g.limit.saturating_sub(g.active.saturating_add(g.reserved))
        }) && self.bootstrap_reservations <= self.bootstraps.active
            && self.contexts_without_intent <= self.contexts.active
            && self.contexts.reserved == self.bootstrap_reservations
            && self.intents.reserved
                == self
                    .bootstrap_reservations
                    .saturating_add(self.contexts_without_intent)
            && self.namespaces.reserved == 0
            && self.bootstraps.reserved == 0
            && self.current_requests.reserved == 0
    }
}
fn gauge(
    db: &Connection,
    table: &str,
    active: &str,
    include_retained: bool,
) -> Result<CapacityGauge, Fault> {
    // Table and predicate are internal constants, never caller-provided SQL.
    let sql = format!("SELECT count(*) FROM {table} WHERE {active}");
    let active: i64 = db.query_row(&sql, [], |row| row.get(0))?;
    let retained: i64 = if include_retained {
        db.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
            row.get(0)
        })?
    } else {
        active
    };
    let retained = u64::try_from(retained).map_err(|_| Fault::Internal)?;
    let active = u64::try_from(active).map_err(|_| Fault::Internal)?;
    Ok(CapacityGauge {
        active,
        retained,
        reserved: 0,
        limit: MANAGED_CAPACITY,
        headroom: MANAGED_CAPACITY.saturating_sub(active),
    })
}
fn managed_capacity_inner(
    db: &Connection,
    include_retained: bool,
) -> Result<ManagedCapacity, Fault> {
    let namespaces = gauge(
        db,
        "managed_namespaces",
        "state!='sealed'",
        include_retained,
    )?;
    let bootstraps = gauge(
        db,
        "managed_bootstrap",
        "state IN ('prepared','submitted')",
        include_retained,
    )?;
    let mut contexts = gauge(
        db,
        "managed_contexts c",
        "EXISTS(SELECT 1 FROM managed_intents i WHERE i.context_id=c.id AND (i.state NOT IN ('committed','aborted') OR i.bridge_resolved=0 OR i.run_resolved=0)) OR (NOT EXISTS(SELECT 1 FROM managed_intents i WHERE i.context_id=c.id) AND EXISTS(SELECT 1 FROM managed_namespaces n WHERE n.id=c.namespace_id AND n.state!='sealed') AND (c.state='prepared' OR EXISTS(SELECT 1 FROM managed_bootstrap b WHERE b.namespace_id=c.namespace_id AND b.invocation_key=c.invocation_key AND b.state='submitted')))",
        include_retained,
    )?;
    let mut intents = gauge(
        db,
        "managed_intents",
        "state NOT IN ('committed','aborted') OR bridge_resolved=0 OR run_resolved=0",
        include_retained,
    )?;
    let current_requests = gauge(
        db,
        "managed_current_requests r",
        "r.state IN ('prepared','received') AND ((r.namespace_id IS NOT NULL AND EXISTS(SELECT 1 FROM managed_bootstrap b WHERE b.namespace_id=r.namespace_id AND b.invocation_key=COALESCE(json_extract(r.request,'$.invocation_key'),json_extract(r.request,'$.observation_ref.invocation_key')) AND b.state='submitted')) OR (r.namespace_id IS NULL AND (r.owner_intent IS NULL OR EXISTS(SELECT 1 FROM managed_intents i WHERE i.id=r.owner_intent AND i.state IN ('admitting','admitted')))))",
        include_retained,
    )?;
    let bootstrap_reservations: i64 = db.query_row("SELECT count(*) FROM managed_bootstrap b WHERE b.state IN ('prepared','submitted') AND NOT EXISTS(SELECT 1 FROM managed_contexts c WHERE c.invocation_key=b.invocation_key)", [], |row| row.get(0))?;
    let contexts_without_intent: i64 = db.query_row("SELECT count(*) FROM managed_contexts c WHERE c.state='prepared' AND EXISTS(SELECT 1 FROM managed_namespaces n WHERE n.id=c.namespace_id AND n.state!='sealed') AND NOT EXISTS(SELECT 1 FROM managed_intents i WHERE i.context_id=c.id)", [], |row| row.get(0))?;
    let bootstrap_reservations =
        u64::try_from(bootstrap_reservations).map_err(|_| Fault::Internal)?;
    let contexts_without_intent =
        u64::try_from(contexts_without_intent).map_err(|_| Fault::Internal)?;
    contexts.reserved = bootstrap_reservations;
    contexts.headroom =
        MANAGED_CAPACITY.saturating_sub(contexts.active.saturating_add(contexts.reserved));
    intents.reserved = bootstrap_reservations.saturating_add(contexts_without_intent);
    intents.headroom =
        MANAGED_CAPACITY.saturating_sub(intents.active.saturating_add(intents.reserved));
    Ok(ManagedCapacity {
        namespaces,
        bootstraps,
        contexts,
        intents,
        current_requests,
        bootstrap_reservations,
        contexts_without_intent,
    })
}
/// The owner sees all gauges from one SQLite read snapshot.
pub(crate) fn managed_capacity(db: &Connection) -> Result<ManagedCapacity, Fault> {
    let tx = db.unchecked_transaction()?;
    let result = managed_capacity_inner(&tx, true)?;
    tx.commit()?;
    Ok(result)
}
/// Wire opaque strings are case-sensitive and need not use Pool's identifier alphabet.
fn wire_string(value: &str) -> Result<(), Fault> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        Err(Fault::Invalid)
    } else {
        Ok(())
    }
}

/// A bootstrap receipt proves a complete root-to-current chain and original actor.
pub(crate) fn valid_ingress_receipt(receipt: &CurrentReceipt, route: &Route) -> bool {
    let proof = &receipt.successor_proof;
    let chain = &proof.chain;
    let distinct: std::collections::BTreeSet<_> =
        chain.iter().map(|link| &link.execution_id).collect();
    let canonical_uuid =
        |value: &str| uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value);
    let actor_address = bridge_sdk::bridge_protocol::NativeAddress::parse(&receipt.actor.address)
        .is_ok_and(|address| {
            address.canonical() == receipt.actor.address
                && address.host == receipt.incarnation.host_id
                && address.session == receipt.actor.native_id
        });
    receipt.purpose == "ingress"
        && wire_string(&receipt.receipt_id).is_ok()
        && wire_string(&receipt.lineage_root_id).is_ok()
        && wire_string(&receipt.attempt.execution_id).is_ok()
        && wire_string(&receipt.attempt.attempt_id).is_ok()
        && receipt.attempt.run_store_id == route.component_store_id
        && receipt.attempt.lineage_root_id == receipt.lineage_root_id
        && receipt.bound_execution_id == receipt.lineage_root_id
        && proof.lineage_root_id == receipt.lineage_root_id
        && proof.bound_execution_id == receipt.lineage_root_id
        && proof.current_execution_id == receipt.attempt.execution_id
        && !chain.is_empty()
        && distinct.len() == chain.len()
        && chain.first().is_some_and(|link| {
            link.execution_id == receipt.lineage_root_id
                && link.parent_execution_id.is_none()
                && link.sequence > 0
        })
        && chain.last().is_some_and(|link| {
            link.execution_id == receipt.attempt.execution_id
                && link.sequence == receipt.attempt.sequence
        })
        && chain.windows(2).all(|pair| {
            pair[1].parent_execution_id.as_deref() == Some(pair[0].execution_id.as_str())
                && pair[0].sequence.checked_add(1) == Some(pair[1].sequence)
        })
        && canonical_uuid(&receipt.attempt.launch_id)
        && canonical_uuid(&receipt.incarnation.boot_id)
        && receipt.incarnation.uid == route.worker_uid
        && receipt.incarnation.pid > 1
        && receipt.incarnation.pid_namespace_inode > 0
        && receipt.incarnation.start_ticks > 0
        && wire_string(&receipt.incarnation.host_id).is_ok()
        && receipt.actor.role == "root"
        && receipt.actor.epoch > 0
        && wire_string(&receipt.actor.native_id).is_ok()
        && actor_address
}

/// Independently checks the authenticated receipt's exact requested lineage segment.
pub(crate) fn receipt_matches(
    receipt: &CurrentReceipt,
    old: &ManagedBinding,
    new: &ManagedBinding,
    incarnation: &Incarnation,
    purpose: &str,
) -> bool {
    let proof = &receipt.successor_proof;
    let chain = &proof.chain;
    let distinct: std::collections::BTreeSet<_> =
        chain.iter().map(|link| &link.execution_id).collect();
    let canonical_uuid =
        |value: &str| uuid::Uuid::parse_str(value).is_ok_and(|parsed| parsed.to_string() == value);
    let anchored = if purpose == "ingress" {
        valid_ingress_receipt(receipt, &new.run_route)
            && chain.iter().any(|link| {
                link.execution_id == old.attempt.execution_id
                    && link.sequence == old.attempt.sequence
            })
    } else {
        receipt.bound_execution_id == old.attempt.execution_id
            && proof.bound_execution_id == old.attempt.execution_id
            && chain.first().is_some_and(|link| {
                link.execution_id == old.attempt.execution_id
                    && link.sequence == old.attempt.sequence
            })
    };
    receipt.purpose == purpose
        && receipt.lineage_root_id == old.attempt.lineage_root_id
        && anchored
        && receipt.attempt == new.attempt
        && receipt.incarnation == *incarnation
        && receipt.actor == new.actor
        && proof.lineage_root_id == old.attempt.lineage_root_id
        && proof.bound_execution_id == receipt.bound_execution_id
        && proof.current_execution_id == new.attempt.execution_id
        && !chain.is_empty()
        && distinct.len() == chain.len()
        && chain.last().is_some_and(|link| {
            link.execution_id == new.attempt.execution_id && link.sequence == new.attempt.sequence
        })
        && chain.windows(2).all(|pair| {
            pair[1].parent_execution_id.as_deref() == Some(pair[0].execution_id.as_str())
                && pair[0].sequence.checked_add(1) == Some(pair[1].sequence)
        })
        && old.attempt.run_store_id == new.attempt.run_store_id
        && crate::domain::store_id(&new.attempt.run_store_id).is_ok()
        && new.attempt.sequence > 0
        && !new.attempt.attempt_id.is_empty()
        && canonical_uuid(&new.attempt.launch_id)
        && old.attempt.lineage_root_id == new.attempt.lineage_root_id
        && old.run_route == new.run_route
        && old.bridge_route == new.bridge_route
        && old.pool_store_id == new.pool_store_id
        && canonical_uuid(&new.pool_store_id)
        && canonical_uuid(&new.bridge_route.component_store_id)
        && old.pool_id == new.pool_id
        && old.member_id == new.member_id
        && old.actor.address == new.actor.address
        && old.actor.native_id == new.actor.native_id
        && new.actor.role == "root"
        && new.actor.epoch > 0
        && new.run_route.component_store_id == new.attempt.run_store_id
        && new.run_route.worker_uid == new.bridge_route.worker_uid
        && incarnation.uid == new.run_route.worker_uid
        && incarnation.pid > 1
        && incarnation.pid_namespace_inode > 0
        && incarnation.start_ticks > 0
        && !incarnation.host_id.is_empty()
        && canonical_uuid(&incarnation.boot_id)
}

/// A current receipt is useful only with its previously staged exact Run endpoint.
fn require_staged_current(
    db: &Connection,
    authority: &crate::managed_run::CurrentAuthority,
    receipt: &CurrentReceipt,
    route: &Route,
    replay: bool,
) -> Result<(), Fault> {
    let request_id = authority.request_id().ok_or(Fault::Unauthorized)?;
    let (pin_json, state, stored_receipt, request_json): (String, String, Option<String>, String) =
        db.query_row(
            "SELECT run_pin,state,receipt,request FROM managed_current_requests WHERE id=?1",
            [request_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
    let pin: RunPin = decoded(&pin_json)?;
    let request: serde_json::Value = decoded(&request_json)?;
    if !(state == "received" || (replay && matches!(state.as_str(), "used" | "aborted")))
        || stored_receipt.as_deref() != Some(encoded(receipt)?.as_str())
        || authority.request() != Some(&request)
        || authority.endpoint() != &pin.endpoint()
        || &pin.route != route
    {
        return Err(Fault::Stale);
    }
    Ok(())
}

/// Installs only a Run-attested same-lineage change under the old generation CAS.
#[allow(
    clippy::too_many_arguments,
    reason = "The receipt and exact pre-I/O authority remain distinct"
)]
fn rebind_inner(
    db: &mut Connection,
    run: &impl RunAuthority,
    old: &ManagedBinding,
    new: &ManagedBinding,
    incarnation: &Incarnation,
    receipt_id: &str,
    purpose: &str,
    authority: Option<&crate::managed_run::CurrentAuthority>,
) -> Result<u64, Fault> {
    if !matches!(purpose, "ingress" | "egress")
        || old.binding_generation == 0
        || new.binding_generation != old.binding_generation
    {
        return Err(Fault::Invalid);
    }
    let receipt = run.current_receipt(&old.run_route, receipt_id)?;
    if receipt.receipt_id != receipt_id
        || !receipt_matches(&receipt, old, new, incarnation, purpose)
    {
        return Err(Fault::Forbidden);
    }
    let old_json = encoded(old)?;
    let new_json = encoded(new)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let previous: Option<(String,String,Vec<u8>)> = tx.query_row("SELECT old_binding,new_binding,generation_after FROM managed_rebinds WHERE receipt_id=?1", [receipt_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
    if let Some((prior_old, prior_new, generation)) = previous {
        if prior_old != old_json || prior_new != new_json {
            return Err(Fault::Conflict);
        }
        if let Some(authority) = authority {
            require_staged_current(&tx, authority, &receipt, &old.run_route, true)?;
        }
        return read_generation(&generation);
    }
    if let Some(authority) = authority {
        require_staged_current(&tx, authority, &receipt, &old.run_route, false)?;
    }
    let row: Option<(Vec<u8>, String, Option<String>)> = tx
        .query_row(
            "SELECT generation,binding,incarnation FROM managed_bindings WHERE member=?1 AND pool=?2",
            params![old.member_id, old.pool_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let (generation, stored, old_incarnation) = row.ok_or(Fault::Forbidden)?;
    if generation != sqlite_generation(old.binding_generation) || stored != old_json {
        return Err(Fault::Stale);
    }
    let is_current: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM members WHERE id=?1 AND pool=?2 AND current=1)",
        params![old.member_id, old.pool_id],
        |r| r.get(0),
    )?;
    if !is_current {
        return Err(Fault::Stale);
    }
    let incarnation_json = encoded(incarnation)?;
    let incarnation_changed = old_incarnation.as_deref() != Some(incarnation_json.as_str());
    if old == new && !incarnation_changed {
        tx.execute(
            "INSERT INTO managed_rebinds VALUES(?1,?2,?3,?4,?5,?5)",
            params![receipt_id, old.member_id, old_json, new_json, generation],
        )?;
        tx.commit()?;
        return Ok(old.binding_generation);
    }
    if old.attempt == new.attempt && old.actor.epoch == new.actor.epoch && !incarnation_changed {
        return Err(Fault::Conflict);
    }
    let next = read_generation(&generation)?
        .checked_add(1)
        .ok_or(Fault::Unavailable)?;
    let mut updated = new.clone();
    updated.binding_generation = next;
    tx.execute(
        "UPDATE managed_bindings SET generation=?2,binding=?3,incarnation=?4 WHERE member=?1",
        params![
            old.member_id,
            sqlite_generation(next),
            encoded(&updated)?,
            incarnation_json
        ],
    )?;
    let pool_json: String = tx.query_row(
        "SELECT data FROM pools WHERE id=?1",
        [&old.pool_id],
        |row| row.get(0),
    )?;
    let pool: crate::domain::Pool = decoded(&pool_json)?;
    if let Some(proposal) = pool.proposal.as_ref().filter(|proposal| {
        proposal.state == crate::domain::ProposalState::Open
            && proposal.votes.contains_key(&old.member_id)
    }) {
        tx.execute("INSERT OR IGNORE INTO managed_invalidated_ballots(pool,proposal,member) VALUES(?1,?2,?3)",params![old.pool_id,proposal.proposal_id,old.member_id])?;
    }
    tx.execute("INSERT INTO managed_pool_epochs(pool,epoch) VALUES(?1,1) ON CONFLICT(pool) DO UPDATE SET epoch=epoch+1",[&old.pool_id])?;
    tx.execute("UPDATE managed_contexts SET state='invalidated' WHERE id IN (SELECT context_id FROM managed_context_bindings WHERE member=?1) AND state='prepared'",[&old.member_id])?;
    tx.execute("UPDATE managed_current_requests SET state='aborted' WHERE COALESCE(json_extract(request,'$.invocation_key'),json_extract(request,'$.observation_ref.invocation_key')) IN (SELECT c.invocation_key FROM managed_contexts c JOIN managed_context_bindings b ON b.context_id=c.id WHERE b.member=?1) AND state IN ('prepared','received')",[&old.member_id])?;
    tx.execute(
        "INSERT INTO managed_rebinds VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            receipt_id,
            old.member_id,
            old_json,
            new_json,
            generation,
            sqlite_generation(next)
        ],
    )?;
    tx.commit()?;
    Ok(next)
}

/// Rebind from a receipt already looked up on its original pinned Run endpoint.
pub(crate) fn rebind_authenticated(
    db: &mut Connection,
    authority: &crate::managed_run::CurrentAuthority,
    old: &ManagedBinding,
    new: &ManagedBinding,
    incarnation: &Incarnation,
    purpose: &str,
) -> Result<u64, Fault> {
    rebind_inner(
        db,
        authority,
        old,
        new,
        incarnation,
        &authority.receipt().receipt_id,
        purpose,
        Some(authority),
    )
}

#[cfg(test)]
fn rebind(
    db: &mut Connection,
    run: &impl RunAuthority,
    old: &ManagedBinding,
    new: &ManagedBinding,
    incarnation: &Incarnation,
    receipt_id: &str,
    purpose: &str,
) -> Result<u64, Fault> {
    rebind_inner(db, run, old, new, incarnation, receipt_id, purpose, None)
}

/// An authenticated observation preserves a verified ballot only for the exact incarnation.
fn voter_valid(
    run: &impl RunAuthority,
    binding: &ManagedBinding,
    attempt: &AttemptRef,
    incarnation: &Incarnation,
) -> Result<bool, Fault> {
    let result = run.consensus(&binding.run_route, attempt, incarnation)?;
    match result.state {
        VoterState::Live | VoterState::TerminalNoSuccessor => {
            if result.last_attempt.as_ref() != Some(attempt)
                || result.last_incarnation.as_ref() != Some(incarnation)
                || result.successor_proof.is_none()
            {
                return Err(Fault::Unavailable);
            }
            let receipt = CurrentReceipt {
                receipt_id: "consensus".into(),
                purpose: "consensus".into(),
                lineage_root_id: attempt.lineage_root_id.clone(),
                bound_execution_id: attempt.execution_id.clone(),
                attempt: attempt.clone(),
                incarnation: incarnation.clone(),
                actor: binding.actor.clone(),
                successor_proof: result.successor_proof.ok_or(Fault::Unavailable)?,
            };
            if !receipt_matches(&receipt, binding, binding, incarnation, "consensus") {
                return Err(Fault::Unavailable);
            }
            Ok(true)
        }
        VoterState::Superseded => {
            let next_attempt = result.last_attempt.ok_or(Fault::Unavailable)?;
            let next_incarnation = result.last_incarnation.ok_or(Fault::Unavailable)?;
            let mut next = binding.clone();
            next.attempt = next_attempt.clone();
            let receipt = CurrentReceipt {
                receipt_id: "consensus".into(),
                purpose: "consensus".into(),
                lineage_root_id: attempt.lineage_root_id.clone(),
                bound_execution_id: attempt.execution_id.clone(),
                attempt: next_attempt.clone(),
                incarnation: next_incarnation.clone(),
                actor: binding.actor.clone(),
                successor_proof: result.successor_proof.ok_or(Fault::Unavailable)?,
            };
            if next_attempt == *attempt
                || !receipt_matches(&receipt, binding, &next, &next_incarnation, "consensus")
            {
                return Err(Fault::Unavailable);
            }
            Ok(false)
        }
        VoterState::Unavailable => Err(Fault::Unavailable),
    }
}

/// A frozen ballot and its author provenance, obtained from one local snapshot.
#[derive(Clone)]
pub(crate) struct VerifiedBallot {
    pub binding: ManagedBinding,
    pub generation: u64,
    pub attempt: AttemptRef,
    pub incarnation: Incarnation,
}

/// Query every managed voter outside SQLite; caller must CAS their generations and
/// the proposal/roster snapshot inside the subsequent acceptance transaction.
pub(crate) fn check_all_voters(
    run: &impl RunAuthority,
    voters: &[VerifiedBallot],
) -> Result<(), Fault> {
    let mut unavailable = false;
    let mut stale = false;
    let mut members = std::collections::BTreeSet::new();
    for voter in voters {
        if !members.insert((&voter.binding.pool_id, &voter.binding.member_id))
            || voter.generation != voter.binding.binding_generation
            || voter.attempt != voter.binding.attempt
        {
            stale = true;
        }
        match voter_valid(run, &voter.binding, &voter.attempt, &voter.incarnation) {
            Ok(true) => {}
            Ok(false) => stale = true,
            Err(_) => unavailable = true,
        }
    }
    if unavailable {
        Err(Fault::Unavailable)
    } else if stale {
        Err(Fault::Stale)
    } else {
        Ok(())
    }
}

/// Captures a deterministic complete pool/member/slot snapshot for commit-time CAS.
fn pool_fingerprint(db: &Connection, pool: &str) -> Result<String, Fault> {
    let pool_data: String =
        db.query_row("SELECT data FROM pools WHERE id=?1", [pool], |r| r.get(0))?;
    let mut stmt = db.prepare("SELECT m.id,m.data,coalesce(s.slot,m.id) FROM members m LEFT JOIN member_slots s ON s.member=m.id WHERE m.pool=?1 AND m.current=1 ORDER BY m.id")?;
    let members = stmt
        .query_map([pool], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let bytes = serde_json::to_vec(&(pool_data, members)).map_err(|_| Fault::Internal)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

/// Normalize and hash an exact command against a deterministic frozen context.
pub(crate) fn validate_context(
    command: &Command,
    context: &SecurityContext,
) -> Result<(String, String), Fault> {
    if context.version != 1
        || context.command_schema != "pool-command-v1"
        || context.bindings.is_empty()
    {
        return Err(Fault::Invalid);
    }
    for value in [
        &context.pool_store_id,
        &context.audience,
        &context.producer,
        &context.intent_id,
        &context.invocation_key,
        &context.nonce,
    ] {
        wire_string(value)?;
    }
    if context.bindings.windows(2).any(|pair| {
        (&pair[0].pool_id, &pair[0].member_id) >= (&pair[1].pool_id, &pair[1].member_id)
    }) || context.bindings.iter().any(|binding| {
        binding.pool_store_id != context.pool_store_id || binding.binding_generation == 0
    }) {
        return Err(Fault::Invalid);
    }
    command.validate()?;
    let normalized = serde_json::to_value(command).map_err(|_| Fault::Internal)?;
    let context_value = serde_json::to_value(context).map_err(|_| Fault::Internal)?;
    let (_, digest) = crate::managed_codec::security_digest(&normalized, &context_value)?;
    Ok((encoded(&normalized)?, digest))
}

/// Persist a frozen context only after the caller has obtained authenticated Run current receipts.
/// The current binding and roster snapshots are rechecked inside the same transaction.
pub(crate) fn prepare_context(
    db: &mut Connection,
    run: &impl RunAuthority,
    context_id: &str,
    namespace_id: &str,
    command: &Command,
    context: &SecurityContext,
    receipts: &[(&str, Incarnation)],
) -> Result<String, Fault> {
    identifier(context_id)?;
    if receipts.len() != context.bindings.len() {
        return Err(Fault::Invalid);
    }
    let (command_json, digest) = validate_context(command, context)?;
    for (binding, (receipt_id, incarnation)) in context.bindings.iter().zip(receipts) {
        let receipt = run.current_receipt(&binding.run_route, receipt_id)?;
        if receipt.receipt_id != *receipt_id
            || !receipt_matches(&receipt, binding, binding, incarnation, "ingress")
        {
            return Err(Fault::Forbidden);
        }
        let persisted:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM managed_current_requests WHERE state='received' AND after_consume=0 AND COALESCE(json_extract(request,'$.invocation_key'),json_extract(request,'$.observation_ref.invocation_key'))=?1 AND receipt=?2)",params![context.invocation_key,encoded(&receipt)?],|row|row.get(0))?;
        if !persisted {
            return Err(Fault::Unavailable);
        }
    }
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let store_id: String = tx.query_row(
        "SELECT store_id FROM inventory_source WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    if store_id != context.pool_store_id {
        return Err(Fault::Stale);
    }
    let namespace: Option<(String, String, String,String)> = tx.query_row("SELECT n.state,n.producer,n.bridge_route,b.command FROM managed_namespaces n JOIN managed_bootstrap b ON b.namespace_id=n.id WHERE n.id=?1 AND b.invocation_key=?2 AND b.state='submitted' AND b.bridge_context_ref IS NOT NULL",params![namespace_id,context.invocation_key],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
    let Some((state, producer, route, bootstrap_command)) = namespace else {
        return Err(Fault::Forbidden);
    };
    if state != "open"
        || bootstrap_command != command_json
        || producer != context.producer
        || context
            .bindings
            .iter()
            .any(|binding| encoded(&binding.bridge_route).map_or(true, |value| value != route))
    {
        return Err(Fault::Stale);
    }
    let mut pools = std::collections::BTreeMap::new();
    for binding in &context.bindings {
        let row: Option<(Vec<u8>, String)> = tx
            .query_row(
                "SELECT generation,binding FROM managed_bindings WHERE member=?1 AND pool=?2",
                params![binding.member_id, binding.pool_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if row
            != Some((
                sqlite_generation(binding.binding_generation),
                encoded(binding)?,
            ))
        {
            return Err(Fault::Stale);
        }
        let current: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM members WHERE id=?1 AND pool=?2 AND current=1)",
            params![binding.member_id, binding.pool_id],
            |r| r.get(0),
        )?;
        if !current {
            return Err(Fault::Stale);
        }
        if !pools.contains_key(&binding.pool_id) {
            let epoch: i64 = tx
                .query_row(
                    "SELECT epoch FROM managed_pool_epochs WHERE pool=?1",
                    [&binding.pool_id],
                    |r| r.get(0),
                )
                .optional()?
                .unwrap_or(0);
            pools.insert(
                binding.pool_id.clone(),
                (epoch, pool_fingerprint(&tx, &binding.pool_id)?),
            );
        }
    }
    let snapshot = encoded(&pools)?;
    let context_json = encoded(context)?;
    let existing: Option<(String, String, String, String, String)> = tx
        .query_row(
            "SELECT command,context,digest,snapshot,state FROM managed_contexts WHERE id=?1",
            [context_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    if let Some((old_command, old_context, old_digest, old_snapshot, state)) = existing {
        if state != "prepared" {
            return Err(Fault::Stale);
        }
        let old_pools: std::collections::BTreeMap<String, (i64, String)> = decoded(&old_snapshot)?;
        let new_pools: std::collections::BTreeMap<String, (i64, String)> = decoded(&snapshot)?;
        let same_rosters = old_pools.len() == new_pools.len()
            && old_pools.iter().all(|(pool, (_, fingerprint))| {
                new_pools
                    .get(pool)
                    .is_some_and(|(_, current)| current == fingerprint)
            });
        if (old_command, old_context, old_digest) != (command_json, context_json, digest.clone())
            || !same_rosters
        {
            return Err(Fault::Conflict);
        }
        return Ok(digest);
    }
    // No network reservation should be made when local durable capacity is exhausted.
    if managed_capacity_inner(&tx, false)?.contexts.active >= MANAGED_CAPACITY {
        return Err(Fault::Unavailable);
    }
    tx.execute("INSERT INTO managed_contexts(id,namespace_id,intent_id,invocation_key,command,context,digest,snapshot,state) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'prepared')",params![context_id,namespace_id,context.intent_id,context.invocation_key,command_json,context_json,digest,snapshot])?;
    for binding in &context.bindings {
        tx.execute(
            "INSERT INTO managed_context_bindings(context_id,member,generation) VALUES(?1,?2,?3)",
            params![
                context_id,
                binding.member_id,
                sqlite_generation(binding.binding_generation)
            ],
        )?;
    }
    for (pool, (epoch, _)) in pools {
        tx.execute(
            "INSERT INTO managed_context_epochs(context_id,pool,epoch) VALUES(?1,?2,?3)",
            params![context_id, pool, epoch],
        )?;
    }
    tx.commit()?;
    Ok(digest)
}

/// Verify stored context, frozen bindings, epochs and full domain snapshot in one SQL transaction.
fn context_current(
    db: &Connection,
    context_id: &str,
    command: &Command,
    digest: &str,
    check_snapshot: bool,
) -> Result<SecurityContext, Fault> {
    let (stored_command, context_json, stored_digest, snapshot, state): (
        String,
        String,
        String,
        String,
        String,
    ) = db.query_row(
        "SELECT command,context,digest,snapshot,state FROM managed_contexts WHERE id=?1",
        [context_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
    )?;
    let namespace_open: bool = db.query_row("SELECT n.state='open' FROM managed_namespaces n JOIN managed_contexts c ON c.namespace_id=n.id WHERE c.id=?1",[context_id],|r|r.get(0))?;
    if state != "prepared" || !namespace_open {
        return Err(Fault::Stale);
    }
    let context: SecurityContext = decoded(&context_json)?;
    let (normalized, recomputed) = validate_context(command, &context)?;
    if stored_command != normalized || stored_digest != digest || recomputed != digest {
        return Err(Fault::Conflict);
    }
    for binding in &context.bindings {
        let row: Option<(Vec<u8>, String)> = db
            .query_row(
                "SELECT generation,binding FROM managed_bindings WHERE member=?1 AND pool=?2",
                params![binding.member_id, binding.pool_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if row
            != Some((
                sqlite_generation(binding.binding_generation),
                encoded(binding)?,
            ))
        {
            return Err(Fault::Stale);
        }
        let current: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM members WHERE id=?1 AND pool=?2 AND current=1)",
            params![binding.member_id, binding.pool_id],
            |row| row.get(0),
        )?;
        if !current {
            return Err(Fault::Stale);
        }
    }
    let stored: std::collections::BTreeMap<String, (i64, String)> = decoded(&snapshot)?;
    for (pool, (_epoch, fingerprint)) in stored {
        // Aggregate binding epoch fences consensus, not unrelated member contexts.
        if check_snapshot && fingerprint != pool_fingerprint(db, &pool)? {
            return Err(Fault::Stale);
        }
    }
    Ok(context)
}

/// Result of the domain-key and exact-intent replay check.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum IntentReservation {
    Created,
    Pending,
    Committed(String),
    Aborted(String),
}

/// The durable original consume and post-consume Run check for one exact binding.
struct FreshAuthority {
    reference: String,
    receipt: String,
    current_id: String,
    run_pin: String,
}
fn verify_fresh_authority(
    db: &Connection,
    context: &SecurityContext,
    digest: &str,
    binding: &ManagedBinding,
    authority: &crate::managed_run::CurrentAuthority,
    consumed: &crate::managed_bridge::Consumed,
) -> Result<FreshAuthority, Fault> {
    let (registration,reference,receipt):(Option<String>,Option<String>,Option<String>)=db.query_row("SELECT registration_digest,consumed_ref,consumed_receipt FROM managed_bootstrap WHERE invocation_key=?1 AND state IN ('submitted','terminal')",[&context.invocation_key],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?)))?;
    if registration.as_deref() != Some(digest)
        || consumed.validity != crate::managed_bridge::Validity::Current
        || consumed.aborted
        || receipt.as_deref() != Some(encoded(&consumed.receipt)?.as_str())
    {
        return Err(Fault::Unauthorized);
    }
    let frozen_reference: crate::managed_run::ConsumedRef =
        decoded(reference.as_deref().ok_or(Fault::Unauthorized)?)?;
    if consumed.store_id != frozen_reference.bridge_route.component_store_id
        || frozen_reference.security_digest != digest
        || frozen_reference.invocation_key != context.invocation_key
        || consumed.receipt.observation.actor != binding.actor
        || consumed.receipt.observation.launch_id != binding.attempt.launch_id
        || !authority.matches_ingress(
            binding,
            &consumed.receipt.observation.incarnation,
            &context.invocation_key,
        )
    {
        return Err(Fault::Unauthorized);
    }
    let current_id = authority.request_id().ok_or(Fault::Unauthorized)?;
    let (current_state, after_consume, current_receipt, current_pin, current_request): (
        String,
        i64,
        Option<String>,
        String,
        String,
    ) = db.query_row(
        "SELECT state,after_consume,receipt,run_pin,request FROM managed_current_requests WHERE id=?1",
        [current_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
    )?;
    let pin: RunPin = decoded(&current_pin)?;
    let request: serde_json::Value = decoded(&current_request)?;
    if current_state != "received"
        || after_consume != 1
        || current_receipt.as_deref() != Some(encoded(authority.receipt())?.as_str())
        || authority.request() != Some(&request)
        || pin.route != binding.run_route
        || &pin.endpoint() != authority.endpoint()
    {
        return Err(Fault::Unauthorized);
    }
    Ok(FreshAuthority {
        reference: reference.ok_or(Fault::Unauthorized)?,
        receipt: receipt.ok_or(Fault::Unauthorized)?,
        current_id: current_id.into(),
        run_pin: current_pin,
    })
}

/// Apply an immediate participant read and consume every fresh authority in one
/// local transaction. Run and Bridge I/O must have finished before this call.
pub(crate) fn execute_read(
    db: &mut Connection,
    context_id: &str,
    command: &Command,
    digest: &str,
    authorities: &[crate::managed_run::CurrentAuthority],
    consumed: &crate::managed_bridge::Consumed,
) -> Result<crate::domain::Reply, Fault> {
    if !matches!(command, Command::Get(_) | Command::List(_)) {
        return Err(Fault::Invalid);
    }
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let context = context_current(&tx, context_id, command, digest, true)?;
    if authorities.len() != context.bindings.len() {
        return Err(Fault::Unauthorized);
    }
    let submitted: bool = tx.query_row(
        "SELECT state='submitted' FROM managed_bootstrap WHERE invocation_key=?1",
        [&context.invocation_key],
        |row| row.get(0),
    )?;
    if !submitted {
        return Err(Fault::Unauthorized);
    }
    let mut current_ids = std::collections::BTreeSet::new();
    for (binding, authority) in context.bindings.iter().zip(authorities) {
        let fresh = verify_fresh_authority(&tx, &context, digest, binding, authority, consumed)?;
        if !current_ids.insert(fresh.current_id) {
            return Err(Fault::Unauthorized);
        }
    }
    let reply = crate::store::managed_read_projection(&tx, command, &context)?;
    for id in current_ids {
        if tx.execute(
            "UPDATE managed_current_requests SET state='used' WHERE id=?1 AND state='received'",
            [id],
        )? != 1
        {
            return Err(Fault::Stale);
        }
    }
    tx.execute(
        "UPDATE managed_contexts SET state='invalidated' WHERE id=?1 AND state='prepared'",
        [context_id],
    )?;
    // The consumed Bridge association still needs its exact abort before the
    // bootstrap can be terminal, even though this read has no Run admission.
    tx.commit()?;
    Ok(reply)
}

/// Atomically reserve one mutation's domain key after fresh authority was established.
/// The caller must verify the current Bridge assertion and Run binding before this operation.
#[allow(
    clippy::too_many_arguments,
    reason = "Explicit evidence and original route are security fences"
)]
pub(crate) fn reserve_intent(
    db: &mut Connection,
    context_id: &str,
    member_id: &str,
    command: &Command,
    digest: &str,
    authority: crate::managed_run::CurrentAuthority,
    consumed: &crate::managed_bridge::Consumed,
    pool_route: &Route,
) -> Result<IntentReservation, Fault> {
    let change = command.change().ok_or(Fault::Invalid)?;
    let domain_digest = command.digest()?;
    let scope = format!("member:{member_id}");
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    // A fresh invocation may replay an earlier domain receipt even if its expected revision differs.
    let context = context_current(&tx, context_id, command, digest, false)?;
    let binding = context
        .bindings
        .iter()
        .find(|b| b.member_id == member_id && b.pool_id == change.pool_id)
        .ok_or(Fault::Forbidden)?;
    let fresh = verify_fresh_authority(&tx, &context, digest, binding, &authority, consumed)?;
    if pool_route.component_store_id != context.pool_store_id
        || pool_route.worker_uid != binding.run_route.worker_uid
        || pool_route.route_id.is_empty()
    {
        return Err(Fault::Conflict);
    }
    let FreshAuthority {
        reference,
        receipt,
        current_id,
        run_pin: current_pin,
    } = fresh;
    let pin: RunPin = decoded(&current_pin)?;
    let member_json: String = tx.query_row(
        "SELECT data FROM members WHERE id=?1 AND pool=?2 AND current=1",
        params![member_id, change.pool_id],
        |row| row.get(0),
    )?;
    let member: crate::domain::Binding = decoded(&member_json)?;
    crate::store::authorize(command, false, Some(&member))?;
    let exact: Option<(String, String, Option<String>)> = tx
        .query_row(
            "SELECT security_digest,state,terminal_receipt FROM managed_intents WHERE id=?1",
            [&context.intent_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    if let Some((original, state, receipt)) = exact {
        if original != digest {
            return Err(Fault::Conflict);
        }
        let result = match state.as_str() {
            "committed" => IntentReservation::Committed(receipt.ok_or(Fault::Internal)?),
            "aborted" => IntentReservation::Aborted(receipt.ok_or(Fault::Internal)?),
            _ => IntentReservation::Pending,
        };
        tx.execute("UPDATE managed_bootstrap SET state='terminal' WHERE invocation_key=?1 AND state='submitted'",[&context.invocation_key])?;
        tx.execute(
            "UPDATE managed_current_requests SET state='used' WHERE id=?1 AND state='received'",
            [current_id],
        )?;
        tx.commit()?;
        return Ok(result);
    }
    let legacy: Option<(String, String)> = tx
        .query_row(
            "SELECT digest,receipt FROM requests WHERE scope=?1 AND key=?2",
            params![scope, change.request_key],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((old, receipt)) = legacy {
        tx.execute(
            "UPDATE managed_contexts SET state='invalidated' WHERE id=?1 AND state='prepared'",
            [context_id],
        )?;
        tx.execute(
            "UPDATE managed_current_requests SET state='used' WHERE id=?1 AND state='received'",
            [current_id],
        )?;
        tx.commit()?;
        return if old == domain_digest {
            Ok(IntentReservation::Committed(receipt))
        } else {
            Err(Fault::Conflict)
        };
    }
    let mapped: Option<(String,String,String,Option<String>)> = tx.query_row("SELECT k.domain_digest,i.id,i.state,i.terminal_receipt FROM managed_domain_keys k JOIN managed_intents i ON i.id=k.intent_id WHERE k.scope=?1 AND k.request_key=?2",params![scope,change.request_key],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
    if let Some((old, _id, state, receipt)) = mapped {
        let result = if old != domain_digest {
            Err(Fault::Conflict)
        } else {
            Ok(match state.as_str() {
                "committed" => IntentReservation::Committed(receipt.ok_or(Fault::Internal)?),
                // An aborted but uncleaned effect remains reserved until all remote fences resolve.
                _ => IntentReservation::Pending,
            })
        };
        tx.execute(
            "UPDATE managed_contexts SET state='invalidated' WHERE id=?1 AND state='prepared'",
            [context_id],
        )?;
        tx.execute(
            "UPDATE managed_current_requests SET state='used' WHERE id=?1 AND state='received'",
            [current_id],
        )?;
        tx.commit()?;
        return result;
    }
    context_current(&tx, context_id, command, digest, true)?;
    if !pin
        .capabilities
        .iter()
        .any(|capability| capability == "attempt_admission_v1")
    {
        return Err(Fault::Unavailable);
    }
    tx.execute("INSERT INTO managed_intents(id,context_id,scope,request_key,domain_digest,security_digest,command,pool_route,run_route,run_pin,state,consumed_ref,consumed_receipt) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'admitting',?11,?12)",params![context.intent_id,context_id,scope,change.request_key,domain_digest,digest,encoded(command)?,encoded(pool_route)?,encoded(&binding.run_route)?,current_pin,reference,receipt])?;
    tx.execute("INSERT INTO managed_domain_keys(scope,request_key,domain_digest,intent_id) VALUES(?1,?2,?3,?4)",params![scope,change.request_key,domain_digest,context.intent_id])?;
    tx.execute("UPDATE managed_bootstrap SET state='terminal' WHERE invocation_key=?1 AND state='submitted'",[&context.invocation_key])?;
    tx.execute(
        "UPDATE managed_current_requests SET state='used' WHERE id=?1 AND state='received'",
        [current_id],
    )?;
    tx.commit()?;
    Ok(IntentReservation::Created)
}

fn admission_lineage_valid(admission: &crate::managed_run::Admission) -> bool {
    let attestation = CurrentReceipt {
        receipt_id: admission.admission_id.clone(),
        purpose: "admission".into(),
        lineage_root_id: admission.binding.attempt.lineage_root_id.clone(),
        bound_execution_id: admission.binding.attempt.execution_id.clone(),
        attempt: admission.binding.attempt.clone(),
        incarnation: admission.incarnation.clone(),
        actor: admission.binding.actor.clone(),
        successor_proof: admission.successor_proof.clone(),
    };
    receipt_matches(
        &attestation,
        &admission.binding,
        &admission.binding,
        &admission.incarnation,
        "admission",
    )
}

/// Persist a correlated, authenticated Run admission, never promoting a terminal abort.
pub(crate) fn mark_admitted(
    db: &mut Connection,
    intent_id: &str,
    digest: &str,
    admission: &crate::managed_run::Admission,
) -> Result<(), Fault> {
    wire_string(&admission.admission_id)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    type AdmissionRow = (
        String,
        String,
        Option<String>,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let (state, stored, prior, context_id, reference, receipt,prior_fingerprint): AdmissionRow = tx.query_row(
        "SELECT state,security_digest,admission,context_id,consumed_ref,consumed_receipt,admission_fingerprint FROM managed_intents WHERE id=?1",
        [intent_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?,r.get(6)?)),
    )?;
    if stored != digest {
        return Err(Fault::Conflict);
    }
    let admission_json = encoded(admission)?;
    let fingerprint = admission_fingerprint(admission)?;
    if state == "admitted"
        && prior.as_deref() == Some(&admission_json)
        && prior_fingerprint.as_deref() == Some(fingerprint.as_str())
    {
        return Ok(());
    }
    if state != "admitting" {
        return Err(Fault::Stale);
    }
    let reference: crate::managed_run::ConsumedRef =
        decoded(reference.as_deref().ok_or(Fault::Internal)?)?;
    let receipt: crate::managed_bridge::ConsumeReceipt =
        decoded(receipt.as_deref().ok_or(Fault::Internal)?)?;
    let context_json: String = tx.query_row(
        "SELECT context FROM managed_contexts WHERE id=?1",
        [context_id],
        |r| r.get(0),
    )?;
    let context: SecurityContext = decoded(&context_json)?;
    if admission.intent_id != intent_id
        || admission.security_digest != digest
        || admission.policy != "admission_snapshot"
        || admission.consumed_ref != reference
        || admission.incarnation != receipt.observation.incarnation
        || admission.binding.actor != receipt.observation.actor
        || admission.binding.attempt.launch_id != receipt.observation.launch_id
        || !context.bindings.contains(&admission.binding)
        || !admission_lineage_valid(admission)
    {
        return Err(Fault::Conflict);
    }
    tx.execute(
        "UPDATE managed_intents SET state='admitted',admission_id=?2,admission=?3,admission_fingerprint=?4 WHERE id=?1",
        params![intent_id, admission.admission_id, admission_json,fingerprint],
    )?;
    tx.commit()?;
    Ok(())
}
/// Local CAS fingerprint over the complete authenticated admission snapshot.
fn admission_fingerprint(admission: &crate::managed_run::Admission) -> Result<String, Fault> {
    let value = serde_json::to_value(admission).map_err(|_| Fault::Internal)?;
    Ok(crate::managed_codec::digest(b"agent-pool/managed-admission-cas/v1\0", &value)?.1)
}
/// Recheck the exact admission and original consumed association in the commit transaction.
fn check_admission(
    db: &Connection,
    intent_id: &str,
    digest: &str,
    context: &SecurityContext,
) -> Result<crate::managed_run::Admission, Fault> {
    let (raw, fingerprint, reference): (Option<String>, Option<String>, Option<String>) = db
        .query_row(
            "SELECT admission,admission_fingerprint,consumed_ref FROM managed_intents WHERE id=?1",
            [intent_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
    let admission: crate::managed_run::Admission =
        decoded(raw.as_deref().ok_or(Fault::Unavailable)?)?;
    let reference: crate::managed_run::ConsumedRef =
        decoded(reference.as_deref().ok_or(Fault::Unavailable)?)?;
    if admission.intent_id != intent_id
        || admission.security_digest != digest
        || admission.policy != "admission_snapshot"
        || admission.consumed_ref != reference
        || !context.bindings.contains(&admission.binding)
        || fingerprint.as_deref() != Some(admission_fingerprint(&admission)?.as_str())
    {
        return Err(Fault::Conflict);
    }
    Ok(admission)
}

/// Fence all delayed CAS operations before requesting remote aborts.
pub(crate) fn terminal_abort(
    db: &mut Connection,
    intent_id: &str,
    digest: &str,
    receipt: &str,
) -> Result<(), Fault> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (state, stored, prior): (String, String, Option<String>) = tx.query_row(
        "SELECT state,security_digest,terminal_receipt FROM managed_intents WHERE id=?1",
        [intent_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    if stored != digest {
        return Err(Fault::Conflict);
    }
    if state == "aborted" {
        return if prior.as_deref() == Some(receipt) {
            Ok(())
        } else {
            Err(Fault::Conflict)
        };
    }
    if state == "committed" {
        return Err(Fault::Conflict);
    }
    // Context creation follows a potentially submitted Bridge bootstrap; even a
    // locally prepared intent needs its original invocation durably fenced.
    let bridge_done = 0;
    let run_done = i64::from(matches!(state.as_str(), "prepared" | "consuming"));
    tx.execute("UPDATE managed_intents SET state='aborted',terminal_receipt=?2,effect_free=1,bridge_resolved=?3,run_resolved=?4 WHERE id=?1",params![intent_id,receipt,bridge_done,run_done])?;
    if bridge_done == 1 && run_done == 1 {
        tx.execute(
            "DELETE FROM managed_domain_keys WHERE intent_id=?1",
            [intent_id],
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// Record a verified durable remote abort/settlement fence; absence/timeout is never a fence.
fn resolve_abort_fence(
    db: &mut Connection,
    intent_id: &str,
    digest: &str,
    bridge: bool,
    proof: &str,
) -> Result<bool, Fault> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (state, stored): (String, String) = tx.query_row(
        "SELECT state,security_digest FROM managed_intents WHERE id=?1",
        [intent_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if stored != digest || state != "aborted" {
        return Err(Fault::Conflict);
    }
    let prior: Option<String> = if bridge {
        tx.query_row(
            "SELECT bridge_abort_receipt FROM managed_intents WHERE id=?1",
            [intent_id],
            |r| r.get(0),
        )?
    } else {
        tx.query_row(
            "SELECT run_resolution_receipt FROM managed_intents WHERE id=?1",
            [intent_id],
            |r| r.get(0),
        )?
    };
    if prior.as_deref().is_some_and(|old| old != proof) {
        return Err(Fault::Conflict);
    }
    if bridge {
        tx.execute(
            "UPDATE managed_intents SET bridge_resolved=1,bridge_abort_receipt=?2 WHERE id=?1",
            params![intent_id, proof],
        )?;
        tx.execute("UPDATE managed_bootstrap SET state='terminal' WHERE invocation_key=(SELECT c.invocation_key FROM managed_intents i JOIN managed_contexts c ON c.id=i.context_id WHERE i.id=?1) AND state='submitted'",[intent_id])?;
    } else {
        tx.execute(
            "UPDATE managed_intents SET run_resolved=1,run_resolution_receipt=?2 WHERE id=?1",
            params![intent_id, proof],
        )?;
    }
    let done: bool = tx.query_row("SELECT bridge_resolved=1 AND run_resolved=1 AND effect_free=1 FROM managed_intents WHERE id=?1",[intent_id],|r|r.get(0))?;
    if done {
        tx.execute(
            "DELETE FROM managed_domain_keys WHERE intent_id=?1",
            [intent_id],
        )?;
    }
    tx.commit()?;
    Ok(done)
}

/// Persist the exact Bridge abort request ID before any abort request can be sent.
pub(crate) fn mark_bridge_abort_submitted(
    db: &mut Connection,
    context_id: &str,
    key: &crate::managed_bridge::ConsumeKey<'_>,
    pin: &crate::managed_bridge::BridgePin,
) -> Result<(), Fault> {
    wire_string(key.abort_request_id)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    verify_bridge_pin(&tx, context_id, pin)?;
    type AbortMarkerRow = (
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let (context_json,route_json,producer,namespace,registration,consume_id,prior,intent_state):AbortMarkerRow=tx.query_row("SELECT c.context,n.bridge_route,n.producer,n.state,b.registration_digest,b.consume_request_id,b.bridge_abort_request_id,(SELECT i.state FROM managed_intents i WHERE i.context_id=c.id) FROM managed_contexts c JOIN managed_bootstrap b ON b.invocation_key=c.invocation_key AND b.namespace_id=c.namespace_id JOIN managed_namespaces n ON n.id=b.namespace_id WHERE c.id=?1",[context_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?)))?;
    let context: SecurityContext = decoded(&context_json)?;
    let route: Route = decoded(&route_json)?;
    if route.component_store_id != key.expected_store_id
        || producer != key.producer
        || context.invocation_key != key.invocation_key
        || context.audience != key.audience
        || registration.as_deref() != Some(key.security_digest)
        || consume_id.as_deref() != Some(key.consume_request_id)
    {
        return Err(Fault::Conflict);
    }
    if namespace == "sealed"
        || intent_state
            .as_deref()
            .is_some_and(|state| state != "aborted")
    {
        return Err(Fault::Stale);
    }
    if prior
        .as_deref()
        .is_some_and(|old| old != key.abort_request_id)
    {
        return Err(Fault::Conflict);
    }
    if intent_state.is_none() {
        // Fence the local continuation before the remote abort can be sent.
        tx.execute(
            "UPDATE managed_contexts SET state='invalidated' WHERE id=?1 AND state='prepared'",
            [context_id],
        )?;
        tx.execute(
            "UPDATE managed_current_requests SET state='aborted' WHERE COALESCE(json_extract(request,'$.invocation_key'),json_extract(request,'$.observation_ref.invocation_key'))=?1 AND state IN ('prepared','received')",
            [&context.invocation_key],
        )?;
    }
    if prior.is_some() {
        tx.commit()?;
        return Ok(());
    }
    tx.execute("UPDATE managed_bootstrap SET bridge_abort_request_id=?2 WHERE invocation_key=?1 AND namespace_id=(SELECT namespace_id FROM managed_contexts WHERE id=?3)",params![context.invocation_key,key.abort_request_id,context_id])?;
    tx.commit()?;
    Ok(())
}

/// Accept only a correlated durable Bridge abort; lookup absence is never a fence.
pub(crate) fn record_bridge_abort(
    db: &mut Connection,
    intent_id: &str,
    digest: &str,
    key: &crate::managed_bridge::ConsumeKey<'_>,
    result: &crate::managed_bridge::Abort,
    pin: &crate::managed_bridge::BridgePin,
) -> Result<bool, Fault> {
    if key.consume_request_id != intent_id
        || key.security_digest != digest
        || result.store_id != key.expected_store_id
        || !result.aborted
        || result.receipt.as_ref().is_some_and(|receipt| {
            receipt.producer != key.producer
                || receipt.consume_request_id != intent_id
                || receipt.invocation_key != key.invocation_key
                || receipt.security_digest != digest
        })
    {
        return Err(Fault::Conflict);
    }
    let (route_json,producer,issuer,context_json,context_digest,abort_id,consumed): (String,String,String,String,String,Option<String>,Option<String>) = db.query_row("SELECT n.bridge_route,n.producer,n.issuer_epoch,c.context,c.digest,b.bridge_abort_request_id,i.consumed_receipt FROM managed_intents i JOIN managed_contexts c ON c.id=i.context_id JOIN managed_namespaces n ON n.id=c.namespace_id JOIN managed_bootstrap b ON b.invocation_key=c.invocation_key AND b.namespace_id=c.namespace_id WHERE i.id=?1",[intent_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?)))?;
    require_original_consume(consumed.as_deref(), result.receipt.as_ref())?;
    let route: Route = decoded(&route_json)?;
    let context: SecurityContext = decoded(&context_json)?;
    let context_id: String = db.query_row(
        "SELECT context_id FROM managed_intents WHERE id=?1",
        [intent_id],
        |row| row.get(0),
    )?;
    verify_bridge_pin(db, &context_id, pin)?;
    if route.component_store_id != key.expected_store_id
        || producer != key.producer
        || context.invocation_key != key.invocation_key
        || context.audience != key.audience
        || context_digest != digest
        || abort_id.as_deref() != Some(key.abort_request_id)
        || result
            .receipt
            .as_ref()
            .is_some_and(|receipt| receipt.issuer_epoch != issuer)
    {
        return Err(Fault::Conflict);
    }
    resolve_abort_fence(db, intent_id, digest, true, &encoded(result)?)
}

/// Accept only Run's matching durable pre-admission tombstone or settled abort.
pub(crate) fn record_run_abort(
    db: &mut Connection,
    intent_id: &str,
    digest: &str,
    result: &crate::managed_run::Lookup,
) -> Result<bool, Fault> {
    let local = outcome(db, intent_id, digest)?;
    if local.state != "aborted" {
        return Err(Fault::Conflict);
    }
    match result.state.as_str() {
        "aborted_before_admit" if result.admission.is_none() && result.outcome_digest.is_none() => {
            let prior: Option<String> = db.query_row(
                "SELECT admission_id FROM managed_intents WHERE id=?1",
                [intent_id],
                |row| row.get(0),
            )?;
            if prior.is_some() {
                return Err(Fault::Conflict);
            }
        }
        "settled_aborted"
            if result.outcome_digest == local.outcome_digest
                && result.admission.as_ref().is_some_and(|admission| {
                    admission.intent_id == intent_id && admission.security_digest == digest
                }) =>
        {
            let admission = result.admission.as_ref().ok_or(Fault::Internal)?;
            let (context_json,reference,receipt,prior): (String,Option<String>,Option<String>,Option<String>) = db.query_row("SELECT c.context,i.consumed_ref,i.consumed_receipt,i.admission FROM managed_intents i JOIN managed_contexts c ON c.id=i.context_id WHERE i.id=?1",[intent_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
            let context: SecurityContext = decoded(&context_json)?;
            let reference: crate::managed_run::ConsumedRef =
                decoded(reference.as_deref().ok_or(Fault::Unavailable)?)?;
            let receipt: crate::managed_bridge::ConsumeReceipt =
                decoded(receipt.as_deref().ok_or(Fault::Unavailable)?)?;
            if admission.policy != "admission_snapshot"
                || admission.consumed_ref != reference
                || !context.bindings.contains(&admission.binding)
                || !admission_lineage_valid(admission)
                || admission.incarnation != receipt.observation.incarnation
                || admission.binding.actor != receipt.observation.actor
                || admission.binding.attempt.launch_id != receipt.observation.launch_id
                || prior.as_ref().is_some_and(|stored| {
                    encoded(admission).map_or(true, |current| current != *stored)
                })
            {
                return Err(Fault::Conflict);
            }
        }
        _ => return Err(Fault::Unavailable),
    }
    resolve_abort_fence(db, intent_id, digest, false, &encoded(result)?)
}

/// Applies the exact admitted command and its terminal receipt atomically after full local CAS.
/// The supplied operation must perform only local SQLite work in this transaction; it must
/// recheck domain authorization/revision and write its domain receipt and outbox atomically.
pub(crate) fn commit<F>(
    db: &mut Connection,
    intent_id: &str,
    digest: &str,
    apply: F,
) -> Result<String, Fault>
where
    F: FnOnce(&Connection, &Command) -> Result<String, Fault>,
{
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (state,stored,context_id,command_json,prior): (String,String,String,String,Option<String>) = tx.query_row("SELECT state,security_digest,context_id,command,terminal_receipt FROM managed_intents WHERE id=?1",[intent_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
    if stored != digest {
        return Err(Fault::Conflict);
    }
    if state == "committed" {
        return prior.ok_or(Fault::Internal);
    }
    if state != "admitted" {
        return Err(Fault::Stale);
    }
    let command: Command = decoded(&command_json)?;
    let context = context_current(&tx, &context_id, &command, digest, true)?;
    check_admission(&tx, intent_id, digest, &context)?;
    // The existing consensus engine cannot yet consume authenticated all-voter
    // observations. Never commit a managed vote through this internal seam.
    if matches!(command, Command::Vote(_)) {
        return Err(Fault::Unavailable);
    }
    let receipt = apply(&tx, &command)?;
    tx.execute("UPDATE managed_intents SET state='committed',terminal_receipt=?2,bridge_resolved=1 WHERE id=?1",params![intent_id,receipt])?;
    tx.commit()?;
    Ok(receipt)
}

/// Apply the existing participant state machine only after the managed CAS.
pub(crate) fn commit_domain(
    db: &mut Connection,
    intent_id: &str,
    digest: &str,
) -> Result<String, Fault> {
    commit(db, intent_id, digest, |tx, command| {
        let context_json: String = tx.query_row(
            "SELECT c.context FROM managed_intents i JOIN managed_contexts c ON c.id=i.context_id WHERE i.id=?1",
            [intent_id],
            |row| row.get(0),
        )?;
        let context: SecurityContext = decoded(&context_json)?;
        Ok(crate::store::apply_managed_mutation(tx, command, &context, false)?.0)
    })
}

/// Reserve a bootstrap and its exact original namespace before any Bridge I/O.
#[derive(Clone, Copy)]
pub(crate) struct BootstrapRequest<'a> {
    pub namespace_id: &'a str,
    pub bootstrap_id: &'a str,
    pub route: &'a Route,
    pub bridge_pin: &'a crate::managed_bridge::BridgePin,
    pub producer: &'a str,
    pub issuer_epoch: &'a str,
    pub invocation_key: &'a str,
    pub command: &'a Command,
    pub native_proof: &'a bridge_sdk::bridge_protocol::CallEvidence,
}
pub(crate) fn reserve_bootstrap(
    db: &mut Connection,
    request: &BootstrapRequest<'_>,
) -> Result<(), Fault> {
    let BootstrapRequest {
        namespace_id,
        bootstrap_id,
        route,
        bridge_pin,
        producer,
        issuer_epoch,
        invocation_key,
        command,
        native_proof,
    } = *request;
    for value in [
        namespace_id,
        bootstrap_id,
        producer,
        issuer_epoch,
        invocation_key,
    ] {
        wire_string(value)?;
    }
    command.validate()?;
    let command_json = encoded(&serde_json::to_value(command).map_err(|_| Fault::Internal)?)?;
    let proof_value = serde_json::to_value(native_proof).map_err(|_| Fault::Invalid)?;
    let proof_hash = crate::managed_codec::digest(
        b"agent-mcp/attempt-binding/bootstrap-proof/v1\0",
        &proof_value,
    )?
    .1;
    let hash_valid = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    if &bridge_pin.route != route
        || bridge_pin.producer != producer
        || !bridge_pin.registration_socket.is_absolute()
        || !bridge_pin.core_socket.is_absolute()
        || !bridge_pin.server_executable.is_absolute()
        || !bridge_pin.credential_file.is_absolute()
        || [
            &bridge_pin.registration_socket,
            &bridge_pin.core_socket,
            &bridge_pin.server_executable,
            &bridge_pin.credential_file,
        ]
        .iter()
        .any(|path| {
            path.components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        })
        || !hash_valid(&bridge_pin.server_sha256)
        || !hash_valid(&bridge_pin.credential_sha256)
    {
        return Err(Fault::Invalid);
    }
    let route_json = encoded(route)?;
    let bridge_pin_json = encoded(bridge_pin)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let pinned: Option<String> = tx
        .query_row(
            "SELECT pin FROM managed_bridge_routes WHERE route=?1",
            [&route_json],
            |row| row.get(0),
        )
        .optional()?;
    match pinned {
        Some(value) if value == bridge_pin_json => {}
        Some(_) => return Err(Fault::Conflict),
        None => return Err(Fault::Unavailable),
    }
    let existing: Option<(String, Option<String>, String, String, String)> = tx
        .query_row(
            "SELECT bridge_route,bridge_pin,producer,issuer_epoch,state FROM managed_namespaces WHERE id=?1",
            [namespace_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?,r.get(4)?)),
        )
        .optional()?;
    match existing {
        Some((old_route, old_pin, old_producer, old_epoch, state)) => {
            if (old_route, old_pin, old_producer, old_epoch)
                != (
                    route_json.clone(),
                    Some(bridge_pin_json.clone()),
                    producer.to_owned(),
                    issuer_epoch.to_owned(),
                )
            {
                return Err(Fault::Conflict);
            }
            if state != "open" {
                return Err(Fault::Stale);
            }
        }
        None => {
            if managed_capacity_inner(&tx, false)?.namespaces.active >= MANAGED_CAPACITY {
                return Err(Fault::Unavailable);
            }
            tx.execute("INSERT INTO managed_namespaces(id,bridge_route,bridge_pin,producer,issuer_epoch,state) VALUES(?1,?2,?3,?4,?5,'open')",params![namespace_id,route_json,bridge_pin_json,producer,issuer_epoch])?;
        }
    }
    let prior: Option<(String, String, String, String)> = tx
        .query_row(
            "SELECT namespace_id,invocation_key,command,proof_hash FROM managed_bootstrap WHERE id=?1",
            [bootstrap_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    if let Some((namespace, invocation, previous_command, previous_proof)) = prior {
        if namespace != namespace_id
            || invocation != invocation_key
            || previous_command != command_json
            || previous_proof != proof_hash
        {
            return Err(Fault::Conflict);
        }
        return Ok(());
    }
    let reused:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM managed_bootstrap WHERE invocation_key=?1 AND state!='stale_epoch')",[invocation_key],|row|row.get(0))?;
    if reused {
        return Err(Fault::Conflict);
    }
    let capacity = managed_capacity_inner(&tx, false)?;
    if capacity.bootstraps.active >= MANAGED_CAPACITY
        || capacity
            .contexts
            .active
            .saturating_add(capacity.bootstrap_reservations)
            >= MANAGED_CAPACITY
        || capacity
            .intents
            .active
            .saturating_add(capacity.bootstrap_reservations)
            .saturating_add(capacity.contexts_without_intent)
            >= MANAGED_CAPACITY
    {
        return Err(Fault::Unavailable);
    }
    tx.execute("INSERT INTO managed_bootstrap(id,namespace_id,invocation_key,command,proof_hash,state) VALUES(?1,?2,?3,?4,?5,'prepared')",params![bootstrap_id,namespace_id,invocation_key,command_json,proof_hash])?;
    tx.commit()?;
    Ok(())
}

/// One in-memory first-submission marker; it cannot be reconstructed after a crash.
pub(crate) struct BootstrapDispatch {
    id: String,
}
/// Mark possible submission durably before preparing the original Bridge observation.
pub(crate) fn mark_bootstrap_submitted(
    db: &mut Connection,
    bootstrap_id: &str,
) -> Result<BootstrapDispatch, Fault> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (state,namespace): (String,String) = tx.query_row("SELECT b.state,n.state FROM managed_bootstrap b JOIN managed_namespaces n ON n.id=b.namespace_id WHERE b.id=?1",[bootstrap_id],|r|Ok((r.get(0)?,r.get(1)?)))?;
    if state != "prepared" || namespace != "open" {
        return Err(Fault::Stale);
    }
    tx.execute(
        "UPDATE managed_bootstrap SET state='submitted' WHERE id=?1",
        [bootstrap_id],
    )?;
    tx.commit()?;
    Ok(BootstrapDispatch {
        id: bootstrap_id.into(),
    })
}

/// A definitive Bridge stale-epoch refusal is pre-reservation and permits
/// rediscovery only on the response to this process's first possible submission.
/// A lost ACK or restart loses the marker and requires exact-key recovery/abort.
pub(crate) fn mark_bootstrap_stale_epoch(
    db: &mut Connection,
    dispatch: BootstrapDispatch,
    refusal: crate::managed_bridge::BridgeFailure,
) -> Result<(), Fault> {
    if refusal != crate::managed_bridge::BridgeFailure::StaleEpoch {
        return Err(Fault::Invalid);
    }
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (state, reference): (String, Option<String>) = tx.query_row(
        "SELECT state,bridge_context_ref FROM managed_bootstrap WHERE id=?1",
        [&dispatch.id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if state != "submitted" || reference.is_some() {
        return Err(Fault::Conflict);
    }
    tx.execute(
        "UPDATE managed_bootstrap SET state='stale_epoch' WHERE id=?1",
        [&dispatch.id],
    )?;
    tx.commit()?;
    Ok(())
}

/// Persist a verified successful prepare before any registration or managed context use.
pub(crate) fn record_bootstrap_ref(
    db: &mut Connection,
    dispatch: BootstrapDispatch,
    prepared: &crate::managed_bridge::Prepared,
    used_pin: &crate::managed_bridge::BridgePin,
) -> Result<(), Fault> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (state,namespace,route,invocation,prior,stored_pin): (String,String,String,String,Option<String>,Option<String>) = tx.query_row("SELECT b.state,n.state,n.bridge_route,b.invocation_key,b.bridge_context_ref,n.bridge_pin FROM managed_bootstrap b JOIN managed_namespaces n ON n.id=b.namespace_id WHERE b.id=?1",[&dispatch.id],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)))?;
    let route: Route = decoded(&route)?;
    if state != "submitted"
        || namespace != "open"
        || route.component_store_id != prepared.store_id
        || invocation != prepared.invocation_key
        || prepared.bridge_context_ref.expose().is_empty()
        || stored_pin.as_deref() != Some(encoded(used_pin)?.as_str())
        || prior.is_some()
    {
        return Err(Fault::Stale);
    }
    tx.execute(
        "UPDATE managed_bootstrap SET bridge_context_ref=?2 WHERE id=?1",
        params![dispatch.id, prepared.bridge_context_ref.expose()],
    )?;
    tx.commit()?;
    Ok(())
}

/// Durably freeze the registration request and real digest before Bridge I/O.
pub(crate) fn mark_registration_submitted(
    db: &mut Connection,
    bootstrap_id: &str,
    context_id: &str,
    request_id: &str,
    digest: &str,
    pin: &crate::managed_bridge::BridgePin,
) -> Result<(), Fault> {
    wire_string(request_id)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    verify_bridge_pin(&tx, context_id, pin)?;
    let (state,namespace,reference,invocation,old_request,old_digest):(String,String,Option<String>,String,Option<String>,Option<String>)=tx.query_row("SELECT b.state,n.state,b.bridge_context_ref,b.invocation_key,b.registration_request_id,b.registration_digest FROM managed_bootstrap b JOIN managed_namespaces n ON n.id=b.namespace_id WHERE b.id=?1",[bootstrap_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)))?;
    let (ctx_invocation, ctx_digest, ctx_state, intent_id): (String, String, String, String) = tx
        .query_row(
        "SELECT invocation_key,digest,state,intent_id FROM managed_contexts WHERE id=?1",
        [context_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    if state != "submitted" || namespace != "open" || reference.is_none() || ctx_state != "prepared"
    {
        return Err(Fault::Stale);
    }
    if invocation != ctx_invocation || ctx_digest != digest {
        return Err(Fault::Conflict);
    }
    if old_request.is_some() || old_digest.is_some() {
        return if old_request.as_deref() == Some(request_id)
            && old_digest.as_deref() == Some(digest)
        {
            Ok(())
        } else {
            Err(Fault::Conflict)
        };
    }
    tx.execute("UPDATE managed_bootstrap SET registration_request_id=?2,registration_digest=?3,consume_request_id=?4 WHERE id=?1",params![bootstrap_id,request_id,digest,intent_id])?;
    tx.commit()?;
    Ok(())
}

/// Abandon a pre-registration invocation locally; delayed prepare ACKs cannot register.
pub(crate) fn abandon_unregistered_bootstrap(
    db: &mut Connection,
    bootstrap_id: &str,
) -> Result<(), Fault> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (state, invocation, registration): (String, String, Option<String>) = tx.query_row(
        "SELECT state,invocation_key,registration_request_id FROM managed_bootstrap WHERE id=?1",
        [bootstrap_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    if state == "terminal" {
        return Ok(());
    }
    if registration.is_some() || !matches!(state.as_str(), "prepared" | "submitted") {
        return Err(Fault::Conflict);
    }
    let has_intent:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM managed_intents i JOIN managed_contexts c ON c.id=i.context_id WHERE c.invocation_key=?1)",[&invocation],|r|r.get(0))?;
    if has_intent {
        return Err(Fault::Conflict);
    }
    tx.execute("UPDATE managed_contexts SET state='invalidated' WHERE invocation_key=?1 AND state='prepared'",[&invocation])?;
    tx.execute("UPDATE managed_current_requests SET state='aborted' WHERE COALESCE(json_extract(request,'$.invocation_key'),json_extract(request,'$.observation_ref.invocation_key'))=?1 AND state IN ('prepared','received')",[&invocation])?;
    tx.execute(
        "UPDATE managed_bootstrap SET state='terminal' WHERE id=?1",
        [bootstrap_id],
    )?;
    tx.commit()?;
    Ok(())
}

/// Serialize a retirement fence with new contexts, pending CAS and recovery accounting.
/// Only the authenticated, configured Run reader may invoke the eventual wire endpoint.
/// The same generated seal ID survives retries while draining progresses to sealed.
pub(crate) struct SealStatus {
    pub seal_id: String,
    pub sealed: bool,
}
/// Strip no-longer-actionable command/snapshot payloads while retaining all keys,
/// terminal outcomes, route bindings and remote recovery receipts as tombstones.
pub(crate) fn compact_sealed(db: &Connection, namespace_id: &str) -> Result<(), Fault> {
    let sealed: bool = db.query_row(
        "SELECT state='sealed' FROM managed_namespaces WHERE id=?1",
        [namespace_id],
        |row| row.get(0),
    )?;
    let pending: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM managed_bootstrap WHERE namespace_id=?1 AND state NOT IN ('terminal','stale_epoch')) OR EXISTS(SELECT 1 FROM managed_intents i JOIN managed_contexts c ON c.id=i.context_id WHERE c.namespace_id=?1 AND (i.state NOT IN ('committed','aborted') OR i.bridge_resolved=0 OR i.run_resolved=0))",[namespace_id],|row|row.get(0))?;
    if !sealed || pending {
        return Err(Fault::Stale);
    }
    db.execute("UPDATE managed_bootstrap SET command='{}' WHERE namespace_id=?1 AND state IN ('terminal','stale_epoch') AND command!='{}'",[namespace_id])?;
    db.execute("UPDATE managed_contexts SET command='{}',snapshot='{}',state='invalidated' WHERE namespace_id=?1 AND (command!='{}' OR snapshot!='{}' OR state!='invalidated')",[namespace_id])?;
    db.execute("UPDATE managed_intents SET command='{}' WHERE context_id IN (SELECT id FROM managed_contexts WHERE namespace_id=?1) AND state IN ('committed','aborted') AND bridge_resolved=1 AND run_resolved=1 AND command!='{}'",[namespace_id])?;
    db.execute("UPDATE managed_current_requests SET request='{}',state='aborted' WHERE (namespace_id=?1 OR owner_intent IN (SELECT i.id FROM managed_intents i JOIN managed_contexts c ON c.id=i.context_id WHERE c.namespace_id=?1)) AND (request!='{}' OR state!='aborted')",[namespace_id])?;
    Ok(())
}
pub(crate) fn seal_namespace(
    db: &mut Connection,
    route: &Route,
    producer: &str,
    issuer_epoch: &str,
    request_id: &str,
    retirement_key: &str,
) -> Result<SealStatus, Fault> {
    for value in [producer, issuer_epoch, request_id, retirement_key] {
        wire_string(value)?;
    }
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let route_json = encoded(route)?;
    let conflicting: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM managed_namespaces WHERE (request_id=?1 OR retirement_key=?2) AND (bridge_route!=?3 OR producer!=?4 OR issuer_epoch!=?5))",params![request_id,retirement_key,route_json,producer,issuer_epoch],|r|r.get(0))?;
    if conflicting {
        return Err(Fault::Conflict);
    }
    type NamespaceRow = (
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let row: Option<NamespaceRow> = tx.query_row("SELECT id,state,request_id,retirement_key,seal_id FROM managed_namespaces WHERE bridge_route=?1 AND producer=?2 AND issuer_epoch=?3",params![route_json,producer,issuer_epoch],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
    let (namespace_id, state, old_request, old_key, old_seal) = if let Some(row) = row {
        row
    } else {
        if managed_capacity_inner(&tx, false)?.namespaces.active >= MANAGED_CAPACITY {
            return Err(Fault::Unavailable);
        }
        let namespace_id = crate::domain::id();
        tx.execute("INSERT INTO managed_namespaces(id,bridge_route,producer,issuer_epoch,state) VALUES(?1,?2,?3,?4,'open')",params![namespace_id,route_json,producer,issuer_epoch])?;
        (namespace_id, "open".into(), None, None, None)
    };
    if state != "open"
        && (old_request.as_deref() != Some(request_id)
            || old_key.as_deref() != Some(retirement_key))
    {
        return Err(Fault::Conflict);
    }
    let seal_id = if state == "open" {
        crate::domain::id()
    } else {
        old_seal.ok_or(Fault::Internal)?
    };
    if state == "sealed" {
        compact_sealed(&tx, &namespace_id)?;
        tx.commit()?;
        return Ok(SealStatus {
            seal_id,
            sealed: true,
        });
    }
    if state == "open" {
        tx.execute("UPDATE managed_namespaces SET state='draining',request_id=?2,retirement_key=?3,seal_id=?4 WHERE id=?1",params![namespace_id,request_id,retirement_key,seal_id])?;
        tx.execute("UPDATE managed_contexts SET state='invalidated' WHERE namespace_id=?1 AND state='prepared'",[&namespace_id])?;
        tx.execute("UPDATE managed_current_requests SET state='aborted' WHERE namespace_id=?1 AND state IN ('prepared','received')",[&namespace_id])?;
        // Bridge owns expiry sealing; Pool fences all pre-registration continuations locally.
        tx.execute("UPDATE managed_bootstrap SET state='terminal' WHERE namespace_id=?1 AND state IN ('prepared','submitted') AND registration_request_id IS NULL",[&namespace_id])?;
    }
    let pending: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM managed_bootstrap WHERE namespace_id=?1 AND state NOT IN ('terminal','stale_epoch')) OR EXISTS(SELECT 1 FROM managed_intents i JOIN managed_contexts c ON c.id=i.context_id WHERE c.namespace_id=?1 AND (i.state NOT IN ('committed','aborted') OR i.bridge_resolved=0 OR i.run_resolved=0))",[&namespace_id],|r|r.get(0))?;
    if !pending {
        tx.execute(
            "UPDATE managed_namespaces SET state='sealed' WHERE id=?1",
            [&namespace_id],
        )?;
        compact_sealed(&tx, &namespace_id)?;
    }
    tx.commit()?;
    Ok(SealStatus {
        seal_id,
        sealed: !pending,
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "Isolated synthetic SQLite and authority fixtures"
)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        domain::{Change, Command},
        store::Store,
    };
    use std::{os::unix::fs::PermissionsExt, path::PathBuf};

    pub(crate) struct FakeRun {
        pub(crate) receipt: CurrentReceipt,
        observation: VoterObservation,
    }
    impl RunAuthority for FakeRun {
        fn current_receipt(
            &self,
            _route: &Route,
            receipt_id: &str,
        ) -> Result<CurrentReceipt, Fault> {
            if receipt_id.starts_with("fixture-initial-") {
                let mut receipt = self.receipt.clone();
                receipt.receipt_id = receipt_id.into();
                return Ok(receipt);
            }
            if self.receipt.receipt_id != receipt_id {
                return Err(Fault::Unavailable);
            }
            Ok(self.receipt.clone())
        }
        fn consensus(
            &self,
            _route: &Route,
            _attempt: &AttemptRef,
            _incarnation: &Incarnation,
        ) -> Result<VoterObservation, Fault> {
            Ok(self.observation.clone())
        }
    }
    pub(crate) fn fake_run_endpoint(binding: &ManagedBinding) -> RunEndpointPin {
        RunEndpointPin {
            route: binding.run_route.clone(),
            socket: "/fixture/attempt.sock".into(),
            executable: "/fixture/run".into(),
            executable_sha256: "a".repeat(64),
        }
    }
    pub(crate) fn fixture() -> (
        tempfile::TempDir,
        Store,
        ManagedBinding,
        Incarnation,
        FakeRun,
    ) {
        fixture_with_uid(1000)
    }
    pub(crate) fn fixture_with_uid(
        uid: u32,
    ) -> (
        tempfile::TempDir,
        Store,
        ManagedBinding,
        Incarnation,
        FakeRun,
    ) {
        let root = PathBuf::from(std::env::var_os("TMPDIR").expect("task TMPDIR required"));
        let dir = tempfile::tempdir_in(root).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut store = Store::open(&dir.path().join("pool.db")).unwrap();
        let db = store.test_db();
        db.execute(
            "INSERT INTO leaders(actor,address) VALUES('owner','owner-address')",
            [],
        )
        .unwrap();
        db.execute("INSERT INTO pools(id,owner,data) VALUES('pool','owner',?1)",[r#"{"pool_id":"pool","name":"pool","purpose":"goal","revision":1,"closed":false,"proposal":null}"#]).unwrap();
        let member = crate::domain::Binding {
            member: crate::domain::Member {
                member_id: "member".into(),
                name: "member".into(),
                role: "role".into(),
                task: "task".into(),
                state: crate::domain::MemberState::Pending,
                runtime: "unknown".into(),
            },
            pool_id: "pool".into(),
            actor: None,
            address: Some("host/codex/store/session".into()),
            run_id: Some("execution".into()),
            run_sequence: Some(1),
            run_execution_ref: None,
            run_pin_id: None,
            run_store_id: None,
        };
        db.execute(
            "INSERT INTO members(id,pool,current,data) VALUES('member','pool',1,?1)",
            [encoded(&member).unwrap()],
        )
        .unwrap();
        let pool_store_id: String = db
            .query_row("SELECT store_id FROM inventory_source", [], |r| r.get(0))
            .unwrap();
        let attempt = AttemptRef {
            run_store_id: "store_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            lineage_root_id: "root".into(),
            execution_id: "root".into(),
            sequence: 1,
            attempt_id: "attempt-1".into(),
            launch_id: "00000000-0000-4000-8000-000000000001".into(),
        };
        let incarnation = Incarnation {
            host_id: "host".into(),
            boot_id: "00000000-0000-4000-8000-000000000001".into(),
            pid_namespace_inode: 1,
            uid,
            pid: 123,
            start_ticks: 1,
        };
        let binding = ManagedBinding {
            pool_store_id,
            pool_id: "pool".into(),
            member_id: "member".into(),
            binding_generation: 1,
            attempt: attempt.clone(),
            actor: ManagedActor {
                address: "host/codex/store/session".into(),
                role: "root".into(),
                native_id: "session".into(),
                epoch: 1,
            },
            run_route: Route {
                component_store_id: "store_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                route_id: "run-route".into(),
                worker_uid: uid,
            },
            bridge_route: Route {
                component_store_id: "00000000-0000-4000-8000-000000000003".into(),
                route_id: "bridge-route".into(),
                worker_uid: uid,
            },
        };
        db.execute("INSERT INTO managed_bindings(member,pool,generation,binding,incarnation) VALUES('member','pool',?1,?2,?3)",params![sqlite_generation(1),encoded(&binding).unwrap(),encoded(&incarnation).unwrap()]).unwrap();
        persist_bridge_route(db, &fake_bridge_pin(&binding)).unwrap();
        persist_run_route(db, &fake_run_endpoint(&binding)).unwrap();
        db.execute(
            "INSERT INTO managed_pool_epochs(pool,epoch) VALUES('pool',1)",
            [],
        )
        .unwrap();
        let proof = SuccessorProof {
            lineage_root_id: "root".into(),
            bound_execution_id: "root".into(),
            current_execution_id: "root".into(),
            chain: vec![SuccessorLink {
                execution_id: "root".into(),
                parent_execution_id: None,
                sequence: 1,
            }],
        };
        let receipt = CurrentReceipt {
            receipt_id: "receipt-1".into(),
            purpose: "ingress".into(),
            lineage_root_id: "root".into(),
            bound_execution_id: "root".into(),
            attempt: attempt.clone(),
            incarnation: incarnation.clone(),
            actor: binding.actor.clone(),
            successor_proof: proof.clone(),
        };
        let observation = VoterObservation {
            state: VoterState::Live,
            last_attempt: Some(attempt),
            last_incarnation: Some(incarnation.clone()),
            successor_proof: Some(proof),
        };
        (
            dir,
            store,
            binding,
            incarnation,
            FakeRun {
                receipt,
                observation,
            },
        )
    }
    fn command(revision: u64) -> Command {
        Command::Join(Change {
            pool_id: "pool".into(),
            expected_revision: revision,
            request_key: "key".into(),
        })
    }
    pub(crate) fn native_proof() -> bridge_sdk::bridge_protocol::CallEvidence {
        bridge_sdk::bridge_protocol::CallEvidence::Native {
            host: bridge_sdk::bridge_protocol::Host::Codex,
            metadata: serde_json::Map::new(),
        }
    }
    pub(crate) fn fake_bridge_pin(binding: &ManagedBinding) -> crate::managed_bridge::BridgePin {
        crate::managed_bridge::BridgePin {
            route: binding.bridge_route.clone(),
            producer: "pool".into(),
            registration_socket: "/fixture/adapter.sock".into(),
            core_socket: "/fixture/core.sock".into(),
            server_executable: "/fixture/bridge".into(),
            server_sha256: "a".repeat(64),
            credential_file: "/fixture/token".into(),
            credential_sha256: "b".repeat(64),
        }
    }
    pub(crate) fn fake_config(binding: &ManagedBinding) -> crate::config::Config {
        crate::config::Config {
            socket_path: "/fixture/pool.sock".into(),
            database_path: "/fixture/pool.db".into(),
            expected_uid: binding.run_route.worker_uid,
            bridge_registration_socket: "/fixture/adapter.sock".into(),
            bridge_core_socket: "/fixture/core.sock".into(),
            bridge_credential_file: "/fixture/token".into(),
            bridge_producer_id: "pool".into(),
            bridge_audience: "pool".into(),
            bridge_server_executable: "/fixture/bridge".into(),
            bridge_server_sha256: "a".repeat(64),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            owner_observer_credential_file: None,
            run_socket: None,
            run_peer_uid: None,
            managed_run_reader: None,
            managed_run_transport: Some(crate::config::ManagedRunTransport {
                frontend_enabled: false,
                mcp_server: None,
                socket: "/fixture/attempt.sock".into(),
                executable: "/fixture/run".into(),
                sha256: "a".repeat(64),
                run_store_id: binding.run_route.component_store_id.clone(),
                run_route_id: binding.run_route.route_id.clone(),
                pool_route_id: "pool-route".into(),
                bridge_store_id: binding.bridge_route.component_store_id.clone(),
                bridge_route_id: binding.bridge_route.route_id.clone(),
                producer: "pool".into(),
            }),
        }
    }
    fn context(binding: &ManagedBinding, intent: &str, invocation: &str) -> SecurityContext {
        SecurityContext {
            version: 1,
            command_schema: "pool-command-v1".into(),
            pool_store_id: binding.pool_store_id.clone(),
            audience: "pool".into(),
            producer: "pool".into(),
            intent_id: intent.into(),
            invocation_key: invocation.into(),
            nonce: "nonce".into(),
            bindings: vec![binding.clone()],
        }
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "Independent fixture identities remain explicit"
    )]
    fn prepare(
        db: &mut Connection,
        run: &FakeRun,
        binding: &ManagedBinding,
        incarnation: &Incarnation,
        id: &str,
        intent: &str,
        invocation: &str,
        revision: u64,
    ) -> String {
        prepare_command(
            db,
            run,
            binding,
            incarnation,
            id,
            intent,
            invocation,
            &command(revision),
        )
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "Independent fixture identities remain explicit"
    )]
    pub(crate) fn prepare_command(
        db: &mut Connection,
        run: &FakeRun,
        binding: &ManagedBinding,
        incarnation: &Incarnation,
        id: &str,
        intent: &str,
        invocation: &str,
        cmd: &Command,
    ) -> String {
        prepare_command_in_namespace(
            db,
            run,
            binding,
            incarnation,
            id,
            intent,
            invocation,
            cmd,
            "namespace",
            "epoch",
        )
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "Test isolates namespace and issuer replay identities"
    )]
    fn prepare_command_in_namespace(
        db: &mut Connection,
        run: &FakeRun,
        binding: &ManagedBinding,
        incarnation: &Incarnation,
        id: &str,
        intent: &str,
        invocation: &str,
        cmd: &Command,
        namespace: &str,
        issuer: &str,
    ) -> String {
        let proof = native_proof();
        reserve_bootstrap(
            db,
            &BootstrapRequest {
                namespace_id: namespace,
                bootstrap_id: id,
                route: &binding.bridge_route,
                bridge_pin: &fake_bridge_pin(binding),
                producer: "pool",
                issuer_epoch: issuer,
                invocation_key: invocation,
                command: cmd,
                native_proof: &proof,
            },
        )
        .unwrap();
        let dispatch = mark_bootstrap_submitted(db, id).unwrap();
        let prepared = crate::managed_bridge::Prepared {
            store_id: binding.bridge_route.component_store_id.clone(),
            bridge_context_ref: bridge_sdk::bridge_protocol::Secret::new(format!("bridge-{id}")),
            invocation_key: invocation.into(),
            expires_at_ms: 100,
        };
        record_bootstrap_ref(db, dispatch, &prepared, &fake_bridge_pin(binding)).unwrap();
        record_fake_current(db, run, binding, incarnation, id, invocation, "initial");
        let digest = prepare_context(
            db,
            run,
            id,
            namespace,
            cmd,
            &context(binding, intent, invocation),
            &[(
                format!("fixture-initial-{id}").as_str(),
                incarnation.clone(),
            )],
        )
        .unwrap();
        mark_registration_submitted(
            db,
            id,
            id,
            &format!("register-{id}"),
            &digest,
            &fake_bridge_pin(binding),
        )
        .unwrap();
        let mut consumed = fake_consumed(binding, incarnation, intent, invocation, &digest, cmd);
        consumed.receipt.issuer_epoch = issuer.into();
        let key = crate::managed_bridge::ConsumeKey {
            abort_request_id: "abort-1",
            expected_store_id: &binding.bridge_route.component_store_id,
            producer: "pool",
            consume_request_id: intent,
            invocation_key: invocation,
            security_digest: &digest,
            audience: "pool",
        };
        mark_bootstrap_consume_submitted(db, id, intent, &digest, &fake_bridge_pin(binding))
            .unwrap();
        record_bootstrap_consumption(
            db,
            id,
            &key,
            &consumed,
            "pool",
            cmd,
            issuer,
            &fake_bridge_pin(binding),
        )
        .unwrap();
        record_fake_current(db, run, binding, incarnation, id, invocation, "fresh");
        digest
    }
    fn record_fake_current(
        db: &mut Connection,
        run: &FakeRun,
        binding: &ManagedBinding,
        incarnation: &Incarnation,
        context_id: &str,
        invocation: &str,
        stage: &str,
    ) {
        assert_eq!(&run.receipt.incarnation, incarnation);
        let request_id = format!("{stage}-{context_id}");
        let endpoint_json: String = db
            .query_row(
                "SELECT pin FROM managed_run_routes WHERE route=?1",
                [encoded(&binding.run_route).unwrap()],
                |row| row.get(0),
            )
            .unwrap();
        let endpoint: RunEndpointPin = decoded(&endpoint_json).unwrap();
        let pin = RunPin {
            route: endpoint.route.clone(),
            socket: endpoint.socket.clone(),
            executable: endpoint.executable.clone(),
            executable_sha256: endpoint.executable_sha256.clone(),
            capabilities: vec![
                "attempt_current_ingress_v1".into(),
                "attempt_admission_v1".into(),
            ],
        };
        let intent = CurrentIntent::Ingress {
            version: 1,
            expected_store_id: binding.attempt.run_store_id.clone(),
            request_id: request_id.clone(),
            observation_ref: bridge_sdk::bridge_protocol::Secret::new(format!(
                "bridge-{context_id}"
            )),
            invocation_key: invocation.into(),
        };
        prepare_current_request(db, &pin, &intent).unwrap();
        let mut receipt = run.receipt.clone();
        receipt.receipt_id = format!("fixture-{stage}-{context_id}");
        let authority = crate::managed_run::CurrentAuthority::fixture(
            endpoint,
            receipt,
            invocation,
            &request_id,
            serde_json::to_value(&intent).unwrap(),
        );
        record_current_receipt(db, &request_id, &authority).unwrap();
    }
    pub(crate) fn fake_consumed(
        binding: &ManagedBinding,
        incarnation: &Incarnation,
        intent: &str,
        invocation: &str,
        digest: &str,
        command: &Command,
    ) -> crate::managed_bridge::Consumed {
        use crate::managed_bridge::{ConsumeReceipt, Consumed, Observation, Validity};
        let receipt = ConsumeReceipt {
            producer: "pool".into(),
            consume_request_id: intent.into(),
            invocation_key: invocation.into(),
            security_digest: digest.into(),
            issuer_epoch: "epoch".into(),
            consumed_at_ms: 1,
            observation: Observation {
                incarnation: incarnation.clone(),
                launch_id: binding.attempt.launch_id.clone(),
                actor: binding.actor.clone(),
                native_call_id: "call".into(),
                tool_name: format!(
                    "mcp__pool__{}",
                    crate::managed_bridge::command_name(command).unwrap()
                ),
                observed_at_ms: 1,
                expires_at_ms: 2,
            },
        };
        Consumed {
            store_id: binding.bridge_route.component_store_id.clone(),
            receipt,
            validity: Validity::Current,
            aborted: false,
        }
    }
    pub(crate) fn fresh_authority(
        db: &Connection,
        _binding: &ManagedBinding,
        context_id: &str,
        invocation: &str,
    ) -> Result<crate::managed_run::CurrentAuthority, Fault> {
        let request_id = format!("fresh-{context_id}");
        let (request_json, pin_json): (String, String) = db.query_row(
            "SELECT request,run_pin FROM managed_current_requests WHERE id=?1",
            [&request_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let pin: RunPin = decoded(&pin_json)?;
        let request: serde_json::Value =
            serde_json::from_str(&request_json).map_err(|_| Fault::Internal)?;
        let receipt_json: String = db.query_row(
            "SELECT receipt FROM managed_current_requests WHERE id=?1",
            [&request_id],
            |row| row.get(0),
        )?;
        let receipt: CurrentReceipt = decoded(&receipt_json)?;
        Ok(crate::managed_run::CurrentAuthority::fixture(
            pin.endpoint(),
            receipt,
            invocation,
            &request_id,
            request,
        ))
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "Fixture verifies exact invocation and evidence"
    )]
    pub(crate) fn reserve(
        db: &mut Connection,
        _run: &FakeRun,
        binding: &ManagedBinding,
        incarnation: &Incarnation,
        context_id: &str,
        invocation: &str,
        intent: &str,
        command: &Command,
        digest: &str,
    ) -> Result<IntentReservation, Fault> {
        let authority = fresh_authority(db, binding, context_id, invocation)?;
        let consumed = fake_consumed(binding, incarnation, intent, invocation, digest, command);
        let pool_route = Route {
            component_store_id: binding.pool_store_id.clone(),
            route_id: "pool-route".into(),
            worker_uid: binding.run_route.worker_uid,
        };
        reserve_intent(
            db,
            context_id,
            "member",
            command,
            digest,
            authority,
            &consumed,
            &pool_route,
        )
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "Fixture retains independent correlation fields"
    )]
    pub(crate) fn consumed_admission(
        _db: &mut Connection,
        run: &FakeRun,
        binding: &ManagedBinding,
        incarnation: &Incarnation,
        intent: &str,
        invocation: &str,
        digest: &str,
        command: &Command,
    ) -> crate::managed_run::Admission {
        let _ = command;
        crate::managed_run::Admission {
            admission_id: "admission-1".into(),
            intent_id: intent.into(),
            security_digest: digest.into(),
            policy: "admission_snapshot".into(),
            binding: binding.clone(),
            incarnation: incarnation.clone(),
            successor_proof: run.receipt.successor_proof.clone(),
            consumed_ref: crate::managed_run::ConsumedRef {
                bridge_route: binding.bridge_route.clone(),
                producer: "pool".into(),
                consume_request_id: intent.into(),
                invocation_key: invocation.into(),
                security_digest: digest.into(),
                issuer_epoch: "epoch".into(),
            },
        }
    }
    #[test]
    fn rootless_ingress_requires_full_chain_containing_original_binding() {
        let (_dir, _store, mut old, incarnation, mut run) = fixture();
        old.attempt.execution_id = "middle".into();
        old.attempt.sequence = 2;
        let mut successor = old.clone();
        successor.attempt.execution_id = "next".into();
        successor.attempt.sequence = 3;
        successor.attempt.attempt_id = "attempt-3".into();
        successor.attempt.launch_id = "00000000-0000-4000-8000-000000000004".into();
        run.receipt.attempt = successor.attempt.clone();
        run.receipt.successor_proof.current_execution_id = "next".into();
        run.receipt.successor_proof.chain.extend([
            SuccessorLink {
                execution_id: "middle".into(),
                parent_execution_id: Some("root".into()),
                sequence: 2,
            },
            SuccessorLink {
                execution_id: "next".into(),
                parent_execution_id: Some("middle".into()),
                sequence: 3,
            },
        ]);
        assert!(valid_ingress_receipt(&run.receipt, &old.run_route));
        let mut mismatched = run.receipt.clone();
        mismatched.actor.native_id = "other-session".into();
        assert!(!valid_ingress_receipt(&mismatched, &old.run_route));
        mismatched = run.receipt.clone();
        mismatched.incarnation.host_id = "other-host".into();
        assert!(!valid_ingress_receipt(&mismatched, &old.run_route));
        assert!(receipt_matches(
            &run.receipt,
            &old,
            &successor,
            &incarnation,
            "ingress"
        ));
        let mut foreign = old.clone();
        foreign.attempt.execution_id = "foreign".into();
        assert!(!receipt_matches(
            &run.receipt,
            &foreign,
            &successor,
            &incarnation,
            "ingress"
        ));
        run.receipt.successor_proof.chain[2].parent_execution_id = Some("root".into());
        assert!(!valid_ingress_receipt(&run.receipt, &old.run_route));
    }

    #[test]
    fn rebind_race_generation_and_failover_boundary_snapshot() {
        let (_dir, mut store, binding, incarnation, mut run) = fixture();
        let db = store.test_db();
        let digest = prepare(
            db,
            &run,
            &binding,
            &incarnation,
            "context-1",
            "intent-1",
            "inv-1",
            1,
        );
        assert_eq!(
            reserve(
                db,
                &run,
                &binding,
                &incarnation,
                "context-1",
                "inv-1",
                "intent-1",
                &command(1),
                &digest
            )
            .unwrap(),
            IntentReservation::Created
        );
        let admission = consumed_admission(
            db,
            &run,
            &binding,
            &incarnation,
            "intent-1",
            "inv-1",
            &digest,
            &command(1),
        );
        mark_admitted(db, "intent-1", &digest, &admission).unwrap();
        let old_revision: i64 = db
            .query_row(
                "SELECT json_extract(data,'$.revision') FROM pools WHERE id='pool'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let mut successor = binding.clone();
        successor.attempt.execution_id = "next".into();
        successor.attempt.sequence = 2;
        successor.attempt.attempt_id = "attempt-2".into();
        successor.attempt.launch_id = "00000000-0000-4000-8000-000000000002".into();
        let mut next_incarnation = incarnation.clone();
        next_incarnation.pid = 124;
        next_incarnation.start_ticks = 2;
        run.receipt.receipt_id = "receipt-2".into();
        run.receipt.attempt = successor.attempt.clone();
        run.receipt.incarnation = next_incarnation.clone();
        run.receipt.successor_proof.current_execution_id = "next".into();
        run.receipt.successor_proof.chain.push(SuccessorLink {
            execution_id: "next".into(),
            parent_execution_id: Some("root".into()),
            sequence: 2,
        });
        assert_eq!(
            rebind(
                db,
                &run,
                &binding,
                &successor,
                &next_incarnation,
                "receipt-2",
                "ingress"
            )
            .unwrap(),
            2
        );
        assert_eq!(
            rebind(
                db,
                &run,
                &binding,
                &successor,
                &next_incarnation,
                "receipt-2",
                "ingress"
            )
            .unwrap(),
            2
        );
        assert_eq!(
            commit(db, "intent-1", &digest, |_, _| panic!(
                "invalidated CAS executed"
            ))
            .err(),
            Some(Fault::Stale)
        );
        let revision: i64 = db
            .query_row(
                "SELECT json_extract(data,'$.revision') FROM pools WHERE id='pool'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(old_revision, revision);
        let mut foreign = successor.clone();
        foreign.attempt.lineage_root_id = "foreign".into();
        assert_eq!(
            rebind(
                db,
                &run,
                &binding,
                &foreign,
                &next_incarnation,
                "receipt-2",
                "ingress"
            )
            .err(),
            Some(Fault::Forbidden)
        );
    }
    #[test]
    fn egress_rebind_without_ingress_context() {
        let (_dir, mut store, binding, incarnation, mut run) = fixture();
        let db = store.test_db();
        let mut successor = binding.clone();
        successor.attempt.execution_id = "next".into();
        successor.attempt.sequence = 2;
        successor.attempt.attempt_id = "attempt-2".into();
        successor.attempt.launch_id = "00000000-0000-4000-8000-000000000004".into();
        let mut next = incarnation.clone();
        next.pid = 124;
        next.start_ticks = 2;
        run.receipt.receipt_id = "egress-1".into();
        run.receipt.purpose = "egress".into();
        run.receipt.attempt = successor.attempt.clone();
        run.receipt.incarnation = next.clone();
        run.receipt.successor_proof.current_execution_id = "next".into();
        run.receipt.successor_proof.chain.push(SuccessorLink {
            execution_id: "next".into(),
            parent_execution_id: Some("root".into()),
            sequence: 2,
        });
        let mut pin = RunPin {
            route: binding.run_route.clone(),
            socket: "/fixture/attempt.sock".into(),
            executable: "/fixture/run".into(),
            executable_sha256: "a".repeat(64),
            capabilities: vec!["attempt_current_ingress_v1".into()],
        };
        assert_eq!(
            crate::managed_run::EgressQuery::stage(db, &pin, &binding.attempt, "egress-key", "rpc")
                .err(),
            Some(Fault::Invalid)
        );
        pin.capabilities = vec!["attempt_current_egress_v1".into()];
        crate::managed_run::EgressQuery::stage(db, &pin, &binding.attempt, "egress-key", "rpc")
            .unwrap();
        let request: String = db
            .query_row(
                "SELECT request FROM managed_current_requests WHERE id='egress-key'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let request: serde_json::Value = serde_json::from_str(&request).unwrap();
        assert_eq!(request["purpose"], "egress");
        assert!(request.get("observation_ref").is_none());
        let mut wrong_receipt = run.receipt.clone();
        wrong_receipt.actor.role = "child".into();
        let wrong = crate::managed_run::CurrentAuthority::egress_fixture(
            fake_run_endpoint(&binding),
            wrong_receipt,
            "egress-key",
            request.clone(),
        );
        assert_eq!(
            record_current_receipt(db, "egress-key", &wrong).err(),
            Some(Fault::Conflict)
        );
        let mut wrong_endpoint = fake_run_endpoint(&binding);
        wrong_endpoint.socket = "/other/attempt.sock".into();
        let wrong_route = crate::managed_run::CurrentAuthority::egress_fixture(
            wrong_endpoint,
            run.receipt.clone(),
            "egress-key",
            request.clone(),
        );
        assert_eq!(
            record_current_receipt(db, "egress-key", &wrong_route).err(),
            Some(Fault::Conflict)
        );
        assert_eq!(
            rebind_authenticated(db, &wrong_route, &binding, &successor, &next, "egress").err(),
            Some(Fault::Stale)
        );
        let authority = crate::managed_run::CurrentAuthority::egress_fixture(
            fake_run_endpoint(&binding),
            run.receipt.clone(),
            "egress-key",
            request,
        );
        record_current_receipt(db, "egress-key", &authority).unwrap();
        record_current_receipt(db, "egress-key", &authority).unwrap();
        assert_eq!(
            rebind_authenticated(db, &authority, &binding, &successor, &next, "egress").unwrap(),
            2
        );
        db.execute(
            "UPDATE managed_current_requests SET state='aborted' WHERE id='egress-key'",
            [],
        )
        .unwrap();
        assert_eq!(
            rebind_authenticated(db, &authority, &binding, &successor, &next, "egress").unwrap(),
            2
        );
        let contexts: i64 = db
            .query_row("SELECT count(*) FROM managed_contexts", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(contexts, 0);
    }
    #[test]
    fn binding_generation_full_u64_and_overflow() {
        let (_dir, mut store, mut binding, incarnation, mut run) = fixture();
        let db = store.test_db();
        binding.binding_generation = u64::MAX - 1;
        db.execute(
            "UPDATE managed_bindings SET generation=?1,binding=?2 WHERE member='member'",
            params![
                sqlite_generation(binding.binding_generation),
                encoded(&binding).unwrap()
            ],
        )
        .unwrap();

        let mut successor = binding.clone();
        successor.attempt.attempt_id = "attempt-2".into();
        successor.attempt.launch_id = "00000000-0000-4000-8000-000000000004".into();
        let mut next = incarnation.clone();
        next.pid += 1;
        next.start_ticks += 1;
        run.receipt.receipt_id = "large-generation-1".into();
        run.receipt.attempt = successor.attempt.clone();
        run.receipt.incarnation = next.clone();
        assert_eq!(
            rebind(
                db,
                &run,
                &binding,
                &successor,
                &next,
                "large-generation-1",
                "ingress"
            )
            .unwrap(),
            u64::MAX
        );
        assert_eq!(
            rebind(
                db,
                &run,
                &binding,
                &successor,
                &next,
                "large-generation-1",
                "ingress"
            )
            .unwrap(),
            u64::MAX
        );

        successor.binding_generation = u64::MAX;
        let mut overflow = successor.clone();
        overflow.attempt.attempt_id = "attempt-3".into();
        overflow.attempt.launch_id = "00000000-0000-4000-8000-000000000005".into();
        let mut overflow_incarnation = next.clone();
        overflow_incarnation.pid += 1;
        overflow_incarnation.start_ticks += 1;
        run.receipt.receipt_id = "large-generation-2".into();
        run.receipt.attempt = overflow.attempt.clone();
        run.receipt.incarnation = overflow_incarnation.clone();
        let before: (Vec<u8>, String, i64) = db
            .query_row(
                "SELECT b.generation,b.binding,e.epoch FROM managed_bindings b JOIN managed_pool_epochs e ON e.pool=b.pool WHERE b.member='member'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(read_generation(&before.0).unwrap(), u64::MAX);
        assert_eq!(
            rebind(
                db,
                &run,
                &successor,
                &overflow,
                &overflow_incarnation,
                "large-generation-2",
                "ingress"
            )
            .err(),
            Some(Fault::Unavailable)
        );
        let after: (Vec<u8>, String, i64) = db
            .query_row(
                "SELECT b.generation,b.binding,e.epoch FROM managed_bindings b JOIN managed_pool_epochs e ON e.pool=b.pool WHERE b.member='member'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(after, before);
    }
    #[test]
    fn failover_boundary_snapshot_allows_pre_rebind_commit() {
        let (_dir, mut store, binding, incarnation, mut run) = fixture();
        let db = store.test_db();
        let digest = prepare(
            db,
            &run,
            &binding,
            &incarnation,
            "context-1",
            "intent-1",
            "inv-1",
            1,
        );
        assert_eq!(
            reserve(
                db,
                &run,
                &binding,
                &incarnation,
                "context-1",
                "inv-1",
                "intent-1",
                &command(1),
                &digest
            )
            .unwrap(),
            IntentReservation::Created
        );
        let admission = consumed_admission(
            db,
            &run,
            &binding,
            &incarnation,
            "intent-1",
            "inv-1",
            &digest,
            &command(1),
        );
        mark_admitted(db, "intent-1", &digest, &admission).unwrap();
        // A successor exists at Run, but Pool has not yet installed its generation.
        let mut successor = binding.clone();
        successor.attempt.execution_id = "next".into();
        successor.attempt.sequence = 2;
        successor.attempt.attempt_id = "attempt-2".into();
        successor.attempt.launch_id = "00000000-0000-4000-8000-000000000004".into();
        let mut next = incarnation.clone();
        next.pid += 1;
        next.start_ticks += 1;
        run.receipt.receipt_id = "receipt-2".into();
        run.receipt.attempt = successor.attempt.clone();
        run.receipt.incarnation = next.clone();
        run.receipt.successor_proof.current_execution_id = "next".into();
        run.receipt.successor_proof.chain.push(SuccessorLink {
            execution_id: "next".into(),
            parent_execution_id: Some("root".into()),
            sequence: 2,
        });
        let result = commit(db, "intent-1", &digest, |db, _| {
            db.execute(
                "UPDATE pools SET data=json_set(data,'$.revision',2) WHERE id='pool'",
                [],
            )?;
            Ok("committed".into())
        })
        .unwrap();
        assert_eq!(result, "committed");
        assert_eq!(
            rebind(
                db,
                &run,
                &binding,
                &successor,
                &next,
                "receipt-2",
                "ingress"
            )
            .unwrap(),
            2
        );
        assert_eq!(outcome(db, "intent-1", &digest).unwrap().state, "committed");
    }
    #[test]
    fn failover_between_consume_reserve_and_admission_fences_old_work() {
        for reserve_before_rebind in [false, true] {
            let (_dir, mut store, binding, incarnation, mut run) = fixture();
            let db = store.test_db();
            let digest = prepare(
                db,
                &run,
                &binding,
                &incarnation,
                "context-1",
                "intent-1",
                "inv-1",
                1,
            );
            if reserve_before_rebind {
                assert_eq!(
                    reserve(
                        db,
                        &run,
                        &binding,
                        &incarnation,
                        "context-1",
                        "inv-1",
                        "intent-1",
                        &command(1),
                        &digest
                    )
                    .unwrap(),
                    IntentReservation::Created
                );
            }
            let admission = consumed_admission(
                db,
                &run,
                &binding,
                &incarnation,
                "intent-1",
                "inv-1",
                &digest,
                &command(1),
            );
            let mut successor = binding.clone();
            successor.attempt.attempt_id = "attempt-2".into();
            successor.attempt.launch_id = "00000000-0000-4000-8000-000000000004".into();
            let mut next = incarnation.clone();
            next.pid += 1;
            next.start_ticks += 1;
            run.receipt.receipt_id = "receipt-2".into();
            run.receipt.attempt = successor.attempt.clone();
            run.receipt.incarnation = next.clone();
            assert_eq!(
                rebind(
                    db,
                    &run,
                    &binding,
                    &successor,
                    &next,
                    "receipt-2",
                    "ingress"
                )
                .unwrap(),
                2
            );

            if reserve_before_rebind {
                // A late durable Run admission still needs settlement, but cannot commit.
                mark_admitted(db, "intent-1", &digest, &admission).unwrap();
                assert_eq!(
                    commit(db, "intent-1", &digest, |_, _| panic!("stale CAS executed")).err(),
                    Some(Fault::Stale)
                );
                assert!(matches!(
                    stage_recovery(db, "intent-1", &digest).unwrap(),
                    RecoveryAction::LocallyFenced
                ));
                assert_eq!(
                    recovery_step(db, "intent-1", &digest).unwrap(),
                    RecoveryStep::AbortBridge
                );
            } else {
                assert_eq!(
                    reserve(
                        db,
                        &run,
                        &binding,
                        &incarnation,
                        "context-1",
                        "inv-1",
                        "intent-1",
                        &command(1),
                        &digest
                    )
                    .err(),
                    Some(Fault::Stale)
                );
                let BootstrapRecoveryAction::BridgeAbort { key, .. } =
                    stage_bootstrap_recovery(db, "context-1").unwrap()
                else {
                    panic!("consumed bootstrap needs its real-digest abort");
                };
                assert_eq!(key.security_digest, digest);
                assert_eq!(key.consume_request_id, "intent-1");
            }
        }
    }
    #[test]
    fn initial_binding_requires_original_run_store_and_lineage() {
        let (_dir, mut store, binding, incarnation, run) = fixture();
        let db = store.test_db();
        db.execute("DELETE FROM managed_bindings WHERE member='member'", [])
            .unwrap();
        let original: String = db
            .query_row("SELECT data FROM members WHERE id='member'", [], |r| {
                r.get(0)
            })
            .unwrap();
        let mut member: crate::domain::Binding = decoded(&original).unwrap();
        assert_eq!(
            bind_initial(db, &run, &binding, &incarnation, "receipt-1").err(),
            Some(Fault::Forbidden)
        );
        member.run_id = Some("root".into());
        member.run_store_id = Some(binding.attempt.run_store_id.clone());
        db.execute(
            "UPDATE members SET data=?1 WHERE id='member'",
            [encoded(&member).unwrap()],
        )
        .unwrap();
        bind_initial(db, &run, &binding, &incarnation, "receipt-1").unwrap();
        bind_initial(db, &run, &binding, &incarnation, "receipt-1").unwrap();
        let generation: Vec<u8> = db
            .query_row(
                "SELECT generation FROM managed_bindings WHERE member='member'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(read_generation(&generation).unwrap(), 1);
    }
    #[test]
    fn effect_free_abort_domain_key_and_delayed_cas() {
        let (_dir, mut store, binding, incarnation, run) = fixture();
        let db = store.test_db();
        let digest = prepare(
            db,
            &run,
            &binding,
            &incarnation,
            "context-1",
            "intent-1",
            "inv-1",
            1,
        );
        assert_eq!(
            reserve(
                db,
                &run,
                &binding,
                &incarnation,
                "context-1",
                "inv-1",
                "intent-1",
                &command(1),
                &digest
            )
            .unwrap(),
            IntentReservation::Created
        );
        let frozen = recovery_intent(db, "intent-1", &digest).unwrap();
        assert_eq!(frozen.state, "admitting");
        assert_eq!(
            recovery_step(db, "intent-1", &digest).unwrap(),
            RecoveryStep::FenceLocally
        );
        assert_eq!(frozen.consumed_ref.invocation_key, "inv-1");
        let recovery_client =
            crate::managed_run::RunPeer::from_recovery(&fake_config(&binding), &frozen).unwrap();
        assert_eq!(recovery_client.route, binding.run_route);
        let admission = consumed_admission(
            db,
            &run,
            &binding,
            &incarnation,
            "intent-1",
            "inv-1",
            &digest,
            &command(1),
        );
        let pending = outcome(db, "intent-1", &digest).unwrap();
        assert_eq!(pending.state, "pending");
        assert!(pending.outcome_digest.is_none());
        assert!(matches!(
            stage_recovery(db, "intent-1", &digest).unwrap(),
            RecoveryAction::LocallyFenced
        ));
        assert_eq!(
            recovery_step(db, "intent-1", &digest).unwrap(),
            RecoveryStep::AbortBridge
        );
        let terminal = outcome(db, "intent-1", &digest).unwrap();
        assert_eq!(terminal.state, "aborted");
        assert_eq!(terminal.outcome_digest.as_ref().unwrap().len(), 64);
        assert_eq!(
            terminal.outcome_digest,
            outcome(db, "intent-1", &digest).unwrap().outcome_digest
        );
        assert!(matches!(
            outcome(db, "intent-1", &"0".repeat(64)),
            Err(Fault::Conflict)
        ));
        let absent = crate::managed_run::Lookup {
            state: "absent".into(),
            admission: None,
            outcome_digest: None,
        };
        assert_eq!(
            record_run_abort(db, "intent-1", &digest, &absent).err(),
            Some(Fault::Unavailable)
        );
        assert_eq!(
            mark_admitted(db, "intent-1", &digest, &admission).err(),
            Some(Fault::Stale)
        );
        assert_eq!(
            commit(db, "intent-1", &digest, |_, _| panic!(
                "aborted CAS executed"
            ))
            .err(),
            Some(Fault::Stale)
        );
        let second = prepare(
            db,
            &run,
            &binding,
            &incarnation,
            "context-2",
            "intent-2",
            "inv-2",
            2,
        );
        assert_eq!(
            reserve(
                db,
                &run,
                &binding,
                &incarnation,
                "context-2",
                "inv-2",
                "intent-2",
                &command(2),
                &second
            )
            .unwrap(),
            IntentReservation::Pending
        );
        let RecoveryAction::BridgeAbort { pin, key, .. } =
            stage_recovery(db, "intent-1", &digest).unwrap()
        else {
            panic!("Bridge abort plan")
        };
        let RecoveryAction::BridgeAbort { key: replayed, .. } =
            stage_recovery(db, "intent-1", &digest).unwrap()
        else {
            panic!("Bridge abort replay")
        };
        assert_eq!(key.abort_request_id, replayed.abort_request_id);
        let missing_receipt = crate::managed_bridge::Abort {
            store_id: binding.bridge_route.component_store_id.clone(),
            aborted: true,
            receipt: None,
        };
        assert_eq!(
            record_bridge_abort(
                db,
                "intent-1",
                &digest,
                &key.borrowed(),
                &missing_receipt,
                &pin
            )
            .err(),
            Some(Fault::Unavailable)
        );
        let mut forged = fake_consumed(
            &binding,
            &incarnation,
            "intent-1",
            "inv-1",
            &digest,
            &command(1),
        )
        .receipt;
        forged.observation.incarnation.start_ticks += 1;
        let forged_abort = crate::managed_bridge::Abort {
            store_id: binding.bridge_route.component_store_id.clone(),
            aborted: true,
            receipt: Some(forged),
        };
        assert_eq!(
            record_bridge_abort(
                db,
                "intent-1",
                &digest,
                &key.borrowed(),
                &forged_abort,
                &pin
            )
            .err(),
            Some(Fault::Conflict)
        );
        let bridge_abort = crate::managed_bridge::Abort {
            store_id: binding.bridge_route.component_store_id.clone(),
            aborted: true,
            receipt: Some(
                fake_consumed(
                    &binding,
                    &incarnation,
                    "intent-1",
                    "inv-1",
                    &digest,
                    &command(1),
                )
                .receipt,
            ),
        };
        assert!(
            !record_bridge_abort(
                db,
                "intent-1",
                &digest,
                &key.borrowed(),
                &bridge_abort,
                &pin
            )
            .unwrap()
        );
        assert_eq!(
            recovery_step(db, "intent-1", &digest).unwrap(),
            RecoveryStep::AbortRun
        );
        let invalid_tombstone = crate::managed_run::Lookup {
            state: "aborted_before_admit".into(),
            admission: None,
            outcome_digest: Some(digest.clone()),
        };
        assert_eq!(
            record_run_abort(db, "intent-1", &digest, &invalid_tombstone).err(),
            Some(Fault::Unavailable)
        );
        assert_eq!(
            recovery_step(db, "intent-1", &digest).unwrap(),
            RecoveryStep::AbortRun
        );
        let tombstone = crate::managed_run::Lookup {
            state: "aborted_before_admit".into(),
            admission: None,
            outcome_digest: None,
        };
        assert!(record_run_abort(db, "intent-1", &digest, &tombstone).unwrap());
        assert_eq!(
            recovery_step(db, "intent-1", &digest).unwrap(),
            RecoveryStep::Done
        );
        let third = prepare(
            db,
            &run,
            &binding,
            &incarnation,
            "context-3",
            "intent-3",
            "inv-3",
            2,
        );
        assert_eq!(
            reserve(
                db,
                &run,
                &binding,
                &incarnation,
                "context-3",
                "inv-3",
                "intent-3",
                &command(2),
                &third
            )
            .unwrap(),
            IntentReservation::Created
        );
        assert_eq!(
            reserve(
                db,
                &run,
                &binding,
                &incarnation,
                "context-1",
                "inv-1",
                "intent-1",
                &command(1),
                &digest
            )
            .err(),
            Some(Fault::Unauthorized)
        );
    }
    #[test]
    fn same_request_key_fresh_invocation_replays_committed_receipt() {
        let (_dir, mut store, binding, incarnation, run) = fixture();
        let db = store.test_db();
        let digest = prepare(
            db,
            &run,
            &binding,
            &incarnation,
            "context-1",
            "intent-1",
            "inv-1",
            1,
        );
        assert_eq!(
            reserve(
                db,
                &run,
                &binding,
                &incarnation,
                "context-1",
                "inv-1",
                "intent-1",
                &command(1),
                &digest
            )
            .unwrap(),
            IntentReservation::Created
        );
        let admission = consumed_admission(
            db,
            &run,
            &binding,
            &incarnation,
            "intent-1",
            "inv-1",
            &digest,
            &command(1),
        );
        mark_admitted(db, "intent-1", &digest, &admission).unwrap();
        db.execute(
            "UPDATE managed_intents SET admission_fingerprint=?1 WHERE id='intent-1'",
            ["0".repeat(64)],
        )
        .unwrap();
        assert_eq!(
            commit(db, "intent-1", &digest, |_, _| panic!(
                "mismatched admission CAS ran"
            ))
            .err(),
            Some(Fault::Conflict)
        );
        db.execute(
            "UPDATE managed_intents SET admission_fingerprint=?1 WHERE id='intent-1'",
            [admission_fingerprint(&admission).unwrap()],
        )
        .unwrap();
        let receipt = commit(db,"intent-1",&digest,|db, command| {
            db.execute("INSERT INTO requests(scope,key,digest,receipt) VALUES('member:member','key',?1,'receipt')",[command.digest()?])?;
            Ok("receipt".into())
        }).unwrap();
        assert_eq!(receipt, "receipt");
        let outcome_digest = outcome(db, "intent-1", &digest)
            .unwrap()
            .outcome_digest
            .unwrap();
        let settlement = crate::managed_run::Lookup {
            state: "settled_committed".into(),
            admission: Some(admission),
            outcome_digest: Some(outcome_digest),
        };
        record_run_settlement(db, "intent-1", &digest, &settlement).unwrap();
        record_run_settlement(db, "intent-1", &digest, &settlement).unwrap();
        let new_digest = prepare(
            db,
            &run,
            &binding,
            &incarnation,
            "context-2",
            "intent-2",
            "inv-2",
            2,
        );
        assert_ne!(digest, new_digest);
        assert_eq!(
            reserve(
                db,
                &run,
                &binding,
                &incarnation,
                "context-2",
                "inv-2",
                "intent-2",
                &command(2),
                &new_digest
            )
            .unwrap(),
            IntentReservation::Committed("receipt".into())
        );
        let BootstrapRecoveryAction::BridgeAbort { key, .. } =
            stage_bootstrap_recovery(db, "context-2").unwrap()
        else {
            panic!("fresh replay must retain its original Bridge abort");
        };
        assert_eq!(key.consume_request_id, "intent-2");
        assert_eq!(key.security_digest, new_digest);
        assert_eq!(
            terminal_abort(db, "intent-1", &digest, "abort").err(),
            Some(Fault::Conflict)
        );
    }
    #[test]
    fn historical_consume_cannot_reserve_or_read_domain_receipt() {
        let (_dir, mut store, binding, incarnation, run) = fixture();
        let db = store.test_db();
        let digest = prepare(
            db,
            &run,
            &binding,
            &incarnation,
            "context-1",
            "intent-1",
            "inv-1",
            1,
        );
        let mut consumed = fake_consumed(
            &binding,
            &incarnation,
            "intent-1",
            "inv-1",
            &digest,
            &command(1),
        );
        consumed.validity = crate::managed_bridge::Validity::Historical;
        let receipt_json: String = db
            .query_row(
                "SELECT receipt FROM managed_current_requests WHERE id='fresh-context-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let authority = crate::managed_run::CurrentAuthority::fixture(
            fake_run_endpoint(&binding),
            decoded(&receipt_json).unwrap(),
            "inv-1",
            "fresh-context-1",
            serde_json::from_str(
                &db.query_row::<String, _, _>(
                    "SELECT request FROM managed_current_requests WHERE id='fresh-context-1'",
                    [],
                    |row| row.get(0),
                )
                .unwrap(),
            )
            .unwrap(),
        );
        let route = Route {
            component_store_id: binding.pool_store_id.clone(),
            route_id: "pool-route".into(),
            worker_uid: binding.run_route.worker_uid,
        };
        assert_eq!(
            reserve_intent(
                db,
                "context-1",
                "member",
                &command(1),
                &digest,
                authority,
                &consumed,
                &route
            )
            .err(),
            Some(Fault::Unauthorized)
        );
        let request_json: String = db
            .query_row(
                "SELECT request FROM managed_current_requests WHERE id='fresh-context-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let mut altered: serde_json::Value = serde_json::from_str(&request_json).unwrap();
        altered["observation_ref"] = serde_json::json!("different-ref");
        let authority = crate::managed_run::CurrentAuthority::fixture(
            fake_run_endpoint(&binding),
            decoded(&receipt_json).unwrap(),
            "inv-1",
            "fresh-context-1",
            altered,
        );
        consumed.validity = crate::managed_bridge::Validity::Current;
        assert_eq!(
            reserve_intent(
                db,
                "context-1",
                "member",
                &command(1),
                &digest,
                authority,
                &consumed,
                &route,
            )
            .err(),
            Some(Fault::Unauthorized)
        );
        let count: i64 = db
            .query_row("SELECT count(*) FROM managed_domain_keys", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0);
    }
    #[test]
    fn admitted_managed_mutation_runs_domain_cas_and_replays_once() {
        let (_dir, mut store, binding, incarnation, run) = fixture();
        let db = store.test_db();
        index_managed_member(db, &binding);
        let raw: String = db
            .query_row("SELECT data FROM members WHERE id='member'", [], |row| {
                row.get(0)
            })
            .unwrap();
        let mut member: crate::domain::Binding = decoded(&raw).unwrap();
        member.member.state = crate::domain::MemberState::Active;
        db.execute(
            "UPDATE members SET data=?1 WHERE id='member'",
            [encoded(&member).unwrap()],
        )
        .unwrap();
        let command = Command::Post(crate::domain::Message {
            change: Change {
                pool_id: "pool".into(),
                expected_revision: 1,
                request_key: "post-key".into(),
            },
            body: "verified post".into(),
        });
        let digest = prepare_command(
            db,
            &run,
            &binding,
            &incarnation,
            "post-context",
            "post-intent",
            "post-inv",
            &command,
        );
        assert_eq!(
            reserve(
                db,
                &run,
                &binding,
                &incarnation,
                "post-context",
                "post-inv",
                "post-intent",
                &command,
                &digest
            )
            .unwrap(),
            IntentReservation::Created
        );
        let admission = consumed_admission(
            db,
            &run,
            &binding,
            &incarnation,
            "post-intent",
            "post-inv",
            &digest,
            &command,
        );
        let mut bad_admission = admission.clone();
        bad_admission.successor_proof.chain.clear();
        assert_eq!(
            mark_admitted(db, "post-intent", &digest, &bad_admission).err(),
            Some(Fault::Conflict)
        );
        mark_admitted(db, "post-intent", &digest, &admission).unwrap();
        let receipt = commit_domain(db, "post-intent", &digest).unwrap();
        assert_eq!(commit_domain(db, "post-intent", &digest).unwrap(), receipt);
        let reply: crate::domain::Reply = decoded(&receipt).unwrap();
        let crate::domain::Reply::Receipt(reply) = reply else {
            panic!("expected a committed post receipt");
        };
        assert_eq!(reply.revision, 2);
        assert_eq!(reply.event.body, "verified post");
        assert_eq!(
            db.query_row("SELECT count(*) FROM events", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        let join = Command::Join(Change {
            pool_id: "pool".into(),
            expected_revision: 2,
            request_key: "join-key".into(),
        });
        assert_eq!(
            crate::store::apply_managed_mutation(
                db,
                &join,
                &context(&binding, "other", "other"),
                false
            )
            .err(),
            Some(Fault::Unavailable)
        );
        let actor = crate::domain::Actor::verified(
            binding.actor.address.clone(),
            &binding.actor.native_id,
            &binding.actor.role,
        )
        .unwrap();
        assert!(matches!(
            store.execute(&actor, &command),
            Err(Fault::Unavailable)
        ));

        let db = store.test_db();
        let remove = Command::Remove(crate::domain::Remove {
            change: Change {
                pool_id: "pool".into(),
                expected_revision: 2,
                request_key: "remove-key".into(),
            },
            member_id: "member".into(),
        });
        let digest = prepare_command(
            db,
            &run,
            &binding,
            &incarnation,
            "remove-context",
            "remove-intent",
            "remove-inv",
            &remove,
        );
        assert_eq!(
            reserve(
                db,
                &run,
                &binding,
                &incarnation,
                "remove-context",
                "remove-inv",
                "remove-intent",
                &remove,
                &digest
            )
            .unwrap(),
            IntentReservation::Created
        );
        let admission = consumed_admission(
            db,
            &run,
            &binding,
            &incarnation,
            "remove-intent",
            "remove-inv",
            &digest,
            &remove,
        );
        mark_admitted(db, "remove-intent", &digest, &admission).unwrap();
        let receipt = commit_domain(db, "remove-intent", &digest).unwrap();
        let reply: crate::domain::Reply = decoded(&receipt).unwrap();
        let crate::domain::Reply::Receipt(reply) = reply else {
            panic!("expected a committed removal receipt");
        };
        assert_eq!(reply.revision, 3);
        assert_eq!(reply.event.kind, "member_removed");
        let current: bool = db
            .query_row("SELECT current FROM members WHERE id='member'", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(!current);
        assert_eq!(
            outcome(db, "remove-intent", &digest).unwrap().state,
            "committed"
        );
    }
    pub(crate) fn index_managed_member(db: &Connection, binding: &ManagedBinding) {
        let raw: String = db
            .query_row("SELECT data FROM members WHERE id='member'", [], |row| {
                row.get(0)
            })
            .unwrap();
        let mut member: crate::domain::Binding = decoded(&raw).unwrap();
        member.run_store_id = Some(binding.attempt.run_store_id.clone());
        db.execute(
            "UPDATE members SET address=?1,data=?2 WHERE id='member'",
            params![binding.actor.address, encoded(&member).unwrap()],
        )
        .unwrap();
    }
    #[test]
    fn managed_reads_require_fresh_evidence_and_consume_it_atomically() {
        for name in ["pool_list", "pool_get"] {
            let (_dir, mut store, binding, incarnation, run) = fixture();
            let db = store.test_db();
            index_managed_member(db, &binding);
            let arguments = if name == "pool_get" {
                serde_json::json!({"pool_id":"pool"})
            } else {
                serde_json::json!({})
            };
            let command: Command =
                serde_json::from_value(serde_json::json!({"name":name,"arguments":arguments}))
                    .unwrap();
            let digest = prepare_command(
                db,
                &run,
                &binding,
                &incarnation,
                "read-context",
                "read-intent",
                "read-inv",
                &command,
            );
            let consumed = fake_consumed(
                &binding,
                &incarnation,
                "read-intent",
                "read-inv",
                &digest,
                &command,
            );
            assert_eq!(
                execute_read(db, "read-context", &command, &digest, &[], &consumed).err(),
                Some(Fault::Unauthorized)
            );
            let authority = || fresh_authority(db, &binding, "read-context", "read-inv").unwrap();
            let mut historical = consumed.clone();
            historical.validity = crate::managed_bridge::Validity::Historical;
            let auth = authority();
            assert_eq!(
                execute_read(db, "read-context", &command, &digest, &[auth], &historical).err(),
                Some(Fault::Unauthorized)
            );
            let auth = fresh_authority(db, &binding, "read-context", "read-inv").unwrap();
            let reply =
                execute_read(db, "read-context", &command, &digest, &[auth], &consumed).unwrap();
            match reply {
                crate::domain::Reply::View(view) => assert_eq!(view.pool.pool_id, "pool"),
                crate::domain::Reply::List { pools, .. } => {
                    assert_eq!(pools.len(), 1);
                    assert_eq!(pools[0].pool_id, "pool");
                }
                _ => panic!("unexpected managed read response"),
            }
            let auth = fresh_authority(db, &binding, "read-context", "read-inv").unwrap();
            assert_eq!(
                execute_read(db, "read-context", &command, &digest, &[auth], &consumed).err(),
                Some(Fault::Stale)
            );
            let state: (String, String) = db.query_row(
                "SELECT c.state,r.state FROM managed_contexts c JOIN managed_current_requests r ON r.id='fresh-read-context' WHERE c.id='read-context'",
                [], |row| Ok((row.get(0)?, row.get(1)?)),
            ).unwrap();
            assert_eq!(state, ("invalidated".into(), "used".into()));
            let bootstrap: String = db
                .query_row(
                    "SELECT state FROM managed_bootstrap WHERE id='read-context'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(bootstrap, "submitted");
            let draining = seal_namespace(
                db,
                &binding.bridge_route,
                "pool",
                "epoch",
                "read-seal",
                "read-retire",
            )
            .unwrap();
            assert!(!draining.sealed);
            let BootstrapRecoveryAction::BridgeAbort {
                context_id,
                pin,
                key,
            } = stage_bootstrap_recovery(db, "read-context").unwrap()
            else {
                panic!("consumed read must retain its exact Bridge abort");
            };
            assert_eq!(key.consume_request_id, "read-intent");
            assert_eq!(key.security_digest, digest);
            let abort = crate::managed_bridge::Abort {
                store_id: binding.bridge_route.component_store_id.clone(),
                aborted: true,
                receipt: Some(consumed.receipt.clone()),
            };
            record_bootstrap_abort(db, &context_id, &key.borrowed(), &abort, &pin).unwrap();
            let sealed = seal_namespace(
                db,
                &binding.bridge_route,
                "pool",
                "epoch",
                "read-seal",
                "read-retire",
            )
            .unwrap();
            assert!(sealed.sealed);
            assert_eq!(sealed.seal_id, draining.seal_id);
        }
    }

    #[test]
    fn managed_read_rejects_stale_binding_foreign_store_and_owner_view() {
        for case in ["stale", "foreign-store", "owner-view"] {
            let (_dir, mut store, binding, incarnation, mut run) = fixture();
            let db = store.test_db();
            index_managed_member(db, &binding);
            if case == "foreign-store" {
                let raw: String = db
                    .query_row("SELECT data FROM members WHERE id='member'", [], |row| {
                        row.get(0)
                    })
                    .unwrap();
                let mut member: crate::domain::Binding = decoded(&raw).unwrap();
                member.run_store_id = Some("store_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into());
                db.execute(
                    "UPDATE members SET data=?1 WHERE id='member'",
                    [encoded(&member).unwrap()],
                )
                .unwrap();
            }
            let owner_view = case == "owner-view";
            let arguments = if owner_view {
                serde_json::json!({"pool_id":"pool","section":"binding","member_id":"member"})
            } else {
                serde_json::json!({"pool_id":"pool"})
            };
            let command: Command = serde_json::from_value(
                serde_json::json!({"name":"pool_get","arguments":arguments}),
            )
            .unwrap();
            let digest = prepare_command(
                db,
                &run,
                &binding,
                &incarnation,
                "read-context",
                "read-intent",
                "read-inv",
                &command,
            );
            let consumed = fake_consumed(
                &binding,
                &incarnation,
                "read-intent",
                "read-inv",
                &digest,
                &command,
            );
            let authority = fresh_authority(db, &binding, "read-context", "read-inv").unwrap();
            if case == "stale" {
                let mut successor = binding.clone();
                successor.attempt.attempt_id = "attempt-2".into();
                successor.attempt.launch_id = "00000000-0000-4000-8000-000000000004".into();
                let mut next = incarnation.clone();
                next.pid += 1;
                next.start_ticks += 1;
                run.receipt.receipt_id = "receipt-2".into();
                run.receipt.attempt = successor.attempt.clone();
                run.receipt.incarnation = next.clone();
                rebind(
                    db,
                    &run,
                    &binding,
                    &successor,
                    &next,
                    "receipt-2",
                    "ingress",
                )
                .unwrap();
            }
            assert_eq!(
                execute_read(
                    db,
                    "read-context",
                    &command,
                    &digest,
                    &[authority],
                    &consumed
                )
                .err(),
                Some(if owner_view {
                    Fault::Forbidden
                } else {
                    Fault::Stale
                })
            );
            if owner_view {
                let state: (String, String) = db
                    .query_row(
                        "SELECT c.state,r.state FROM managed_contexts c JOIN managed_current_requests r ON r.id='fresh-read-context' WHERE c.id='read-context'",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .unwrap();
                assert_eq!(state, ("prepared".into(), "received".into()));
            }
        }
    }
    #[test]
    fn concurrent_same_request_key() {
        let (dir, mut store, binding, incarnation, run) = fixture();
        let db = store.test_db();
        let a = prepare(
            db,
            &run,
            &binding,
            &incarnation,
            "context-1",
            "intent-1",
            "inv-1",
            1,
        );
        let b = prepare(
            db,
            &run,
            &binding,
            &incarnation,
            "context-2",
            "intent-2",
            "inv-2",
            1,
        );
        let path = dir.path().join("pool.db");
        let results = std::thread::scope(|scope| {
            let first = scope.spawn(|| {
                let mut db = Connection::open(&path).unwrap();
                db.busy_timeout(std::time::Duration::from_secs(2)).unwrap();
                reserve(
                    &mut db,
                    &run,
                    &binding,
                    &incarnation,
                    "context-1",
                    "inv-1",
                    "intent-1",
                    &command(1),
                    &a,
                )
                .unwrap()
            });
            let second = scope.spawn(|| {
                let mut db = Connection::open(&path).unwrap();
                db.busy_timeout(std::time::Duration::from_secs(2)).unwrap();
                reserve(
                    &mut db,
                    &run,
                    &binding,
                    &incarnation,
                    "context-2",
                    "inv-2",
                    "intent-2",
                    &command(1),
                    &b,
                )
                .unwrap()
            });
            [first.join().unwrap(), second.join().unwrap()]
        });
        assert!(results.contains(&IntentReservation::Created));
        assert!(results.contains(&IntentReservation::Pending));
        let count: i64 = db
            .query_row("SELECT count(*) FROM managed_domain_keys", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);
    }
    #[test]
    fn unresolved_managed_recovery_rotates_past_blocked_head() {
        let (_dir, mut store, binding, incarnation, run) = fixture();
        {
            let db = store.test_db();
            let digest = prepare(
                db,
                &run,
                &binding,
                &incarnation,
                "context-1",
                "intent-1",
                "inv-1",
                1,
            );
            reserve(
                db,
                &run,
                &binding,
                &incarnation,
                "context-1",
                "inv-1",
                "intent-1",
                &command(1),
                &digest,
            )
            .unwrap();
            for index in 0..34 {
                let id = format!("extra-{index}");
                db.execute("INSERT INTO managed_contexts(id,namespace_id,intent_id,invocation_key,command,context,digest,snapshot,state) SELECT ?1,namespace_id,?1,?2,command,context,digest,snapshot,state FROM managed_contexts WHERE id='context-1'",params![id,format!("extra-inv-{index}")]).unwrap();
                db.execute("INSERT INTO managed_intents(id,context_id,scope,request_key,domain_digest,security_digest,command,pool_route,run_route,run_pin,state,consumed_ref,consumed_receipt) SELECT ?1,?1,scope,request_key,domain_digest,security_digest,command,pool_route,run_route,run_pin,state,consumed_ref,consumed_receipt FROM managed_intents WHERE id='intent-1'",[id]).unwrap();
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..35 {
            let batch = store.managed_pending().unwrap();
            assert_eq!(batch.len(), 1);
            assert!(seen.insert(batch[0].0.clone()));
        }
        assert!(store.managed_pending().unwrap().is_empty());
        assert_eq!(store.managed_pending().unwrap().len(), 1);
    }
    #[test]
    fn historical_migrations_restart_preserves_unresolved_fences() {
        let (dir, mut store, binding, incarnation, run) = fixture();
        let path = dir.path().join("pool.db");
        let db = store.test_db();
        let digest = prepare(
            db,
            &run,
            &binding,
            &incarnation,
            "context-1",
            "intent-1",
            "inv-1",
            1,
        );
        assert_eq!(
            reserve(
                db,
                &run,
                &binding,
                &incarnation,
                "context-1",
                "inv-1",
                "intent-1",
                &command(1),
                &digest,
            )
            .unwrap(),
            IntentReservation::Created
        );
        let admission = consumed_admission(
            db,
            &run,
            &binding,
            &incarnation,
            "intent-1",
            "inv-1",
            &digest,
            &command(1),
        );
        assert!(matches!(
            stage_recovery(db, "intent-1", &digest).unwrap(),
            RecoveryAction::LocallyFenced
        ));
        let RecoveryAction::BridgeAbort { pin, key, .. } =
            stage_recovery(db, "intent-1", &digest).unwrap()
        else {
            panic!("expected a staged Bridge abort");
        };
        let original_key = key.abort_request_id.clone();
        let original_pin = encoded(&pin).unwrap();
        drop(store);

        let mut store = Store::open(&path).unwrap();
        let db = store.test_db();
        let RecoveryAction::BridgeAbort { pin, key, .. } =
            stage_recovery(db, "intent-1", &digest).unwrap()
        else {
            panic!("expected the same Bridge abort after restart");
        };
        assert_eq!(key.abort_request_id, original_key);
        assert_eq!(encoded(&pin).unwrap(), original_pin);
        assert_eq!(key.consume_request_id, "intent-1");
        assert_eq!(key.invocation_key, "inv-1");
        assert_eq!(key.security_digest, digest);
        assert_eq!(
            mark_admitted(db, "intent-1", &digest, &admission).err(),
            Some(Fault::Stale)
        );
        assert_eq!(
            commit(db, "intent-1", &digest, |_, _| panic!(
                "aborted CAS executed"
            ))
            .err(),
            Some(Fault::Stale)
        );
        let bridge_abort = crate::managed_bridge::Abort {
            store_id: binding.bridge_route.component_store_id.clone(),
            aborted: true,
            receipt: Some(
                fake_consumed(
                    &binding,
                    &incarnation,
                    "intent-1",
                    "inv-1",
                    &digest,
                    &command(1),
                )
                .receipt,
            ),
        };
        assert!(
            !record_bridge_abort(
                db,
                "intent-1",
                &digest,
                &key.borrowed(),
                &bridge_abort,
                &pin
            )
            .unwrap()
        );
        let RecoveryAction::RunAbort {
            intent,
            outcome_digest,
        } = stage_recovery(db, "intent-1", &digest).unwrap()
        else {
            panic!("expected a staged Run abort");
        };
        let original_run_pin = encoded(&intent.run_pin).unwrap();
        let original_reference = encoded(&intent.consumed_ref).unwrap();
        drop(store);

        let mut store = Store::open(&path).unwrap();
        let db = store.test_db();
        let RecoveryAction::RunAbort {
            intent,
            outcome_digest: replayed,
        } = stage_recovery(db, "intent-1", &digest).unwrap()
        else {
            panic!("expected the same Run abort after restart");
        };
        assert_eq!(replayed, outcome_digest);
        assert_eq!(encoded(&intent.run_pin).unwrap(), original_run_pin);
        assert_eq!(encoded(&intent.consumed_ref).unwrap(), original_reference);
        assert_eq!(intent.intent_id, "intent-1");
        assert_eq!(intent.security_digest, digest);
        let tombstone = crate::managed_run::Lookup {
            state: "aborted_before_admit".into(),
            admission: None,
            outcome_digest: None,
        };
        assert!(record_run_abort(db, "intent-1", &digest, &tombstone).unwrap());
        drop(store);

        let mut store = Store::open(&path).unwrap();
        let db = store.test_db();
        assert!(matches!(
            stage_recovery(db, "intent-1", &digest).unwrap(),
            RecoveryAction::Done
        ));
        assert_eq!(outcome(db, "intent-1", &digest).unwrap().state, "aborted");
        let keys: i64 = db
            .query_row("SELECT count(*) FROM managed_domain_keys", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(keys, 0);
    }

    #[test]
    fn outcome_pins_settlement_reference_vector() {
        let (_directory, mut store, binding, incarnation, run) = fixture();
        let db = store.test_db();
        let original = prepare(
            db,
            &run,
            &binding,
            &incarnation,
            "context-1",
            "intent-1",
            "inv-1",
            1,
        );
        assert_eq!(
            reserve(
                db,
                &run,
                &binding,
                &incarnation,
                "context-1",
                "inv-1",
                "intent-1",
                &command(1),
                &original
            )
            .unwrap(),
            IntentReservation::Created
        );
        let digest = "a".repeat(64);
        db.execute("UPDATE inventory_source SET store_id='pool-store-uuid'", [])
            .unwrap();
        db.execute("UPDATE managed_intents SET state='committed',security_digest=?1,terminal_receipt='receipt' WHERE id='intent-1'", [&digest]).unwrap();
        let value = serde_json::json!({"version":1,"pool_store_id":"pool-store-uuid","intent_id":"intent-1","security_digest":digest,"state":"committed"});
        let (length, hash) =
            crate::managed_codec::digest(b"agent-mcp/attempt-binding/settlement/v1\0", &value)
                .unwrap();
        assert_eq!(length, 223);
        assert_eq!(
            hash,
            "10a5159c5c085fd018534a640862ed8600fdf334cbfac41be9964659d72de8eb"
        );
        assert_eq!(
            outcome(db, "intent-1", &digest)
                .unwrap()
                .outcome_digest
                .as_deref(),
            Some(hash.as_str())
        );
    }
    #[test]
    fn consensus_voter_finished_after_vote() {
        let (_dir, _store, binding, incarnation, mut run) = fixture();
        run.observation.state = VoterState::TerminalNoSuccessor;
        assert!(voter_valid(&run, &binding, &binding.attempt, &incarnation).unwrap());
        run.observation.state = VoterState::Superseded;
        let mut next = binding.attempt.clone();
        next.attempt_id = "attempt-2".into();
        next.launch_id = "00000000-0000-4000-8000-000000000004".into();
        run.observation.last_attempt = Some(next);
        let mut next_incarnation = incarnation.clone();
        next_incarnation.pid += 1;
        run.observation.last_incarnation = Some(next_incarnation);
        assert!(!voter_valid(&run, &binding, &binding.attempt, &incarnation).unwrap());
        run.observation.state = VoterState::Unavailable;
        assert_eq!(
            voter_valid(&run, &binding, &binding.attempt, &incarnation).err(),
            Some(Fault::Unavailable)
        );
        run.observation.state = VoterState::Live;
        run.observation.last_incarnation = None;
        assert_eq!(
            voter_valid(&run, &binding, &binding.attempt, &incarnation).err(),
            Some(Fault::Unavailable)
        );
    }
    #[test]
    fn consensus_every_voter_current() {
        struct CountingRun<'a> {
            run: &'a FakeRun,
            calls: std::cell::Cell<usize>,
        }
        impl RunAuthority for CountingRun<'_> {
            fn current_receipt(&self, route: &Route, id: &str) -> Result<CurrentReceipt, Fault> {
                self.run.current_receipt(route, id)
            }
            fn consensus(
                &self,
                route: &Route,
                attempt: &AttemptRef,
                incarnation: &Incarnation,
            ) -> Result<VoterObservation, Fault> {
                self.calls.set(self.calls.get() + 1);
                self.run.consensus(route, attempt, incarnation)
            }
        }
        let (_dir, _store, binding, incarnation, mut fake) = fixture();
        let voters = vec![
            VerifiedBallot {
                binding: binding.clone(),
                generation: 1,
                attempt: binding.attempt.clone(),
                incarnation: incarnation.clone(),
            },
            VerifiedBallot {
                binding: ManagedBinding {
                    member_id: "other".into(),
                    ..binding.clone()
                },
                generation: 1,
                attempt: binding.attempt.clone(),
                incarnation: incarnation.clone(),
            },
        ];
        fake.observation.state = VoterState::Unavailable;
        let run = CountingRun {
            run: &fake,
            calls: std::cell::Cell::new(0),
        };
        assert_eq!(
            check_all_voters(&run, &voters).err(),
            Some(Fault::Unavailable)
        );
        assert_eq!(run.calls.get(), 2);
    }

    /// A resumed voter invalidates only its prior open ballot, not another member's context.
    #[test]
    fn consensus_every_voter_current_rebind_fences_old_ballot_but_records_other_vote() {
        use crate::domain::{Ballot, Choice, MemberState, Pool, Proposal, ProposalState, Vote};
        struct Live;
        impl RunAuthority for Live {
            fn current_receipt(&self, _: &Route, _: &str) -> Result<CurrentReceipt, Fault> {
                Err(Fault::Unavailable)
            }
            fn consensus(
                &self,
                _: &Route,
                attempt: &AttemptRef,
                incarnation: &Incarnation,
            ) -> Result<VoterObservation, Fault> {
                Ok(VoterObservation {
                    state: VoterState::Live,
                    last_attempt: Some(attempt.clone()),
                    last_incarnation: Some(incarnation.clone()),
                    successor_proof: Some(SuccessorProof {
                        lineage_root_id: attempt.lineage_root_id.clone(),
                        bound_execution_id: attempt.execution_id.clone(),
                        current_execution_id: attempt.execution_id.clone(),
                        chain: vec![SuccessorLink {
                            execution_id: attempt.execution_id.clone(),
                            parent_execution_id: (attempt.sequence > 1)
                                .then(|| attempt.lineage_root_id.clone()),
                            sequence: attempt.sequence,
                        }],
                    }),
                })
            }
        }
        let (_dir, mut store, binding, incarnation, run) = fixture();
        let db = store.test_db();
        index_managed_member(db, &binding);
        let raw: String = db
            .query_row("SELECT data FROM members WHERE id='member'", [], |row| {
                row.get(0)
            })
            .unwrap();
        let mut author: crate::domain::Binding = decoded(&raw).unwrap();
        author.member.state = MemberState::Active;
        db.execute(
            "UPDATE members SET data=?1 WHERE id='member'",
            [encoded(&author).unwrap()],
        )
        .unwrap();
        let mut other = author.clone();
        other.member.member_id = "other".into();
        other.member.name = "other".into();
        other.address = Some("host/codex/store/other".into());
        other.run_id = Some("root-other".into());
        other.run_sequence = Some(1);
        db.execute(
            "INSERT INTO members(id,pool,address,current,data) VALUES('other','pool',?1,1,?2)",
            params![other.address, encoded(&other).unwrap()],
        )
        .unwrap();
        let mut other_binding = binding.clone();
        other_binding.member_id = "other".into();
        other_binding.actor.address = "host/codex/store/other".into();
        other_binding.actor.native_id = "other".into();
        other_binding.attempt.lineage_root_id = "root-other".into();
        other_binding.attempt.execution_id = "root-other".into();
        db.execute("INSERT INTO managed_bindings(member,pool,generation,binding) VALUES('other','pool',?1,?2)",params![sqlite_generation(1),encoded(&other_binding).unwrap()]).unwrap();
        let event = serde_json::json!({"event_id":1,"revision":1,"kind":"vote_recorded","author":{"kind":"member","member_id":"other"},"body":"Proposal proposal: Ready.\nevidence","recipient":null});
        db.execute(
            "INSERT INTO events(pool,data) VALUES('pool',?1)",
            [event.to_string()],
        )
        .unwrap();
        let event_id = db.last_insert_rowid();
        let mut pool: Pool = decoded(
            &db.query_row::<String, _, _>("SELECT data FROM pools WHERE id='pool'", [], |row| {
                row.get(0)
            })
            .unwrap(),
        )
        .unwrap();
        let ballot = Ballot {
            choice: Choice::Ready,
            evidence: "evidence".into(),
            checks_met: None,
            vote_event_id: Some(event_id.to_string()),
            checks_count: None,
            validity: None,
        };
        pool.proposal = Some(Proposal {
            proposal_id: "proposal".into(),
            roster_key: "roster".into(),
            voters: vec!["member".into(), "other".into()],
            result: "result".into(),
            criteria: "criteria".into(),
            snapshot: None,
            snapshot_bytes: None,
            state: ProposalState::Open,
            votes: std::collections::BTreeMap::from([("other".into(), ballot)]),
        });
        db.execute(
            "INSERT INTO proposals(id,pool,state,data) VALUES('proposal','pool','open',?1)",
            [encoded(pool.proposal.as_ref().unwrap()).unwrap()],
        )
        .unwrap();
        db.execute(
            "UPDATE pools SET data=?1 WHERE id='pool'",
            [encoded(&pool).unwrap()],
        )
        .unwrap();
        db.execute("INSERT INTO managed_ballot_provenance(pool,proposal,member,event_id,generation,attempt,incarnation,admission_id,security_digest) VALUES('pool','proposal','other',?1,?2,?3,?4,'old-admission',?5)",params![event_id,sqlite_generation(1),encoded(&other_binding.attempt).unwrap(),encoded(&incarnation).unwrap(),"a".repeat(64)]).unwrap();
        let vote = Command::Vote(Vote {
            change: Change {
                pool_id: "pool".into(),
                expected_revision: 1,
                request_key: "vote-key".into(),
            },
            proposal_id: "proposal".into(),
            roster_key: "roster".into(),
            choice: Choice::Ready,
            evidence: "evidence".into(),
            checks: vec![],
        });
        let independent_digest = prepare_command(
            db,
            &run,
            &binding,
            &incarnation,
            "independent-context",
            "independent-intent",
            "independent-inv",
            &vote,
        );
        let digest = prepare_command(
            db,
            &run,
            &binding,
            &incarnation,
            "vote-context",
            "vote-intent",
            "vote-inv",
            &vote,
        );
        assert_eq!(
            reserve(
                db,
                &run,
                &binding,
                &incarnation,
                "vote-context",
                "vote-inv",
                "vote-intent",
                &vote,
                &digest
            )
            .unwrap(),
            IntentReservation::Created
        );
        let admission = consumed_admission(
            db,
            &run,
            &binding,
            &incarnation,
            "vote-intent",
            "vote-inv",
            &digest,
            &vote,
        );
        mark_admitted(db, "vote-intent", &digest, &admission).unwrap();
        let pending = snapshot_consensus(db, "vote-intent", &digest).unwrap();
        assert_eq!(pending.voters().len(), 2);
        let old_fence = pending.verify(&Live).unwrap();
        let pending_before_rebind = snapshot_consensus(db, "vote-intent", &digest).unwrap();
        let mut next = other_binding.clone();
        next.attempt.execution_id = "next-other".into();
        next.attempt.sequence = 2;
        next.attempt.attempt_id = "next-attempt".into();
        next.attempt.launch_id = "00000000-0000-4000-8000-000000000004".into();
        let mut other_receipt = run.receipt.clone();
        other_receipt.receipt_id = "other-rebind".into();
        other_receipt.lineage_root_id = "root-other".into();
        other_receipt.bound_execution_id = "root-other".into();
        other_receipt.attempt = next.attempt.clone();
        other_receipt.actor = next.actor.clone();
        other_receipt.successor_proof = SuccessorProof {
            lineage_root_id: "root-other".into(),
            bound_execution_id: "root-other".into(),
            current_execution_id: "next-other".into(),
            chain: vec![
                SuccessorLink {
                    execution_id: "root-other".into(),
                    parent_execution_id: None,
                    sequence: 1,
                },
                SuccessorLink {
                    execution_id: "next-other".into(),
                    parent_execution_id: Some("root-other".into()),
                    sequence: 2,
                },
            ],
        };
        let other_run = FakeRun {
            receipt: other_receipt,
            observation: run.observation.clone(),
        };
        assert_eq!(
            rebind(
                db,
                &other_run,
                &other_binding,
                &next,
                &incarnation,
                "other-rebind",
                "ingress"
            )
            .unwrap(),
            2
        );
        assert_eq!(
            db.query_row::<i64, _, _>(
                "SELECT json_extract(data,'$.revision') FROM pools WHERE id='pool'",
                [],
                |row| row.get(0)
            )
            .unwrap(),
            1
        );
        assert!(context_current(db, "vote-context", &vote, &digest, true).is_ok());
        assert_eq!(
            prepare_context(
                db,
                &run,
                "independent-context",
                "namespace",
                &vote,
                &context(&binding, "independent-intent", "independent-inv"),
                &[("fixture-initial-independent-context", incarnation.clone())]
            )
            .unwrap(),
            independent_digest
        );
        assert_eq!(
            commit_vote(db, "vote-intent", &digest, old_fence, |_, _| panic!(
                "stale voter CAS executed"
            ))
            .err(),
            Some(Fault::Stale)
        );
        assert_eq!(
            db.query_row::<i64, _, _>(
                "SELECT count(*) FROM managed_invalidated_ballots WHERE member='other'",
                [],
                |row| row.get(0)
            )
            .unwrap(),
            1
        );
        let pending = pending_before_rebind.refresh_after_rebind(db).unwrap();
        assert!(pending.voters().is_empty());
        let fence = pending.verify(&Live).unwrap();
        let receipt = commit_domain_vote(db, "vote-intent", &digest, fence).unwrap();
        let reply: crate::domain::Reply = decoded(&receipt).unwrap();
        let crate::domain::Reply::Receipt(receipt) = reply else {
            panic!("vote receipt")
        };
        assert_eq!(receipt.event.kind, "vote_recorded");
        let final_pool: Pool = decoded(
            &db.query_row::<String, _, _>("SELECT data FROM pools WHERE id='pool'", [], |row| {
                row.get(0)
            })
            .unwrap(),
        )
        .unwrap();
        let proposal = final_pool.proposal.unwrap();
        assert_eq!(proposal.state, ProposalState::Open);
        assert!(proposal.votes.contains_key("member"));
        assert!(proposal.votes.contains_key("other"));
        next.binding_generation = 2;
        let other_vote = Command::Vote(Vote {
            change: Change {
                pool_id: "pool".into(),
                expected_revision: 2,
                request_key: "other-key".into(),
            },
            proposal_id: "proposal".into(),
            roster_key: "roster".into(),
            choice: Choice::Ready,
            evidence: "fresh evidence".into(),
            checks: vec![],
        });
        let other_digest = prepare_command(
            db,
            &other_run,
            &next,
            &incarnation,
            "other-context",
            "other-intent",
            "other-inv",
            &other_vote,
        );
        let authority = fresh_authority(db, &next, "other-context", "other-inv").unwrap();
        let consumed = fake_consumed(
            &next,
            &incarnation,
            "other-intent",
            "other-inv",
            &other_digest,
            &other_vote,
        );
        let pool_route = Route {
            component_store_id: next.pool_store_id.clone(),
            route_id: "pool-route".into(),
            worker_uid: next.run_route.worker_uid,
        };
        assert_eq!(
            reserve_intent(
                db,
                "other-context",
                "other",
                &other_vote,
                &other_digest,
                authority,
                &consumed,
                &pool_route
            )
            .unwrap(),
            IntentReservation::Created
        );
        let mut admission = consumed_admission(
            db,
            &other_run,
            &next,
            &incarnation,
            "other-intent",
            "other-inv",
            &other_digest,
            &other_vote,
        );
        admission.admission_id = "other-admission".into();
        admission.successor_proof.bound_execution_id = next.attempt.execution_id.clone();
        admission.successor_proof.chain =
            vec![admission.successor_proof.chain.last().unwrap().clone()];
        mark_admitted(db, "other-intent", &other_digest, &admission).unwrap();
        let pending = snapshot_consensus(db, "other-intent", &other_digest).unwrap();
        assert_eq!(pending.voters().len(), 2);
        commit_domain_vote(
            db,
            "other-intent",
            &other_digest,
            pending.verify(&Live).unwrap(),
        )
        .unwrap();
        assert_eq!(
            db.query_row::<i64, _, _>(
                "SELECT count(*) FROM managed_invalidated_ballots WHERE member='other'",
                [],
                |row| row.get(0)
            )
            .unwrap(),
            0
        );
        let accepted: Pool = decoded(
            &db.query_row::<String, _, _>("SELECT data FROM pools WHERE id='pool'", [], |row| {
                row.get(0)
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(accepted.proposal.unwrap().state, ProposalState::Accepted);
    }

    #[test]
    fn same_attempt_actor_epoch_rebind_fences_old_context_and_admits_new() {
        use crate::domain::{MemberState, Message};
        let (_dir, mut store, binding, incarnation, mut run) = fixture();
        let db = store.test_db();
        index_managed_member(db, &binding);
        let raw: String = db
            .query_row("SELECT data FROM members WHERE id='member'", [], |row| {
                row.get(0)
            })
            .unwrap();
        let mut member: crate::domain::Binding = decoded(&raw).unwrap();
        member.member.state = MemberState::Active;
        member.run_id = Some(binding.attempt.execution_id.clone());
        member.run_sequence = Some(u64::from(binding.attempt.sequence));
        db.execute(
            "UPDATE members SET data=?1 WHERE id='member'",
            [encoded(&member).unwrap()],
        )
        .unwrap();
        let post = Command::Post(Message {
            change: Change {
                pool_id: "pool".into(),
                expected_revision: 1,
                request_key: "new-key".into(),
            },
            body: "epoch-bound".into(),
        });
        let old_digest = prepare_command(
            db,
            &run,
            &binding,
            &incarnation,
            "old-context",
            "old-intent",
            "old-inv",
            &post,
        );
        let mut next = binding.clone();
        next.actor.epoch += 1;
        run.receipt.receipt_id = "epoch-rebind".into();
        run.receipt.actor = next.actor.clone();
        let pin = fake_bridge_pin(&binding);
        let proof = native_proof();
        reserve_bootstrap(
            db,
            &BootstrapRequest {
                namespace_id: "namespace-2",
                bootstrap_id: "stage-context",
                route: &binding.bridge_route,
                bridge_pin: &pin,
                producer: "pool",
                issuer_epoch: "epoch-2",
                invocation_key: "stage-inv",
                command: &post,
                native_proof: &proof,
            },
        )
        .unwrap();
        let dispatch = mark_bootstrap_submitted(db, "stage-context").unwrap();
        record_bootstrap_ref(
            db,
            dispatch,
            &crate::managed_bridge::Prepared {
                store_id: binding.bridge_route.component_store_id.clone(),
                bridge_context_ref: bridge_sdk::bridge_protocol::Secret::new(
                    "bridge-stage-context",
                ),
                invocation_key: "stage-inv".into(),
                expires_at_ms: 100,
            },
            &pin,
        )
        .unwrap();
        record_fake_current(
            db,
            &run,
            &binding,
            &incarnation,
            "stage-context",
            "stage-inv",
            "initial",
        );
        let (request,pin_json,receipt):(String,String,String)=db.query_row("SELECT request,run_pin,receipt FROM managed_current_requests WHERE id='initial-stage-context'",[],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap();
        let staged_pin: RunPin = decoded(&pin_json).unwrap();
        let authority = crate::managed_run::CurrentAuthority::fixture(
            staged_pin.endpoint(),
            decoded(&receipt).unwrap(),
            "stage-inv",
            "initial-stage-context",
            decoded(&request).unwrap(),
        );
        let selected =
            select_ingress_binding(db, &authority, &binding.bridge_route, "pool", &post).unwrap();
        next.binding_generation = 2;
        assert_eq!(selected, next);
        abandon_unregistered_bootstrap(db, "stage-context").unwrap();
        assert_eq!(
            context_current(db, "old-context", &post, &old_digest, false).err(),
            Some(Fault::Stale)
        );
        let digest = prepare_command_in_namespace(
            db,
            &run,
            &next,
            &incarnation,
            "new-context",
            "new-intent",
            "new-inv",
            &post,
            "namespace-2",
            "epoch-2",
        );
        let authority = fresh_authority(db, &next, "new-context", "new-inv").unwrap();
        let mut consumed =
            fake_consumed(&next, &incarnation, "new-intent", "new-inv", &digest, &post);
        consumed.receipt.issuer_epoch = "epoch-2".into();
        let pool_route = Route {
            component_store_id: next.pool_store_id.clone(),
            route_id: "pool-route".into(),
            worker_uid: next.run_route.worker_uid,
        };
        assert_eq!(
            reserve_intent(
                db,
                "new-context",
                "member",
                &post,
                &digest,
                authority,
                &consumed,
                &pool_route
            )
            .unwrap(),
            IntentReservation::Created
        );
        let mut admission = consumed_admission(
            db,
            &run,
            &next,
            &incarnation,
            "new-intent",
            "new-inv",
            &digest,
            &post,
        );
        admission.consumed_ref.issuer_epoch = "epoch-2".into();
        mark_admitted(db, "new-intent", &digest, &admission).unwrap();
        let result = commit_domain(db, "new-intent", &digest).unwrap();
        let crate::domain::Reply::Receipt(receipt) = decoded(&result).unwrap() else {
            panic!("post receipt")
        };
        assert_eq!(receipt.event.body, "epoch-bound");
        assert_eq!(receipt.revision, 2);
    }

    #[test]
    fn same_binding_requires_same_recorded_incarnation_for_noop() {
        let (_dir, mut store, binding, incarnation, mut run) = fixture();
        let db = store.test_db();
        assert_eq!(
            rebind(
                db,
                &run,
                &binding,
                &binding,
                &incarnation,
                "receipt-1",
                "ingress"
            )
            .unwrap(),
            1
        );
        let digest = prepare(
            db,
            &run,
            &binding,
            &incarnation,
            "old-context",
            "old-intent",
            "old-inv",
            1,
        );
        let mut changed = incarnation.clone();
        changed.pid += 1;
        changed.start_ticks += 1;
        run.receipt.receipt_id = "incarnation-rebind".into();
        run.receipt.incarnation = changed.clone();
        assert_eq!(
            rebind(
                db,
                &run,
                &binding,
                &binding,
                &changed,
                "incarnation-rebind",
                "ingress"
            )
            .unwrap(),
            2
        );
        assert_eq!(
            context_current(db, "old-context", &command(1), &digest, false).err(),
            Some(Fault::Stale)
        );
        let stored: String = db
            .query_row(
                "SELECT incarnation FROM managed_bindings WHERE member='member'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, encoded(&changed).unwrap());
    }

    #[test]
    fn unknown_migrated_incarnation_requires_a_generation_fence() {
        let (_dir, mut store, binding, incarnation, run) = fixture();
        let db = store.test_db();
        db.execute(
            "UPDATE managed_bindings SET incarnation=NULL WHERE member='member'",
            [],
        )
        .unwrap();
        assert_eq!(
            rebind(
                db,
                &run,
                &binding,
                &binding,
                &incarnation,
                "receipt-1",
                "ingress"
            )
            .unwrap(),
            2
        );
        let stored: String = db
            .query_row(
                "SELECT incarnation FROM managed_bindings WHERE member='member'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, encoded(&incarnation).unwrap());
    }
    #[test]
    fn ballot_provenance_is_atomic_and_legacy_is_unverified() {
        use crate::domain::{Choice, MemberState, Pool, Proposal, ProposalState, Vote};
        let (_dir, mut store, binding, incarnation, mut run) = fixture();
        let db = store.test_db();
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM managed_ballot_provenance",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        index_managed_member(db, &binding);
        let member_json: String = db
            .query_row("SELECT data FROM members WHERE id='member'", [], |row| {
                row.get(0)
            })
            .unwrap();
        let mut member: crate::domain::Binding = decoded(&member_json).unwrap();
        member.member.state = MemberState::Active;
        db.execute(
            "UPDATE members SET data=?1 WHERE id='member'",
            [encoded(&member).unwrap()],
        )
        .unwrap();
        let pool_json: String = db
            .query_row("SELECT data FROM pools WHERE id='pool'", [], |row| {
                row.get(0)
            })
            .unwrap();
        let mut pool: Pool = decoded(&pool_json).unwrap();
        pool.proposal = Some(Proposal {
            proposal_id: "proposal".into(),
            roster_key: "roster".into(),
            voters: vec!["member".into()],
            result: "result".into(),
            criteria: "criteria".into(),
            snapshot: None,
            snapshot_bytes: None,
            state: ProposalState::Open,
            votes: std::collections::BTreeMap::new(),
        });
        db.execute(
            "INSERT INTO proposals(id,pool,state,data) VALUES('proposal','pool','open',?1)",
            [encoded(pool.proposal.as_ref().unwrap()).unwrap()],
        )
        .unwrap();
        db.execute(
            "UPDATE pools SET data=?1 WHERE id='pool'",
            [encoded(&pool).unwrap()],
        )
        .unwrap();
        let vote = Command::Vote(Vote {
            change: Change {
                pool_id: "pool".into(),
                expected_revision: 1,
                request_key: "vote-key".into(),
            },
            proposal_id: "proposal".into(),
            roster_key: "roster".into(),
            choice: Choice::Ready,
            evidence: "evidence".into(),
            checks: vec![],
        });
        let proof = native_proof();
        reserve_bootstrap(
            db,
            &BootstrapRequest {
                namespace_id: "namespace",
                bootstrap_id: "vote-context",
                route: &binding.bridge_route,
                bridge_pin: &fake_bridge_pin(&binding),
                producer: "pool",
                issuer_epoch: "epoch",
                invocation_key: "vote-inv",
                command: &vote,
                native_proof: &proof,
            },
        )
        .unwrap();
        let dispatch = mark_bootstrap_submitted(db, "vote-context").unwrap();
        record_bootstrap_ref(
            db,
            dispatch,
            &crate::managed_bridge::Prepared {
                store_id: binding.bridge_route.component_store_id.clone(),
                bridge_context_ref: bridge_sdk::bridge_protocol::Secret::new("bridge-vote-context"),
                invocation_key: "vote-inv".into(),
                expires_at_ms: 100,
            },
            &fake_bridge_pin(&binding),
        )
        .unwrap();
        record_fake_current(
            db,
            &run,
            &binding,
            &incarnation,
            "vote-context",
            "vote-inv",
            "initial",
        );
        let digest = prepare_context(
            db,
            &run,
            "vote-context",
            "namespace",
            &vote,
            &context(&binding, "vote-intent", "vote-inv"),
            &[("fixture-initial-vote-context", incarnation.clone())],
        )
        .unwrap();
        mark_registration_submitted(
            db,
            "vote-context",
            "vote-context",
            "vote-register",
            &digest,
            &fake_bridge_pin(&binding),
        )
        .unwrap();
        let consumed = fake_consumed(
            &binding,
            &incarnation,
            "vote-intent",
            "vote-inv",
            &digest,
            &vote,
        );
        let key = crate::managed_bridge::ConsumeKey {
            abort_request_id: "abort-vote",
            expected_store_id: &binding.bridge_route.component_store_id,
            producer: "pool",
            consume_request_id: "vote-intent",
            invocation_key: "vote-inv",
            security_digest: &digest,
            audience: "pool",
        };
        mark_bootstrap_consume_submitted(
            db,
            "vote-context",
            "vote-intent",
            &digest,
            &fake_bridge_pin(&binding),
        )
        .unwrap();
        record_bootstrap_consumption(
            db,
            "vote-context",
            &key,
            &consumed,
            "pool",
            &vote,
            "epoch",
            &fake_bridge_pin(&binding),
        )
        .unwrap();
        record_fake_current(
            db,
            &run,
            &binding,
            &incarnation,
            "vote-context",
            "vote-inv",
            "fresh",
        );
        reserve(
            db,
            &run,
            &binding,
            &incarnation,
            "vote-context",
            "vote-inv",
            "vote-intent",
            &vote,
            &digest,
        )
        .unwrap();
        let admission = consumed_admission(
            db,
            &run,
            &binding,
            &incarnation,
            "vote-intent",
            "vote-inv",
            &digest,
            &vote,
        );
        mark_admitted(db, "vote-intent", &digest, &admission).unwrap();
        assert_eq!(
            record_ballot_provenance(db, "vote-intent", 1).err(),
            Some(Fault::Invalid)
        );
        let pending = snapshot_consensus(db, "vote-intent", &digest).unwrap();
        assert_eq!(pending.voters().len(), 1);
        let pin = RunPin {
            route: binding.run_route.clone(),
            socket: "/fixture/attempt.sock".into(),
            executable: "/fixture/run".into(),
            executable_sha256: "a".repeat(64),
            capabilities: vec!["attempt_consensus_v1".into()],
        };
        crate::managed_run::VoterQuery::stage(
            db,
            &pin,
            &pending.voters()[0],
            "consensus-request",
            "consensus-rpc",
        )
        .unwrap();
        let staged: String = db
            .query_row(
                "SELECT request FROM managed_current_requests WHERE id='consensus-request'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let staged: serde_json::Value = serde_json::from_str(&staged).unwrap();
        assert_eq!(staged["purpose"], "consensus");
        assert_eq!(
            staged["expected_attempt"]["attempt_id"],
            binding.attempt.attempt_id
        );
        let mut changed_incarnation = incarnation.clone();
        changed_incarnation.start_ticks += 1;
        let changed_voter = VerifiedBallot {
            binding: binding.clone(),
            generation: binding.binding_generation,
            attempt: binding.attempt.clone(),
            incarnation: changed_incarnation,
        };
        assert_eq!(
            crate::managed_run::VoterQuery::stage(
                db,
                &pin,
                &changed_voter,
                "consensus-request",
                "different-rpc",
            )
            .err(),
            Some(Fault::Conflict)
        );
        let fence = pending.verify(&run).unwrap();
        let receipt = commit_domain_vote(db, "vote-intent", &digest, fence).unwrap();
        let reply: crate::domain::Reply = decoded(&receipt).unwrap();
        let crate::domain::Reply::Receipt(reply) = reply else {
            panic!("expected a committed vote receipt");
        };
        assert_eq!(reply.revision, 2);
        assert_eq!(reply.event.kind, "proposal_accepted");
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM managed_ballot_provenance",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        let mut successor = binding.clone();
        successor.attempt.execution_id = "next".into();
        successor.attempt.sequence = 2;
        successor.attempt.attempt_id = "attempt-2".into();
        successor.attempt.launch_id = "00000000-0000-4000-8000-000000000004".into();
        let mut next = incarnation.clone();
        next.pid += 1;
        next.start_ticks += 1;
        run.receipt.receipt_id = "receipt-2".into();
        run.receipt.attempt = successor.attempt.clone();
        run.receipt.incarnation = next.clone();
        run.receipt.successor_proof.current_execution_id = "next".into();
        run.receipt.successor_proof.chain.push(SuccessorLink {
            execution_id: "next".into(),
            parent_execution_id: Some("root".into()),
            sequence: 2,
        });
        assert_eq!(
            rebind(
                db,
                &run,
                &binding,
                &successor,
                &next,
                "receipt-2",
                "ingress"
            )
            .unwrap(),
            2
        );
        successor.binding_generation = 2;
        let old_ballot = VerifiedBallot {
            binding: successor,
            generation: 1,
            attempt: binding.attempt.clone(),
            incarnation: incarnation.clone(),
        };
        assert!(check_all_voters(&run, &[old_ballot]).is_err());
        let retained: String = db
            .query_row("SELECT data FROM pools WHERE id='pool'", [], |row| {
                row.get(0)
            })
            .unwrap();
        let retained: Pool = decoded(&retained).unwrap();
        assert_eq!(retained.proposal.unwrap().state, ProposalState::Accepted);
    }
    #[test]
    fn nonfinal_managed_vote_does_not_require_other_ballots_or_accept() {
        use crate::domain::{Ballot, Choice, MemberState, Pool, Proposal, ProposalState, Vote};

        fn apply_vote(
            db: &Connection,
            original: &Pool,
            force_accept: bool,
        ) -> Result<(String, u64), Fault> {
            let mut pool = original.clone();
            pool.revision = 2;
            let proposal = pool.proposal.as_mut().ok_or(Fault::Internal)?;
            let ballot = Ballot {
                choice: Choice::Ready,
                evidence: "evidence".into(),
                checks_met: None,
                vote_event_id: None,
                checks_count: None,
                validity: None,
            };
            proposal.votes.insert("member".into(), ballot.clone());
            if force_accept {
                proposal.votes.insert("other".into(), ballot);
                proposal.state = ProposalState::Accepted;
            }
            db.execute(
                "UPDATE pools SET data=?1 WHERE id='pool'",
                [encoded(&pool)?],
            )?;
            let kind = if force_accept {
                "proposal_accepted"
            } else {
                "vote_recorded"
            };
            let event = serde_json::json!({"event_id":0,"revision":2,"kind":kind,"author":{"kind":"member","member_id":"member"},"body":"Proposal proposal: Ready.\nevidence","recipient":null});
            db.execute(
                "INSERT INTO events(pool,data) VALUES('pool',?1)",
                [event.to_string()],
            )?;
            Ok((
                "vote-receipt".into(),
                u64::try_from(db.last_insert_rowid()).map_err(|_| Fault::Internal)?,
            ))
        }

        let (_dir, mut store, binding, incarnation, mut run) = fixture();
        // A later Run observation may be unavailable after admission; recording
        // a nonfinal vote is still governed by the admitted generation CAS.
        run.observation.state = VoterState::Unavailable;
        let db = store.test_db();
        let raw: String = db
            .query_row("SELECT data FROM members WHERE id='member'", [], |r| {
                r.get(0)
            })
            .unwrap();
        let mut author: crate::domain::Binding = decoded(&raw).unwrap();
        author.member.state = MemberState::Active;
        db.execute(
            "UPDATE members SET data=?1 WHERE id='member'",
            [encoded(&author).unwrap()],
        )
        .unwrap();
        let mut other = author.clone();
        other.member.member_id = "other".into();
        other.member.name = "other".into();
        other.run_id = None;
        other.address = None;
        db.execute(
            "INSERT INTO members(id,pool,current,data) VALUES('other','pool',1,?1)",
            [encoded(&other).unwrap()],
        )
        .unwrap();
        let raw: String = db
            .query_row("SELECT data FROM pools WHERE id='pool'", [], |r| r.get(0))
            .unwrap();
        let mut pool: Pool = decoded(&raw).unwrap();
        pool.proposal = Some(Proposal {
            proposal_id: "proposal".into(),
            roster_key: "roster".into(),
            voters: vec!["member".into(), "other".into()],
            result: "result".into(),
            criteria: "criteria".into(),
            snapshot: None,
            snapshot_bytes: None,
            state: ProposalState::Open,
            votes: std::collections::BTreeMap::new(),
        });
        db.execute(
            "INSERT INTO proposals(id,pool,state,data) VALUES('proposal','pool','open',?1)",
            [encoded(pool.proposal.as_ref().unwrap()).unwrap()],
        )
        .unwrap();
        db.execute(
            "UPDATE pools SET data=?1 WHERE id='pool'",
            [encoded(&pool).unwrap()],
        )
        .unwrap();
        let vote = Command::Vote(Vote {
            change: Change {
                pool_id: "pool".into(),
                expected_revision: 1,
                request_key: "vote-key".into(),
            },
            proposal_id: "proposal".into(),
            roster_key: "roster".into(),
            choice: Choice::Ready,
            evidence: "evidence".into(),
            checks: vec![],
        });
        let digest = prepare_command(
            db,
            &run,
            &binding,
            &incarnation,
            "vote-context",
            "vote-intent",
            "vote-inv",
            &vote,
        );
        assert_eq!(
            reserve(
                db,
                &run,
                &binding,
                &incarnation,
                "vote-context",
                "vote-inv",
                "vote-intent",
                &vote,
                &digest
            )
            .unwrap(),
            IntentReservation::Created
        );
        let admission = consumed_admission(
            db,
            &run,
            &binding,
            &incarnation,
            "vote-intent",
            "vote-inv",
            &digest,
            &vote,
        );
        mark_admitted(db, "vote-intent", &digest, &admission).unwrap();

        let pending = snapshot_consensus(db, "vote-intent", &digest).unwrap();
        assert!(pending.voters().is_empty());
        let fence = pending.verify(&run).unwrap();
        assert_eq!(
            commit_vote(db, "vote-intent", &digest, fence, |db, _| apply_vote(
                db, &pool, true
            ))
            .err(),
            Some(Fault::Conflict)
        );
        let events: i64 = db
            .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(events, 0);
        let fence = snapshot_consensus(db, "vote-intent", &digest)
            .unwrap()
            .verify(&run)
            .unwrap();
        assert_eq!(
            commit_vote(db, "vote-intent", &digest, fence, |db, _| apply_vote(
                db, &pool, false
            ))
            .unwrap(),
            "vote-receipt"
        );
        let raw: String = db
            .query_row("SELECT data FROM pools WHERE id='pool'", [], |r| r.get(0))
            .unwrap();
        let stored: Pool = decoded(&raw).unwrap();
        let proposal = stored.proposal.unwrap();
        assert_eq!(proposal.state, ProposalState::Open);
        assert!(proposal.votes.contains_key("member"));
        assert!(!proposal.votes.contains_key("other"));
    }
    #[test]
    fn namespace_seal_keeps_uncertain_work_draining() {
        let (_dir, mut store, binding, incarnation, run) = fixture();
        let db = store.test_db();
        let digest = prepare(
            db,
            &run,
            &binding,
            &incarnation,
            "context-1",
            "intent-1",
            "inv-1",
            1,
        );
        assert_eq!(
            reserve(
                db,
                &run,
                &binding,
                &incarnation,
                "context-1",
                "inv-1",
                "intent-1",
                &command(1),
                &digest
            )
            .unwrap(),
            IntentReservation::Created
        );
        let _admission = consumed_admission(
            db,
            &run,
            &binding,
            &incarnation,
            "intent-1",
            "inv-1",
            &digest,
            &command(1),
        );
        let first = seal_namespace(
            db,
            &binding.bridge_route,
            "pool",
            "epoch",
            "seal-request",
            "retire-key",
        )
        .unwrap();
        assert!(!first.sealed);
        assert_eq!(
            commit(db, "intent-1", &digest, |_, _| panic!(
                "sealed CAS executed"
            ))
            .err(),
            Some(Fault::Stale)
        );
        assert_eq!(
            reserve_bootstrap(
                db,
                &BootstrapRequest {
                    namespace_id: "namespace",
                    bootstrap_id: "context-2",
                    route: &binding.bridge_route,
                    bridge_pin: &fake_bridge_pin(&binding),
                    producer: "pool",
                    issuer_epoch: "epoch",
                    invocation_key: "inv-2",
                    command: &command(1),
                    native_proof: &native_proof()
                }
            )
            .err(),
            Some(Fault::Stale)
        );
        terminal_abort(db, "intent-1", &digest, "aborted").unwrap();
        resolve_abort_fence(db, "intent-1", &digest, true, "bridge-proof").unwrap();
        let draining = seal_namespace(
            db,
            &binding.bridge_route,
            "pool",
            "epoch",
            "seal-request",
            "retire-key",
        )
        .unwrap();
        assert!(!draining.sealed);
        assert_eq!(first.seal_id, draining.seal_id);
        resolve_abort_fence(db, "intent-1", &digest, false, "run-proof").unwrap();
        let sealed = seal_namespace(
            db,
            &binding.bridge_route,
            "pool",
            "epoch",
            "seal-request",
            "retire-key",
        )
        .unwrap();
        assert!(sealed.sealed);
        assert_eq!(first.seal_id, sealed.seal_id);
        assert_eq!(
            seal_namespace(
                db,
                &binding.bridge_route,
                "pool",
                "epoch",
                "other-request",
                "retire-key"
            )
            .err(),
            Some(Fault::Conflict)
        );
    }

    #[test]
    fn managed_capacity_counts_only_live_work_and_compacts_after_seal() {
        let (directory, mut store, binding, incarnation, run) = fixture();
        let path = directory.path().join("pool.db");
        let digest;
        let outcome_digest;
        {
            let db = store.test_db();
            digest = prepare(
                db,
                &run,
                &binding,
                &incarnation,
                "context-1",
                "intent-1",
                "inv-1",
                1,
            );
            let before = managed_capacity(db).unwrap();
            assert!(before.valid());
            assert_eq!(before.bootstraps.active, 1);
            assert_eq!(before.contexts.active, 1);
            assert_eq!(before.contexts_without_intent, 1);
            assert_eq!(before.intents.reserved, 1);
            assert_eq!(before.intents.headroom, MANAGED_CAPACITY - 1);
            let mut invalid = before.clone();
            invalid.intents.headroom += 1;
            assert!(!invalid.valid());
            assert_eq!(
                reserve(
                    db,
                    &run,
                    &binding,
                    &incarnation,
                    "context-1",
                    "inv-1",
                    "intent-1",
                    &command(1),
                    &digest
                )
                .unwrap(),
                IntentReservation::Created
            );
            let admission = consumed_admission(
                db,
                &run,
                &binding,
                &incarnation,
                "intent-1",
                "inv-1",
                &digest,
                &command(1),
            );
            mark_admitted(db, "intent-1", &digest, &admission).unwrap();
            db.execute("INSERT INTO managed_current_requests(id,run_pin,request,digest,after_consume,state,owner_intent) VALUES('owned-current','{}','{}','hash',0,'prepared','intent-1')",[]).unwrap();
            assert_eq!(managed_capacity(db).unwrap().current_requests.active, 1);
            commit(
                db,
                "intent-1",
                &digest,
                |_, _| Ok("terminal-receipt".into()),
            )
            .unwrap();
            let before = managed_capacity(db).unwrap();
            assert_eq!(before.intents.active, 1);
            assert_eq!(before.contexts.active, 1);
            assert_eq!(before.current_requests.active, 0);
            let draining =
                seal_namespace(db, &binding.bridge_route, "pool", "epoch", "seal", "retire")
                    .unwrap();
            assert!(!draining.sealed);
            assert_ne!(
                db.query_row::<String, _, _>(
                    "SELECT command FROM managed_intents WHERE id='intent-1'",
                    [],
                    |row| row.get(0)
                )
                .unwrap(),
                "{}"
            );
            outcome_digest = outcome(db, "intent-1", &digest)
                .unwrap()
                .outcome_digest
                .unwrap();
            let settlement = crate::managed_run::Lookup {
                state: "settled_committed".into(),
                admission: Some(admission),
                outcome_digest: Some(outcome_digest.clone()),
            };
            record_run_settlement(db, "intent-1", &digest, &settlement).unwrap();
            let sealed =
                seal_namespace(db, &binding.bridge_route, "pool", "epoch", "seal", "retire")
                    .unwrap();
            assert!(sealed.sealed);
            assert_eq!(sealed.seal_id, draining.seal_id);
            let payloads:(String,String,String,String)=db.query_row("SELECT b.command,c.command,c.snapshot,i.command FROM managed_bootstrap b JOIN managed_contexts c ON c.invocation_key=b.invocation_key JOIN managed_intents i ON i.context_id=c.id WHERE i.id='intent-1'",[],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).unwrap();
            assert_eq!(
                payloads,
                ("{}".into(), "{}".into(), "{}".into(), "{}".into())
            );
            assert_eq!(
                outcome(db, "intent-1", &digest)
                    .unwrap()
                    .outcome_digest
                    .as_deref(),
                Some(outcome_digest.as_str())
            );
            assert!(authorize_outcome_route(db, "intent-1", &binding.run_route).is_ok());
            assert_eq!(
                db.query_row::<String, _, _>(
                    "SELECT terminal_receipt FROM managed_intents WHERE id='intent-1'",
                    [],
                    |row| row.get(0)
                )
                .unwrap(),
                "terminal-receipt"
            );
            assert_eq!(
                db.query_row::<i64, _, _>(
                    "SELECT count(*) FROM managed_domain_keys WHERE intent_id='intent-1'",
                    [],
                    |row| row.get(0)
                )
                .unwrap(),
                1
            );
            let after = managed_capacity(db).unwrap();
            assert!(after.valid());
            assert_eq!(
                (
                    after.namespaces.active,
                    after.bootstraps.active,
                    after.contexts.active,
                    after.intents.active,
                    after.current_requests.active
                ),
                (0, 0, 0, 0, 0)
            );
            assert!(
                after.bootstraps.retained > 0
                    && after.contexts.retained > 0
                    && after.intents.retained > 0
            );
            assert_eq!(after.intents.headroom, MANAGED_CAPACITY);
            let again =
                seal_namespace(db, &binding.bridge_route, "pool", "epoch", "seal", "retire")
                    .unwrap();
            assert_eq!(again.seal_id, sealed.seal_id);
            let proof = native_proof();
            let pin = fake_bridge_pin(&binding);
            assert_eq!(
                reserve_bootstrap(
                    db,
                    &BootstrapRequest {
                        namespace_id: "namespace-2",
                        bootstrap_id: "new-bootstrap",
                        route: &binding.bridge_route,
                        bridge_pin: &pin,
                        producer: "pool",
                        issuer_epoch: "epoch-2",
                        invocation_key: "inv-1",
                        command: &command(1),
                        native_proof: &proof
                    }
                )
                .err(),
                Some(Fault::Conflict)
            );
            let fresh_command = command(1);
            let fresh_digest = prepare_command_in_namespace(
                db,
                &run,
                &binding,
                &incarnation,
                "fresh-context",
                "fresh-intent",
                "fresh-inv",
                &fresh_command,
                "namespace-2",
                "epoch-2",
            );
            let mut fresh_consumed = fake_consumed(
                &binding,
                &incarnation,
                "fresh-intent",
                "fresh-inv",
                &fresh_digest,
                &fresh_command,
            );
            fresh_consumed.receipt.issuer_epoch = "epoch-2".into();
            let fresh_authority =
                fresh_authority(db, &binding, "fresh-context", "fresh-inv").unwrap();
            let pool_route = Route {
                component_store_id: binding.pool_store_id.clone(),
                route_id: "pool-route".into(),
                worker_uid: binding.run_route.worker_uid,
            };
            assert_eq!(
                reserve_intent(
                    db,
                    "fresh-context",
                    "member",
                    &fresh_command,
                    &fresh_digest,
                    fresh_authority,
                    &fresh_consumed,
                    &pool_route
                )
                .unwrap(),
                IntentReservation::Committed("terminal-receipt".into())
            );
            assert_eq!(
                db.query_row::<i64, _, _>("SELECT count(*) FROM managed_intents", [], |row| row
                    .get(0))
                    .unwrap(),
                1
            );
            let BootstrapRecoveryAction::BridgeAbort {
                context_id,
                pin,
                key,
            } = stage_bootstrap_recovery(db, "fresh-context").unwrap()
            else {
                panic!("fresh replay requires Bridge abort")
            };
            let abort = crate::managed_bridge::Abort {
                store_id: binding.bridge_route.component_store_id.clone(),
                aborted: true,
                receipt: Some(fresh_consumed.receipt.clone()),
            };
            record_bootstrap_abort(db, &context_id, &key.borrowed(), &abort, &pin).unwrap();
            db.execute("INSERT INTO managed_current_requests(id,run_pin,request,digest,after_consume,state) VALUES('orphan','{}','{}','hash',0,'prepared')",[]).unwrap();
            assert_eq!(managed_capacity(db).unwrap().current_requests.active, 1);
        }
        drop(store);
        let mut store = Store::open(&path).unwrap();
        assert_eq!(
            store
                .managed_outcome("intent-1", &digest, &binding.run_route)
                .unwrap()
                .outcome_digest
                .as_deref(),
            Some(outcome_digest.as_str())
        );
        let observation = crate::observer::Request {
            schema_version: 1,
            operation: crate::observer::Operation::ManagedCapacity(
                crate::observer::IdentityParams {},
            ),
        };
        let crate::observer::Data::ManagedCapacity(capacity) = store.observe(&observation).unwrap()
        else {
            panic!("capacity projection")
        };
        assert!(capacity.valid());
        assert_eq!(capacity.current_requests.active, 0);
        assert!(capacity.current_requests.retained > 0);
        assert_eq!(
            store
                .test_db()
                .query_row::<String, _, _>(
                    "SELECT state FROM managed_current_requests WHERE id='orphan'",
                    [],
                    |row| row.get(0)
                )
                .unwrap(),
            "aborted"
        );
    }

    /// Permanent old keys cannot permanently consume the live reservation budget.
    #[test]
    fn terminal_keys_above_capacity_do_not_exhaust_new_work() {
        let (_directory, mut store, binding, _incarnation, _run) = fixture();
        let db = store.test_db();
        let pin = fake_bridge_pin(&binding);
        let proof = native_proof();
        let command = command(1);
        let request = |id: &'static str, invocation: &'static str| BootstrapRequest {
            namespace_id: "namespace",
            bootstrap_id: id,
            route: &binding.bridge_route,
            bridge_pin: &pin,
            producer: "pool",
            issuer_epoch: "epoch",
            invocation_key: invocation,
            command: &command,
            native_proof: &proof,
        };
        reserve_bootstrap(db, &request("first", "first-inv")).unwrap();
        abandon_unregistered_bootstrap(db, "first").unwrap();
        db.execute_batch("BEGIN IMMEDIATE; WITH RECURSIVE seq(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM seq WHERE n<100000) INSERT INTO managed_bootstrap(id,namespace_id,invocation_key,command,proof_hash,state) SELECT 'old-'||n,'namespace','old-inv-'||n,'{}','hash','terminal' FROM seq; WITH RECURSIVE seq(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM seq WHERE n<100000) INSERT INTO managed_current_requests(id,run_pin,request,digest,after_consume,state) SELECT 'old-current-'||n,'{}','{}','hash',0,'used' FROM seq; COMMIT;").unwrap();
        let before = managed_capacity(db).unwrap();
        assert_eq!(before.bootstraps.retained, MANAGED_CAPACITY + 1);
        assert_eq!(before.bootstraps.active, 0);
        assert_eq!(before.current_requests.retained, MANAGED_CAPACITY);
        assert_eq!(before.current_requests.headroom, MANAGED_CAPACITY);
        reserve_bootstrap(db, &request("next", "next-inv")).unwrap();
        let dispatch = mark_bootstrap_submitted(db, "next").unwrap();
        record_bootstrap_ref(
            db,
            dispatch,
            &crate::managed_bridge::Prepared {
                store_id: binding.bridge_route.component_store_id.clone(),
                bridge_context_ref: bridge_sdk::bridge_protocol::Secret::new("ref"),
                invocation_key: "next-inv".into(),
                expires_at_ms: 1,
            },
            &pin,
        )
        .unwrap();
        let endpoint = fake_run_endpoint(&binding);
        let run_pin = RunPin {
            route: endpoint.route,
            socket: endpoint.socket,
            executable: endpoint.executable,
            executable_sha256: endpoint.executable_sha256,
            capabilities: vec!["attempt_current_ingress_v1".into()],
        };
        let input = CurrentIntent::Ingress {
            version: 1,
            expected_store_id: binding.run_route.component_store_id.clone(),
            request_id: "new-current".into(),
            observation_ref: bridge_sdk::bridge_protocol::Secret::new("ref"),
            invocation_key: "next-inv".into(),
        };
        prepare_current_request(db, &run_pin, &input).unwrap();
        let after = managed_capacity(db).unwrap();
        assert_eq!(after.bootstraps.active, 1);
        assert_eq!(after.current_requests.active, 1);
        assert!(after.valid());
        db.execute(
            "UPDATE managed_bootstrap SET state='prepared' WHERE id LIKE 'old-%'",
            [],
        )
        .unwrap();
        assert_eq!(
            reserve_bootstrap(db, &request("blocked", "blocked-inv")).err(),
            Some(Fault::Unavailable)
        );
        assert_eq!(
            db.query_row::<i64, _, _>(
                "SELECT count(*) FROM managed_bootstrap WHERE id='blocked'",
                [],
                |row| row.get(0)
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn v8_upgrade_compacts_already_sealed_namespace_without_losing_fences() {
        let (directory, mut store, binding, _incarnation, _run) = fixture();
        let path = directory.path().join("pool.db");
        let pin = fake_bridge_pin(&binding);
        let proof = native_proof();
        {
            let db = store.test_db();
            reserve_bootstrap(
                db,
                &BootstrapRequest {
                    namespace_id: "namespace",
                    bootstrap_id: "old",
                    route: &binding.bridge_route,
                    bridge_pin: &pin,
                    producer: "pool",
                    issuer_epoch: "epoch",
                    invocation_key: "old-inv",
                    command: &command(1),
                    native_proof: &proof,
                },
            )
            .unwrap();
            abandon_unregistered_bootstrap(db, "old").unwrap();
            let seal = seal_namespace(db, &binding.bridge_route, "pool", "epoch", "seal", "retire")
                .unwrap();
            assert!(seal.sealed);
            db.execute(
                "UPDATE managed_bootstrap SET command='legacy-command' WHERE id='old'",
                [],
            )
            .unwrap();
            db.execute("INSERT INTO managed_contexts(id,namespace_id,intent_id,invocation_key,command,context,digest,snapshot,state) VALUES('old-context','namespace','old-intent','old-inv','legacy-command','{}','digest','legacy-snapshot','invalidated')",[]).unwrap();
            db.execute_batch("DROP TABLE managed_invalidated_ballots; DROP INDEX managed_current_state_owner; ALTER TABLE managed_current_requests DROP COLUMN owner_intent; ALTER TABLE managed_bindings DROP COLUMN incarnation; DROP INDEX managed_bootstrap_state; DROP INDEX managed_intent_state; PRAGMA user_version=8;").unwrap();
        }
        drop(store);
        let mut reopened = Store::open(&path).unwrap();
        let db = reopened.test_db();
        assert_eq!(
            db.query_row::<i64, _, _>("PRAGMA user_version", [], |row| row.get(0))
                .unwrap(),
            9
        );
        let payloads:(String,String,String)=db.query_row("SELECT b.command,c.command,c.snapshot FROM managed_bootstrap b JOIN managed_contexts c ON c.invocation_key=b.invocation_key WHERE b.id='old'",[],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap();
        assert_eq!(payloads, ("{}".into(), "{}".into(), "{}".into()));
        assert_eq!(
            reserve_bootstrap(
                db,
                &BootstrapRequest {
                    namespace_id: "new-namespace",
                    bootstrap_id: "new",
                    route: &binding.bridge_route,
                    bridge_pin: &pin,
                    producer: "pool",
                    issuer_epoch: "next-epoch",
                    invocation_key: "old-inv",
                    command: &command(1),
                    native_proof: &proof
                }
            )
            .err(),
            Some(Fault::Conflict)
        );
        assert!(
            seal_namespace(db, &binding.bridge_route, "pool", "epoch", "seal", "retire")
                .unwrap()
                .sealed
        );
    }

    #[test]
    fn v8_upgrade_recovers_incarnation_only_from_retained_rebind_receipt() {
        let (directory, mut store, binding, incarnation, run) = fixture();
        let path = directory.path().join("pool.db");
        {
            let db = store.test_db();
            prepare(
                db,
                &run,
                &binding,
                &incarnation,
                "old-context",
                "old-intent",
                "old-inv",
                1,
            );
            db.execute("INSERT INTO managed_rebinds(receipt_id,member,old_binding,new_binding,generation_before,generation_after) VALUES('fixture-initial-old-context','member',?1,?1,?2,?2)",params![encoded(&binding).unwrap(),sqlite_generation(1)]).unwrap();
            db.execute_batch("DROP TABLE managed_invalidated_ballots; DROP INDEX managed_current_state_owner; ALTER TABLE managed_current_requests DROP COLUMN owner_intent; ALTER TABLE managed_bindings DROP COLUMN incarnation; DROP INDEX managed_bootstrap_state; DROP INDEX managed_intent_state; PRAGMA user_version=8;").unwrap();
        }
        drop(store);
        let mut reopened = Store::open(&path).unwrap();
        let db = reopened.test_db();
        let stored: String = db
            .query_row(
                "SELECT incarnation FROM managed_bindings WHERE member='member'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, encoded(&incarnation).unwrap());
        assert_eq!(
            rebind(
                db,
                &run,
                &binding,
                &binding,
                &incarnation,
                "receipt-1",
                "ingress"
            )
            .unwrap(),
            1
        );
    }

    #[test]
    fn v8_upgrade_refuses_inconsistent_seal_without_discarding_recovery() {
        let (directory, mut store, binding, incarnation, run) = fixture();
        let path = directory.path().join("pool.db");
        let digest;
        {
            let db = store.test_db();
            digest = prepare(
                db,
                &run,
                &binding,
                &incarnation,
                "old-context",
                "old-intent",
                "old-inv",
                1,
            );
            assert_eq!(
                reserve(
                    db,
                    &run,
                    &binding,
                    &incarnation,
                    "old-context",
                    "old-inv",
                    "old-intent",
                    &command(1),
                    &digest
                )
                .unwrap(),
                IntentReservation::Created
            );
            db.execute(
                "UPDATE managed_namespaces SET state='sealed' WHERE id='namespace'",
                [],
            )
            .unwrap();
            db.execute_batch("DROP TABLE managed_invalidated_ballots; DROP INDEX managed_current_state_owner; ALTER TABLE managed_current_requests DROP COLUMN owner_intent; ALTER TABLE managed_bindings DROP COLUMN incarnation; DROP INDEX managed_bootstrap_state; DROP INDEX managed_intent_state; PRAGMA user_version=8;").unwrap();
        }
        drop(store);
        assert!(Store::open(&path).is_err());
        let db = Connection::open(&path).unwrap();
        assert_eq!(
            db.query_row::<i64, _, _>("PRAGMA user_version", [], |row| row.get(0))
                .unwrap(),
            8
        );
        let stored:(String,String,Option<String>)=db.query_row("SELECT state,security_digest,consumed_receipt FROM managed_intents WHERE id='old-intent'",[],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap();
        assert_eq!(stored.0, "admitting");
        assert_eq!(stored.1, digest);
        assert!(stored.2.is_some());
    }
    #[test]
    fn stale_epoch_refresh_requires_definitive_first_response() {
        let (_dir, mut store, binding, _incarnation, _run) = fixture();
        let db = store.test_db();
        let proof = native_proof();
        let cmd = command(1);
        reserve_bootstrap(
            db,
            &BootstrapRequest {
                namespace_id: "old-namespace",
                bootstrap_id: "bootstrap-1",
                route: &binding.bridge_route,
                bridge_pin: &fake_bridge_pin(&binding),
                producer: "pool",
                issuer_epoch: "old-epoch",
                invocation_key: "invocation",
                command: &cmd,
                native_proof: &proof,
            },
        )
        .unwrap();
        let first = mark_bootstrap_submitted(db, "bootstrap-1").unwrap();
        mark_bootstrap_stale_epoch(db, first, crate::managed_bridge::BridgeFailure::StaleEpoch)
            .unwrap();
        reserve_bootstrap(
            db,
            &BootstrapRequest {
                namespace_id: "new-namespace",
                bootstrap_id: "bootstrap-2",
                route: &binding.bridge_route,
                bridge_pin: &fake_bridge_pin(&binding),
                producer: "pool",
                issuer_epoch: "new-epoch",
                invocation_key: "invocation",
                command: &cmd,
                native_proof: &proof,
            },
        )
        .unwrap();
        let lost_ack = mark_bootstrap_submitted(db, "bootstrap-2").unwrap();
        drop(lost_ack);
        assert!(matches!(
            mark_bootstrap_submitted(db, "bootstrap-2"),
            Err(Fault::Stale)
        ));
        let recovered = crate::managed_bridge::Prepared {
            store_id: binding.bridge_route.component_store_id.clone(),
            bridge_context_ref: bridge_sdk::bridge_protocol::Secret::new("recovered-ref"),
            invocation_key: "invocation".into(),
            expires_at_ms: 100,
        };
        let bridge_pin = fake_bridge_pin(&binding);
        let replay = BootstrapRequest {
            namespace_id: "new-namespace",
            bootstrap_id: "bootstrap-2",
            route: &binding.bridge_route,
            bridge_pin: &bridge_pin,
            producer: "pool",
            issuer_epoch: "new-epoch",
            invocation_key: "invocation",
            command: &cmd,
            native_proof: &proof,
        };
        recover_bootstrap_ref(db, &replay, &recovered).unwrap();
        recover_bootstrap_ref(db, &replay, &recovered).unwrap();
        let changed = command(2);
        assert_eq!(
            recover_bootstrap_ref(
                db,
                &BootstrapRequest {
                    command: &changed,
                    ..replay
                },
                &recovered
            )
            .err(),
            Some(Fault::Conflict)
        );
        assert!(
            seal_namespace(
                db,
                &binding.bridge_route,
                "pool",
                "new-epoch",
                "seal-request",
                "retire-key"
            )
            .unwrap()
            .sealed
        );
        assert_eq!(
            recover_bootstrap_ref(db, &replay, &recovered).err(),
            Some(Fault::Stale)
        );
    }
    #[test]
    fn abandoned_prepare_fences_delayed_ack_without_abort() {
        let (_dir, mut store, binding, _incarnation, _run) = fixture();
        let db = store.test_db();
        let cmd = command(1);
        let proof = native_proof();
        let bridge_pin = fake_bridge_pin(&binding);
        let request = BootstrapRequest {
            namespace_id: "abandon-ns",
            bootstrap_id: "abandon",
            route: &binding.bridge_route,
            bridge_pin: &bridge_pin,
            producer: "pool",
            issuer_epoch: "opaque:epoch",
            invocation_key: "invocation",
            command: &cmd,
            native_proof: &proof,
        };
        reserve_bootstrap(db, &request).unwrap();
        let delayed = mark_bootstrap_submitted(db, "abandon").unwrap();
        abandon_unregistered_bootstrap(db, "abandon").unwrap();
        let prepared = crate::managed_bridge::Prepared {
            store_id: binding.bridge_route.component_store_id.clone(),
            bridge_context_ref: bridge_sdk::bridge_protocol::Secret::new("late"),
            invocation_key: "invocation".into(),
            expires_at_ms: 100,
        };
        assert_eq!(
            record_bootstrap_ref(db, delayed, &prepared, &bridge_pin).err(),
            Some(Fault::Stale)
        );
        let duplicate = BootstrapRequest {
            bootstrap_id: "different",
            ..request
        };
        assert!(reserve_bootstrap(db, &duplicate).is_err());
        let bootstrap: (String, Option<String>) = db
            .query_row(
                "SELECT state,abort_receipt FROM managed_bootstrap WHERE id='abandon'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(bootstrap, ("terminal".into(), None));
    }
    #[test]
    fn consumed_bootstrap_without_intent_requires_real_digest_abort() {
        let (_dir, mut store, binding, incarnation, run) = fixture();
        let db = store.test_db();
        let digest = prepare(
            db,
            &run,
            &binding,
            &incarnation,
            "context-1",
            "intent-1",
            "inv-1",
            1,
        );
        assert_eq!(
            abandon_unregistered_bootstrap(db, "context-1").err(),
            Some(Fault::Conflict)
        );
        let key = crate::managed_bridge::ConsumeKey {
            abort_request_id: "abort-1",
            expected_store_id: &binding.bridge_route.component_store_id,
            producer: "pool",
            consume_request_id: "intent-1",
            invocation_key: "inv-1",
            security_digest: &digest,
            audience: "pool",
        };
        let abort = crate::managed_bridge::Abort {
            store_id: binding.bridge_route.component_store_id.clone(),
            aborted: true,
            receipt: Some(
                fake_consumed(
                    &binding,
                    &incarnation,
                    "intent-1",
                    "inv-1",
                    &digest,
                    &command(1),
                )
                .receipt,
            ),
        };
        assert_eq!(
            record_bootstrap_abort(db, "context-1", &key, &abort, &fake_bridge_pin(&binding)).err(),
            Some(Fault::Conflict)
        );
        let BootstrapRecoveryAction::BridgeAbort {
            context_id,
            pin,
            key: staged,
        } = stage_bootstrap_recovery(db, "context-1").unwrap()
        else {
            panic!("bootstrap abort plan")
        };
        let missing = crate::managed_bridge::Abort {
            store_id: binding.bridge_route.component_store_id.clone(),
            aborted: true,
            receipt: None,
        };
        assert_eq!(
            record_bootstrap_abort(db, &context_id, &staged.borrowed(), &missing, &pin).err(),
            Some(Fault::Unavailable)
        );
        assert_eq!(
            reserve(
                db,
                &run,
                &binding,
                &incarnation,
                "context-1",
                "inv-1",
                "intent-1",
                &command(1),
                &digest,
            )
            .err(),
            Some(Fault::Stale)
        );
        let BootstrapRecoveryAction::BridgeAbort { key: replayed, .. } =
            stage_bootstrap_recovery(db, "context-1").unwrap()
        else {
            panic!("bootstrap abort replay")
        };
        assert_eq!(staged.abort_request_id, replayed.abort_request_id);
        record_bootstrap_abort(db, &context_id, &staged.borrowed(), &abort, &pin).unwrap();
        record_bootstrap_abort(db, &context_id, &staged.borrowed(), &abort, &pin).unwrap();
        let sealed = seal_namespace(
            db,
            &binding.bridge_route,
            "pool",
            "epoch",
            "seal-request",
            "retire-key",
        )
        .unwrap();
        assert!(sealed.sealed);
    }
    #[tokio::test]
    async fn current_request_pins_route_and_exact_intention_before_io() {
        let (_dir, mut store, binding, _incarnation, _run) = fixture();
        let db = store.test_db();
        let endpoint = fake_run_endpoint(&binding);
        db.execute("DELETE FROM managed_run_routes", []).unwrap();
        assert_eq!(
            require_run_route(db, &endpoint).err(),
            Some(Fault::Unavailable)
        );
        persist_run_route(db, &endpoint).unwrap();
        let command = command(1);
        let proof = native_proof();
        let bridge_pin = fake_bridge_pin(&binding);
        let bootstrap = BootstrapRequest {
            namespace_id: "ns",
            bootstrap_id: "bootstrap",
            route: &binding.bridge_route,
            bridge_pin: &bridge_pin,
            producer: "pool",
            issuer_epoch: "opaque-epoch",
            invocation_key: "inv",
            command: &command,
            native_proof: &proof,
        };
        reserve_bootstrap(db, &bootstrap).unwrap();
        let mut changed_bridge = bridge_pin.clone();
        changed_bridge.server_sha256 = "c".repeat(64);
        assert_eq!(
            reserve_bootstrap(
                db,
                &BootstrapRequest {
                    bridge_pin: &changed_bridge,
                    ..bootstrap
                }
            )
            .err(),
            Some(Fault::Conflict)
        );
        let dispatch = mark_bootstrap_submitted(db, "bootstrap").unwrap();
        record_bootstrap_ref(
            db,
            dispatch,
            &crate::managed_bridge::Prepared {
                store_id: binding.bridge_route.component_store_id.clone(),
                bridge_context_ref: bridge_sdk::bridge_protocol::Secret::new("ref"),
                invocation_key: "inv".into(),
                expires_at_ms: 100,
            },
            &bridge_pin,
        )
        .unwrap();
        let pin = RunPin {
            route: binding.run_route.clone(),
            socket: "/fixture/attempt.sock".into(),
            executable: "/fixture/run".into(),
            executable_sha256: "a".repeat(64),
            capabilities: vec!["attempt_current_ingress_v1".into()],
        };
        let intent = CurrentIntent::Ingress {
            version: 1,
            expected_store_id: binding.attempt.run_store_id.clone(),
            request_id: "current-key".into(),
            observation_ref: bridge_sdk::bridge_protocol::Secret::new("ref"),
            invocation_key: "inv".into(),
        };
        prepare_current_request(db, &pin, &intent).unwrap();
        // A definitive not-ready response has no receipt and may replay this exact request.
        prepare_current_request(db, &pin, &intent).unwrap();
        let state: String = db
            .query_row(
                "SELECT state FROM managed_current_requests WHERE id='current-key'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "prepared");
        let input = crate::managed_run::IngressInput {
            bridge_route: binding.bridge_route.clone(),
            producer: "pool".into(),
            observation_ref: bridge_sdk::bridge_protocol::Secret::new("ref"),
            invocation_key: "inv".into(),
            request_id: "current-key".into(),
            transport_id: "current-rpc".into(),
        };
        let query = crate::managed_run::IngressQuery::stage(db, &pin, input.clone()).unwrap();
        let mut changed = pin.clone();
        changed.socket = "/other/attempt.sock".into();
        let wrong_peer = crate::managed_run::RunPeer {
            socket: changed.socket.clone(),
            expected_uid: binding.run_route.worker_uid,
            executable: changed.executable.clone(),
            sha256: changed.executable_sha256.clone(),
            route: binding.run_route.clone(),
            pool_route: Route {
                component_store_id: binding.pool_store_id.clone(),
                route_id: "pool-route".into(),
                worker_uid: binding.run_route.worker_uid,
            },
            bridge_route: binding.bridge_route.clone(),
            producer: "pool".into(),
            recovery_capabilities: Vec::new(),
        };
        assert_eq!(
            wrong_peer.current_ingress(&query).await.err(),
            Some(crate::managed_run::RunError::Invalid)
        );
        assert_eq!(
            crate::managed_run::IngressQuery::stage(db, &changed, input).err(),
            Some(Fault::Conflict)
        );
        assert_eq!(
            prepare_current_request(db, &changed, &intent).err(),
            Some(Fault::Conflict)
        );
        changed.capabilities.clear();
        assert_eq!(
            prepare_current_request(db, &changed, &intent).err(),
            Some(Fault::Invalid)
        );
    }
}

/// Owner of a terminal Pool state and its immutable settlement fingerprint.
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedOutcome {
    pub version: u8,
    pub store_id: String,
    pub intent_id: String,
    pub security_digest: String,
    pub state: String,
    pub outcome_digest: Option<String>,
}
/// Local terminal-outcome lookup; the caller must first authenticate the configured Run reader.
pub(crate) fn outcome(
    db: &Connection,
    intent_id: &str,
    security_digest: &str,
) -> Result<ManagedOutcome, Fault> {
    wire_string(intent_id)?;
    if security_digest.len() != 64
        || !security_digest
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(Fault::Invalid);
    }
    let store_id: String = db.query_row(
        "SELECT store_id FROM inventory_source WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    let row: Option<(String, String)> = db
        .query_row(
            "SELECT security_digest,state FROM managed_intents WHERE id=?1",
            [intent_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let state = match row {
        None => "absent",
        Some((stored, _)) if stored != security_digest => return Err(Fault::Conflict),
        Some((_, state)) if state == "committed" => "committed",
        Some((_, state)) if state == "aborted" => "aborted",
        Some(_) => "pending",
    };
    let digest = if matches!(state, "committed" | "aborted") {
        let value = serde_json::json!({"version":1,"pool_store_id":store_id,"intent_id":intent_id,"security_digest":security_digest,"state":state});
        Some(crate::managed_codec::digest(b"agent-mcp/attempt-binding/settlement/v1\0", &value)?.1)
    } else {
        None
    };
    Ok(ManagedOutcome {
        version: 1,
        store_id,
        intent_id: intent_id.into(),
        security_digest: security_digest.into(),
        state: state.into(),
        outcome_digest: digest,
    })
}

/// Persist Run's matching authenticated committed settlement; domain keys remain retained.
pub(crate) fn record_run_settlement(
    db: &mut Connection,
    intent_id: &str,
    digest: &str,
    result: &crate::managed_run::Lookup,
) -> Result<(), Fault> {
    let local = outcome(db, intent_id, digest)?;
    if local.state != "committed"
        || result.state != "settled_committed"
        || result.outcome_digest != local.outcome_digest
    {
        return Err(Fault::Conflict);
    }
    let returned = result.admission.as_ref().ok_or(Fault::Unavailable)?;
    if returned.intent_id != intent_id || returned.security_digest != digest {
        return Err(Fault::Conflict);
    }
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (state,stored_digest,admission,prior):(String,String,Option<String>,Option<String>)=tx.query_row("SELECT state,security_digest,admission,run_resolution_receipt FROM managed_intents WHERE id=?1",[intent_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
    let proof = encoded(result)?;
    if state != "committed"
        || stored_digest != digest
        || admission.as_deref() != Some(encoded(returned)?.as_str())
        || prior.as_ref().is_some_and(|old| old != &proof)
    {
        return Err(Fault::Conflict);
    }
    tx.execute(
        "UPDATE managed_intents SET run_resolved=1,run_resolution_receipt=?2 WHERE id=?1",
        params![intent_id, proof],
    )?;
    tx.commit()?;
    Ok(())
}

/// Store immutable provenance in the same transaction as the corresponding vote event.
/// Legacy ballots have no row and can never be inferred verified from an address or status.
pub(crate) fn record_ballot_provenance(
    db: &Connection,
    intent_id: &str,
    event_id: u64,
) -> Result<(), Fault> {
    if db.is_autocommit() {
        return Err(Fault::Invalid);
    }
    let (state, command_json, admission_json, digest): (String, String, Option<String>, String) =
        db.query_row(
            "SELECT state,command,admission,security_digest FROM managed_intents WHERE id=?1",
            [intent_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
    if state != "admitted" {
        return Err(Fault::Stale);
    }
    let Command::Vote(vote) = decoded::<Command>(&command_json)? else {
        return Err(Fault::Invalid);
    };
    let admission: crate::managed_run::Admission =
        decoded(admission_json.as_deref().ok_or(Fault::Internal)?)?;
    let binding = &admission.binding;
    if admission.intent_id != intent_id
        || admission.security_digest != digest
        || binding.pool_id != vote.change.pool_id
    {
        return Err(Fault::Conflict);
    }
    let pool_json: String = db.query_row(
        "SELECT data FROM pools WHERE id=?1",
        [&binding.pool_id],
        |r| r.get(0),
    )?;
    let pool: crate::domain::Pool = decoded(&pool_json)?;
    let expected_revision = vote
        .change
        .expected_revision
        .checked_add(1)
        .ok_or(Fault::Invalid)?;
    if pool.revision != expected_revision {
        return Err(Fault::Stale);
    }
    let proposal = pool
        .proposal
        .as_ref()
        .filter(|p| {
            p.proposal_id == vote.proposal_id
                && p.roster_key == vote.roster_key
                && p.voters.contains(&binding.member_id)
        })
        .ok_or(Fault::Stale)?;
    let ballot = proposal.votes.get(&binding.member_id).ok_or(Fault::Stale)?;
    let expected_checks_met = pool.acceptance.as_ref().and_then(|_| {
        (vote.choice == crate::domain::Choice::Ready).then(|| {
            vote.checks
                .iter()
                .all(|c| c.status == crate::domain::CheckStatus::Met)
        })
    });
    let expected_checks_count = pool.acceptance.as_ref().map(|_| vote.checks.len());
    if ballot.choice != vote.choice
        || ballot.evidence != vote.evidence
        || ballot.checks_met != expected_checks_met
        || ballot.checks_count != expected_checks_count
        || (pool.acceptance.is_none() && !vote.checks.is_empty())
        || ballot
            .vote_event_id
            .as_ref()
            .is_some_and(|id| id != &event_id.to_string())
    {
        return Err(Fault::Conflict);
    }
    let event_sql = i64::try_from(event_id).map_err(|_| Fault::Invalid)?;
    let event_json: String = db.query_row(
        "SELECT data FROM events WHERE id=?1 AND pool=?2",
        params![event_sql, binding.pool_id],
        |r| r.get(0),
    )?;
    let event: crate::domain::Event = decoded(&event_json)?;
    if event.revision != expected_revision
        || !matches!(&event.author,crate::domain::Author::Member(member) if member==&binding.member_id)
        || !matches!(event.kind.as_str(), "vote_recorded" | "proposal_accepted")
        || !event
            .body
            .starts_with(&format!("Proposal {}: ", vote.proposal_id))
    {
        return Err(Fault::Conflict);
    }
    let stored: (Vec<u8>, String) = db.query_row(
        "SELECT generation,binding FROM managed_bindings WHERE member=?1 AND pool=?2",
        params![binding.member_id, binding.pool_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if stored
        != (
            sqlite_generation(binding.binding_generation),
            encoded(binding)?,
        )
    {
        return Err(Fault::Stale);
    }
    db.execute("INSERT INTO managed_ballot_provenance(pool,proposal,member,event_id,generation,attempt,incarnation,admission_id,security_digest) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![binding.pool_id,vote.proposal_id,binding.member_id,event_sql,stored.0,encoded(&binding.attempt)?,encoded(&admission.incarnation)?,admission.admission_id,digest])?;
    Ok(())
}

/// Install generation one only from a Run-authenticated ingress receipt tied to
/// the member's original retained Run store and admission execution. Legacy rows
/// without that evidence are never promoted.
fn bind_initial_inner(
    db: &mut Connection,
    run: &impl RunAuthority,
    binding: &ManagedBinding,
    incarnation: &Incarnation,
    receipt_id: &str,
    authority: Option<&crate::managed_run::CurrentAuthority>,
) -> Result<(), Fault> {
    if binding.binding_generation != 1 {
        return Err(Fault::Invalid);
    }
    let receipt = run.current_receipt(&binding.run_route, receipt_id)?;
    if receipt.receipt_id != receipt_id
        || !valid_ingress_receipt(&receipt, &binding.run_route)
        || receipt.attempt != binding.attempt
        || receipt.actor != binding.actor
        || receipt.incarnation != *incarnation
        || receipt.lineage_root_id != binding.attempt.lineage_root_id
    {
        return Err(Fault::Forbidden);
    }
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let source: String = tx.query_row(
        "SELECT store_id FROM inventory_source WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    if source != binding.pool_store_id {
        return Err(Fault::Stale);
    }
    let raw: String = tx.query_row(
        "SELECT data FROM members WHERE id=?1 AND pool=?2 AND current=1",
        params![binding.member_id, binding.pool_id],
        |row| row.get(0),
    )?;
    let member: crate::domain::Binding = decoded(&raw)?;
    if member.run_store_id.as_deref() != Some(binding.attempt.run_store_id.as_str())
        || member.address.as_deref() != Some(binding.actor.address.as_str())
        || !receipt.successor_proof.chain.iter().any(|link| {
            Some(link.execution_id.as_str()) == member.run_id.as_deref()
                && Some(u64::from(link.sequence)) == member.run_sequence
        })
    {
        return Err(Fault::Forbidden);
    }
    let existing: Option<(Vec<u8>, String, Option<String>)> = tx
        .query_row(
            "SELECT generation,binding,incarnation FROM managed_bindings WHERE member=?1",
            [&binding.member_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    if let Some((generation, stored, prior_incarnation)) = existing {
        if read_generation(&generation)? != 1 || stored != encoded(binding)? {
            return Err(Fault::Conflict);
        }
        if prior_incarnation.as_deref() != Some(encoded(incarnation)?.as_str()) {
            return Err(Fault::Stale);
        }
        if let Some(authority) = authority {
            require_staged_current(&tx, authority, &receipt, &binding.run_route, true)?;
        }
        return Ok(());
    }
    if let Some(authority) = authority {
        require_staged_current(&tx, authority, &receipt, &binding.run_route, false)?;
    }
    // Reuse the same strict lineage/process/route checks as subsequent rebinds.
    let mut old = binding.clone();
    let original = receipt
        .successor_proof
        .chain
        .iter()
        .find(|link| Some(link.execution_id.as_str()) == member.run_id.as_deref())
        .ok_or(Fault::Forbidden)?;
    old.attempt.execution_id = original.execution_id.clone();
    old.attempt.sequence = original.sequence;
    if !receipt_matches(&receipt, &old, binding, incarnation, "ingress") {
        return Err(Fault::Forbidden);
    }
    tx.execute(
        "INSERT INTO managed_bindings(member,pool,generation,binding,incarnation) VALUES(?1,?2,?3,?4,?5)",
        params![
            binding.member_id,
            binding.pool_id,
            sqlite_generation(1),
            encoded(binding)?,
            encoded(incarnation)?
        ],
    )?;
    tx.execute("INSERT INTO managed_pool_epochs(pool,epoch) VALUES(?1,1) ON CONFLICT(pool) DO UPDATE SET epoch=epoch+1",[&binding.pool_id])?;
    tx.execute("INSERT INTO managed_rebinds(receipt_id,member,old_binding,new_binding,generation_before,generation_after) VALUES(?1,?2,'null',?3,?4,?5)",params![receipt_id,binding.member_id,encoded(binding)?,sqlite_generation(0),sqlite_generation(1)])?;
    tx.commit()?;
    Ok(())
}

/// Bind an initial managed member only through its staged, pinned Run receipt.
pub(crate) fn bind_initial_authenticated(
    db: &mut Connection,
    authority: &crate::managed_run::CurrentAuthority,
    binding: &ManagedBinding,
    incarnation: &Incarnation,
) -> Result<(), Fault> {
    bind_initial_inner(
        db,
        authority,
        binding,
        incarnation,
        &authority.receipt().receipt_id,
        Some(authority),
    )
}

/// Select exactly one current membership using only Run's authenticated root
/// chain and actor, then bind or rebind it before any context is frozen.
pub(crate) fn select_ingress_binding(
    db: &mut Connection,
    authority: &crate::managed_run::CurrentAuthority,
    bridge_route: &Route,
    producer: &str,
    command: &Command,
) -> Result<ManagedBinding, Fault> {
    if matches!(
        command,
        Command::Join(_) | Command::Start(_) | Command::StartBatch(_) | Command::Replace(_)
    ) {
        return Err(Fault::Unavailable);
    }
    let receipt = authority.receipt();
    if !valid_ingress_receipt(receipt, authority.route())
        || bridge_route.worker_uid != authority.route().worker_uid
    {
        return Err(Fault::Unauthorized);
    }
    let request_id = authority.request_id().ok_or(Fault::Unauthorized)?;
    let (saved_bridge, saved_producer): (String, String) = db.query_row(
        "SELECT n.bridge_route,n.producer FROM managed_current_requests r JOIN managed_namespaces n ON n.id=r.namespace_id WHERE r.id=?1",
        [request_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if saved_bridge != encoded(bridge_route)? || saved_producer != producer {
        return Err(Fault::Conflict);
    }
    let actor = crate::domain::Actor::verified(
        receipt.actor.address.clone(),
        &receipt.actor.native_id,
        &receipt.actor.role,
    )?;
    let target_pool = match command {
        Command::List(_) => None,
        Command::Get(get) => Some(get.pool_id.as_str()),
        Command::Create(_) => return Err(Fault::Forbidden),
        _ => Some(command.change().ok_or(Fault::Invalid)?.pool_id.as_str()),
    };
    let mut statement = db.prepare(
        "SELECT data FROM members WHERE current=1 AND (actor=?1 OR (actor IS NULL AND address=?2)) ORDER BY id LIMIT 2",
    )?;
    let candidates = statement
        .query_map(params![actor.key, actor.address], |row| {
            row.get::<_, String>(0)
        })?
        .map(|row| decoded::<crate::domain::Binding>(&row?))
        .collect::<Result<Vec<_>, Fault>>()?;
    drop(statement);
    let [member] = candidates.as_slice() else {
        return Err(Fault::Forbidden);
    };
    if target_pool.is_some_and(|pool| pool != member.pool_id)
        || member.run_store_id.as_deref() != Some(receipt.attempt.run_store_id.as_str())
        || !receipt.successor_proof.chain.iter().any(|link| {
            Some(link.execution_id.as_str()) == member.run_id.as_deref()
                && Some(u64::from(link.sequence)) == member.run_sequence
        })
    {
        return Err(Fault::Forbidden);
    }
    let stored: Option<String> = db
        .query_row(
            "SELECT binding FROM managed_bindings WHERE member=?1 AND pool=?2",
            params![member.member.member_id, member.pool_id],
            |row| row.get(0),
        )
        .optional()?;
    let store_id: String = db.query_row(
        "SELECT store_id FROM inventory_source WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    let binding = if let Some(stored) = stored {
        let old: ManagedBinding = decoded(&stored)?;
        if old.pool_store_id != store_id
            || old.run_route != *authority.route()
            || old.bridge_route != *bridge_route
        {
            return Err(Fault::Conflict);
        }
        let mut next = old.clone();
        next.attempt = receipt.attempt.clone();
        next.actor = receipt.actor.clone();
        let generation =
            rebind_authenticated(db, authority, &old, &next, &receipt.incarnation, "ingress")?;
        next.binding_generation = generation;
        next
    } else {
        let binding = ManagedBinding {
            pool_store_id: store_id,
            pool_id: member.pool_id.clone(),
            member_id: member.member.member_id.clone(),
            binding_generation: 1,
            attempt: receipt.attempt.clone(),
            actor: receipt.actor.clone(),
            run_route: authority.route().clone(),
            bridge_route: bridge_route.clone(),
        };
        bind_initial_authenticated(db, authority, &binding, &receipt.incarnation)?;
        binding
    };
    Ok(binding)
}

#[cfg(test)]
fn bind_initial(
    db: &mut Connection,
    run: &impl RunAuthority,
    binding: &ManagedBinding,
    incarnation: &Incarnation,
    receipt_id: &str,
) -> Result<(), Fault> {
    bind_initial_inner(db, run, binding, incarnation, receipt_id, None)
}

/// Restrict terminal outcome reads to the exact Run route frozen into the context.
pub(crate) fn authorize_outcome_route(
    db: &Connection,
    intent_id: &str,
    route: &Route,
) -> Result<(), Fault> {
    let context:Option<String>=db.query_row("SELECT c.context FROM managed_intents i JOIN managed_contexts c ON c.id=i.context_id WHERE i.id=?1",[intent_id],|row|row.get(0)).optional()?;
    if let Some(context) = context {
        let context: SecurityContext = decoded(&context)?;
        if context.bindings.is_empty()
            || context
                .bindings
                .iter()
                .any(|binding| binding.run_route != *route)
        {
            return Err(Fault::Forbidden);
        }
    }
    Ok(())
}

/// Recover an exact prepared Bridge reference after an unknown ACK. A retry may
/// supply the same original proof and command, but a stale response after an
/// earlier uncertain submission never releases or replaces this invocation.
pub(crate) fn recover_bootstrap_ref(
    db: &mut Connection,
    request: &BootstrapRequest<'_>,
    prepared: &crate::managed_bridge::Prepared,
) -> Result<(), Fault> {
    let BootstrapRequest {
        namespace_id,
        bootstrap_id,
        route,
        bridge_pin,
        producer,
        issuer_epoch,
        invocation_key,
        command,
        native_proof,
    } = *request;
    let command_json = encoded(&serde_json::to_value(command).map_err(|_| Fault::Internal)?)?;
    let proof_value = serde_json::to_value(native_proof).map_err(|_| Fault::Invalid)?;
    let proof_hash = crate::managed_codec::digest(
        b"agent-mcp/attempt-binding/bootstrap-proof/v1\0",
        &proof_value,
    )?
    .1;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    type BootstrapRecoveryRow = (
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        String,
        String,
        String,
        String,
        Option<String>,
    );
    let (namespace,invocation,old_command,old_proof,state,old_ref,ns_state,stored_route,stored_producer,stored_epoch,stored_pin):BootstrapRecoveryRow=tx.query_row("SELECT b.namespace_id,b.invocation_key,b.command,b.proof_hash,b.state,b.bridge_context_ref,n.state,n.bridge_route,n.producer,n.issuer_epoch,n.bridge_pin FROM managed_bootstrap b JOIN managed_namespaces n ON n.id=b.namespace_id WHERE b.id=?1",[bootstrap_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?)))?;
    if state != "submitted" || ns_state != "open" {
        return Err(Fault::Stale);
    }
    if namespace != namespace_id
        || invocation != invocation_key
        || old_command != command_json
        || old_proof != proof_hash
        || stored_route != encoded(route)?
        || stored_producer != producer
        || stored_epoch != issuer_epoch
        || stored_pin.as_deref() != Some(encoded(bridge_pin)?.as_str())
        || prepared.store_id != route.component_store_id
        || prepared.invocation_key != invocation_key
        || prepared.bridge_context_ref.expose().is_empty()
    {
        return Err(Fault::Conflict);
    }
    if let Some(old) = old_ref {
        return if old == prepared.bridge_context_ref.expose() {
            Ok(())
        } else {
            Err(Fault::Conflict)
        };
    }
    tx.execute(
        "UPDATE managed_bootstrap SET bridge_context_ref=?2 WHERE id=?1",
        params![bootstrap_id, prepared.bridge_context_ref.expose()],
    )?;
    tx.commit()?;
    Ok(())
}

/// Freeze a consume request before contacting Bridge; this does not reserve a domain key.
pub(crate) fn mark_bootstrap_consume_submitted(
    db: &mut Connection,
    context_id: &str,
    consume_request_id: &str,
    digest: &str,
    pin: &crate::managed_bridge::BridgePin,
) -> Result<(), Fault> {
    wire_string(consume_request_id)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    verify_bridge_pin(&tx, context_id, pin)?;
    let (state,namespace,ctx_state,ctx_digest,registration,prior,sent):(String,String,String,String,Option<String>,Option<String>,i64)=tx.query_row("SELECT b.state,n.state,c.state,c.digest,b.registration_digest,b.consume_request_id,b.consume_submitted FROM managed_contexts c JOIN managed_bootstrap b ON b.invocation_key=c.invocation_key JOIN managed_namespaces n ON n.id=b.namespace_id WHERE c.id=?1 AND b.state='submitted'",[context_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?)))?;
    if state != "submitted" || namespace != "open" || ctx_state != "prepared" {
        return Err(Fault::Stale);
    }
    if ctx_digest != digest || registration.as_deref() != Some(digest) {
        return Err(Fault::Conflict);
    }
    if prior.as_deref() != Some(consume_request_id) {
        return Err(Fault::Conflict);
    }
    if sent == 1 {
        return Ok(());
    }
    tx.execute("UPDATE managed_bootstrap SET consume_submitted=1 WHERE invocation_key=(SELECT invocation_key FROM managed_contexts WHERE id=?1) AND state='submitted'",[context_id])?;
    tx.commit()?;
    Ok(())
}

/// Persist Bridge's exact current consumed receipt before domain replay or key reservation.
#[allow(
    clippy::too_many_arguments,
    reason = "Exact Bridge evidence and endpoint pin remain explicit"
)]
pub(crate) fn record_bootstrap_consumption(
    db: &mut Connection,
    context_id: &str,
    key: &crate::managed_bridge::ConsumeKey<'_>,
    consumed: &crate::managed_bridge::Consumed,
    server: &str,
    command: &Command,
    epoch: &str,
    pin: &crate::managed_bridge::BridgePin,
) -> Result<(), Fault> {
    crate::managed_bridge::validate_consume(consumed, key, server, command, epoch)
        .map_err(|_| Fault::Unauthorized)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    verify_bridge_pin(&tx, context_id, pin)?;
    let context = context_current(&tx, context_id, command, key.security_digest, true)?;
    type ConsumeRow = (
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        i64,
    );
    let (namespace_route,producer,issuer,request,registration,prior_ref,prior_receipt,sent):ConsumeRow=tx.query_row("SELECT n.bridge_route,n.producer,n.issuer_epoch,b.consume_request_id,b.registration_digest,b.consumed_ref,b.consumed_receipt,b.consume_submitted FROM managed_bootstrap b JOIN managed_namespaces n ON n.id=b.namespace_id WHERE b.invocation_key=?1 AND b.state='submitted'",[&context.invocation_key],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?)))?;
    let route: Route = decoded(&namespace_route)?;
    if route.component_store_id != key.expected_store_id
        || producer != key.producer
        || issuer != epoch
        || context.invocation_key != key.invocation_key
        || context.audience != key.audience
        || request.as_deref() != Some(key.consume_request_id)
        || registration.as_deref() != Some(key.security_digest)
        || sent != 1
    {
        return Err(Fault::Conflict);
    }
    let reference = crate::managed_run::ConsumedRef {
        bridge_route: route,
        producer: key.producer.into(),
        consume_request_id: key.consume_request_id.into(),
        invocation_key: key.invocation_key.into(),
        security_digest: key.security_digest.into(),
        issuer_epoch: epoch.into(),
    };
    let reference_json = encoded(&reference)?;
    let receipt_json = encoded(&consumed.receipt)?;
    if prior_ref.is_some() || prior_receipt.is_some() {
        return if prior_ref.as_deref() == Some(&reference_json)
            && prior_receipt.as_deref() == Some(&receipt_json)
        {
            Ok(())
        } else {
            Err(Fault::Conflict)
        };
    }
    tx.execute("UPDATE managed_bootstrap SET consumed_ref=?2,consumed_receipt=?3 WHERE invocation_key=?1 AND state='submitted'",params![context.invocation_key,reference_json,receipt_json])?;
    tx.commit()?;
    Ok(())
}

/// Resolve a registered/consumed bootstrap with no Pool intent using its real
/// original digest and a verified Bridge abort, including lost-ACK recovery.
pub(crate) fn record_bootstrap_abort(
    db: &mut Connection,
    context_id: &str,
    key: &crate::managed_bridge::ConsumeKey<'_>,
    result: &crate::managed_bridge::Abort,
    pin: &crate::managed_bridge::BridgePin,
) -> Result<(), Fault> {
    if result.store_id != key.expected_store_id
        || !result.aborted
        || result.receipt.as_ref().is_some_and(|receipt| {
            receipt.producer != key.producer
                || receipt.consume_request_id != key.consume_request_id
                || receipt.invocation_key != key.invocation_key
                || receipt.security_digest != key.security_digest
        })
    {
        return Err(Fault::Conflict);
    }
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    verify_bridge_pin(&tx, context_id, pin)?;
    type AbortRow = (
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
        Option<String>,
        Option<String>,
    );
    let (state,route,producer,issuer,invocation,registration,consume_id,prior,context_json,abort_id,consumed):AbortRow=tx.query_row("SELECT b.state,n.bridge_route,n.producer,n.issuer_epoch,b.invocation_key,b.registration_digest,b.consume_request_id,b.abort_receipt,c.context,b.bridge_abort_request_id,b.consumed_receipt FROM managed_contexts c JOIN managed_bootstrap b ON b.invocation_key=c.invocation_key AND b.namespace_id=c.namespace_id JOIN managed_namespaces n ON n.id=b.namespace_id WHERE c.id=?1",[context_id],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?,row.get(9)?,row.get(10)?)))?;
    require_original_consume(consumed.as_deref(), result.receipt.as_ref())?;
    let route: Route = decoded(&route)?;
    let context: SecurityContext = decoded(&context_json)?;
    if route.component_store_id != key.expected_store_id
        || producer != key.producer
        || invocation != key.invocation_key
        || context.audience != key.audience
        || registration.as_deref() != Some(key.security_digest)
        || consume_id.as_deref() != Some(key.consume_request_id)
        || abort_id.as_deref() != Some(key.abort_request_id)
        || result
            .receipt
            .as_ref()
            .is_some_and(|receipt| receipt.issuer_epoch != issuer)
    {
        return Err(Fault::Conflict);
    }
    let proof = encoded(result)?;
    if state == "terminal" {
        return if prior.as_deref() == Some(&proof) {
            Ok(())
        } else {
            Err(Fault::Conflict)
        };
    }
    let has_intent: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM managed_intents WHERE context_id=?1)",
        [context_id],
        |row| row.get(0),
    )?;
    if state != "submitted" || has_intent {
        return Err(Fault::Conflict);
    }
    tx.execute(
        "UPDATE managed_contexts SET state='invalidated' WHERE id=?1 AND state='prepared'",
        [context_id],
    )?;
    tx.execute(
        "UPDATE managed_bootstrap SET state='terminal',abort_receipt=?2 WHERE invocation_key=?1",
        params![invocation, proof],
    )?;
    tx.commit()?;
    Ok(())
}

/// Exact protected Run endpoint and verified capability evidence frozen before I/O.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RunEndpointPin {
    pub route: Route,
    pub socket: std::path::PathBuf,
    pub executable: std::path::PathBuf,
    pub executable_sha256: String,
}
/// Pin the Run route before even a read-only capability exchange.
pub(crate) fn persist_run_route(db: &mut Connection, pin: &RunEndpointPin) -> Result<(), Fault> {
    if crate::domain::store_id(&pin.route.component_store_id).is_err()
        || wire_string(&pin.route.route_id).is_err()
        || !pin.socket.is_absolute()
        || pin
            .socket
            .file_name()
            .is_none_or(|name| name != "attempt.sock")
        || !pin.executable.is_absolute()
        || pin.executable_sha256.len() != 64
        || !pin
            .executable_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Fault::Invalid);
    }
    let route = encoded(&pin.route)?;
    let pin_json = encoded(pin)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let prior: Option<String> = tx
        .query_row(
            "SELECT pin FROM managed_run_routes WHERE route=?1",
            [&route],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(prior) = prior {
        return if prior == pin_json {
            Ok(())
        } else {
            Err(Fault::Conflict)
        };
    }
    tx.execute(
        "INSERT INTO managed_run_routes(route,pin) VALUES(?1,?2)",
        params![route, pin_json],
    )?;
    tx.commit()?;
    Ok(())
}

/// Existing bindings never discover or recreate a missing original Run route.
pub(crate) fn require_run_route(db: &Connection, pin: &RunEndpointPin) -> Result<(), Fault> {
    let prior: Option<String> = db
        .query_row(
            "SELECT pin FROM managed_run_routes WHERE route=?1",
            [encoded(&pin.route)?],
            |row| row.get(0),
        )
        .optional()?;
    match prior {
        Some(value) if value == encoded(pin)? => Ok(()),
        Some(_) => Err(Fault::Conflict),
        None => Err(Fault::Unavailable),
    }
}
/// Capability evidence is added only after authenticated discovery.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RunPin {
    pub route: Route,
    pub socket: std::path::PathBuf,
    pub executable: std::path::PathBuf,
    pub executable_sha256: String,
    pub capabilities: Vec<String>,
}
impl RunPin {
    fn endpoint(&self) -> RunEndpointPin {
        RunEndpointPin {
            route: self.route.clone(),
            socket: self.socket.clone(),
            executable: self.executable.clone(),
            executable_sha256: self.executable_sha256.clone(),
        }
    }
}
/// Closed Run currentness intentions; each purpose has its own capability.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "purpose", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum CurrentIntent {
    Ingress {
        version: u8,
        expected_store_id: String,
        request_id: String,
        observation_ref: bridge_sdk::bridge_protocol::Secret,
        invocation_key: String,
    },
    Egress {
        version: u8,
        expected_store_id: String,
        request_id: String,
        lineage_root_id: String,
        bound_execution_id: String,
    },
    Consensus {
        version: u8,
        expected_store_id: String,
        request_id: String,
        lineage_root_id: String,
        bound_execution_id: String,
        expected_attempt: AttemptRef,
        expected_incarnation: Incarnation,
    },
}
/// Persist exact request identity and source route before the first possible Run read.
pub(crate) fn prepare_current_request(
    db: &mut Connection,
    pin: &RunPin,
    intent: &CurrentIntent,
) -> Result<(), Fault> {
    let (version, store_id, request_id, root, bound, capability) = match intent {
        CurrentIntent::Ingress {
            version,
            expected_store_id,
            request_id,
            ..
        } => (
            *version,
            expected_store_id,
            request_id,
            None,
            None,
            "attempt_current_ingress_v1",
        ),
        CurrentIntent::Egress {
            version,
            expected_store_id,
            request_id,
            lineage_root_id,
            bound_execution_id,
        } => (
            *version,
            expected_store_id,
            request_id,
            Some(lineage_root_id),
            Some(bound_execution_id),
            "attempt_current_egress_v1",
        ),
        CurrentIntent::Consensus {
            version,
            expected_store_id,
            request_id,
            lineage_root_id,
            bound_execution_id,
            ..
        } => (
            *version,
            expected_store_id,
            request_id,
            Some(lineage_root_id),
            Some(bound_execution_id),
            "attempt_consensus_v1",
        ),
    };
    if version != 1
        || *store_id != pin.route.component_store_id
        || crate::domain::store_id(store_id).is_err()
        || !pin.socket.is_absolute()
        || pin
            .socket
            .file_name()
            .is_none_or(|name| name != "attempt.sock")
        || !pin.executable.is_absolute()
        || !pin.capabilities.iter().any(|item| item == capability)
        || pin.executable_sha256.len() != 64
        || !pin
            .executable_sha256
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(Fault::Invalid);
    }
    for value in [request_id, &pin.route.route_id]
        .into_iter()
        .chain(root)
        .chain(bound)
    {
        wire_string(value)?;
    }
    if let CurrentIntent::Consensus {
        expected_attempt,
        expected_incarnation,
        ..
    } = intent
        && (expected_attempt.run_store_id != *store_id
            || Some(&expected_attempt.lineage_root_id) != root
            || Some(&expected_attempt.execution_id) != bound
            || expected_incarnation.uid != pin.route.worker_uid)
    {
        return Err(Fault::Forbidden);
    }
    let request_json = encoded(intent)?;
    let pin_json = encoded(pin)?;
    let digest = crate::managed_codec::digest(
        b"agent-mcp/attempt-binding/pool-current-request/v1\0",
        &serde_json::json!({"pin":pin,"intent":intent}),
    )?
    .1;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let endpoint = pin.endpoint();
    require_run_route(&tx, &endpoint)?;
    let mut after_consume = 0;
    let mut namespace_id: Option<String> = None;
    if let CurrentIntent::Ingress {
        observation_ref,
        invocation_key,
        ..
    } = intent
    {
        type BootstrapRow = (Option<String>, String, String, String, String, bool, String);
        let stored:Option<BootstrapRow>=tx.query_row("SELECT b.bridge_context_ref,n.bridge_route,n.producer,b.state,n.state,b.consumed_receipt IS NOT NULL,n.id FROM managed_bootstrap b JOIN managed_namespaces n ON n.id=b.namespace_id WHERE b.invocation_key=?1 AND b.state='submitted'",[invocation_key],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).optional()?;
        let Some((reference, route, producer, state, namespace, consumed, ns_id)) = stored else {
            return Err(Fault::Stale);
        };
        let route: Route = decoded(&route)?;
        if reference.as_deref() != Some(observation_ref.expose())
            || route.worker_uid != pin.route.worker_uid
            || wire_string(&producer).is_err()
            || state != "submitted"
            || namespace != "open"
        {
            return Err(Fault::Stale);
        }
        after_consume = i64::from(consumed);
        namespace_id = Some(ns_id);
    }
    let prior: Option<(String, String, String)> = tx
        .query_row(
            "SELECT run_pin,request,digest FROM managed_current_requests WHERE id=?1",
            [request_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    if let Some(prior) = prior {
        return if prior == (pin_json, request_json, digest) {
            Ok(())
        } else {
            Err(Fault::Conflict)
        };
    }
    if managed_capacity_inner(&tx, false)?.current_requests.active >= MANAGED_CAPACITY {
        return Err(Fault::Unavailable);
    }
    tx.execute("INSERT INTO managed_current_requests(id,namespace_id,run_pin,request,digest,after_consume,state) VALUES(?1,?2,?3,?4,?5,?6,'prepared')",params![request_id,namespace_id,pin_json,request_json,digest,after_consume])?;
    tx.commit()?;
    Ok(())
}

/// Retain an authenticated exact Run current receipt under the pre-I/O request key.
pub(crate) fn record_current_receipt(
    db: &mut Connection,
    request_id: &str,
    authority: &crate::managed_run::CurrentAuthority,
) -> Result<(), Fault> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (pin_json, request_json, state, prior): (String, String, String, Option<String>) = tx
        .query_row(
            "SELECT run_pin,request,state,receipt FROM managed_current_requests WHERE id=?1",
            [request_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
    let pin: RunPin = decoded(&pin_json)?;
    let request_value: serde_json::Value = decoded(&request_json)?;
    let request: CurrentIntent = decoded(&request_json)?;
    let receipt = authority.receipt();
    if authority.request_id() != Some(request_id)
        || authority.route() != &pin.route
        || authority.endpoint() != &pin.endpoint()
        || authority.request() != Some(&request_value)
        || receipt.attempt.run_store_id != pin.route.component_store_id
        || receipt.incarnation.uid != pin.route.worker_uid
        || receipt.actor.role != "root"
    {
        return Err(Fault::Conflict);
    }
    match request {
        CurrentIntent::Ingress {
            request_id: stored_id,
            invocation_key,
            ..
        } if stored_id == request_id
            && authority.invocation() == Some(invocation_key.as_str())
            && valid_ingress_receipt(receipt, &pin.route) => {}
        CurrentIntent::Egress {
            request_id: stored_id,
            lineage_root_id,
            bound_execution_id,
            ..
        } if stored_id == request_id
            && authority.invocation().is_none()
            && receipt.purpose == "egress"
            && receipt.lineage_root_id == lineage_root_id
            && receipt.bound_execution_id == bound_execution_id => {}
        _ => return Err(Fault::Conflict),
    }
    let value = encoded(receipt)?;
    if state == "received" {
        return if prior.as_deref() == Some(&value) {
            Ok(())
        } else {
            Err(Fault::Conflict)
        };
    }
    if state != "prepared" {
        return Err(Fault::Stale);
    }
    tx.execute(
        "UPDATE managed_current_requests SET state='received',receipt_id=?2,receipt=?3 WHERE id=?1",
        params![request_id, receipt.receipt_id, value],
    )?;
    tx.commit()?;
    Ok(())
}

/// Durable Run admission recovery inputs captured before any Run admission I/O.
pub(crate) struct RecoveryIntent {
    pub intent_id: String,
    pub security_digest: String,
    pub state: String,
    pub run_pin: RunPin,
    pub bridge_pin: crate::managed_bridge::BridgePin,
    pub pool_route: Route,
    pub consumed_ref: crate::managed_run::ConsumedRef,
    pub admission: Option<crate::managed_run::Admission>,
    pub bridge_resolved: bool,
    pub run_resolved: bool,
}

/// Immutable admission inputs recovered from the reserved context and pinned route.
pub(crate) struct AdmissionPlan {
    pub recovery: RecoveryIntent,
    pub binding: ManagedBinding,
}

pub(crate) fn admission_plan(
    db: &Connection,
    intent_id: &str,
    digest: &str,
) -> Result<AdmissionPlan, Fault> {
    let recovery = recovery_intent(db, intent_id, digest)?;
    if recovery.state != "admitting" {
        return Err(Fault::Stale);
    }
    let (scope, context_json): (String, String) = db.query_row(
        "SELECT i.scope,c.context FROM managed_intents i JOIN managed_contexts c ON c.id=i.context_id WHERE i.id=?1",
        [intent_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let member = scope.strip_prefix("member:").ok_or(Fault::Conflict)?;
    let context: SecurityContext = decoded(&context_json)?;
    let binding = context
        .bindings
        .iter()
        .find(|binding| binding.member_id == member)
        .cloned()
        .ok_or(Fault::Conflict)?;
    if context.intent_id != intent_id
        || binding.run_route != recovery.run_pin.route
        || binding.bridge_route != recovery.consumed_ref.bridge_route
        || binding.pool_store_id != recovery.pool_route.component_store_id
    {
        return Err(Fault::Conflict);
    }
    Ok(AdmissionPlan { recovery, binding })
}
/// Reconstruct only the original exact route and correlation; absence is not an abort fence.
pub(crate) fn recovery_intent(
    db: &Connection,
    intent_id: &str,
    digest: &str,
) -> Result<RecoveryIntent, Fault> {
    let (stored,state,pin_json,pool_json,run_json,reference_json,admission_json,bridge_resolved,run_resolved):(String,String,String,String,String,Option<String>,Option<String>,bool,bool)=db.query_row("SELECT security_digest,state,run_pin,pool_route,run_route,consumed_ref,admission,bridge_resolved,run_resolved FROM managed_intents WHERE id=?1",[intent_id],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?,row.get(8)?)))?;
    if stored != digest {
        return Err(Fault::Conflict);
    }
    let run_pin: RunPin = decoded(&pin_json)?;
    let run_route: Route = decoded(&run_json)?;
    let pool_route: Route = decoded(&pool_json)?;
    let bridge_pin_json:Option<String>=db.query_row("SELECT n.bridge_pin FROM managed_intents i JOIN managed_contexts c ON c.id=i.context_id JOIN managed_namespaces n ON n.id=c.namespace_id WHERE i.id=?1",[intent_id],|row|row.get(0))?;
    let bridge_pin: crate::managed_bridge::BridgePin =
        decoded(bridge_pin_json.as_deref().ok_or(Fault::Unavailable)?)?;
    let consumed_ref: crate::managed_run::ConsumedRef =
        decoded(reference_json.as_deref().ok_or(Fault::Unavailable)?)?;
    let admission: Option<crate::managed_run::Admission> =
        admission_json.as_deref().map(decoded).transpose()?;
    if run_pin.route != run_route
        || consumed_ref.security_digest != digest
        || pool_route.worker_uid != run_route.worker_uid
        || consumed_ref.bridge_route.worker_uid != run_route.worker_uid
        || bridge_pin.route != consumed_ref.bridge_route
        || bridge_pin.producer != consumed_ref.producer
        || !run_pin
            .capabilities
            .iter()
            .any(|c| c == "attempt_admission_v1")
    {
        return Err(Fault::Unavailable);
    }
    if admission.as_ref().is_some_and(|a| {
        a.intent_id != intent_id
            || a.security_digest != digest
            || a.consumed_ref != consumed_ref
            || a.binding.run_route != run_route
            || a.binding.pool_store_id != pool_route.component_store_id
    }) {
        return Err(Fault::Conflict);
    }
    Ok(RecoveryIntent {
        intent_id: intent_id.into(),
        security_digest: digest.into(),
        state,
        run_pin,
        bridge_pin,
        pool_route,
        consumed_ref,
        admission,
        bridge_resolved,
        run_resolved,
    })
}

/// Deterministic next recovery action; neither a negative lookup nor a timeout resolves a fence.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RecoveryStep {
    FenceLocally,
    AbortBridge,
    AbortRun,
    SettleRun,
    Done,
}
/// Select bounded unresolved records without changing them or calling external services.
pub(crate) fn pending_recovery(
    db: &Connection,
    limit: u32,
    after: i64,
) -> Result<Vec<(i64, String, String)>, Fault> {
    if limit == 0 || limit > 100 {
        return Err(Fault::Invalid);
    }
    let mut statement=db.prepare("SELECT rowid,id,security_digest FROM managed_intents WHERE rowid>?1 AND (state IN ('admitting','admitted') OR (state='aborted' AND (bridge_resolved=0 OR run_resolved=0)) OR (state='committed' AND run_resolved=0)) ORDER BY rowid LIMIT ?2")?;
    let rows = statement
        .query_map(params![after, limit], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}
/// Plan conservative reconciliation from one durable snapshot; no I/O occurs here.
pub(crate) fn recovery_step(
    db: &Connection,
    intent_id: &str,
    digest: &str,
) -> Result<RecoveryStep, Fault> {
    let intent = recovery_intent(db, intent_id, digest)?;
    match intent.state.as_str() {
        "admitting" | "admitted" => Ok(RecoveryStep::FenceLocally),
        "aborted" if !intent.bridge_resolved => Ok(RecoveryStep::AbortBridge),
        "aborted" if !intent.run_resolved => Ok(RecoveryStep::AbortRun),
        "committed" if !intent.run_resolved => Ok(RecoveryStep::SettleRun),
        "aborted" | "committed" => Ok(RecoveryStep::Done),
        _ => Err(Fault::Unavailable),
    }
}

/// One verified all-voter observation, bound to the exact local roster/proposal snapshot.
pub(crate) struct ConsensusFence {
    intent_id: String,
    security_digest: String,
    pool_id: String,
    proposal_id: String,
    roster_key: String,
    member_id: String,
    fingerprint: String,
    epoch: i64,
    can_accept: bool,
    voters: Vec<VerifiedBallot>,
}
/// Unverified snapshot. Its voter identities can be queried without holding SQLite.
pub(crate) struct PendingConsensus(ConsensusFence);
impl PendingConsensus {
    pub(crate) fn intent_id(&self) -> &str {
        &self.0.intent_id
    }
    /// Re-snapshot after another voter's verified rebind; never reuse old
    /// observations to authorize acceptance under the new binding epoch.
    pub(crate) fn refresh_after_rebind(self, db: &Connection) -> Result<Self, Fault> {
        let refreshed = snapshot_consensus(db, &self.0.intent_id, &self.0.security_digest)?;
        if !refreshed.voters().is_empty() {
            return Err(Fault::Stale);
        }
        Ok(refreshed)
    }
    pub(crate) fn voters(&self) -> &[VerifiedBallot] {
        &self.0.voters
    }

    pub(crate) fn verify(self, run: &impl RunAuthority) -> Result<ConsensusFence, Fault> {
        check_all_voters(run, &self.0.voters)?;
        Ok(self.0)
    }
}

/// Only a ready vote with every other ready ballot can make acceptance possible.
fn could_accept(
    pool: &crate::domain::Pool,
    proposal: &crate::domain::Proposal,
    vote: &crate::domain::Vote,
    member_id: &str,
) -> bool {
    if vote.choice != crate::domain::Choice::Ready {
        return false;
    }
    let structured = if let Some(criteria) = &pool.acceptance {
        let required: std::collections::BTreeSet<_> = criteria.iter().map(|c| &c.id).collect();
        let supplied: std::collections::BTreeSet<_> =
            vote.checks.iter().map(|c| &c.criterion_id).collect();
        if required != supplied
            || supplied.len() != vote.checks.len()
            || vote
                .checks
                .iter()
                .any(|c| c.status != crate::domain::CheckStatus::Met)
        {
            return false;
        }
        true
    } else {
        if !vote.checks.is_empty() {
            return false;
        }
        false
    };
    proposal.voters.iter().all(|member| {
        member == member_id
            || proposal.votes.get(member).is_some_and(|ballot| {
                ballot.choice == crate::domain::Choice::Ready
                    && (!structured || ballot.checks_met == Some(true))
            })
    })
}

/// Capture the roster and provenance in one read snapshot. A vote that cannot
/// accept is recorded without a consensus evaluation; acceptance is forbidden
/// unless every managed voter is subsequently checked outside the transaction.
pub(crate) fn snapshot_consensus(
    db: &Connection,
    intent_id: &str,
    digest: &str,
) -> Result<PendingConsensus, Fault> {
    let tx = db.unchecked_transaction()?;
    let (state, stored, command_json, admission_json): (String, String, String, Option<String>) =
        tx.query_row(
            "SELECT state,security_digest,command,admission FROM managed_intents WHERE id=?1",
            [intent_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
    if state != "admitted" || stored != digest {
        return Err(Fault::Stale);
    }
    let Command::Vote(vote) = decoded::<Command>(&command_json)? else {
        return Err(Fault::Invalid);
    };
    let admission: crate::managed_run::Admission =
        decoded(admission_json.as_deref().ok_or(Fault::Unavailable)?)?;
    let pool_json: String = tx.query_row(
        "SELECT data FROM pools WHERE id=?1",
        [&vote.change.pool_id],
        |r| r.get(0),
    )?;
    let pool: crate::domain::Pool = decoded(&pool_json)?;
    let proposal = pool
        .proposal
        .as_ref()
        .filter(|p| {
            p.state == crate::domain::ProposalState::Open
                && p.proposal_id == vote.proposal_id
                && p.roster_key == vote.roster_key
        })
        .ok_or(Fault::Stale)?;
    if proposal.voters.len() > 20
        || proposal
            .voters
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != proposal.voters.len()
        || !proposal.voters.contains(&admission.binding.member_id)
        || admission.binding.pool_id != pool.pool_id
    {
        return Err(Fault::Conflict);
    }
    let author_json: String = tx
        .query_row(
            "SELECT data FROM members WHERE id=?1 AND pool=?2 AND current=1",
            params![admission.binding.member_id, pool.pool_id],
            |r| r.get(0),
        )
        .map_err(|_| Fault::Stale)?;
    let author: crate::domain::Binding = decoded(&author_json)?;
    let author_binding: (Vec<u8>, String) = tx
        .query_row(
            "SELECT generation,binding FROM managed_bindings WHERE member=?1 AND pool=?2",
            params![admission.binding.member_id, pool.pool_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(|_| Fault::Unavailable)?;
    if author.member.state != crate::domain::MemberState::Active
        || author.run_id.is_none()
        || author_binding
            != (
                sqlite_generation(admission.binding.binding_generation),
                encoded(&admission.binding)?,
            )
    {
        return Err(Fault::Stale);
    }
    let invalidated: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM managed_invalidated_ballots WHERE pool=?1 AND proposal=?2 AND member!=?3)",params![pool.pool_id,proposal.proposal_id,admission.binding.member_id],|row|row.get(0))?;
    let mut can_accept =
        !invalidated && could_accept(&pool, proposal, &vote, &admission.binding.member_id);
    let mut voters = Vec::new();
    for member_id in proposal.voters.iter().filter(|_| can_accept) {
        let raw: String = tx
            .query_row(
                "SELECT data FROM members WHERE id=?1 AND pool=?2 AND current=1",
                params![member_id, pool.pool_id],
                |r| r.get(0),
            )
            .map_err(|_| Fault::Stale)?;
        let domain: crate::domain::Binding = decoded(&raw)?;
        if domain.member.state != crate::domain::MemberState::Active {
            return Err(Fault::Stale);
        }
        if domain.run_id.is_none() {
            continue;
        }
        let (generation, binding_json): (Vec<u8>, String) = tx
            .query_row(
                "SELECT generation,binding FROM managed_bindings WHERE member=?1 AND pool=?2",
                params![member_id, pool.pool_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| Fault::Unavailable)?;
        let binding: ManagedBinding = decoded(&binding_json)?;
        let generation = read_generation(&generation)?;
        if binding.binding_generation != generation {
            return Err(Fault::Stale);
        }
        let (attempt, incarnation) = if *member_id == admission.binding.member_id {
            if binding != admission.binding {
                return Err(Fault::Stale);
            }
            (
                admission.binding.attempt.clone(),
                admission.incarnation.clone(),
            )
        } else {
            let ballot = proposal.votes.get(member_id).ok_or(Fault::Unavailable)?;
            if ballot.validity == Some(crate::domain::VoteValidity::Unknown) {
                can_accept = false;
                break;
            }
            let prefix = format!("Proposal {}: ", proposal.proposal_id);
            let latest:Option<i64>=tx.query_row("SELECT max(id) FROM events WHERE pool=?1 AND json_extract(data,'$.author.kind')='member' AND json_extract(data,'$.author.member_id')=?2 AND json_extract(data,'$.kind') IN ('vote_recorded','proposal_accepted') AND substr(json_extract(data,'$.body'),1,length(?3))=?3",params![pool.pool_id,member_id,prefix],|r|r.get(0))?;
            let Some(event_id) = latest else {
                can_accept = false;
                break;
            };
            if ballot
                .vote_event_id
                .as_ref()
                .is_some_and(|id| id != &event_id.to_string())
            {
                can_accept = false;
                break;
            }
            let prior:Option<(Vec<u8>,String,String)>=tx.query_row("SELECT generation,attempt,incarnation FROM managed_ballot_provenance WHERE pool=?1 AND proposal=?2 AND member=?3 AND event_id=?4",params![pool.pool_id,proposal.proposal_id,member_id,event_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
            let Some((stored_gen, attempt_json, incarnation_json)) = prior else {
                can_accept = false;
                break;
            };
            if read_generation(&stored_gen)? != generation {
                can_accept = false;
                break;
            }
            (decoded(&attempt_json)?, decoded(&incarnation_json)?)
        };
        voters.push(VerifiedBallot {
            binding,
            generation,
            attempt,
            incarnation,
        });
    }
    if !can_accept {
        voters.clear();
    }
    if can_accept
        && !voters
            .iter()
            .any(|voter| voter.binding.member_id == admission.binding.member_id)
    {
        return Err(Fault::Forbidden);
    }
    let fingerprint = pool_fingerprint(&tx, &pool.pool_id)?;
    let epoch: i64 = tx
        .query_row(
            "SELECT epoch FROM managed_pool_epochs WHERE pool=?1",
            [&pool.pool_id],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(0);
    let fence = ConsensusFence {
        intent_id: intent_id.into(),
        security_digest: digest.into(),
        pool_id: pool.pool_id.clone(),
        proposal_id: proposal.proposal_id.clone(),
        roster_key: proposal.roster_key.clone(),
        member_id: admission.binding.member_id.clone(),
        fingerprint,
        epoch,
        can_accept,
        voters,
    };
    tx.commit()?;
    Ok(PendingConsensus(fence))
}

/// Commit a managed vote only when every captured voter still matches the local
/// generation/roster/proposal CAS. The callback performs only SQL in this transaction.
pub(crate) fn commit_vote<F>(
    db: &mut Connection,
    intent_id: &str,
    digest: &str,
    fence: ConsensusFence,
    apply: F,
) -> Result<String, Fault>
where
    F: FnOnce(&Connection, &Command) -> Result<(String, u64), Fault>,
{
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (state, stored, context_id, command_json): (String, String, String, String) = tx
        .query_row(
            "SELECT state,security_digest,context_id,command FROM managed_intents WHERE id=?1",
            [intent_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
    if state != "admitted" || stored != digest {
        return Err(Fault::Stale);
    }
    let command: Command = decoded(&command_json)?;
    let Command::Vote(vote) = &command else {
        return Err(Fault::Invalid);
    };
    let context = context_current(&tx, &context_id, &command, digest, true)?;
    let admission = check_admission(&tx, intent_id, digest, &context)?;
    let epoch: i64 = tx
        .query_row(
            "SELECT epoch FROM managed_pool_epochs WHERE pool=?1",
            [&fence.pool_id],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(0);
    if fence.intent_id != intent_id
        || fence.security_digest != digest
        || vote.change.pool_id != fence.pool_id
        || vote.proposal_id != fence.proposal_id
        || vote.roster_key != fence.roster_key
        || admission.binding.member_id != fence.member_id
        || epoch != fence.epoch
        || pool_fingerprint(&tx, &fence.pool_id)? != fence.fingerprint
    {
        return Err(Fault::Stale);
    }
    for voter in &fence.voters {
        let (generation, binding): (Vec<u8>, String) = tx
            .query_row(
                "SELECT generation,binding FROM managed_bindings WHERE member=?1 AND pool=?2",
                params![voter.binding.member_id, fence.pool_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| Fault::Stale)?;
        if read_generation(&generation)? != voter.generation || binding != encoded(&voter.binding)?
        {
            return Err(Fault::Stale);
        }
    }
    let before: String = tx.query_row(
        "SELECT data FROM pools WHERE id=?1",
        [&fence.pool_id],
        |r| r.get(0),
    )?;
    let before: crate::domain::Pool = decoded(&before)?;
    let (receipt, event_id) = apply(&tx, &command)?;
    record_ballot_provenance(&tx, intent_id, event_id)?;
    tx.execute(
        "DELETE FROM managed_invalidated_ballots WHERE pool=?1 AND proposal=?2 AND member=?3",
        params![fence.pool_id, fence.proposal_id, fence.member_id],
    )?;
    let raw: String = tx.query_row(
        "SELECT data FROM pools WHERE id=?1",
        [&fence.pool_id],
        |r| r.get(0),
    )?;
    let pool: crate::domain::Pool = decoded(&raw)?;
    if vote_projection(&before, &fence.member_id)? != vote_projection(&pool, &fence.member_id)? {
        return Err(Fault::Conflict);
    }
    let proposal = pool
        .proposal
        .as_ref()
        .filter(|p| p.proposal_id == fence.proposal_id && p.roster_key == fence.roster_key)
        .ok_or(Fault::Stale)?;
    if !matches!(
        proposal.state,
        crate::domain::ProposalState::Open | crate::domain::ProposalState::Accepted
    ) {
        return Err(Fault::Conflict);
    }
    if proposal.state == crate::domain::ProposalState::Accepted
        && (!fence.can_accept
            || !proposal.voters.iter().all(|id| {
                proposal.votes.get(id).is_some_and(|ballot| {
                    ballot.choice == crate::domain::Choice::Ready
                        && (pool.acceptance.is_none() || ballot.checks_met == Some(true))
                })
            }))
    {
        return Err(Fault::Conflict);
    }
    tx.execute("UPDATE managed_intents SET state='committed',terminal_receipt=?2,bridge_resolved=1 WHERE id=?1",params![intent_id,receipt])?;
    tx.commit()?;
    Ok(receipt)
}

/// Apply a real vote using only the verified consensus fence supplied by Run checks.
pub(crate) fn commit_domain_vote(
    db: &mut Connection,
    intent_id: &str,
    digest: &str,
    fence: ConsensusFence,
) -> Result<String, Fault> {
    let checked_consensus = fence.can_accept;
    commit_vote(db, intent_id, digest, fence, |tx, command| {
        let context_json: String = tx.query_row(
            "SELECT c.context FROM managed_intents i JOIN managed_contexts c ON c.id=i.context_id WHERE i.id=?1",
            [intent_id],
            |row| row.get(0),
        )?;
        let context: SecurityContext = decoded(&context_json)?;
        crate::store::apply_managed_mutation(tx, command, &context, checked_consensus)
    })
}

/// A vote may update only its author's ballot, the proposal state and pool revision.
fn vote_projection(
    pool: &crate::domain::Pool,
    member_id: &str,
) -> Result<serde_json::Value, Fault> {
    let mut value = serde_json::to_value(pool).map_err(|_| Fault::Internal)?;
    let pool = value.as_object_mut().ok_or(Fault::Internal)?;
    pool.remove("revision");
    let proposal = pool
        .get_mut("proposal")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or(Fault::Internal)?;
    proposal.remove("state");
    proposal
        .get_mut("votes")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or(Fault::Internal)?
        .remove(member_id);
    Ok(value)
}

/// Owned exact Bridge abort identity, reconstructed solely from durable state.
pub(crate) struct RecoveryBridgeKey {
    pub abort_request_id: String,
    pub expected_store_id: String,
    pub producer: String,
    pub consume_request_id: String,
    pub invocation_key: String,
    pub security_digest: String,
    pub audience: String,
}
impl RecoveryBridgeKey {
    pub(crate) fn borrowed(&self) -> crate::managed_bridge::ConsumeKey<'_> {
        crate::managed_bridge::ConsumeKey {
            abort_request_id: &self.abort_request_id,
            expected_store_id: &self.expected_store_id,
            producer: &self.producer,
            consume_request_id: &self.consume_request_id,
            invocation_key: &self.invocation_key,
            security_digest: &self.security_digest,
            audience: &self.audience,
        }
    }
}
/// One staged action; no SQL transaction or store lock survives external I/O.
pub(crate) enum RecoveryAction {
    LocallyFenced,
    BridgeAbort {
        intent_id: String,
        context_id: String,
        digest: String,
        pin: crate::managed_bridge::BridgePin,
        key: RecoveryBridgeKey,
    },
    RunAbort {
        intent: RecoveryIntent,
        outcome_digest: String,
    },
    RunSettle {
        intent: RecoveryIntent,
        outcome_digest: String,
    },
    Done,
}
/// Stage the next exact operation and persist any new request identity before I/O.
pub(crate) fn stage_recovery(
    db: &mut Connection,
    intent_id: &str,
    digest: &str,
) -> Result<RecoveryAction, Fault> {
    match recovery_step(db, intent_id, digest)? {
        RecoveryStep::FenceLocally => {
            terminal_abort(db, intent_id, digest, "recovery_aborted")?;
            Ok(RecoveryAction::LocallyFenced)
        }
        RecoveryStep::AbortBridge => {
            let intent = recovery_intent(db, intent_id, digest)?;
            let (context_id,context_json,abort_id):(String,String,Option<String>)=db.query_row("SELECT c.id,c.context,b.bridge_abort_request_id FROM managed_intents i JOIN managed_contexts c ON c.id=i.context_id JOIN managed_bootstrap b ON b.invocation_key=c.invocation_key AND b.namespace_id=c.namespace_id WHERE i.id=?1",[intent_id],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?)))?;
            let context: SecurityContext = decoded(&context_json)?;
            let key = RecoveryBridgeKey {
                abort_request_id: abort_id.unwrap_or_else(crate::domain::id),
                expected_store_id: intent.consumed_ref.bridge_route.component_store_id.clone(),
                producer: intent.consumed_ref.producer.clone(),
                consume_request_id: intent.consumed_ref.consume_request_id.clone(),
                invocation_key: intent.consumed_ref.invocation_key.clone(),
                security_digest: digest.into(),
                audience: context.audience,
            };
            mark_bridge_abort_submitted(db, &context_id, &key.borrowed(), &intent.bridge_pin)?;
            Ok(RecoveryAction::BridgeAbort {
                intent_id: intent_id.into(),
                context_id,
                digest: digest.into(),
                pin: intent.bridge_pin,
                key,
            })
        }
        RecoveryStep::AbortRun => {
            let intent = recovery_intent(db, intent_id, digest)?;
            let outcome_digest = outcome(db, intent_id, digest)?
                .outcome_digest
                .ok_or(Fault::Internal)?;
            Ok(RecoveryAction::RunAbort {
                intent,
                outcome_digest,
            })
        }
        RecoveryStep::SettleRun => {
            let intent = recovery_intent(db, intent_id, digest)?;
            let outcome_digest = outcome(db, intent_id, digest)?
                .outcome_digest
                .ok_or(Fault::Internal)?;
            Ok(RecoveryAction::RunSettle {
                intent,
                outcome_digest,
            })
        }
        RecoveryStep::Done => Ok(RecoveryAction::Done),
    }
}

/// Local abandonment or an exact Bridge abort for a bootstrap with no Pool intent.
pub(crate) enum BootstrapRecoveryAction {
    LocallyAbandoned,
    BridgeAbort {
        context_id: String,
        pin: Box<crate::managed_bridge::BridgePin>,
        key: RecoveryBridgeKey,
    },
}
/// Select bounded bootstraps whose registration or preparation has not been resolved.
pub(crate) fn pending_bootstraps(
    db: &Connection,
    limit: u32,
    after: i64,
) -> Result<Vec<(i64, String)>, Fault> {
    if limit == 0 || limit > 100 {
        return Err(Fault::Invalid);
    }
    let mut statement=db.prepare("SELECT b.rowid,b.id FROM managed_bootstrap b WHERE b.rowid>?1 AND b.state IN ('prepared','submitted') AND NOT EXISTS(SELECT 1 FROM managed_contexts c JOIN managed_intents i ON i.context_id=c.id WHERE c.invocation_key=b.invocation_key) ORDER BY b.rowid LIMIT ?2")?;
    let rows = statement
        .query_map(params![after, limit], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}
/// Stage abandonment or normal real-digest Bridge abort without external I/O.
pub(crate) fn stage_bootstrap_recovery(
    db: &mut Connection,
    bootstrap_id: &str,
) -> Result<BootstrapRecoveryAction, Fault> {
    type BootstrapStageRow = (
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
    );
    let (invocation,registration,consume_id,abort_id,context_id,context_json,pin_json,producer):BootstrapStageRow=db.query_row("SELECT b.invocation_key,b.registration_digest,b.consume_request_id,b.bridge_abort_request_id,c.id,c.context,n.bridge_pin,n.producer FROM managed_bootstrap b JOIN managed_namespaces n ON n.id=b.namespace_id LEFT JOIN managed_contexts c ON c.invocation_key=b.invocation_key AND c.namespace_id=b.namespace_id WHERE b.id=?1",[bootstrap_id],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?,row.get(7)?)))?;
    let Some(digest) = registration else {
        abandon_unregistered_bootstrap(db, bootstrap_id)?;
        return Ok(BootstrapRecoveryAction::LocallyAbandoned);
    };
    let context_id = context_id.ok_or(Fault::Unavailable)?;
    let context: SecurityContext = decoded(context_json.as_deref().ok_or(Fault::Unavailable)?)?;
    let pin: crate::managed_bridge::BridgePin =
        decoded(pin_json.as_deref().ok_or(Fault::Unavailable)?)?;
    let key = RecoveryBridgeKey {
        abort_request_id: abort_id.unwrap_or_else(crate::domain::id),
        expected_store_id: pin.route.component_store_id.clone(),
        producer,
        consume_request_id: consume_id.ok_or(Fault::Unavailable)?,
        invocation_key: invocation,
        security_digest: digest,
        audience: context.audience,
    };
    mark_bridge_abort_submitted(db, &context_id, &key.borrowed(), &pin)?;
    Ok(BootstrapRecoveryAction::BridgeAbort {
        context_id,
        pin: Box::new(pin),
        key,
    })
}
