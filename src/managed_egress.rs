//! Durable, effect-scoped managed owner delivery. No native owner is contacted here.
use crate::{
    domain::{Binding, Effect, Fault, Work, identifier},
    managed_bridge::BridgePin,
    managed_run::CurrentAuthority,
    managed_state::{ManagedBinding, RunPin},
};
use bridge_sdk::bridge_protocol::{
    RetireDeliveryScopeParams, RetireResult, RetirementAction,
    attempt::IncarnationV1,
    managed_owner::{
        BindingV1, CompactManagedOwnerScopeParamsV1, CompactManagedOwnerScopeResultV1,
        LookupManagedOwnerParamsV1, ManagedModeV1, ManagedOwnerResultV1, ManagedOwnerStateV1,
        ManagedRetentionV1, OutboxIntentV1, PublishManagedOwnerParamsV1, RouteV1,
        egress_intent_digest,
    },
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

const ACTIVE_LIMIT: i64 = 100_000;
/// E12: non-decisive exact lookups tolerated before the exact-effect abort.
pub(crate) const LIVENESS_LOOKUPS: i64 = 3;

/// Schema v15 (E12): per-effect liveness bookkeeping and the permanent link
/// from an aborted original to the one new effect republished for its event.
pub(crate) fn migrate_liveness(db: &Connection) -> Result<(), Fault> {
    db.execute_batch("\
CREATE TABLE managed_delivery_liveness(effect_id TEXT PRIMARY KEY REFERENCES managed_delivery_outbox(effect_id),failures INTEGER NOT NULL DEFAULT 0 CHECK(failures>=0),next_attempt INTEGER NOT NULL DEFAULT 0 CHECK(next_attempt>=0),aborting INTEGER NOT NULL DEFAULT 0 CHECK(aborting IN (0,1)),republished_as TEXT UNIQUE REFERENCES managed_delivery_seeds(effect_id));\
CREATE TRIGGER managed_delivery_liveness_link BEFORE UPDATE OF effect_id,republished_as ON managed_delivery_liveness WHEN OLD.effect_id IS NOT NEW.effect_id OR (OLD.republished_as IS NOT NULL AND OLD.republished_as IS NOT NEW.republished_as) OR (OLD.aborting=1 AND NEW.aborting=0) BEGIN SELECT RAISE(ABORT,'immutable managed delivery liveness'); END;\
CREATE TRIGGER managed_delivery_liveness_retained BEFORE DELETE ON managed_delivery_liveness BEGIN SELECT RAISE(ABORT,'retained managed delivery liveness'); END;")?;
    Ok(())
}

/// Whether an unresolved effect's liveness backoff has elapsed.
pub(crate) fn liveness_due(db: &Connection, effect_id: &str, now: i64) -> Result<bool, Fault> {
    Ok(db.query_row(
        "SELECT NOT EXISTS(SELECT 1 FROM managed_delivery_liveness WHERE effect_id=?1 AND next_attempt>?2)",
        params![effect_id, now],
        |row| row.get(0),
    )?)
}

/// Count one non-decisive exact lookup or abort and schedule capped backoff.
pub(crate) fn liveness_failed(
    db: &mut Connection,
    effect_id: &str,
    now: i64,
) -> Result<i64, Fault> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let failures: i64 = tx
        .query_row(
            "SELECT failures FROM managed_delivery_liveness WHERE effect_id=?1",
            [effect_id],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(0_i64)
        .saturating_add(1);
    let shift = u32::try_from((failures - 1).clamp(0, 6)).map_err(|_| Fault::Internal)?;
    let next = now.saturating_add(5_i64.saturating_mul(1_i64 << shift).min(300));
    tx.execute(
        "INSERT INTO managed_delivery_liveness(effect_id,failures,next_attempt) VALUES(?1,?2,?3) ON CONFLICT(effect_id) DO UPDATE SET failures=excluded.failures,next_attempt=excluded.next_attempt",
        params![effect_id, failures, next.max(0)],
    )?;
    tx.commit()?;
    Ok(failures)
}

/// After bounded non-decisive lookups, fence the exact original effect for abort.
pub(crate) fn begin_liveness_abort(db: &mut Connection, effect_id: &str) -> Result<(), Fault> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if state(&tx, effect_id)? != Some(State::Unknown) {
        return Err(Fault::Stale);
    }
    tx.execute(
        "INSERT INTO managed_delivery_liveness(effect_id,aborting) VALUES(?1,1) ON CONFLICT(effect_id) DO UPDATE SET aborting=1",
        [effect_id],
    )?;
    let prior: Option<String> = tx.query_row(
        "SELECT abort_request_id FROM managed_delivery_outbox WHERE effect_id=?1",
        [effect_id],
        |row| row.get(0),
    )?;
    tx.execute(
        "UPDATE managed_delivery_outbox SET state='abort_pending',abort_request_id=?2,attention='outcome_unknown' WHERE effect_id=?1 AND state='unknown'",
        params![effect_id, prior.unwrap_or_else(crate::domain::id)],
    )?;
    tx.commit()?;
    Ok(())
}

/// Whether an abort-pending effect was fenced by E12 liveness (not scope retirement).
pub(crate) fn liveness_aborting(db: &Connection, effect_id: &str) -> Result<bool, Fault> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM managed_delivery_liveness WHERE effect_id=?1 AND aborting=1)",
        [effect_id],
        |row| row.get(0),
    )?)
}

/// After a durable `aborted` for a liveness-fenced original, create exactly one
/// NEW effect (new effect_id) for the same event under the normal freeze rules.
/// The original stays aborted and is never retargeted. Returns the new ID, or
/// `None` when the membership/scope no longer permits delivery.
pub(crate) fn republish(db: &mut Connection, effect_id: &str) -> Result<Option<String>, Fault> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let row: Option<(bool, Option<String>)> = tx
        .query_row(
            "SELECT aborting=1,republished_as FROM managed_delivery_liveness WHERE effect_id=?1",
            [effect_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((true, prior)) = row else {
        return Ok(None);
    };
    if let Some(prior) = prior {
        return Ok(Some(prior));
    }
    if state(&tx, effect_id)? != Some(State::Aborted) {
        return Err(Fault::Stale);
    }
    let seed = seed(&tx, effect_id)?;
    let scope_state: String = tx.query_row(
        "SELECT state FROM managed_delivery_scopes WHERE producer_scope=?1",
        [&seed.producer_scope],
        |row| row.get(0),
    )?;
    let current: bool = tx.query_row(
        "SELECT current FROM members WHERE id=?1 AND pool=?2",
        params![seed.member_id, seed.pool_id],
        |row| row.get(0),
    )?;
    let deliverable = if seed.final_notice {
        !current && matches!(scope_state.as_str(), "open" | "draining")
    } else {
        current && scope_state == "open"
    };
    if !deliverable {
        return Ok(None);
    }
    require_capacity(&tx, ACTIVE_LIMIT)?;
    let mut copy = effect(&tx, effect_id)?;
    let fresh = crate::domain::id();
    copy.effect_id = fresh.clone();
    copy.state = match &copy.work {
        Work::Deliver { address, .. } if address.is_empty() => "awaiting_binding".into(),
        Work::Deliver { .. } => "queued".into(),
        _ => return Err(Fault::Internal),
    };
    tx.execute(
        "INSERT INTO effects(id,pool,member,state,data) VALUES(?1,?2,?3,?4,?5)",
        params![
            fresh,
            copy.pool_id,
            copy.member_id,
            copy.state,
            encode(&copy)?
        ],
    )?;
    tx.execute(
        "INSERT INTO managed_delivery_seeds(effect_id,pool_id,member_id,event_key,payload_sha256,payload_length,producer_scope,final_notice,issuer_namespace) SELECT ?2,pool_id,member_id,event_key,payload_sha256,payload_length,producer_scope,final_notice,issuer_namespace FROM managed_delivery_seeds WHERE effect_id=?1",
        params![effect_id, fresh],
    )?;
    tx.execute(
        "INSERT INTO managed_delivery_outbox(effect_id,state) VALUES(?1,'pending')",
        [&fresh],
    )?;
    tx.execute(
        "UPDATE managed_delivery_liveness SET republished_as=?2 WHERE effect_id=?1 AND republished_as IS NULL",
        params![effect_id, fresh],
    )?;
    tx.commit()?;
    Ok(Some(fresh))
}
/// Check the approved active pin in the transaction that first freezes work.
fn require_active_bridge(db: &Connection, pin: &BridgePin) -> Result<(), Fault> {
    let prior: Option<String> = db
        .query_row(
            "SELECT pin FROM managed_bridge_routes WHERE route=?1",
            [encode(&pin.route)?],
            |row| row.get(0),
        )
        .optional()?;
    match prior {
        Some(value) if value == encode(pin)? => Ok(()),
        Some(_) => Err(Fault::Conflict),
        None => Err(Fault::Unavailable),
    }
}
fn require_capacity(db: &Connection, limit: i64) -> Result<(), Fault> {
    let active:i64=db.query_row("SELECT count(*) FROM managed_delivery_outbox WHERE state IN ('pending','frozen','publishing','known_unsent','unknown','abort_pending')",[],|row|row.get(0))?;
    if active >= limit {
        Err(Fault::Unavailable)
    } else {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn drop_test_schema(db: &Connection) -> Result<(), Fault> {
    db.execute_batch("DROP TABLE managed_namespace_retirements; DROP TABLE managed_route_pin_history; ALTER TABLE managed_bootstrap DROP COLUMN bridge_pin; ALTER TABLE managed_run_routes DROP COLUMN pool_route; DROP TABLE managed_delivery_outbox; DROP TABLE managed_delivery_seeds; DROP TABLE managed_delivery_scopes;")?;
    Ok(())
}

/// A pre-write refusal can be retried only for the same frozen effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OwnerFailure {
    NotSent(&'static str),
    RelaunchRequired,
    Unknown,
}

#[derive(Clone)]
pub(crate) struct ScopePlan {
    pub producer_scope: String,
    pub bridge_pin: BridgePin,
    pub audience: String,
    pub retire_request_id: String,
    pub needs_retire: bool,
}

/// Narrow custody seam for the pinned SDK and synthetic owner/retirement tests.
pub(crate) trait OwnerClient: Send + Sync {
    fn capabilities(&self, expected_store: &str) -> Result<(), OwnerFailure>;
    fn publish(
        &self,
        dispatch: &str,
        frozen: &Frozen,
    ) -> Result<ManagedOwnerResultV1, OwnerFailure>;
    fn lookup(
        &self,
        request_id: &str,
        frozen: &Frozen,
    ) -> Result<ManagedOwnerResultV1, OwnerFailure>;
    fn abort(
        &self,
        request_id: &str,
        frozen: &Frozen,
    ) -> Result<ManagedOwnerResultV1, OwnerFailure>;
    fn retire(&self, request_id: &str, scope: &ScopePlan) -> Result<RetireResult, OwnerFailure>;
    fn compact(
        &self,
        request_id: &str,
        scope: &ScopePlan,
    ) -> Result<CompactManagedOwnerScopeResultV1, OwnerFailure>;
}

fn sdk_error(error: bridge_sdk::AttemptClientError) -> OwnerFailure {
    use bridge_sdk::{AttemptClientError, TransportOutcome};
    match error {
        AttemptClientError::Refused(refusal)
            if refusal.code == "relaunch_required"
                && matches!(
                    refusal.recovery,
                    bridge_sdk::bridge_protocol::attempt::RecoveryV1::None
                ) =>
        {
            OwnerFailure::RelaunchRequired
        }
        AttemptClientError::Refused(refusal)
            if matches!(
                refusal.code.as_str(),
                "attempt_not_ready" | "qualification_pending"
            ) && matches!(
                refusal.recovery,
                bridge_sdk::bridge_protocol::attempt::RecoveryV1::None
                    | bridge_sdk::bridge_protocol::attempt::RecoveryV1::SameKeyLookup
            ) =>
        {
            OwnerFailure::NotSent(if refusal.code == "attempt_not_ready" {
                "attempt_not_ready"
            } else {
                "qualification_pending"
            })
        }
        AttemptClientError::PeerNotAuthorized
        | AttemptClientError::InvalidRequest(_)
        | AttemptClientError::Transport {
            outcome: TransportOutcome::NotSent,
            ..
        } => OwnerFailure::NotSent("route_unavailable"),
        _ => OwnerFailure::Unknown,
    }
}
fn publish_params(frozen: &Frozen) -> PublishManagedOwnerParamsV1 {
    PublishManagedOwnerParamsV1 {
        version: 1,
        expected_store_id: frozen.bridge_pin.route.component_store_id.clone(),
        audience: frozen.audience.clone(),
        run_receipt_id: frozen.run_receipt_id.clone(),
        outbox_intent: frozen.intent.clone(),
        effect_digest: frozen.digest.clone(),
        text: bridge_sdk::bridge_protocol::Secret::new(frozen.text.clone()),
    }
}
impl OwnerClient for crate::managed_bridge::SdkBridge {
    fn capabilities(&self, expected_store: &str) -> Result<(), OwnerFailure> {
        let caps =
            crate::managed_bridge::BridgeB1Client::capabilities(self).map_err(
                |error| match error {
                    crate::managed_bridge::BridgeFailure::RelaunchRequired => {
                        OwnerFailure::RelaunchRequired
                    }
                    _ => OwnerFailure::Unknown,
                },
            )?;
        if caps.store_id != expected_store
            || !caps
                .capabilities
                .iter()
                .any(|value| value == "managed_owner_v2")
        {
            return Err(OwnerFailure::NotSent("capability_missing"));
        }
        Ok(())
    }
    fn publish(
        &self,
        dispatch: &str,
        frozen: &Frozen,
    ) -> Result<ManagedOwnerResultV1, OwnerFailure> {
        self.client
            .publish_managed_owner_v1(dispatch, &self.server_pin, publish_params(frozen))
            .map_err(sdk_error)
    }
    fn lookup(
        &self,
        request_id: &str,
        frozen: &Frozen,
    ) -> Result<ManagedOwnerResultV1, OwnerFailure> {
        self.client
            .lookup_managed_owner_v1(
                request_id,
                &self.server_pin,
                LookupManagedOwnerParamsV1 {
                    version: 1,
                    expected_store_id: frozen.bridge_pin.route.component_store_id.clone(),
                    audience: frozen.audience.clone(),
                    producer_scope: frozen.seed.producer_scope.clone(),
                    effect_id: frozen.seed.effect_id.clone(),
                    effect_digest: frozen.digest.clone(),
                },
            )
            .map_err(sdk_error)
    }
    fn abort(
        &self,
        request_id: &str,
        frozen: &Frozen,
    ) -> Result<ManagedOwnerResultV1, OwnerFailure> {
        self.client
            .abort_managed_owner_v1(request_id, &self.server_pin, publish_params(frozen))
            .map_err(sdk_error)
    }
    fn retire(&self, request_id: &str, scope: &ScopePlan) -> Result<RetireResult, OwnerFailure> {
        if request_id != scope.retire_request_id {
            return Err(OwnerFailure::NotSent("route_unavailable"));
        }
        self.client
            .retire_delivery_scope_pinned(
                request_id,
                &self.server_pin,
                RetireDeliveryScopeParams {
                    scope_key: scope.producer_scope.clone(),
                    action: RetirementAction::RetireUnhanded,
                },
            )
            .map_err(sdk_error)
    }
    fn compact(
        &self,
        request_id: &str,
        scope: &ScopePlan,
    ) -> Result<CompactManagedOwnerScopeResultV1, OwnerFailure> {
        self.client
            .compact_managed_owner_scope_v1(
                request_id,
                &self.server_pin,
                CompactManagedOwnerScopeParamsV1 {
                    version: 1,
                    expected_store_id: scope.bridge_pin.route.component_store_id.clone(),
                    audience: scope.audience.clone(),
                    producer_scope: scope.producer_scope.clone(),
                },
            )
            .map_err(sdk_error)
    }
}

fn encode<T: Serialize>(value: &T) -> Result<String, Fault> {
    serde_json::to_string(value).map_err(|_| Fault::Internal)
}
fn decode<T: DeserializeOwned>(value: &str) -> Result<T, Fault> {
    serde_json::from_str(value).map_err(|_| Fault::Internal)
}

/// Immutable event-linked seed, retained independently of target changes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Seed {
    pub effect_id: String,
    pub pool_id: String,
    pub member_id: String,
    pub event_key: String,
    pub payload_sha256: String,
    pub payload_length: u64,
    pub producer_scope: String,
    pub final_notice: bool,
}

/// Target observed before a fresh Run attestation; it is never authority by itself.
#[derive(Clone)]
pub(crate) struct Target {
    pub seed: Seed,
    pub binding: ManagedBinding,
    pub text: String,
}

/// Exact frozen custody request; all values survive retry and restart unchanged.
#[derive(Clone)]
pub(crate) struct Frozen {
    pub seed: Seed,
    pub text: String,
    pub intent: OutboxIntentV1,
    pub digest: String,
    pub run_pin: RunPin,
    pub bridge_pin: BridgePin,
    pub audience: String,
    pub run_receipt_id: String,
}

/// Durable lifecycle; only `known_unsent` can issue another publish for this target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    Pending,
    Frozen,
    Publishing,
    KnownUnsent,
    Unknown,
    Accepted,
    AbortPending,
    Aborted,
    NotDelivered,
}
impl State {
    fn parse(value: &str) -> Result<Self, Fault> {
        match value {
            "pending" => Ok(Self::Pending),
            "frozen" => Ok(Self::Frozen),
            "publishing" => Ok(Self::Publishing),
            "known_unsent" => Ok(Self::KnownUnsent),
            "unknown" => Ok(Self::Unknown),
            "accepted" => Ok(Self::Accepted),
            "abort_pending" => Ok(Self::AbortPending),
            "aborted" => Ok(Self::Aborted),
            "not_delivered" => Ok(Self::NotDelivered),
            _ => Err(Fault::Internal),
        }
    }
}
pub(crate) fn state(db: &Connection, effect_id: &str) -> Result<Option<State>, Fault> {
    let value: Option<String> = db
        .query_row(
            "SELECT state FROM managed_delivery_outbox WHERE effect_id=?1",
            [effect_id],
            |row| row.get(0),
        )
        .optional()?;
    value.map(|value| State::parse(&value)).transpose()
}
pub(crate) fn scope_draining(db: &Connection, effect_id: &str) -> Result<bool, Fault> {
    let value:String=db.query_row("SELECT x.state FROM managed_delivery_seeds s JOIN managed_delivery_scopes x ON x.producer_scope=s.producer_scope WHERE s.effect_id=?1",[effect_id],|row|row.get(0))?;
    Ok(value != "open")
}
/// Project only closed, nonsecret owner-facing attention codes.
pub(crate) fn owner_attention(
    db: &Connection,
    effect_id: &str,
) -> Result<(Option<String>, Option<String>), Fault> {
    let value: Option<Option<String>> = db
        .query_row(
            "SELECT attention FROM managed_delivery_outbox WHERE effect_id=?1",
            [effect_id],
            |row| row.get(0),
        )
        .optional()?;
    let value = value.flatten();
    if value.as_deref().is_some_and(|reason| {
        !matches!(
            reason,
            "awaiting_root_hook"
                | "relaunch_required"
                | "actor_relaunch_required"
                | "actor_unavailable"
                | "binding_unavailable"
                | "route_unavailable"
                | "origin_unavailable"
                | "outcome_unknown"
                | "qualification_pending"
                | "attempt_not_ready"
                | "capability_missing"
                | "native_uncertain"
                | "channel_failed"
                | "scope_retiring"
                | "member_removed"
                | "different_lineage"
                | "actor_mismatch"
                | "not_idle"
                | "awaiting_input"
                | "finished"
                | "budget"
                | "cancelled"
                | "unavailable"
                | "invalid_request"
                | "capacity"
                | "conflict"
        )
    }) {
        return Err(Fault::Internal);
    }
    Ok(match value.as_deref() {
        Some("actor_relaunch_required") => {
            (Some("relaunch_required".into()), Some("member".into()))
        }
        Some("relaunch_required") => (value, Some("resident".into())),
        _ => (value, None),
    })
}

fn effect(db: &Connection, effect_id: &str) -> Result<Effect, Fault> {
    let (raw, state): (String, String) = db.query_row(
        "SELECT data,state FROM effects WHERE id=?1",
        [effect_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let mut effect: Effect = decode(&raw)?;
    effect.state = state;
    Ok(effect)
}
fn seed(db: &Connection, effect_id: &str) -> Result<Seed, Fault> {
    let (effect_id,pool_id,member_id,event_key,payload_sha256,length,producer_scope,final_notice):(String,String,String,String,String,i64,String,bool)=db.query_row("SELECT effect_id,pool_id,member_id,event_key,payload_sha256,payload_length,producer_scope,final_notice FROM managed_delivery_seeds WHERE effect_id=?1",[effect_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?)))?;
    Ok(Seed {
        effect_id,
        pool_id,
        member_id,
        event_key,
        payload_sha256,
        payload_length: u64::try_from(length).map_err(|_| Fault::Internal)?,
        producer_scope,
        final_notice,
    })
}
fn verified_text(db: &Connection, seed: &Seed) -> Result<String, Fault> {
    let effect = effect(db, &seed.effect_id)?;
    if effect.pool_id != seed.pool_id
        || effect.member_id.as_deref() != Some(seed.member_id.as_str())
    {
        return Err(Fault::Conflict);
    }
    let Work::Deliver { text, .. } = effect.work else {
        return Err(Fault::Conflict);
    };
    if u64::try_from(text.len()).map_err(|_| Fault::Invalid)? != seed.payload_length
        || format!("{:x}", Sha256::digest(text.as_bytes())) != seed.payload_sha256
    {
        return Err(Fault::Conflict);
    }
    Ok(text)
}

/// Select the exact previously bound member. Missing proof is unavailable, never a sampled address.
pub(crate) fn target(db: &Connection, effect_id: &str, prefix: &str) -> Result<Target, Fault> {
    let state: String = db.query_row(
        "SELECT state FROM managed_delivery_outbox WHERE effect_id=?1",
        [effect_id],
        |r| r.get(0),
    )?;
    if state != "pending" {
        return Err(Fault::Stale);
    }
    let seed = seed(db, effect_id)?;
    let source: String = db.query_row(
        "SELECT store_id FROM inventory_source WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    if prefix != format!("pool/{source}/")
        || seed.producer_scope
            != producer_scope(&source, &seed.pool_id, &seed.member_id, seed.final_notice)?
    {
        return Err(Fault::Conflict);
    }
    let (raw, current): (String, bool) = db
        .query_row(
            "SELECT data,current FROM members WHERE id=?1 AND pool=?2",
            params![seed.member_id, seed.pool_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(|_| Fault::Unavailable)?;
    if current == seed.final_notice {
        return Err(Fault::Stale);
    }
    let member: Binding = decode(&raw)?;
    let raw: Option<String> = db
        .query_row(
            "SELECT binding FROM managed_bindings WHERE member=?1 AND pool=?2",
            params![seed.member_id, seed.pool_id],
            |r| r.get(0),
        )
        .optional()?;
    let binding: ManagedBinding = decode(raw.as_deref().ok_or(Fault::Unavailable)?)?;
    if member.run_id.is_none()
        || member.run_store_id.as_deref() != Some(binding.attempt.run_store_id.as_str())
        || binding.pool_store_id != source
        || binding.pool_id != seed.pool_id
        || binding.member_id != seed.member_id
    {
        return Err(Fault::Conflict);
    }
    let text = verified_text(db, &seed)?;
    Ok(Target {
        seed,
        binding,
        text,
    })
}

/// Persist one Run observation key before I/O, and reuse it for the same candidate.
pub(crate) fn prepare_probe(
    db: &mut Connection,
    target: &Target,
    pin: &RunPin,
) -> Result<(String, RunPin, bool), Fault> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (state, prior_id, prior_pin, prior_binding, uncertain): (
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        bool,
    ) = tx.query_row(
        "SELECT state,probe_request_id,probe_pin,probe_binding,probe_uncertain FROM managed_delivery_outbox WHERE effect_id=?1",
        [&target.seed.effect_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
    )?;
    let binding: String = tx.query_row(
        "SELECT binding FROM managed_bindings WHERE pool=?1 AND member=?2",
        params![target.seed.pool_id, target.seed.member_id],
        |row| row.get(0),
    )?;
    let current: bool = tx.query_row(
        "SELECT current FROM members WHERE pool=?1 AND id=?2",
        params![target.seed.pool_id, target.seed.member_id],
        |row| row.get(0),
    )?;
    if state != "pending"
        || current == target.seed.final_notice
        || decode::<ManagedBinding>(&binding)? != target.binding
        || seed(&tx, &target.seed.effect_id)? != target.seed
    {
        return Err(Fault::Stale);
    }
    match (prior_id, prior_pin, prior_binding) {
        (Some(id), Some(old_pin), Some(old_binding)) => {
            let old_pin: RunPin = decode(&old_pin)?;
            if old_pin.endpoint() != pin.endpoint() {
                return Err(Fault::Conflict);
            }
            if decode::<ManagedBinding>(&old_binding)? == target.binding {
                tx.commit()?;
                return Ok((id, old_pin, uncertain));
            }
            tx.execute("UPDATE managed_current_requests SET state='aborted' WHERE id=?1 AND state IN ('prepared','received')", [&id])?;
        }
        (None, None, None) if !uncertain => {}
        _ => return Err(Fault::Conflict),
    }
    let id = crate::domain::id();
    tx.execute("UPDATE managed_delivery_outbox SET probe_request_id=?2,probe_pin=?3,probe_binding=?4,probe_uncertain=0 WHERE effect_id=?1 AND state='pending'",params![target.seed.effect_id,id,encode(pin)?,encode(&target.binding)?])?;
    tx.commit()?;
    Ok((id, pin.clone(), false))
}

/// Mark a possible Run write before I/O; a replayed receipt is not fresh proof.
pub(crate) fn probe_inflight(
    db: &mut Connection,
    effect_id: &str,
    id: &str,
    uncertain: bool,
) -> Result<(), Fault> {
    if db.execute("UPDATE managed_delivery_outbox SET probe_uncertain=?3 WHERE effect_id=?1 AND state='pending' AND probe_request_id=?2",params![effect_id,id,uncertain])? != 1 {
        return Err(Fault::Stale);
    }
    Ok(())
}

/// Fence an obsolete observation before a fresh request ID can select a new launch.
pub(crate) fn reset_probe(db: &mut Connection, effect_id: &str, id: &str) -> Result<(), Fault> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if tx.execute("UPDATE managed_delivery_outbox SET probe_request_id=NULL,probe_pin=NULL,probe_binding=NULL,probe_uncertain=0 WHERE effect_id=?1 AND state='pending' AND probe_request_id=?2",params![effect_id,id])? != 1 {
        return Err(Fault::Stale);
    }
    tx.execute("UPDATE managed_current_requests SET state='aborted' WHERE id=?1 AND state IN ('prepared','received')", [id])?;
    tx.commit()?;
    Ok(())
}

/// A removed ordinary member cannot acquire a new target, even on a later retry.
pub(crate) fn mark_not_delivered(
    db: &mut Connection,
    effect_id: &str,
    reason: &str,
) -> Result<(), Fault> {
    if !matches!(
        reason,
        "member_removed" | "different_lineage" | "origin_unavailable"
    ) {
        return Err(Fault::Invalid);
    }
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute("UPDATE managed_current_requests SET state='aborted' WHERE state IN ('prepared','received') AND id=(SELECT probe_request_id FROM managed_delivery_outbox WHERE effect_id=?1 AND state='pending')", [effect_id])?;
    tx.execute("UPDATE managed_delivery_outbox SET state='not_delivered',attention=?2 WHERE effect_id=?1 AND state IN ('pending','frozen')",params![effect_id,reason])?;
    tx.execute("UPDATE effects SET state='cancelled' WHERE id=?1 AND EXISTS(SELECT 1 FROM managed_delivery_outbox WHERE effect_id=?1 AND state='not_delivered')",[effect_id])?;
    tx.commit()?;
    Ok(())
}

/// Freeze a complete B2 intent only after the rebind transaction and generation CAS.
#[allow(
    clippy::too_many_arguments,
    reason = "Pinned routes, attested receipt and preflight target are independent fences"
)]
pub(crate) fn freeze(
    db: &mut Connection,
    target: &Target,
    authority: &CurrentAuthority,
    run_pin: &RunPin,
    bridge_pin: &BridgePin,
    audience: &str,
    expected_generation: u64,
) -> Result<Frozen, Fault> {
    let receipt = authority.receipt();
    if receipt.purpose != "egress"
        || authority.route() != &target.binding.run_route
        || authority.endpoint() != &run_pin.endpoint()
        || receipt.lineage_root_id != target.binding.attempt.lineage_root_id
        || receipt.actor.address != target.binding.actor.address
        || receipt.actor.native_id != target.binding.actor.native_id
        || bridge_pin.route != target.binding.bridge_route
        || bridge_pin.producer.is_empty()
        || audience.is_empty()
    {
        return Err(Fault::Forbidden);
    }
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_active_bridge(&tx, bridge_pin)?;
    crate::managed_state::require_staged_current(
        &tx,
        authority,
        receipt,
        &target.binding.run_route,
        false,
    )?;
    let (state, probe, in_flight): (String, Option<String>, bool) = tx.query_row(
        "SELECT state,probe_request_id,probe_uncertain FROM managed_delivery_outbox WHERE effect_id=?1",
        [&target.seed.effect_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    if state != "pending"
        || !in_flight
        || probe.as_deref() != authority.request_id()
        || seed(&tx, &target.seed.effect_id)? != target.seed
    {
        return Err(Fault::Stale);
    }
    let current: bool = tx.query_row(
        "SELECT current FROM members WHERE id=?1 AND pool=?2",
        params![target.seed.member_id, target.seed.pool_id],
        |r| r.get(0),
    )?;
    if current == target.seed.final_notice {
        return Err(Fault::Stale);
    }
    let (generation,binding_json,incarnation_json):(Vec<u8>,String,Option<String>)=tx.query_row("SELECT generation,binding,incarnation FROM managed_bindings WHERE member=?1 AND pool=?2",params![target.seed.member_id,target.seed.pool_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
    let binding: ManagedBinding = decode(&binding_json)?;
    if generation.as_slice() != expected_generation.to_be_bytes()
        || binding.binding_generation != expected_generation
        || binding.attempt != receipt.attempt
        || binding.actor != receipt.actor
        || binding.run_route != target.binding.run_route
        || binding.bridge_route != target.binding.bridge_route
        || binding.attempt.lineage_root_id != target.binding.attempt.lineage_root_id
        || incarnation_json.as_deref() != Some(encode(&receipt.incarnation)?.as_str())
    {
        return Err(Fault::Stale);
    }
    let scope_state: String = tx.query_row(
        "SELECT state FROM managed_delivery_scopes WHERE producer_scope=?1",
        [&target.seed.producer_scope],
        |r| r.get(0),
    )?;
    if !(scope_state == "open" || (target.seed.final_notice && scope_state == "draining")) {
        return Err(Fault::Stale);
    }
    let bridge_json = encode(bridge_pin)?;
    let text = verified_text(&tx, &target.seed)?;
    if text != target.text {
        return Err(Fault::Conflict);
    }
    let sdk_binding: BindingV1 =
        serde_json::from_value(serde_json::to_value(&binding).map_err(|_| Fault::Internal)?)
            .map_err(|_| Fault::Invalid)?;
    let sdk_incarnation: IncarnationV1 = serde_json::from_value(
        serde_json::to_value(&receipt.incarnation).map_err(|_| Fault::Internal)?,
    )
    .map_err(|_| Fault::Invalid)?;
    let sdk_route: RouteV1 = serde_json::from_value(
        serde_json::to_value(&binding.bridge_route).map_err(|_| Fault::Internal)?,
    )
    .map_err(|_| Fault::Invalid)?;
    let intent = OutboxIntentV1 {
        effect_id: target.seed.effect_id.clone(),
        producer_scope: target.seed.producer_scope.clone(),
        event_key: target.seed.event_key.clone(),
        payload_sha256: target.seed.payload_sha256.clone(),
        payload_length: target.seed.payload_length,
        target_binding: sdk_binding,
        expected_incarnation: sdk_incarnation,
        bridge_route: sdk_route,
        mode: ManagedModeV1::Message,
        retention: ManagedRetentionV1::KeepAll,
    };
    intent.validate(&text).map_err(|_| Fault::Invalid)?;
    let digest = egress_intent_digest(&intent).map_err(|_| Fault::Invalid)?;
    let request_id = authority.request_id().ok_or(Fault::Unauthorized)?;
    let changed=tx.execute("UPDATE managed_delivery_outbox SET state='frozen',run_pin=?2,bridge_pin=?3,audience=?4,run_receipt_id=?5,target_binding=?6,incarnation=?7,intent=?8,effect_digest=?9,attention=NULL WHERE effect_id=?1 AND state='pending'",params![target.seed.effect_id,encode(run_pin)?,bridge_json,audience,receipt.receipt_id,binding_json,encode(&receipt.incarnation)?,encode(&intent)?,digest])?;
    if changed != 1 {
        return Err(Fault::Stale);
    }
    if tx.execute(
        "UPDATE managed_current_requests SET state='used' WHERE id=?1 AND state='received'",
        [request_id],
    )? != 1
    {
        return Err(Fault::Stale);
    }
    tx.commit()?;
    Ok(Frozen {
        seed: target.seed.clone(),
        text,
        intent,
        digest,
        run_pin: run_pin.clone(),
        bridge_pin: bridge_pin.clone(),
        audience: audience.into(),
        run_receipt_id: receipt.receipt_id.clone(),
    })
}

/// Recover the original typed outbox; no configuration or rediscovery may change it.
pub(crate) fn frozen(db: &Connection, effect_id: &str) -> Result<Frozen, Fault> {
    type Row = (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let (run,bridge,audience,receipt,intent,digest):Row=db.query_row("SELECT run_pin,bridge_pin,audience,run_receipt_id,intent,effect_digest FROM managed_delivery_outbox WHERE effect_id=?1 AND state NOT IN ('pending','not_delivered')",[effect_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)))?;
    let seed = seed(db, effect_id)?;
    let text = verified_text(db, &seed)?;
    let intent: OutboxIntentV1 = decode(intent.as_deref().ok_or(Fault::Internal)?)?;
    let run_pin: RunPin = decode(run.as_deref().ok_or(Fault::Internal)?)?;
    let bridge_pin: BridgePin = decode(bridge.as_deref().ok_or(Fault::Internal)?)?;
    let audience = audience.ok_or(Fault::Internal)?;
    let run_receipt_id = receipt.ok_or(Fault::Internal)?;
    let digest = digest.ok_or(Fault::Internal)?;
    let source: String = db.query_row(
        "SELECT store_id FROM inventory_source WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    let sdk_run =
        serde_json::to_value(&intent.target_binding.run_route).map_err(|_| Fault::Internal)?;
    let sdk_bridge = serde_json::to_value(&intent.bridge_route).map_err(|_| Fault::Internal)?;
    intent.validate(&text).map_err(|_| Fault::Conflict)?;
    if egress_intent_digest(&intent).map_err(|_| Fault::Conflict)? != digest
        || intent.effect_id != seed.effect_id
        || intent.producer_scope != seed.producer_scope
        || intent.event_key != seed.event_key
        || intent.payload_sha256 != seed.payload_sha256
        || intent.payload_length != seed.payload_length
        || intent.target_binding.pool_id != seed.pool_id
        || intent.target_binding.member_id != seed.member_id
        || intent.target_binding.pool_store_id != source
        || seed.producer_scope
            != producer_scope(&source, &seed.pool_id, &seed.member_id, seed.final_notice)?
        || sdk_run != serde_json::to_value(&run_pin.route).map_err(|_| Fault::Internal)?
        || sdk_bridge != serde_json::to_value(&bridge_pin.route).map_err(|_| Fault::Internal)?
        || run_receipt_id.is_empty()
        || audience.is_empty()
    {
        return Err(Fault::Conflict);
    }
    Ok(Frozen {
        seed,
        text,
        intent,
        digest,
        run_pin,
        bridge_pin,
        audience,
        run_receipt_id,
    })
}

/// Record a safe pre-effect wait or an unresolved effect without changing its target.
pub(crate) fn attention(db: &mut Connection, effect_id: &str, reason: &str) -> Result<(), Fault> {
    if !matches!(
        reason,
        "awaiting_root_hook"
            | "relaunch_required"
            | "actor_relaunch_required"
            | "actor_unavailable"
            | "binding_unavailable"
            | "route_unavailable"
            | "origin_unavailable"
            | "outcome_unknown"
            | "qualification_pending"
            | "attempt_not_ready"
            | "capability_missing"
            | "native_uncertain"
            | "channel_failed"
            | "scope_retiring"
    ) {
        return Err(Fault::Invalid);
    }
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current = state(&tx, effect_id)?.ok_or(Fault::Unavailable)?;
    if matches!(
        current,
        State::Accepted | State::Aborted | State::NotDelivered
    ) {
        return Ok(());
    }
    let unknown = matches!(
        current,
        State::Publishing | State::Unknown | State::AbortPending
    );
    tx.execute("UPDATE managed_delivery_outbox SET state=CASE WHEN state='publishing' THEN 'unknown' ELSE state END,attention=?2 WHERE effect_id=?1",params![effect_id,reason])?;
    tx.execute(
        "UPDATE effects SET state=?2 WHERE id=?1",
        params![effect_id, if unknown { "unknown" } else { "custody" }],
    )?;
    tx.commit()?;
    Ok(())
}

/// Reserve exactly one dispatch before a possible Bridge write.
pub(crate) fn begin_publish(
    db: &mut Connection,
    effect_id: &str,
) -> Result<(Frozen, String), Fault> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current = state(&tx, effect_id)?.ok_or(Fault::Unavailable)?;
    if !matches!(current, State::Frozen | State::KnownUnsent) {
        return Err(Fault::Stale);
    }
    let frozen = frozen(&tx, effect_id)?;
    let scope_state: String = tx.query_row(
        "SELECT state FROM managed_delivery_scopes WHERE producer_scope=?1",
        [&frozen.seed.producer_scope],
        |r| r.get(0),
    )?;
    if !(scope_state == "open" || (frozen.seed.final_notice && scope_state == "draining")) {
        return Err(Fault::Stale);
    }
    let current_member: bool = tx.query_row(
        "SELECT current FROM members WHERE id=?1 AND pool=?2",
        params![frozen.seed.member_id, frozen.seed.pool_id],
        |r| r.get(0),
    )?;
    if current_member == frozen.seed.final_notice {
        return Err(Fault::Stale);
    }
    let dispatch = crate::domain::id();
    let changed=tx.execute("UPDATE managed_delivery_outbox SET state='publishing',dispatch_id=?2,attention=NULL WHERE effect_id=?1 AND state IN ('frozen','known_unsent')",params![effect_id,dispatch])?;
    if changed != 1 {
        return Err(Fault::Stale);
    }
    tx.execute(
        "UPDATE effects SET state='inflight' WHERE id=?1",
        [effect_id],
    )?;
    tx.commit()?;
    Ok((frozen, dispatch))
}

/// Before any abort I/O, install a local fence against delayed publication.
pub(crate) fn begin_abort(db: &mut Connection, effect_id: &str) -> Result<(Frozen, String), Fault> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current = state(&tx, effect_id)?.ok_or(Fault::Unavailable)?;
    if !matches!(
        current,
        State::Frozen
            | State::Publishing
            | State::KnownUnsent
            | State::Unknown
            | State::AbortPending
    ) {
        return Err(Fault::Stale);
    }
    let frozen = frozen(&tx, effect_id)?;
    let prior: Option<String> = tx.query_row(
        "SELECT abort_request_id FROM managed_delivery_outbox WHERE effect_id=?1",
        [effect_id],
        |row| row.get(0),
    )?;
    let abort_id = prior.unwrap_or_else(crate::domain::id);
    tx.execute("UPDATE managed_delivery_outbox SET state='abort_pending',abort_request_id=?2,attention=CASE WHEN EXISTS(SELECT 1 FROM managed_delivery_liveness WHERE effect_id=?1 AND aborting=1) THEN 'outcome_unknown' ELSE 'scope_retiring' END WHERE effect_id=?1 AND state IN ('frozen','publishing','known_unsent','unknown','abort_pending')",params![effect_id,abort_id])?;
    tx.execute(
        "UPDATE effects SET state='unknown' WHERE id=?1",
        [effect_id],
    )?;
    tx.commit()?;
    Ok((frozen, abort_id))
}

/// A verified pre-write transport refusal can retry only the identical frozen effect.
pub(crate) fn record_not_sent(
    db: &mut Connection,
    effect_id: &str,
    dispatch: &str,
    reason: &str,
) -> Result<(), Fault> {
    if !matches!(
        reason,
        "relaunch_required"
            | "capability_missing"
            | "route_unavailable"
            | "attempt_not_ready"
            | "qualification_pending"
    ) {
        return Err(Fault::Invalid);
    }
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (state, sent): (String, Option<String>) = tx.query_row(
        "SELECT state,dispatch_id FROM managed_delivery_outbox WHERE effect_id=?1",
        [effect_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if sent.as_deref() != Some(dispatch) {
        return Err(Fault::Conflict);
    }
    match state.as_str() {
        "publishing" => {
            tx.execute("UPDATE managed_delivery_outbox SET state='known_unsent',attention=?2 WHERE effect_id=?1",params![effect_id,reason])?;
            tx.execute(
                "UPDATE effects SET state='custody' WHERE id=?1",
                [effect_id],
            )?;
        }
        "abort_pending" => {}
        _ => return Err(Fault::Stale),
    }
    tx.commit()?;
    Ok(())
}

/// Record a correlated SDK receipt. Unknown/abort-pending never permits resend.
pub(crate) fn record_result(
    db: &mut Connection,
    effect_id: &str,
    dispatch: Option<&str>,
    result: &ManagedOwnerResultV1,
    aborting: bool,
) -> Result<State, Fault> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current = state(&tx, effect_id)?.ok_or(Fault::Unavailable)?;
    let frozen = frozen(&tx, effect_id)?;
    let sent: Option<String> = tx.query_row(
        "SELECT dispatch_id FROM managed_delivery_outbox WHERE effect_id=?1",
        [effect_id],
        |r| r.get(0),
    )?;
    if dispatch.is_some_and(|id| sent.as_deref() != Some(id))
        || result.version != 1
        || result.store_id != frozen.bridge_pin.route.component_store_id
        || result.producer != frozen.bridge_pin.producer
        || result.producer_scope != frozen.seed.producer_scope
        || result.effect_id != effect_id
        || result.effect_digest != frozen.digest
    {
        return Err(Fault::Conflict);
    }
    let target = bridge_sdk::bridge_protocol::NativeAddress::parse(
        &frozen.intent.target_binding.actor.address,
    )
    .map_err(|_| Fault::Invalid)?;
    let protocol = match target.harness.as_str() {
        "codex" => "codex_turn",
        "claude-code" => "claude_input",
        _ => return Err(Fault::Invalid),
    };
    let valid = match (
        result.state,
        result.protocol.as_deref(),
        result.native_id.as_deref(),
        result.reason.as_deref(),
    ) {
        (ManagedOwnerStateV1::Accepted, Some(actual), Some(native), None) => {
            actual == protocol
                && !native.is_empty()
                && native.len() <= 256
                && !native.chars().any(char::is_control)
        }
        (ManagedOwnerStateV1::KnownUnsent, None, None, Some(reason)) => {
            !aborting
                && matches!(
                    reason,
                    "capability_missing"
                        | "actor_mismatch"
                        | "not_idle"
                        | "awaiting_input"
                        | "finished"
                        | "budget"
                        | "cancelled"
                        | "unavailable"
                        | "invalid_request"
                        | "capacity"
                        | "conflict"
                        | "attempt_not_ready"
                        | "qualification_pending"
                )
        }
        (ManagedOwnerStateV1::Unknown, None, None, Some("native_uncertain" | "channel_failed")) => {
            true
        }
        (ManagedOwnerStateV1::Aborted, None, None, None) => true,
        _ => false,
    };
    if !valid {
        return Err(Fault::Conflict);
    }
    if matches!(current, State::Accepted | State::Aborted) {
        let prior: Option<String> = tx.query_row(
            "SELECT result FROM managed_delivery_outbox WHERE effect_id=?1",
            [effect_id],
            |row| row.get(0),
        )?;
        return if prior.as_deref() == Some(encode(result)?.as_str()) {
            Ok(current)
        } else {
            Err(Fault::Conflict)
        };
    }
    if current == State::NotDelivered {
        return Err(Fault::Stale);
    }
    if !matches!(
        current,
        State::Publishing | State::Unknown | State::AbortPending | State::KnownUnsent
    ) {
        return Err(Fault::Stale);
    }
    let (next, effect_state, attention) = match result.state {
        ManagedOwnerStateV1::Accepted => ("accepted", "accepted", None),
        ManagedOwnerStateV1::Aborted => ("aborted", "cancelled", None),
        ManagedOwnerStateV1::Unknown => (
            if current == State::AbortPending {
                "abort_pending"
            } else {
                "unknown"
            },
            "unknown",
            result.reason.as_deref(),
        ),
        ManagedOwnerStateV1::KnownUnsent if current == State::AbortPending => {
            ("abort_pending", "unknown", Some("scope_retiring"))
        }
        ManagedOwnerStateV1::KnownUnsent if current == State::Unknown => {
            ("unknown", "unknown", Some("outcome_unknown"))
        }
        ManagedOwnerStateV1::KnownUnsent => ("known_unsent", "custody", result.reason.as_deref()),
    };
    tx.execute(
        "UPDATE managed_delivery_outbox SET state=?2,result=?3,attention=?4 WHERE effect_id=?1",
        params![effect_id, next, encode(result)?, attention],
    )?;
    tx.execute(
        "UPDATE effects SET state=?2 WHERE id=?1",
        params![effect_id, effect_state],
    )?;
    tx.commit()?;
    State::parse(next)
}

/// The scope is derived only from the durable Pool store and exact membership.
pub(crate) fn producer_scope(
    store: &str,
    pool: &str,
    member: &str,
    final_notice: bool,
) -> Result<String, Fault> {
    if !uuid::Uuid::parse_str(store).is_ok_and(|id| id.to_string() == store)
        || identifier(pool).is_err()
        || identifier(member).is_err()
        || member == "final-notice"
    {
        return Err(Fault::Invalid);
    }
    let suffix = if final_notice { "final-notice" } else { member };
    let scope = format!("pool/{store}/{pool}/{suffix}");
    if scope.len() > 256 {
        return Err(Fault::Invalid);
    }
    Ok(scope)
}

/// Insert the immutable seed in the same transaction as the source event and effect.
pub(crate) fn insert_seed(
    db: &Connection,
    effect_id: &str,
    pool: &str,
    member: &str,
    event_id: u64,
    final_notice: bool,
) -> Result<(), Fault> {
    if db.is_autocommit() {
        return Err(Fault::Internal);
    }
    let event_id = i64::try_from(event_id).map_err(|_| Fault::Invalid)?;
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM events WHERE id=?1 AND pool=?2)",
        params![event_id, pool],
        |row| row.get(0),
    )?;
    if !exists {
        return Err(Fault::Conflict);
    }
    let raw: String = db.query_row("SELECT data FROM effects WHERE id=?1", [effect_id], |row| {
        row.get(0)
    })?;
    let effect: Effect = serde_json::from_str(&raw).map_err(|_| Fault::Internal)?;
    let Work::Deliver { text, .. } = effect.work else {
        return Err(Fault::Invalid);
    };
    if effect.pool_id != pool || effect.member_id.as_deref() != Some(member) {
        return Err(Fault::Conflict);
    }
    let source: String = db.query_row(
        "SELECT store_id FROM inventory_source WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    let scope = producer_scope(&source, pool, member, final_notice)?;
    require_capacity(db, ACTIVE_LIMIT)?;
    let owner = if final_notice { None } else { Some(member) };
    let existing: Option<(String, Option<String>, String)> = db
        .query_row(
            "SELECT pool_id,member_id,state FROM managed_delivery_scopes WHERE producer_scope=?1",
            [&scope],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    match existing {
        Some((old_pool, old_member, state))
            if old_pool == pool && old_member.as_deref() == owner && state == "open" => {}
        Some(_) => return Err(Fault::Stale),
        None => {
            let active: i64 = db.query_row(
                "SELECT count(*) FROM managed_delivery_scopes WHERE state!='compacted'",
                [],
                |row| row.get(0),
            )?;
            if active >= ACTIVE_LIMIT {
                return Err(Fault::Unavailable);
            }
            db.execute("INSERT INTO managed_delivery_scopes(producer_scope,pool_id,member_id,state,retire_request_id) VALUES(?1,?2,?3,'open',?4)",params![scope,pool,owner,crate::domain::id()])?;
        }
    }
    let hash = format!("{:x}", Sha256::digest(text.as_bytes()));
    // Empty means explicitly non-issuer owner/legacy origin; NULL is reserved
    // for migrated v10 seeds whose provenance was never recorded.
    let origin: Option<String> = db
        .query_row(
            "SELECT namespace_id FROM temp.managed_delivery_origin WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    db.execute("INSERT INTO managed_delivery_seeds(effect_id,pool_id,member_id,event_key,payload_sha256,payload_length,producer_scope,final_notice,issuer_namespace) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![effect_id,pool,member,format!("event/{event_id}"),hash,i64::try_from(text.len()).map_err(|_|Fault::Invalid)?,scope,i64::from(final_notice),origin.as_deref().unwrap_or("")])?;
    db.execute(
        "INSERT INTO managed_delivery_outbox(effect_id,state) VALUES(?1,'pending')",
        [effect_id],
    )?;
    Ok(())
}

/// A removed member can never create more ordinary effects under its old scope.
pub(crate) fn retire_member_scope(db: &Connection, pool: &str, member: &str) -> Result<(), Fault> {
    db.execute("UPDATE managed_delivery_scopes SET state='draining' WHERE pool_id=?1 AND member_id=?2 AND state='open'",params![pool,member])?;
    db.execute("UPDATE managed_current_requests SET state='aborted' WHERE state IN ('prepared','received') AND id IN (SELECT o.probe_request_id FROM managed_delivery_seeds s JOIN managed_delivery_outbox o ON o.effect_id=s.effect_id WHERE s.pool_id=?1 AND s.member_id=?2 AND s.final_notice=0 AND o.state='pending')",params![pool,member])?;
    db.execute("UPDATE managed_delivery_outbox SET state='not_delivered',attention='member_removed' WHERE effect_id IN (SELECT effect_id FROM managed_delivery_seeds WHERE pool_id=?1 AND member_id=?2 AND final_notice=0) AND state IN ('pending','frozen')",params![pool,member])?;
    db.execute("UPDATE effects SET state='cancelled' WHERE id IN (SELECT s.effect_id FROM managed_delivery_seeds s JOIN managed_delivery_outbox o ON o.effect_id=s.effect_id WHERE s.pool_id=?1 AND s.member_id=?2 AND s.final_notice=0 AND o.state='not_delivered') AND state NOT IN ('accepted','refused','cancelled')",params![pool,member])?;
    Ok(())
}

/// Closing a pool fences the dedicated, shared final-notice scope after enqueue.
pub(crate) fn retire_final_scope(db: &Connection, pool: &str) -> Result<(), Fault> {
    db.execute("UPDATE managed_delivery_scopes SET state='draining' WHERE pool_id=?1 AND member_id IS NULL AND state='open'",[pool])?;
    Ok(())
}

/// Rotate past draining scopes with unresolved effects; they cannot be retired yet.
pub(crate) fn pending_scopes(
    db: &Connection,
    after: i64,
) -> Result<Vec<(i64, String, String)>, Fault> {
    let mut statement=db.prepare("SELECT s.rowid,s.producer_scope,s.state FROM managed_delivery_scopes s WHERE s.rowid>?1 AND s.state IN ('draining','retiring','retired','compacting') AND NOT EXISTS(SELECT 1 FROM managed_delivery_seeds x JOIN managed_delivery_outbox o ON o.effect_id=x.effect_id WHERE x.producer_scope=s.producer_scope AND o.state NOT IN ('accepted','aborted','not_delivered')) ORDER BY s.rowid LIMIT 1")?;
    let rows = statement
        .query_map([after], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Pin the original audience and Bridge endpoint before scope retirement I/O.
pub(crate) fn prepare_scope(
    db: &mut Connection,
    scope: &str,
    pin: &BridgePin,
    audience: &str,
) -> Result<ScopePlan, Fault> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let source: String = tx.query_row(
        "SELECT store_id FROM inventory_source WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    let (pool,member,state,request,old_pin,old_audience):(String,Option<String>,String,String,Option<String>,Option<String>)=tx.query_row("SELECT pool_id,member_id,state,retire_request_id,bridge_pin,audience FROM managed_delivery_scopes WHERE producer_scope=?1",[scope],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)))?;
    let expected = if let Some(member) = member.as_deref() {
        producer_scope(&source, &pool, member, false)?
    } else {
        format!("pool/{source}/{pool}/final-notice")
    };
    if scope != expected
        || !matches!(
            state.as_str(),
            "draining" | "retiring" | "retired" | "compacting"
        )
        || audience.is_empty()
    {
        return Err(Fault::Stale);
    }
    let unsettled:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM managed_delivery_seeds s JOIN managed_delivery_outbox o ON o.effect_id=s.effect_id WHERE s.producer_scope=?1 AND o.state NOT IN ('accepted','aborted','not_delivered'))",[scope],|r|r.get(0))?;
    if unsettled {
        return Err(Fault::Unavailable);
    }
    if old_pin.is_some() != old_audience.is_some() {
        return Err(Fault::Conflict);
    }
    let (pin, audience) = match (old_pin, old_audience) {
        (Some(old_pin), Some(old_audience)) => (decode::<BridgePin>(&old_pin)?, old_audience),
        (None, None) if state == "draining" => {
            require_active_bridge(&tx, pin)?;
            (pin.clone(), audience.to_owned())
        }
        _ => return Err(Fault::Conflict),
    };
    let pin_json = encode(&pin)?;
    let needs_retire = matches!(state.as_str(), "draining" | "retiring");
    tx.execute("UPDATE managed_delivery_scopes SET state=?2,bridge_pin=?3,audience=?4 WHERE producer_scope=?1",params![scope,if needs_retire{"retiring"}else{"compacting"},pin_json,audience])?;
    tx.commit()?;
    Ok(ScopePlan {
        producer_scope: scope.into(),
        bridge_pin: pin,
        audience,
        retire_request_id: request,
        needs_retire,
    })
}

/// Record only the exact pinned Bridge retirement receipt; timeouts remain unresolved.
pub(crate) fn record_scope_retired(
    db: &mut Connection,
    plan: &ScopePlan,
    result: &RetireResult,
) -> Result<(), Fault> {
    let receipt = &result.receipt;
    if receipt.producer != plan.bridge_pin.producer
        || receipt.request_id != plan.retire_request_id
        || receipt.scope_key != plan.producer_scope
        || receipt.action != RetirementAction::RetireUnhanded
        || receipt.retired_at_ms == 0
    {
        return Err(Fault::Conflict);
    }
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (state,pin,audience,request,prior):(String,Option<String>,Option<String>,String,Option<String>)=tx.query_row("SELECT state,bridge_pin,audience,retire_request_id,retire_receipt FROM managed_delivery_scopes WHERE producer_scope=?1",[&plan.producer_scope],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
    let proof = encode(receipt)?;
    if !matches!(
        state.as_str(),
        "retiring" | "retired" | "compacting" | "compacted"
    ) || pin.as_deref() != Some(encode(&plan.bridge_pin)?.as_str())
        || audience.as_deref() != Some(&plan.audience)
        || request != plan.retire_request_id
        || prior.as_deref().is_some_and(|old| old != proof)
    {
        return Err(Fault::Conflict);
    }
    if state == "retiring" {
        tx.execute("UPDATE managed_delivery_scopes SET state='retired',retire_receipt=?2 WHERE producer_scope=?1",params![plan.producer_scope,proof])?;
    }
    tx.commit()?;
    Ok(())
}

/// Compaction is allowed only after the exact durable scope fence.
pub(crate) fn record_scope_compaction(
    db: &mut Connection,
    plan: &ScopePlan,
    result: &CompactManagedOwnerScopeResultV1,
) -> Result<(), Fault> {
    if result.version != 1
        || result.store_id != plan.bridge_pin.route.component_store_id
        || result.producer != plan.bridge_pin.producer
        || result.producer_scope != plan.producer_scope
    {
        return Err(Fault::Conflict);
    }
    let remaining = i64::try_from(result.remaining).map_err(|_| Fault::Unavailable)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (state,pin,audience,receipt):(String,Option<String>,Option<String>,Option<String>)=tx.query_row("SELECT state,bridge_pin,audience,retire_receipt FROM managed_delivery_scopes WHERE producer_scope=?1",[&plan.producer_scope],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
    if !matches!(state.as_str(), "retired" | "compacting")
        || pin.as_deref() != Some(encode(&plan.bridge_pin)?.as_str())
        || audience.as_deref() != Some(&plan.audience)
        || receipt.is_none()
    {
        return Err(Fault::Stale);
    }
    tx.execute("UPDATE managed_delivery_scopes SET state=?2,compact_result=?3,compact_remaining=?4 WHERE producer_scope=?1",params![plan.producer_scope,if remaining==0{"compacted"}else{"retired"},encode(result)?,remaining])?;
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "Isolated SQLite and fake custody fixtures"
)]
pub(crate) mod tests {
    use super::*;
    use crate::managed_state::{
        CurrentReceipt, Incarnation, SuccessorLink, SuccessorProof,
        tests::{fake_bridge_pin, fake_run_endpoint, fixture, index_managed_member},
    };
    use crate::store::Store;

    pub(crate) fn add_seed(
        store: &mut Store,
        binding: &ManagedBinding,
        id: &str,
        text: &str,
        final_notice: bool,
    ) -> i64 {
        let db = store.test_db();
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        tx.execute("INSERT INTO events(pool,data) VALUES('pool','{}')", [])
            .unwrap();
        let event = tx.last_insert_rowid();
        let effect = Effect {
            effect_id: id.into(),
            pool_id: binding.pool_id.clone(),
            member_id: Some(binding.member_id.clone()),
            work: Work::Deliver {
                address: binding.actor.address.clone(),
                scope: if final_notice {
                    "final:member".into()
                } else {
                    "agent-pool:member:member".into()
                },
                text: text.into(),
            },
            state: "inflight".into(),
        };
        tx.execute(
            "INSERT INTO effects(id,pool,member,state,data) VALUES(?1,?2,?3,'inflight',?4)",
            params![
                id,
                binding.pool_id,
                binding.member_id,
                encode(&effect).unwrap()
            ],
        )
        .unwrap();
        insert_seed(
            &tx,
            id,
            &binding.pool_id,
            &binding.member_id,
            u64::try_from(event).unwrap(),
            final_notice,
        )
        .unwrap();
        tx.commit().unwrap();
        event
    }
    pub(crate) fn pin(binding: &ManagedBinding) -> RunPin {
        let endpoint = fake_run_endpoint(binding);
        RunPin {
            route: endpoint.route,
            socket: endpoint.socket,
            executable: endpoint.executable,
            executable_sha256: endpoint.executable_sha256,
            capabilities: vec![
                "attempt_current_egress_v1".into(),
                "attempt_egress_actor_recovery_v1".into(),
            ],
        }
    }
    pub(crate) fn receipt(
        old: &ManagedBinding,
        incarnation: &Incarnation,
        next: &str,
        sequence: u32,
        id: &str,
    ) -> CurrentReceipt {
        let mut attempt = old.attempt.clone();
        attempt.execution_id = next.into();
        attempt.sequence = sequence;
        attempt.attempt_id = format!("attempt-{sequence}");
        attempt.launch_id = if sequence == 2 {
            "00000000-0000-4000-8000-000000000004"
        } else {
            "00000000-0000-4000-8000-000000000005"
        }
        .into();
        CurrentReceipt {
            receipt_id: id.into(),
            purpose: "egress".into(),
            lineage_root_id: old.attempt.lineage_root_id.clone(),
            bound_execution_id: old.attempt.execution_id.clone(),
            attempt,
            incarnation: incarnation.clone(),
            actor: old.actor.clone(),
            successor_proof: SuccessorProof {
                lineage_root_id: old.attempt.lineage_root_id.clone(),
                bound_execution_id: old.attempt.execution_id.clone(),
                current_execution_id: next.into(),
                chain: vec![
                    SuccessorLink {
                        execution_id: old.attempt.execution_id.clone(),
                        parent_execution_id: if old.attempt.sequence == 1 {
                            None
                        } else {
                            Some(old.attempt.lineage_root_id.clone())
                        },
                        sequence: old.attempt.sequence,
                    },
                    SuccessorLink {
                        execution_id: next.into(),
                        parent_execution_id: Some(old.attempt.execution_id.clone()),
                        sequence,
                    },
                ],
            },
        }
    }
    pub(crate) fn freeze_next(
        store: &mut Store,
        binding: &ManagedBinding,
        incarnation: &Incarnation,
        id: &str,
        next: &str,
        sequence: u32,
    ) -> Frozen {
        freeze_next_pin(
            store,
            binding,
            incarnation,
            id,
            next,
            sequence,
            &fake_bridge_pin(binding),
        )
    }
    fn freeze_next_pin(
        store: &mut Store,
        binding: &ManagedBinding,
        incarnation: &Incarnation,
        id: &str,
        next: &str,
        sequence: u32,
        bridge: &BridgePin,
    ) -> Frozen {
        let prefix = format!("pool/{}/", binding.pool_store_id);
        let target = store.egress_target(id, &prefix).unwrap();
        let run_pin = pin(&target.binding);
        let (request_id, run_pin, _) = store.egress_probe(&target, &run_pin).unwrap();
        let query = store
            .egress_stage(id, &run_pin, &target.binding.attempt, &request_id, "rpc")
            .unwrap();
        store.egress_probe_inflight(id, &request_id, true).unwrap();
        let authority = query
            .fixture_authority(receipt(
                &target.binding,
                incarnation,
                next,
                sequence,
                &format!("receipt-{id}"),
            ))
            .unwrap();
        store
            .egress_freeze(&target, &authority, &run_pin, bridge, "pool")
            .unwrap()
    }
    pub(crate) fn result(
        frozen: &Frozen,
        state: ManagedOwnerStateV1,
        reason: Option<&str>,
    ) -> ManagedOwnerResultV1 {
        ManagedOwnerResultV1 {
            version: 1,
            store_id: frozen.bridge_pin.route.component_store_id.clone(),
            producer: frozen.bridge_pin.producer.clone(),
            producer_scope: frozen.seed.producer_scope.clone(),
            effect_id: frozen.seed.effect_id.clone(),
            effect_digest: frozen.digest.clone(),
            state,
            protocol: if state == ManagedOwnerStateV1::Accepted {
                Some("codex_turn".into())
            } else {
                None
            },
            native_id: if state == ManagedOwnerStateV1::Accepted {
                Some("native-receipt".into())
            } else {
                None
            },
            reason: reason.map(str::to_owned),
        }
    }

    #[test]
    fn canonical_outbox_vector_matches_bridge_and_frozen_reference() {
        let value = serde_json::json!({"effect_id":"effect","producer_scope":"scope","event_key":"event","payload_sha256":"982d9e3eb996f559e633f4d194def3761d909f5a3b647d1a851fead67c32c9d1","payload_length":4,"target_binding":{"pool_store_id":"pool-store","pool_id":"pool","member_id":"member","binding_generation":1,"attempt":{"run_store_id":"store_run","lineage_root_id":"root","execution_id":"exec","sequence":1,"attempt_id":"attempt","launch_id":"01234567-89ab-4cde-8fab-0123456789ab"},"actor":{"address":"lab/codex/store/session","role":"root","native_id":"session","epoch":1},"run_route":{"component_store_id":"store_run","route_id":"run-route","worker_uid":1000},"bridge_route":{"component_store_id":"01234567-89ab-4cde-8fab-0123456789ab","route_id":"bridge-route","worker_uid":1000}},"expected_incarnation":{"host_id":"lab","boot_id":"01234567-89ab-4cde-8fab-0123456789ab","pid_namespace_inode":2,"uid":1000,"pid":42,"start_ticks":7},"bridge_route":{"component_store_id":"01234567-89ab-4cde-8fab-0123456789ab","route_id":"bridge-route","worker_uid":1000},"mode":"message","retention":"keep_all"});
        let intent: OutboxIntentV1 = serde_json::from_value(value.clone()).unwrap();
        let (length, local) =
            crate::managed_codec::digest(b"agent-mcp/attempt-binding/egress-intent/v1\0", &value)
                .unwrap();
        assert_eq!(length, 1436);
        assert_eq!(
            local,
            "72518e5ded118c2d5922aabd377f6f85fd4a906a6cd2775512daaadf7d77a6e9"
        );
        assert_eq!(egress_intent_digest(&intent).unwrap(), local);
    }

    #[test]
    fn dispatch_effect_identity_fences_inflight_accepted_and_changed_digest() {
        let (_directory, mut store, binding, incarnation, _run) = fixture();
        index_managed_member(store.test_db(), &binding);
        add_seed(&mut store, &binding, "identity-effect", "payload", false);
        let target = freeze_next(
            &mut store,
            &binding,
            &incarnation,
            "identity-effect",
            "next",
            2,
        );
        let (_, dispatch) = begin_publish(store.test_db(), "identity-effect").unwrap();
        assert!(matches!(
            begin_publish(store.test_db(), "identity-effect"),
            Err(Fault::Stale)
        ));
        let accepted = result(&target, ManagedOwnerStateV1::Accepted, None);
        let mut changed = accepted.clone();
        changed.effect_digest = "0".repeat(64);
        assert_eq!(
            record_result(
                store.test_db(),
                "identity-effect",
                Some(&dispatch),
                &changed,
                false
            )
            .err(),
            Some(Fault::Conflict)
        );
        assert_eq!(
            record_result(
                store.test_db(),
                "identity-effect",
                Some(&dispatch),
                &accepted,
                false
            )
            .unwrap(),
            State::Accepted
        );
        assert_eq!(
            record_result(
                store.test_db(),
                "identity-effect",
                Some(&dispatch),
                &accepted,
                false
            )
            .unwrap(),
            State::Accepted
        );
        assert!(matches!(
            begin_publish(store.test_db(), "identity-effect"),
            Err(Fault::Stale)
        ));
    }

    #[test]
    fn repin_never_retargets_a_frozen_egress_effect() {
        let (_directory, mut store, binding, incarnation, _run) = fixture();
        index_managed_member(store.test_db(), &binding);
        add_seed(&mut store, &binding, "repin-effect", "payload", false);
        let original = freeze_next(
            &mut store,
            &binding,
            &incarnation,
            "repin-effect",
            "next",
            2,
        );
        let mut bridge = fake_bridge_pin(&binding);
        bridge.server_sha256 = "c".repeat(64);
        bridge.credential_sha256 = "d".repeat(64);
        let mut run = fake_run_endpoint(&binding);
        run.executable_sha256 = "e".repeat(64);
        let pool_route = crate::managed_state::Route {
            component_store_id: binding.pool_store_id.clone(),
            route_id: "pool-route".into(),
            worker_uid: binding.run_route.worker_uid,
        };
        assert_eq!(
            store
                .managed_repin_routes(&bridge, &run, &pool_route, true)
                .unwrap(),
            (2, 2)
        );
        let retained = frozen(store.test_db(), "repin-effect").unwrap();
        assert!(retained.run_pin.endpoint() == original.run_pin.endpoint());
        assert!(retained.bridge_pin == original.bridge_pin);
        assert_eq!(retained.digest, original.digest);
        assert!(retained.intent.target_binding == original.intent.target_binding);
        let candidate = encode(&bridge).unwrap();
        assert!(
            store
                .test_db()
                .execute(
                    "UPDATE managed_delivery_outbox SET bridge_pin=?2 WHERE effect_id=?1",
                    params!["repin-effect", candidate]
                )
                .is_err()
        );
    }

    #[test]
    fn repin_allows_new_effects_and_retirement_for_used_member_and_final_scopes() {
        for final_notice in [false, true] {
            let (_directory, mut store, binding, incarnation, _run) = fixture();
            index_managed_member(store.test_db(), &binding);
            if final_notice {
                store
                    .test_db()
                    .execute("UPDATE members SET current=0 WHERE id='member'", [])
                    .unwrap();
            }
            add_seed(&mut store, &binding, "first-effect", "one", final_notice);
            let first = freeze_next(
                &mut store,
                &binding,
                &incarnation,
                "first-effect",
                "next",
                2,
            );
            let (_, dispatch) = begin_publish(store.test_db(), "first-effect").unwrap();
            record_result(
                store.test_db(),
                "first-effect",
                Some(&dispatch),
                &result(&first, ManagedOwnerStateV1::Accepted, None),
                false,
            )
            .unwrap();
            let mut bridge = fake_bridge_pin(&binding);
            bridge.server_sha256 = "c".repeat(64);
            bridge.credential_sha256 = "d".repeat(64);
            let run = fake_run_endpoint(&binding);
            let pool_route = crate::managed_state::Route {
                component_store_id: binding.pool_store_id.clone(),
                route_id: "pool-route".into(),
                worker_uid: binding.run_route.worker_uid,
            };
            store
                .managed_repin_routes(&bridge, &run, &pool_route, true)
                .unwrap();
            assert_eq!(
                require_active_bridge(store.test_db(), &first.bridge_pin),
                Err(Fault::Conflict)
            );
            add_seed(&mut store, &binding, "second-effect", "two", final_notice);
            let second = freeze_next_pin(
                &mut store,
                &binding,
                &incarnation,
                "second-effect",
                "next-2",
                3,
                &bridge,
            );
            let (_, dispatch) = begin_publish(store.test_db(), "second-effect").unwrap();
            record_result(
                store.test_db(),
                "second-effect",
                Some(&dispatch),
                &result(&second, ManagedOwnerStateV1::Accepted, None),
                false,
            )
            .unwrap();
            assert!(
                frozen(store.test_db(), "first-effect").unwrap().bridge_pin == first.bridge_pin
            );
            assert!(second.bridge_pin == bridge);
            if final_notice {
                retire_final_scope(store.test_db(), "pool").unwrap();
            } else {
                retire_member_scope(store.test_db(), "pool", "member").unwrap();
            }
            let plan = prepare_scope(store.test_db(), &first.seed.producer_scope, &bridge, "pool")
                .unwrap();
            assert!(plan.bridge_pin == bridge);
            let original_key = plan.retire_request_id.clone();
            let replay = prepare_scope(
                store.test_db(),
                &first.seed.producer_scope,
                &first.bridge_pin,
                "different",
            )
            .unwrap();
            assert!(replay.bridge_pin == bridge);
            assert_eq!(replay.audience, "pool");
            assert_eq!(replay.retire_request_id, original_key);
            let retire = RetireResult {
                receipt: bridge_sdk::bridge_protocol::RetireReceipt {
                    producer: plan.bridge_pin.producer.clone(),
                    request_id: original_key,
                    scope_key: plan.producer_scope.clone(),
                    action: RetirementAction::RetireUnhanded,
                    retired_at_ms: 1,
                    disposed: 0,
                    already_terminal: 2,
                    preserved_possible_effect: 0,
                    preserved_unhanded: 0,
                },
                replayed: false,
            };
            record_scope_retired(store.test_db(), &plan, &retire).unwrap();
        }
    }

    #[test]
    fn egress_freeze_rejects_generation_changed_after_its_rebind() {
        let (_directory, mut store, binding, incarnation, _run) = fixture();
        index_managed_member(store.test_db(), &binding);
        add_seed(&mut store, &binding, "race-effect", "payload", false);
        let prefix = format!("pool/{}/", binding.pool_store_id);
        let target = store.egress_target("race-effect", &prefix).unwrap();
        let run_pin = pin(&target.binding);
        let (request, run_pin, _) = store.egress_probe(&target, &run_pin).unwrap();
        let query = store
            .egress_stage(
                "race-effect",
                &run_pin,
                &target.binding.attempt,
                &request,
                "rpc",
            )
            .unwrap();
        store
            .egress_probe_inflight("race-effect", &request, true)
            .unwrap();
        let current = receipt(&target.binding, &incarnation, "next", 2, "race-receipt");
        let authority = query.fixture_authority(current.clone()).unwrap();
        crate::managed_state::record_current_receipt(store.test_db(), &request, &authority)
            .unwrap();
        let mut successor = target.binding.clone();
        successor.attempt = current.attempt.clone();
        successor.actor = current.actor.clone();
        let expected = crate::managed_state::rebind_authenticated(
            store.test_db(),
            &authority,
            &target.binding,
            &successor,
            &incarnation,
            "egress",
        )
        .unwrap();
        assert_eq!(expected, 2);
        let mut changed: ManagedBinding = decode(
            &store
                .test_db()
                .query_row::<String, _, _>(
                    "SELECT binding FROM managed_bindings WHERE member='member'",
                    [],
                    |row| row.get(0),
                )
                .unwrap(),
        )
        .unwrap();
        changed.binding_generation = 3;
        store
            .test_db()
            .execute(
                "UPDATE managed_bindings SET generation=?1,binding=?2 WHERE member='member'",
                params![3u64.to_be_bytes().as_slice(), encode(&changed).unwrap()],
            )
            .unwrap();
        assert_eq!(
            freeze(
                store.test_db(),
                &target,
                &authority,
                &run_pin,
                &fake_bridge_pin(&binding),
                "pool",
                expected
            )
            .err(),
            Some(Fault::Stale)
        );
        let state: (String, bool) = store.test_db().query_row(
            "SELECT state,target_binding IS NULL FROM managed_delivery_outbox WHERE effect_id='race-effect'", [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert_eq!(state, ("pending".into(), true));
    }

    #[test]
    fn p1_namespace_seal_does_not_block_or_change_p2_effects() {
        let (_directory, mut store, binding, incarnation, _run) = fixture();
        index_managed_member(store.test_db(), &binding);
        add_seed(&mut store, &binding, "inflight-effect", "first", false);
        let first = freeze_next(
            &mut store,
            &binding,
            &incarnation,
            "inflight-effect",
            "next",
            2,
        );
        let (_, dispatch) = begin_publish(store.test_db(), "inflight-effect").unwrap();
        add_seed(&mut store, &binding, "independent-effect", "second", false);
        let sealed = crate::managed_state::seal_namespace(
            store.test_db(),
            &binding.bridge_route,
            "pool",
            "old-issuer",
            "seal",
            "retire",
        )
        .unwrap();
        assert!(sealed.sealed);
        assert_eq!(
            state(store.test_db(), "inflight-effect").unwrap(),
            Some(State::Publishing)
        );
        assert_eq!(
            frozen(store.test_db(), "inflight-effect").unwrap().digest,
            first.digest
        );
        let second = freeze_next(
            &mut store,
            &binding,
            &incarnation,
            "independent-effect",
            "next-2",
            3,
        );
        let (_, second_dispatch) = begin_publish(store.test_db(), "independent-effect").unwrap();
        assert!(
            crate::managed_state::seal_namespace(
                store.test_db(),
                &binding.bridge_route,
                "pool",
                "old-issuer",
                "seal",
                "retire",
            )
            .unwrap()
            .sealed
        );
        let accepted = result(&first, ManagedOwnerStateV1::Accepted, None);
        assert_eq!(
            record_result(
                store.test_db(),
                "inflight-effect",
                Some(&dispatch),
                &accepted,
                false
            )
            .unwrap(),
            State::Accepted
        );
        let accepted = result(&second, ManagedOwnerStateV1::Accepted, None);
        assert_eq!(
            record_result(
                store.test_db(),
                "independent-effect",
                Some(&second_dispatch),
                &accepted,
                false
            )
            .unwrap(),
            State::Accepted
        );
    }

    #[test]
    fn egress_after_resume_without_ingress_unknown_never_resends_or_blocks_rebind() {
        let (directory, mut store, binding, incarnation, _run) = fixture();
        index_managed_member(store.test_db(), &binding);
        let event = add_seed(&mut store, &binding, "effect-1", "hello", false);
        let first_target = freeze_next(&mut store, &binding, &incarnation, "effect-1", "next", 2);
        assert_eq!(first_target.seed.event_key, format!("event/{event}"));
        assert_eq!(
            first_target.intent.target_binding.attempt.execution_id,
            "next"
        );
        assert_eq!(first_target.intent.target_binding.binding_generation, 2);
        assert_eq!(
            store
                .test_db()
                .query_row::<i64, _, _>("SELECT count(*) FROM managed_contexts", [], |row| row
                    .get(0))
                .unwrap(),
            0
        );
        assert!(
            store
                .test_db()
                .execute(
                    "UPDATE managed_delivery_outbox SET effect_digest=?2 WHERE effect_id=?1",
                    params!["effect-1", "0".repeat(64)]
                )
                .is_err()
        );
        let (_, first) = begin_publish(store.test_db(), "effect-1").unwrap();
        let unsent = result(
            &first_target,
            ManagedOwnerStateV1::KnownUnsent,
            Some("qualification_pending"),
        );
        assert_eq!(
            record_result(store.test_db(), "effect-1", Some(&first), &unsent, false).unwrap(),
            State::KnownUnsent
        );
        let (same, second) = begin_publish(store.test_db(), "effect-1").unwrap();
        assert_ne!(first, second);
        assert_eq!(same.digest, first_target.digest);
        assert_eq!(same.intent, first_target.intent);
        let unknown = result(
            &first_target,
            ManagedOwnerStateV1::Unknown,
            Some("native_uncertain"),
        );
        assert_eq!(
            record_result(store.test_db(), "effect-1", Some(&second), &unknown, false).unwrap(),
            State::Unknown
        );
        assert_eq!(
            record_result(store.test_db(), "effect-1", Some(&second), &unsent, false).unwrap(),
            State::Unknown
        );
        assert!(matches!(
            begin_publish(store.test_db(), "effect-1"),
            Err(Fault::Stale)
        ));
        let path = directory.path().join("pool.db");
        drop(store);
        let mut store = Store::open(&path).unwrap();
        let recovered = frozen(store.test_db(), "effect-1").unwrap();
        assert_eq!(recovered.digest, first_target.digest);
        assert_eq!(
            state(store.test_db(), "effect-1").unwrap(),
            Some(State::Unknown)
        );
        add_seed(&mut store, &binding, "effect-2", "new owner message", false);
        let later = freeze_next(&mut store, &binding, &incarnation, "effect-2", "next-2", 3);
        assert_eq!(later.intent.target_binding.attempt.execution_id, "next-2");
        assert_eq!(
            state(store.test_db(), "effect-1").unwrap(),
            Some(State::Unknown)
        );
        retire_member_scope(store.test_db(), "pool", "member").unwrap();
        assert!(pending_scopes(store.test_db(), 0).unwrap().is_empty());
        let (_, abort_id) = begin_abort(store.test_db(), "effect-1").unwrap();
        assert_eq!(
            begin_abort(store.test_db(), "effect-1").unwrap().1,
            abort_id
        );
        let aborted = result(&first_target, ManagedOwnerStateV1::Aborted, None);
        assert_eq!(
            record_result(store.test_db(), "effect-1", None, &aborted, true).unwrap(),
            State::Aborted
        );
        assert_eq!(
            record_result(store.test_db(), "effect-1", None, &aborted, true).unwrap(),
            State::Aborted
        );
        let late = result(&first_target, ManagedOwnerStateV1::Accepted, None);
        assert_eq!(
            record_result(store.test_db(), "effect-1", Some(&second), &late, false).err(),
            Some(Fault::Conflict)
        );
        assert!(matches!(
            begin_publish(store.test_db(), "effect-1"),
            Err(Fault::Stale)
        ));
        assert_eq!(
            state(store.test_db(), "effect-2").unwrap(),
            Some(State::NotDelivered)
        );
        assert_eq!(pending_scopes(store.test_db(), 0).unwrap().len(), 1);
    }

    #[test]
    fn crash_after_publish_claim_recovers_as_unknown() {
        let (directory, mut store, binding, incarnation, _run) = fixture();
        index_managed_member(store.test_db(), &binding);
        add_seed(&mut store, &binding, "effect-1", "hello", false);
        let first_target = freeze_next(&mut store, &binding, &incarnation, "effect-1", "next", 2);
        begin_publish(store.test_db(), "effect-1").unwrap();
        let path = directory.path().join("pool.db");
        drop(store);
        let mut store = Store::open(&path).unwrap();
        assert_eq!(
            state(store.test_db(), "effect-1").unwrap(),
            Some(State::Unknown)
        );
        assert_eq!(
            frozen(store.test_db(), "effect-1").unwrap().digest,
            first_target.digest
        );
        assert!(matches!(
            begin_publish(store.test_db(), "effect-1"),
            Err(Fault::Stale)
        ));
    }

    #[test]
    fn egress_currentness_probe_survives_restart_and_rotates_after_stale() {
        let (directory, mut store, binding, _incarnation, _run) = fixture();
        index_managed_member(store.test_db(), &binding);
        add_seed(&mut store, &binding, "probe-effect", "hello", false);
        let prefix = format!("pool/{}/", binding.pool_store_id);
        let target = store.egress_target("probe-effect", &prefix).unwrap();
        let run = pin(&target.binding);
        let (request, saved_pin, uncertain) = store.egress_probe(&target, &run).unwrap();
        assert!(!uncertain);
        store
            .egress_stage(
                "probe-effect",
                &saved_pin,
                &target.binding.attempt,
                &request,
                "rpc",
            )
            .unwrap();
        store
            .egress_probe_inflight("probe-effect", &request, true)
            .unwrap();
        let path = directory.path().join("pool.db");
        drop(store);
        let mut store = Store::open(&path).unwrap();
        let state: String = store
            .test_db()
            .query_row(
                "SELECT state FROM managed_current_requests WHERE id=?1",
                [&request],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "prepared");
        let target = store.egress_target("probe-effect", &prefix).unwrap();
        let (same, saved_pin, uncertain) = store.egress_probe(&target, &run).unwrap();
        assert_eq!(same, request);
        assert!(uncertain);
        store
            .egress_stage(
                "probe-effect",
                &saved_pin,
                &target.binding.attempt,
                &same,
                "rpc2",
            )
            .unwrap();
        store.egress_reset_probe("probe-effect", &request).unwrap();
        let (fresh, _, uncertain) = store.egress_probe(&target, &run).unwrap();
        assert_ne!(fresh, request);
        assert!(!uncertain);
        let state: String = store
            .test_db()
            .query_row(
                "SELECT state FROM managed_current_requests WHERE id=?1",
                [&request],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(state, "aborted");
    }

    #[test]
    fn final_notice_rebinds_only_removed_members_original_lineage_without_access() {
        let (_directory, mut store, binding, incarnation, _run) = fixture();
        index_managed_member(store.test_db(), &binding);
        store
            .test_db()
            .execute("UPDATE members SET current=0 WHERE id='member'", [])
            .unwrap();
        add_seed(&mut store, &binding, "final-effect", "final notice", true);
        let final_target = freeze_next(
            &mut store,
            &binding,
            &incarnation,
            "final-effect",
            "next",
            2,
        );
        assert_eq!(
            final_target.intent.target_binding.attempt.lineage_root_id,
            binding.attempt.lineage_root_id
        );
        assert_eq!(
            final_target.intent.target_binding.attempt.execution_id,
            "next"
        );
        assert_eq!(
            final_target.seed.producer_scope,
            format!("pool/{}/pool/final-notice", binding.pool_store_id)
        );
        let actor = crate::domain::Actor::verified(
            binding.actor.address.clone(),
            &binding.actor.native_id,
            "root",
        )
        .unwrap();
        let get = crate::domain::Command::Get(crate::domain::Get {
            pool_id: "pool".into(),
            after: 0,
            section: crate::domain::Section::Overview,
            proposal_id: None,
            member_id: None,
            wait_seconds: 0.0,
            reverse: false,
            before: None,
            field: None,
            expected_revision: None,
        });
        assert!(matches!(store.execute(&actor, &get), Err(Fault::Forbidden)));
    }

    #[test]
    fn scope_retirement_waits_for_effects_and_compacts_only_after_exact_fence() {
        let (_directory, mut store, binding, incarnation, _run) = fixture();
        index_managed_member(store.test_db(), &binding);
        add_seed(&mut store, &binding, "effect-1", "hello", false);
        let original = freeze_next(&mut store, &binding, &incarnation, "effect-1", "next", 2);
        let (_, dispatch) = begin_publish(store.test_db(), "effect-1").unwrap();
        let unknown = result(
            &original,
            ManagedOwnerStateV1::Unknown,
            Some("channel_failed"),
        );
        record_result(
            store.test_db(),
            "effect-1",
            Some(&dispatch),
            &unknown,
            false,
        )
        .unwrap();
        retire_member_scope(store.test_db(), "pool", "member").unwrap();
        assert!(pending_scopes(store.test_db(), 0).unwrap().is_empty());
        assert!(matches!(
            prepare_scope(
                store.test_db(),
                &original.seed.producer_scope,
                &original.bridge_pin,
                "pool"
            ),
            Err(Fault::Unavailable)
        ));
        let (_, abort_id) = begin_abort(store.test_db(), "effect-1").unwrap();
        let aborted = result(&original, ManagedOwnerStateV1::Aborted, None);
        record_result(store.test_db(), "effect-1", None, &aborted, true).unwrap();
        assert!(!abort_id.is_empty());
        let plan = prepare_scope(
            store.test_db(),
            &original.seed.producer_scope,
            &original.bridge_pin,
            "pool",
        )
        .unwrap();
        assert!(plan.needs_retire);
        let retire = RetireResult {
            receipt: bridge_sdk::bridge_protocol::RetireReceipt {
                producer: plan.bridge_pin.producer.clone(),
                request_id: plan.retire_request_id.clone(),
                scope_key: plan.producer_scope.clone(),
                action: RetirementAction::RetireUnhanded,
                retired_at_ms: 1,
                disposed: 0,
                already_terminal: 1,
                preserved_possible_effect: 0,
                preserved_unhanded: 0,
            },
            replayed: false,
        };
        record_scope_retired(store.test_db(), &plan, &retire).unwrap();
        let mut replay = retire.clone();
        replay.replayed = true;
        record_scope_retired(store.test_db(), &plan, &replay).unwrap();
        let compact_plan = prepare_scope(
            store.test_db(),
            &plan.producer_scope,
            &plan.bridge_pin,
            "pool",
        )
        .unwrap();
        assert!(!compact_plan.needs_retire);
        let mut compact = CompactManagedOwnerScopeResultV1 {
            version: 1,
            store_id: plan.bridge_pin.route.component_store_id.clone(),
            producer: plan.bridge_pin.producer.clone(),
            producer_scope: plan.producer_scope.clone(),
            compacted: 1,
            remaining: 1,
        };
        record_scope_compaction(store.test_db(), &compact_plan, &compact).unwrap();
        assert_eq!(
            store
                .test_db()
                .query_row::<String, _, _>(
                    "SELECT state FROM managed_delivery_scopes WHERE producer_scope=?1",
                    [&plan.producer_scope],
                    |r| r.get(0)
                )
                .unwrap(),
            "retired"
        );
        let again = prepare_scope(
            store.test_db(),
            &plan.producer_scope,
            &plan.bridge_pin,
            "pool",
        )
        .unwrap();
        compact.remaining = 0;
        record_scope_compaction(store.test_db(), &again, &compact).unwrap();
        assert_eq!(
            store
                .test_db()
                .query_row::<String, _, _>(
                    "SELECT state FROM managed_delivery_scopes WHERE producer_scope=?1",
                    [&plan.producer_scope],
                    |r| r.get(0)
                )
                .unwrap(),
            "compacted"
        );
    }

    #[test]
    fn egress_capacity_counts_active_and_retains_terminal_fences() {
        let (_directory, mut store, binding, _incarnation, _run) = fixture();
        index_managed_member(store.test_db(), &binding);
        add_seed(&mut store, &binding, "effect-1", "hello", false);
        assert!(matches!(
            target(store.test_db(), "effect-1", "pool/other/"),
            Err(Fault::Conflict)
        ));
        assert_eq!(
            require_capacity(store.test_db(), 1).err(),
            Some(Fault::Unavailable)
        );
        mark_not_delivered(store.test_db(), "effect-1", "member_removed").unwrap();
        assert!(require_capacity(store.test_db(), 1).is_ok());
        assert_eq!(
            store
                .test_db()
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM managed_delivery_seeds WHERE effect_id='effect-1'",
                    [],
                    |row| row.get(0)
                )
                .unwrap(),
            1
        );
    }
}
