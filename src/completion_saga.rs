//! Automatic resident completion settlement (owner decision C1).
//!
//! The serial resident worker drives each durable saga
//! `prepared -> acquire_possible -> held -> committed|aborted -> release_pending -> released`
//! one awaited step at a time. Every Run exchange happens outside SQLite and
//! after the preceding stage is durable, so a crash or lost acknowledgement is
//! recovered from the original stage with the original request ID, fingerprint
//! and key: never a second hold, a TTL unlock or a regenerated key. Owner
//! reads and observers never reach this module.
use crate::{
    completion::{self, Saga, Stage, TargetFacts},
    completion_key::KeyStore,
    config::Config,
    domain::{Fault, RunRoute},
    managed_state::{RunAuthority, VerifiedBallot, VoterObservation, VoterState},
    run_hold::{
        AcquireResult, HoldError, HoldIntent, HoldObservation, HoldState, LookupResult,
        ReleaseResult,
    },
    run_status::{ProofProjection, Target},
    store::Store,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

type SharedStore = Arc<Mutex<Store>>;
/// Sagas advanced per worker cycle; recovery rotates past blocked rows.
const SAGAS_PER_TICK: u32 = 8;
/// New settlement candidates examined per worker cycle.
const CANDIDATES_PER_TICK: u32 = 2;
/// Minimum delay before a not-yet-eligible pool is examined again.
const CANDIDATE_BACKOFF: Duration = Duration::from_secs(30);
const RETRY_CEILING: Duration = Duration::from_secs(300);
/// Uncertain held-stage reads tolerated before the saga is aborted and released.
const HELD_FAILURE_LIMIT: i64 = 3;
/// Bounded local progress per saga per cycle.
const STEPS_PER_SAGA: usize = 8;

/// Runs one bounded store step on the blocking pool; no guard survives an await.
async fn stored<T, F>(store: &SharedStore, operation: F) -> Result<T, Fault>
where
    T: Send + 'static,
    F: FnOnce(&mut Store) -> Result<T, Fault> + Send + 'static,
{
    let store = Arc::clone(store);
    tokio::task::spawn_blocking(move || {
        let mut guard = store.lock().map_err(|_| Fault::Internal)?;
        operation(&mut guard)
    })
    .await
    .map_err(|_| Fault::Internal)?
}

/// One validated Run status item: historical facts plus the proven lineage tip.
pub(crate) struct StatusFact {
    pub projection: ProofProjection,
    pub latest: Option<Target>,
}

/// Every Run interaction used by settlement. The production adapter reuses
/// the unchanged hold v1 client, status reader and managed consensus reader.
pub(crate) trait SettlementRun {
    /// The configured Run operator route, without a store identity.
    fn configured_route(&self) -> Result<RunRoute, Fault>;
    /// Fresh consensus for each exact voter, in order; failures stay per voter.
    async fn consensus(
        &self,
        store: &SharedStore,
        voters: &[VerifiedBallot],
    ) -> Vec<Result<VoterObservation, Fault>>;
    /// One store-fenced status snapshot and its observation time as decimal text.
    async fn status(
        &self,
        store_id: &str,
        targets: &[Target],
    ) -> Result<(String, Vec<StatusFact>), Fault>;
    /// Exact v1 hold method discovery for the expected store.
    async fn discover(&self, store_id: &str) -> Result<(), HoldError>;
    /// Original-key acquire or exact replay.
    async fn acquire(
        &self,
        intent: &HoldIntent,
        prior: Option<&HoldObservation>,
    ) -> Result<AcquireResult, HoldError>;
    /// Original-key lookup; absence is only a snapshot.
    async fn lookup(
        &self,
        intent: &HoldIntent,
        prior: Option<&HoldObservation>,
    ) -> Result<LookupResult, HoldError>;
    /// Signed release of the same hold.
    async fn release(
        &self,
        intent: &HoldIntent,
        prior: &HoldObservation,
        signature: &[u8; 64],
    ) -> Result<ReleaseResult, HoldError>;
}

/// Production adapter over the configured Run routes.
pub(crate) struct ConfiguredRun {
    config: Config,
}
impl ConfiguredRun {
    pub(crate) fn new(config: Config) -> Self {
        Self { config }
    }
    /// Stages, performs and retires one fresh consensus read for one voter.
    async fn consensus_one(
        &self,
        store: &SharedStore,
        voter: &VerifiedBallot,
    ) -> Result<VoterObservation, Fault> {
        let peer =
            crate::managed_run::RunPeer::from_config(&self.config, &voter.binding.pool_store_id)
                .map_err(|_| Fault::Unavailable)?;
        if peer.route != voter.binding.run_route {
            return Err(Fault::Unavailable);
        }
        let endpoint = peer.endpoint_pin();
        stored(store, move |store| store.managed_require_run_pin(&endpoint)).await?;
        let pin = peer
            .current_pin("attempt_consensus_v1")
            .await
            .map_err(|_| Fault::Unavailable)?;
        let request_id = crate::domain::id();
        let transport_id = crate::domain::id();
        let query =
            crate::managed_run::VoterQuery::read_only(&pin, voter, &request_id, &transport_id)?;
        let authority = peer.collect_voters(&[query]).await;
        authority.map_err(|_| Fault::Unavailable)?.consensus(
            &voter.binding.run_route,
            &voter.attempt,
            &voter.incarnation,
        )
    }
}
impl SettlementRun for ConfiguredRun {
    fn configured_route(&self) -> Result<RunRoute, Fault> {
        let socket = self
            .config
            .run_socket
            .as_ref()
            .and_then(|path| path.to_str())
            .ok_or(Fault::Unavailable)?;
        Ok(RunRoute {
            socket: socket.to_owned(),
            expected_uid: self.config.expected_uid,
            peer_uid: self.config.run_peer_uid,
            store_id: None,
        })
    }
    async fn consensus(
        &self,
        store: &SharedStore,
        voters: &[VerifiedBallot],
    ) -> Vec<Result<VoterObservation, Fault>> {
        let mut results = Vec::with_capacity(voters.len());
        for voter in voters {
            results.push(self.consensus_one(store, voter).await);
        }
        results
    }
    async fn status(
        &self,
        store_id: &str,
        targets: &[Target],
    ) -> Result<(String, Vec<StatusFact>), Fault> {
        let evidence = crate::integrations::run_status(&self.config, store_id, targets)
            .await
            .map_err(|_| Fault::Unavailable)?;
        let facts = evidence
            .items()
            .map(|item| StatusFact {
                projection: item.projection(),
                latest: item.replacement_precondition(),
            })
            .collect();
        Ok((evidence.observed_at_text().to_owned(), facts))
    }
    async fn discover(&self, store_id: &str) -> Result<(), HoldError> {
        crate::run_hold::discover(&self.config, store_id).await
    }
    async fn acquire(
        &self,
        intent: &HoldIntent,
        prior: Option<&HoldObservation>,
    ) -> Result<AcquireResult, HoldError> {
        crate::run_hold::acquire(&self.config, intent, prior).await
    }
    async fn lookup(
        &self,
        intent: &HoldIntent,
        prior: Option<&HoldObservation>,
    ) -> Result<LookupResult, HoldError> {
        crate::run_hold::lookup(&self.config, intent, prior).await
    }
    async fn release(
        &self,
        intent: &HoldIntent,
        prior: &HoldObservation,
        signature: &[u8; 64],
    ) -> Result<ReleaseResult, HoldError> {
        crate::run_hold::release(&self.config, intent, prior, signature).await
    }
}

/// Whether one saga step changed durable state and may be followed immediately.
pub(crate) enum Step {
    Progress,
    Idle,
}

fn now_ms() -> u64 {
    crate::observer::now().unwrap_or(0)
}

/// Serial settlement driver owned by the resident worker.
pub(crate) struct Driver<R> {
    run: R,
    keys: KeyStore,
    saga_cursor: String,
    pool_cursor: String,
    backoff: HashMap<String, ((String, i64), u32, Instant)>,
    saga_backoff: HashMap<String, Instant>,
}

fn retry_delay(base: Duration, failures: u32) -> Duration {
    base.saturating_mul(1_u32 << failures.saturating_sub(1).min(16))
        .min(RETRY_CEILING)
}

impl Driver<ConfiguredRun> {
    /// Enabled only with a configured Run operator socket and managed consensus
    /// transport; otherwise settlement stays off and pools remain open.
    pub(crate) fn production(config: &Config) -> Option<Self> {
        if config.run_socket.is_none() || config.managed_run_transport.is_none() {
            return None;
        }
        let keys = KeyStore::open(&config.database_path, config.expected_uid).ok()?;
        Some(Self::new(ConfiguredRun::new(config.clone()), keys))
    }

    pub(crate) fn unavailable_reason(config: &Config) -> &'static str {
        if config.run_socket.is_none() || config.managed_run_transport.is_none() {
            "route_changed"
        } else {
            "key_unavailable"
        }
    }
}

impl<R: SettlementRun> Driver<R> {
    pub(crate) async fn sweep(&self, store: &SharedStore) -> Result<(), Fault> {
        let references = stored(store, |store| {
            completion::retained_keys(store.completion_db())
        })
        .await?;
        self.keys.sweep(&references)
    }
    pub(crate) fn new(run: R, keys: KeyStore) -> Self {
        Self {
            run,
            keys,
            saga_cursor: String::new(),
            pool_cursor: String::new(),
            backoff: HashMap::new(),
            saga_backoff: HashMap::new(),
        }
    }

    /// One bounded cycle: recover existing sagas first, then consider new candidates.
    pub(crate) async fn tick(
        &mut self,
        store: &SharedStore,
        stopped: &tokio::sync::watch::Receiver<bool>,
    ) -> Result<(), Fault> {
        let after = self.saga_cursor.clone();
        let mut sagas = stored(store, move |store| {
            completion::pending(store.completion_db(), &after, SAGAS_PER_TICK)
        })
        .await?;
        if sagas.is_empty() && !self.saga_cursor.is_empty() {
            sagas = stored(store, |store| {
                completion::pending(store.completion_db(), "", SAGAS_PER_TICK)
            })
            .await?;
        }
        self.saga_cursor = sagas.last().cloned().unwrap_or_default();
        for saga in sagas {
            if *stopped.borrow() {
                return Ok(());
            }
            if self
                .saga_backoff
                .get(&saga)
                .is_some_and(|until| Instant::now() < *until)
            {
                continue;
            }
            if self.advance(store, &saga).await.is_err() {
                eprintln!("completion saga advance failed; recovery will retry");
                self.attention(store, &saga, "internal_error").await?;
            }
            let id = saga.clone();
            let failures: i64 = stored(store, move |store| {
                Ok(store.completion_db().query_row(
                    "SELECT failures FROM completion_sagas WHERE id=?1",
                    [id],
                    |row| row.get(0),
                )?)
            })
            .await?;
            if failures > 0 {
                self.saga_backoff.insert(
                    saga,
                    Instant::now()
                        + retry_delay(
                            Duration::from_secs(5),
                            u32::try_from(failures).unwrap_or(u32::MAX),
                        ),
                );
            } else {
                self.saga_backoff.remove(&saga);
            }
        }
        let after = self.pool_cursor.clone();
        let pools = stored(store, move |store| {
            completion::candidates(store.completion_db(), &after, CANDIDATES_PER_TICK)
        })
        .await?;
        self.pool_cursor = pools.last().cloned().unwrap_or_default();
        for pool in pools {
            if *stopped.borrow() {
                return Ok(());
            }
            let id = pool.clone();
            let version = stored(store, move |store| {
                completion::candidate_version(store.completion_db(), &id)
            })
            .await?;
            if self
                .backoff
                .get(&pool)
                .is_some_and(|(old, _, until)| *old == version && Instant::now() < *until)
            {
                continue;
            }
            if let Ok(Some(saga)) = self.start(store, &pool).await {
                self.backoff.remove(&pool);
                if self.advance(store, &saga).await.is_err() {
                    eprintln!("completion saga advance failed; recovery will retry");
                    self.attention(store, &saga, "internal_error").await?;
                    self.saga_backoff
                        .insert(saga, Instant::now() + Duration::from_secs(5));
                }
            } else {
                let attempts = self
                    .backoff
                    .get(&pool)
                    .filter(|(old, _, _)| *old == version)
                    .map_or(1, |(_, attempts, _)| attempts.saturating_add(1));
                self.backoff.insert(
                    pool,
                    (
                        version,
                        attempts,
                        Instant::now() + retry_delay(CANDIDATE_BACKOFF, attempts),
                    ),
                );
            }
        }
        Ok(())
    }

    /// Verifies eligibility, fresh voter currentness and Run facts with reads
    /// only, then creates the key durably and prepares the saga. No hold yet.
    pub(crate) async fn start(
        &mut self,
        store: &SharedStore,
        pool_id: &str,
    ) -> Result<Option<String>, Fault> {
        let pool = pool_id.to_owned();
        let Some(candidate) = stored(store, move |store| {
            completion::snapshot(store.completion_db(), &pool)
        })
        .await?
        else {
            return Ok(None);
        };
        let mut route = self.run.configured_route()?;
        let run_store_id = candidate.voters[0].run_store_id.clone();
        route.store_id = Some(run_store_id.clone());
        let ballots: Vec<VerifiedBallot> = candidate
            .voters
            .iter()
            .map(|voter| voter.ballot.clone())
            .collect();
        let observations = self.run.consensus(store, &ballots).await;
        if observations.len() != ballots.len() {
            return Ok(None);
        }
        for (result, voter) in observations.iter().zip(&ballots) {
            match result {
                Ok(observation)
                    if observation.state == VoterState::TerminalNoSuccessor
                        && observation.last_attempt.as_ref() == Some(&voter.attempt)
                        && observation.last_incarnation.as_ref() == Some(&voter.incarnation) => {}
                _ => return Ok(None),
            }
        }
        let selectors: Vec<Target> = candidate
            .voters
            .iter()
            .map(|voter| voter.selector.clone())
            .collect();
        let (_, facts) = self.run.status(&run_store_id, &selectors).await?;
        if facts.len() != selectors.len() {
            return Ok(None);
        }
        let mut targets = Vec::with_capacity(facts.len());
        for ((fact, selector), voter) in facts.iter().zip(&selectors).zip(&candidate.voters) {
            let Some(latest) = fact.latest.clone() else {
                return Ok(None);
            };
            if fact.projection.selector() != selector
                || latest.pin_id != selector.pin_id
                || latest.agent_id != voter.ballot.attempt.lineage_root_id
                || latest.sequence != voter.ballot.attempt.sequence
            {
                return Ok(None);
            }
            targets.push(latest);
        }
        if targets != selectors {
            let (_, latest) = self.run.status(&run_store_id, &targets).await?;
            if latest.len() != targets.len()
                || latest.iter().zip(&targets).any(|(fact, target)| {
                    fact.projection.selector() != target || !fact.projection.historical_success
                })
            {
                return Ok(None);
            }
        } else if facts.iter().any(|fact| !fact.projection.historical_success) {
            return Ok(None);
        }
        // The key reference is independent of the public saga and hold request IDs.
        let saga_id = crate::domain::id();
        let key_ref = crate::domain::id();
        let public = self.keys.create(&key_ref)?;
        let pool = pool_id.to_owned();
        let digest = candidate.frozen_digest.clone();
        let id = saga_id.clone();
        let reference = key_ref.clone();
        let prepared = stored(store, move |store| {
            completion::prepare(
                store.completion_db(),
                &id,
                &reference,
                &pool,
                &digest,
                public,
                &targets,
                &route,
                now_ms(),
            )
        })
        .await;
        if let Err(error) = prepared {
            // The fresh key was never referenced by a durable saga.
            let _ = self.keys.destroy(&key_ref);
            return Err(error);
        }
        Ok(Some(saga_id))
    }

    /// Advances one saga until it waits on uncertainty or reaches a terminal step.
    pub(crate) async fn advance(
        &mut self,
        store: &SharedStore,
        saga_id: &str,
    ) -> Result<(), Fault> {
        for _ in 0..STEPS_PER_SAGA {
            match self.step(store, saga_id).await? {
                Step::Progress => continue,
                Step::Idle => break,
            }
        }
        Ok(())
    }

    async fn attention(
        &self,
        store: &SharedStore,
        saga_id: &str,
        code: &'static str,
    ) -> Result<i64, Fault> {
        let id = saga_id.to_owned();
        stored(store, move |store| {
            completion::note_attention(store.completion_db(), &id, code)
        })
        .await
    }

    /// The frozen original route must still be the configured route; otherwise
    /// only explicit operator recovery can continue.
    fn route_matches(&self, saga: &Saga) -> bool {
        self.run.configured_route().is_ok_and(|mut route| {
            route.store_id = Some(saga.run_store_id.clone());
            route == saga.route
        })
    }

    /// Performs exactly one durable saga transition or one awaited Run exchange.
    pub(crate) async fn step(&mut self, store: &SharedStore, saga_id: &str) -> Result<Step, Fault> {
        let id = saga_id.to_owned();
        let saga = stored(store, move |store| {
            completion::load(store.completion_db(), &id)
        })
        .await?;
        match saga.stage {
            Stage::Released => {
                if saga.key_present {
                    self.keys.destroy(&saga.key_ref)?;
                    let id = saga.id.clone();
                    stored(store, move |store| {
                        completion::mark_key_destroyed(store.completion_db(), &id)
                    })
                    .await?;
                }
                if saga.outcome.as_deref() == Some("committed") {
                    let id = saga.id.clone();
                    stored(store, move |store| {
                        completion::link_notice(store.completion_db(), &id, now_ms())
                    })
                    .await?;
                }
                Ok(Step::Idle)
            }
            Stage::Prepared => self.prepared(store, &saga).await,
            Stage::AcquirePossible => self.recover_acquire(store, &saga).await,
            Stage::Held => self.settle(store, &saga).await,
            Stage::Committed | Stage::Aborted => {
                let id = saga.id.clone();
                if saga.hold_id.is_none() {
                    stored(store, move |store| {
                        completion::finish_without_hold(store.completion_db(), &id)
                    })
                    .await?;
                } else {
                    stored(store, move |store| {
                        completion::mark_release_pending(store.completion_db(), &id)
                    })
                    .await?;
                }
                Ok(Step::Progress)
            }
            Stage::ReleasePending => self.release(store, &saga).await,
        }
    }

    /// Before any acquire is possible a missing key or route aborts safely.
    async fn prepared(&mut self, store: &SharedStore, saga: &Saga) -> Result<Step, Fault> {
        let reason = if !self.keys.available(&saga.key_ref, &saga.public_key) {
            Some("key_unavailable")
        } else if !self.route_matches(saga) {
            Some("route_changed")
        } else {
            None
        };
        if let Some(reason) = reason {
            let id = saga.id.clone();
            stored(store, move |store| {
                completion::abort(store.completion_db(), &id, reason)
            })
            .await?;
            return Ok(Step::Progress);
        }
        if self.run.discover(&saga.run_store_id).await.is_err() {
            self.attention(store, &saga.id, "hold_unavailable").await?;
            return Ok(Step::Idle);
        }
        let id = saga.id.clone();
        stored(store, move |store| {
            completion::mark_acquire_possible(store.completion_db(), &id)
        })
        .await?;
        // The first possible request; its outcome is unknown until correlated.
        let result = self.run.acquire(&saga.intent, None).await;
        self.record_acquire(store, saga, result, true).await
    }

    async fn record_acquire(
        &self,
        store: &SharedStore,
        saga: &Saga,
        result: Result<AcquireResult, HoldError>,
        first: bool,
    ) -> Result<Step, Fault> {
        if first && matches!(result, Err(HoldError::Refused)) {
            let id = saga.id.clone();
            stored(store, move |store| {
                completion::refuse_first_acquire(store.completion_db(), &id)
            })
            .await?;
            return Ok(Step::Progress);
        }
        let Ok(result) = result else {
            return self.acquire_unknown(store, saga).await;
        };
        self.record_observation(store, saga, &result.observation)
            .await
    }

    /// An uncertain acquire stays at its stage. After bounded failures the Pool
    /// outcome is fenced as aborted so this saga can never commit, while exact
    /// lookup and replay continue until any hold it created is found and released.
    async fn acquire_unknown(&self, store: &SharedStore, saga: &Saga) -> Result<Step, Fault> {
        let failures = self.attention(store, &saga.id, "outcome_unknown").await?;
        if failures >= HELD_FAILURE_LIMIT && saga.outcome.is_none() {
            let id = saga.id.clone();
            stored(store, move |store| {
                completion::abort(store.completion_db(), &id, "hold_unavailable")
            })
            .await?;
        }
        Ok(Step::Idle)
    }

    async fn record_observation(
        &self,
        store: &SharedStore,
        saga: &Saga,
        observation: &HoldObservation,
    ) -> Result<Step, Fault> {
        let hold_id = observation.receipt().hold_id().to_owned();
        let id = saga.id.clone();
        match observation.state() {
            HoldState::Active => {
                stored(store, move |store| {
                    completion::record_held(store.completion_db(), &id, &hold_id)
                })
                .await?
            }
            // A released replay never authorizes a CAS.
            HoldState::Released => {
                stored(store, move |store| {
                    completion::record_found_released(store.completion_db(), &id, &hold_id)
                })
                .await?
            }
        }
        Ok(Step::Progress)
    }

    /// Lost acquire ACK: exact lookup, then exact replay of the original acquire.
    async fn recover_acquire(&mut self, store: &SharedStore, saga: &Saga) -> Result<Step, Fault> {
        if !self.route_matches(saga) {
            self.attention(store, &saga.id, "route_changed").await?;
            return Ok(Step::Idle);
        }
        let id = saga.id.clone();
        stored(store, move |store| {
            completion::clear_route_attention(store.completion_db(), &id)
        })
        .await?;
        let prior = match &saga.hold_id {
            Some(hold_id) => Some(
                HoldObservation::from_persisted(&saga.intent, hold_id, HoldState::Active)
                    .map_err(|_| Fault::Internal)?,
            ),
            None => None,
        };
        match self.run.lookup(&saga.intent, prior.as_ref()).await {
            Ok(LookupResult::Found(observation)) => {
                self.record_observation(store, saga, &observation).await
            }
            // Absence is only a snapshot: replay the original acquire, never a new key.
            Ok(LookupResult::AbsentSnapshot) => {
                let result = self.run.acquire(&saga.intent, prior.as_ref()).await;
                self.record_acquire(store, saga, result, false).await
            }
            Err(_) => self.acquire_unknown(store, saga).await,
        }
    }

    async fn abort(
        &self,
        store: &SharedStore,
        saga: &Saga,
        reason: &'static str,
    ) -> Result<Step, Fault> {
        let id = saga.id.clone();
        stored(store, move |store| {
            completion::abort(store.completion_db(), &id, reason)
        })
        .await?;
        Ok(Step::Progress)
    }

    /// With the hold active: fresh all-voter consensus and held Run facts, then the CAS.
    async fn settle(&mut self, store: &SharedStore, saga: &Saga) -> Result<Step, Fault> {
        if !self.route_matches(saga) {
            self.attention(store, &saga.id, "route_changed").await?;
            return Ok(Step::Idle);
        }
        let id = saga.id.clone();
        stored(store, move |store| {
            completion::clear_route_attention(store.completion_db(), &id)
        })
        .await?;
        let pool = saga.pool_id.clone();
        let candidate = stored(store, move |store| {
            completion::snapshot(store.completion_db(), &pool)
        })
        .await?;
        let Some(candidate) = candidate.filter(|c| c.frozen_digest == saga.frozen_digest) else {
            return self.abort(store, saga, "roster_stale").await;
        };
        let ballots: Vec<VerifiedBallot> = candidate
            .voters
            .iter()
            .map(|voter| voter.ballot.clone())
            .collect();
        let observations = self.run.consensus(store, &ballots).await;
        let mut unavailable = false;
        for (result, voter) in observations.iter().zip(&ballots) {
            match result {
                Ok(observation) if observation.state == VoterState::TerminalNoSuccessor => {
                    if observation.last_attempt.as_ref() != Some(&voter.attempt)
                        || observation.last_incarnation.as_ref() != Some(&voter.incarnation)
                    {
                        return self.abort(store, saga, "voter_superseded").await;
                    }
                }
                Ok(observation) if observation.state == VoterState::Live => {
                    return self.abort(store, saga, "voter_not_finished").await;
                }
                Ok(observation) if observation.state == VoterState::Superseded => {
                    return self.abort(store, saga, "voter_superseded").await;
                }
                _ => unavailable = true,
            }
        }
        let status = if unavailable || observations.len() != ballots.len() {
            Err(Fault::Unavailable)
        } else {
            self.run.status(&saga.run_store_id, &saga.targets).await
        };
        let (observed_at, facts) = match status {
            Ok(value) => value,
            Err(_) => {
                if self.attention(store, &saga.id, "run_unavailable").await? >= HELD_FAILURE_LIMIT {
                    return self.abort(store, saga, "run_unavailable").await;
                }
                return Ok(Step::Idle);
            }
        };
        if facts.len() != saga.targets.len() {
            return self.abort(store, saga, "run_facts_unverified").await;
        }
        let mut targets = Vec::with_capacity(facts.len());
        for (((fact, target), root), (voter, observation)) in facts
            .into_iter()
            .zip(&saga.targets)
            .zip(&saga.roots)
            .zip(candidate.voters.iter().zip(observations))
        {
            let Ok(observation) = observation else {
                return Err(Fault::Internal);
            };
            let Some(successor_proof) = observation.successor_proof else {
                return self.abort(store, saga, "run_facts_unverified").await;
            };
            if fact.projection.selector() != target || !fact.projection.historical_success {
                return self.abort(store, saga, "run_facts_unverified").await;
            }
            targets.push(TargetFacts {
                member_id: voter.member_id.clone(),
                canonical_root: root.clone(),
                target: target.clone(),
                consensus_state: observation.state,
                consensus_attempt: voter.ballot.attempt.clone(),
                consensus_incarnation: voter.ballot.incarnation.clone(),
                successor_proof,
                status: fact.projection,
            });
        }
        let facts = completion::HeldFacts {
            status_observed_at: observed_at,
            targets,
        };
        let id = saga.id.clone();
        match stored(store, move |store| {
            completion::commit(store.completion_db(), &id, &facts)
        })
        .await
        {
            Ok(_) => Ok(Step::Progress),
            Err(Fault::Stale | Fault::Conflict | Fault::Invalid) => {
                self.abort(store, saga, "cas_refused").await
            }
            Err(error) => Err(error),
        }
    }

    /// Signs the original release message with the protected key and releases the same hold.
    async fn release(&mut self, store: &SharedStore, saga: &Saga) -> Result<Step, Fault> {
        if !self.route_matches(saga) {
            self.attention(store, &saga.id, "route_changed").await?;
            return Ok(Step::Idle);
        }
        let id = saga.id.clone();
        stored(store, move |store| {
            completion::clear_route_attention(store.completion_db(), &id)
        })
        .await?;
        let hold_id = saga.hold_id.as_deref().ok_or(Fault::Internal)?;
        let observation = HoldObservation::from_persisted(&saga.intent, hold_id, HoldState::Active)
            .map_err(|_| Fault::Internal)?;
        let message = observation
            .release_message(&saga.intent)
            .map_err(|_| Fault::Internal)?;
        // A lost key leaves the hold unresolved for explicit operator recovery.
        let Ok(signature) = self.keys.sign(&saga.key_ref, &saga.public_key, &message) else {
            self.attention(store, &saga.id, "key_unavailable").await?;
            return Ok(Step::Idle);
        };
        let result = self
            .run
            .release(&saga.intent, &observation, &signature)
            .await;
        let Ok(result) = result else {
            self.attention(store, &saga.id, "release_unknown").await?;
            return Ok(Step::Idle);
        };
        let id = saga.id.clone();
        stored(store, move |store| {
            completion::record_released(
                store.completion_db(),
                &id,
                result.already_released,
                now_ms(),
            )
        })
        .await?;
        Ok(Step::Progress)
    }
}

#[cfg(test)]
mod review_tests {
    use super::*;
    #[test]
    fn retry_backoff_grows_and_is_bounded() {
        assert_eq!(
            retry_delay(Duration::from_secs(5), 1),
            Duration::from_secs(5)
        );
        assert_eq!(
            retry_delay(Duration::from_secs(5), 3),
            Duration::from_secs(20)
        );
        assert_eq!(retry_delay(Duration::from_secs(5), 100), RETRY_CEILING);
        assert_eq!(retry_delay(CANDIDATE_BACKOFF, 100), RETRY_CEILING);
    }
}
