//! P3-C completion ledger and saga tests with real SQLite restarts and a
//! synthetic stateful Run (consensus, status and hold v1 with strict Ed25519).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "Isolated synthetic SQLite, key and Run fixtures"
)]
use crate::{
    completion::{self, GetRequest, Item},
    completion_key::KeyStore,
    completion_saga::{Driver, SettlementRun, StatusFact},
    domain::{
        Actor, Ballot, BatchJob, Binding, Change, CheckStatus, Choice, Command, Criterion,
        CriterionCheck, Effect, Event, Fault, Member, MemberState, Pool, Proposal, ProposalState,
        RunRoute, VoteValidity, Work,
    },
    managed_state::{
        AttemptRef, Incarnation, ManagedActor, ManagedBinding, Route, SuccessorLink,
        SuccessorProof, VerifiedBallot, VoterObservation, VoterState,
    },
    run_hold::{
        AcquireResult, HoldError, HoldIntent, HoldObservation, HoldState, LookupResult,
        ReleaseResult,
    },
    run_status::Target,
    store::{Admitted, Store},
};
use ed25519_dalek::{Signature, VerifyingKey};
use rusqlite::params;
use serde_json::json;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
    sync::{Arc, Mutex},
};

type SharedStore = Arc<Mutex<Store>>;
const RUN_STORE: &str = "store_00112233445566778899aabbccddeeff";
const POOL: &str = "pool-c";
const PROPOSAL: &str = "proposal-c";

fn agent(n: u32) -> String {
    format!("ag-20261110-120000-{n:010x}")
}
fn target(n: u32, sequence: u32) -> Target {
    Target {
        agent_id: agent(n),
        sequence,
        execution_ref: format!("ex1_{:064x}", u64::from(n) * 1000 + u64::from(sequence)),
        pin_id: format!("pin_00000000000040008000{n:012x}"),
    }
}
fn incarnation(n: u32) -> Incarnation {
    Incarnation {
        host_id: "host".into(),
        boot_id: "00000000-0000-4000-8000-000000000001".into(),
        pid_namespace_inode: 1,
        uid: 1000,
        pid: 100 + n,
        start_ticks: 1,
    }
}
fn attempt(n: u32, sequence: u32) -> AttemptRef {
    AttemptRef {
        run_store_id: RUN_STORE.into(),
        lineage_root_id: agent(n),
        execution_id: agent(n),
        sequence,
        attempt_id: format!("attempt-{n}-{sequence}"),
        launch_id: format!("00000000-0000-4000-8000-{n:012x}"),
    }
}
fn proof(n: u32) -> SuccessorProof {
    SuccessorProof {
        lineage_root_id: agent(n),
        bound_execution_id: agent(n),
        current_execution_id: agent(n),
        chain: vec![SuccessorLink {
            execution_id: agent(n),
            parent_execution_id: None,
            sequence: 1,
        }],
    }
}
fn owner() -> Actor {
    Actor {
        key: "owner".into(),
        address: "owner-address".into(),
    }
}

/// Voter kinds used to exercise eligibility.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Managed,
    Native,
    LegacyRun,
    UnknownBallot,
}

struct Options {
    voters: Vec<Kind>,
    structured: bool,
    snapshot: Option<String>,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            voters: vec![Kind::Managed, Kind::Managed],
            structured: true,
            snapshot: Some("final snapshot é".into()),
        }
    }
}

struct Fixture {
    dir: tempfile::TempDir,
    store: Option<SharedStore>,
    keys: KeyStore,
}
impl Fixture {
    fn store(&self) -> SharedStore {
        Arc::clone(self.store.as_ref().unwrap())
    }
    fn db_path(&self) -> PathBuf {
        self.dir.path().join("pool.db")
    }
    /// Drops every handle and reopens the same database, as after a crash.
    fn restart(&mut self) {
        let store = self.store.take().unwrap();
        drop(Arc::try_unwrap(store).ok().unwrap());
        self.store = Some(Arc::new(Mutex::new(Store::open(&self.db_path()).unwrap())));
    }
    fn with<T>(&self, f: impl FnOnce(&mut rusqlite::Connection) -> T) -> T {
        let store = self.store();
        let mut guard = store.lock().unwrap();
        f(guard.completion_db())
    }
    fn count(&self, sql: &str) -> i64 {
        self.with(|db| db.query_row(sql, [], |r| r.get(0)).unwrap())
    }
    fn stage(&self, saga: &str) -> (String, Option<String>, Option<String>) {
        self.with(|db| {
            db.query_row(
                "SELECT stage,outcome,attention FROM completion_sagas WHERE id=?1",
                [saga],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap()
        })
    }
    fn key_files(&self) -> usize {
        std::fs::read_dir(self.keys.directory())
            .map(|entries| entries.count())
            .unwrap_or(0)
    }
}

fn private_dir() -> tempfile::TempDir {
    let base = std::env::var_os("TMPDIR").expect("task TMPDIR required");
    let dir = tempfile::tempdir_in(base).unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

/// Builds one pool with an accepted proposal, exact journal events, managed
/// bindings and ballot provenance, using the real schema and Store::open.
fn fixture(options: Options) -> Fixture {
    let dir = private_dir();
    let mut store = Store::open(&dir.path().join("pool.db")).unwrap();
    let uid = std::fs::metadata(dir.path()).unwrap().uid();
    let db = store.completion_db();
    let pool_store_id: String = db
        .query_row("SELECT store_id FROM inventory_source", [], |r| r.get(0))
        .unwrap();
    let keys = KeyStore::open(&dir.path().join("pool.db"), uid, &pool_store_id).unwrap();
    db.execute(
        "INSERT INTO leaders(actor,address) VALUES('owner','owner-address')",
        [],
    )
    .unwrap();
    let acceptance = options.structured.then(|| {
        vec![Criterion {
            id: "c1".into(),
            text: "The result works.".into(),
        }]
    });
    let voters: Vec<String> = (1..=options.voters.len())
        .map(|n| format!("member-{n}"))
        .collect();
    let mut pool = Pool {
        pool_id: POOL.into(),
        name: "Completion pool".into(),
        purpose: "Deliver the frozen goal.".into(),
        purpose_bytes: None,
        acceptance: acceptance.clone(),
        revision: 7,
        closed: false,
        proposal: Some(Proposal {
            proposal_id: PROPOSAL.into(),
            roster_key: "roster-key".into(),
            voters: voters.clone(),
            result: "Result ready.".into(),
            criteria: "Everything verified.".into(),
            snapshot: options.snapshot.clone(),
            snapshot_bytes: options.snapshot.as_ref().map(String::len),
            state: ProposalState::Accepted,
            votes: BTreeMap::new(),
        }),
    };
    db.execute(
        "INSERT INTO pools(id,owner,data) VALUES(?1,'owner',?2)",
        params![POOL, serde_json::to_string(&pool).unwrap()],
    )
    .unwrap();
    db.execute(
        "INSERT INTO proposals(id,pool,state,data) VALUES(?1,?2,'accepted','{}')",
        params![PROPOSAL, POOL],
    )
    .unwrap();
    db.execute(
        "INSERT INTO managed_pool_epochs(pool,epoch) VALUES(?1,3)",
        [POOL],
    )
    .unwrap();
    let mut votes = BTreeMap::new();
    for (index, kind) in options.voters.iter().enumerate() {
        let n = u32::try_from(index + 1).unwrap();
        let member_id = format!("member-{n}");
        let run = *kind != Kind::Native;
        let t = target(n, 1);
        let binding = Binding {
            member: Member {
                member_id: member_id.clone(),
                name: format!("worker {n}"),
                role: "builder".into(),
                task: format!("task {n}"),
                state: MemberState::Active,
                runtime: "unknown".into(),
            },
            pool_id: POOL.into(),
            actor: Some(format!("actor-{n}")),
            address: Some(format!("host/codex/store/session-{n}")),
            run_id: run.then(|| t.agent_id.clone()),
            run_sequence: run.then_some(1),
            run_execution_ref: run.then(|| t.execution_ref.clone()),
            run_pin_id: run.then(|| t.pin_id.clone()),
            run_store_id: run.then(|| RUN_STORE.to_owned()),
        };
        db.execute(
            "INSERT INTO members(id,pool,actor,address,current,data) VALUES(?1,?2,?3,?4,1,?5)",
            params![
                member_id,
                POOL,
                binding.actor,
                binding.address,
                serde_json::to_string(&binding).unwrap()
            ],
        )
        .unwrap();
        if matches!(kind, Kind::Managed | Kind::UnknownBallot) {
            let managed = ManagedBinding {
                pool_store_id: pool_store_id.clone(),
                pool_id: POOL.into(),
                member_id: member_id.clone(),
                binding_generation: 1,
                attempt: attempt(n, 1),
                actor: ManagedActor {
                    address: format!("host/codex/store/session-{n}"),
                    role: "root".into(),
                    native_id: format!("session-{n}"),
                    epoch: 1,
                },
                run_route: Route {
                    component_store_id: RUN_STORE.into(),
                    route_id: "run-route".into(),
                    worker_uid: 1000,
                },
                bridge_route: Route {
                    component_store_id: "00000000-0000-4000-8000-000000000003".into(),
                    route_id: "bridge-route".into(),
                    worker_uid: 1000,
                },
            };
            db.execute(
                "INSERT INTO managed_bindings(member,pool,generation,binding,incarnation) VALUES(?1,?2,?3,?4,?5)",
                params![
                    member_id,
                    POOL,
                    1_u64.to_be_bytes().to_vec(),
                    serde_json::to_string(&managed).unwrap(),
                    serde_json::to_string(&incarnation(n)).unwrap()
                ],
            )
            .unwrap();
        }
        let last = index + 1 == options.voters.len();
        let vote = Event {
            event_id: 0,
            event_id_exact: None,
            revision: 6,
            kind: if last {
                "proposal_accepted"
            } else {
                "vote_recorded"
            }
            .into(),
            author: crate::domain::Author::Member(member_id.clone()),
            body: format!("Proposal {PROPOSAL}: Ready.\nVerified by {member_id}."),
            recipient: None,
            check: None,
            vote_event_id: None,
            message_event_id: None,
            part_index: None,
            part_count: None,
        };
        db.execute(
            "INSERT INTO events(pool,data) VALUES(?1,?2)",
            params![POOL, serde_json::to_string(&vote).unwrap()],
        )
        .unwrap();
        let event_id = db.last_insert_rowid();
        if options.structured {
            let check = Event {
                kind: "vote_check".into(),
                body: "check".into(),
                check: Some(Box::new(CriterionCheck {
                    criterion_id: "c1".into(),
                    status: CheckStatus::Met,
                    evidence: format!("Checked by {member_id}."),
                })),
                vote_event_id: Some(event_id.to_string()),
                ..vote.clone()
            };
            db.execute(
                "INSERT INTO events(pool,data) VALUES(?1,?2)",
                params![POOL, serde_json::to_string(&check).unwrap()],
            )
            .unwrap();
        }
        if matches!(kind, Kind::Managed | Kind::UnknownBallot) {
            db.execute(
                "INSERT INTO managed_ballot_provenance(pool,proposal,member,event_id,generation,attempt,incarnation,admission_id,security_digest) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    POOL,
                    PROPOSAL,
                    member_id,
                    event_id,
                    1_u64.to_be_bytes().to_vec(),
                    serde_json::to_string(&attempt(n, 1)).unwrap(),
                    serde_json::to_string(&incarnation(n)).unwrap(),
                    format!("admission-{n}"),
                    "d".repeat(64)
                ],
            )
            .unwrap();
        }
        votes.insert(
            member_id,
            Ballot {
                choice: Choice::Ready,
                evidence: format!("Evidence {n}."),
                checks_met: options.structured.then_some(true),
                vote_event_id: options.structured.then(|| event_id.to_string()),
                checks_count: options.structured.then_some(1),
                validity: (*kind == Kind::UnknownBallot).then_some(VoteValidity::Unknown),
            },
        );
    }
    pool.proposal.as_mut().unwrap().votes = votes;
    db.execute(
        "UPDATE pools SET data=?2 WHERE id=?1",
        params![POOL, serde_json::to_string(&pool).unwrap()],
    )
    .unwrap();
    Fixture {
        dir,
        store: Some(Arc::new(Mutex::new(store))),
        keys,
    }
}

/// One synthetic hold row, enforcing the v1 replay, fingerprint and signature rules.
struct FakeHold {
    hold_id: String,
    fingerprint: String,
    state: HoldState,
    key: [u8; 32],
}
/// Stateful synthetic Run; failure flags model lost acknowledgements after commit.
struct RunState {
    route: RunRoute,
    store_id: String,
    voters: HashMap<String, VoterState>,
    consensus_unavailable: bool,
    status_unavailable: bool,
    failed: HashSet<String>,
    cleanup_pending: HashSet<String>,
    holds: HashMap<String, FakeHold>,
    lose_acquire_ack: bool,
    drop_acquire: bool,
    refuse_acquire: bool,
    lose_release_ack: bool,
    created: usize,
    releases: usize,
    calls: Vec<&'static str>,
}
#[derive(Clone)]
struct FakeRun(Arc<Mutex<RunState>>);
impl FakeRun {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(RunState {
            route: RunRoute {
                socket: "/fixture/run.sock".into(),
                expected_uid: 1000,
                peer_uid: None,
                store_id: None,
            },
            store_id: RUN_STORE.into(),
            voters: HashMap::new(),
            consensus_unavailable: false,
            status_unavailable: false,
            failed: HashSet::new(),
            cleanup_pending: HashSet::new(),
            holds: HashMap::new(),
            lose_acquire_ack: false,
            drop_acquire: false,
            refuse_acquire: false,
            lose_release_ack: false,
            created: 0,
            releases: 0,
            calls: Vec::new(),
        })))
    }
    fn state(&self) -> std::sync::MutexGuard<'_, RunState> {
        self.0.lock().unwrap()
    }
    fn active_holds(&self) -> usize {
        self.state()
            .holds
            .values()
            .filter(|hold| hold.state == HoldState::Active)
            .count()
    }
    fn status_item(&self, selector: &Target) -> serde_json::Value {
        let state = self.state();
        let failed = state.failed.contains(&selector.agent_id);
        let execution = json!({"sequence":selector.sequence,"execution_ref":selector.execution_ref,
            "raw_status": if failed { "failed" } else { "succeeded" }});
        json!({"selector":selector,"canonical_agent_id":selector.agent_id,"match":"verified",
            "pin_id":selector.pin_id,"pin_state":"active","selected":execution,"retained_latest":execution,
            "coverage":"complete","restart_resume":"none","lineage_terminal":true,
            "terminal_outcome": if failed { "failed" } else { "succeeded" },
            "success_commit": if failed { "not_succeeded" } else { "recorded" },
            "cleanup":{"scope":"lineage","state": if state.cleanup_pending.contains(&selector.agent_id) { "pending" } else { "confirmed" }}})
    }
    fn eligible(&self, target: &Target) -> bool {
        let state = self.state();
        !state.failed.contains(&target.agent_id)
            && !state.cleanup_pending.contains(&target.agent_id)
    }
}
impl SettlementRun for FakeRun {
    fn configured_route(&self) -> Result<RunRoute, Fault> {
        Ok(self.state().route.clone())
    }
    async fn consensus(
        &self,
        _store: &SharedStore,
        voters: &[VerifiedBallot],
    ) -> Vec<Result<VoterObservation, Fault>> {
        let mut state = self.state();
        state.calls.push("consensus");
        voters
            .iter()
            .map(|voter| {
                if state.consensus_unavailable {
                    return Err(Fault::Unavailable);
                }
                let root = &voter.attempt.lineage_root_id;
                let n = u32::from_str_radix(&root[19..], 16).unwrap();
                match state
                    .voters
                    .get(root)
                    .copied()
                    .unwrap_or(VoterState::TerminalNoSuccessor)
                {
                    VoterState::Superseded => Ok(VoterObservation {
                        state: VoterState::Superseded,
                        last_attempt: Some(attempt(n, 2)),
                        last_incarnation: Some(incarnation(n + 50)),
                        successor_proof: Some(proof(n)),
                    }),
                    VoterState::Unavailable => Err(Fault::Unavailable),
                    other => Ok(VoterObservation {
                        state: other,
                        last_attempt: Some(voter.attempt.clone()),
                        last_incarnation: Some(voter.incarnation.clone()),
                        successor_proof: Some(proof(n)),
                    }),
                }
            })
            .collect()
    }
    async fn status(
        &self,
        store_id: &str,
        targets: &[Target],
    ) -> Result<(String, Vec<StatusFact>), Fault> {
        {
            let mut state = self.state();
            state.calls.push("status");
            if state.status_unavailable || store_id != state.store_id {
                return Err(Fault::Unavailable);
            }
        }
        let items: Vec<_> = targets.iter().map(|t| self.status_item(t)).collect();
        let body =
            json!({"version":1,"store_id":store_id,"observed_at":1_792_000_000.5,"items":items});
        let evidence =
            crate::run_status::parse(body.to_string().as_bytes(), store_id, targets).unwrap();
        Ok((
            evidence.observed_at().to_string(),
            evidence
                .items()
                .map(|item| StatusFact {
                    projection: item.projection(),
                    latest: item.replacement_precondition(),
                })
                .collect(),
        ))
    }
    async fn discover(&self, store_id: &str) -> Result<(), HoldError> {
        let mut state = self.state();
        state.calls.push("discover");
        if store_id == state.store_id {
            Ok(())
        } else {
            Err(HoldError::Unknown)
        }
    }
    async fn acquire(
        &self,
        intent: &HoldIntent,
        prior: Option<&HoldObservation>,
    ) -> Result<AcquireResult, HoldError> {
        let (store, request, targets, _, key) = intent.fixture_view();
        let eligible = targets.iter().all(|t| self.eligible(t));
        let mut state = self.state();
        state.calls.push("acquire");
        if store != state.store_id {
            return Err(HoldError::Unknown);
        }
        if let Some(hold) = state.holds.get(request) {
            if hold.fingerprint != intent.fingerprint() {
                return Err(HoldError::Unknown);
            }
            let observation =
                HoldObservation::from_persisted(intent, &hold.hold_id, hold.state).unwrap();
            return Ok(AcquireResult {
                observation,
                replayed: true,
            });
        }
        if state.drop_acquire {
            state.drop_acquire = false;
            return Err(HoldError::Unknown);
        }
        if state.refuse_acquire {
            return Err(HoldError::Refused);
        }
        if !eligible || prior.is_some() {
            return Err(HoldError::Unknown);
        }
        let hold_id = format!("hold_{}", uuid::Uuid::new_v4().simple());
        state.holds.insert(
            request.to_owned(),
            FakeHold {
                hold_id: hold_id.clone(),
                fingerprint: intent.fingerprint().to_owned(),
                state: HoldState::Active,
                key,
            },
        );
        state.created += 1;
        if state.lose_acquire_ack {
            state.lose_acquire_ack = false;
            return Err(HoldError::Unknown);
        }
        Ok(AcquireResult {
            observation: HoldObservation::from_persisted(intent, &hold_id, HoldState::Active)
                .unwrap(),
            replayed: false,
        })
    }
    async fn lookup(
        &self,
        intent: &HoldIntent,
        _prior: Option<&HoldObservation>,
    ) -> Result<LookupResult, HoldError> {
        let (_, request, ..) = intent.fixture_view();
        let mut state = self.state();
        state.calls.push("lookup");
        Ok(match state.holds.get(request) {
            Some(hold) if hold.fingerprint == intent.fingerprint() => LookupResult::Found(
                HoldObservation::from_persisted(intent, &hold.hold_id, hold.state).unwrap(),
            ),
            Some(_) => return Err(HoldError::Unknown),
            None => LookupResult::AbsentSnapshot,
        })
    }
    async fn release(
        &self,
        intent: &HoldIntent,
        prior: &HoldObservation,
        signature: &[u8; 64],
    ) -> Result<ReleaseResult, HoldError> {
        let (_, request, ..) = intent.fixture_view();
        let message = prior.release_message(intent).unwrap();
        let mut state = self.state();
        state.calls.push("release");
        let lose = state.lose_release_ack;
        let hold = state.holds.get_mut(request).ok_or(HoldError::Unknown)?;
        if hold.hold_id != prior.receipt().hold_id() {
            return Err(HoldError::Unknown);
        }
        VerifyingKey::from_bytes(&hold.key)
            .and_then(|key| key.verify_strict(&message, &Signature::from_bytes(signature)))
            .map_err(|_| HoldError::Unknown)?;
        let already = hold.state == HoldState::Released;
        hold.state = HoldState::Released;
        state.releases += 1;
        if lose {
            state.lose_release_ack = false;
            return Err(HoldError::Unknown);
        }
        Ok(ReleaseResult {
            already_released: already,
        })
    }
}

fn driver(fixture: &Fixture, run: &FakeRun) -> Driver<FakeRun> {
    Driver::new(run.clone(), fixture.keys.clone())
}
async fn run_to_end(fixture: &Fixture, run: &FakeRun) -> Option<String> {
    let mut driver = driver(fixture, run);
    let saga = driver.start(&fixture.store(), POOL).await.unwrap()?;
    driver.advance(&fixture.store(), &saga).await.unwrap();
    Some(saga)
}
fn record_count(fixture: &Fixture) -> i64 {
    fixture.count("SELECT count(*) FROM completion_records")
}
fn page(fixture: &Fixture, request: serde_json::Value) -> Result<completion::Page, Fault> {
    let request: GetRequest = serde_json::from_value(request).unwrap();
    let store = fixture.store();
    let mut guard = store.lock().unwrap();
    completion::page(guard.completion_db(), &request)
}
fn completion_id(fixture: &Fixture) -> String {
    fixture.with(|db| {
        db.query_row("SELECT completion_id FROM completion_records", [], |r| {
            r.get(0)
        })
        .unwrap()
    })
}
fn inventory(fixture: &Fixture) -> serde_json::Value {
    let store = fixture.store();
    let guard = store.lock().unwrap();
    let request: crate::observer::Request = serde_json::from_value(json!({"schema_version":1,
        "operation":"inventory_snapshot","params":{"filter":"all","limit":10}}))
    .unwrap();
    serde_json::to_value(guard.observe(&request).unwrap()).unwrap()
}

/// Ready ballots plus finished, successful, cleaned lineages complete exactly
/// once; failed, unclean, live, legacy or Unknown voters never acquire a hold.
#[tokio::test]
async fn p3_completion_ready_finish() {
    let fixture = fixture(Options::default());
    let run = FakeRun::new();
    let saga = run_to_end(&fixture, &run).await.unwrap();
    assert_eq!(fixture.stage(&saga).0, "released");
    assert_eq!(record_count(&fixture), 1);
    assert_eq!(run.state().created, 1);
    assert_eq!(run.active_holds(), 0);
    assert_eq!(
        fixture.key_files(),
        0,
        "key destroyed only after verified release"
    );
    // The commit queued one owner notice and journaled the completion.
    assert_eq!(fixture.count("SELECT count(*) FROM effects WHERE pool='pool-c' AND json_extract(data,'$.work.scope')='owner:pool-c'"), 1);
    assert_eq!(
        fixture.count(
            "SELECT count(*) FROM events WHERE json_extract(data,'$.kind')='pool_completed'"
        ),
        1
    );

    for (setup, label) in [
        (0, "live worker"),
        (1, "failed terminal"),
        (2, "cleanup pending"),
        (3, "unavailable"),
    ] {
        let fixture = self::fixture(Options::default());
        let run = FakeRun::new();
        {
            let mut state = run.state();
            match setup {
                0 => {
                    state.voters.insert(agent(2), VoterState::Live);
                }
                1 => {
                    state.failed.insert(agent(1));
                }
                2 => {
                    state.cleanup_pending.insert(agent(2));
                }
                _ => {
                    state.voters.insert(agent(1), VoterState::Unavailable);
                }
            }
        }
        assert!(run_to_end(&fixture, &run).await.is_none(), "{label}");
        assert_eq!(run.state().created, 0, "{label}");
        assert!(!run.state().calls.contains(&"acquire"), "{label}");
        assert_eq!(fixture.count("SELECT count(*) FROM completion_sagas"), 0);
        assert_eq!(fixture.key_files(), 0, "{label}");
    }
    for voters in [
        vec![Kind::Managed, Kind::UnknownBallot],
        vec![Kind::Managed, Kind::LegacyRun],
        vec![Kind::Native],
    ] {
        let fixture = self::fixture(Options {
            voters,
            ..Options::default()
        });
        let run = FakeRun::new();
        assert!(run_to_end(&fixture, &run).await.is_none());
        assert!(
            run.state().calls.is_empty(),
            "ineligible ballots never reach Run"
        );
    }
    // A required native voter keeps its existing verified proof beside a held managed lineage.
    let fixture = self::fixture(Options {
        voters: vec![Kind::Native, Kind::Managed],
        structured: false,
        snapshot: None,
    });
    let run = FakeRun::new();
    run_to_end(&fixture, &run).await.unwrap();
    assert_eq!(record_count(&fixture), 1);
}

#[tokio::test]
async fn completion_fences_pending_admission_and_refuses_late_receipt() {
    let fixture = fixture(Options::default());
    let run = FakeRun::new();
    let effect = Effect {
        effect_id: "late-start".into(),
        pool_id: POOL.into(),
        member_id: Some("member-1".into()),
        state: "queued".into(),
        work: Work::Start {
            spec: json!({}),
            request_key: "start-key".into(),
            route_fence: false,
            route: None,
        },
    };
    let raw = serde_json::to_string(&effect).unwrap();
    fixture.with(|db| {
        db.execute(
            "INSERT INTO effects(id,pool,member,state,data) VALUES(?1,?2,?3,'queued',?4)",
            params![effect.effect_id, POOL, "member-1", raw],
        )
        .unwrap();
    });
    assert!(
        fixture
            .with(|db| completion::snapshot(db, POOL).unwrap())
            .is_none()
    );
    assert!(
        driver(&fixture, &run)
            .start(&fixture.store(), POOL)
            .await
            .unwrap()
            .is_none()
    );
    fixture.with(|db| {
        db.execute(
            "UPDATE effects SET state='cancelled' WHERE id='late-start'",
            [],
        )
        .unwrap();
    });
    let mut driver = driver(&fixture, &run);
    let saga = driver.start(&fixture.store(), POOL).await.unwrap().unwrap();
    driver.step(&fixture.store(), &saga).await.unwrap();
    fixture.with(|db| {
        db.execute(
            "UPDATE effects SET state='unknown' WHERE id='late-start'",
            [],
        )
        .unwrap();
    });
    driver.advance(&fixture.store(), &saga).await.unwrap();
    assert_eq!(record_count(&fixture), 0);
    assert_eq!(fixture.stage(&saga).1.as_deref(), Some("aborted"));
    fixture.with(|db| {
        db.execute(
            "UPDATE effects SET state='cancelled' WHERE id='late-start'",
            [],
        )
        .unwrap();
    });
    let run = FakeRun::new();
    run_to_end(&fixture, &run).await.unwrap();
    fixture.with(|db| {
        db.execute(
            "UPDATE effects SET state='unknown' WHERE id='late-start'",
            [],
        )
        .unwrap();
    });
    let before = fixture.with(|db| {
        db.query_row::<String, _, _>("SELECT data FROM pools WHERE id=?1", [POOL], |r| r.get(0))
            .unwrap()
    });
    let store = fixture.store();
    // The late receipt is retained exactly and the effect becomes terminal.
    for _ in 0..2 {
        assert_eq!(
            store
                .lock()
                .unwrap()
                .record_run_admission("late-start", &agent(99), 1),
            Ok(Admitted::ReconciliationNeeded)
        );
    }
    assert_eq!(
        store
            .lock()
            .unwrap()
            .record_run_admission("late-start", &agent(98), 1),
        Err(Fault::Conflict)
    );
    assert_eq!(
        fixture.with(|db| db
            .query_row::<String, _, _>(
                "SELECT receipt FROM completed_admissions WHERE effect='late-start'",
                [],
                |r| r.get(0)
            )
            .unwrap()),
        json!({"kind":"start","agent_id":agent(99),"sequence":1}).to_string()
    );
    assert_eq!(
        fixture.count(
            "SELECT count(*) FROM effects WHERE id='late-start' AND state='reconciliation_needed'"
        ),
        1
    );
    // A later settlement cannot overwrite the retained terminal outcome.
    store
        .lock()
        .unwrap()
        .settle_effect("late-start", "unknown")
        .unwrap();
    assert_eq!(
        fixture.count(
            "SELECT count(*) FROM effects WHERE id='late-start' AND state='reconciliation_needed'"
        ),
        1
    );
    assert!(
        store
            .lock()
            .unwrap()
            .pending_unknown()
            .unwrap()
            .iter()
            .all(|effect| effect.effect_id != "late-start")
    );
    assert_eq!(
        fixture.count(
            "SELECT count(*) FROM alerts WHERE effect='late-start' AND kind='completed_admission'"
        ),
        1
    );
    assert_eq!(
        fixture.with(|db| db
            .query_row::<String, _, _>("SELECT data FROM pools WHERE id=?1", [POOL], |r| r.get(0))
            .unwrap()),
        before
    );
}

#[tokio::test]
async fn completed_pool_refuses_late_batch_and_replacement_receipts() {
    let fixture = fixture(Options::default());
    let old: Binding = fixture.with(|db| {
        serde_json::from_str(
            &db.query_row::<String, _, _>(
                "SELECT data FROM members WHERE id='member-1'",
                [],
                |r| r.get(0),
            )
            .unwrap(),
        )
        .unwrap()
    });
    let condition = fixture.with(|db| {
        completion::snapshot(db, POOL).unwrap().unwrap().voters[0]
            .selector
            .clone()
    });
    let run = FakeRun::new();
    run_to_end(&fixture, &run).await.unwrap();
    let route = RunRoute {
        socket: "/fixture/run.sock".into(),
        expected_uid: 1000,
        peer_uid: None,
        store_id: Some(RUN_STORE.into()),
    };
    let job = BatchJob {
        member_id: "member-1".into(),
        spec: json!({}),
        original_spec: None,
    };
    let batch = Effect {
        effect_id: "late-batch".into(),
        pool_id: POOL.into(),
        member_id: Some("member-1".into()),
        state: "unknown".into(),
        work: Work::StartBatch {
            request_key: "batch".into(),
            retain_history: true,
            store_fence: true,
            route_fence: true,
            route: Some(route.clone()),
            jobs: vec![job.clone()],
        },
    };
    let mut new = old.clone();
    new.member.member_id = "new-member".into();
    let replacement = Effect {
        effect_id: "late-replacement".into(),
        pool_id: POOL.into(),
        member_id: Some("member-1".into()),
        state: "inflight".into(),
        work: Work::Replace {
            request_key: "replacement".into(),
            old: Box::new(old),
            new: Box::new(new),
            job,
            route,
            condition: Some(condition),
            submitted: true,
            claim: Some("claim".into()),
            send_first: Some(false),
        },
    };
    fixture.with(|db| {
        for effect in [&batch, &replacement] {
            db.execute(
                "INSERT INTO effects(id,pool,member,state,data) VALUES(?1,?2,?3,?4,?5)",
                params![
                    effect.effect_id,
                    POOL,
                    effect.member_id,
                    effect.state,
                    serde_json::to_string(effect).unwrap()
                ],
            )
            .unwrap();
        }
    });
    let receipt = (
        agent(99),
        1,
        format!("ex1_{}", "b".repeat(64)),
        Some(target(99, 1).pin_id),
    );
    let store = fixture.store();
    for _ in 0..2 {
        assert_eq!(
            store.lock().unwrap().record_batch_admission(
                "late-batch",
                Some(RUN_STORE),
                std::slice::from_ref(&receipt)
            ),
            Ok(Admitted::ReconciliationNeeded)
        );
        assert_eq!(
            store.lock().unwrap().record_replacement_admission(
                "late-replacement",
                "claim",
                RUN_STORE,
                &receipt
            ),
            Ok(Admitted::ReconciliationNeeded)
        );
    }
    let retained = json!({"kind":"replace","store_id":RUN_STORE,"admissions":[{
        "agent_id":receipt.0,"sequence":1,"execution_ref":receipt.2,"pin_id":receipt.3}]});
    assert_eq!(
        fixture.with(|db| db
            .query_row::<String, _, _>(
                "SELECT receipt FROM completed_admissions WHERE effect='late-replacement'",
                [],
                |r| r.get(0)
            )
            .unwrap()),
        retained.to_string()
    );
    assert_eq!(
        fixture.count("SELECT count(*) FROM effects WHERE id IN ('late-batch','late-replacement') AND state='reconciliation_needed' AND json_extract(data,'$.work.claim') IS NULL"),
        2
    );
    assert_eq!(
        fixture.count("SELECT count(*) FROM members WHERE id='new-member'"),
        0
    );
    assert_eq!(
        fixture.count("SELECT count(*) FROM alerts WHERE kind='completed_admission'"),
        2
    );
}

/// All-voter currentness and the complete roster/epoch/generation CAS refuse stale settlement.
#[tokio::test]
async fn p3_completion_all_voters() {
    for case in 0..5 {
        let fixture = fixture(Options::default());
        let run = FakeRun::new();
        let mut driver = driver(&fixture, &run);
        let saga = driver.start(&fixture.store(), POOL).await.unwrap().unwrap();
        // One step: prepared -> acquire_possible -> held, without settling.
        driver.step(&fixture.store(), &saga).await.unwrap();
        assert_eq!(fixture.stage(&saga).0, "held");
        match case {
            0 => {
                run.state().voters.insert(agent(1), VoterState::Superseded);
            }
            1 => {
                run.state().voters.insert(agent(2), VoterState::Live);
            }
            2 => fixture.with(|db| {
                db.execute(
                    "UPDATE managed_pool_epochs SET epoch=epoch+1 WHERE pool=?1",
                    [POOL],
                )
                .unwrap();
            }),
            3 => fixture.with(|db| {
                db.execute(
                    "UPDATE managed_bindings SET generation=?2 WHERE member=?1",
                    params!["member-2", 2_u64.to_be_bytes().to_vec()],
                )
                .unwrap();
            }),
            _ => run.state().consensus_unavailable = true,
        }
        driver.advance(&fixture.store(), &saga).await.unwrap();
        if case == 4 {
            // Unavailable refuses: bounded retries, then abort and release.
            assert_eq!(fixture.stage(&saga).2.as_deref(), Some("run_unavailable"));
            for _ in 0..3 {
                driver.advance(&fixture.store(), &saga).await.unwrap();
            }
        }
        let (stage, outcome, _) = fixture.stage(&saga);
        assert_eq!(
            (stage.as_str(), outcome.as_deref()),
            ("released", Some("aborted")),
            "case {case}"
        );
        assert_eq!(record_count(&fixture), 0, "case {case}");
        assert_eq!(run.state().created, 1);
        assert_eq!(run.active_holds(), 0, "aborted saga released its hold");
        assert_eq!(run.state().releases, 1);
    }
}

/// Lost acquire and release acknowledgements recover with the same key and
/// fingerprint, one hold and one effective release; a released replay never commits.
#[tokio::test]
async fn p3_hold_lost_ack_release() {
    let fixture = fixture(Options::default());
    let run = FakeRun::new();
    run.state().lose_acquire_ack = true;
    run.state().lose_release_ack = true;
    let mut driver = driver(&fixture, &run);
    let saga = driver.start(&fixture.store(), POOL).await.unwrap().unwrap();
    driver.advance(&fixture.store(), &saga).await.unwrap();
    assert_eq!(fixture.stage(&saga).0, "acquire_possible");
    assert_eq!(run.state().created, 1);
    driver.advance(&fixture.store(), &saga).await.unwrap();
    // Recovered by lookup, committed, then the release ACK was lost.
    assert_eq!(fixture.stage(&saga).0, "release_pending");
    assert_eq!(record_count(&fixture), 1);
    assert_eq!(run.active_holds(), 0);
    driver.advance(&fixture.store(), &saga).await.unwrap();
    assert_eq!(fixture.stage(&saga).0, "released");
    assert_eq!(run.state().created, 1, "never a second hold");
    assert_eq!(
        run.state().releases,
        2,
        "exact replay of the same signed release"
    );
    let receipt: String = fixture.with(|db| {
        db.query_row(
            "SELECT release_receipt FROM completion_sagas WHERE id=?1",
            [&saga],
            |r| r.get(0),
        )
        .unwrap()
    });
    assert!(receipt.contains("\"already_released\":true"));

    // A dropped request: absent lookup is only a snapshot; the original acquire is replayed.
    let fixture = self::fixture(Options::default());
    let run = FakeRun::new();
    run.state().drop_acquire = true;
    let mut driver = self::driver(&fixture, &run);
    let saga = driver.start(&fixture.store(), POOL).await.unwrap().unwrap();
    driver.advance(&fixture.store(), &saga).await.unwrap();
    assert_eq!(fixture.stage(&saga).0, "acquire_possible");
    driver.advance(&fixture.store(), &saga).await.unwrap();
    assert_eq!(fixture.stage(&saga).0, "released");
    assert_eq!(record_count(&fixture), 1);
    assert_eq!(run.state().created, 1);
    let calls = run.state().calls.clone();
    let lookup = calls.iter().position(|c| *c == "lookup").unwrap();
    assert_eq!(
        calls[lookup + 1],
        "acquire",
        "replay follows the absent snapshot"
    );

    // An exact replay observed released can never authorize the CAS.
    let fixture = self::fixture(Options::default());
    let run = FakeRun::new();
    run.state().lose_acquire_ack = true;
    let mut driver = self::driver(&fixture, &run);
    let saga = driver.start(&fixture.store(), POOL).await.unwrap().unwrap();
    driver.advance(&fixture.store(), &saga).await.unwrap();
    for hold in run.state().holds.values_mut() {
        hold.state = HoldState::Released;
    }
    driver.advance(&fixture.store(), &saga).await.unwrap();
    let (stage, outcome, _) = fixture.stage(&saga);
    assert_eq!(
        (stage.as_str(), outcome.as_deref()),
        ("released", Some("aborted"))
    );
    assert_eq!(record_count(&fixture), 0);
    assert_eq!(run.state().releases, 0);

    // A wrong signature or a changed store never releases or acquires.
    let fixture = self::fixture(Options::default());
    let run = FakeRun::new();
    let mut driver = self::driver(&fixture, &run);
    let saga = driver.start(&fixture.store(), POOL).await.unwrap().unwrap();
    driver.step(&fixture.store(), &saga).await.unwrap();
    let loaded = fixture.with(|db| completion::load(db, &saga).unwrap());
    let observation = HoldObservation::from_persisted(
        &loaded.intent,
        loaded_hold(&fixture, &saga).as_str(),
        HoldState::Active,
    )
    .unwrap();
    assert!(
        run.release(&loaded.intent, &observation, &[0; 64])
            .await
            .is_err()
    );
    assert_eq!(run.active_holds(), 1);
    run.state().store_id = "store_ffffffffffffffffffffffffffffffff".into();
    assert!(run.acquire(&loaded.intent, None).await.is_err());
}

#[tokio::test]
async fn initial_hold_refusal_terminates_but_uncertain_saga_blocks_new_attempts() {
    let fixture = fixture(Options::default());
    let run = FakeRun::new();
    run.state().refuse_acquire = true;
    let mut driver = driver(&fixture, &run);
    let saga = driver.start(&fixture.store(), POOL).await.unwrap().unwrap();
    driver.advance(&fixture.store(), &saga).await.unwrap();
    assert_eq!(fixture.stage(&saga).0, "released");
    assert_eq!(fixture.stage(&saga).1.as_deref(), Some("aborted"));
    assert_eq!(run.state().created, 0);

    let fixture = self::fixture(Options::default());
    let run = FakeRun::new();
    run.state().drop_acquire = true;
    let mut driver = self::driver(&fixture, &run);
    let saga = driver.start(&fixture.store(), POOL).await.unwrap().unwrap();
    driver.step(&fixture.store(), &saga).await.unwrap();
    run.state().refuse_acquire = true;
    for _ in 0..3 {
        driver.step(&fixture.store(), &saga).await.unwrap();
    }
    assert_eq!(fixture.stage(&saga).0, "acquire_possible");
    assert_eq!(fixture.stage(&saga).1.as_deref(), Some("aborted"));
    assert!(
        fixture
            .with(|db| completion::candidates(db, "", 20).unwrap())
            .is_empty()
    );
    assert!(driver.start(&fixture.store(), POOL).await.is_err());
    assert_eq!(run.state().created, 0);
}

#[tokio::test]
async fn completion_attention_does_not_invalidate_inventory_and_route_restore_resets_failures() {
    let fixture = fixture(Options::default());
    let run = FakeRun::new();
    let mut driver = driver(&fixture, &run);
    let saga = driver.start(&fixture.store(), POOL).await.unwrap().unwrap();
    fixture.with(|db| {
        completion::note_attention(db, &saga, "hold_unavailable").unwrap();
        completion::note_attention(db, &saga, "hold_unavailable").unwrap();
    });
    driver.step(&fixture.store(), &saga).await.unwrap();
    assert_eq!(
        fixture.with(|db| db
            .query_row::<i64, _, _>(
                "SELECT failures FROM completion_sagas WHERE id=?1",
                [&saga],
                |r| r.get(0)
            )
            .unwrap()),
        0
    );
    let original = run.state().route.clone();
    let revision = fixture.count("SELECT revision FROM inventory_source");
    run.state().route.socket = "/changed".into();
    for _ in 0..5 {
        driver.step(&fixture.store(), &saga).await.unwrap();
    }
    assert_eq!(
        fixture.count("SELECT revision FROM inventory_source"),
        revision
    );
    assert_eq!(
        fixture.with(|db| completion::driver_unavailable(db, "key_unavailable").unwrap()),
        1
    );
    let store = fixture.store();
    let request: crate::observer::Request =
        serde_json::from_value(json!({"schema_version":1,"operation":"identity","params":{}}))
            .unwrap();
    let identity = serde_json::to_value(store.lock().unwrap().observe(&request).unwrap()).unwrap();
    assert!(
        identity["capabilities"]
            .as_array()
            .unwrap()
            .contains(&json!("completion_attention_key_unavailable"))
    );
    fixture.with(|db| {
        completion::note_attention(db, &saga, "route_changed").unwrap();
    });
    run.state().route = original;
    run.state().consensus_unavailable = true;
    driver.step(&fixture.store(), &saga).await.unwrap();
    assert_eq!(fixture.stage(&saga).0, "held");
    assert_eq!(
        fixture.with(|db| db
            .query_row::<i64, _, _>(
                "SELECT failures FROM completion_sagas WHERE id=?1",
                [&saga],
                |r| r.get(0)
            )
            .unwrap()),
        1
    );
}

#[tokio::test]
async fn candidate_retry_is_backed_off_until_local_revision_changes() {
    let fixture = fixture(Options::default());
    let run = FakeRun::new();
    run.state().voters.insert(agent(1), VoterState::Live);
    let mut driver = driver(&fixture, &run);
    let (_sender, stopped) = tokio::sync::watch::channel(false);
    driver.tick(&fixture.store(), &stopped).await.unwrap();
    assert_eq!(
        run.state()
            .calls
            .iter()
            .filter(|call| **call == "consensus")
            .count(),
        1
    );
    driver.tick(&fixture.store(), &stopped).await.unwrap();
    driver.tick(&fixture.store(), &stopped).await.unwrap();
    assert_eq!(
        run.state()
            .calls
            .iter()
            .filter(|call| **call == "consensus")
            .count(),
        1
    );
    fixture.with(|db| { db.execute("UPDATE pools SET data=json_set(data,'$.revision',json_extract(data,'$.revision')+1) WHERE id=?1", [POOL]).unwrap(); });
    driver.tick(&fixture.store(), &stopped).await.unwrap();
    driver.tick(&fixture.store(), &stopped).await.unwrap();
    assert_eq!(
        run.state()
            .calls
            .iter()
            .filter(|call| **call == "consensus")
            .count(),
        2
    );
}

#[test]
fn read_only_consensus_probes_never_create_currentness_rows() {
    let fixture = fixture(Options::default());
    let candidate = fixture.with(|db| completion::snapshot(db, POOL).unwrap().unwrap());
    let voter = &candidate.voters[0].ballot;
    let pin = crate::managed_state::RunPin {
        route: voter.binding.run_route.clone(),
        socket: "/fixture/attempt.sock".into(),
        executable: "/fixture/run".into(),
        executable_sha256: "a".repeat(64),
        capabilities: vec!["attempt_consensus_v1".into()],
    };
    let before = fixture.count("SELECT count(*) FROM managed_current_requests");
    for n in 0..100 {
        crate::managed_run::VoterQuery::read_only(
            &pin,
            voter,
            &format!("read-{n}"),
            &format!("rpc-{n}"),
        )
        .unwrap();
    }
    assert_eq!(
        fixture.count("SELECT count(*) FROM managed_current_requests"),
        before
    );
}

#[tokio::test]
async fn tick_records_and_backs_off_unexpected_advance_error() {
    let fixture = fixture(Options::default());
    let run = FakeRun::new();
    let mut driver = driver(&fixture, &run);
    let saga = driver.start(&fixture.store(), POOL).await.unwrap().unwrap();
    fixture.with(|db| {
        db.execute_batch("DROP TRIGGER completion_saga_frozen")
            .unwrap();
        db.execute(
            "UPDATE completion_sagas SET frozen='{}' WHERE id=?1",
            [&saga],
        )
        .unwrap();
    });
    let (_sender, stopped) = tokio::sync::watch::channel(false);
    driver.tick(&fixture.store(), &stopped).await.unwrap();
    assert_eq!(fixture.stage(&saga).2.as_deref(), Some("internal_error"));
    driver.tick(&fixture.store(), &stopped).await.unwrap();
    assert_eq!(
        fixture.with(|db| db
            .query_row::<i64, _, _>(
                "SELECT failures FROM completion_sagas WHERE id=?1",
                [&saga],
                |r| r.get(0)
            )
            .unwrap()),
        1
    );
}
fn loaded_hold(fixture: &Fixture, saga: &str) -> String {
    fixture.with(|db| {
        db.query_row(
            "SELECT hold_id FROM completion_sagas WHERE id=?1",
            [saga],
            |r| r.get(0),
        )
        .unwrap()
    })
}

/// Crash at every boundary, then restart: one immutable completion or abort,
/// one hold, no premature release, no second record.
#[tokio::test]
async fn p3_completion_crash_matrix() {
    // Boundaries are expressed as the number of individual saga steps before the crash.
    for crash_after in 0..6 {
        let mut fixture = fixture(Options::default());
        let run = FakeRun::new();
        let saga = {
            let mut driver = driver(&fixture, &run);
            let saga = driver.start(&fixture.store(), POOL).await.unwrap().unwrap();
            for _ in 0..crash_after {
                driver.step(&fixture.store(), &saga).await.unwrap();
            }
            saga
        };
        let before = fixture.stage(&saga).0;
        fixture.restart();
        // Nothing is released before a terminal outcome is durable.
        if matches!(before.as_str(), "prepared" | "acquire_possible" | "held") {
            assert_eq!(run.state().releases, 0, "crash at {before}");
        }
        let mut driver = driver(&fixture, &run);
        driver
            .tick(&fixture.store(), &tokio::sync::watch::channel(false).1)
            .await
            .unwrap();
        driver.advance(&fixture.store(), &saga).await.unwrap();
        let (stage, outcome, _) = fixture.stage(&saga);
        assert_eq!(
            (stage.as_str(), outcome.as_deref()),
            ("released", Some("committed")),
            "crash at {before}"
        );
        assert_eq!(record_count(&fixture), 1);
        assert_eq!(run.state().created, 1, "crash at {before}");
        assert_eq!(run.active_holds(), 0);
        assert_eq!(fixture.count("SELECT count(*) FROM completion_sagas"), 1);
        assert_eq!(fixture.key_files(), 0);
    }

    // Crash after acquire_possible was persisted but before the request was sent.
    let mut fixture = fixture(Options::default());
    let run = FakeRun::new();
    let mut driver = self::driver(&fixture, &run);
    let saga = driver.start(&fixture.store(), POOL).await.unwrap().unwrap();
    fixture.with(|db| completion::mark_acquire_possible(db, &saga).unwrap());
    drop(driver);
    fixture.restart();
    let mut driver = self::driver(&fixture, &run);
    driver.advance(&fixture.store(), &saga).await.unwrap();
    assert_eq!(fixture.stage(&saga).0, "released");
    assert_eq!(run.state().created, 1);

    // Crash after the release was durably verified but before key destruction.
    let mut fixture = self::fixture(Options::default());
    let run = FakeRun::new();
    let mut driver = self::driver(&fixture, &run);
    let saga = driver.start(&fixture.store(), POOL).await.unwrap().unwrap();
    for _ in 0..4 {
        driver.step(&fixture.store(), &saga).await.unwrap();
    }
    assert_eq!(fixture.stage(&saga).0, "released");
    assert_eq!(fixture.key_files(), 1);
    drop(driver);
    fixture.restart();
    self::driver(&fixture, &run)
        .advance(&fixture.store(), &saga)
        .await
        .unwrap();
    assert_eq!(fixture.key_files(), 0);

    // A blocked late commit loses to an already durable abort, and vice versa.
    for abort_first in [true, false] {
        let fixture = self::fixture(Options::default());
        let run = FakeRun::new();
        let mut driver = self::driver(&fixture, &run);
        let saga = driver.start(&fixture.store(), POOL).await.unwrap().unwrap();
        driver.step(&fixture.store(), &saga).await.unwrap();
        let loaded = fixture.with(|db| completion::load(db, &saga).unwrap());
        let ballots: Vec<VerifiedBallot> = fixture.with(|db| {
            completion::snapshot(db, POOL)
                .unwrap()
                .unwrap()
                .voters
                .into_iter()
                .map(|voter| voter.ballot)
                .collect()
        });
        let observations = run.consensus(&fixture.store(), &ballots).await;
        let (observed, status) = run.status(RUN_STORE, &loaded.targets).await.unwrap();
        let facts = completion::HeldFacts {
            status_observed_at: observed,
            targets: status
                .into_iter()
                .zip(observations)
                .enumerate()
                .map(|(index, (fact, observation))| {
                    let observation = observation.unwrap();
                    completion::TargetFacts {
                        member_id: format!("member-{}", index + 1),
                        canonical_root: loaded.roots[index].clone(),
                        target: loaded.targets[index].clone(),
                        consensus_state: observation.state,
                        consensus_attempt: ballots[index].attempt.clone(),
                        consensus_incarnation: ballots[index].incarnation.clone(),
                        successor_proof: observation.successor_proof.unwrap(),
                        status: fact.projection,
                    }
                })
                .collect(),
        };
        if abort_first {
            fixture.with(|db| completion::abort(db, &saga, "operator").unwrap());
            assert_eq!(
                fixture.with(|db| completion::commit(db, &saga, &facts)),
                Err(Fault::Stale)
            );
            assert_eq!(record_count(&fixture), 0);
        } else {
            fixture.with(|db| completion::commit(db, &saga, &facts).unwrap());
            assert_eq!(
                fixture.with(|db| completion::abort(db, &saga, "late")),
                Err(Fault::Stale)
            );
            assert_eq!(
                fixture.with(|db| completion::commit(db, &saga, &facts)),
                Err(Fault::Stale)
            );
            assert_eq!(record_count(&fixture), 1);
        }
        // The terminal outcome cannot be rewritten even by direct SQL.
        assert!(fixture.with(|db| db.execute("UPDATE completion_sagas SET outcome='committed' WHERE id=?1 AND outcome='aborted'", [&saga])).is_err() || !abort_first);
        driver.advance(&fixture.store(), &saga).await.unwrap();
        assert_eq!(fixture.stage(&saga).0, "released");
        assert_eq!(run.active_holds(), 0);
    }
}

/// Accepted, closed, delivered or Run-succeeded pools are open; the ledger,
/// counts and source revision advance together; C3 freezes the pool.
#[tokio::test]
async fn p3_completion_counts() {
    let fixture = fixture(Options::default());
    fixture.with(|db| {
        db.execute("INSERT INTO pools(id,owner,data) VALUES('pool-closed','owner',?1)", [r#"{"pool_id":"pool-closed","name":"closed","purpose":"goal","revision":1,"closed":true,"proposal":null}"#]).unwrap();
    });
    let before = inventory(&fixture);
    assert_eq!(
        before["totals"],
        json!({"total":"2","open":"2","completed":"0","unknown":"0","closed":"1"})
    );
    let run = FakeRun::new();
    run_to_end(&fixture, &run).await.unwrap();
    let after = inventory(&fixture);
    assert_eq!(
        after["totals"],
        json!({"total":"2","open":"1","completed":"1","unknown":"0","closed":"1"})
    );
    let revision = |value: &serde_json::Value| {
        value["source"]["revision"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap()
    };
    assert!(revision(&after) > revision(&before));

    // C3: goal, roster, assignments, proposals and votes are frozen; close and messages remain.
    let mut guard = fixture.store.as_ref().unwrap().lock().unwrap();
    let pool_revision: i64 = guard
        .completion_db()
        .query_row(
            "SELECT json_extract(data,'$.revision') FROM pools WHERE id=?1",
            [POOL],
            |r| r.get(0),
        )
        .unwrap();
    let pool_revision = u64::try_from(pool_revision).unwrap();
    let change = |key: &str| Change {
        pool_id: POOL.into(),
        expected_revision: pool_revision,
        request_key: key.into(),
    };
    for command in [
        Command::Update(crate::domain::Update {
            change: change("update"),
            name: "renamed".into(),
            purpose: "new goal".into(),
        }),
        Command::Propose(crate::domain::Propose {
            change: change("propose"),
            result: "again".into(),
            criteria: "again".into(),
            snapshot: None,
        }),
        Command::Remove(crate::domain::Remove {
            change: change("remove"),
            member_id: "member-1".into(),
        }),
    ] {
        assert_eq!(guard.execute(&owner(), &command).err(), Some(Fault::Closed));
    }
    guard
        .execute(
            &owner(),
            &Command::Post(crate::domain::Message {
                change: change("post"),
                body: "Thanks.".into(),
            }),
        )
        .unwrap();
    guard
        .execute(
            &owner(),
            &Command::Close(change("close").clone_with(pool_revision + 1)),
        )
        .unwrap();
    drop(guard);
    let closed = inventory(&fixture);
    assert_eq!(closed["totals"]["completed"], "1");
    assert_eq!(closed["totals"]["closed"], "2");
}
trait CloneWith {
    fn clone_with(&self, revision: u64) -> Self;
}
impl CloneWith for Change {
    fn clone_with(&self, revision: u64) -> Self {
        Change {
            expected_revision: revision,
            ..self.clone()
        }
    }
}

/// Canonical vectors, exact bounded pages and cursors, no key material, and a
/// record that stays verifiable after release and Run history pruning.
#[tokio::test]
async fn p3_completion_evidence() {
    let snapshot: String = "é漢🙂x".repeat(4000);
    let fixture = fixture(Options {
        snapshot: Some(snapshot.clone()),
        ..Options::default()
    });
    let run = FakeRun::new();
    let saga = run_to_end(&fixture, &run).await.unwrap();
    // Run prunes history after release; local evidence still verifies.
    run.state().status_unavailable = true;
    let id = completion_id(&fixture);
    let header = page(
        &fixture,
        json!({"pool_id":POOL,"completion_id":id,"section":"header","limit":1}),
    )
    .unwrap();
    let digest = header.record_digest.clone();
    let head = header.header.as_ref().unwrap();
    assert!(head.snapshot_present);
    assert_eq!(head.ballots, 2);
    assert_eq!(head.run_targets, 2);
    assert!(
        head.notice_entries >= 2,
        "intent plus linked release observation"
    );
    // Content pages reconstruct exact bytes with exact offsets.
    let mut rebuilt = String::new();
    let mut after = serde_json::Value::Null;
    let mut pages = 0;
    loop {
        let result = page(
            &fixture,
            json!({"pool_id":POOL,"completion_id":id,"section":"content","after":after,"limit":2}),
        )
        .unwrap();
        pages += 1;
        for item in &result.items {
            let Item::Content {
                field,
                offset,
                total_bytes,
                sha256,
                text,
            } = item
            else {
                panic!("content item")
            };
            if field == "snapshot" {
                assert_eq!(*offset as usize, rebuilt.len());
                assert_eq!(*total_bytes as usize, snapshot.len());
                assert_eq!(
                    sha256,
                    &format!(
                        "{:x}",
                        <sha2::Sha256 as sha2::Digest>::digest(snapshot.as_bytes())
                    )
                );
                rebuilt.push_str(text);
            }
        }
        match result.next_cursor {
            Some(cursor) => after = serde_json::to_value(cursor).unwrap(),
            None => break,
        }
    }
    assert_eq!(rebuilt, snapshot);
    assert!(pages > 2);
    // Every list section pages exactly, and the final exclusive cursor is an empty page.
    for (section, expected) in [("roster", 2), ("ballots", 2), ("run_facts", 3)] {
        let first = page(
            &fixture,
            json!({"pool_id":POOL,"completion_id":id,"section":section,"limit":1}),
        )
        .unwrap();
        assert_eq!(first.returned, 1);
        let mut cursor = first.next_cursor.clone();
        let mut total = 1;
        while let Some(next) = cursor {
            let result = page(
                &fixture,
                json!({"pool_id":POOL,"completion_id":id,"section":section,"after":next,"limit":1}),
            )
            .unwrap();
            total += result.returned;
            cursor = result.next_cursor;
        }
        assert_eq!(total, expected, "{section}");
    }
    let ballots = page(
        &fixture,
        json!({"pool_id":POOL,"completion_id":id,"section":"ballots","limit":10}),
    )
    .unwrap();
    let text = serde_json::to_string(&ballots).unwrap();
    assert!(text.contains("managed_attempt_v1") && text.contains("Checked by member-1."));
    // Cursor fences: foreign section, digest or completion fail explicitly.
    let mut cursor = serde_json::to_value(first_cursor(&fixture, &id, "roster")).unwrap();
    assert_eq!(
        page(
            &fixture,
            json!({"pool_id":POOL,"completion_id":id,"section":"ballots","after":cursor,"limit":1})
        )
        .err(),
        Some(Fault::Stale)
    );
    cursor["record_digest"] = json!("0".repeat(64));
    assert_eq!(
        page(
            &fixture,
            json!({"pool_id":POOL,"completion_id":id,"section":"roster","after":cursor,"limit":1})
        )
        .err(),
        Some(Fault::Stale)
    );
    cursor["record_digest"] = json!(digest);
    cursor["position"] = json!("99");
    assert_eq!(
        page(
            &fixture,
            json!({"pool_id":POOL,"completion_id":id,"section":"roster","after":cursor,"limit":1})
        )
        .err(),
        Some(Fault::Stale)
    );
    assert_eq!(
        page(
            &fixture,
            json!({"pool_id":"other","completion_id":id,"section":"header","limit":1})
        )
        .err(),
        Some(Fault::Forbidden)
    );
    assert_eq!(
        page(
            &fixture,
            json!({"pool_id":POOL,"completion_id":"missing","section":"header","limit":1})
        )
        .err(),
        Some(Fault::Forbidden)
    );
    assert_eq!(
        page(
            &fixture,
            json!({"pool_id":POOL,"completion_id":id,"section":"header","limit":11})
        )
        .err(),
        Some(Fault::Invalid)
    );
    // No key material, key reference or signature reaches any owner page.
    let (key_ref, public): (String, String) = fixture.with(|db| {
        db.query_row(
            "SELECT key_ref,verifying_key FROM completion_sagas WHERE id=?1",
            [&saga],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
    });
    for section in [
        "header",
        "content",
        "roster",
        "ballots",
        "run_facts",
        "notice",
    ] {
        let text = serde_json::to_string(
            &page(
                &fixture,
                json!({"pool_id":POOL,"completion_id":id,"section":section,"limit":10}),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(
            !text.contains(&key_ref) && !text.contains(&public),
            "{section}"
        );
        assert!(
            !text.contains("completion-keys") && !text.contains(".key"),
            "{section}"
        );
    }
    // Records and observations are immutable and retained.
    assert!(
        fixture
            .with(|db| db.execute("UPDATE completion_records SET record='{}'", []))
            .is_err()
    );
    assert!(
        fixture
            .with(|db| db.execute("DELETE FROM completion_records", []))
            .is_err()
    );
    assert!(
        fixture
            .with(|db| db.execute("DELETE FROM completion_observations", []))
            .is_err()
    );
    // An altered record fails closed even if an operator removes the trigger.
    fixture.with(|db| {
        db.execute_batch("DROP TRIGGER completion_record_immutable; UPDATE completion_records SET record=replace(record,'Result ready.','Result forged.');").unwrap();
    });
    assert_eq!(
        page(
            &fixture,
            json!({"pool_id":POOL,"completion_id":id,"section":"header","limit":1})
        )
        .err(),
        Some(Fault::Internal)
    );

    // Absent and empty snapshots are distinct, explicit facts.
    let mut digests = Vec::new();
    for snapshot in [None, Some(String::new())] {
        let fixture = self::fixture(Options {
            snapshot: snapshot.clone(),
            ..Options::default()
        });
        run_to_end(&fixture, &FakeRun::new()).await.unwrap();
        let id = completion_id(&fixture);
        let header = page(
            &fixture,
            json!({"pool_id":POOL,"completion_id":id,"section":"header","limit":1}),
        )
        .unwrap();
        let head = header.header.unwrap();
        assert_eq!(head.snapshot_present, snapshot.is_some());
        let field = head.content.iter().find(|f| f.field == "snapshot").unwrap();
        assert_eq!(field.present, snapshot.is_some());
        let content = page(
            &fixture,
            json!({"pool_id":POOL,"completion_id":id,"section":"content","limit":10}),
        )
        .unwrap();
        let slices = content
            .items
            .iter()
            .filter(|item| matches!(item, Item::Content { field, .. } if field == "snapshot"))
            .count();
        assert_eq!(slices, usize::from(snapshot.is_some()));
        digests.push(header.record_digest);
    }
    assert_ne!(digests[0], digests[1]);
}
fn first_cursor(fixture: &Fixture, id: &str, section: &str) -> completion::Cursor {
    page(
        fixture,
        json!({"pool_id":POOL,"completion_id":id,"section":section,"limit":1}),
    )
    .unwrap()
    .next_cursor
    .unwrap()
}

/// Published cross-language vectors for the record and observation digests.
#[test]
fn p3_completion_record_vectors() {
    let text = completion::Text::new;
    let body = |snapshot: Option<&str>| completion::RecordBody {
        completion_id: "00000000-0000-4000-8000-000000000001".into(),
        pool_store_id: "00000000-0000-4000-8000-000000000002".into(),
        pool_id: "pool".into(),
        commit_sequence: 1,
        record_version: 1,
        source_revision: 7,
        proposal_id: "proposal".into(),
        proposal_event_sequence: 12,
        goal: completion::Goal {
            name: text("Pool"),
            purpose: text("Goal"),
        },
        criteria: completion::Criteria {
            kind: "legacy".into(),
            text: text("Criteria"),
            acceptance: None,
        },
        result: text("Result"),
        snapshot_present: snapshot.is_some(),
        snapshot_bytes: snapshot.map(text),
        roster: completion::Roster {
            roster_key: "rk".into(),
            binding_epoch: 1,
            voters: vec![],
            members: vec![],
        },
        leader: completion::Leader {
            leader_id: "leader".into(),
        },
        ballots: vec![],
        run_evidence: completion::RunEvidence {
            run_store_id: RUN_STORE.into(),
            route_digest: "0".repeat(64),
            hold: completion::HoldFacts {
                request_id: "agent-pool.completion.saga".into(),
                hold_id: "hold_0123456789ab4cde8f0123456789abcd".into(),
                fingerprint: "1".repeat(64),
                intent_digest: "2".repeat(64),
                state_at_commit: "active".into(),
            },
            status_observed_at: "1792000000.5".into(),
            scope: "scope".into(),
            targets: vec![],
        },
        notice_intent: completion::NoticeIntent {
            operation_id: "effect".into(),
            recipient: "owner".into(),
            scope: "owner:pool".into(),
            payload_sha256: "3".repeat(64),
            payload_length: 5,
        },
        notice_observed_outcome: "pending".into(),
        integrity_algorithm: completion::INTEGRITY_ALGORITHM.into(),
    };
    let vectors: Vec<_> = [None, Some(""), Some("snap")]
        .into_iter()
        .map(|snapshot| completion::record_digest(&body(snapshot)).unwrap())
        .collect();
    assert_eq!(
        vectors,
        VECTORS
            .iter()
            .map(|(l, d)| (*l, (*d).to_owned()))
            .collect::<Vec<_>>()
    );
    let observation = completion::observation_digest(
        "00000000-0000-4000-8000-000000000001",
        VECTORS[0].1,
        "release",
        &json!({"hold_id":"hold_0123456789ab4cde8f0123456789abcd","state":"released","already_released":false,"observed_at_unix_ms":"1"}),
    )
    .unwrap();
    assert_eq!(observation, OBSERVATION_VECTOR);
}
/// Independently reproduced outside Rust; see the Completion section of pool-p1-wire.md.
const VECTORS: [(usize, &str); 3] = [
    (
        2189,
        "d33719dd505d284d4d4eb357bcb3a062bb263d6476ed78364f28eda503d55778",
    ),
    (
        2313,
        "61d9a1df5655a0cf8739efdb607fb63bd957684bb9cd0d92dd4583ad905271d7",
    ),
    (
        2317,
        "f31c939fd894b5007b2c3833b162d98fad90410ab6f3e28670f71a24fa46a806",
    ),
];
const OBSERVATION_VECTOR: &str = "b064aac1d9a85278def8314c8e1fe6c6b233c94a284464b750f78fb158254b9a";

/// Missing keys, changed routes or stores keep recovery unresolved; no TTL
/// unlock, no regenerated key; explicit operator repair resumes the same saga.
#[tokio::test]
async fn p3_key_route_loss() {
    // Before any acquire is possible a lost key aborts without contacting Run.
    let fixture = fixture(Options::default());
    let run = FakeRun::new();
    let mut driver = driver(&fixture, &run);
    let saga = driver.start(&fixture.store(), POOL).await.unwrap().unwrap();
    let key_ref: String = fixture.with(|db| {
        db.query_row(
            "SELECT key_ref FROM completion_sagas WHERE id=?1",
            [&saga],
            |r| r.get(0),
        )
        .unwrap()
    });
    std::fs::remove_file(fixture.keys.key_path(&key_ref)).unwrap();
    driver.advance(&fixture.store(), &saga).await.unwrap();
    let (stage, outcome, _) = fixture.stage(&saga);
    assert_eq!(
        (stage.as_str(), outcome.as_deref()),
        ("released", Some("aborted"))
    );
    assert!(!run.state().calls.contains(&"acquire"));

    // After commit a lost key leaves the hold active; nothing regenerates or unlocks it.
    let fixture = self::fixture(Options::default());
    let run = FakeRun::new();
    let mut driver = self::driver(&fixture, &run);
    let saga = driver.start(&fixture.store(), POOL).await.unwrap().unwrap();
    for _ in 0..2 {
        driver.step(&fixture.store(), &saga).await.unwrap();
    }
    assert_eq!(fixture.stage(&saga).0, "committed");
    let key_ref: String = fixture.with(|db| {
        db.query_row(
            "SELECT key_ref FROM completion_sagas WHERE id=?1",
            [&saga],
            |r| r.get(0),
        )
        .unwrap()
    });
    let path = fixture.keys.key_path(&key_ref);
    let backup = std::fs::read(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    for _ in 0..4 {
        driver.advance(&fixture.store(), &saga).await.unwrap();
    }
    let (stage, _, attention) = fixture.stage(&saga);
    assert_eq!(
        (stage.as_str(), attention.as_deref()),
        ("release_pending", Some("key_unavailable"))
    );
    assert_eq!(run.active_holds(), 1);
    assert_eq!(fixture.key_files(), 0, "no automatic key regeneration");
    // A substituted key cannot sign for the frozen public key.
    std::fs::write(&path, [9_u8; 32]).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    driver.advance(&fixture.store(), &saga).await.unwrap();
    assert_eq!(run.active_holds(), 1);
    // Operator restores the original key from backup: the same hold is released.
    std::fs::write(&path, &backup).unwrap();
    driver.advance(&fixture.store(), &saga).await.unwrap();
    assert_eq!(fixture.stage(&saga).0, "released");
    assert_eq!(run.active_holds(), 0);

    // A changed configured route performs no Run I/O and keeps the original stage.
    let fixture = self::fixture(Options::default());
    let run = FakeRun::new();
    let mut driver = self::driver(&fixture, &run);
    let saga = driver.start(&fixture.store(), POOL).await.unwrap().unwrap();
    driver.step(&fixture.store(), &saga).await.unwrap();
    assert_eq!(fixture.stage(&saga).0, "held");
    run.state().route.socket = "/fixture/other.sock".into();
    let calls = run.state().calls.len();
    driver.advance(&fixture.store(), &saga).await.unwrap();
    let (stage, _, attention) = fixture.stage(&saga);
    assert_eq!(
        (stage.as_str(), attention.as_deref()),
        ("held", Some("route_changed"))
    );
    assert_eq!(run.state().calls.len(), calls);
    run.state().route.socket = "/fixture/run.sock".into();
    driver.advance(&fixture.store(), &saga).await.unwrap();
    assert_eq!(fixture.stage(&saga).0, "released");

    // A changed Run store identity refuses the acquire; the saga stays recoverable.
    let fixture = self::fixture(Options::default());
    let run = FakeRun::new();
    let mut driver = self::driver(&fixture, &run);
    let saga = driver.start(&fixture.store(), POOL).await.unwrap().unwrap();
    fixture.with(|db| completion::mark_acquire_possible(db, &saga).unwrap());
    run.state().store_id = "store_ffffffffffffffffffffffffffffffff".into();
    driver.advance(&fixture.store(), &saga).await.unwrap();
    assert_eq!(fixture.stage(&saga).0, "acquire_possible");
    assert_eq!(run.state().created, 0);
    // Bounded failures fence the Pool outcome; exact replay continues, never a new key.
    driver.advance(&fixture.store(), &saga).await.unwrap();
    driver.advance(&fixture.store(), &saga).await.unwrap();
    let (stage, outcome, _) = fixture.stage(&saga);
    assert_eq!(
        (stage.as_str(), outcome.as_deref()),
        ("acquire_possible", Some("aborted"))
    );
    // A delayed acquire that later succeeds is found and released, never committed.
    run.state().store_id = RUN_STORE.into();
    driver.advance(&fixture.store(), &saga).await.unwrap();
    let (stage, outcome, _) = fixture.stage(&saga);
    assert_eq!(
        (stage.as_str(), outcome.as_deref()),
        ("released", Some("aborted"))
    );
    let created = run.state().created;
    assert_eq!((created, run.active_holds()), (1, 0));
    assert_eq!(record_count(&fixture), 0);
    // The pool may then settle under a new saga with a new key and request ID.
    let next = driver.start(&fixture.store(), POOL).await.unwrap().unwrap();
    assert_ne!(next, saga);
    driver.advance(&fixture.store(), &next).await.unwrap();
    assert_eq!(record_count(&fixture), 1);
    let created = run.state().created;
    assert_eq!((created, run.active_holds()), (2, 0));
}

/// Reconstruct the schema produced by the attempt-binding branch at v9/v10/v11.
fn downgrade_for_completion_test(db: &rusqlite::Connection, version: i64) {
    db.execute_batch(completion::TEST_DROP_SCHEMA).unwrap();
    for table in ["managed_route_pin_history", "managed_namespace_retirements"] {
        for action in ["INSERT", "UPDATE", "DELETE"] {
            db.execute_batch(&format!(
                "DROP TRIGGER IF EXISTS inventory_rev_{table}_{action};"
            ))
            .unwrap();
        }
    }
    if version == 9 {
        crate::managed_egress::drop_test_schema(db).unwrap();
    } else if version == 10 {
        db.execute_batch("DROP TABLE managed_namespace_retirements; DROP TABLE managed_route_pin_history; ALTER TABLE managed_bootstrap DROP COLUMN bridge_pin; ALTER TABLE managed_run_routes DROP COLUMN pool_route; ALTER TABLE managed_delivery_seeds DROP COLUMN issuer_namespace;").unwrap();
    }
    db.execute_batch(&format!("PRAGMA user_version={version};"))
        .unwrap();
}

/// Upgrade every pre-completion attempt-binding schema without inventing records.
#[test]
fn p3_completion_migration_history_and_downgrade() {
    assert_eq!(
        i64::from(family_delivery::CURRENT_STATE_SCHEMA),
        completion::SCHEMA_VERSION
    );
    for prior in [9, 10, 11] {
        let dir = private_dir();
        let path = dir.path().join("pool.db");
        {
            let mut store = Store::open(&path).unwrap();
            let db = store.completion_db();
            db.execute(
                "INSERT INTO leaders(actor,address) VALUES('owner','owner-address')",
                [],
            )
            .unwrap();
            db.execute("INSERT INTO pools(id,owner,data) VALUES('legacy','owner',?1)", [r#"{"pool_id":"legacy","name":"legacy","purpose":"goal","revision":3,"closed":true,"proposal":{"proposal_id":"p","roster_key":"k","voters":[],"result":"r","criteria":"c","state":"accepted","votes":{}}}"#]).unwrap();
            downgrade_for_completion_test(db, prior);
        }
        let store = Store::open(&path).unwrap();
        let request: crate::observer::Request = serde_json::from_value(json!({"schema_version":1,"operation":"inventory_snapshot","params":{"filter":"all","limit":10}})).unwrap();
        let totals =
            serde_json::to_value(store.observe(&request).unwrap()).unwrap()["totals"].clone();
        assert_eq!(
            totals,
            json!({"total":"1","open":"1","completed":"0","unknown":"0","closed":"1"})
        );
        drop(store);
        let db = rusqlite::Connection::open(&path).unwrap();
        assert_eq!(
            db.query_row::<i64, _, _>("PRAGMA user_version", [], |r| r.get(0))
                .unwrap(),
            completion::SCHEMA_VERSION
        );
        assert_eq!(
            db.query_row::<i64, _, _>("SELECT count(*) FROM completion_records", [], |r| r.get(0))
                .unwrap(),
            0
        );
        let triggers: i64 = db.query_row("SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name IN (SELECT 'inventory_rev_' || t.name || '_' || a.action FROM (SELECT 'completion_sagas' AS name UNION ALL SELECT 'completion_records' UNION ALL SELECT 'completion_observations' UNION ALL SELECT 'managed_delivery_seeds' UNION ALL SELECT 'managed_delivery_outbox' UNION ALL SELECT 'managed_delivery_scopes' UNION ALL SELECT 'managed_route_pin_history' UNION ALL SELECT 'managed_namespace_retirements') t CROSS JOIN (SELECT 'INSERT' AS action UNION ALL SELECT 'UPDATE' UNION ALL SELECT 'DELETE') a)", [], |r| r.get(0)).unwrap();
        assert_eq!(
            triggers, 18,
            "only inventory-visible durable tables fence inventory after v{prior}"
        );
    }
    // Step v14 only adds the immutable late-admission receipt table.
    let dir = private_dir();
    let path = dir.path().join("pool.db");
    drop(Store::open(&path).unwrap());
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute_batch("DROP TABLE completed_admissions; PRAGMA user_version=13;")
        .unwrap();
    drop(Store::open(&path).unwrap());
    let db = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        db.query_row::<i64, _, _>("PRAGMA user_version", [], |r| r.get(0))
            .unwrap(),
        14
    );
    assert_eq!(
        db.query_row::<i64, _, _>("SELECT count(*) FROM sqlite_master WHERE name IN ('completed_admissions','completed_admission_immutable','completed_admission_retained')", [], |r| r.get(0))
            .unwrap(),
        3
    );
}

#[test]
fn review_v13_migration_preserves_prepared_retirement_and_rolls_back_on_failure() {
    let dir = private_dir();
    let path = dir.path().join("pool.db");
    {
        let mut store = Store::open(&path).unwrap();
        let db = store.completion_db();
        db.execute("INSERT INTO leaders VALUES('owner','address')", [])
            .unwrap();
        db.execute("INSERT INTO pools VALUES('p','owner','{}')", [])
            .unwrap();
        db.execute("INSERT INTO managed_delivery_scopes(producer_scope,pool_id,state,retire_request_id,bridge_pin,audience) VALUES('open','p','open','a','old','aud'),('drain','p','draining','b','old','aud'),('retire','p','retiring','c','frozen','aud')", []).unwrap();
        for table in ["completion_sagas", "completion_observations"] {
            for action in ["INSERT", "UPDATE", "DELETE"] {
                db.execute_batch(&format!("CREATE TRIGGER inventory_rev_{table}_{action} AFTER {action} ON {table} BEGIN UPDATE inventory_source SET revision=revision+1 WHERE singleton=1; END;")).unwrap();
            }
        }
        db.execute_batch(
            "DROP TABLE completed_admissions; PRAGMA user_version=12; DROP TRIGGER inventory_rev_completion_sagas_INSERT;",
        )
        .unwrap();
    }
    assert!(Store::open(&path).is_err());
    {
        let db = rusqlite::Connection::open(&path).unwrap();
        assert_eq!(
            db.query_row::<i64, _, _>("PRAGMA user_version", [], |r| r.get(0))
                .unwrap(),
            12
        );
        assert_eq!(
            db.query_row::<String, _, _>(
                "SELECT bridge_pin FROM managed_delivery_scopes WHERE producer_scope='open'",
                [],
                |r| r.get(0)
            )
            .unwrap(),
            "old"
        );
        db.execute_batch("CREATE TRIGGER inventory_rev_completion_sagas_INSERT AFTER INSERT ON completion_sagas BEGIN UPDATE inventory_source SET revision=revision+1 WHERE singleton=1; END;").unwrap();
    }
    let mut store = Store::open(&path).unwrap();
    let db = store.completion_db();
    assert_eq!(db.query_row::<i64,_,_>("SELECT count(*) FROM managed_delivery_scopes WHERE state IN ('open','draining') AND bridge_pin IS NULL AND audience IS NULL", [], |r| r.get(0)).unwrap(), 2);
    assert_eq!(
        db.query_row::<String, _, _>(
            "SELECT bridge_pin FROM managed_delivery_scopes WHERE state='retiring'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        "frozen"
    );
    assert!(
        db.execute(
            "UPDATE managed_delivery_scopes SET bridge_pin='changed' WHERE state='retiring'",
            []
        )
        .is_err()
    );
    assert_eq!(db.query_row::<i64,_,_>("SELECT count(*) FROM sqlite_master WHERE type='trigger' AND (name LIKE 'inventory_rev_completion_sagas_%' OR name LIKE 'inventory_rev_completion_observations_%')", [], |r| r.get(0)).unwrap(), 0);
}

/// Failures in the v11 and v12 steps roll back the entire upgrade; future schemas refuse.
#[test]
fn p3_completion_migration_failure_and_future_schema() {
    let dir = private_dir();
    let path = dir.path().join("pool.db");
    {
        let mut store = Store::open(&path).unwrap();
        let db = store.completion_db();
        db.execute(
            "INSERT INTO leaders(actor,address) VALUES('owner','owner-address')",
            [],
        )
        .unwrap();
        db.execute("INSERT INTO pools(id,owner,data) VALUES('legacy','owner',?1)", [r#"{"pool_id":"legacy","name":"legacy","purpose":"goal","revision":3,"closed":true,"proposal":{"proposal_id":"p","roster_key":"k","voters":[],"result":"r","criteria":"c","state":"accepted","votes":{}}}"#]).unwrap();
        downgrade_for_completion_test(db, 10);
        db.execute_batch("CREATE TABLE managed_namespace_retirements(sentinel TEXT); INSERT INTO managed_namespace_retirements VALUES('retained');").unwrap();
    }
    assert!(Store::open(&path).is_err());
    {
        let db = rusqlite::Connection::open(&path).unwrap();
        assert_eq!(
            db.query_row::<i64, _, _>("PRAGMA user_version", [], |r| r.get(0))
                .unwrap(),
            10
        );
        assert_eq!(
            db.query_row::<String, _, _>(
                "SELECT sentinel FROM managed_namespace_retirements",
                [],
                |r| r.get(0)
            )
            .unwrap(),
            "retained"
        );
        assert_eq!(
            db.query_row::<i64, _, _>(
                "SELECT count(*) FROM sqlite_master WHERE name='managed_route_pin_history'",
                [],
                |r| r.get(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(db.query_row::<i64, _, _>("SELECT count(*) FROM pragma_table_info('managed_delivery_seeds') WHERE name='issuer_namespace'", [], |r| r.get(0)).unwrap(), 0);
        db.execute_batch("DROP TABLE managed_namespace_retirements;")
            .unwrap();
    }
    let mut store = Store::open(&path).unwrap();
    downgrade_for_completion_test(store.completion_db(), 11);
    drop(store);
    // A failed completion step leaves v11 and all prior state intact.
    {
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE completion_records(sentinel TEXT); INSERT INTO completion_records VALUES('retained');").unwrap();
    }
    assert!(Store::open(&path).is_err());
    {
        let db = rusqlite::Connection::open(&path).unwrap();
        let version: i64 = db
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, 11);
        let sentinel: String = db
            .query_row("SELECT sentinel FROM completion_records", [], |r| r.get(0))
            .unwrap();
        assert_eq!(sentinel, "retained");
        assert_eq!(
            db.query_row::<i64, _, _>(
                "SELECT count(*) FROM sqlite_master WHERE name='completion_sagas'",
                [],
                |r| r.get(0)
            )
            .unwrap(),
            0
        );
        let pools: i64 = db
            .query_row("SELECT count(*) FROM pools", [], |r| r.get(0))
            .unwrap();
        assert_eq!(pools, 1);
        // An older binary sees a newer schema and must refuse rather than roll back.
        db.execute_batch(&format!(
            "DROP TABLE completion_records; PRAGMA user_version={};",
            completion::SCHEMA_VERSION + 1
        ))
        .unwrap();
    }
    assert_eq!(Store::open(&path).err(), Some(Fault::Conflict));
}

/// The owner protocol validates completion reads and advertises the capabilities.
#[test]
fn p3_completion_owner_protocol() {
    let request: crate::observer::Request = serde_json::from_value(json!({"schema_version":1,"operation":"completion_get","params":{"pool_id":"pool","completion_id":"c","section":"notice","limit":3}})).unwrap();
    request.validate().unwrap();
    assert_eq!(request.kind(), "completion_page");
    for params in [
        json!({"pool_id":"pool","completion_id":"c","section":"header","limit":0}),
        json!({"pool_id":"pool","completion_id":"c","section":"header","limit":1,"after":{"version":1,"completion_id":"c","record_digest":"d","section":"header","position":"1"}}),
        json!({"pool_id":"pool","completion_id":"c","section":"secrets","limit":1}),
        json!({"pool_id":"pool","completion_id":"c","section":"header","limit":1,"extra":true}),
    ] {
        let parsed: Result<crate::observer::Request, _> = serde_json::from_value(
            json!({"schema_version":1,"operation":"completion_get","params":params}),
        );
        assert!(parsed.is_err() || parsed.unwrap().validate().is_err());
    }
    let identity = serde_json::to_value(crate::observer::Envelope::identity().unwrap()).unwrap();
    let capabilities = identity["capabilities"].as_array().unwrap();
    assert!(capabilities.contains(&json!("completion_record_v1")));
    assert!(capabilities.contains(&json!("inventory_completion_v1")));
}

/// Stateful synthetic Run hold v1 over the real operator-socket JSON-RPC framing.
#[derive(Default)]
struct HoldServer {
    holds: HashMap<String, (String, String, String, [u8; 32], serde_json::Value)>,
    lose_next: Option<&'static str>,
    acquires: usize,
    created: usize,
    releases: usize,
}
fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}
fn hold_reply(
    state: &Mutex<HoldServer>,
    method: &str,
    params: &serde_json::Value,
) -> Option<serde_json::Value> {
    let mut server = state.lock().unwrap();
    let lose = server.lose_next == Some(method);
    if lose {
        server.lose_next = None;
    }
    let store = params["expected_store_id"].as_str().unwrap_or_default();
    if method != "capabilities" && store != RUN_STORE {
        return Some(json!({"error":{"code":-32602,"message":"store mismatch"}}));
    }
    let result = match method {
        "capabilities" => json!({"schema_version":1,"product":"agent-run","store_id":RUN_STORE,
            "lineage_holds":{"version":1,"transport":"operator_socket","acquire":"_lineage_hold_acquire",
            "lookup":"_lineage_hold_lookup","list":"_lineage_hold_list","release":"_lineage_hold_release"}}),
        "_lineage_hold_acquire" => {
            server.acquires += 1;
            let targets: Vec<Target> = serde_json::from_value(params["targets"].clone()).unwrap();
            let roots: Vec<String> = targets.iter().map(|t| t.agent_id.clone()).collect();
            let key: [u8; 32] = unhex(params["verifying_key"].as_str().unwrap())
                .try_into()
                .unwrap();
            let digest = params["intent_digest"]
                .as_str()
                .map(|d| <[u8; 32]>::try_from(unhex(d)).unwrap());
            let request = params["request_id"].as_str().unwrap().to_owned();
            let fingerprint = HoldIntent::new(
                RUN_STORE.into(),
                request.clone(),
                targets.clone(),
                roots.clone(),
                key,
                digest,
            )
            .unwrap()
            .fingerprint()
            .to_owned();
            if let Some((hold_id, existing, state, _, receipt)) = server.holds.get(&request) {
                if *existing != fingerprint {
                    return Some(json!({"error":{"code":-32602,"message":"intent conflict"}}));
                }
                let _ = hold_id;
                json!({"receipt":receipt,"state":state,"replayed":true})
            } else {
                let hold_id = format!("hold_{}", uuid::Uuid::new_v4().simple());
                let receipt = json!({"version":1,"store_id":RUN_STORE,"hold_id":hold_id,"fingerprint":fingerprint,"targets":targets,"canonical_roots":roots});
                server.holds.insert(
                    request,
                    (hold_id, fingerprint, "active".into(), key, receipt.clone()),
                );
                server.created += 1;
                json!({"receipt":receipt,"state":"active","replayed":false})
            }
        }
        "_lineage_hold_lookup" => match server.holds.get(params["request_id"].as_str().unwrap()) {
            Some((_, fingerprint, state, _, receipt))
                if fingerprint == params["fingerprint"].as_str().unwrap() =>
            {
                json!({"store_id":RUN_STORE,"found":true,"receipt":receipt,"state":state})
            }
            _ => json!({"store_id":RUN_STORE,"found":false}),
        },
        "_lineage_hold_release" => {
            let hold_id = params["hold_id"].as_str().unwrap();
            let signature: [u8; 64] = unhex(params["signature"].as_str().unwrap())
                .try_into()
                .unwrap();
            let Some(entry) = server.holds.values_mut().find(|entry| entry.0 == hold_id) else {
                return Some(json!({"result":{"store_id":RUN_STORE,"found":false}}));
            };
            let mut message = b"agent-run:lineage-hold:release:v1\0".to_vec();
            message.extend(unhex(&RUN_STORE[6..]));
            message.extend(unhex(&hold_id[5..]));
            message.extend(unhex(&entry.1));
            if VerifyingKey::from_bytes(&entry.3)
                .and_then(|key| key.verify_strict(&message, &Signature::from_bytes(&signature)))
                .is_err()
            {
                return Some(json!({"error":{"code":-32602,"message":"invalid release proof"}}));
            }
            let already = entry.2 == "released";
            entry.2 = "released".into();
            server.releases += 1;
            json!({"store_id":RUN_STORE,"found":true,"hold_id":hold_id,"state":"released","already_released":already})
        }
        _ => return Some(json!({"error":{"code":-32601,"message":"unknown"}})),
    };
    (!lose).then(|| json!({"result":result}))
}
async fn serve_holds(listener: tokio::net::UnixListener, state: Arc<Mutex<HoldServer>>) {
    use tokio::io::AsyncWriteExt;
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(frame) = crate::integrations::read_frame(&mut stream).await else {
            continue;
        };
        let request: serde_json::Value = serde_json::from_slice(&frame).unwrap();
        let Some(mut reply) = hold_reply(
            &state,
            request["method"].as_str().unwrap(),
            &request["params"],
        ) else {
            continue; // Lost acknowledgement after the durable effect.
        };
        reply["jsonrpc"] = json!("2.0");
        reply["id"] = request["id"].clone();
        let mut bytes = serde_json::to_vec(&reply).unwrap();
        bytes.push(b'\n');
        let _ = stream.write_all(&bytes).await;
    }
}
/// Consensus and status from the synthetic Run, holds through the production adapter.
struct HybridRun {
    fake: FakeRun,
    real: crate::completion_saga::ConfiguredRun,
}
impl SettlementRun for HybridRun {
    fn configured_route(&self) -> Result<RunRoute, Fault> {
        self.real.configured_route()
    }
    async fn consensus(
        &self,
        store: &SharedStore,
        voters: &[VerifiedBallot],
    ) -> Vec<Result<VoterObservation, Fault>> {
        self.fake.consensus(store, voters).await
    }
    async fn status(
        &self,
        store_id: &str,
        targets: &[Target],
    ) -> Result<(String, Vec<StatusFact>), Fault> {
        self.fake.status(store_id, targets).await
    }
    async fn discover(&self, store_id: &str) -> Result<(), HoldError> {
        self.real.discover(store_id).await
    }
    async fn acquire(
        &self,
        intent: &HoldIntent,
        prior: Option<&HoldObservation>,
    ) -> Result<AcquireResult, HoldError> {
        self.real.acquire(intent, prior).await
    }
    async fn lookup(
        &self,
        intent: &HoldIntent,
        prior: Option<&HoldObservation>,
    ) -> Result<LookupResult, HoldError> {
        self.real.lookup(intent, prior).await
    }
    async fn release(
        &self,
        intent: &HoldIntent,
        prior: &HoldObservation,
        signature: &[u8; 64],
    ) -> Result<ReleaseResult, HoldError> {
        self.real.release(intent, prior, signature).await
    }
}

/// The saga drives the unchanged hold v1 client over a real socket: lost
/// acquire and release ACKs recover with one hold, the same fingerprint and an
/// exactly replayed signed release; wrong proofs and stores are refused.
#[tokio::test]
async fn p3_hold_lost_ack_release_over_operator_socket() {
    let fixture = fixture(Options::default());
    let sockets = private_dir();
    let uid = std::fs::metadata(sockets.path()).unwrap().uid();
    let socket = sockets.path().join("run.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let server = Arc::new(Mutex::new(HoldServer::default()));
    let task = tokio::spawn(serve_holds(listener, Arc::clone(&server)));
    let config = crate::config::Config {
        socket_path: sockets.path().join("pool.sock"),
        database_path: fixture.db_path(),
        expected_uid: uid,
        bridge_registration_socket: sockets.path().join("bridge.sock"),
        bridge_core_socket: sockets.path().join("core.sock"),
        bridge_credential_file: sockets.path().join("token"),
        bridge_producer_id: "test".into(),
        bridge_audience: "test".into(),
        bridge_server_executable: "/fixture/bridge".into(),
        bridge_server_sha256: "0".repeat(64),
        bridge_observer_socket: None,
        bridge_observer_credential_file: None,
        owner_observer_credential_file: None,
        run_socket: Some(socket.clone()),
        run_peer_uid: None,
        managed_run_reader: None,
        managed_run_transport: None,
    };
    // Settlement stays off without the managed consensus transport.
    assert!(Driver::production(&config, &crate::domain::id()).is_none());
    let run = HybridRun {
        fake: FakeRun::new(),
        real: crate::completion_saga::ConfiguredRun::new(config.clone()),
    };
    let mut driver = Driver::new(run, fixture.keys.clone());
    server.lock().unwrap().lose_next = Some("_lineage_hold_acquire");
    let saga = driver.start(&fixture.store(), POOL).await.unwrap().unwrap();
    driver.advance(&fixture.store(), &saga).await.unwrap();
    assert_eq!(fixture.stage(&saga).0, "acquire_possible");
    server.lock().unwrap().lose_next = Some("_lineage_hold_release");
    driver.advance(&fixture.store(), &saga).await.unwrap();
    assert_eq!(fixture.stage(&saga).0, "release_pending");
    assert_eq!(record_count(&fixture), 1);
    driver.advance(&fixture.store(), &saga).await.unwrap();
    assert_eq!(fixture.stage(&saga).0, "released");
    {
        let server = server.lock().unwrap();
        assert_eq!(
            (server.created, server.acquires, server.releases),
            (1, 1, 2)
        );
        assert!(server.holds.values().all(|entry| entry.2 == "released"));
    }
    // Exact replay returns the released receipt, which cannot authorize a new CAS.
    let loaded = fixture.with(|db| completion::load(db, &saga).unwrap());
    let replay = crate::run_hold::acquire(&config, &loaded.intent, None)
        .await
        .unwrap();
    assert!(replay.replayed && replay.observation.state() == HoldState::Released);
    let observation = replay.observation.clone();
    assert_eq!(
        crate::run_hold::release(&config, &loaded.intent, &observation, &[0; 64])
            .await
            .err(),
        Some(HoldError::Unknown)
    );
    // A different store identity is refused by Run before any effect.
    let (_, request, targets, roots, key) = loaded.intent.fixture_view();
    let foreign = HoldIntent::new(
        "store_ffffffffffffffffffffffffffffffff".into(),
        format!("{request}-foreign"),
        targets.to_vec(),
        roots.to_vec(),
        key,
        None,
    )
    .unwrap();
    assert!(
        crate::run_hold::acquire(&config, &foreign, None)
            .await
            .is_err()
    );
    assert_eq!(server.lock().unwrap().created, 1);
    task.abort();
}

/// Fixture-local Pool config pointing Run at a private synthetic socket.
fn worker_config(fixture: &Fixture, sockets: &tempfile::TempDir) -> crate::config::Config {
    let uid = std::fs::metadata(sockets.path()).unwrap().uid();
    crate::config::Config {
        socket_path: sockets.path().join("pool.sock"),
        database_path: fixture.db_path(),
        expected_uid: uid,
        bridge_registration_socket: sockets.path().join("bridge.sock"),
        bridge_core_socket: sockets.path().join("core.sock"),
        bridge_credential_file: sockets.path().join("token"),
        bridge_producer_id: "test".into(),
        bridge_audience: "test".into(),
        bridge_server_executable: "/fixture/bridge".into(),
        bridge_server_sha256: "0".repeat(64),
        bridge_observer_socket: None,
        bridge_observer_credential_file: None,
        owner_observer_credential_file: None,
        run_socket: Some(sockets.path().join("run.sock")),
        run_peer_uid: None,
        managed_run_reader: None,
        managed_run_transport: None,
    }
}

/// Polls a fixture condition while the worker runs, failing if the worker exits.
async fn wait_for(
    fixture: &Fixture,
    worker: &mut tokio::task::JoinHandle<Result<(), Fault>>,
    label: &str,
    condition: impl Fn(&Fixture) -> bool,
) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !condition(fixture) {
        if worker.is_finished() {
            let result = worker.await;
            panic!("resident worker exited before {label}: {result:?}");
        }
        assert!(std::time::Instant::now() < deadline, "timed out: {label}");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// Recovery that finds an admission receipt after completion settles the
/// effect as terminal `reconciliation_needed` with the exact receipt; the
/// resident worker stays up, queues one owner notice, keeps dispatching later
/// effects and never redelivers the settled one.
#[tokio::test]
async fn completed_pool_late_start_recovery_keeps_worker_running() {
    use tokio::io::AsyncWriteExt;
    let fixture = fixture(Options::default());
    let run = FakeRun::new();
    run_to_end(&fixture, &run).await.unwrap();
    let sockets = private_dir();
    let config = worker_config(&fixture, &sockets);
    let socket = config.run_socket.clone().unwrap();
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let route = RunRoute {
        socket: socket.to_str().unwrap().into(),
        expected_uid: config.expected_uid,
        peer_uid: None,
        store_id: Some(RUN_STORE.into()),
    };
    // A current, never-bound member whose single-batch start outcome is unknown.
    let late = Binding {
        member: Member {
            member_id: "member-late".into(),
            name: "late worker".into(),
            role: "builder".into(),
            task: "late task".into(),
            state: MemberState::Active,
            runtime: "unknown".into(),
        },
        pool_id: POOL.into(),
        actor: None,
        address: None,
        run_id: None,
        run_sequence: None,
        run_execution_ref: None,
        run_pin_id: None,
        run_store_id: None,
    };
    let start = Effect {
        effect_id: "late-start".into(),
        pool_id: POOL.into(),
        member_id: Some("member-late".into()),
        state: "unknown".into(),
        work: Work::StartBatch {
            request_key: "late-request".into(),
            retain_history: true,
            store_fence: true,
            route_fence: true,
            route: Some(route.clone()),
            jobs: vec![BatchJob {
                member_id: "member-late".into(),
                spec: json!({}),
                original_spec: None,
            }],
        },
    };
    let released = target(96, 1).pin_id;
    let other = Effect {
        effect_id: "later-release".into(),
        pool_id: POOL.into(),
        member_id: None,
        state: "unknown".into(),
        work: Work::ReleasePin {
            pin_id: released.clone(),
            route: Some(route),
        },
    };
    fixture.with(|db| {
        // Deliverable owner notices need a real Bridge address; the completion
        // notice already queued for the placeholder address is not under test.
        db.execute(
            "UPDATE leaders SET address='local/codex/main/owner' WHERE actor='owner'",
            [],
        )
        .unwrap();
        db.execute(
            "UPDATE effects SET state='accepted' WHERE state='queued' AND json_extract(data,'$.work.scope')='owner:pool-c'",
            [],
        )
        .unwrap();
        db.execute(
            "INSERT INTO members(id,pool,actor,address,current,data) VALUES('member-late',?1,NULL,NULL,1,?2)",
            params![POOL, serde_json::to_string(&late).unwrap()],
        )
        .unwrap();
        for effect in [&start, &other] {
            db.execute(
                "INSERT INTO effects(id,pool,member,state,data) VALUES(?1,?2,?3,'unknown',?4)",
                params![
                    effect.effect_id,
                    POOL,
                    effect.member_id,
                    serde_json::to_string(effect).unwrap()
                ],
            )
            .unwrap();
        }
    });
    let execution_ref = format!("ex1_{}", "c".repeat(64));
    let pin = target(97, 1).pin_id;
    let receipt = json!({"version":1,"request_id":"late-request","store_id":RUN_STORE,"jobs":[
        {"index":0,"agent_id":agent(97),"sequence":1,"execution_ref":execution_ref,"pin_id":pin}]});
    let methods = Arc::new(Mutex::new(Vec::<String>::new()));
    let seen = Arc::clone(&methods);
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let Ok(frame) = crate::integrations::read_frame(&mut stream).await else {
                continue;
            };
            let request: serde_json::Value = serde_json::from_slice(&frame).unwrap();
            let method = request["method"].as_str().unwrap_or_default().to_owned();
            seen.lock().unwrap().push(method.clone());
            let result = match method.as_str() {
                "capabilities" => {
                    json!({"schema_version":1,"product":"agent-run","store_id":RUN_STORE})
                }
                "batch_receipt" => json!({"found":true,"receipt":receipt}),
                "history_pins" => json!({"pin_id":request["params"]["pin_id"],
                    "status":"released","already_released":false}),
                _ => continue,
            };
            let mut bytes =
                serde_json::to_vec(&json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
                    .unwrap();
            bytes.push(b'\n');
            let _ = stream.write_all(&bytes).await;
        }
    });
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let mut worker = tokio::spawn(crate::runtime::fixture_work(
        config,
        fixture.store(),
        stopped,
    ));
    wait_for(&fixture, &mut worker, "late start settles and later effect runs", |f| {
        f.count("SELECT count(*) FROM effects WHERE id='late-start' AND state='reconciliation_needed'") == 1
            && f.count("SELECT count(*) FROM effects WHERE id='later-release' AND state='accepted'") == 1
    })
    .await;
    // The next pass processes the queued owner notice; the settled effect stays settled.
    let notice = "SELECT count(*) FROM effects WHERE json_extract(data,'$.work.scope')='owner:pool-c' AND json_extract(data,'$.work.text') LIKE '%admission late-start needs owner reconciliation%'";
    wait_for(&fixture, &mut worker, "owner notice dispatched", |f| {
        f.count(&format!("{notice} AND state!='queued'")) == 1
    })
    .await;
    assert!(!worker.is_finished(), "resident worker must keep running");
    assert_eq!(fixture.count(notice), 1);
    assert_eq!(
        fixture.count(
            "SELECT count(*) FROM alerts WHERE effect='late-start' AND kind='completed_admission'"
        ),
        1
    );
    assert_eq!(
        fixture.with(|db| db
            .query_row::<String, _, _>(
                "SELECT receipt FROM completed_admissions WHERE effect='late-start'",
                [],
                |r| r.get(0)
            )
            .unwrap()),
        json!({"kind":"start_batch","store_id":RUN_STORE,"admissions":[{
            "agent_id":agent(97),"sequence":1,"execution_ref":execution_ref,"pin_id":pin}]})
        .to_string()
    );
    let binding: Binding = fixture.with(|db| {
        serde_json::from_str(
            &db.query_row::<String, _, _>(
                "SELECT data FROM members WHERE id='member-late'",
                [],
                |r| r.get(0),
            )
            .unwrap(),
        )
        .unwrap()
    });
    assert_eq!(
        binding.run_id, None,
        "a completed pool installs no late member"
    );
    assert_eq!(
        methods
            .lock()
            .unwrap()
            .iter()
            .filter(|method| *method == "batch_receipt")
            .count(),
        1,
        "the settled admission is never redelivered"
    );
    stop.send(true).unwrap();
    assert_eq!(worker.await.unwrap(), Ok(()));
    server.abort();
}

/// Two Pool databases share one private parent: starting B (migration and
/// sweep) while A holds an active hold never removes A's release key, and A
/// still releases with it.
#[tokio::test]
async fn two_pool_stores_in_one_parent_keep_active_release_keys() {
    let fixture = fixture(Options::default());
    let run = FakeRun::new();
    let mut driver = driver(&fixture, &run);
    let saga = driver.start(&fixture.store(), POOL).await.unwrap().unwrap();
    driver.step(&fixture.store(), &saga).await.unwrap();
    assert_eq!(fixture.stage(&saga).0, "held");
    assert_eq!(run.active_holds(), 1);
    assert_eq!(fixture.key_files(), 1);
    let other: SharedStore = Arc::new(Mutex::new(
        Store::open(&fixture.dir.path().join("other.db")).unwrap(),
    ));
    let other_id: String = other
        .lock()
        .unwrap()
        .completion_db()
        .query_row("SELECT store_id FROM inventory_source", [], |r| r.get(0))
        .unwrap();
    let uid = std::fs::metadata(fixture.dir.path()).unwrap().uid();
    for _ in 0..3 {
        let keys = KeyStore::open(&fixture.dir.path().join("other.db"), uid, &other_id).unwrap();
        Driver::new(FakeRun::new(), keys)
            .sweep(&other)
            .await
            .unwrap();
    }
    // A restarted A driver also sweeps only its own directory and keeps the key.
    driver.sweep(&fixture.store()).await.unwrap();
    assert_eq!(fixture.key_files(), 1, "B's startup kept A's active key");
    driver.advance(&fixture.store(), &saga).await.unwrap();
    assert_eq!(fixture.stage(&saga).0, "released");
    assert_eq!(record_count(&fixture), 1);
    assert_eq!(run.active_holds(), 0);
    assert_eq!(fixture.key_files(), 0);
}

/// Startup moves only this store's still-owned keys out of the legacy shared
/// directory; other legacy files stay untouched and the saga still releases.
#[tokio::test]
async fn driver_startup_migrates_owned_legacy_keys_only() {
    let fixture = fixture(Options::default());
    let run = FakeRun::new();
    let mut driver = driver(&fixture, &run);
    let saga = driver.start(&fixture.store(), POOL).await.unwrap().unwrap();
    driver.step(&fixture.store(), &saga).await.unwrap();
    let key_ref: String = fixture.with(|db| {
        db.query_row(
            "SELECT key_ref FROM completion_sagas WHERE id=?1",
            [&saga],
            |r| r.get(0),
        )
        .unwrap()
    });
    // Recreate the pre-isolation layout: the saga key and foreign files share the root.
    let root = fixture.dir.path().join("completion-keys");
    let legacy = root.join(format!("{key_ref}.key"));
    std::fs::rename(fixture.keys.key_path(&key_ref), &legacy).unwrap();
    let foreign = root.join(format!("{}.key", crate::domain::id()));
    std::fs::write(&foreign, [7_u8; 32]).unwrap();
    std::fs::set_permissions(&foreign, std::fs::Permissions::from_mode(0o600)).unwrap();
    let staged = root.join(format!("{}.tmp", crate::domain::id()));
    std::fs::write(&staged, [8_u8; 32]).unwrap();
    assert_eq!(fixture.key_files(), 0);
    driver.sweep(&fixture.store()).await.unwrap();
    assert_eq!(fixture.key_files(), 1);
    assert!(!legacy.exists());
    assert_eq!(std::fs::read(&foreign).unwrap(), [7_u8; 32]);
    assert_eq!(std::fs::read(&staged).unwrap(), [8_u8; 32]);
    driver.advance(&fixture.store(), &saga).await.unwrap();
    assert_eq!(fixture.stage(&saga).0, "released");
    assert_eq!(fixture.key_files(), 0);
    assert!(foreign.exists() && staged.exists());
}
