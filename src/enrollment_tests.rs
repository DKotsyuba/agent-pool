//! P3-E/P3-X acceptance rows (`enrollment-p3.md` §9) with a synthetic Run peer
//! behind the resident's enrollment client, real SQLite restarts and the real
//! store-level P1 join pipeline (context, intent, admission and domain CAS).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "Assertions in isolated synthetic fixtures"
)]
use crate::{
    domain::{
        Actor, Change, Command, Create, Disposition, EnrollmentGet, EnrollmentResolve, Fault,
        MemberState, Replace, Reply, Start, StartBatch, StartMember,
    },
    managed_enrollment::{
        self as journal, Admission, Attested, EnrollmentRoute, Failure, JobState, Key, Lookup,
        OldStatus, Qualification, StartReceipt,
    },
    managed_state::{
        AttemptRef, CurrentReceipt, Incarnation, ManagedActor, ManagedBinding, Route,
        RunEndpointPin, SuccessorLink, SuccessorProof,
    },
    run_status::Target,
    runtime::enrollment_dispatch::{self, Client, Response},
    store::Store,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
    sync::{Arc, Mutex},
};

const ROLE: &str = "managed";
const RUN_STORE: &str = "store_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// One admitted Run root as the synthetic peer remembers it.
#[derive(Clone)]
struct Root {
    admission: Admission,
    native: String,
    execution: String,
    sequence: u32,
    epoch: u64,
    launch: String,
    boot: String,
}

/// Durable synthetic Run state; survives Pool store restarts.
#[derive(Default)]
struct RunState {
    capability: bool,
    switch: bool,
    keys: BTreeMap<String, (String, Option<StartReceipt>, bool)>,
    roots: BTreeMap<String, Root>,
    admissions: usize,
    submits: usize,
    lookups: usize,
    aborts: usize,
    current_calls: usize,
    status_calls: usize,
    lose_submit_ack: bool,
    refuse_submit: Option<(&'static str, &'static str)>,
    lose_current_ack: bool,
    qualified: BTreeSet<String>,
    failed: BTreeSet<String>,
    role_digest_override: Option<String>,
    receipts: BTreeMap<String, CurrentReceipt>,
    status: Option<OldStatus>,
    route_override: Option<EnrollmentRoute>,
    in_progress_lookups: usize,
    counter: u64,
}

#[derive(Clone)]
struct SyntheticRun {
    state: Arc<Mutex<RunState>>,
    route: EnrollmentRoute,
}

fn agent(n: u64) -> String {
    format!("ag-20261110-120000-{n:010x}")
}
fn uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

impl SyntheticRun {
    fn state(&self) -> std::sync::MutexGuard<'_, RunState> {
        self.state.lock().unwrap()
    }
    fn validate(&self, params: &Value) -> Result<String, Failure> {
        let object = params.as_object().ok_or(Failure::Refused("invalid"))?;
        let keys: BTreeSet<_> = object.keys().map(String::as_str).collect();
        let expected: BTreeSet<_> = [
            "version",
            "expected_store_id",
            "pool_store_id",
            "pool_id",
            "request_id",
            "mode",
            "jobs",
            "preconditions",
        ]
        .into_iter()
        .collect();
        if keys != expected
            || params["version"] != json!(1)
            || params["expected_store_id"] != json!(RUN_STORE)
            || params["pool_store_id"] != json!(self.route.pool_route.component_store_id)
        {
            return Err(Failure::Refused("invalid"));
        }
        let jobs = params["jobs"]
            .as_array()
            .ok_or(Failure::Refused("invalid"))?;
        let conditions = params["preconditions"]
            .as_array()
            .ok_or(Failure::Refused("invalid"))?;
        if jobs.is_empty()
            || jobs.len() > 20
            || match params["mode"].as_str() {
                Some("start") => !conditions.is_empty(),
                Some("replace") => jobs.len() != 1 || conditions.len() != 1,
                _ => true,
            }
        {
            return Err(Failure::Refused("invalid"));
        }
        for job in jobs {
            let spec = &job["spec"];
            if job["selector"] != json!({"version":1,"role_name":ROLE})
                || spec["profile"] != json!(ROLE)
                || spec["explicit_finish"] != json!(true)
                || spec["write"] != json!(false)
                || spec.get("request_id").is_some()
            {
                return Err(Failure::Refused("role_mismatch"));
            }
        }
        Ok(journal::fingerprint(params).unwrap())
    }
    fn jobs_state(&self, state: &RunState, receipt: &StartReceipt) -> Vec<JobState> {
        receipt
            .jobs
            .iter()
            .map(|job| {
                let failed = state.failed.contains(&job.member_id);
                JobState {
                    index: job.index,
                    member_id: job.member_id.clone(),
                    state: if failed {
                        "terminal"
                    } else if state.qualified.contains(&job.member_id) {
                        "qualified"
                    } else {
                        "qualification_pending"
                    }
                    .into(),
                    failure_code: failed.then(|| "execution_failed".into()),
                    last_attempt: None,
                    incarnation: None,
                    qualification: None,
                }
            })
            .collect()
    }
    fn lookup_now(&self, key: &Key, abort: bool) -> Lookup {
        let mut state = self.state();
        if abort {
            state.aborts += 1;
        } else {
            state.lookups += 1;
        }
        let entry = state.keys.get(&key.request_id).cloned();
        let (status, receipt) = match entry {
            Some((_, Some(receipt), _)) => ("admitted", Some(receipt)),
            Some((_, None, true)) => ("aborted", None),
            Some((_, None, false)) | None if abort => {
                state.keys.insert(
                    key.request_id.clone(),
                    (key.fingerprint.clone(), None, true),
                );
                ("aborted", None)
            }
            _ => ("absent", None),
        };
        let jobs_state = receipt
            .as_ref()
            .map(|receipt| self.jobs_state(&state, receipt))
            .unwrap_or_default();
        Lookup {
            version: 1,
            store_id: RUN_STORE.into(),
            request_id: key.request_id.clone(),
            fingerprint: key.fingerprint.clone(),
            state: status.into(),
            receipt,
            jobs_state,
        }
    }
    /// The egress receipt Run would attest for this member's current launch.
    fn current_receipt(&self, root: &Root, request: &str, uid: u32) -> CurrentReceipt {
        let lineage = &root.admission.lineage_root_id;
        let mut chain = vec![SuccessorLink {
            execution_id: root.admission.execution_id.clone(),
            parent_execution_id: None,
            sequence: root.admission.sequence,
        }];
        if root.execution != root.admission.execution_id {
            chain.push(SuccessorLink {
                execution_id: root.execution.clone(),
                parent_execution_id: Some(root.admission.execution_id.clone()),
                sequence: root.sequence,
            });
        }
        CurrentReceipt {
            receipt_id: format!("current-{request}"),
            purpose: "egress".into(),
            lineage_root_id: lineage.clone(),
            bound_execution_id: root.admission.execution_id.clone(),
            attempt: AttemptRef {
                run_store_id: RUN_STORE.into(),
                lineage_root_id: lineage.clone(),
                execution_id: root.execution.clone(),
                sequence: root.sequence,
                attempt_id: format!("attempt-{}", root.execution),
                launch_id: root.launch.clone(),
            },
            incarnation: Incarnation {
                host_id: "host".into(),
                boot_id: root.boot.clone(),
                pid_namespace_inode: 1,
                uid,
                pid: 4242,
                start_ticks: 7,
            },
            actor: ManagedActor {
                address: format!("host/codex/store/{}", root.native),
                role: "root".into(),
                native_id: root.native.clone(),
                epoch: root.epoch,
            },
            successor_proof: SuccessorProof {
                lineage_root_id: lineage.clone(),
                bound_execution_id: root.admission.execution_id.clone(),
                current_execution_id: root.execution.clone(),
                chain,
            },
        }
    }
}

impl Client for SyntheticRun {
    fn route(&self) -> EnrollmentRoute {
        self.state()
            .route_override
            .clone()
            .unwrap_or_else(|| self.route.clone())
    }
    fn switch_enabled(&self) -> bool {
        self.state().switch
    }
    fn enabled(&self) -> Response<'_, ()> {
        let enabled = self.state().capability;
        Box::pin(async move {
            if enabled {
                Ok(())
            } else {
                Err(Failure::Refused("capability_missing"))
            }
        })
    }
    fn submit<'a>(&'a self, params: &'a Value) -> Response<'a, StartReceipt> {
        Box::pin(async move {
            let fingerprint = self.validate(params)?;
            let mut state = self.state();
            state.submits += 1;
            if let Some((code, recovery)) = state.refuse_submit.take() {
                return Err(Failure::classify(code, recovery));
            }
            let request_id = params["request_id"].as_str().unwrap().to_owned();
            if let Some((prior, receipt, aborted)) = state.keys.get(&request_id).cloned() {
                if prior != fingerprint {
                    return Err(Failure::Refused("intent_conflict"));
                }
                if aborted {
                    return Err(Failure::Aborted);
                }
                if let Some(receipt) = receipt {
                    return Ok(receipt);
                }
            }
            if params["mode"] == "replace" {
                let condition: Target =
                    serde_json::from_value(params["preconditions"][0].clone()).unwrap();
                if state.status != Some(OldStatus::Ready(condition)) {
                    return Err(Failure::Refused("precondition_failed"));
                }
            }
            let mut jobs = Vec::new();
            for (index, job) in params["jobs"].as_array().unwrap().iter().enumerate() {
                state.counter += 1;
                let n = state.counter;
                let root = agent(n);
                let admission = Admission {
                    index,
                    member_id: job["member_id"].as_str().unwrap().into(),
                    lineage_root_id: root.clone(),
                    execution_id: root,
                    sequence: 1,
                    execution_ref: format!("ex1_{n:064x}"),
                    pin_id: format!("pin_{}", uuid::Uuid::new_v4().simple()),
                    managed_role_name: ROLE.into(),
                    role_digest: "c".repeat(64),
                };
                state.roots.insert(
                    admission.member_id.clone(),
                    Root {
                        native: format!("native{n}"),
                        execution: admission.execution_id.clone(),
                        sequence: 1,
                        epoch: 1,
                        launch: uuid(),
                        boot: uuid(),
                        admission: admission.clone(),
                    },
                );
                jobs.push(admission);
            }
            state.admissions += 1;
            let receipt = StartReceipt {
                version: 1,
                store_id: RUN_STORE.into(),
                request_id: request_id.clone(),
                receipt_id: format!("receipt-{}", state.admissions),
                fingerprint: fingerprint.clone(),
                state: "admitted".into(),
                jobs,
            };
            state
                .keys
                .insert(request_id, (fingerprint, Some(receipt.clone()), false));
            if std::mem::take(&mut state.lose_submit_ack) {
                return Err(Failure::Unknown);
            }
            Ok(receipt)
        })
    }
    fn lookup<'a>(&'a self, key: &'a Key) -> Response<'a, Lookup> {
        Box::pin(async move {
            {
                let mut state = self.state();
                if state.in_progress_lookups > 0 {
                    state.in_progress_lookups -= 1;
                    state.lookups += 1;
                    return Err(Failure::InProgress);
                }
            }
            Ok(self.lookup_now(key, false))
        })
    }
    fn abort<'a>(&'a self, key: &'a Key) -> Response<'a, Lookup> {
        Box::pin(async move { Ok(self.lookup_now(key, true)) })
    }
    fn current<'a>(
        &'a self,
        key: &'a Key,
        member: &'a str,
        request: &'a str,
    ) -> Response<'a, Attested> {
        Box::pin(async move {
            let mut state = self.state();
            state.current_calls += 1;
            let Some((_, Some(receipt), _)) = state.keys.get(&key.request_id).cloned() else {
                return Err(Failure::NotReady);
            };
            if !receipt.jobs.iter().any(|job| job.member_id == member) {
                return Err(Failure::Refused("attempt_mismatch"));
            }
            if !state.qualified.contains(member) {
                return Err(Failure::NotReady);
            }
            let root = state.roots.get(member).cloned().unwrap();
            let current = match state.receipts.get(request) {
                Some(prior) => prior.clone(),
                None => {
                    let fresh =
                        self.current_receipt(&root, request, self.route.run.route.worker_uid);
                    state.receipts.insert(request.into(), fresh.clone());
                    fresh
                }
            };
            if std::mem::take(&mut state.lose_current_ack) {
                return Err(Failure::Unknown);
            }
            let qualification = Qualification {
                launch_id: current.attempt.launch_id.clone(),
                role_digest: state
                    .role_digest_override
                    .clone()
                    .unwrap_or_else(|| root.admission.role_digest.clone()),
                config_digest: "d".repeat(64),
                inventory_digest: "e".repeat(64),
            };
            let authority = crate::managed_run::CurrentAuthority::egress_fixture(
                self.route.run.clone(),
                current,
                request,
                json!({"member_id":member}),
            );
            Ok(Attested {
                authority,
                qualification,
                admission_receipt_id: receipt.receipt_id,
            })
        })
    }
    fn status<'a>(
        &'a self,
        _store: &'a str,
        _target: &'a Target,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = OldStatus> + Send + 'a>> {
        Box::pin(async move {
            let mut state = self.state();
            state.status_calls += 1;
            state.status.clone().unwrap_or(OldStatus::Unavailable)
        })
    }
}

/// One Pool database, its owner and a synthetic Run peer.
pub(crate) struct Harness {
    _dir: tempfile::TempDir,
    path: PathBuf,
    pub(crate) store: Arc<Mutex<Store>>,
    owner: Actor,
    pub(crate) pool: String,
    pub(crate) route: EnrollmentRoute,
    run: SyntheticRun,
    keys: u64,
}

impl Harness {
    pub(crate) fn new() -> Self {
        let root = std::env::var_os("TMPDIR").expect("task TMPDIR required");
        let dir = tempfile::tempdir_in(root).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = std::fs::metadata(dir.path()).unwrap().uid();
        let path = dir.path().join("pool.db");
        let mut store = Store::open(&path).unwrap();
        let owner = Actor::verified("host/codex/store/owner".into(), "owner", "root").unwrap();
        let Reply::Receipt(created) = store
            .execute(
                &owner,
                &Command::Create(Create {
                    request_key: "create".into(),
                    name: "P3".into(),
                    purpose: "Managed enrollment".into(),
                    acceptance: None,
                }),
            )
            .unwrap()
        else {
            panic!("pool receipt");
        };
        let pool_store = store.managed_store_id().unwrap();
        let run_route = Route {
            component_store_id: RUN_STORE.into(),
            route_id: "run-route".into(),
            worker_uid: uid,
        };
        let route = EnrollmentRoute {
            run: RunEndpointPin {
                route: run_route,
                socket: "/fixture/attempt.sock".into(),
                executable: "/fixture/run".into(),
                executable_sha256: "a".repeat(64),
            },
            pool_route: Route {
                component_store_id: pool_store,
                route_id: "pool-route".into(),
                worker_uid: uid,
            },
            bridge_route: Route {
                component_store_id: "00000000-0000-4000-8000-000000000003".into(),
                route_id: "bridge-route".into(),
                worker_uid: uid,
            },
            producer: "pool".into(),
            role: ROLE.into(),
            status: Some(crate::domain::RunRoute {
                socket: "/fixture/run.sock".into(),
                expected_uid: uid,
                peer_uid: None,
                store_id: None,
            }),
        };
        store.configure_enrollment(Some(route.clone()));
        let run = SyntheticRun {
            state: Arc::new(Mutex::new(RunState {
                capability: true,
                switch: true,
                ..RunState::default()
            })),
            route: route.clone(),
        };
        Self {
            _dir: dir,
            path,
            store: Arc::new(Mutex::new(store)),
            owner,
            pool: created.pool_id,
            route,
            run,
            keys: 0,
        }
    }
    /// Drop the only resident store and reopen the same SQLite file.
    fn restart(&mut self) {
        let placeholder = Arc::new(Mutex::new(
            Store::open(&self._dir.path().join("placeholder.db")).unwrap(),
        ));
        let old = std::mem::replace(&mut self.store, placeholder);
        drop(Arc::try_unwrap(old).ok().unwrap());
        let mut reopened = Store::open(&self.path).unwrap();
        reopened.configure_enrollment(Some(self.route.clone()));
        self.store = Arc::new(Mutex::new(reopened));
    }
    fn db<T>(&self, f: impl FnOnce(&mut rusqlite::Connection) -> T) -> T {
        let mut guard = self.store.lock().unwrap();
        f(guard.test_db())
    }
    pub(crate) fn revision(&self) -> u64 {
        self.db(|db| {
            let data: String = db
                .query_row("SELECT data FROM pools WHERE id=?1", [&self.pool], |row| {
                    row.get(0)
                })
                .unwrap();
            serde_json::from_str::<Value>(&data).unwrap()["revision"]
                .as_u64()
                .unwrap()
        })
    }
    fn key(&mut self) -> String {
        self.keys += 1;
        format!("key-{}", self.keys)
    }
    fn change(&mut self) -> Change {
        Change {
            pool_id: self.pool.clone(),
            expected_revision: self.revision(),
            request_key: self.key(),
        }
    }
    fn execute(&self, actor: &Actor, command: &Command) -> Result<Reply, Fault> {
        self.store.lock().unwrap().execute(actor, command)
    }
    fn spec(task: &str) -> Value {
        json!({"provider":"codex","model":"model","profile":ROLE,"task":task,"workdir":"/work"})
    }
    /// Owner single start through the actual domain command.
    fn start(&mut self, name: &str) -> (String, String) {
        let command = Command::Start(Start {
            change: self.change(),
            name: name.into(),
            role: "worker".into(),
            task: "work".into(),
            spec: Self::spec("work"),
        });
        let Reply::Receipt(receipt) = self.execute(&self.owner.clone(), &command).unwrap() else {
            panic!("start receipt");
        };
        assert_eq!(receipt.status, "committed; managed enrollment pending");
        (
            receipt.created_id.clone().unwrap(),
            receipt.created_ids[0].clone(),
        )
    }
    fn batch(&mut self, count: usize) -> Result<(String, Vec<String>), Fault> {
        let command = Command::StartBatch(StartBatch {
            change: self.change(),
            members: (0..count)
                .map(|index| StartMember {
                    name: format!("worker-{index}"),
                    role: "worker".into(),
                    task: format!("task {index}"),
                    spec: Self::spec(&format!("task {index}")),
                })
                .collect(),
        });
        let Reply::Receipt(receipt) = self.execute(&self.owner.clone(), &command)? else {
            panic!("batch receipt");
        };
        Ok((
            receipt.created_id.clone().unwrap(),
            receipt.created_ids.clone(),
        ))
    }
    async fn drive(&self, id: &str) {
        enrollment_dispatch::drive(&self.store, &self.run, id)
            .await
            .unwrap();
    }
    pub(crate) fn view(&self, id: &str) -> crate::domain::EnrollmentView {
        let Reply::Enrollment(view) = self
            .execute(
                &self.owner,
                &Command::EnrollmentGet(EnrollmentGet {
                    pool_id: self.pool.clone(),
                    enrollment_id: id.into(),
                }),
            )
            .unwrap()
        else {
            panic!("enrollment view");
        };
        *view
    }
    pub(crate) fn member(&self, id: &str) -> (crate::domain::Binding, bool) {
        self.db(|db| crate::store::binding_any(db, id).unwrap())
    }
    pub(crate) fn managed_binding(&self, member: &str) -> Option<(ManagedBinding, Incarnation)> {
        self.db(|db| {
            use rusqlite::OptionalExtension;
            db.query_row(
                "SELECT binding,incarnation FROM managed_bindings WHERE member=?1",
                [member],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .unwrap()
            .map(|(binding, incarnation)| {
                (
                    serde_json::from_str(&binding).unwrap(),
                    serde_json::from_str(&incarnation).unwrap(),
                )
            })
        })
    }
    fn qualify(&self, member: &str) {
        self.run.state().qualified.insert(member.into());
    }
    fn count(&self, sql: &str) -> i64 {
        self.db(|db| db.query_row(sql, [], |row| row.get(0)).unwrap())
    }
    /// Admit, qualify and bind one owner start, returning (enrollment, member).
    pub(crate) async fn bound_member(&mut self, name: &str) -> (String, String) {
        let (id, member) = self.start(name);
        self.drive(&id).await;
        self.qualify(&member);
        self.drive(&id).await;
        assert_eq!(self.view(&id).jobs[0].state, "bound_pending_join");
        (id, member)
    }
    /// The real store-level P1 pool_join for a bound managed member.
    fn join(&mut self, member: &str, revision: u64) -> Result<Reply, Fault> {
        let key = self.key();
        self.p1(
            member,
            Command::Join(Change {
                pool_id: self.pool.clone(),
                expected_revision: revision,
                request_key: key,
            }),
        )
    }
    /// Freeze the exact P1 context, reserve its intent, admit and run the domain CAS.
    fn p1(&mut self, member: &str, command: Command) -> Result<Reply, Fault> {
        use crate::managed_state::tests::{
            FakeRun, fake_bridge_pin, fake_consumed, fake_run_endpoint, fresh_authority,
            prepare_command,
        };
        self.keys += 1;
        let tag = format!("p1-{}", self.keys);
        let (binding, incarnation) = self.managed_binding(member).ok_or(Fault::Forbidden)?;
        let mut ingress = CurrentReceipt {
            receipt_id: format!("ingress-{tag}"),
            purpose: "ingress".into(),
            lineage_root_id: binding.attempt.lineage_root_id.clone(),
            bound_execution_id: binding.attempt.lineage_root_id.clone(),
            attempt: binding.attempt.clone(),
            incarnation: incarnation.clone(),
            actor: binding.actor.clone(),
            successor_proof: SuccessorProof {
                lineage_root_id: binding.attempt.lineage_root_id.clone(),
                bound_execution_id: binding.attempt.lineage_root_id.clone(),
                current_execution_id: binding.attempt.execution_id.clone(),
                chain: vec![SuccessorLink {
                    execution_id: binding.attempt.lineage_root_id.clone(),
                    parent_execution_id: None,
                    sequence: 1,
                }],
            },
        };
        if binding.attempt.execution_id != binding.attempt.lineage_root_id {
            ingress.successor_proof.chain.push(SuccessorLink {
                execution_id: binding.attempt.execution_id.clone(),
                parent_execution_id: Some(binding.attempt.lineage_root_id.clone()),
                sequence: binding.attempt.sequence,
            });
        }
        let run = FakeRun::with_receipt(ingress);
        let mut guard = self.store.lock().unwrap();
        let db = guard.test_db();
        crate::managed_state::persist_bridge_route(db, &fake_bridge_pin(&binding))?;
        crate::managed_state::persist_run_route(db, &fake_run_endpoint(&binding))?;
        let (context, intent, invocation) = (
            format!("{tag}-context"),
            format!("{tag}-intent"),
            format!("{tag}-invocation"),
        );
        let digest = prepare_command(
            db,
            &run,
            &binding,
            &incarnation,
            &context,
            &intent,
            &invocation,
            &command,
        );
        let authority = fresh_authority(db, &binding, &context, &invocation)?;
        let consumed = fake_consumed(
            &binding,
            &incarnation,
            &intent,
            &invocation,
            &digest,
            &command,
        );
        let pool_route = Route {
            component_store_id: binding.pool_store_id.clone(),
            route_id: "pool-route".into(),
            worker_uid: binding.run_route.worker_uid,
        };
        match crate::managed_state::reserve_intent(
            db,
            &context,
            &binding.member_id,
            &command,
            &digest,
            authority,
            &consumed,
            &pool_route,
        )? {
            crate::managed_state::IntentReservation::Created => {}
            crate::managed_state::IntentReservation::Committed(receipt) => {
                return Ok(serde_json::from_str(&receipt).unwrap());
            }
            _ => return Err(Fault::Unavailable),
        }
        let admission = crate::managed_run::Admission {
            admission_id: format!("{tag}-admission"),
            intent_id: intent.clone(),
            security_digest: digest.clone(),
            policy: "admission_snapshot".into(),
            binding: binding.clone(),
            incarnation: incarnation.clone(),
            successor_proof: SuccessorProof {
                lineage_root_id: binding.attempt.lineage_root_id.clone(),
                bound_execution_id: binding.attempt.execution_id.clone(),
                current_execution_id: binding.attempt.execution_id.clone(),
                chain: vec![SuccessorLink {
                    execution_id: binding.attempt.execution_id.clone(),
                    parent_execution_id: (binding.attempt.execution_id
                        != binding.attempt.lineage_root_id)
                        .then(|| binding.attempt.lineage_root_id.clone()),
                    sequence: binding.attempt.sequence,
                }],
            },
            consumed_ref: crate::managed_run::ConsumedRef {
                bridge_route: binding.bridge_route.clone(),
                producer: "pool".into(),
                consume_request_id: intent.clone(),
                invocation_key: invocation.clone(),
                security_digest: digest.clone(),
                issuer_epoch: "epoch".into(),
            },
        };
        crate::managed_state::mark_admitted(db, &intent, &digest, &admission)?;
        let committed = crate::managed_state::commit_domain(db, &intent, &digest)?;
        Ok(serde_json::from_str(&committed).unwrap())
    }
    /// Stage a rootless first-hook ingress receipt and select the binding as the resident does.
    fn first_hook(&mut self, receipt: CurrentReceipt) -> Result<ManagedBinding, Fault> {
        self.keys += 1;
        let tag = format!("hook-{}", self.keys);
        let pin = crate::managed_bridge::BridgePin {
            route: self.route.bridge_route.clone(),
            producer: "pool".into(),
            registration_socket: "/fixture/adapter.sock".into(),
            core_socket: "/fixture/core.sock".into(),
            server_executable: "/fixture/bridge".into(),
            server_sha256: "a".repeat(64),
            credential_file: "/fixture/token".into(),
            credential_sha256: "b".repeat(64),
        };
        let command = Command::Get(crate::domain::Get {
            pool_id: self.pool.clone(),
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
        let mut guard = self.store.lock().unwrap();
        let db = guard.test_db();
        crate::managed_state::persist_bridge_route(db, &pin)?;
        crate::managed_state::persist_run_route(db, &self.route.run)?;
        let proof = crate::managed_state::tests::native_proof();
        crate::managed_state::reserve_bootstrap(
            db,
            &crate::managed_state::BootstrapRequest {
                namespace_id: "namespace",
                bootstrap_id: &tag,
                route: &self.route.bridge_route,
                bridge_pin: &pin,
                producer: "pool",
                issuer_epoch: "epoch",
                invocation_key: &tag,
                command: &command,
                native_proof: &proof,
            },
        )?;
        let dispatch = crate::managed_state::mark_bootstrap_submitted(db, &tag)?;
        crate::managed_state::record_bootstrap_ref(
            db,
            dispatch,
            &crate::managed_bridge::Prepared {
                store_id: self.route.bridge_route.component_store_id.clone(),
                bridge_context_ref: bridge_sdk::bridge_protocol::Secret::new(format!("{tag}-ref")),
                invocation_key: tag.clone(),
                expires_at_ms: 100,
            },
            &pin,
        )?;
        let request = format!("{tag}-request");
        let run_pin = crate::managed_state::RunPin {
            route: self.route.run.route.clone(),
            socket: self.route.run.socket.clone(),
            executable: self.route.run.executable.clone(),
            executable_sha256: self.route.run.executable_sha256.clone(),
            capabilities: vec!["attempt_current_ingress_v1".into()],
        };
        let intent = crate::managed_state::CurrentIntent::Ingress {
            version: 1,
            expected_store_id: RUN_STORE.into(),
            request_id: request.clone(),
            observation_ref: bridge_sdk::bridge_protocol::Secret::new(format!("{tag}-ref")),
            invocation_key: tag.clone(),
        };
        crate::managed_state::prepare_current_request(db, &run_pin, &intent)?;
        let authority = crate::managed_run::CurrentAuthority::fixture(
            self.route.run.clone(),
            receipt,
            &tag,
            &request,
            serde_json::to_value(&intent).unwrap(),
        );
        crate::managed_state::record_current_receipt(db, &request, &authority)?;
        crate::managed_state::select_ingress_binding(
            db,
            &authority,
            &self.route.bridge_route,
            "pool",
            &command,
        )
    }
    pub(crate) fn ingress_for(&self, member: &str, tag: &str) -> CurrentReceipt {
        let state = self.run.state();
        let root = state.roots.get(member).cloned().unwrap();
        let mut receipt = self
            .run
            .current_receipt(&root, tag, self.route.run.route.worker_uid);
        receipt.purpose = "ingress".into();
        receipt.receipt_id = format!("ingress-{tag}");
        receipt
    }
    fn resolve(&mut self, id: &str, revision: u64) -> Result<Reply, Fault> {
        let key = self.key();
        self.execute(
            &self.owner.clone(),
            &Command::EnrollmentResolve(EnrollmentResolve {
                pool_id: self.pool.clone(),
                enrollment_id: id.into(),
                expected_enrollment_revision: revision,
                request_key: key,
                disposition: Disposition::RetainUnassigned,
            }),
        )
    }
    fn replace(&mut self, member: &str) -> Result<(String, String), Fault> {
        let command = Command::Replace(Replace {
            change: self.change(),
            member_id: member.into(),
            spec: None,
        });
        let Reply::Receipt(receipt) = self.execute(&self.owner.clone(), &command)? else {
            panic!("replace receipt");
        };
        Ok((
            receipt.created_id.clone().unwrap(),
            receipt.created_ids[0].clone(),
        ))
    }
    /// Make the old member's lineage terminal and cleaned at its admitted tip.
    fn old_terminal(&self, member: &str) -> Target {
        let (binding, _) = self.member(member);
        let target = Target {
            agent_id: binding.run_id.unwrap(),
            sequence: u32::try_from(binding.run_sequence.unwrap()).unwrap(),
            execution_ref: binding.run_execution_ref.unwrap(),
            pin_id: binding.run_pin_id.unwrap(),
        };
        self.run.state().status = Some(OldStatus::Ready(target.clone()));
        target
    }
    /// An active, joined P3 member.
    async fn active_member(&mut self, name: &str) -> (String, String) {
        let (id, member) = self.bound_member(name).await;
        let revision = self.revision();
        self.join(&member, revision).unwrap();
        assert_eq!(self.member(&member).0.member.state, MemberState::Active);
        (id, member)
    }
}

fn owner_view_state(h: &Harness, id: &str) -> (String, Option<String>) {
    let view = h.view(id);
    (view.state, view.attention)
}

/// Published `run-p3-wire.md` vector: canonical length and fingerprint.
#[test]
fn p3_fingerprint_vector_matches_run_wire() {
    let vector = json!({"version":1,"expected_store_id":"store_0123456789abcdef0123456789abcdef","pool_store_id":"00000000-0000-4000-8000-000000000001","pool_id":"pool-1","request_id":"enroll-1","mode":"start","jobs":[{"member_id":"member-1","selector":{"version":1,"role_name":"managed"},"spec":{"provider":"codex","model":"model","profile":"managed","task":"hello","workdir":"/work","explicit_finish":true,"write":false}}],"preconditions":[]});
    let (length, digest) =
        crate::managed_codec::digest(journal::FINGERPRINT_DOMAIN, &vector).unwrap();
    assert_eq!(length, 597);
    assert_eq!(
        digest,
        "33052668086558da6746ae6863012ab5005befc4d30523ad6b6e0b39e3a2a162"
    );
    assert_eq!(journal::fingerprint(&vector).unwrap(), digest);
}

#[tokio::test]
async fn p3_owner_only() {
    let mut h = Harness::new();
    let (id, member) = h.start("owner-started");
    // Participant: a legacy invited member who joined cannot start, batch,
    // replace, read or resolve an owner enrollment, even with copied IDs.
    let invited = Actor::verified("host/codex/store/invited".into(), "invited", "root").unwrap();
    let add = Command::Add(crate::domain::Add {
        change: h.change(),
        address: invited.address.clone(),
        name: "invited".into(),
        role: "peer".into(),
        task: "peer".into(),
    });
    let Reply::Receipt(added) = h.execute(&h.owner.clone(), &add).unwrap() else {
        panic!("add");
    };
    let invited_member = added.created_id.clone().unwrap();
    let expected = h.member(&invited_member).0;
    let join = Command::Join(h.change());
    h.store
        .lock()
        .unwrap()
        .execute_join(&invited, &join, &expected)
        .unwrap();
    let before = h.count("SELECT count(*) FROM managed_enrollments");
    for command in [
        Command::Start(Start {
            change: h.change(),
            name: "x".into(),
            role: "x".into(),
            task: "x".into(),
            spec: Harness::spec("x"),
        }),
        Command::StartBatch(StartBatch {
            change: h.change(),
            members: vec![StartMember {
                name: "x".into(),
                role: "x".into(),
                task: "x".into(),
                spec: Harness::spec("x"),
            }],
        }),
        Command::Replace(Replace {
            change: h.change(),
            member_id: member.clone(),
            spec: None,
        }),
        Command::EnrollmentGet(EnrollmentGet {
            pool_id: h.pool.clone(),
            enrollment_id: id.clone(),
        }),
        Command::EnrollmentResolve(EnrollmentResolve {
            pool_id: h.pool.clone(),
            enrollment_id: id.clone(),
            expected_enrollment_revision: 1,
            request_key: "copied".into(),
            disposition: Disposition::RetainUnassigned,
        }),
    ] {
        assert_eq!(h.execute(&invited, &command).err(), Some(Fault::Forbidden));
    }
    assert_eq!(h.count("SELECT count(*) FROM managed_enrollments"), before);
    // Managed participant ingress can never carry an owner operation.
    let receipt = CurrentReceipt {
        receipt_id: "x".into(),
        purpose: "ingress".into(),
        lineage_root_id: agent(99),
        bound_execution_id: agent(99),
        attempt: AttemptRef {
            run_store_id: RUN_STORE.into(),
            lineage_root_id: agent(99),
            execution_id: agent(99),
            sequence: 1,
            attempt_id: "a".into(),
            launch_id: uuid(),
        },
        incarnation: Incarnation {
            host_id: "host".into(),
            boot_id: uuid(),
            pid_namespace_inode: 1,
            uid: h.route.run.route.worker_uid,
            pid: 7,
            start_ticks: 1,
        },
        actor: ManagedActor {
            address: "host/codex/store/n".into(),
            role: "root".into(),
            native_id: "n".into(),
            epoch: 1,
        },
        successor_proof: SuccessorProof {
            lineage_root_id: agent(99),
            bound_execution_id: agent(99),
            current_execution_id: agent(99),
            chain: vec![SuccessorLink {
                execution_id: agent(99),
                parent_execution_id: None,
                sequence: 1,
            }],
        },
    };
    let authority = crate::managed_run::CurrentAuthority::fixture(
        h.route.run.clone(),
        receipt,
        "inv",
        "req",
        json!({}),
    );
    for command in [
        Command::Start(Start {
            change: h.change(),
            name: "x".into(),
            role: "x".into(),
            task: "x".into(),
            spec: Harness::spec("x"),
        }),
        Command::EnrollmentGet(EnrollmentGet {
            pool_id: h.pool.clone(),
            enrollment_id: id.clone(),
        }),
    ] {
        let result = h.db(|db| {
            crate::managed_state::select_ingress_binding(
                db,
                &authority,
                &h.route.bridge_route,
                "pool",
                &command,
            )
        });
        assert_eq!(result.err(), Some(Fault::Unavailable));
    }
    // A wrong route (changed endpoint/route identity) never reaches Run.
    let mut changed = h.route.clone();
    changed.run.socket = "/other/attempt.sock".into();
    h.run.state().route_override = Some(changed);
    h.drive(&id).await;
    assert_eq!(h.run.state().submits, 0);
    assert_eq!(
        owner_view_state(&h, &id),
        ("reserved".into(), Some("route_changed".into()))
    );
    h.run.state().route_override = None;
    h.drive(&id).await;
    assert_eq!(h.run.state().submits, 1);
    assert_eq!(h.view(&id).state, "admitted");
    // Without the configured enrollment route the owner start stays legacy.
    h.store.lock().unwrap().configure_enrollment(None);
    let command = Command::Start(Start {
        change: h.change(),
        name: "legacy".into(),
        role: "x".into(),
        task: "x".into(),
        spec: Harness::spec("x"),
    });
    let Reply::Receipt(legacy) = h.execute(&h.owner.clone(), &command).unwrap() else {
        panic!("legacy receipt");
    };
    assert_eq!(legacy.status, "committed; delivery pending");
    assert_eq!(h.count("SELECT count(*) FROM managed_enrollments"), before);
}

#[tokio::test]
async fn p3_exact_selector() {
    let mut h = Harness::new();
    let before = h.revision();
    for spec in [
        json!({"provider":"codex","model":"m","profile":"other","task":"t","workdir":"/w"}),
        json!({"provider":"codex","model":"m","task":"t","workdir":"/w"}),
        json!({"provider":"codex","model":"m","profile":ROLE,"task":"t","workdir":"/w","explicit_finish":false}),
        json!({"provider":"codex","model":"m","profile":ROLE,"task":"t","workdir":"/w","write":true}),
        json!({"provider":"codex","model":"m","profile":ROLE,"task":"t","workdir":"/w","required_mcp":{}}),
        json!({"provider":"opencode","model":"m","profile":"research","task":"t","workdir":"/w"}),
    ] {
        let command = Command::Start(Start {
            change: h.change(),
            name: "bad".into(),
            role: "r".into(),
            task: "t".into(),
            spec,
        });
        assert_eq!(
            h.execute(&h.owner.clone(), &command).err(),
            Some(Fault::Invalid)
        );
    }
    assert_eq!(h.revision(), before);
    assert_eq!(h.count("SELECT count(*) FROM managed_enrollments"), 0);
    // The frozen request carries the exact selector, explicit finish and no write.
    let (id, member) = h.start("exact");
    let params: Value = h.db(|db| {
        serde_json::from_str(
            &db.query_row(
                "SELECT params FROM managed_enrollments WHERE id=?1",
                [&id],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        )
        .unwrap()
    });
    assert_eq!(
        params["jobs"][0]["selector"],
        json!({"version":1,"role_name":ROLE})
    );
    assert_eq!(params["jobs"][0]["spec"]["profile"], json!(ROLE));
    assert_eq!(params["jobs"][0]["spec"]["explicit_finish"], json!(true));
    assert_eq!(params["jobs"][0]["spec"]["write"], json!(false));
    assert!(params["jobs"][0]["spec"].get("required_mcp").is_none());
    // Run refuses an unqualified role on the first submission: definitive, no fallback.
    h.run.state().refuse_submit = Some(("role_unqualified", "none"));
    h.drive(&id).await;
    assert_eq!(
        owner_view_state(&h, &id),
        ("refused".into(), Some("role_unqualified".into()))
    );
    assert_eq!(h.run.state().admissions, 0);
    assert!(h.member(&member).0.run_id.is_none());
    // A launch whose qualification does not match the admitted role digest never binds.
    let (id, member) = h.start("unqualified");
    h.drive(&id).await;
    h.qualify(&member);
    h.run.state().role_digest_override = Some("f".repeat(64));
    h.drive(&id).await;
    let view = h.view(&id);
    assert_eq!(view.jobs[0].state, "admitted");
    assert_eq!(
        view.jobs[0].attention.as_deref(),
        Some("attestation_mismatch")
    );
    assert!(h.managed_binding(&member).is_none());
    assert!(h.member(&member).0.address.is_none());
    // Join is refused for a root with no qualified enrollment binding.
    assert_eq!(h.join(&member, h.revision()).err(), Some(Fault::Forbidden));
}

#[tokio::test]
async fn p3_single_enrollment() {
    let mut h = Harness::new();
    let (id, member) = h.start("single");
    let (binding, _) = h.member(&member);
    assert_eq!(binding.member.state, MemberState::Pending);
    assert!(binding.run_id.is_none());
    assert_eq!(h.view(&id).state, "reserved");
    // Onboarding is reserved in P2 as an exact member seed, awaiting binding.
    assert_eq!(
        h.count(&format!(
            "SELECT count(*) FROM managed_delivery_seeds WHERE member_id='{member}' AND final_notice=0"
        )),
        2
    );
    h.drive(&id).await;
    let view = h.view(&id);
    assert_eq!(view.state, "admitted");
    let root = view.jobs[0].lineage_root_id.clone().unwrap();
    let (binding, _) = h.member(&member);
    assert_eq!(binding.run_id.as_deref(), Some(root.as_str()));
    assert!(binding.run_pin_id.is_some());
    assert_eq!(binding.run_store_id.as_deref(), Some(RUN_STORE));
    // Not yet qualified: no binding, explicit per-job reason, no new start.
    h.drive(&id).await;
    let view = h.view(&id);
    assert_eq!(view.jobs[0].state, "admitted");
    assert_eq!(
        view.jobs[0].attention.as_deref(),
        Some("qualification_pending")
    );
    assert!(h.managed_binding(&member).is_none());
    h.qualify(&member);
    let revision = h.revision();
    h.drive(&id).await;
    let view = h.view(&id);
    assert_eq!(view.jobs[0].state, "bound_pending_join");
    assert_eq!(view.jobs[0].binding_generation, Some(1));
    let (managed, _) = h.managed_binding(&member).unwrap();
    assert_eq!(managed.binding_generation, 1);
    assert_eq!(managed.attempt.lineage_root_id, root);
    // Binding is not a domain change and does not activate the member.
    assert_eq!(h.revision(), revision);
    assert_eq!(h.member(&member).0.member.state, MemberState::Pending);
    assert_eq!(h.run.state().admissions, 1);
    // Delivery accepted is not join: mark onboarding accepted, still pending.
    h.db(|db| {
        db.execute(
            "UPDATE managed_delivery_outbox SET state='accepted' WHERE effect_id IN (SELECT effect_id FROM managed_delivery_seeds WHERE member_id=?1)",
            [&member],
        )
        .unwrap()
    });
    assert_eq!(h.member(&member).0.member.state, MemberState::Pending);
    // Real P1 join activates exactly this member at the acknowledged revision.
    let Reply::Receipt(joined) = h.join(&member, revision).unwrap() else {
        panic!("join receipt");
    };
    assert_eq!(joined.event.kind, "member_joined");
    assert_eq!(h.member(&member).0.member.state, MemberState::Active);
    assert_eq!(h.view(&id).jobs[0].state, "active");
    // The joined member is an eligible voter.
    let propose = Command::Propose(crate::domain::Propose {
        change: h.change(),
        result: "done".into(),
        criteria: "check".into(),
        snapshot: None,
    });
    let Reply::Receipt(_) = h.execute(&h.owner.clone(), &propose).unwrap() else {
        panic!("proposal");
    };
    let voters: Value = h.db(|db| {
        serde_json::from_str(
            &db.query_row("SELECT data FROM pools", [], |row| row.get::<_, String>(0))
                .unwrap(),
        )
        .unwrap()
    });
    assert_eq!(voters["proposal"]["voters"], json!([member]));
    // The separately authorized owner observer reads the same projection.
    let observed = h
        .store
        .lock()
        .unwrap()
        .observe(&crate::observer::Request {
            schema_version: 1,
            operation: crate::observer::Operation::EnrollmentGet(EnrollmentGet {
                pool_id: h.pool.clone(),
                enrollment_id: id.clone(),
            }),
        })
        .unwrap();
    let crate::observer::Data::Enrollment(observed) = observed else {
        panic!("enrollment observation");
    };
    assert_eq!(*observed, h.view(&id));
    let identity = h
        .store
        .lock()
        .unwrap()
        .observe(&crate::observer::Request {
            schema_version: 1,
            operation: crate::observer::Operation::Identity(crate::observer::IdentityParams {}),
        })
        .unwrap();
    let crate::observer::Data::Identity(identity) = identity else {
        panic!("identity");
    };
    assert!(
        identity
            .capabilities
            .iter()
            .any(|c| c == "managed_enrollment_v1")
    );
    // A completed enrollment needs no further Run I/O.
    let calls = h.run.state().current_calls;
    assert!(h.db(|db| journal::pending(db).unwrap()).is_empty());
    h.drive(&id).await;
    assert_eq!(h.run.state().current_calls, calls);
}

#[tokio::test]
async fn p3_batch_enrollment() {
    let mut h = Harness::new();
    // One job.
    let (one, members) = h.batch(1).unwrap();
    assert_eq!(members.len(), 1);
    h.drive(&one).await;
    assert_eq!(h.view(&one).state, "admitted");
    // Twenty jobs, one transaction, ordered; injected admission failure admits none.
    h.db(|db| {
        db.execute("UPDATE members SET current=0 WHERE id=?1", [&members[0]])
            .unwrap()
    });
    let (twenty, members) = h.batch(20).unwrap();
    assert_eq!(members.len(), 20);
    let ordered: Vec<String> = h.db(|db| {
        let mut stmt = db
            .prepare("SELECT member FROM managed_enrollment_jobs WHERE enrollment=?1 ORDER BY idx")
            .unwrap();
        stmt.query_map([&twenty], |row| row.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    });
    assert_eq!(ordered, members);
    assert_eq!(
        h.batch(1).err(),
        Some(Fault::Conflict),
        "roster bound includes reserved members"
    );
    h.run.state().refuse_submit = Some(("capacity_exhausted", "operator"));
    h.drive(&twenty).await;
    let view = h.view(&twenty);
    assert_eq!(view.state, "refused");
    assert!(view.jobs.iter().all(|job| job.lineage_root_id.is_none()));
    assert!(
        members
            .iter()
            .all(|member| h.member(member).0.run_id.is_none())
    );
    // A fresh owner batch admits all; qualification/join progress per member.
    for member in &members {
        h.db(|db| {
            db.execute("UPDATE members SET current=0 WHERE id=?1", [member])
                .unwrap()
        });
    }
    let (batch, members) = h.batch(3).unwrap();
    h.drive(&batch).await;
    let view = h.view(&batch);
    assert_eq!(view.state, "admitted");
    assert_eq!(
        view.jobs
            .iter()
            .filter_map(|job| job.lineage_root_id.clone())
            .collect::<BTreeSet<_>>()
            .len(),
        3
    );
    h.qualify(&members[0]);
    h.run.state().failed.insert(members[2].clone());
    h.drive(&batch).await;
    let view = h.view(&batch);
    assert_eq!(view.jobs[0].state, "bound_pending_join");
    assert_eq!(view.jobs[1].state, "admitted");
    assert_eq!(
        view.jobs[1].attention.as_deref(),
        Some("qualification_pending")
    );
    assert_eq!(view.jobs[2].state, "admitted");
    assert_eq!(view.jobs[2].attention.as_deref(), Some("execution_failed"));
    h.join(&members[0], h.revision()).unwrap();
    assert_eq!(h.view(&batch).jobs[0].state, "active");
    assert_eq!(h.member(&members[1]).0.member.state, MemberState::Pending);
    assert_eq!(h.run.state().admissions, 2);
    // A failed member is not automatically replaced; the owner resolves explicitly.
    let revision = h.view(&batch).revision;
    let Reply::Receipt(resolved) = h.resolve(&batch, revision).unwrap() else {
        panic!("resolve");
    };
    assert_eq!(
        resolved.created_ids,
        vec![members[1].clone(), members[2].clone()]
    );
    let view = h.view(&batch);
    assert_eq!(view.state, "resolved");
    assert_eq!(view.jobs[0].state, "active");
    assert_eq!(view.jobs[1].state, "unassigned");
    assert!(view.jobs[1].pin_id.is_some(), "pins are retained");
    assert!(!h.member(&members[1]).1);
    assert_eq!(h.run.state().admissions, 2);
}

#[tokio::test]
async fn p3_enrollment_replay_crash() {
    let mut h = Harness::new();
    // Crash after the Pool reservation commit, before any Run I/O.
    let (id, member) = h.start("crash");
    let request: String = h.db(|db| {
        db.query_row(
            "SELECT request_id FROM managed_enrollments WHERE id=?1",
            [&id],
            |row| row.get(0),
        )
        .unwrap()
    });
    h.restart();
    assert_eq!(h.run.state().submits, 0);
    // Crash after submit_possible is durable but before Run received the request.
    h.db(|db| journal::begin_submit(db, &id).unwrap());
    h.restart();
    // Recovery: lookup (absent snapshot) then the SAME key replay.
    h.run.state().lose_submit_ack = true;
    h.drive(&id).await;
    assert_eq!(h.run.state().lookups, 1);
    assert_eq!(h.run.state().admissions, 1);
    // Run committed but the ACK was lost: the enrollment stays uncertain.
    assert_eq!(
        owner_view_state(&h, &id),
        ("submit_possible".into(), Some("outcome_unknown".into()))
    );
    // The owner domain key replays its original receipt; no second enrollment.
    let replay_key = h.db(|db| {
        db.query_row(
            "SELECT domain_key FROM managed_enrollments WHERE id=?1",
            [&id],
            |row| row.get::<_, String>(0),
        )
        .unwrap()
    });
    let replay = Command::Start(Start {
        change: Change {
            pool_id: h.pool.clone(),
            expected_revision: 1,
            request_key: replay_key,
        },
        name: "crash".into(),
        role: "worker".into(),
        task: "work".into(),
        spec: Harness::spec("work"),
    });
    let Reply::Receipt(original) = h.execute(&h.owner.clone(), &replay).unwrap() else {
        panic!("replayed receipt");
    };
    assert_eq!(original.created_id.as_deref(), Some(id.as_str()));
    assert_eq!(h.count("SELECT count(*) FROM managed_enrollments"), 1);
    h.restart();
    h.drive(&id).await;
    let view = h.view(&id);
    assert_eq!(view.state, "admitted");
    assert_eq!(h.run.state().admissions, 1, "no duplicate admission");
    let root = view.jobs[0].lineage_root_id.clone().unwrap();
    assert_eq!(
        h.db(|db| db
            .query_row(
                "SELECT request_id FROM managed_enrollments WHERE id=?1",
                [&id],
                |row| row.get::<_, String>(0)
            )
            .unwrap()),
        request,
        "the original key is never replaced"
    );
    // Lost current-attestation ACK: the replayed observation is not fresh authority.
    h.qualify(&member);
    h.run.state().lose_current_ack = true;
    h.drive(&id).await;
    assert!(h.managed_binding(&member).is_none());
    h.restart();
    h.drive(&id).await;
    assert!(h.managed_binding(&member).is_none(), "replay discarded");
    h.drive(&id).await;
    assert_eq!(h.managed_binding(&member).unwrap().0.binding_generation, 1);
    assert_eq!(h.count("SELECT count(*) FROM managed_bindings"), 1);
    // After the bind commit, restart neither re-observes nor rebinds.
    let calls = h.run.state().current_calls;
    h.restart();
    h.drive(&id).await;
    assert_eq!(h.run.state().current_calls, calls);
    assert_eq!(
        h.view(&id).jobs[0].lineage_root_id.as_deref(),
        Some(root.as_str())
    );
    // Join replay: the same domain key returns the original receipt.
    let revision = h.revision();
    let key = h.key();
    let join = Command::Join(Change {
        pool_id: h.pool.clone(),
        expected_revision: revision,
        request_key: key,
    });
    let Reply::Receipt(first) = h.p1(&member, join.clone()).unwrap() else {
        panic!("join");
    };
    h.restart();
    let Reply::Receipt(second) = h.p1(&member, join).unwrap() else {
        panic!("join replay");
    };
    assert_eq!(first.event.event_id, second.event.event_id);
    assert_eq!(h.run.state().admissions, 1);
}

/// A Run-prepared key reported as in progress continues only by same-key replay.
#[tokio::test]
async fn p3_prepared_key_replays_same_key() {
    let mut h = Harness::new();
    let (id, _) = h.start("prepared");
    h.run.state().refuse_submit = Some(("request_in_progress", "same_key_lookup"));
    h.drive(&id).await;
    assert_eq!(
        owner_view_state(&h, &id),
        ("submit_possible".into(), Some("outcome_unknown".into()))
    );
    h.run.state().in_progress_lookups = 1;
    h.drive(&id).await;
    assert_eq!(h.view(&id).state, "admitted");
    let state = h.run.state();
    assert_eq!(
        (state.submits, state.admissions, state.keys.len()),
        (2, 1, 1)
    );
}

#[tokio::test]
async fn p3_absent_abort_late_submit() {
    let mut h = Harness::new();
    let (_, old) = h.active_member("old").await;
    h.old_terminal(&old);
    let (id, candidate) = h.replace(&old).unwrap();
    // Freeze the precondition and make the first submission uncertain without
    // reaching Run (crash after submit_possible).
    h.db(|db| {
        let (enrollment, _) = journal::load(db, &id).unwrap();
        assert!(enrollment.params.is_none());
    });
    let target = h.old_terminal(&old);
    h.db(|db| journal::freeze_precondition(db, &id, &target).unwrap());
    h.db(|db| journal::begin_submit(db, &id).unwrap());
    let submits = h.run.state().submits;
    let lookups = h.run.state().lookups;
    // A negative lookup is only a snapshot: with no abort requested, Pool
    // replays the same key (here refused by Run as precondition drift).
    h.run.state().status = Some(OldStatus::NotReady);
    h.drive(&id).await;
    assert_eq!(h.run.state().lookups, lookups + 1);
    assert_eq!(h.run.state().submits, submits + 1);
    assert_eq!(
        owner_view_state(&h, &id),
        ("submit_possible".into(), Some("precondition_failed".into())),
        "a later refusal cannot settle an earlier uncertain submission"
    );
    // Owner cancellation of an uncertain replacement requests the same-key abort.
    let cancel = Command::CancelReplacement(crate::domain::CancelReplacement {
        change: h.change(),
        operation_id: id.clone(),
    });
    let Reply::Receipt(requested) = h.execute(&h.owner.clone(), &cancel).unwrap() else {
        panic!("cancel");
    };
    assert_eq!(requested.event.kind, "replacement_cancel_requested");
    h.drive(&id).await;
    assert_eq!(h.run.state().aborts, 1);
    assert_eq!(h.view(&id).state, "aborted");
    // A delayed submit of the same key loses to the tombstone.
    let params = h.db(|db| journal::load(db, &id).unwrap().0.params.unwrap());
    h.run.state().status = Some(OldStatus::Ready(target));
    assert_eq!(h.run.submit(&params).await.err(), Some(Failure::Aborted));
    assert_eq!(h.run.state().admissions, 1, "only the old member's start");
    assert!(h.member(&old).1, "old member stays current");
    assert!(
        h.db(|db| crate::store::binding_any(db, &candidate))
            .is_err()
    );
    // The roster is no longer frozen; a new replacement uses a NEW key.
    let (next, _) = h.replace(&old).unwrap();
    assert_ne!(next, id);
    // Abort of an admitted key returns the original receipt, not a cancellation.
    h.drive(&next).await;
    assert_eq!(h.view(&next).state, "admitted");
    let key = h.db(|db| journal::load(db, &next).unwrap().0.key().unwrap());
    let aborted = h.run.abort(&key).await.unwrap();
    assert_eq!(aborted.state, "admitted");
    assert!(aborted.receipt.is_some());
    assert_eq!(h.view(&next).state, "admitted");
}

#[tokio::test]
async fn p3_rootless_first_hook() {
    let mut h = Harness::new();
    let (id, member) = h.start("hook");
    h.drive(&id).await;
    // No root actor before input: background attestation is not ready.
    h.drive(&id).await;
    assert!(h.managed_binding(&member).is_none());
    // The first protected hook resolves the pending admitted root.
    let receipt = h.ingress_for(&member, "first");
    let binding = h.first_hook(receipt).unwrap();
    assert_eq!(binding.binding_generation, 1);
    assert_eq!(binding.member_id, member);
    // Background reconciliation racing after it cannot mint a second binding.
    h.qualify(&member);
    h.drive(&id).await;
    assert_eq!(h.count("SELECT count(*) FROM managed_bindings"), 1);
    assert_eq!(
        h.count(&format!(
            "SELECT count(*) FROM managed_rebinds WHERE member='{member}'"
        )),
        1
    );
    // A later hook for the same root sees the bound member (no-op rebind).
    let again = h.first_hook(h.ingress_for(&member, "again")).unwrap();
    assert_eq!(again.binding_generation, 1);
    // Reverse race: background binds first, then the hook rebinds as a no-op.
    let (id2, member2) = h.start("hook-2");
    h.drive(&id2).await;
    h.qualify(&member2);
    h.drive(&id2).await;
    let hooked = h.first_hook(h.ingress_for(&member2, "late")).unwrap();
    assert_eq!(hooked.binding_generation, 1);
    assert_eq!(h.count("SELECT count(*) FROM managed_bindings"), 2);
    // An unrelated or not-yet-admitted root is refused.
    let mut foreign = h.ingress_for(&member, "foreign");
    let other = agent(4096);
    foreign.lineage_root_id = other.clone();
    foreign.bound_execution_id = other.clone();
    foreign.attempt.lineage_root_id = other.clone();
    foreign.attempt.execution_id = other.clone();
    foreign.actor.native_id = "foreign".into();
    foreign.actor.address = "host/codex/store/foreign".into();
    foreign.successor_proof = SuccessorProof {
        lineage_root_id: other.clone(),
        bound_execution_id: other.clone(),
        current_execution_id: other.clone(),
        chain: vec![SuccessorLink {
            execution_id: other,
            parent_execution_id: None,
            sequence: 1,
        }],
    };
    assert_eq!(h.first_hook(foreign).err(), Some(Fault::Forbidden));
}

#[tokio::test]
async fn p3_join_not_delivery() {
    let mut h = Harness::new();
    let (id, member) = h.start("join");
    // Early: no admission and no binding, so neither read nor join can resolve.
    assert_eq!(h.join(&member, h.revision()).err(), Some(Fault::Forbidden));
    h.drive(&id).await;
    h.qualify(&member);
    h.drive(&id).await;
    // Stale revision: a new owner change after binding makes the join stale.
    let stale = h.revision();
    let update = Command::Update(crate::domain::Update {
        change: h.change(),
        name: "renamed".into(),
        purpose: "changed".into(),
    });
    h.execute(&h.owner.clone(), &update).unwrap();
    assert_eq!(h.join(&member, stale).err(), Some(Fault::Stale));
    assert_eq!(h.member(&member).0.member.state, MemberState::Pending);
    // Pending members may only read and join.
    let post = Command::Post(crate::domain::Message {
        change: h.change(),
        body: "too early".into(),
    });
    assert_eq!(h.p1(&member, post).err(), Some(Fault::Forbidden));
    // Unknown onboarding delivery never locks the member out of a direct join.
    h.db(|db| {
        db.execute(
            "UPDATE managed_delivery_outbox SET state='unknown',attention='outcome_unknown' WHERE effect_id IN (SELECT effect_id FROM managed_delivery_seeds WHERE member_id=?1)",
            [&member],
        )
        .unwrap()
    });
    let fresh = h.revision();
    h.join(&member, fresh).unwrap();
    assert_eq!(h.member(&member).0.member.state, MemberState::Active);
    assert_eq!(h.view(&id).jobs[0].state, "active");
    // Unknown delivery remains effect-scoped and is never resent as a new key.
    assert!(
        h.count(&format!(
            "SELECT count(*) FROM managed_delivery_outbox o JOIN managed_delivery_seeds s ON s.effect_id=o.effect_id WHERE s.member_id='{member}' AND o.state='unknown'"
        )) > 0
    );
}

#[tokio::test]
async fn p3_epoch_resume() {
    let mut h = Harness::new();
    // Resume/account failover BEFORE attestation: the successor proof anchors at
    // the admitted root and generation 1 binds the current execution.
    let (id, member) = h.start("resume");
    h.drive(&id).await;
    {
        let mut state = h.run.state();
        let root = state.roots.get_mut(&member).unwrap();
        root.execution = agent(777);
        root.sequence = 2;
        root.launch = uuid();
    }
    h.qualify(&member);
    h.drive(&id).await;
    let (bound, incarnation) = h.managed_binding(&member).unwrap();
    assert_eq!(bound.binding_generation, 1);
    assert_eq!(bound.attempt.execution_id, agent(777));
    // Another member's prepared context is not invalidated by this member's rebind (E7).
    let (_, peer) = h.active_member("peer").await;
    // E1: an attested actor-epoch change for the same attempt bumps the generation.
    let mut next = bound.clone();
    next.actor.epoch = 2;
    let receipt = CurrentReceipt {
        receipt_id: "epoch-2".into(),
        purpose: "egress".into(),
        lineage_root_id: bound.attempt.lineage_root_id.clone(),
        bound_execution_id: bound.attempt.execution_id.clone(),
        attempt: bound.attempt.clone(),
        incarnation: incarnation.clone(),
        actor: next.actor.clone(),
        successor_proof: SuccessorProof {
            lineage_root_id: bound.attempt.lineage_root_id.clone(),
            bound_execution_id: bound.attempt.execution_id.clone(),
            current_execution_id: bound.attempt.execution_id.clone(),
            chain: vec![SuccessorLink {
                execution_id: bound.attempt.execution_id.clone(),
                parent_execution_id: Some(bound.attempt.lineage_root_id.clone()),
                sequence: 2,
            }],
        },
    };
    let run = crate::managed_state::tests::FakeRun::with_receipt(receipt);
    let generation = h
        .db(|db| {
            crate::managed_state::rebind(db, &run, &bound, &next, &incarnation, "epoch-2", "egress")
        })
        .unwrap();
    assert_eq!(generation, 2);
    // Join follows the current generation's fresh proof.
    h.join(&member, h.revision()).unwrap();
    assert_eq!(h.member(&member).0.member.state, MemberState::Active);
    // The unrelated member still acts under its own generation.
    let post = Command::Post(crate::domain::Message {
        change: h.change(),
        body: "still valid".into(),
    });
    h.p1(&peer, post).unwrap();
    assert_eq!(h.managed_binding(&peer).unwrap().0.binding_generation, 1);
}

#[tokio::test]
async fn p3_membership_ever() {
    let mut h = Harness::new();
    let (_, old) = h.active_member("old").await;
    let old_receipt = h.ingress_for(&old, "old-root");
    h.old_terminal(&old);
    let (id, candidate) = h.replace(&old).unwrap();
    for _ in 0..3 {
        h.drive(&id).await;
        h.qualify(&candidate);
    }
    assert_eq!(h.view(&id).state, "switched");
    // The retired root cannot regain membership through a later hook, and its
    // historical binding no longer names a current member.
    assert_eq!(h.first_hook(old_receipt).err(), Some(Fault::Forbidden));
    assert!(!h.member(&old).1);
    assert_eq!(h.view(&id).replaces.as_deref(), Some(old.as_str()));
    // A Run receipt reusing an already enrolled root is never installed.
    let (dup, _) = h.start("dup");
    h.db(|db| journal::begin_submit(db, &dup).unwrap());
    let (enrollment, jobs) = h.db(|db| journal::load(db, &dup).unwrap());
    let (_, old_jobs) = h.db(|db| {
        let old_id: String = db
            .query_row(
                "SELECT enrollment FROM managed_enrollment_jobs WHERE member=?1",
                [&old],
                |row| row.get(0),
            )
            .unwrap();
        journal::load(db, &old_id).unwrap()
    });
    let mut reused = old_jobs[0].admission.clone().unwrap();
    reused.member_id = jobs[0].member.clone();
    let forged = StartReceipt {
        version: 1,
        store_id: RUN_STORE.into(),
        request_id: enrollment.request_id.clone(),
        receipt_id: "forged".into(),
        fingerprint: enrollment.fingerprint.clone().unwrap(),
        state: "admitted".into(),
        jobs: vec![reused],
    };
    assert_eq!(
        h.db(|db| journal::record_admission(db, &dup, &forged))
            .err(),
        Some(Fault::Conflict)
    );
    assert_eq!(h.view(&dup).state, "submit_possible");
    // A NEW lineage replacement of the replacement remains possible.
    h.join(&candidate, h.revision()).unwrap();
    h.old_terminal(&candidate);
    let (second, newer) = h.replace(&candidate).unwrap();
    for _ in 0..3 {
        h.drive(&second).await;
        h.qualify(&newer);
    }
    assert_eq!(h.view(&second).state, "switched");
    // An ordinary (non-enrolled) Run root can never join through P1.
    let legacy_member = h.member(&newer).0;
    assert!(legacy_member.run_id.is_some());
}

#[tokio::test]
async fn p3_replace_end_to_end() {
    let mut h = Harness::new();
    let (_, old) = h.active_member("old").await;
    let (_, other) = h.active_member("other").await;
    let slot_before: Vec<String> = h.db(|db| {
        crate::store::bindings(db, &h.pool)
            .unwrap()
            .into_iter()
            .map(|binding| binding.member.member_id)
            .collect()
    });
    let propose = Command::Propose(crate::domain::Propose {
        change: h.change(),
        result: "r".into(),
        criteria: "c".into(),
        snapshot: None,
    });
    h.execute(&h.owner.clone(), &propose).unwrap();
    // Failed-but-clean old root: terminal, cleaned, active pin.
    let target = h.old_terminal(&old);
    let revision = h.revision();
    let (id, candidate) = h.replace(&old).unwrap();
    assert_eq!(h.revision(), revision + 1);
    assert!(h.member(&old).1, "old member remains current");
    assert!(
        h.db(|db| crate::store::binding_any(db, &candidate))
            .is_err()
    );
    // Conflicting roster edits are frozen; messages are not.
    let remove = Command::Remove(crate::domain::Remove {
        change: h.change(),
        member_id: other.clone(),
    });
    assert_eq!(
        h.execute(&h.owner.clone(), &remove).err(),
        Some(Fault::Conflict)
    );
    h.drive(&id).await;
    let (enrollment, _) = h.db(|db| journal::load(db, &id).unwrap());
    let params = enrollment.params.unwrap();
    assert_eq!(params["mode"], "replace");
    assert_eq!(params["preconditions"], json!([target]));
    assert_eq!(h.view(&id).state, "admitted");
    let root = h.view(&id).jobs[0].lineage_root_id.clone().unwrap();
    assert_ne!(Some(root.clone()), h.member(&old).0.run_id);
    h.qualify(&candidate);
    h.drive(&id).await;
    assert_eq!(h.view(&id).state, "switched");
    // Atomic: old retired, candidate current pending with generation 1 in the same slot.
    assert!(!h.member(&old).1);
    let (installed, current) = h.member(&candidate);
    assert!(current);
    assert_eq!(installed.member.state, MemberState::Pending);
    assert_eq!(installed.run_id.as_deref(), Some(root.as_str()));
    assert_eq!(
        h.managed_binding(&candidate).unwrap().0.binding_generation,
        1
    );
    assert_eq!(h.revision(), revision + 2);
    let slot_after: Vec<String> = h.db(|db| {
        crate::store::bindings(db, &h.pool)
            .unwrap()
            .into_iter()
            .map(|binding| binding.member.member_id)
            .collect()
    });
    let position = slot_before.iter().position(|id| *id == old).unwrap();
    assert_eq!(slot_after[position], candidate);
    let pool: Value = h.db(|db| {
        serde_json::from_str(
            &db.query_row("SELECT data FROM pools", [], |row| row.get::<_, String>(0))
                .unwrap(),
        )
        .unwrap()
    });
    assert_eq!(pool["proposal"]["state"], "stale");
    // Old member/root stays immutable historical evidence.
    assert!(h.managed_binding(&old).is_some());
    // Candidate joins and votes on a fresh proposal.
    h.join(&candidate, h.revision()).unwrap();
    let propose = Command::Propose(crate::domain::Propose {
        change: h.change(),
        result: "r2".into(),
        criteria: "c2".into(),
        snapshot: None,
    });
    h.execute(&h.owner.clone(), &propose).unwrap();
    let pool: Value = h.db(|db| {
        serde_json::from_str(
            &db.query_row("SELECT data FROM pools", [], |row| row.get::<_, String>(0))
                .unwrap(),
        )
        .unwrap()
    });
    let voters = pool["proposal"]["voters"].as_array().unwrap();
    assert!(voters.contains(&json!(candidate)));
    assert!(!voters.contains(&json!(old)));
    assert_eq!(h.run.state().admissions, 3);
}

#[tokio::test]
async fn p3_replace_resume_race() {
    let mut h = Harness::new();
    // Old resumes before Run's precondition check: definitive first refusal.
    let (_, old) = h.active_member("old").await;
    h.old_terminal(&old);
    let (id, _) = h.replace(&old).unwrap();
    {
        let mut state = h.run.state();
        state.refuse_submit = Some(("precondition_failed", "none"));
    }
    h.drive(&id).await;
    assert_eq!(
        owner_view_state(&h, &id),
        ("refused".into(), Some("precondition_failed".into()))
    );
    assert!(h.member(&old).1);
    // Proven busy old lineage is refused before any submission.
    h.run.state().status = Some(OldStatus::NotReady);
    let (busy, _) = h.replace(&old).unwrap();
    h.drive(&busy).await;
    assert_eq!(h.view(&busy).state, "refused");
    let submits = h.run.state().submits;
    // Old resumes after Run admitted the candidate but before the Pool switch.
    let target = h.old_terminal(&old);
    let (race, candidate) = h.replace(&old).unwrap();
    h.drive(&race).await;
    assert_eq!(h.view(&race).state, "admitted");
    assert_eq!(h.run.state().submits, submits + 1);
    let mut resumed = target.clone();
    resumed.sequence += 1;
    resumed.execution_ref = format!("ex1_{}", "9".repeat(64));
    h.run.state().status = Some(OldStatus::Ready(resumed));
    h.qualify(&candidate);
    h.drive(&race).await;
    assert_eq!(
        owner_view_state(&h, &race),
        ("admitted".into(), Some("old_resumed".into()))
    );
    assert!(h.member(&old).1, "no switch on a moved old tip");
    assert!(
        h.db(|db| crate::store::binding_any(db, &candidate))
            .is_err()
    );
    // An old generation change (rebind) also blocks the switch with attention.
    h.run.state().status = Some(OldStatus::Ready(target));
    let (bound, incarnation) = h.managed_binding(&old).unwrap();
    let mut next = bound.clone();
    next.actor.epoch = 9;
    let receipt = CurrentReceipt {
        receipt_id: "old-epoch".into(),
        purpose: "egress".into(),
        lineage_root_id: bound.attempt.lineage_root_id.clone(),
        bound_execution_id: bound.attempt.execution_id.clone(),
        attempt: bound.attempt.clone(),
        incarnation: incarnation.clone(),
        actor: next.actor.clone(),
        successor_proof: SuccessorProof {
            lineage_root_id: bound.attempt.lineage_root_id.clone(),
            bound_execution_id: bound.attempt.execution_id.clone(),
            current_execution_id: bound.attempt.execution_id.clone(),
            chain: vec![SuccessorLink {
                execution_id: bound.attempt.execution_id.clone(),
                parent_execution_id: None,
                sequence: 1,
            }],
        },
    };
    let run = crate::managed_state::tests::FakeRun::with_receipt(receipt);
    h.db(|db| {
        crate::managed_state::rebind(db, &run, &bound, &next, &incarnation, "old-epoch", "egress")
    })
    .unwrap();
    h.drive(&race).await;
    assert_eq!(
        owner_view_state(&h, &race),
        ("admitted".into(), Some("old_rebound".into()))
    );
    assert!(h.member(&old).1);
    // The owner resolves; nothing is cancelled and the old member keeps its slot.
    let revision = h.view(&race).revision;
    h.resolve(&race, revision).unwrap();
    let view = h.view(&race);
    assert_eq!(view.state, "resolved");
    assert_eq!(view.jobs[0].state, "unassigned");
    assert!(h.member(&old).1);
    // A late attestation for the resolved candidate cannot switch it in.
    h.drive(&race).await;
    assert!(
        h.db(|db| crate::store::binding_any(db, &candidate))
            .is_err()
    );
}

#[tokio::test]
async fn p3_replace_unknown_candidate() {
    let mut h = Harness::new();
    let (_, old) = h.active_member("old").await;
    h.old_terminal(&old);
    let (id, candidate) = h.replace(&old).unwrap();
    h.run.state().lose_submit_ack = true;
    h.drive(&id).await;
    assert_eq!(
        owner_view_state(&h, &id),
        ("submit_possible".into(), Some("outcome_unknown".into()))
    );
    // The old roster stays current and frozen; no second candidate can start.
    assert!(h.member(&old).1);
    assert_eq!(h.replace(&old).err(), Some(Fault::Conflict));
    // Unknown submission cannot be resolved as retain_unassigned.
    let revision = h.view(&id).revision;
    assert_eq!(h.resolve(&id, revision).err(), Some(Fault::Conflict));
    h.restart();
    h.drive(&id).await;
    assert_eq!(h.view(&id).state, "admitted");
    assert_eq!(h.run.state().admissions, 2, "old start + one candidate");
    // Admitted candidates cannot be cancelled away.
    let cancel = Command::CancelReplacement(crate::domain::CancelReplacement {
        change: h.change(),
        operation_id: id.clone(),
    });
    assert_eq!(
        h.execute(&h.owner.clone(), &cancel).err(),
        Some(Fault::Conflict)
    );
    // Candidate qualification failure: explicit retain_unassigned fences late bind.
    h.run.state().failed.insert(candidate.clone());
    h.drive(&id).await;
    assert_eq!(
        h.view(&id).jobs[0].attention.as_deref(),
        Some("execution_failed")
    );
    let revision = h.view(&id).revision;
    assert_eq!(h.resolve(&id, revision + 1).err(), Some(Fault::Stale));
    h.resolve(&id, revision).unwrap();
    assert_eq!(h.view(&id).state, "resolved");
    h.qualify(&candidate);
    h.drive(&id).await;
    assert!(
        h.db(|db| crate::store::binding_any(db, &candidate))
            .is_err()
    );
    assert!(h.managed_binding(&candidate).is_none());
    assert!(h.member(&old).1);
    // The candidate's pin stays recorded as owner-visible unassigned history.
    assert!(h.view(&id).jobs[0].pin_id.is_some());
}

#[tokio::test]
async fn p3_old_outbox_after_retirement() {
    let mut h = Harness::new();
    let (_, old) = h.active_member("old").await;
    let (_, peer) = h.active_member("peer").await;
    // Old member effects: one still pending, one frozen-and-unknown.
    let post = Command::Post(crate::domain::Message {
        change: h.change(),
        body: "before replacement".into(),
    });
    h.p1(&peer, post).unwrap();
    let old_seeds: Vec<(String, String)> = h.db(|db| {
        let mut stmt = db
            .prepare("SELECT s.effect_id,o.state FROM managed_delivery_seeds s JOIN managed_delivery_outbox o ON o.effect_id=s.effect_id WHERE s.member_id=?1 AND s.final_notice=0 ORDER BY s.effect_id")
            .unwrap();
        stmt.query_map([&old], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    });
    assert!(old_seeds.len() >= 2);
    let unknown = old_seeds[0].0.clone();
    h.db(|db| {
        db.execute(
            "UPDATE managed_delivery_outbox SET state='unknown' WHERE effect_id=?1",
            [&unknown],
        )
        .unwrap();
        db.execute(
            "UPDATE managed_delivery_outbox SET state='pending' WHERE effect_id<>?1 AND effect_id IN (SELECT effect_id FROM managed_delivery_seeds WHERE member_id=?2)",
            rusqlite::params![unknown, old],
        )
        .unwrap();
    });
    h.old_terminal(&old);
    let (id, candidate) = h.replace(&old).unwrap();
    h.drive(&id).await;
    h.qualify(&candidate);
    h.drive(&id).await;
    assert_eq!(h.view(&id).state, "switched");
    // Frozen old effects never retarget the new member.
    let retargeted = h.count(&format!(
        "SELECT count(*) FROM managed_delivery_seeds WHERE member_id='{candidate}' AND effect_id IN ({})",
        old_seeds
            .iter()
            .map(|(id, _)| format!("'{id}'"))
            .collect::<Vec<_>>()
            .join(",")
    ));
    assert_eq!(retargeted, 0);
    // Known-unsent old effects are sealed as not delivered; unknown is retained.
    let states: BTreeMap<String, String> = h.db(|db| {
        let mut stmt = db
            .prepare("SELECT s.effect_id,o.state FROM managed_delivery_seeds s JOIN managed_delivery_outbox o ON o.effect_id=s.effect_id WHERE s.member_id=?1 AND s.final_notice=0")
            .unwrap();
        stmt.query_map([&old], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    });
    assert_eq!(states[&unknown], "unknown");
    assert!(
        states
            .iter()
            .filter(|(id, _)| **id != unknown)
            .all(|(_, state)| state == "not_delivered")
    );
    // Exactly one onboarding and one replacement notice for the candidate; no
    // duplicate onboarding text.
    let onboarding = h.count(&format!(
        "SELECT count(*) FROM effects WHERE member='{candidate}' AND json_extract(data,'$.work.text') LIKE 'Agent Pool onboarding%'"
    ));
    assert_eq!(onboarding, 1);
    // The old member keeps one final notice seed scoped to its own lineage.
    assert_eq!(
        h.count(&format!(
            "SELECT count(*) FROM managed_delivery_seeds WHERE member_id='{old}' AND final_notice=1"
        )),
        1
    );
}

/// Schema v15 upgrades a v14 store in one transaction and older binaries cannot open it.
#[test]
fn p3_schema_v15_migration_and_rollback() {
    let root = std::env::var_os("TMPDIR").expect("task TMPDIR required");
    let dir = tempfile::tempdir_in(root).unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join("pool.db");
    let owner = Actor::verified("host/codex/store/owner".into(), "owner", "root").unwrap();
    {
        let mut store = Store::open(&path).unwrap();
        store
            .execute(
                &owner,
                &Command::Create(Create {
                    request_key: "create".into(),
                    name: "v14".into(),
                    purpose: "kept".into(),
                    acceptance: None,
                }),
            )
            .unwrap();
        let db = store.test_db();
        db.execute_batch("DROP TABLE managed_enrollment_jobs; DROP TABLE managed_enrollments; DROP TABLE managed_route_attention; DROP TABLE managed_delivery_liveness; PRAGMA user_version=14;").unwrap();
    }
    // A failing v15 step rolls back to the intact v14 schema and data.
    {
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE managed_enrollments(blocker INTEGER);")
            .unwrap();
    }
    assert!(Store::open(&path).is_err());
    {
        let db = rusqlite::Connection::open(&path).unwrap();
        let version: i64 = db
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 14);
        assert_eq!(
            db.query_row("SELECT count(*) FROM pools", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        db.execute_batch("DROP TABLE managed_enrollments;").unwrap();
    }
    let mut store = Store::open(&path).unwrap();
    let db = store.test_db();
    let version: i64 = db
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 15);
    assert_eq!(
        db.query_row("SELECT count(*) FROM pools", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM managed_enrollments", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    // Retained journal rows can be neither deleted nor rekeyed.
    assert!(db.execute("DELETE FROM managed_enrollments", []).is_ok());
    drop(store);
    // A newer schema is refused without mutation (older-binary behavior).
    {
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch("PRAGMA user_version=16;").unwrap();
    }
    assert!(matches!(Store::open(&path), Err(Fault::Conflict)));
}
