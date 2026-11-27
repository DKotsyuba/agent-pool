//! Failure routing and recovery against isolated Run and Quota socket peers.

use super::*;
use crate::chat_recovery::Schedule;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use tokio::task::JoinHandle;

const OWNER: &str = "test/codex/owner/session";
const FAILURE_TIME: f64 = 1_700_000_000.0;
const UNKNOWN_ARGUMENT: &str = "unknown, missing, or incorrectly typed tool argument";

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type AuditRow = (String, String, Option<String>, Option<String>);

/// Mutable replies and the exact resume arguments received by the synthetic Run peer.
struct Run {
    failed: usize,
    leader_running: AtomicBool,
    sequence: AtomicU32,
    failure_kind: Mutex<&'static str>,
    calls: Mutex<Vec<Value>>,
    refusal: Option<&'static str>,
    refusals: AtomicU32,
}

impl Run {
    /// Replies with one typed failure or a new successful admission in the same lineage.
    fn response(&self, request: &Value) -> Value {
        let context = &request["params"];
        let mut reply = json!({"jsonrpc":"2.0","id":request["id"]});
        match request["method"].as_str() {
            Some("capabilities") => {
                reply["result"] =
                    json!({"schema_version":1,"product":"agent-run","store_id":RUN_STORE});
            }
            Some("agent_integration") => {
                let failed = context["agent_id"] == agent(self.failed);
                let sequence = if failed {
                    self.sequence.load(Ordering::SeqCst)
                } else {
                    1
                };
                let failure = failed && sequence < 5;
                let status = if failure {
                    "failed"
                } else if !failed && !self.leader_running.load(Ordering::SeqCst) {
                    "cancelled"
                } else {
                    "running"
                };
                reply["result"] = json!({
                    "schema_version":1, "agent":{
                        "agent_id":context["agent_id"],"status":status,"sequence":sequence,
                        "model":"test","finished_at":FAILURE_TIME,
                        "failure_kind":*self.failure_kind.lock().unwrap_or_else(|e| e.into_inner()),
                        "failure_text":"failover_blocked: no_eligible_account"
                    },
                    "communication":{"state":"unknown","reason":"unavailable"}
                });
            }
            Some("resume") => {
                self.calls
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(context.clone());
                let sequence = self.sequence.load(Ordering::SeqCst);
                let refusal = self.refusal.filter(|_| {
                    self.refusals
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                        .is_ok()
                });
                if let Some(code) = refusal {
                    reply["error"] = if code == UNKNOWN_ARGUMENT {
                        json!({"code":-32602,"message":code})
                    } else {
                        json!({"code":-32000,"message":"refused","data":{"code":code}})
                    };
                } else if sequence > 1 && context["expected_sequence"] != sequence {
                    reply["error"] = json!({"code":-32000,"message":"refused","data":{"code":"sequence_mismatch"}});
                } else {
                    self.sequence.store(sequence + 1, Ordering::SeqCst);
                    reply["result"] = json!({"agent_id":context["agent_id"],"sequence":sequence+1});
                }
            }
            method => panic!("unexpected Run method {method:?}"),
        }
        reply
    }

    /// Copies recorded calls for assertions without holding a guard across awaits.
    fn calls(&self) -> Vec<Value> {
        self.calls.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

/// Per-test fixture launches only synthetic Unix peers and aborts them on drop.
struct Case {
    tasks: Vec<JoinHandle<()>>,
    _root: tempfile::TempDir,
    config: Config,
    store: SharedStore,
    batch: state::ChatBatch,
    run: Arc<Run>,
    fresh: Arc<AtomicBool>,
    exhausted: Arc<AtomicBool>,
}

impl Drop for Case {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Case {
    /// Installs an admitted leader and member and creates mutable fake Run/Quota peers.
    async fn new(
        failed: usize,
        sequence: u32,
        refusal: Option<(&'static str, u32)>,
        enabled: bool,
    ) -> TestResult<Self> {
        let (root, mut config, store) = fixture()?;
        let mut args = input(Some(OWNER));
        args["members"] = json!([spec("pool-leader"), spec("implement")]);
        args["auto_resume"] = enabled.into();
        let batch = stored(&store, move |store| state::start(store, parse(args)?, 1002)).await?;
        install(&store, &batch).await?;
        let socket = config.run_socket.as_ref().ok_or("Run socket missing")?;
        let run = Arc::new(Run {
            failed,
            leader_running: true.into(),
            sequence: sequence.into(),
            failure_kind: Mutex::new("quota_exhausted"),
            calls: Mutex::default(),
            refusal: refusal.map(|(code, _)| code),
            refusals: refusal.map_or(0, |(_, count)| count).into(),
        });
        let run_reply = run.clone();
        let run_peer = mock(socket, move |request| run_reply.response(&request))?;
        let fresh = Arc::new(AtomicBool::new(false));
        let fresh_reply = fresh.clone();
        let exhausted = Arc::new(AtomicBool::new(false));
        let exhausted_reply = exhausted.clone();
        config.quota_socket = Some(root.path().join("quota.sock"));
        let quota_peer = mock(
            config
                .quota_socket
                .as_deref()
                .ok_or("Quota socket missing")?,
            move |request| {
                assert_eq!(
                    request,
                    json!({"version":1,"method":"snapshot","accounts":[],"model":"test"})
                );
                let fresh = fresh_reply.load(Ordering::SeqCst);
                let exhausted = exhausted_reply.load(Ordering::SeqCst);
                json!({"version":1,"result":{"schema_version":2,"revision":1,
                "evaluated_at":FAILURE_TIME+60.0,"accounts":[{"models":[{
                    "provider":"fixture","model":"test","state":if exhausted { "exhausted" } else { "known" },
                    "state_validity":{"kind":"until","at":253400000000.0},
                    "evidence":"fresh","remaining_percent":if exhausted { 0 } else { 80 },
                    "exhausted_until":4102444800.0,
                    "newest_observed_at":if fresh { FAILURE_TIME+1.0 } else { FAILURE_TIME }
                }]}]}})
            },
        )?;
        Ok(Self {
            tasks: vec![run_peer, quota_peer],
            _root: root,
            config,
            store,
            batch,
            run,
            fresh,
            exhausted,
        })
    }

    /// Sweeps both seats once, regardless of generated membership ID order.
    async fn tick(&self) -> TestResult {
        let mut schedule = Schedule::default();
        for _ in 0..2 {
            schedule.tick(&self.config, &self.store).await?;
        }
        Ok(())
    }

    /// Reads the journal and both outbox routes without sending a Bridge notice.
    async fn audit(&self) -> TestResult<Vec<AuditRow>> {
        let pool = self.batch.pool_id.clone();
        Ok(stored(&self.store, move |store| {
            let mut query = store.test_db().prepare(
                "SELECT json_extract(data,'$.kind'), json_extract(data,'$.body'),
                 json_extract(data,'$.audience[0]'),
                 (SELECT json_extract(x.data,'$.work.text') FROM effects x
                  WHERE x.pool=e.pool AND json_extract(x.data,'$.work.scope')='owner:'||e.pool
                    AND instr(json_extract(x.data,'$.work.text'),json_extract(e.data,'$.body'))>0 LIMIT 1)
                 FROM events e WHERE pool=?1 AND json_extract(data,'$.kind') LIKE 'member_%'
                 AND json_extract(data,'$.kind') IN ('member_execution_failed','member_resume_attempt','member_resume_outcome')
                 ORDER BY id",
            )?;
            query.query_map([pool], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)))?
                .collect::<Result<Vec<_>,_>>().map_err(Into::into)
        }).await?)
    }

    /// Moves persisted backoff into the past after a test of the actual deadline.
    async fn expire_backoff(&self) -> TestResult {
        stored(&self.store, |store| {
            assert_eq!(
                store
                    .test_db()
                    .execute("UPDATE chat_recovery SET next_ms=0 WHERE next_ms>0", [])?,
                1
            );
            Ok(())
        })
        .await?;
        Ok(())
    }
}

/// Serves framed protocol requests without touching any installed service.
fn mock(
    path: &Path,
    response: impl Fn(Value) -> Value + Send + 'static,
) -> TestResult<JoinHandle<()>> {
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let Ok(frame) = integrations::read_frame(&mut stream).await else {
                continue;
            };
            let Ok(request) = serde_json::from_slice(&frame) else {
                continue;
            };
            if write(&mut stream, &response(request)).await.is_err() {
                break;
            }
        }
    }))
}

/// Fresh evidence is strictly after failure and only one request is admitted for that execution.
#[tokio::test]
async fn recovery_waits_for_fresh_evidence_and_resumes_once() -> TestResult {
    let case = Case::new(1, 4, None, true).await?;
    case.tick().await?;
    let audit = case.audit().await?;
    assert_eq!(audit.len(), 1);
    assert!(audit[0].1.contains("Waiting for quota."));
    let overview = owner_call(
        OwnerRequest {
            tool: "pool_get".into(),
            arguments: json!({"pool_id":case.batch.pool_id}),
        },
        &case.config,
        &case.store,
    )
    .await?;
    let ChatReply::Overview(overview) = overview else {
        return Err("expected overview".into());
    };
    assert!(
        overview
            .roster
            .iter()
            .any(|seat| seat.agent_id.as_deref() == Some(agent(1).as_str())
                && seat.process == "waiting for quota")
    );
    assert!(case.run.calls().is_empty());
    case.fresh.store(true, Ordering::SeqCst);
    case.tick().await?;
    case.tick().await?;
    let calls = case.run.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0]["expected_sequence"], 4);
    assert_eq!(calls[0]["agent_id"], agent(1));
    assert_eq!(
        calls[0]["task"],
        "Quota restored. Re-read the pool chat tail and continue your role."
    );
    let audit = case.audit().await?;
    assert_eq!(audit.len(), 3);
    assert!(audit[2].1.contains("Run admitted execution 5"));
    assert!(audit.iter().all(|entry| {
        entry.2.as_deref() == Some(case.batch.jobs[0].member_id.as_str()) && entry.3.is_none()
    }));
    Ok(())
}

/// A failed or unavailable leader routes to the initiating owner instead of a member.
#[tokio::test]
async fn recovery_routes_leader_failure_and_inactive_leader_to_owner() -> TestResult {
    for failed in [0, 1] {
        let case = Case::new(failed, 4, None, true).await?;
        case.run.leader_running.store(false, Ordering::SeqCst);
        case.tick().await?;
        let audit = case.audit().await?;
        assert_eq!(audit.len(), 1);
        assert!(audit[0].2.is_none());
        assert!(
            audit[0]
                .3
                .as_ref()
                .is_some_and(|notice| notice.contains("Waiting for quota."))
        );
    }
    Ok(())
}

/// Both policy switches preserve the first failure notice while disabling resume.
#[tokio::test]
async fn recovery_honors_global_and_pool_opt_out() -> TestResult {
    for pool_opt_in in [true, false] {
        let mut case = Case::new(1, 4, None, pool_opt_in).await?;
        case.config.auto_resume = !pool_opt_in;
        case.fresh.store(true, Ordering::SeqCst);
        case.tick().await?;
        assert!(case.run.calls().is_empty());
        assert!(case.audit().await?[0].1.contains("disabled"));
    }
    Ok(())
}

/// Closed pools, removed/replaced seats, and already advanced lineages never resume.
#[tokio::test]
async fn recovery_rechecks_membership_pool_and_lineage() -> TestResult {
    for change in ["closed", "removed", "replaced", "resumed"] {
        let case = Case::new(1, 4, None, true).await?;
        case.tick().await?;
        match change {
            "closed" => {
                owner_call(OwnerRequest { tool:"pool_close".into(),
                    arguments:json!({"pool_id":case.batch.pool_id,"expected_revision":1,"request_key":"close"}) },
                    &case.config,&case.store).await?;
            }
            "removed" => {
                let id = case.batch.jobs[1].member_id.clone();
                stored(&case.store, move |store| {
                    store
                        .test_db()
                        .execute("UPDATE members SET current=0 WHERE id=?1", [id])?;
                    Ok(())
                })
                .await?;
            }
            "replaced" => {
                owner_call(OwnerRequest { tool:"pool_replace".into(),
                    arguments:json!({"pool_id":case.batch.pool_id,"expected_revision":1,"request_key":"replace",
                        "member_id":case.batch.jobs[1].member_id,"member":spec("implement")}) },
                    &case.config,&case.store).await?;
            }
            _ => case.run.sequence.store(5, Ordering::SeqCst),
        }
        case.fresh.store(true, Ordering::SeqCst);
        case.tick().await?;
        assert!(case.run.calls().is_empty(), "{change}");
    }
    Ok(())
}

/// A cooldown refusal backs off, then uses a distinct key and can succeed.
#[tokio::test]
async fn recovery_retries_binding_cooldown_after_backoff() -> TestResult {
    let case = Case::new(1, 4, Some(("binding_cooldown", 1)), true).await?;
    case.fresh.store(true, Ordering::SeqCst);
    case.tick().await?;
    case.tick().await?;
    assert_eq!(case.run.calls().len(), 1);
    assert!(case.audit().await?[2].1.contains("Pool will retry after"));
    case.expire_backoff().await?;
    case.tick().await?;
    let calls = case.run.calls();
    assert_eq!(calls.len(), 2);
    assert_ne!(calls[0]["request_id"], calls[1]["request_id"]);
    assert!(
        case.audit().await?[4]
            .1
            .contains("Run admitted execution 5")
    );
    Ok(())
}

/// Repeated cooldowns end the bounded retry budget and record each outcome.
#[tokio::test]
async fn recovery_caps_resume_attempts() -> TestResult {
    let case = Case::new(1, 4, Some(("binding_cooldown", 99)), true).await?;
    case.fresh.store(true, Ordering::SeqCst);
    case.tick().await?;
    for _ in 0..2 {
        case.expire_backoff().await?;
        case.tick().await?;
    }
    case.tick().await?;
    assert_eq!(case.run.calls().len(), 3);
    let audit = case.audit().await?;
    assert_eq!(audit.len(), 7);
    assert!(audit[6].1.contains("resume attempt limit"));
    Ok(())
}

/// A competing resume or an older Run stops the scheduler and logs a visible outcome.
#[tokio::test]
async fn recovery_stops_on_sequence_mismatch_or_old_run() -> TestResult {
    for (refusal, message) in [
        ("sequence_mismatch", "newer execution"),
        (UNKNOWN_ARGUMENT, "Auto-resume unavailable"),
    ] {
        let case = Case::new(1, 4, Some((refusal, 1)), true).await?;
        case.fresh.store(true, Ordering::SeqCst);
        case.tick().await?;
        case.tick().await?;
        assert_eq!(case.run.calls().len(), 1);
        assert!(case.audit().await?[2].1.contains(message));
    }
    Ok(())
}

/// Sequence one remains guarded by the original execution ID on older Run versions.
#[tokio::test]
async fn recovery_pins_first_execution() -> TestResult {
    let case = Case::new(1, 1, None, true).await?;
    case.fresh.store(true, Ordering::SeqCst);
    case.tick().await?;
    let calls = case.run.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0]["run_id"], agent(1));
    assert!(calls[0].get("expected_sequence").is_none());
    assert!(
        case.audit().await?[2]
            .1
            .contains("Run admitted execution 2")
    );
    Ok(())
}

/// Transport loss uses Run's safe failure code and Quota's known reset estimate.
#[tokio::test]
async fn recovery_notices_runtime_transport_failure_and_reset_time() -> TestResult {
    let case = Case::new(1, 4, None, true).await?;
    *case
        .run
        .failure_kind
        .lock()
        .map_err(|_| "fixture lock poisoned")? = "runtime_transport_failed";
    case.exhausted.store(true, Ordering::SeqCst);
    case.tick().await?;
    assert!(case.run.calls().is_empty());
    let audit = case.audit().await?;
    assert_eq!(audit.len(), 1);
    assert!(audit[0].1.contains("runtime_transport_failed"));
    assert!(audit[0].1.contains("2100-01-01T00:00:00Z"));
    Ok(())
}
