//! Isolated Pool chat contract fixtures. The Run socket is a synthetic peer.
use super::*;
use crate::domain::{Author, Reply};
use crate::store::Store;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    sync::{Arc, Mutex},
};
use tokio::{io::AsyncReadExt, net::UnixListener, sync::Semaphore};

const RUN_STORE: &str = "store_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// Calls the resident owner dispatcher as the test owner UID.
async fn owner_call(
    request: OwnerRequest,
    config: &Config,
    store: &SharedStore,
) -> Result<ChatReply, Fault> {
    super::owner_call(request, config, store, 1002).await
}

fn fixture() -> Result<(tempfile::TempDir, Config, SharedStore), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let path = root.path();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    let uid = fs::metadata(path)?.uid();
    let config: Config = serde_json::from_value(json!({
        "socket_path":path.join("pool.sock"),"database_path":path.join("pool.db"),"expected_uid":uid,
        "bridge_registration_socket":path.join("registration"),"bridge_core_socket":path.join("core"),
        "bridge_credential_file":path.join("token"),"bridge_producer_id":"fixture","bridge_audience":"fixture",
        "bridge_server_executable":"/fixture/bridge","bridge_server_sha256":"0".repeat(64),
        "run_socket":path.join("run.sock")
    }))?;
    let store = Arc::new(Mutex::new(Store::open(&config.database_path)?));
    Ok((root, config, store))
}

fn spec(profile: &str) -> Value {
    json!({"assignment":format!("{profile} assignment"),"spec":{"provider":"fixture","model":"test","profile":profile,"workdir":"/fixture"}})
}

fn input(address: Option<&str>) -> Value {
    json!({"request_key":"start","name":"Mixed profiles","purpose":"Agree a result","members":[spec("implement"),spec("review"),spec("implement")],"owner_address":address})
}

fn agent(index: usize) -> String {
    format!("ag-20261119-120000-{:010x}", index + 1)
}

fn execution(index: usize) -> String {
    format!("ex1_{:064x}", index + 1)
}

fn member_call(
    batch: &state::ChatBatch,
    index: usize,
    tool: &str,
    request_id: &str,
    arguments: Value,
) -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"member_call_v1","params":{
        "version":1,"run_store_id":RUN_STORE,"agent_id":agent(index),"sequence":1,
        "pool_id":batch.pool_id,"seat_id":batch.jobs[index].member_id,
        "tool":tool,"arguments":arguments,"request_id":request_id
    }})
}

fn reply_text(value: &Value) -> &str {
    value
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn ok(value: &Value) -> bool {
    value.pointer("/result/is_error") == Some(&json!(false))
}

fn assert_refusal(value: &Value, kind: &str) {
    assert_eq!(value.get("result"), None);
    let error = &value["error"];
    assert_eq!(error.as_object().map(Map::len), Some(3));
    assert_eq!(error["code"], -32000);
    assert!(
        error["message"]
            .as_str()
            .is_some_and(|text| !text.is_empty())
    );
    assert_eq!(error["data"], json!({"kind":kind}));
}

/// Kernel UID admission rejects foreign peers, the resident itself, and excess connections.
#[tokio::test]
async fn chat_owner_ingress_checks_peer_and_bound() -> Result<(), Box<dyn std::error::Error>> {
    let permits = Arc::new(Semaphore::new(1));
    let (server, _) = UnixStream::pair()?;
    let uid = server.peer_cred()?.uid();
    let resident = uid.wrapping_add(1);
    let accepted = crate::observer_socket::admit_owner(server, resident, &[uid], &permits)
        .ok_or("allowlisted peer rejected")?;
    for (resident, allowed, expected) in [
        (resident, vec![uid], "unavailable"),
        (resident, vec![resident], "unauthorized"),
        (uid, vec![uid], "unauthorized"),
    ] {
        let (server, mut peer) = UnixStream::pair()?;
        assert!(
            crate::observer_socket::admit_owner(server, resident, &allowed, &permits).is_none()
        );
        let mut body = Vec::new();
        peer.read_to_end(&mut body).await?;
        let response: Value = serde_json::from_slice(&body)?;
        assert_eq!(response["error"]["code"], expected);
    }
    drop(accepted);
    assert_eq!(permits.available_permits(), 1);
    let catalog = owner_tools();
    assert_eq!(
        catalog
            .iter()
            .filter_map(|row| row["name"].as_str())
            .collect::<Vec<_>>(),
        OWNER_TOOLS
    );
    Ok(())
}

/// A lost acknowledgement reuses the original frozen request and seats via receipt lookup.
#[tokio::test]
async fn chat_uncertain_start_reuses_saved_receipt() -> Result<(), Box<dyn std::error::Error>> {
    let (_root, config, store) = fixture()?;
    let socket = config.run_socket.as_ref().ok_or("fixture Run socket")?;
    let listener = UnixListener::bind(socket)?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
    let mock = tokio::spawn(async move {
        let mut original = Value::Null;
        for index in 0..3 {
            let (mut stream, _) = listener.accept().await?;
            let request: Value =
                serde_json::from_slice(&integrations::read_frame(&mut stream).await?)?;
            assert_eq!(request["method"], "start_batch");
            let result = match index {
                0 => {
                    original = request["params"].clone();
                    continue;
                }
                _ => {
                    if index == 2 {
                        assert_eq!(request["params"], original);
                    } else {
                        assert_ne!(request["params"]["request_id"], original["request_id"]);
                    }
                    let request_jobs = &request["params"];
                    let jobs = request_jobs["jobs"].as_array().ok_or("jobs")?;
                    let mut entries = Vec::new();
                    for (index, spec) in jobs.iter().enumerate() {
                        assert_eq!(spec["pool_chat"]["version"], 1);
                        assert!(
                            crate::domain::store_id(
                                spec["pool_chat"]["pool_store_id"].as_str().ok_or("store")?
                            )
                            .is_ok()
                        );
                        assert_eq!(spec["profile"], ["implement", "review", "implement"][index]);
                        entries.push(json!({"index":index,"agent_id":agent(index),"sequence":1,"execution_ref":execution(index)}));
                    }
                    let receipt = json!({"version":1,"store_id":RUN_STORE,"request_id":request_jobs["request_id"],"jobs":entries});
                    json!({"replayed":index == 2,"receipt":receipt})
                }
            };
            write(
                &mut stream,
                &json!({"jsonrpc":"2.0","id":request["id"],"result":result}),
            )
            .await?;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(original)
    });
    let request = || OwnerRequest {
        tool: "pool_start".into(),
        arguments: input(None),
    };
    let mut second = request();
    second.arguments["request_key"] = json!("other-start");
    let (first, second) = tokio::join!(
        owner_call(request(), &config, &store),
        owner_call(second, &config, &store),
    );
    let mut launched = Vec::new();
    for reply in [first?, second?] {
        let templates = renderer()?;
        let ChatReply::Launch {
            pool_id,
            state,
            seats,
            ..
        } = reply
        else {
            return Err("launch".into());
        };
        assert_eq!(state, "pending");
        let result = present(
            Ok(ChatReply::Launch {
                pool_id: pool_id.clone(),
                revision: 1,
                state: state.clone(),
                request_key: "start".into(),
                seats: Vec::new(),
                old_agent_id: None,
                owner_binding_hint: Some(OWNER_BIND_HINT),
            }),
            templates,
        );
        assert_eq!(result.is_error, Some(false));
        let result = serde_json::to_value(result)?;
        assert!(
            result["content"][0]["text"]
                .as_str()
                .is_some_and(|text| text.contains("once the session hook binds"))
        );
        launched.push((pool_id, seats));
    }
    // Persist the Run fence, then restart before any socket write.
    stored(&store, |store| {
        let first = state::next_batch(store, "")?.ok_or(Fault::Internal)?;
        let second = state::next_batch(store, &first.id)?.ok_or(Fault::Internal)?;
        assert_ne!(first.id, second.id);
        state::fence(store, &first.id, RUN_STORE)?;
        state::fence(store, &second.id, RUN_STORE)?;
        Ok(())
    })
    .await?;
    drop(store);
    let store = Arc::new(Mutex::new(crate::store::Store::open(
        &config.database_path,
    )?));
    // Neither owner reconnects.
    let mut cursor = String::new();
    for _ in 0..3 {
        reconcile(&config, &store, &mut cursor).await?;
    }
    let original = tokio::time::timeout(EXCHANGE_TIMEOUT, mock)
        .await??
        .map_err(|e| e.to_string())?;
    assert!(
        launched
            .iter()
            .any(|(_, seats)| original["jobs"][0]["pool_chat"]["seat_id"] == seats[0].id)
    );
    for (pool_id, seats) in launched {
        let ChatReply::Overview(view) = stored(&store, move |store| {
            state::owner_call(store, "pool_get", json!({"pool_id":pool_id}))
        })
        .await?
        else {
            return Err("overview".into());
        };
        for (index, (old, new)) in seats.iter().zip(view.roster).enumerate() {
            assert_eq!(old.id, new.seat_id);
            assert_eq!(new.agent_id, Some(agent(index)));
        }
    }
    let mut changed = request();
    changed.arguments["purpose"] = json!("changed");
    assert!(matches!(
        owner_call(changed, &config, &store).await,
        Err(Fault::Conflict)
    ));
    Ok(())
}

async fn reserve(store: &SharedStore, address: Option<&str>) -> Result<state::ChatBatch, Fault> {
    let args = input(address);
    stored(store, move |store| {
        let batch = state::start(store, parse(args)?, 1002)?;
        Ok(batch)
    })
    .await
}

async fn install(store: &SharedStore, batch: &state::ChatBatch) -> Result<(), Fault> {
    let id = batch.id.clone();
    stored(store, move |store| {
        let batch = state::fence(store, &id, RUN_STORE)?;
        let rows = (0..batch.jobs.len())
            .map(|index| integrations::BatchAdmission {
                agent_id: agent(index),
                sequence: 1,
                execution_ref: execution(index),
                pin_id: None,
                release_token: None,
            })
            .collect();
        state::admitted(store, &batch, rows)
    })
    .await
}

/// Member authorization, filtered durable history, unanimous agreement, and owner recovery.
#[tokio::test]
async fn chat_mixed_profiles_complete_without_owner_address()
-> Result<(), Box<dyn std::error::Error>> {
    complete_with_address(None).await
}

#[tokio::test]
async fn chat_mixed_profiles_queue_notice_for_known_owner() -> Result<(), Box<dyn std::error::Error>>
{
    complete_with_address(Some("test/codex/route/owner")).await
}

async fn complete_with_address(
    address: Option<&'static str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (_root, config, store) = fixture()?;
    let mut args = input(address);
    let structured = address.is_some();
    if structured {
        args["acceptance"] = json!([{"id":"tested","text":"Result is tested"}]);
    }
    let batch = stored(&store, move |store| state::start(store, parse(args)?, 1002)).await?;
    let templates = renderer()?;
    let call = |value| private_call(value, &config, &store, templates);
    let catalog =
        call(json!({"jsonrpc":"2.0","id":1,"method":"chat_catalog_v1","params":{"version":1}}))
            .await;
    let names = catalog["result"]["tools"]
        .as_array()
        .ok_or("catalog")?
        .iter()
        .filter_map(|row| row["name"].as_str())
        .collect::<Vec<_>>();
    assert_eq!(names, MEMBER_TOOLS);
    let wrong_version =
        call(json!({"jsonrpc":"2.0","id":1,"method":"chat_catalog_v1","params":{"version":2}}))
            .await;
    assert_eq!(wrong_version["error"]["code"], -32602);
    let get = || member_call(&batch, 0, "pool_get", "get", json!({}));
    let batch_id = batch.id.clone();
    stored(&store, move |store| {
        state::fence(store, &batch_id, RUN_STORE)
    })
    .await?;
    let pending = call(get()).await;
    assert_eq!(pending["error"]["code"], -32000);
    assert_eq!(
        pending["error"]["data"],
        json!({"kind":"admission_pending","retry_after_ms":1000})
    );
    install(&store, &batch).await?;
    let mut foreign = get();
    foreign["params"]["seat_id"] = json!(batch.jobs[2].member_id);
    assert_refusal(&call(foreign).await, "not_member");
    let mut wrong_store = get();
    wrong_store["params"]["run_store_id"] = json!("store_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    assert_refusal(&call(wrong_store).await, "not_member");
    let overview = call(get()).await;
    assert!(
        ok(&overview) && reply_text(&overview).contains("joined=false"),
        "{overview}"
    );
    let join = |index, rev| {
        member_call(
            &batch,
            index,
            "pool_join",
            &format!("join-{index}"),
            json!({"expected_revision":rev}),
        )
    };
    assert!(ok(&call(join(0, 1)).await));
    let premature = member_call(
        &batch,
        0,
        "pool_propose",
        "premature",
        json!({"expected_revision":2,"result":"result","criteria":"evidence"}),
    );
    assert!(!ok(&call(premature).await));
    assert!(ok(&call(join(1, 2)).await));
    assert!(ok(&call(join(2, 3)).await));
    let get_history = |index| {
        member_call(
            &batch,
            index,
            "pool_get",
            "history",
            json!({"section":"history","after":"4"}),
        )
    };
    let dm = member_call(
        &batch,
        0,
        "pool_send_member",
        "message",
        json!({"expected_revision":4,
        "member_id":batch.jobs[1].member_id,"body":"direct text","agent_id":agent(2),"seat_id":batch.jobs[2].member_id,
        "pool_id":"foreign","request_key":"forged","author":agent(2)}),
    );
    let receipt = call(dm.clone()).await;
    assert!(ok(&receipt));
    assert!(reply_text(&receipt).contains("\ndirect_message\nBody: "));
    assert!(ok(&call(dm).await));
    let visible = call(get_history(1)).await;
    assert!(reply_text(&visible).contains("direct text"));
    assert!(reply_text(&visible).contains(&batch.jobs[0].member_id));
    assert!(!reply_text(&call(get_history(2)).await).contains("direct text"));
    let note = member_call(
        &batch,
        0,
        "pool_notify_owner",
        "owner-note",
        json!({"expected_revision":5,"body":format!("owner-only {}", "x".repeat(2048))}),
    );
    assert!(ok(&call(note).await));
    assert!(!reply_text(&call(get_history(1)).await).contains(&"x".repeat(20)));
    let pid = batch.pool_id.clone();
    stored(&store, move |store| {
        let ChatReply::History { events, .. } = state::owner_call(
            store,
            "pool_get",
            json!({"pool_id":pid,"section":"history","after":"4"}),
        )?
        else {
            return Err(Fault::Internal);
        };
        assert_eq!(
            events
                .iter()
                .filter(|event| event.kind == "direct_message")
                .count(),
            1
        );
        assert!(events.iter().any(|e| e.kind == "owner_message"));
        let effect: String =
            store
                .test_db()
                .query_row("SELECT effect FROM chat_notice_targets", [], |r| r.get(0))?;
        let state::Notice::Unresolved {
            binding: target,
            closing: false,
        } = state::notice(store, &effect)?
        else {
            return Err(Fault::Internal);
        };
        assert_eq!(target.run_id, Some(agent(1)));
        Ok(())
    })
    .await?;
    let proposal = member_call(
        &batch,
        0,
        "pool_propose",
        "proposal",
        json!({"expected_revision":6,"result":"agreed result","criteria":"checked"}),
    );
    let opened = call(proposal.clone()).await;
    assert!(ok(&opened));
    assert!(reply_text(&opened).contains("revision=7"));
    assert_eq!(call(proposal).await, opened);
    let pid = batch.pool_id.clone();
    let (proposal, roster_key) = stored(&store, move |store| {
        let ChatReply::Overview(view) =
            state::owner_call(store, "pool_get", json!({"pool_id":pid}))?
        else {
            return Err(Fault::Internal);
        };
        let proposal = view.proposal.ok_or(Fault::Internal)?;
        Ok((proposal.id, proposal.roster_key))
    })
    .await?;
    let vote_args = |revision, evidence: String| {
        json!({
            "expected_revision":revision,"proposal_id":proposal,"roster_key":roster_key,
            "choice":"ready","evidence":evidence
        })
    };
    for (status, expected) in [
        (
            "met",
            if structured {
                "pool_get section=criteria"
            } else {
                "Omit checks"
            },
        ),
        (
            "private-invalid-status",
            "checks[].status must be met or unmet",
        ),
    ] {
        let mut args = vote_args(7, "private-evidence".into());
        args["checks"] =
            json!([{"criterion_id":"1","status":status,"evidence":"private-evidence"}]);
        let rejected = call(member_call(&batch, 1, "pool_vote", "invalid-check", args)).await;
        assert_eq!(rejected["result"]["is_error"], true);
        let text = reply_text(&rejected);
        assert!(text.contains(expected), "{text}");
        assert!(!text.contains("private-"));
    }
    let first_voter = usize::from(address.is_none());
    for index in first_voter..3 {
        let mut args = vote_args(7 + index - first_voter, format!("evidence {index}"));
        if structured {
            args["checks"] =
                json!([{"criterion_id":"tested","status":"met","evidence":"verified"}]);
        }
        let vote = member_call(&batch, index, "pool_vote", &format!("ready-{index}"), args);
        let result = call(vote.clone()).await;
        assert!(ok(&result), "{result}");
        if index == 2 {
            assert_eq!(call(vote).await, result);
        }
    }
    let completion = OwnerRequest {
        tool: "pool_completion_get".into(),
        arguments: json!({"pool_id":batch.pool_id}),
    };
    let result = present(owner_call(completion, &config, &store).await, templates);
    let text = serde_json::to_value(&result)?;
    assert!(
        text["content"][0]["text"]
            .as_str()
            .is_some_and(|text| text.contains("agreed result")),
        "{text}"
    );
    let listed = present(
        owner_call(
            OwnerRequest {
                tool: "pool_list".into(),
                arguments: json!({"state":"completed"}),
            },
            &config,
            &store,
        )
        .await,
        templates,
    );
    let listed = serde_json::to_value(&listed)?;
    assert!(
        listed["content"][0]["text"]
            .as_str()
            .is_some_and(|text| text.contains(&batch.pool_id))
    );
    let pid = batch.pool_id.clone();
    let completion_id = stored(&store,move |store| {
        let db = store.test_db();
        let count: i64 = db.query_row("SELECT count(*) FROM completion_sagas",[],|r|r.get(0))?;
        assert_eq!(count,0);
        let count: i64 = db.query_row("SELECT count(*) FROM effects WHERE member IS NULL AND json_extract(data,'$.work.scope') LIKE 'owner:%'",[],|r|r.get(0))?;
        assert_eq!(count, if address.is_some() { 2 } else { 0 });
        Ok(db.query_row("SELECT id FROM chat_agreements WHERE pool=?1",[pid],|r|r.get::<_,String>(0))?)
    }).await?;
    check_owner_binding(
        config.clone(),
        &store,
        &batch.pool_id,
        address,
        &completion_id,
    )
    .await?;
    let pid = batch.pool_id.clone();
    let proposal_id = proposal.clone();
    stored(&store, move |store| {
        let db = store.test_db();
        let proposal_notices: i64 = db.query_row("SELECT count(*) FROM chat_notice_targets n JOIN effects e ON e.id=n.effect WHERE e.pool=?1 AND instr(e.data,?2)>0", [&pid,&format!("A vote is requested on proposal {proposal_id}")], |r| r.get(0))?;
        assert_eq!(proposal_notices,2);
        let completion_notices: i64 = db.query_row("SELECT count(*) FROM chat_notice_targets n JOIN effects e ON e.id=n.effect WHERE e.pool=?1 AND instr(e.data,'This is informational')>0", [pid], |r| r.get(0))?;
        assert_eq!(completion_notices,3);
        Ok(())
    }).await?;
    let observe = |operation: &'static str, params: Value, owner| {
        let store = &store;
        async move {
            let request = serde_json::to_vec(
                &json!({"schema_version":1,"operation":operation,"params":params}),
            )
            .map_err(|_| Fault::Internal)?;
            serde_json::to_value(crate::observer_socket::answer(&request, store, owner).await)
                .map_err(|_| Fault::Internal)
        }
    };
    let inventory = observe(
        "inventory_snapshot",
        json!({"filter":"all","limit":10}),
        false,
    )
    .await?;
    let row = &inventory["data"]["pools"][0];
    assert_eq!(row["kind"], "chat");
    assert_eq!(row["completion_id"], completion_id);
    let seat = &row["roster"][0];
    assert_eq!(seat["seat_id"], batch.jobs[0].member_id);
    assert_eq!(seat["run_agent_id"], agent(0));
    assert_eq!(seat["profile"], "implement");
    assert_eq!(seat["admission"], "admitted");
    assert_eq!(seat["joined"], true);
    let detail = observe(
        "get",
        json!({"pool_id":batch.pool_id,"section":"overview"}),
        false,
    )
    .await?;
    assert_eq!(detail["data"]["kind"], "chat");
    assert_eq!(detail["data"]["completion_id"], completion_id);
    assert_eq!(detail["data"]["view"]["members"][0], *seat);
    for direction in [None, Some("forward")] {
        let mut args = json!({"pool_id":batch.pool_id,"section":"history","after":4});
        if let Some(direction) = direction {
            args["direction"] = json!(direction);
        }
        let public = observe("get", args.clone(), false).await?;
        let events = public["data"]["view"]["events"]
            .as_array()
            .ok_or("observer history")?;
        assert!(events.iter().any(|e| e["kind"] == "proposal_opened"));
        assert!(events.iter().all(|e| e["kind"] != "direct_message"
            && e["kind"] != "owner_message"
            && e["kind"] != "message_part"));
        let owner = observe("get", args, true).await?;
        let events = owner["data"]["view"]["events"]
            .as_array()
            .ok_or("owner observer history")?;
        assert!(events.iter().any(|e| e["kind"] == "direct_message"));
        assert!(events.iter().any(|e| e["kind"] == "message_part"));
    }
    let dm_effect = stored(&store, |store| {
        Ok(store.test_db().query_row(
            "SELECT n.effect FROM chat_notice_targets n JOIN events e ON e.id=n.event
             WHERE json_extract(e.data,'$.kind')='direct_message'",
            [],
            |r| r.get::<_, String>(0),
        )?)
    })
    .await?;
    for owner in [false, true] {
        let data = observe(
            "get",
            json!({"pool_id":batch.pool_id,"section":"deliveries"}),
            owner,
        )
        .await?;
        let rows = data["data"]["view"]["deliveries"]
            .as_array()
            .ok_or("deliveries")?;
        let direct = rows.iter().find(|row| row["operation_id"] == dm_effect);
        if owner {
            assert_eq!(
                direct.ok_or("owner direct delivery")?["member_id"],
                batch.jobs[1].member_id
            );
        } else {
            assert!(direct.is_none());
            assert!(!rows.is_empty(), "public deliveries remain visible");
        }
    }
    let observer = crate::observer::Request {
        schema_version: 1,
        operation: crate::observer::Operation::CompletionGet(completion::GetRequest {
            pool_id: batch.pool_id.clone(),
            completion_id,
            section: completion::Section::Header,
            after: None,
            limit: 1,
        }),
    };
    let observed =
        crate::observer_socket::answer(&serde_json::to_vec(&observer)?, &store, false).await;
    assert!(matches!(
        observed.data,
        Some(crate::observer::Data::Agreement(_))
    ));
    let close = OwnerRequest {
        tool: "pool_close".into(),
        arguments: json!({"pool_id":batch.pool_id,"expected_revision":10-first_voter,"request_key":"close"}),
    };
    let ChatReply::Existing(Reply::Receipt(receipt)) = owner_call(close, &config, &store).await?
    else {
        return Err("close".into());
    };
    assert!(matches!(receipt.event.author, Author::Leader));
    assert_refusal(&call(get()).await, "pool_closed");
    let pid = batch.pool_id.clone();
    stored(&store, move |store| {
        let db = store.test_db();
        let read = |closing| -> Result<Vec<String>, Fault> {
            let mut query = db.prepare("SELECT n.effect FROM chat_notice_targets n JOIN effects e ON e.id=n.effect WHERE e.pool=?1 AND n.close_notice=?2")?;
            Ok(query.query_map(rusqlite::params![pid,closing], |row| row.get(0))?.collect::<Result<Vec<_>,_>>()?)
        };
        let close = read(true)?;
        let ordinary = read(false)?;
        assert_eq!(close.len(),3);
        for id in close {
            assert!(matches!(state::notice(store, &id)?, state::Notice::Unresolved { closing: true, .. }));
        }
        for id in ordinary {
            assert!(matches!(state::notice(store, &id)?, state::Notice::Cancelled));
        }
        Ok(())
    }).await?;
    Ok(())
}

/// Exercises member and owner broadcasts, durable resolution backoff, and retirement.
#[tokio::test]
async fn chat_notice_backoff_survives_restart() -> Result<(), Box<dyn std::error::Error>> {
    let (_root, config, store) = fixture()?;
    let batch = reserve(&store, None).await?;
    let templates = renderer()?;
    let pid = batch.pool_id.clone();
    let post = |revision, request_key| json!({"pool_id":pid,"expected_revision":revision,"request_key":request_key,"body":"owner broadcast"});
    let args = post(1, "before-admission");
    stored(&store, move |store| {
        state::owner_call(store, "pool_post", args)?;
        assert!(store.next_effect()?.is_none());
        Ok(())
    })
    .await?;
    install(&store, &batch).await?;
    let join = member_call(
        &batch,
        0,
        "pool_join",
        "join-for-post",
        json!({"expected_revision":2}),
    );
    assert!(ok(&private_call(join, &config, &store, templates).await));
    let request = member_call(
        &batch,
        0,
        "pool_post",
        "broadcast",
        json!({
            "expected_revision":3,"body":format!("{}\nINJECT", "界".repeat(2100))
        }),
    );
    let reply = private_call(request.clone(), &config, &store, templates).await;
    assert!(ok(&reply), "{reply}");
    assert_eq!(
        private_call(request, &config, &store, templates).await,
        reply
    );
    let args = post(4, "after-admission");
    let replay = args.clone();
    let member = batch.jobs[0].member_id.clone();
    let first = stored(&store, move |store| {
        state::owner_call(store, "pool_post", args.clone())?;
        state::owner_call(store, "pool_post", args)?;
        let db = store.test_db();
        let (total, author): (i64, i64) = db.query_row(
            "SELECT count(*),sum(member=?1) FROM chat_notice_targets",
            [member],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!((total, author), (5, 1));
        state::due_notices(store, 1)?.pop().ok_or(Fault::Internal)
    })
    .await?;
    let crate::domain::Work::Deliver { ref text, .. } = first.work else {
        return Err("delivery".into());
    };
    assert!(text.contains("Untrusted chat body") && !text.contains("INJECT"));
    assert!(text.chars().count() < 2300);
    let effect_id = first.effect_id.clone();
    crate::runtime::effect(&store, &config, first, false).await?;
    drop(store);
    let store = Arc::new(Mutex::new(Store::open(&config.database_path)?));
    let id = effect_id.clone();
    let (expired, next, target) = stored(&store, move |store| {
        state::owner_call(store, "pool_post", replay)?;
        let count: i64 = store.test_db().query_row("SELECT count(*) FROM chat_notice_targets", [], |row| row.get(0))?;
        assert_eq!(count,5);
        let db = store.test_db();
        let (state, deferred, frozen): (String, bool, bool) = db.query_row(
            "SELECT e.state,n.next_resolve_ms>0,EXISTS(SELECT 1 FROM publications p WHERE p.effect=e.id)
             FROM effects e JOIN chat_notice_targets n ON n.effect=e.id WHERE e.id=?1",
            [&id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
        )?;
        assert_eq!((state.as_str(),deferred,frozen),("queued",true,false));
        let next = state::due_notices(store, 1)?.pop().ok_or(Fault::Internal)?;
        assert_ne!(next.effect_id,id);
        let target: String = store.test_db().query_row("SELECT member FROM chat_notice_targets WHERE effect=?1", [&next.effect_id], |r| r.get(0))?;
        store.test_db().execute("UPDATE chat_notice_targets SET next_resolve_ms=0,resolve_until_ms=0 WHERE effect=?1", [&id])?;
        let expired = state::due_notices(store, 1)?.pop().ok_or(Fault::Internal)?;
        assert_eq!(expired.effect_id,id);
        Ok((expired,next,target))
    }).await?;
    crate::runtime::effect(&store, &config, expired, false).await?;
    let overview = private_call(
        member_call(&batch, 0, "pool_get", "overview", json!({})),
        &config,
        &store,
        templates,
    )
    .await;
    assert!(reply_text(&overview).contains("notice_undeliverable=true"));
    let replacement = json!({"pool_id":pid,"expected_revision":5,"request_key":"replace-notice-seat",
        "member_id":target,"member":spec("implement")});
    let next_id = next.effect_id.clone();
    stored(&store, move |store| {
        state::replace(store, parse(replacement)?)?;
        assert!(matches!(
            state::notice(store, &next_id)?,
            state::Notice::Cancelled
        ));
        Ok(())
    })
    .await?;
    crate::runtime::effect(&store, &config, next, false).await?;
    Ok(())
}

/// Rejects the non-wakeable profile through both owner admission paths.
#[tokio::test]
async fn chat_research_start_and_replace_are_refused() -> Result<(), Box<dyn std::error::Error>> {
    let (_root, config, store) = fixture()?;
    let templates = renderer()?;
    let mut research = input(None);
    research["members"][1] = spec("research");
    let start = OwnerRequest {
        tool: "pool_start".into(),
        arguments: research,
    };
    let response = present(owner_call(start, &config, &store).await, templates);
    assert_eq!(response.is_error, Some(true));
    assert!(serde_json::to_string(&response)?.contains("Use review."));
    let batch = reserve(&store, None).await?;
    install(&store, &batch).await?;
    let replace = OwnerRequest {
        tool: "pool_replace".into(),
        arguments: json!({
            "pool_id":batch.pool_id,"expected_revision":1,"request_key":"reject-replace",
            "member_id":batch.jobs[0].member_id,"member":spec("research")
        }),
    };
    let response = present(owner_call(replace, &config, &store).await, templates);
    assert_eq!(response.is_error, Some(true));
    assert!(serde_json::to_string(&response)?.contains("Use review."));
    Ok(())
}

/// A restricted role settles immediately and remains visible on the exact seat.
#[tokio::test]
async fn chat_restricted_role_is_undeliverable_without_backoff()
-> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::AsyncWriteExt;
    let (_root, config, store) = fixture()?;
    let batch = reserve(&store, None).await?;
    install(&store, &batch).await?;
    let pid = batch.pool_id.clone();
    let (notice, seat_id) = stored(&store, move |store| {
        state::owner_call(
            store,
            "pool_post",
            json!({"pool_id":pid,"expected_revision":1,
            "request_key":"restricted-runtime","body":"pending"}),
        )?;
        assert!(
            store.next_effect()?.is_none(),
            "chat work belongs to its own queue"
        );
        let notice = state::due_notices(store, 1)?.pop().ok_or(Fault::Internal)?;
        let seat_id = store.test_db().query_row(
            "SELECT member FROM chat_notice_targets WHERE effect=?1",
            [&notice.effect_id],
            |r| r.get::<_, String>(0),
        )?;
        Ok((notice, seat_id))
    })
    .await?;
    let target = batch
        .jobs
        .iter()
        .position(|job| job.member_id == seat_id)
        .ok_or("target")?;
    let path = config.run_socket.as_ref().ok_or("Run socket")?;
    let run = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    let mock = tokio::spawn(async move {
        for index in 0..3 {
            let (mut stream, _) = run.accept().await.map_err(|_| Fault::Unavailable)?;
            let request: Value =
                serde_json::from_slice(&integrations::read_frame(&mut stream).await?)
                    .map_err(|_| Fault::Internal)?;
            let result = if index == 1 {
                assert_eq!(request["method"], "agent_integration");
                json!({"schema_version":1,"agent":{"agent_id":agent(target),"sequence":1},
                    "communication":{"state":"unsupported","reason":"restricted_role"}})
            } else {
                assert_eq!(request["method"], "capabilities");
                json!({"schema_version":1,"product":"agent-run","store_id":RUN_STORE})
            };
            let response = json!({"jsonrpc":"2.0","id":request["id"],"result":result});
            stream
                .write_all(format!("{response}\n").as_bytes())
                .await
                .map_err(|_| Fault::Unavailable)?;
        }
        Ok::<_, Fault>(())
    });
    let id = notice.effect_id.clone();
    crate::runtime::effect(&store, &config, notice, false).await?;
    tokio::time::timeout(std::time::Duration::from_secs(3), mock).await???;
    stored(&store, move |store| {
        let db = store.test_db();
        let result: (String, bool) = db.query_row(
            "SELECT e.state,n.pending FROM effects e
            JOIN chat_notice_targets n ON e.id=n.effect WHERE e.id=?1",
            [&id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        assert_eq!(result, (state::NOTICE_UNDELIVERABLE.into(), false));
        let request: crate::observer::Request =
            parse(json!({"schema_version":1,"operation":"get",
            "params":{"pool_id":batch.pool_id,"section":"deliveries"}}))?;
        let view = serde_json::to_value(store.observe(&request)?).map_err(|_| Fault::Internal)?;
        assert!(
            view["view"]["deliveries"]
                .as_array()
                .is_some_and(|rows| rows.iter().any(|row| row["operation_id"] == id
                    && row["member_id"] == seat_id
                    && row["state"] == state::NOTICE_UNDELIVERABLE))
        );
        Ok(())
    })
    .await?;
    Ok(())
}

/// Freezes two valid publications before any provider contact.
async fn frozen_notices(
    store: &SharedStore,
    pool_id: String,
) -> Result<Vec<crate::domain::Effect>, Fault> {
    stored(store, move |store| {
        state::owner_call(
            store,
            "pool_post",
            json!({"pool_id":pool_id,"expected_revision":1,
            "request_key":"frozen-notices","body":"pending"}),
        )?;
        let mut effects = state::due_notices(store, 2)?;
        assert_eq!(effects.len(), 2);
        for effect in &mut effects {
            let crate::domain::Work::Deliver { address, .. } = &mut effect.work else {
                return Err(Fault::Internal);
            };
            *address = "test/codex/route/session".into();
            let params = integrations::publication(effect)?;
            store.freeze_publication(
                &effect.effect_id,
                "fixture",
                &serde_json::to_value(params).map_err(|_| Fault::Internal)?,
            )?;
        }
        Ok(effects)
    })
    .await
}

/// A crash before the first write and a lost acknowledgement both replay the exact publication.
#[tokio::test]
async fn chat_replays_frozen_publish_after_restart() -> Result<(), Box<dyn std::error::Error>> {
    let (_root, config, store) = fixture()?;
    let batch = reserve(&store, None).await?;
    install(&store, &batch).await?;
    let mut effects = frozen_notices(&store, batch.pool_id).await?;
    let effect = effects.pop().ok_or("missing frozen notice")?;
    drop(store);
    let store = Arc::new(Mutex::new(Store::open(&config.database_path)?));
    let registration = UnixListener::bind(&config.bridge_registration_socket)?;
    let core = UnixListener::bind(&config.bridge_core_socket)?;
    for path in [
        &config.bridge_registration_socket,
        &config.bridge_core_socket,
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    fs::write(&config.bridge_credential_file, "abcde1234567890")?;
    fs::set_permissions(
        &config.bridge_credential_file,
        fs::Permissions::from_mode(0o600),
    )?;
    let peer = tokio::spawn(async move {
        let _registration = registration;
        let mut frames = Vec::new();
        for _ in 0..2 {
            let (mut socket, _) = core.accept().await.map_err(|_| Fault::Unavailable)?;
            frames.push(integrations::read_frame(&mut socket).await?);
            // Drop the ack, as if the daemon lost the connection after accepting custody.
        }
        Ok::<_, Fault>(frames)
    });
    for _ in 0..2 {
        let id = effect.effect_id.clone();
        let recovered = stored(&store, move |store| {
            store.test_db().execute(
                "UPDATE chat_notice_targets SET next_resolve_ms=0 WHERE effect=?1",
                [&id],
            )?;
            state::due_notices(store, 1)?.pop().ok_or(Fault::Internal)
        })
        .await?;
        assert_eq!(recovered.effect_id, effect.effect_id);
        crate::runtime::effect(&store, &config, recovered, true).await?;
    }
    let frames = tokio::time::timeout(std::time::Duration::from_secs(3), peer).await???;
    assert_eq!(frames[0], frames[1]);
    let frame = bridge_sdk::bridge_protocol::decode_request(&frames[0])?;
    assert!(
        matches!(frame.operation, bridge_sdk::bridge_protocol::Operation::Publish(params)
        if params.event_id == effect.effect_id && params == integrations::publication(&effect)?)
    );
    Ok(())
}

/// Close before the send boundary suppresses publication; close after it preserves status recovery.
#[tokio::test]
async fn chat_close_orders_with_first_send() -> Result<(), Box<dyn std::error::Error>> {
    let (_root, _config, store) = fixture()?;
    let batch = reserve(&store, None).await?;
    install(&store, &batch).await?;
    let pool_id = batch.pool_id;
    let effects = frozen_notices(&store, pool_id.clone()).await?;
    stored(&store, move |store| {
        let first = &effects[0].effect_id;
        let second = &effects[1].effect_id;
        assert_eq!(
            state::begin_notice_send(store, first)?,
            state::NoticeSend::Publish { replay: false }
        );
        state::owner_call(
            store,
            "pool_close",
            json!({"pool_id":pool_id,"expected_revision":2,"request_key":"close-before-send"}),
        )?;
        assert_eq!(
            state::begin_notice_send(store, first)?,
            state::NoticeSend::Status
        );
        assert_eq!(
            state::begin_notice_send(store, second)?,
            state::NoticeSend::Cancel
        );
        store.settle_effect(second, state::NOTICE_UNDELIVERABLE)?;
        let due = state::due_notices(store, 4)?;
        assert_eq!(due.len(), 3);
        for notice in due {
            assert!(matches!(
                state::notice(store, &notice.effect_id)?,
                state::Notice::Unresolved { closing: true, .. }
            ));
        }
        let ChatReply::Overview(overview) =
            state::owner_call(store, "pool_get", json!({"pool_id":pool_id}))?
        else {
            return Err(Fault::Internal);
        };
        assert_eq!(overview.seat_count, 0);
        assert_eq!(overview.roster.len(), 3);
        assert!(overview.roster.iter().all(|row| row.retired));
        Ok(())
    })
    .await?;
    Ok(())
}

/// Due retries keep their position ahead of a steady stream of new posts.
#[tokio::test]
async fn chat_retry_is_not_starved_by_new_posts() -> Result<(), Box<dyn std::error::Error>> {
    let (_root, _config, store) = fixture()?;
    let batch = reserve(&store, None).await?;
    install(&store, &batch).await?;
    stored(&store, move |store| {
        let pid = batch.pool_id;
        for revision in 1..=5 {
            state::owner_call(
                store,
                "pool_post",
                json!({"pool_id":pid,"expected_revision":revision,
                "request_key":format!("post-{revision}"),"body":"message"}),
            )?;
            if revision == 1 {
                continue;
            }
            let db = store.test_db();
            let retry: String = db.query_row(
                "SELECT effect FROM chat_notice_targets ORDER BY event,effect LIMIT 1",
                [],
                |r| r.get(0),
            )?;
            db.execute(
                "UPDATE chat_notice_targets SET next_resolve_ms=1 WHERE effect=?1",
                [&retry],
            )?;
            let claim = state::due_notices(store, 1)?.pop().ok_or(Fault::Internal)?;
            assert_eq!(claim.effect_id, retry);
            state::defer_notice(store, &retry)?;
        }
        Ok(())
    })
    .await?;
    Ok(())
}

/// A retired managed seat stays absent from the owner chat read and triggers no Run RPC.
#[tokio::test]
async fn chat_owner_managed_overview_does_not_read_retired_seats()
-> Result<(), Box<dyn std::error::Error>> {
    let (_root, config, store) = fixture()?;
    let pid = stored(&store, |store| {
        let actor = crate::domain::Actor::verified("legacy owner".into(), "legacy", "owner")?;
        let Reply::Receipt(created) = store.execute(
            &actor,
            &Command::Create(Create {
                request_key: "managed".into(),
                name: "Managed".into(),
                purpose: "Persistent pool".into(),
                acceptance: None,
            }),
        )?
        else {
            return Err(Fault::Internal);
        };
        let pid = created.pool_id;
        let command = command(
            "pool_add",
            json!({"pool_id":pid,"expected_revision":1,
            "request_key":"managed-seat","address":"test/codex/route/managed",
            "name":"Seat","role":"review","task":"Review"}),
        )?;
        let Reply::Receipt(added) = store.execute(&actor, &command)? else {
            return Err(Fault::Internal);
        };
        let seat = added.created_id.ok_or(Fault::Internal)?;
        let db = store.test_db();
        let (mut binding, _) = crate::store::binding_any(db, &seat)?;
        binding.run_id = Some(agent(0));
        binding.run_store_id = Some(RUN_STORE.into());
        binding.run_sequence = Some(1);
        crate::store::save_binding(db, &binding, false)?;
        Ok(pid)
    })
    .await?;
    let run_path = config.run_socket.as_ref().ok_or("Run socket")?;
    let run = UnixListener::bind(run_path)?;
    fs::set_permissions(run_path, fs::Permissions::from_mode(0o600))?;
    let read = OwnerRequest {
        tool: "pool_get".into(),
        arguments: json!({"pool_id":pid}),
    };
    let ChatReply::Overview(overview) = owner_call(read, &config, &store).await? else {
        return Err("overview".into());
    };
    assert!(overview.roster.is_empty());
    assert_eq!(overview.omitted_retired, 0);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), run.accept())
            .await
            .is_err()
    );
    Ok(())
}

/// The overview caps its retired block and the members cursor exposes every failure.
#[tokio::test]
async fn chat_owner_pages_retired_seats_and_failures() -> Result<(), Box<dyn std::error::Error>> {
    let (_root, _config, store) = fixture()?;
    let mut args = input(None);
    args["members"] = json!(vec![spec("review"); 8]);
    let batch = stored(&store, move |store| state::start(store, parse(args)?, 1002)).await?;
    install(&store, &batch).await?;
    let mut walk = input(None);
    walk["request_key"] = json!("interleaved-walk");
    walk["members"] = json!(vec![spec("review"); 6]);
    let walk = stored(&store, move |store| state::start(store, parse(walk)?, 1002)).await?;
    install(&store, &walk).await?;
    let templates = renderer()?;
    stored(&store, move |store| {
        let pid = batch.pool_id;
        state::owner_call(
            store,
            "pool_post",
            json!({"pool_id":pid,"expected_revision":1,
            "request_key":"post-before-close","body":"Test"}),
        )?;
        for notice in state::due_notices(store, 8)? {
            store.settle_effect(&notice.effect_id, state::NOTICE_UNDELIVERABLE)?;
        }
        state::owner_call(
            store,
            "pool_close",
            json!({"pool_id":pid,"expected_revision":2,"request_key":"close"}),
        )?;
        let overview = state::owner_call(store, "pool_get", json!({"pool_id":pid}))?;
        let ChatReply::Overview(view) = &overview else {
            return Err(Fault::Internal);
        };
        assert_eq!(view.roster.len(), 5);
        assert_eq!((view.omitted_retired, view.omitted_undeliverable), (3, 3));
        let revision = view.revision;
        let text = serde_json::to_string(&present(Ok(overview), templates))
            .map_err(|_| Fault::Internal)?;
        assert!(text.contains("+3 more retired seats (3 undeliverable), see section=members."));
        let mut ids = std::collections::BTreeSet::new();
        for (after, size, more) in [("0", 5, true), ("5", 3, false)] {
            let reply = state::owner_call(
                store,
                "pool_get",
                json!({"pool_id":pid,"section":"members","after":after,"expected_revision":revision}),
            )?;
            let ChatReply::Members {
                roster,
                more: has_more,
                next,
                ..
            } = &reply
            else {
                return Err(Fault::Internal);
            };
            assert_eq!((roster.len(), *has_more), (size, more));
            assert_eq!(*next, if more { 5 } else { 8 });
            for seat in roster {
                assert!(seat.retired && seat.notice_undeliverable);
                assert!(ids.insert(seat.seat_id.clone()));
            }
            let text = serde_json::to_string(&present(Ok(reply), templates))
                .map_err(|_| Fault::Internal)?;
            assert!(text.contains("retired=true") && text.contains("notice_undeliverable=true"));
        }
        assert_eq!(ids.len(), 8);

        let pid = walk.pool_id;
        let page = state::owner_call(store, "pool_get", json!({"pool_id":pid,"section":"members"}))?;
        let ChatReply::Members { revision, next, more: true, .. } = page else {
            return Err(Fault::Internal);
        };
        let after = next.to_string();
        assert_eq!(state::owner_call(store, "pool_get", json!({
            "pool_id":pid,"section":"members","after":after
        })).err(), Some(Fault::Invalid));
        state::replace(store, parse(json!({
            "pool_id":pid,"expected_revision":revision,"request_key":"interleaved-replace",
            "member_id":walk.jobs[0].member_id,"member":spec("review")
        }))?)?;
        assert_eq!(state::owner_call(store, "pool_get", json!({
            "pool_id":pid,"section":"members","after":after,"expected_revision":revision
        })).err(), Some(Fault::Stale));
        Ok(())
    })
    .await?;
    Ok(())
}

/// A replacement invalidates the retired member before mutation replay or reads.
#[tokio::test]
async fn chat_retired_seat_cannot_replay() -> Result<(), Box<dyn std::error::Error>> {
    let (_root, config, store) = fixture()?;
    let batch = reserve(&store, Some("test/codex/route/owner")).await?;
    install(&store, &batch).await?;
    let templates = renderer()?;
    let join = member_call(
        &batch,
        0,
        "pool_join",
        "join",
        json!({"expected_revision":1}),
    );
    assert!(ok(
        &private_call(join.clone(), &config, &store, templates).await
    ));
    let args = json!({"pool_id":batch.pool_id,"expected_revision":2,"request_key":"replace", "member_id":batch.jobs[0].member_id,"member":spec("review")});
    let replacement = stored(&store, move |store| state::replace(store, parse(args)?)).await?;
    assert_eq!(replacement.old_agent_id, Some(agent(0)));
    let refused = private_call(join, &config, &store, templates).await;
    assert_refusal(&refused, "seat_retired");
    Ok(())
}

/// A v17 database upgrades transactionally and keeps its retained legacy pool.
#[tokio::test]
async fn chat_migrates_v17_without_changing_old_pool() -> Result<(), Box<dyn std::error::Error>> {
    let (_root, config, store) = fixture()?;
    let pid = stored(&store,move |store| {
        let actor = crate::domain::Actor::verified("legacy owner".into(),"legacy","owner")?;
        let command = Command::Create(Create {request_key:"legacy-create".into(),name:"Legacy".into(),purpose:"Old purpose".into(),acceptance:None});
        let Reply::Receipt(old) = store.execute(&actor,&command)? else { return Err(Fault::Internal); };
        store.test_db().execute_batch("DROP TABLE chat_starters; DROP TABLE chat_notice_targets; DROP TABLE chat_agreements; DROP TABLE chat_batches; DROP TABLE chat_pools; PRAGMA user_version=17;")?;
        Ok(old.pool_id)
    }).await?;
    drop(store);
    let mut upgraded = Store::open(&config.database_path)?;
    assert_eq!(
        upgraded
            .test_db()
            .query_row("PRAGMA user_version", [], |r| r.get::<_, u32>(0))?,
        20
    );
    let ChatReply::Overview(old) =
        state::owner_call(&mut upgraded, "pool_get", json!({"pool_id":pid}))?
    else {
        return Err("old pool".into());
    };
    assert_eq!(old.name, "Legacy");
    assert!(old.purpose.contains("Old purpose"));
    let new = state::start(&mut upgraded, parse(input(None))?, 1002)?;
    assert_ne!(new.pool_id, pid);
    Ok(())
}

/// A released v18 store preserves pending notice IDs when adding backoff columns.
#[tokio::test]
async fn chat_migrates_pending_v18_notice() -> Result<(), Box<dyn std::error::Error>> {
    let (_root, config, store) = fixture()?;
    let batch = reserve(&store, None).await?;
    install(&store, &batch).await?;
    let effect_id = stored(&store, move |store| {
        let ChatReply::Existing(Reply::Receipt(receipt)) = state::owner_call(
            store,
            "pool_post",
            json!({"pool_id":batch.pool_id,"expected_revision":1,
                "request_key":"legacy-notice","body":"pending"}),
        )?
        else {
            return Err(Fault::Internal);
        };
        let db = store.test_db();
        db.execute_batch(
            "DROP TABLE chat_notice_targets; DELETE FROM effects;
            CREATE TABLE chat_notice_targets(effect TEXT PRIMARY KEY REFERENCES effects(id),
                member TEXT NOT NULL REFERENCES members(id)); PRAGMA user_version=18;",
        )?;
        let event_id = receipt.event.event_id;
        let effect_id = "released-v18-effect".to_owned();
        let member_id = &batch.jobs[0].member_id;
        let effect = crate::domain::Effect {
            effect_id: effect_id.clone(),
            pool_id: batch.pool_id.clone(),
            member_id: None,
            state: "queued".into(),
            work: crate::domain::Work::Deliver {
                address: "pool-chat-unresolved".into(),
                scope: format!("agent-pool:member:{member_id}"),
                text: format!(
                    "Pool {} event {event_id} (message).\npending",
                    batch.pool_id
                ),
            },
        };
        let data = serde_json::to_string(&effect).map_err(|_| Fault::Internal)?;
        db.execute(
            "INSERT INTO effects(id,pool,state,data) VALUES(?1,?2,'queued',?3)",
            rusqlite::params![effect_id, batch.pool_id, data],
        )?;
        db.execute(
            "INSERT INTO chat_notice_targets(effect,member) VALUES(?1,?2)",
            rusqlite::params![effect_id, member_id],
        )?;
        let mut frozen = effect.clone();
        frozen.effect_id = "released-v18-frozen".into();
        frozen.state = "custody".into();
        let frozen_seat = &batch.jobs[1].member_id;
        let crate::domain::Work::Deliver { scope, .. } = &mut frozen.work else {
            return Err(Fault::Internal);
        };
        *scope = format!("agent-pool:member:{frozen_seat}");
        let raw = serde_json::to_string(&frozen).map_err(|_| Fault::Internal)?;
        db.execute(
            "INSERT INTO effects(id,pool,state,data) VALUES(?1,?2,'custody',?3)",
            rusqlite::params![frozen.effect_id, batch.pool_id, raw],
        )?;
        db.execute(
            "INSERT INTO chat_notice_targets(effect,member) VALUES(?1,?2)",
            rusqlite::params![frozen.effect_id, frozen_seat],
        )?;
        let crate::domain::Work::Deliver { address, .. } = &mut frozen.work else {
            return Err(Fault::Internal);
        };
        *address = "test/codex/route/session".into();
        let publication = serde_json::to_value(integrations::publication(&frozen)?)
            .map_err(|_| Fault::Internal)?;
        db.execute(
            "INSERT INTO publications(effect,producer,params) VALUES(?1,'fixture',?2)",
            rusqlite::params![frozen.effect_id, publication.to_string()],
        )?;
        Ok((effect_id, raw, publication))
    })
    .await?;
    drop(store);
    let (effect_id, old_frozen, old_publication) = effect_id;
    let mut upgraded = Store::open(&config.database_path)?;
    let claimed = state::due_notices(&mut upgraded, 1)?
        .pop()
        .ok_or("pending notice")?;
    assert_eq!(claimed.effect_id, effect_id);
    let crate::domain::Work::Deliver { text, .. } = claimed.work else {
        return Err("expected notice".into());
    };
    assert!(text.contains("Untrusted chat body: \"pending\""));
    let event: i64 = upgraded.test_db().query_row(
        "SELECT event FROM chat_notice_targets WHERE effect=?1",
        [&effect_id],
        |r| r.get(0),
    )?;
    assert!(event > 0);
    let (frozen_event, frozen_raw): (i64, String) = upgraded.test_db().query_row(
        "SELECT n.event,e.data FROM chat_notice_targets n JOIN effects e ON n.effect=e.id
         WHERE n.effect='released-v18-frozen'",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    assert_eq!((frozen_event, frozen_raw), (event, old_frozen));
    assert!(matches!(state::notice(&upgraded,"released-v18-frozen")?,
        state::Notice::Frozen(producer, value) if producer=="fixture" && value==old_publication));
    assert_eq!(
        state::begin_notice_send(&mut upgraded, "released-v18-frozen")?,
        state::NoticeSend::Status
    );
    assert!(matches!(
        state::notice(&upgraded, &effect_id)?,
        state::Notice::Unresolved { closing: false, .. }
    ));
    Ok(())
}

/// Absence is provisional, including after backoff and the overview grace window.
#[tokio::test]
async fn chat_closed_batch_records_late_receipt() -> Result<(), Box<dyn std::error::Error>> {
    let (_root, config, store) = fixture()?;
    let socket = config.run_socket.as_ref().ok_or("fixture Run socket")?;
    let listener = UnixListener::bind(socket)?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
    let batch = reserve(&store, None).await?;
    let id = batch.id.clone();
    stored(&store, move |store| state::fence(store, &id, RUN_STORE)).await?;
    owner_call(
        OwnerRequest {
            tool: "pool_close".into(),
            arguments: json!({"pool_id":batch.pool_id,"expected_revision":1,"request_key":"close"}),
        },
        &config,
        &store,
    )
    .await?;
    let mock = tokio::spawn(async move {
        for found in [false, true] {
            let (mut stream, _) = listener.accept().await?;
            let request: Value =
                serde_json::from_slice(&integrations::read_frame(&mut stream).await?)?;
            assert_eq!(request["method"], "batch_receipt");
            let mut result = json!({"found":found});
            if found {
                let jobs: Vec<_> = (0..3).map(|index| json!({"index":index,"agent_id":agent(index),"sequence":1,"execution_ref":execution(index)})).collect();
                result["receipt"] = json!({"version":1,"store_id":RUN_STORE,"request_id":request["params"]["request_id"],"jobs":jobs});
            }
            write(
                &mut stream,
                &json!({"jsonrpc":"2.0","id":request["id"],"result":result}),
            )
            .await?;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    reconcile(&config, &store, &mut String::new()).await?;
    let id = batch.id.clone();
    let pool_id = batch.pool_id.clone();
    stored(&store, move |store| {
        assert!(state::next_batch(store, "")?.is_none());
        let (status, delay, next): (String, i64, i64) = store.test_db().query_row(
            "SELECT state,receipt_delay_ms,next_receipt_ms FROM chat_batches WHERE id=?1",
            [&id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        assert_eq!(status, "pending");
        assert_eq!(delay, 10_000);
        assert!(next > i64::try_from(crate::observer::now()?).map_err(|_| Fault::Internal)?);
        // Advance the persisted schedule without sleeping through the grace period.
        store.test_db().execute(
            "UPDATE chat_batches SET closed_at_ms=0,next_receipt_ms=0 WHERE id=?1",
            [&id],
        )?;
        let ChatReply::Overview(view) =
            state::owner_call(store, "pool_get", json!({"pool_id":pool_id}))?
        else {
            return Err(Fault::Internal);
        };
        assert_eq!(
            view.latest_admission.as_deref(),
            Some("launch unconfirmed (closed pool)")
        );
        Ok(())
    })
    .await?;
    reconcile(&config, &store, &mut String::new()).await?;
    mock.await?.map_err(|error| error.to_string())?;
    let ChatReply::Launch { state, seats, .. } = stored(&store, move |store| {
        state::launch_read(store, &batch, true, None)
    })
    .await?
    else {
        return Err("launch".into());
    };
    assert_eq!(state, "admitted");
    for (index, seat) in seats.iter().enumerate() {
        assert!(!seat.current);
        assert_eq!(seat.agent_id.as_deref(), Some(agent(index).as_str()));
    }
    Ok(())
}

/// Close settles a batch that never reached a possible-send decision.
#[tokio::test]
async fn chat_closed_never_sent_batch_settles_immediately() -> Result<(), Box<dyn std::error::Error>>
{
    let (_root, config, store) = fixture()?;
    let batch = reserve(&store, None).await?;
    owner_call(
        OwnerRequest {
            tool: "pool_close".into(),
            arguments: json!({"pool_id":batch.pool_id,"expected_revision":1,"request_key":"close"}),
        },
        &config,
        &store,
    )
    .await?;
    stored(&store, move |store| {
        assert!(state::next_batch(store, "")?.is_none());
        let ChatReply::Launch { state, seats, .. } = state::launch_read(store, &batch, true, None)?
        else {
            return Err(Fault::Internal);
        };
        assert_eq!(state, "not_launched");
        assert!(
            seats
                .iter()
                .all(|seat| !seat.current && seat.agent_id.is_none())
        );
        Ok(())
    })
    .await?;
    Ok(())
}

/// Run validation refusal settles the batch durably without preflight lookup.
#[tokio::test]
async fn chat_invalid_spec_settles_refused() -> Result<(), Box<dyn std::error::Error>> {
    let (_root, config, store) = fixture()?;
    let socket = config.run_socket.as_ref().ok_or("fixture Run socket")?;
    let listener = UnixListener::bind(socket)?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
    let mut args = input(None);
    args["members"][0]["spec"]["model"] = json!("invalid-run-model");
    let batch = stored(&store, move |store| state::start(store, parse(args)?, 1002)).await?;
    let mock = tokio::spawn(async move {
        for method in ["capabilities", "start_batch"] {
            let (mut stream, _) = listener.accept().await?;
            let request: Value =
                serde_json::from_slice(&integrations::read_frame(&mut stream).await?)?;
            assert_eq!(request["method"], method);
            let reply = if method == "capabilities" {
                json!({"jsonrpc":"2.0","id":request["id"],"result":{"schema_version":1,"product":"agent-run","store_id":RUN_STORE}})
            } else {
                assert_eq!(request["params"]["jobs"][0]["model"], "invalid-run-model");
                json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":-32602,"message":"Invalid model"}})
            };
            write(&mut stream, &reply).await?;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    reconcile(&config, &store, &mut String::new()).await?;
    mock.await?.map_err(|error| error.to_string())?;
    let ChatReply::Overview(view) = stored(&store, move |store| {
        state::owner_call(store, "pool_get", json!({"pool_id":batch.pool_id}))
    })
    .await?
    else {
        return Err("overview".into());
    };
    assert_eq!(view.latest_admission.as_deref(), Some("refused"));
    assert!(
        view.roster
            .iter()
            .all(|seat| seat.admitted == "refused" && seat.agent_id.is_none())
    );
    Ok(())
}

/// Keeps one text line per pool and seat through the owner tool presentation.
#[tokio::test]
async fn chat_owner_text_separates_pool_and_seat_rows() -> Result<(), Box<dyn std::error::Error>> {
    let (_root, config, store) = fixture()?;
    let templates = renderer()?;
    let call = |tool: &str, arguments| {
        let request = OwnerRequest {
            tool: tool.into(),
            arguments,
        };
        let config = &config;
        let store = &store;
        async move {
            let reply = owner_call(request, config, store).await?;
            let rendered = present(Ok(reply), templates);
            serde_json::to_value(rendered).map_err(|_| Fault::Internal)
        }
    };
    let launch = call("pool_start", input(None)).await?;
    let launch_text = reply_text(&json!({"result":launch})).to_owned();
    let rows: Vec<_> = launch_text
        .lines()
        .filter(|row| row.starts_with("Seat "))
        .collect();
    assert_eq!(rows.len(), 3, "{launch_text}");
    assert!(
        rows.iter().all(|row| row.ends_with("joined=false")),
        "{launch_text}"
    );
    assert!(
        launch_text
            .lines()
            .any(|line| line.starts_with("The resident reconciles"))
    );

    let mut second = input(None);
    second["request_key"] = json!("second-start");
    second["name"] = json!("Second pool");
    call("pool_start", second).await?;
    let list = json!({"result": call("pool_list", json!({})).await?});
    let list_text = reply_text(&list);
    assert_eq!(
        list_text.lines().filter(|line| line.ends_with("\"Mixed profiles\"") || line.ends_with("\"Second pool\"")).count(),
        2,
        "{list_text}"
    );

    let pid = launch_text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .ok_or("pool id")?;
    let view = json!({"result": call("pool_get", json!({"pool_id":pid})).await?});
    let text = reply_text(&view);
    assert_eq!(
        text.lines()
            .filter(|line| line.contains("admission=pending") && line.contains("joined=false"))
            .count(),
        3,
        "{text}"
    );
    Ok(())
}

/// A sole joined proposer completes in one revision with a durable ballot and exact replay.
#[tokio::test]
async fn chat_sole_proposer_completes() -> Result<(), Box<dyn std::error::Error>> {
    let (_root, config, store) = fixture()?;
    let mut args = input(None);
    args["members"] = json!([spec("implement")]);
    args["acceptance"] = json!([{"id":"tested","text":"Result is tested"}]);
    let batch = stored(&store, move |store| state::start(store, parse(args)?, 1002)).await?;
    install(&store, &batch).await?;
    let templates = renderer()?;
    let call = |value| private_call(value, &config, &store, templates);
    assert!(ok(&call(member_call(
        &batch,
        0,
        "pool_join",
        "join",
        json!({"expected_revision":1})
    ))
    .await));
    let propose = member_call(
        &batch,
        0,
        "pool_propose",
        "proposal",
        json!({"expected_revision":2,"result":"done","criteria":"tested"}),
    );
    let receipt = call(propose.clone()).await;
    assert!(ok(&receipt), "{receipt}");
    assert!(reply_text(&receipt).contains("revision=3"));
    assert!(reply_text(&receipt).contains("agreement recorded"));
    assert_eq!(call(propose).await, receipt);
    let pid = batch.pool_id.clone();
    let seat = batch.jobs[0].member_id.clone();
    stored(&store, move |store| {
        let db = store.test_db();
        let data: String = db.query_row("SELECT data FROM chat_agreements WHERE pool=?1", [&pid], |row| row.get(0))?;
        let record: Value = serde_json::from_str(&data).map_err(|_| Fault::Internal)?;
        assert_eq!(record["revision"], 3);
        assert_eq!(record["ballots"][0]["seat_id"], seat);
        let ballot = record["ballots"][0]["vote_event_id"].as_str().ok_or(Fault::Internal)?;
        let (kind, revision, body): (String, i64, String) = db.query_row(
            "SELECT json_extract(data,'$.kind'),json_extract(data,'$.revision'),json_extract(data,'$.body') FROM events WHERE rowid=?1",
            [ballot], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        )?;
        assert_eq!(kind, "proposal_accepted");
        assert_eq!(revision, 3);
        assert!(body.ends_with("proposer"));
        let count: i64 = db.query_row("SELECT count(*) FROM events WHERE pool=?1 AND json_extract(data,'$.revision')=3", [&pid], |row| row.get(0))?;
        assert_eq!(count, 4);
        Ok(())
    }).await?;
    Ok(())
}

/// Exercises UID fencing, explicit address precedence and replay after a real agreement.
async fn check_owner_binding(
    mut config: Config,
    store: &SharedStore,
    pool_id: &str,
    explicit: Option<&str>,
    completion: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    config.owner_ingress = Some(toml::from_str(
        r#"
        path = "/run/agent-pool/owner.sock"
        gid = 1000
        allowed_uids = [1002, 1004]
        host_id = "test"
        [stores]
        1002 = { codex = "owner", claude-code = "claude-owner" }
        1004 = { codex = "other" }
    "#,
    )?);
    let request = |session: &str| OwnerRequest {
        tool: BIND_OWNER.into(),
        arguments: json!({"pool_id":pool_id,"harness":"codex","session_id":session}),
    };
    assert!(matches!(
        super::owner_call(request("session"), &config, store, 1004).await,
        Err(Fault::Unauthorized)
    ));
    if explicit.is_some() {
        assert!(matches!(
            owner_call(request("session"), &config, store).await,
            Err(Fault::Conflict)
        ));
    } else {
        for _ in 0..2 {
            assert!(matches!(
                owner_call(request("session"), &config, store).await?,
                ChatReply::OwnerBound
            ));
        }
        assert!(matches!(
            owner_call(request("other-session"), &config, store).await,
            Err(Fault::Conflict)
        ));
    }
    let address = explicit.unwrap_or("test/codex/owner/session").to_owned();
    let pool_id = pool_id.to_owned();
    let completion = completion.to_owned();
    stored(store, move |store| {
        let db = store.test_db();
        let mut stmt = db.prepare("SELECT json_extract(data,'$.work.address'),json_extract(data,'$.work.text')
            FROM effects WHERE pool=?1 AND member IS NULL AND json_extract(data,'$.work.scope')='owner:'||?1 ORDER BY sequence")?;
        let deliveries = stmt.query_map([pool_id], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(deliveries.len(), 2);
        assert!(deliveries.iter().all(|(target, _)| target == &address));
        assert!(deliveries[0].1.contains("owner-only"));
        assert!(deliveries[1].1.contains(&completion));
        Ok(())
    }).await?;
    Ok(())
}

/// Migrates a populated v19 store and replays a new pool's persisted backlog after restart.
#[tokio::test]
async fn chat_migrates_v19_and_replays_owner_backlog() -> Result<(), Box<dyn std::error::Error>> {
    let (_root, mut config, store) = fixture()?;
    let old = reserve(&store, None).await?;
    stored(&store, |store| {
        store
            .test_db()
            .execute_batch("DROP TABLE chat_starters; PRAGMA user_version=19;")?;
        Ok(())
    })
    .await?;
    drop(store);

    config.owner_ingress = Some(toml::from_str(
        r#"
        path = "/run/agent-pool/owner.sock"
        gid = 1000
        allowed_uids = [1002]
        host_id = "test"
        [stores]
        1002 = { codex = "owner" }
    "#,
    )?);
    let store = Arc::new(Mutex::new(Store::open(&config.database_path)?));
    let start = |arguments| OwnerRequest {
        tool: "pool_start".into(),
        arguments,
    };
    let ChatReply::Launch {
        pool_id,
        owner_binding_hint,
        ..
    } = owner_call(start(input(None)), &config, &store).await?
    else {
        return Err("legacy start receipt".into());
    };
    assert_eq!(pool_id, old.pool_id);
    assert_eq!(owner_binding_hint, Some(OWNER_BIND_UNAVAILABLE));

    let mut args = input(None);
    args["request_key"] = json!("new-start");
    let start_args = args.clone();
    let batch = stored(&store, move |store| {
        let version: i64 = store
            .test_db()
            .query_row("PRAGMA user_version", [], |row| row.get(0))?;
        assert_eq!(version, 20);
        state::start(store, parse(args)?, 1002)
    })
    .await?;
    let mut no_routes = config.clone();
    no_routes.owner_ingress = None;
    for (settings, expected) in [
        (&no_routes, OWNER_BIND_UNAVAILABLE),
        (&config, OWNER_BIND_HINT),
    ] {
        let reply = owner_call(start(start_args.clone()), settings, &store).await?;
        let result = serde_json::to_value(present(Ok(reply), renderer()?))?;
        assert!(
            result["content"][0]["text"]
                .as_str()
                .is_some_and(|text| text.contains(expected))
        );
    }
    install(&store, &batch).await?;
    let templates = renderer()?;
    for (tool, key, args) in [
        ("pool_join", "join", json!({"expected_revision":1})),
        (
            "pool_notify_owner",
            "notice",
            json!({"expected_revision":2,"body":"persisted backlog"}),
        ),
    ] {
        let call = member_call(&batch, 0, tool, key, args);
        assert!(ok(&private_call(call, &config, &store, templates).await));
    }
    drop(store);

    let store = Arc::new(Mutex::new(Store::open(&config.database_path)?));
    let bind = |pool_id: &str| OwnerRequest {
        tool: BIND_OWNER.into(),
        arguments: json!({"pool_id":pool_id,"harness":"codex","session_id":"session"}),
    };
    assert!(matches!(
        owner_call(bind(&old.pool_id), &config, &store).await,
        Err(Fault::Unauthorized)
    ));
    assert!(matches!(
        owner_call(bind(&batch.pool_id), &config, &store).await?,
        ChatReply::OwnerBound
    ));
    stored(&store, move |store| {
        let (address, text): (String, String) = store.test_db().query_row(
            "SELECT json_extract(data,'$.work.address'),json_extract(data,'$.work.text')
             FROM effects WHERE pool=?1 AND json_extract(data,'$.work.scope')='owner:'||?1",
            [batch.pool_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        assert_eq!(address, "test/codex/owner/session");
        assert!(text.contains("persisted backlog"));
        Ok(())
    })
    .await?;
    Ok(())
}
