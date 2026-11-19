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
    json!({"request_key":"start","name":"Mixed profiles","purpose":"Agree a result","members":[spec("implement"),spec("review"),spec("research")],"owner_address":address})
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
                        assert_eq!(spec["profile"], ["implement", "review", "research"][index]);
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
        assert_eq!(
            present(
                Ok(ChatReply::Launch {
                    pool_id: pool_id.clone(),
                    revision: 1,
                    state: state.clone(),
                    request_key: "start".into(),
                    seats: Vec::new(),
                    old_agent_id: None
                }),
                templates
            )
            .is_error,
            Some(false)
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
        let batch = state::start(store, parse(args)?)?;
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
    let batch = reserve(&store, address).await?;
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
    assert!(ok(&call(dm.clone()).await));
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
        let state::Notice::Unresolved(target) = state::notice(store, &effect)? else {
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
    assert!(ok(&call(proposal).await));
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
    for index in 0..3 {
        let vote = member_call(
            &batch,
            index,
            "pool_vote",
            &format!("ready-{index}"),
            json!({
                "expected_revision":7+index,"proposal_id":proposal,"roster_key":roster_key,
                "choice":"ready","evidence":format!("evidence {index}")
            }),
        );
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
        arguments: json!({"pool_id":batch.pool_id,"expected_revision":10,"request_key":"close"}),
    };
    let ChatReply::Existing(Reply::Receipt(receipt)) = owner_call(close, &config, &store).await?
    else {
        return Err("close".into());
    };
    assert!(matches!(receipt.event.author, Author::Leader));
    assert_refusal(&call(get()).await, "pool_closed");
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
        store.test_db().execute_batch("DROP TABLE chat_notice_targets; DROP TABLE chat_agreements; DROP TABLE chat_batches; DROP TABLE chat_pools; PRAGMA user_version=17;")?;
        Ok(old.pool_id)
    }).await?;
    drop(store);
    let mut upgraded = Store::open(&config.database_path)?;
    assert_eq!(
        upgraded
            .test_db()
            .query_row("PRAGMA user_version", [], |r| r.get::<_, u32>(0))?,
        18
    );
    let ChatReply::Overview(old) =
        state::owner_call(&mut upgraded, "pool_get", json!({"pool_id":pid}))?
    else {
        return Err("old pool".into());
    };
    assert_eq!(old.name, "Legacy");
    assert!(old.purpose.contains("Old purpose"));
    let new = state::start(&mut upgraded, parse(input(None))?)?;
    assert_ne!(new.pool_id, pid);
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
    let ChatReply::Launch { state, seats, .. } =
        stored(&store, move |store| state::launch_read(store, &batch)).await?
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
        let ChatReply::Launch { state, seats, .. } = state::launch_read(store, &batch)? else {
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
    let batch = stored(&store, move |store| state::start(store, parse(args)?)).await?;
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
