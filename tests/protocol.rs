//! Black-box SDK lifecycle and raw JSON-RPC compatibility tests against a spawned binary.
//! This is SDK-pair compatibility, not certification of all external agent hosts.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "Explicit test failures"
)]
use rmcp::{ServiceExt, model::CallToolRequestParams, transport::TokioChildProcess};
use std::{
    path::PathBuf,
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
/// Resolve an explicitly supplied shipped binary or the Cargo-built product.
fn binary() -> PathBuf {
    std::env::var_os("MCP_TEST_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_agent-pool")))
}
/// The actual installer refuses another platform or product before creating an installation home.
#[cfg(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")
))]
#[test]
fn self_install_rejects_foreign_bundle_identity() {
    let root =
        tempfile::tempdir_in(std::env::var_os("TMPDIR").expect("task TMPDIR required")).unwrap();
    let source = root.path().join("fake-binary");
    std::fs::write(&source, b"#!/bin/sh\nprintf 'synthetic-ok\\n'\n").unwrap();
    let bin_dir = root.path().join("bin");
    std::fs::create_dir(&bin_dir).unwrap();
    let local_target = if cfg!(target_os = "macos") {
        "aarch64-apple-darwin"
    } else {
        "x86_64-unknown-linux-gnu"
    };
    let foreign_target = if cfg!(target_os = "macos") {
        "x86_64-unknown-linux-gnu"
    } else {
        "aarch64-apple-darwin"
    };
    for (index, product, target) in [
        (1, "agent-pool", foreign_target),
        (2, "agent-other", local_target),
    ] {
        let bundle = root.path().join(format!("bundle-{index}"));
        family_delivery::package(
            &source,
            &bundle,
            family_delivery::Manifest {
                schema_version: 1,
                profile: "single-binary-v1".into(),
                product: product.into(),
                version: "0.1.0".into(),
                source_commit: "a".repeat(40),
                target: target.into(),
                binary: format!("{product}-{target}"),
                size: 1,
                sha256: "0".repeat(64),
                state_schema: 0,
                run_id: None,
                run_attempt: None,
            },
        )
        .unwrap();
        let home = root.path().join(format!("home-{index}"));
        let output = std::process::Command::new(binary())
            .args(["self-install", "--bundle"])
            .arg(&bundle)
            .arg("--home")
            .arg(&home)
            .arg("--bin-dir")
            .arg(&bin_dir)
            .env_clear()
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(!home.exists());
        assert!(std::fs::read_dir(&bin_dir).unwrap().next().is_none());
    }
    let bundle = root.path().join("bundle-valid");
    family_delivery::package(
        &source,
        &bundle,
        family_delivery::Manifest {
            schema_version: 1,
            profile: "single-binary-v1".into(),
            product: "agent-pool".into(),
            version: "0.1.0".into(),
            source_commit: "a".repeat(40),
            target: local_target.into(),
            binary: format!("agent-pool-{local_target}"),
            size: 1,
            sha256: "0".repeat(64),
            state_schema: 0,
            run_id: None,
            run_attempt: None,
        },
    )
    .unwrap();
    let home = root.path().join("home-valid");
    let output = std::process::Command::new(binary())
        .args(["self-install", "--bundle"])
        .arg(&bundle)
        .arg("--home")
        .arg(&home)
        .arg("--bin-dir")
        .arg(&bin_dir)
        .env_clear()
        .output()
        .unwrap();
    assert!(output.status.success());
    let output = std::process::Command::new(bin_dir.join("agent-pool"))
        .env_clear()
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"synthetic-ok\n");
    let current = home.join("standalone/current");
    let selected = std::fs::read_link(&current).unwrap();
    let lock = home.join("standalone/install.lock");
    std::fs::remove_file(&lock).unwrap();
    let output = std::process::Command::new(binary())
        .args(["releases", "use", "--version", "0.1.0", "--home"])
        .arg(&home)
        .arg("--bin-dir")
        .arg(&bin_dir)
        .env_clear()
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!lock.exists());
    assert_eq!(std::fs::read_link(current).unwrap(), selected);
}
/// A previous binary must refuse newer state before changing the database or starting a resident.
#[tokio::test]
#[ignore = "requires AGENT_POOL_TEST_PREVIOUS_BINARY pointing to a task-owned previous-schema binary"]
async fn previous_binary_refuses_newer_state() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let previous = std::env::var_os("AGENT_POOL_TEST_PREVIOUS_BINARY")
        .or_else(|| std::env::var_os("AGENT_POOL_TEST_V2_BINARY"))
        .expect("previous binary path");
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let uid = std::fs::metadata(root.path()).unwrap().uid();
    let database = root.path().join("pool.db");
    let connection = rusqlite::Connection::open(&database).unwrap();
    connection
        .execute_batch(&format!(
            "PRAGMA journal_mode=DELETE; CREATE TABLE retained(value TEXT); \
             INSERT INTO retained VALUES('fixture'); PRAGMA user_version={};",
            family_delivery::CURRENT_STATE_SCHEMA
        ))
        .unwrap();
    drop(connection);
    std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o600)).unwrap();
    let before = std::fs::read(&database).unwrap();
    let socket = root.path().join("pool.sock");
    let config = root.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            "socket_path = {socket:?}\ndatabase_path = {database:?}\nexpected_uid = {uid}\n\
             bridge_registration_socket = {:?}\nbridge_core_socket = {:?}\n\
             bridge_credential_file = {:?}\nbridge_producer_id = \"fixture\"\n\
             bridge_audience = \"fixture\"\nbridge_server_executable = \"/fixture/bridge\"\nbridge_server_sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\n",
            root.path().join("absent-registration"),
            root.path().join("absent-bridge"),
            root.path().join("absent-token")
        ),
    )
    .unwrap();
    let output = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::process::Command::new(previous)
            .arg("serve")
            .arg("--config")
            .arg(&config)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("previous binary deadline")
    .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr).trim(),
        "resident: Conflict"
    );
    assert_eq!(std::fs::read(&database).unwrap(), before);
    assert!(!socket.exists());
}
/// Exercise discovery, valid and invalid calls through the SDK within 20 seconds.
#[tokio::test]
async fn protocol() {
    let root = tempfile::tempdir().unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut command = tokio::process::Command::new(binary());
        command
            .arg("mcp")
            .env_clear()
            .env("HOME", root.path())
            .current_dir(root.path())
            .kill_on_drop(true)
            .stderr(Stdio::null());
        let client = ().serve(TokioChildProcess::new(command).unwrap()).await.unwrap();
        let listed = client.list_tools(Default::default()).await.unwrap();
        let expected: serde_json::Value =
            serde_json::from_str(include_str!("../schemas/tools.json")).unwrap();
        assert_eq!(serde_json::to_value(&listed.tools).unwrap(), expected);
        let result = client
            .call_tool(CallToolRequestParams::new("get_status"))
            .await
            .unwrap();
        let wire = serde_json::to_value(result).unwrap();
        assert_eq!(wire["isError"], false);
        assert_eq!(wire["content"].as_array().unwrap().len(), 1);
        let args = serde_json::json!({"unexpected":true})
            .as_object()
            .unwrap()
            .clone();
        let invalid = client
            .call_tool(CallToolRequestParams::new("get_status").with_arguments(args))
            .await
            .unwrap();
        assert_eq!(serde_json::to_value(invalid).unwrap()["isError"], true);
        assert!(
            client
                .call_tool(CallToolRequestParams::new("missing_tool"))
                .await
                .is_err()
        );
        client.cancel().await.unwrap();
    })
    .await
    .expect("protocol deadline");
}

/// Exchange raw JSON-RPC in an isolated child. Notifications receive no reply.
/// A 20-second deadline covers reads and EOF shutdown; cancellation kills the child.
async fn raw_exchange(requests: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let root = tempfile::tempdir().unwrap();
    let mut child = tokio::process::Command::new(binary())
        .arg("mcp")
        .env_clear()
        .env("HOME", root.path())
        .current_dir(root.path())
        .kill_on_drop(true)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut input = child.stdin.take().unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap()).lines();
        let mut replies = Vec::new();
        for request in requests {
            input
                .write_all(format!("{request}\n").as_bytes())
                .await
                .unwrap();
            input.flush().await.unwrap();
            if request.get("id").is_some() {
                let line = output
                    .next_line()
                    .await
                    .unwrap()
                    .expect("JSON-RPC response before EOF");
                let reply: serde_json::Value = serde_json::from_str(&line).unwrap();
                assert_eq!(reply["id"], request["id"]);
                assert!(reply.get("error").is_none(), "{reply}");
                replies.push(reply);
            }
        }
        drop(input);
        assert!(child.wait().await.unwrap().success());
        replies
    })
    .await
    .expect("raw protocol deadline")
}

/// Build a modern request with its version and empty client capabilities.
fn modern_request(method: &str) -> serde_json::Value {
    serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":{"_meta":{
        "io.modelcontextprotocol/protocolVersion":"2026-07-28",
        "io.modelcontextprotocol/clientCapabilities":{}
    }}})
}

/// Require a nonempty live catalog identical to the reviewed snapshot.
fn assert_catalog(result: &serde_json::Value) {
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("../schemas/tools.json")).unwrap();
    assert!(!result["tools"].as_array().unwrap().is_empty());
    assert_eq!(result["tools"], expected);
}

/// Modern tools/list has no handshake and supplies exact private cache hints.
#[tokio::test]
async fn modern_tools_list() {
    let replies = raw_exchange(&[modern_request("tools/list")]).await;
    let result = &replies[0]["result"];
    assert_eq!(result["resultType"], "complete");
    assert_eq!(result["ttlMs"].as_u64(), Some(60_000));
    assert_eq!(result["cacheScope"], "private");
    assert_catalog(result);
}

/// Legacy initialize/initialized sessions omit all modern-only result fields.
#[tokio::test]
async fn legacy_tools_list() {
    let replies = raw_exchange(&[
        serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-11-25","capabilities":{},
            "clientInfo":{"name":"raw-test","version":"1"}
        }}),
        serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    ])
    .await;
    assert_eq!(replies[0]["result"]["protocolVersion"], "2025-11-25");
    let result = &replies[1]["result"];
    for field in ["ttlMs", "cacheScope", "resultType"] {
        assert!(
            result.get(field).is_none(),
            "legacy field {field}: {result}"
        );
    }
    assert_catalog(result);
}

/// Guard modern server/discover defaults and the advertised modern revision.
#[tokio::test]
async fn modern_server_discover() {
    let replies = raw_exchange(&[modern_request("server/discover")]).await;
    let result = &replies[0]["result"];
    assert!(
        result["supportedVersions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|version| version == "2026-07-28")
    );
    assert_eq!(result["ttlMs"].as_u64(), Some(0));
    assert_eq!(result["cacheScope"], "private");
}

/// Require termination within five seconds after stdin closes.
#[test]
fn eof_releases_stdio_process() {
    let mut child = std::process::Command::new(binary())
        .arg("mcp")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    drop(child.stdin.take());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().unwrap().is_some() {
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("MCP process survived stdin EOF");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The real rmcp dispatch moves wire _meta into RequestContext; the frontend must
/// preserve those exact fields for SDK registration. The fake adapter only captures
/// bytes and refuses authority: this is metadata transport proof, not native qualification.
#[tokio::test]
async fn original_call_metadata_reaches_registration_after_rmcp_dispatch() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let root =
        tempfile::tempdir_in(std::env::var_os("TMPDIR").expect("task TMPDIR required")).unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let adapter_path = root.path().join("adapter.sock");
    let core_path = root.path().join("core.sock");
    let adapter = tokio::net::UnixListener::bind(&adapter_path).unwrap();
    let _core = tokio::net::UnixListener::bind(&core_path).unwrap();
    for path in [&adapter_path, &core_path] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let token = root.path().join("token");
    std::fs::write(&token, "fixture-not-a-live-credential").unwrap();
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    let config = root.path().join("config.toml");
    std::fs::write(&config,format!("socket_path={:?}\ndatabase_path={:?}\nexpected_uid={}\nbridge_registration_socket={:?}\nbridge_core_socket={:?}\nbridge_credential_file={:?}\nbridge_producer_id=\"pool-fixture\"\nbridge_audience=\"pool-backend-fixture\"\nbridge_server_executable=\"/fixture/bridge\"\nbridge_server_sha256=\"0000000000000000000000000000000000000000000000000000000000000000\"\n",root.path().join("pool.sock"),root.path().join("pool.db"),std::fs::metadata(root.path()).unwrap().uid(),adapter_path,core_path,token)).unwrap();
    let capture = tokio::spawn(async move {
        let (stream, _) = adapter.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        serde_json::from_str::<serde_json::Value>(&line).unwrap()
    });
    tokio::time::timeout(Duration::from_secs(20),async {
        let mut command=tokio::process::Command::new(binary());command.arg("mcp").arg("--config").arg(config).env_clear().env("HOME",root.path()).current_dir(root.path()).kill_on_drop(true).stderr(Stdio::null());
        let client=().serve(TokioChildProcess::new(command).unwrap()).await.unwrap();
        let original=serde_json::json!({"threadId":"fixture-thread","callId":"fixture-call","x-codex-turn-metadata":{"fixture":"protected-original"}});
        let mut call=CallToolRequestParams::new("pool_list");call.meta=Some(serde_json::from_value(original.clone()).unwrap());
        let result=client.call_tool(call).await.unwrap();assert_eq!(result.is_error,Some(true));
        let received=capture.await.unwrap();let metadata=received.pointer("/params/evidence/metadata").expect("native registration metadata");
        for key in ["threadId","callId","x-codex-turn-metadata"]{assert_eq!(metadata.get(key),original.get(key));}
        client.cancel().await.unwrap();
    }).await.expect("metadata fixture deadline");
}

/// Serves only the Bridge operations needed by this fixture, validating SDK request/response bindings.
/// Assertions are single-use, and publication custody is synthetic rather than native delivery.
async fn fixture_bridge(
    adapter: tokio::net::UnixListener,
    core: tokio::net::UnixListener,
    mut stop: tokio::sync::oneshot::Receiver<()>,
    publications: tokio::sync::mpsc::UnboundedSender<bridge_sdk::bridge_protocol::PublishParams>,
) {
    use bridge_sdk::bridge_protocol::{
        CallEvidence, Destination, Operation, OperationResult, Response, Secret, StatusSelector,
        decode_request, encode_response, publication_intent_fingerprint,
    };
    use std::collections::HashMap;

    let mut assertions = HashMap::new();
    let mut receipts = HashMap::new();
    loop {
        let (stream, registration) = tokio::select! {
            _ = &mut stop => break,
            accepted = adapter.accept() => (accepted.unwrap().0, true),
            accepted = core.accept() => (accepted.unwrap().0, false),
        };
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let request = decode_request(line.trim_end_matches('\n').as_bytes()).unwrap();
        assert_eq!(request.credential.expose(), "fixture-token");
        let now = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        let result = match &request.operation {
            Operation::RegisterCall(params) if registration => {
                let Some(CallEvidence::Native { metadata, .. }) = &params.evidence else {
                    panic!("expected native fixture metadata");
                };
                assert_eq!(metadata["threadId"], "fixture-thread");
                let call = metadata["callId"].as_str().unwrap();
                assert!(matches!(
                    call,
                    "current" | "historical" | "member" | "wait-expired" | "wait-tampered"
                ));
                let invocation = params.invocation_key.as_ref().unwrap();
                let key = format!("fixture-{invocation}");
                assertions.insert(
                    key.clone(),
                    (
                        invocation.clone(),
                        call.to_owned(),
                        None::<(String, serde_json::Value)>,
                        now,
                    ),
                );
                serde_json::json!({"op":"register_call","value":{
                    "receipt":{"producer":"pool-fixture","request_id":request.request_id,
                        "operation_key":params.operation_key,"route_key":"fixture-route",
                        "caller_scope":"fixture-caller","destination_scope":"fixture-destination",
                        "reply_policy":"self","constraints":{"allowed_modes":["message"],
                            "allowed_kinds":["agent_pool"],"max_payload_bytes":16384,"reply_policy":"self"},
                        "state":"open","created_at_ms":now,"route_expires_at_ms":params.route_expires_at_ms},
                    "evidence_state":"fresh_assertion_available",
                    "assertion":{"assertion_key":Secret::new(key),"invocation_key":invocation,
                        "audience":params.assertion_audience,"observed_at_ms":now,"expires_at_ms":now+60000,
                        "issuer_boot":"fixture-boot","endpoint_incarnation":"fixture-endpoint"}
                }})
            }
            Operation::ConsumeAssertion(params) if registration => {
                let (invocation, call, consumed, observed) = assertions
                    .get_mut(params.assertion_key.expose())
                    .expect("registered assertion");
                assert_eq!(params.invocation_key, *invocation);
                let invocation = invocation.clone();
                let call = call.as_str();
                let (address, actor) = if call == "member" {
                    ("local/codex/store/fixture-member", "fixture-member")
                } else {
                    ("local/codex/store/fixture-leader", "fixture-leader")
                };
                let replayed = consumed.is_some();
                let mut receipt = if let Some((request_id, receipt)) = consumed.as_ref() {
                    assert_eq!(request_id, &request.request_id);
                    receipt.clone()
                } else {
                    let receipt = serde_json::json!({"producer":"pool-fixture","request_id":request.request_id,
                        "context":{"audience":"pool-backend-fixture","caller_scope":"fixture-caller",
                            "destination_scope":"fixture-destination","caller_address":address,
                            "destination_address":address,"role":"root","native_actor_id":actor,
                            "native_call_id":"fixture-call","invocation_key":invocation,"observed_at_ms":observed,
                            "expires_at_ms":now+60000,"issuer_boot":"fixture-boot",
                            "endpoint_incarnation":"fixture-endpoint"},"consumed_at_ms":now});
                    *consumed = Some((request.request_id.clone(), receipt.clone()));
                    receipt
                };
                if call == "wait-tampered" && replayed {
                    receipt["context"]["expires_at_ms"] = serde_json::json!(now + 120000);
                }
                serde_json::json!({"op":"consume_assertion","value":{
                    "receipt":receipt,
                    "state":if call == "historical" || (call == "wait-expired" && replayed) {"historical"} else {"current"}
                }})
            }
            Operation::Publish(params) if !registration => {
                let Destination::Address { address } = &params.destination else {
                    panic!("expected direct fixture destination");
                };
                let receipt = serde_json::json!({"producer":"pool-fixture","event_id":params.event_id,
                    "intent_hash":publication_intent_fingerprint(params).unwrap(),"envelope_hash":"a".repeat(64),
                    "accepted_at_ms":now,"acceptance_seq":1,"destination":{"address":address,
                        "route_key":null,"caller_scope":null,"destination_scope":null}});
                receipts.insert(params.event_id.clone(), receipt.clone());
                serde_json::json!({"op":"publish","value":{"receipt":receipt,"replayed":false}})
            }
            Operation::Status(params) if !registration => {
                let StatusSelector::Event { event_id } = &params.selector else {
                    panic!("expected fixture event status");
                };
                serde_json::json!({"op":"status","value":{"type":"event","event":{
                    "receipt":receipts.get(event_id).expect("published fixture event"),"custody_state":"pending",
                    "delivery":{"delivery":"unhanded","attempt_state":null,"effective_mode":null,
                        "note":null,"attempts_made":0,"attempt":null,"tiers":[],"incident":null,
                        "hold_reason":null,"blocked_by":null}
                }}})
            }
            _ => panic!(
                "unexpected fixture Bridge operation {} on {} socket",
                serde_json::to_value(&request.operation).unwrap()["op"],
                if registration { "adapter" } else { "core" }
            ),
        };
        let result: OperationResult = serde_json::from_value(result).unwrap();
        let response = Response::ok(request.request_id.clone(), result);
        response.validate_for(&request).unwrap();
        let mut bytes = encode_response(&response).unwrap();
        bytes.push(b'\n');
        reader.get_mut().write_all(&bytes).await.unwrap();
        if let Operation::Publish(params) = request.operation {
            publications.send(params).unwrap();
        }
    }
}

/// Constructs a real MCP call whose original metadata selects the fixture assertion state.
fn fixture_pool_call(
    name: &'static str,
    arguments: serde_json::Value,
    call_id: &str,
) -> CallToolRequestParams {
    let mut call =
        CallToolRequestParams::new(name).with_arguments(arguments.as_object().unwrap().clone());
    call.meta = Some(
        serde_json::from_value(
            serde_json::json!({"threadId":"fixture-thread","callId":call_id,
            "x-codex-turn-metadata":{"fixture":"protected-original"}}),
        )
        .unwrap(),
    );
    call
}

/// A real frontend and resident reject historical authority, commit a pool and publish its invitation.
/// All identities, Bridge responses and tokens are synthetic; this is not native qualification.
#[tokio::test]
async fn frontend_resident_fixture_commits_and_publishes() {
    use bridge_sdk::bridge_protocol::{Destination, Mode, Policy};
    use rusqlite::{Connection, OpenFlags};
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

    let root =
        tempfile::tempdir_in(std::env::var_os("TMPDIR").expect("task TMPDIR required")).unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let adapter_path = root.path().join("adapter.sock");
    let core_path = root.path().join("core.sock");
    let pool_socket = root.path().join("pool.sock");
    let database = root.path().join("pool.db");
    let adapter = tokio::net::UnixListener::bind(&adapter_path).unwrap();
    let core = tokio::net::UnixListener::bind(&core_path).unwrap();
    for path in [&adapter_path, &core_path] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let token = root.path().join("token");
    std::fs::write(&token, "fixture-token").unwrap();
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    let config = root.path().join("config.toml");
    std::fs::write(&config,format!("socket_path={pool_socket:?}\ndatabase_path={database:?}\nexpected_uid={}\nbridge_registration_socket={adapter_path:?}\nbridge_core_socket={core_path:?}\nbridge_credential_file={token:?}\nbridge_producer_id=\"pool-fixture\"\nbridge_audience=\"pool-backend-fixture\"\nbridge_server_executable=\"/fixture/bridge\"\nbridge_server_sha256=\"0000000000000000000000000000000000000000000000000000000000000000\"\n",std::fs::metadata(root.path()).unwrap().uid())).unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let (publish, mut published) = tokio::sync::mpsc::unbounded_channel();
    let bridge = tokio::spawn(fixture_bridge(adapter, core, stopped, publish));
    let mut resident = tokio::process::Command::new(binary())
        .arg("serve")
        .arg("--config")
        .arg(&config)
        .env_clear()
        .env("HOME", root.path())
        .current_dir(root.path())
        .kill_on_drop(true)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(25), async {
        loop {
            assert!(
                resident.try_wait().unwrap().is_none(),
                "resident exited before readiness"
            );
            if std::fs::symlink_metadata(&pool_socket).is_ok_and(|metadata| {
                metadata.file_type().is_socket() && metadata.permissions().mode() & 0o777 == 0o600
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let mut command = tokio::process::Command::new(binary());
        command
            .arg("mcp")
            .arg("--config")
            .arg(&config)
            .env_clear()
            .env("HOME", root.path())
            .current_dir(root.path())
            .kill_on_drop(true)
            .stderr(Stdio::null());
        let client = ().serve(TokioChildProcess::new(command).unwrap()).await.unwrap();
        let db = Connection::open_with_flags(&database, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();

        let rejected = client
            .call_tool(fixture_pool_call(
                "pool_create",
                serde_json::json!({
                    "request_key":"historical-create","name":"Denied","purpose":"Must not persist"
                }),
                "historical",
            ))
            .await
            .unwrap();
        assert_eq!(rejected.is_error, Some(true));
        let rejected = serde_json::to_value(rejected).unwrap();
        assert!(
            rejected["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("unauthorized")
        );
        let count: i64 = db
            .query_row("SELECT count(*) FROM pools", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0, "historical assertion must not mutate state");

        let created = client.call_tool(fixture_pool_call("pool_create", serde_json::json!({
            "request_key":"create-fixture","name":"Fixture Pool","purpose":"goal".repeat(2048),
            "acceptance":[{"id":"fixture","text":"The fixture was checked."}]
        }), "current")).await.unwrap();
        assert_eq!(created.is_error, Some(false));
        let (pool_id, pool_data): (String, String) = db
            .query_row("SELECT id,data FROM pools", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        let pool: serde_json::Value = serde_json::from_str(&pool_data).unwrap();
        assert_eq!(pool["name"], "Fixture Pool");
        assert_eq!(pool["revision"], 1);
        assert_eq!(pool["acceptance"][0]["id"], "fixture");
        let content = client.call_tool(fixture_pool_call("pool_get", serde_json::json!({
            "pool_id":pool_id,"section":"content","field":"purpose"
        }), "current")).await.unwrap();
        assert_eq!(content.is_error, Some(false));
        let content = serde_json::to_value(content).unwrap();
        assert!(content["content"][0]["text"].as_str().unwrap().contains("Content purpose bytes 0/8192"));
        let criteria = client
            .call_tool(fixture_pool_call(
                "pool_get",
                serde_json::json!({
                    "pool_id":pool_id,"section":"criteria"
                }),
                "current",
            ))
            .await
            .unwrap();
        assert_eq!(criteria.is_error, Some(false));
        let criteria = serde_json::to_value(criteria).unwrap();
        assert!(
            criteria["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("Criterion fixture:")
        );
        let last_event: i64 = db.query_row("SELECT MAX(id) FROM events WHERE pool=?1", [&pool_id], |row| row.get(0)).unwrap();
        let began = std::time::Instant::now();
        let waited = client.call_tool(fixture_pool_call("pool_get", serde_json::json!({
            "pool_id":pool_id,"section":"history","after":last_event,"wait_seconds":0.1
        }), "current")).await.unwrap();
        assert_eq!(waited.is_error, Some(false));
        assert!(began.elapsed() >= Duration::from_millis(90));
        let expired = client.call_tool(fixture_pool_call("pool_get", serde_json::json!({
            "pool_id":pool_id,"section":"history","after":last_event,"wait_seconds":0.1
        }), "wait-expired")).await.unwrap();
        assert_eq!(expired.is_error, Some(true));
        let tampered = client.call_tool(fixture_pool_call("pool_get", serde_json::json!({
            "pool_id":pool_id,"section":"history","after":last_event,"wait_seconds":0.1
        }), "wait-tampered")).await.unwrap();
        assert_eq!(tampered.is_error, Some(true));
        let reverse = client.call_tool(fixture_pool_call("pool_get", serde_json::json!({
            "pool_id":pool_id,"section":"history","reverse":true
        }), "current")).await.unwrap();
        assert_eq!(reverse.is_error, Some(false));
        let reverse = serde_json::to_value(reverse).unwrap();
        assert!(reverse["content"][0]["text"].as_str().unwrap().contains("next_before="));

        let address = "local/codex/store/fixture-member";
        let added = client.call_tool(fixture_pool_call("pool_add", serde_json::json!({
            "pool_id":pool_id,"expected_revision":1,"request_key":"add-fixture","address":address,
            "name":"Fixture member","role":"Worker","task":"Check the invitation"
        }), "current")).await.unwrap();
        assert_eq!(added.is_error, Some(false));
        let member_address: String = db
            .query_row(
                "SELECT address FROM members WHERE pool=?1 AND current=1",
                [&pool_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(member_address, address);
        let publication = published.recv().await.expect("fixture publication");
        assert_eq!(
            publication.destination,
            Destination::Address {
                address: address.into()
            }
        );
        assert_eq!(publication.kind, "agent_pool");
        assert_eq!(publication.mode, Mode::Message);
        assert_eq!(publication.policy, Policy::KeepAll);
        assert!(publication.payload.as_str().contains(&pool_id));
        let stored: String = db
            .query_row(
                "SELECT params FROM publications WHERE effect=?1",
                [&publication.event_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&stored).unwrap(),
            serde_json::to_value(&publication).unwrap()
        );
        loop {
            let state: String = db
                .query_row(
                    "SELECT state FROM effects WHERE id=?1",
                    [&publication.event_id],
                    |row| row.get(0),
                )
                .unwrap();
            if state == "custody" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let joined = client.call_tool(fixture_pool_call("pool_join", serde_json::json!({
            "pool_id":pool_id,"expected_revision":2,"request_key":"join-fixture"
        }), "member")).await.unwrap();
        assert_eq!(joined.is_error, Some(false));
        let proposed = client.call_tool(fixture_pool_call("pool_propose", serde_json::json!({
            "pool_id":pool_id,"expected_revision":3,"request_key":"proposal-fixture",
            "result":"Fixture result","criteria":"See acceptance","snapshot":"s".repeat(65536)
        }), "current")).await.unwrap();
        assert_eq!(proposed.is_error, Some(false));
        let snapshot = client.call_tool(fixture_pool_call("pool_get", serde_json::json!({
            "pool_id":pool_id,"section":"content","field":"snapshot"
        }), "current")).await.unwrap();
        assert_eq!(snapshot.is_error, Some(false));
        let snapshot = serde_json::to_value(snapshot).unwrap();
        assert!(snapshot["content"][0]["text"].as_str().unwrap().contains("Content snapshot bytes 0/65536"));
        let long = client.call_tool(fixture_pool_call("pool_post", serde_json::json!({
            "pool_id":pool_id,"expected_revision":4,"request_key":"long-fixture","body":"🦀".repeat(1025)
        }), "current")).await.unwrap();
        assert_eq!(long.is_error, Some(false));
        let long = serde_json::to_value(long).unwrap();
        assert!(long["content"][0]["text"].as_str().unwrap().contains("has 3 history parts"));
        let batch = client.call_tool(fixture_pool_call("pool_start_batch", serde_json::json!({
            "pool_id":pool_id,"expected_revision":5,"request_key":"batch-fixture",
            "members":[
                {"name":"One","role":"Tester","task":"First","spec":{"task":"First","provider":"fixture"}},
                {"name":"Two","role":"Tester","task":"Second","spec":{"task":"Second","provider":"fixture"}}
            ]
        }), "current")).await.unwrap();
        assert_eq!(batch.is_error, Some(false));
        let batch = serde_json::to_value(batch).unwrap();
        let text = batch["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("Created members in request order:"), "{text}");
        let count: i64 = db.query_row("SELECT count(*) FROM members WHERE pool=?1 AND current=1", [&pool_id], |row| row.get(0)).unwrap();
        assert_eq!(count, 3);
        client.cancel().await.unwrap();
    })
    .await
    .expect("frontend-to-resident fixture deadline");
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(20), bridge)
        .await
        .expect("fixture Bridge shutdown deadline")
        .unwrap();
    resident.kill().await.unwrap();
    resident.wait().await.unwrap();
}

/// Runs the fixed observer CLI with finite input and collects exactly one structured line.
/// kill_on_drop and an external deadline bound child cleanup without any live service.
async fn observer_cli(input: &[u8], config: Option<&std::path::Path>) -> std::process::Output {
    let mut command = tokio::process::Command::new(binary());
    command
        .arg("observe")
        .env_clear()
        .kill_on_drop(true)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(config) = config {
        command.arg("--config").arg(config);
    }
    let mut child = command.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(input).await.unwrap();
    drop(stdin);
    tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .expect("observer CLI fixture deadline")
        .unwrap()
}

/// Malformed, multiple-line, missing-source and unknown-operation inputs preserve typed errors, without prose.
#[tokio::test]
async fn observer_cli_errors_are_one_structured_line() {
    for input in [
        b"{}\n".as_slice(),
        b"{\"schema_version\":1,\"operation\":\"identity\",\"params\":{}}\n\n",
        b"{\"schema_version\":1,\"operation\":\"pool_create\",\"params\":{}}\n",
        b"\xff\n",
        b"{\"schema_version\":1,\"operation\":\"identity\",\"params\":{}}\n",
    ] {
        let output = observer_cli(input, None).await;
        assert!(!output.status.success());
        assert!(output.stderr.is_empty());
        assert_eq!(
            output.stdout.iter().filter(|byte| **byte == b'\n').count(),
            1
        );
        let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(envelope["schema_version"], 1);
        assert!(envelope.get("data").is_none());
        assert!(envelope["error"]["code"].is_string());
        assert!(envelope["error"]["outcome"].is_string());
    }
}

/// The CLI loads only its protected observer token and forwards to the existing socket, without opening a DB.
#[tokio::test]
async fn observer_cli_uses_separate_credential_and_resident() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let directory =
        tempfile::tempdir_in(std::env::var_os("TMPDIR").expect("task TMPDIR required")).unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.path();
    let socket = path.join("pool.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let token = path.join("observer.token");
    std::fs::write(&token, "fixture-only-observer").unwrap();
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    let config = path.join("config.toml");
    std::fs::write(&config, format!("socket_path={socket:?}\ndatabase_path={:?}\nexpected_uid={}\nbridge_registration_socket={:?}\nbridge_core_socket={:?}\nbridge_credential_file={:?}\nbridge_producer_id=\"fixture\"\nbridge_audience=\"fixture\"\nbridge_server_executable=\"/fixture/bridge\"\nbridge_server_sha256=\"0000000000000000000000000000000000000000000000000000000000000000\"\nowner_observer_credential_file={token:?}\n",path.join("must-not-open.db"),std::fs::metadata(path).unwrap().uid(),path.join("absent-register.sock"),path.join("absent-core.sock"),path.join("absent-bridge.token"))).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        let resident = async {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let mut line = String::new();
            stream.read_line(&mut line).await.unwrap();
            let request: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(request["observer_credential"], "fixture-only-observer");
            assert_eq!(request["observe"]["operation"], "identity");
            assert!(request.get("assertion").is_none());
            stream.write_all(b"{\"schema_version\":1,\"kind\":\"identity\",\"data\":{\"product\":\"agent-pool\",\"version\":\"0.1.0\",\"qualification\":\"not_verified\",\"capabilities\":[\"identity\",\"list\",\"get\"],\"observed_at_unix_ms\":1}}\n").await.unwrap();
        };
        let (_, output) = tokio::join!(resident, observer_cli(b"{\"schema_version\":1,\"operation\":\"identity\",\"params\":{}}\n",Some(&config)));
        assert!(output.status.success(), "{}",String::from_utf8_lossy(&output.stdout));
        assert!(output.stderr.is_empty());
        assert_eq!(output.stdout.iter().filter(|byte| **byte == b'\n').count(), 1);
        let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(envelope["data"]["product"], "agent-pool");
        assert!(envelope.get("error").is_none());
        assert!(!output.stdout.windows(b"fixture-only-observer".len()).any(|bytes| bytes == b"fixture-only-observer"));
    }).await.expect("observer resident fixture deadline");
    assert!(!path.join("must-not-open.db").exists());
}

/// Doctor uses only an explicitly configured owner grant for the resident headroom snapshot.
#[tokio::test]
async fn doctor_reports_owner_capacity_without_opening_database() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let directory =
        tempfile::tempdir_in(std::env::var_os("TMPDIR").expect("task TMPDIR required")).unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.path();
    let socket = path.join("pool.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let token = path.join("observer.token");
    std::fs::write(&token, "fixture-only-observer").unwrap();
    std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    let config = path.join("config.toml");
    std::fs::write(&config,format!("socket_path={socket:?}\ndatabase_path={:?}\nexpected_uid={}\nbridge_registration_socket={:?}\nbridge_core_socket={:?}\nbridge_credential_file={:?}\nbridge_producer_id=\"fixture\"\nbridge_audience=\"fixture\"\nbridge_server_executable=\"/fixture/bridge\"\nbridge_server_sha256=\"{}\"\nowner_observer_credential_file={token:?}\n",path.join("must-not-open.db"),std::fs::metadata(path).unwrap().uid(),path.join("absent-register.sock"),path.join("absent-core.sock"),path.join("absent-bridge.token"),"0".repeat(64))).unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        let resident = async {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let mut line = String::new();
            stream.read_line(&mut line).await.unwrap();
            let request: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(request["observer_credential"], "fixture-only-observer");
            assert_eq!(request["observe"]["operation"], "managed_capacity");
            let gauge = serde_json::json!({"active":0,"retained":3,"reserved":0,"limit":100000,"headroom":100000});
            let data = serde_json::json!({"namespaces":gauge,"bootstraps":gauge,"contexts":gauge,"intents":gauge,"current_requests":gauge,"bootstrap_reservations":0,"contexts_without_intent":0});
            let response = serde_json::json!({"schema_version":1,"kind":"managed_capacity","data":data});
            stream.write_all(format!("{response}\n").as_bytes()).await.unwrap();
        };
        let run = async {
            tokio::process::Command::new(env!("CARGO_BIN_EXE_agent-pool"))
                .args(["doctor","--json","--config"]).arg(&config)
                .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped())
                .output().await.unwrap()
        };
        let (_, output) = tokio::join!(resident, run);
        assert!(output.status.success());
        assert!(output.stderr.is_empty());
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["managed_capacity"]["intents"]["retained"], 3);
        assert_eq!(report["managed_capacity"]["intents"]["headroom"], 100000);
        assert!(!output.stdout.windows(b"fixture-only-observer".len()).any(|bytes| bytes == b"fixture-only-observer"));
    }).await.expect("doctor fixture deadline");
    assert!(!path.join("must-not-open.db").exists());
}
