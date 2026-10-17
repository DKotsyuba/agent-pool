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
    std::fs::write(&config,format!("socket_path={:?}\ndatabase_path={:?}\nexpected_uid={}\nbridge_registration_socket={:?}\nbridge_core_socket={:?}\nbridge_credential_file={:?}\nbridge_producer_id=\"pool-fixture\"\nbridge_audience=\"pool-backend-fixture\"\n",root.path().join("pool.sock"),root.path().join("pool.db"),std::fs::metadata(root.path()).unwrap().uid(),adapter_path,core_path,token)).unwrap();
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
