//! Process coverage for the hook's host-safe exit behavior.
use serde_json::json;
use std::{process::Stdio, time::Duration};
use tokio::{io::AsyncWriteExt, process::Command};

/// A bad payload, connection failure and bad hook arguments all preserve the turn.
#[tokio::test]
async fn owner_hook_failures_exit_zero() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let no_socket = directory.path().join("missing.sock");
    let receipt = json!({
        "hook_event_name":"PostToolUse",
        "tool_name":"mcp__agent-pool__pool_start",
        "session_id":"private-session-canary",
        "tool_response":{"pool_id":"00000000-0000-4000-8000-000000000001"}
    })
    .to_string();
    for (socket, payload) in [
        (Some(&no_socket), "private-input-canary".as_bytes()),
        (Some(&no_socket), receipt.as_bytes()),
        (None, b""),
    ] {
        let mut cli = Command::new(env!("CARGO_BIN_EXE_agent-pool"));
        cli.args(["hook", "bind"]);
        if let Some(path) = socket {
            cli.args(["--server-uid", "1003", "--owner-socket"])
                .arg(path);
        }
        let mut child = cli
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let mut stdin = child.stdin.take().ok_or("hook stdin")?;
        stdin.write_all(payload).await?;
        drop(stdin);
        let output =
            tokio::time::timeout(Duration::from_secs(5), child.wait_with_output()).await??;
        assert!(output.status.success());
        assert!(output.stdout.is_empty());
        let note = std::str::from_utf8(&output.stderr)?;
        assert!(note.starts_with("agent-pool: "));
        assert!(!note.contains("canary"));
    }
    Ok(())
}

/// An input pipe whose writer stays open cannot hold the host turn indefinitely.
#[tokio::test]
async fn owner_hook_times_out_with_open_stdin() -> Result<(), Box<dyn std::error::Error>> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_agent-pool"))
        .args([
            "hook",
            "bind",
            "--owner-socket",
            "/nonexistent/owner.sock",
            "--server-uid",
            "1003",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let stdin = child.stdin.take().ok_or("hook stdin")?;
    let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output()).await??;
    drop(stdin);
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"agent-pool: owner binding timed out\n");
    Ok(())
}
