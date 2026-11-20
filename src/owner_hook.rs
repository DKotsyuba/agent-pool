//! Bounded PostToolUse adapter for the Crew-managed owner MCP session.
use crate::{
    chat::{self, BindOwner, OwnerHarness},
    domain::Fault,
    integrations::MAX_FRAME,
};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    io::{Read, Write},
    path::PathBuf,
    time::Duration,
};

/// Leaves time for startup and exit within the host's five-second budget.
const BUDGET: Duration = Duration::from_secs(4);

/// Session lifecycle hooks exposed by the Pool binary.
#[derive(clap::Subcommand)]
pub(crate) enum HookCommand {
    /// Bind the pool from a native PostToolUse payload on stdin.
    Bind {
        /// Group owner ingress socket.
        #[arg(long)]
        owner_socket: PathBuf,
        /// Required kernel UID of the resident.
        #[arg(long)]
        server_uid: u32,
        /// Harness that emitted the native hook.
        #[arg(long, value_enum, default_value = "codex")]
        harness: OwnerHarness,
    },
}

/// Writes a short diagnostic without echoing the hook input or service reply.
pub(crate) fn note(message: &str) {
    let _ = writeln!(std::io::stderr(), "agent-pool: {message}");
}

/// Reads and submits one binding under a shared deadline. Process exit cancels a stalled stdin read.
pub(crate) async fn run(
    HookCommand::Bind {
        owner_socket,
        server_uid,
        harness,
    }: HookCommand,
) {
    let operation = async {
        let (send, receive) = tokio::sync::oneshot::channel();
        // Tokio's blocking stdin would keep the runtime alive after timeout.
        std::thread::Builder::new()
            .spawn(move || {
                let mut bytes = Vec::new();
                let result = std::io::stdin()
                    .take((MAX_FRAME + 1) as u64)
                    .read_to_end(&mut bytes);
                let _ = send.send(result.map(|_| bytes));
            })
            .map_err(|_| "cannot read hook input")?;
        let bytes = receive
            .await
            .map_err(|_| "cannot read hook input")?
            .map_err(|_| "cannot read hook input")?;
        let binding = decode(&bytes, harness).map_err(|_| "unusable pool_start hook receipt")?;
        let arguments = serde_json::to_value(binding).map_err(|_| "cannot encode owner binding")?;
        let reply = chat::frontend(
            &owner_socket,
            server_uid,
            chat::BIND_OWNER.into(),
            arguments,
        )
        .await
        .map_err(|_| "owner binding could not be confirmed")?;
        if reply.is_error == Some(true) {
            return Err("resident refused owner binding");
        }
        Ok(())
    };
    match tokio::time::timeout(BUDGET, operation).await {
        Ok(Ok(())) => {}
        Ok(Err(message)) => note(message),
        Err(_) => note("owner binding timed out"),
    }
}

/// Reads one exact pool identity from a successful native pool_start receipt.
fn decode(bytes: &[u8], harness: OwnerHarness) -> Result<BindOwner, Fault> {
    if bytes.len() > MAX_FRAME {
        return Err(Fault::Invalid);
    }
    let event = crate::managed_codec::parse_raw(bytes)?;
    if event["hook_event_name"].as_str() != Some("PostToolUse")
        || !matches!(
            event["tool_name"].as_str(),
            Some("mcp__agent-pool__pool_start" | "mcp__agent_pool__pool_start")
        )
    {
        return Err(Fault::Invalid);
    }
    let session_id = event["session_id"]
        .as_str()
        .filter(|id| !id.trim().is_empty())
        .ok_or(Fault::Invalid)?;
    let mut ids = BTreeSet::new();
    receipt_ids(&event["tool_response"], &mut ids, 0)?;
    if ids.len() != 1 {
        return Err(Fault::Invalid);
    }
    Ok(BindOwner {
        pool_id: ids.pop_first().ok_or(Fault::Invalid)?,
        harness,
        session_id: session_id.into(),
    })
}

/// Inspects known MCP envelope fields and the launch receipt header, leaving other text opaque.
fn receipt_ids(value: &Value, ids: &mut BTreeSet<String>, depth: usize) -> Result<(), Fault> {
    if depth > 12
        || ["isError", "is_error"].iter().any(|key| {
            value
                .get(*key)
                .is_some_and(|flag| flag.as_bool() != Some(false))
        })
    {
        return Err(Fault::Invalid);
    }
    match value {
        Value::Object(object) => {
            if let Some(id) = object.get("pool_id") {
                insert_id(id.as_str().ok_or(Fault::Invalid)?, ids)?;
            }
            for key in ["content", "text", "result", "structuredContent"] {
                if let Some(child) = object.get(key) {
                    receipt_ids(child, ids, depth + 1)?;
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                receipt_ids(item, ids, depth + 1)?;
            }
        }
        Value::String(text) => {
            if let Some((id, _)) = text
                .trim_start()
                .strip_prefix("Pool ")
                .and_then(|text| text.split_once(" revision="))
            {
                insert_id(id, ids)?;
            } else if serde_json::from_str::<&serde_json::value::RawValue>(text).is_ok() {
                let decoded = crate::managed_codec::parse_raw(text.as_bytes())?;
                receipt_ids(&decoded, ids, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Accepts the canonical UUID emitted by Pool's durable create path.
fn insert_id(id: &str, ids: &mut BTreeSet<String>) -> Result<(), Fault> {
    let uuid = uuid::Uuid::parse_str(id).map_err(|_| Fault::Invalid)?;
    if uuid.to_string() != id {
        return Err(Fault::Invalid);
    }
    ids.insert(id.into());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Checks Claude's text blocks and Codex's encoded result against Pool's launch header.
    #[test]
    fn owner_hook_decodes_native_receipts() -> Result<(), Fault> {
        let pool = crate::domain::id();
        let content = json!([{"type":"text","text":format!(
            "Pool {pool} revision=1 admission=pending. Request key start"
        )}]);
        for (harness, tool, response) in [
            (
                OwnerHarness::ClaudeCode,
                "mcp__agent-pool__pool_start",
                content.clone(),
            ),
            (
                OwnerHarness::Codex,
                "mcp__agent-pool__pool_start",
                json!({"content":content,"isError":false}),
            ),
            (
                OwnerHarness::Codex,
                "mcp__agent_pool__pool_start",
                Value::String(json!({"result":{"content":content,"isError":false}}).to_string()),
            ),
            (
                OwnerHarness::Codex,
                "mcp__agent-pool__pool_start",
                json!({"pool_id":pool}),
            ),
        ] {
            let event = json!({"hook_event_name":"PostToolUse","session_id":"caller",
                "tool_name":tool,"tool_response":response,"tool_input":{"pool_id":"ignore"}});
            let binding = decode(event.to_string().as_bytes(), harness)?;
            assert_eq!(binding.pool_id, pool);
            assert_eq!(binding.session_id, "caller");
            assert_eq!(binding.harness.as_str(), harness.as_str());
        }
        Ok(())
    }

    /// Failed receipts, other tools and conflicting identities cannot bind a session.
    #[test]
    fn owner_hook_refuses_unusable_receipts() {
        let pool = crate::domain::id();
        let mut event = json!({"hook_event_name":"PostToolUse","session_id":"caller",
            "tool_name":"mcp__agent-pool__pool_start","tool_response":{"pool_id":pool}});
        let invalid = |event: &Value| {
            assert!(matches!(
                decode(event.to_string().as_bytes(), OwnerHarness::Codex),
                Err(Fault::Invalid)
            ));
        };
        event["tool_response"]["isError"] = json!(true);
        invalid(&event);
        event["tool_response"]["isError"] = json!("false");
        invalid(&event);
        event["tool_response"] = json!(format!(
            r#"{{"pool_id":"{pool}","isError":true,"isError":false}}"#
        ));
        invalid(&event);
        event["tool_response"] = json!([{"pool_id":pool},{"pool_id":crate::domain::id()}]);
        invalid(&event);
        event["tool_response"] = json!({"pool_id":pool});
        event["tool_name"] = json!("mcp__agent-pool__pool_get");
        invalid(&event);
    }
}
