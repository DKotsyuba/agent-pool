//! Version and tool discovery across the existing authenticated resident sockets.
use crate::{config::Config, domain::Fault, integrations};
use rmcp::model::Tool;
use serde::Deserialize;
use std::{path::Path, time::Duration};
use tokio::{io::AsyncWriteExt, net::UnixStream};

/// Private read-only request shared by both frontend ingress modes.
pub(crate) const METHOD: &str = "pool_service_catalog_v1";
/// Version compiled into this executable.
pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Catalog and version come from the same resident connection.
#[derive(Deserialize)]
pub(crate) struct Catalog {
    pub(crate) version: String,
    pub(crate) tools: Vec<Tool>,
}

/// Advertises the exact tool surface of the ingress handling the probe.
pub(crate) fn reply(owner: bool) -> serde_json::Value {
    let tools = if owner {
        crate::chat::owner_tools()
    } else {
        crate::tools::definitions()
    };
    serde_json::json!({"version": VERSION, "tools": tools})
}

/// Reads discovery from the configured resident without registering a native invocation.
pub(crate) async fn probe(
    config: Option<&Path>,
    owner: Option<(&Path, u32)>,
) -> Result<Catalog, Fault> {
    let Some((path, uid)) = owner else {
        let config = config.ok_or(Fault::Unavailable)?.to_owned();
        let config = tokio::task::spawn_blocking(move || Config::load(&config))
            .await
            .map_err(|_| Fault::Unavailable)??;
        integrations::own_uid(config.expected_uid)?;
        return tokio::time::timeout(Duration::from_secs(2), async {
            let mut stream =
                integrations::connect(&config.socket_path, config.expected_uid).await?;
            exchange(&mut stream, false).await
        })
        .await
        .map_err(|_| Fault::Unavailable)?;
    };
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut stream = crate::chat::connect_owner(path, uid).await?;
        exchange(&mut stream, true).await
    })
    .await
    .map_err(|_| Fault::Unavailable)?
}

/// Sends a bounded discovery frame and validates discovery from the authenticated peer.
async fn exchange(stream: &mut UnixStream, owner: bool) -> Result<Catalog, Fault> {
    let request = if owner {
        serde_json::json!({"tool": METHOD, "arguments": {}})
    } else {
        serde_json::json!({"method": METHOD})
    };
    let frame = format!("{request}\n");
    stream
        .write_all(frame.as_bytes())
        .await
        .map_err(|_| Fault::Unavailable)?;
    let bytes = integrations::read_frame(stream).await?;
    let catalog: Catalog = serde_json::from_slice(&bytes).map_err(|_| Fault::Unavailable)?;
    if catalog.version.is_empty()
        || catalog.version.len() > 128
        || !catalog
            .version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".+-".contains(&byte))
    {
        return Err(Fault::Unavailable);
    }
    Ok(catalog)
}

/// Shared recovery text for tool calls and installer checks.
pub(crate) fn reconnect(version: &str) -> String {
    format!(
        "agent-pool service is {version}, this MCP frontend is {VERSION}: reconnect the agent-pool MCP server (Claude Code: /mcp → reconnect; Codex: restart the session)"
    )
}
