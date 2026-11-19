//! Pool chat v1 command catalog, wire adapters and compact typed replies.
use crate::{
    completion,
    config::Config,
    domain::{Command, Create, Fault, Reply},
    integrations::{self, EXCHANGE_TIMEOUT},
    response::Templates,
    runtime::{SharedStore, stored},
    store::chat as state,
};
use rmcp::model::{CallToolResult, ContentBlock};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Map, Value, json};
use std::path::Path;
use tokio::{io::AsyncWriteExt, net::UnixStream};

const VERSION: u32 = 1;
const MEMBER_TOOLS: [&str; 7] = [
    "pool_join",
    "pool_get",
    "pool_post",
    "pool_send_member",
    "pool_notify_owner",
    "pool_propose",
    "pool_vote",
];
const OWNER_TOOLS: [&str; 8] = [
    "pool_start",
    "pool_list",
    "pool_get",
    "pool_post",
    "pool_send_member",
    "pool_replace",
    "pool_close",
    "pool_completion_get",
];

/// Owner start creates one ordered ordinary Run batch.
#[derive(Serialize, Deserialize)]
pub(crate) struct Start {
    #[serde(flatten)]
    pub create: Create,
    pub members: Vec<StartMember>,
    pub owner_address: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StartMember {
    pub assignment: String,
    pub spec: Value,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ReplaceSeat {
    #[serde(flatten)]
    pub change: crate::domain::Change,
    pub member_id: String,
    pub member: StartMember,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListPools {
    pub after: Option<String>,
    pub state: Option<PoolState>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PoolState {
    Open,
    Completed,
    Closed,
}

impl PoolState {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Completed => "completed",
            Self::Closed => "closed",
        }
    }
}

#[derive(Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ChatSection {
    #[default]
    Overview,
    History,
    Members,
    Proposal,
    Votes,
    Criteria,
    Content,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GetPool {
    pub pool_id: String,
    #[serde(default)]
    pub section: ChatSection,
    pub after: Option<String>,
    pub field: Option<crate::domain::ContentField>,
    pub expected_revision: Option<u64>,
}

fn header() -> completion::Section {
    completion::Section::Header
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompletionGet {
    pub pool_id: String,
    pub completion_id: Option<String>,
    #[serde(default = "header")]
    pub section: completion::Section,
    pub after: Option<completion::Cursor>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MemberCall {
    version: u32,
    pub run_store_id: String,
    pub agent_id: String,
    sequence: u32,
    pub pool_id: String,
    pub seat_id: String,
    pub tool: String,
    pub arguments: Map<String, Value>,
    pub request_id: String,
}

#[derive(Clone, Copy)]
pub(crate) enum ChatActor<'a> {
    Owner,
    Member(&'a str),
}

#[derive(Debug)]
pub(crate) enum ChatError {
    NotMember,
    SeatRetired,
    PoolClosed,
    AdmissionPending,
    Fault(Fault),
}

impl From<Fault> for ChatError {
    fn from(fault: Fault) -> Self {
        Self::Fault(fault)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Agreement {
    pub version: u32,
    pub completion_id: String,
    pub pool_id: String,
    pub revision: u64,
    pub event_id: String,
    pub proposal_id: String,
    pub roster_key: String,
    pub result: String,
    pub ballots: Vec<AgreementBallot>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct AgreementBallot {
    pub seat_id: String,
    pub agent_id: String,
    pub vote_event_id: String,
}

#[derive(Serialize)]
pub(crate) struct Overview {
    /// Durable state of the latest launch or replacement, including after closure.
    pub latest_admission: Option<String>,
    pub pool_id: String,
    pub name: String,
    pub purpose: String,
    pub revision: u64,
    pub state: &'static str,
    pub roster: Vec<SeatRow>,
    pub seat_count: usize,
    pub ready: usize,
    pub blocked: usize,
    pub completion: Option<String>,
    pub proposal: Option<ProposalRow>,
    pub acceptance: bool,
}

#[derive(Serialize)]
pub(crate) struct SeatRow {
    pub seat_id: String,
    pub profile: String,
    pub assignment: String,
    #[serde(skip)]
    pub run_store_id: Option<String>,
    pub sequence: Option<u64>,
    pub agent_id: Option<String>,
    pub admitted: String,
    pub joined: bool,
    pub process: String,
}

#[derive(Serialize)]
pub(crate) struct ProposalRow {
    pub id: String,
    pub roster_key: String,
    pub state: crate::domain::ProposalState,
}

#[derive(Serialize)]
pub(crate) struct ChatEvent {
    pub id: String,
    pub kind: String,
    pub author: String,
    pub recipient: Option<String>,
    pub body: String,
    pub message_event_id: Option<String>,
    pub part_index: Option<usize>,
    pub part_count: Option<usize>,
}

#[derive(Serialize)]
pub(crate) struct PoolRow {
    pub id: String,
    pub name: String,
    pub status: &'static str,
    pub completion: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct LaunchSeat {
    pub id: String,
    pub current: bool,
    pub joined: bool,
    pub agent_id: Option<String>,
}

#[derive(Serialize)]
#[serde(tag = "view", rename_all = "snake_case")]
pub(crate) enum ChatReply {
    #[serde(skip)]
    Existing(Reply),
    Overview(Overview),
    History {
        pool_id: String,
        revision: u64,
        events: Vec<ChatEvent>,
        more: bool,
        next: String,
    },
    List {
        pools: Vec<PoolRow>,
        returned: usize,
        next: Option<String>,
    },
    Launch {
        pool_id: String,
        revision: u64,
        state: String,
        request_key: String,
        seats: Vec<LaunchSeat>,
        old_agent_id: Option<String>,
    },
    Agreement(Agreement),
    Legacy(Box<completion::Page>),
}

/// Decodes a bounded endpoint payload without exposing deserializer diagnostics.
pub(crate) fn parse<T: DeserializeOwned>(value: Value) -> Result<T, Fault> {
    serde_json::from_value(value).map_err(|_| Fault::Invalid)
}

/// Uses the existing closed domain schemas and validators for shared chat mutations.
pub(crate) fn command(name: &str, args: Value) -> Result<Command, Fault> {
    let command: Command = parse(json!({"name":name,"arguments":args}))?;
    command.validate()?;
    Ok(command)
}

/// Returns the exact group owner catalog.
pub(crate) fn owner_tools() -> Vec<Value> {
    crate::tools::chat_definitions(&OWNER_TOOLS, false)
}

/// Initializes and shares embedded layouts before accepting chat mutations.
pub(crate) fn renderer() -> Result<&'static Templates, Fault> {
    static TEMPLATES: std::sync::OnceLock<Result<Templates, Fault>> = std::sync::OnceLock::new();
    TEMPLATES
        .get_or_init(|| {
            let mut entries = crate::tools::templates();
            entries.push(("chat", include_str!("templates/chat.j2")));
            Templates::new(&entries).map_err(|_| Fault::Internal)
        })
        .as_ref()
        .map_err(|fault| *fault)
}

fn text_reply(text: String, error: bool) -> CallToolResult {
    let mut reply = CallToolResult::success(vec![ContentBlock::text(text)]);
    reply.is_error = Some(error);
    reply
}

fn present(result: Result<ChatReply, Fault>, templates: &Templates) -> CallToolResult {
    match result {
        Ok(ChatReply::Existing(reply)) => crate::tools::present(Ok(reply), templates),
        Ok(reply) => {
            let is_error = matches!(&reply, ChatReply::Launch { state, .. } if matches!(state.as_str(), "refused" | "cancelled" | "not_launched"));
            let text = templates.render("chat", &reply).unwrap_or_else(|_| match &reply {
                ChatReply::Launch { pool_id, revision, state, request_key, old_agent_id, .. } => format!("Pool {pool_id} revision={revision} admission={state}. Request key {request_key}. Read pool_get for current admission. Prior Run ID: {old_agent_id:?}"),
                _ => "READ COMPLETED; presentation degraded. Repeat the read with the same cursor.".into(),
            });
            text_reply(text, is_error)
        }
        Err(fault) => crate::tools::present(Err(fault), templates),
    }
}

/// Selects the versioned private methods without giving them access to legacy mutation routes.
pub(crate) fn private_method(value: &Value) -> bool {
    matches!(
        value.get("method").and_then(Value::as_str),
        Some("chat_catalog_v1" | "member_call_v1")
    )
}

/// Reports a typed membership refusal without constructing an MCP tool result.
fn membership_refusal(id: Value, kind: &str, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":message,"data":{"kind":kind}}})
}

/// Serves Run's same-UID JSON-RPC catalog or member call.
pub(crate) async fn private_call(
    value: Value,
    config: &Config,
    store: &SharedStore,
    templates: &Templates,
) -> Value {
    let id = value.get("id").cloned().unwrap_or(Value::Null);
    let params = value.get("params").cloned().unwrap_or(Value::Null);
    let invalid = || json!({"jsonrpc":"2.0","id":id,"error":{"code":-32602,"message":"Invalid chat v1 parameters"}});
    if value
        .get("jsonrpc")
        .and_then(Value::as_str)
        .is_some_and(|v| v != "2.0")
        || params.get("version").and_then(Value::as_u64) != Some(u64::from(VERSION))
    {
        return invalid();
    }
    let result = if value["method"] == "chat_catalog_v1" {
        let tools: Vec<_> = crate::tools::chat_definitions(&MEMBER_TOOLS, true).into_iter().map(|tool| {
            json!({"name":tool["name"],"description":tool["description"],"inputSchema":tool["inputSchema"]})
        }).collect();
        json!({"version":VERSION,"tools":tools})
    } else {
        let Ok(call) = parse::<MemberCall>(params) else {
            return invalid();
        };
        if call.version != VERSION
            || call.sequence == 0
            || crate::domain::store_id(&call.run_store_id).is_err()
            || !crate::run_status::valid_agent_id(&call.agent_id)
            || [&call.seat_id, &call.pool_id, &call.request_id]
                .iter()
                .any(|id| crate::domain::identifier(id).is_err())
            || !MEMBER_TOOLS.contains(&call.tool.as_str())
        {
            return invalid();
        }
        let result = stored(store, move |store| Ok(state::member(store, call))).await;
        let result = match result {
            Ok(Ok(mut reply)) => {
                observe_overview(config, &mut reply).await;
                Ok(reply)
            }
            Ok(Err(ChatError::Fault(fault))) if fault != Fault::Internal => Err(fault),
            Ok(Err(ChatError::NotMember)) => {
                return membership_refusal(
                    id,
                    "not_member",
                    "The Run lineage does not own this seat.",
                );
            }
            Ok(Err(ChatError::SeatRetired)) => {
                return membership_refusal(id, "seat_retired", "This seat has been retired.");
            }
            Ok(Err(ChatError::PoolClosed)) => {
                return membership_refusal(id, "pool_closed", "This pool has been closed.");
            }
            Ok(Err(ChatError::AdmissionPending)) => {
                return json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":"Seat admission is pending. Retry after Run admission is recorded.","data":{"kind":"admission_pending","retry_after_ms":1000}}});
            }
            Ok(Err(ChatError::Fault(_))) | Err(_) => {
                return json!({"jsonrpc":"2.0","id":id,"error":{"code":-32603,"message":"Pool chat could not complete the relay."}});
            }
        };
        let reply = present(result, templates);
        json!({"version":VERSION,"content":reply.content,"is_error":reply.is_error.unwrap_or(false)})
    };
    json!({"jsonrpc":"2.0","id":id,"result":result})
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerRequest {
    tool: String,
    arguments: Value,
}

/// Executes one request from a kernel-allowlisted owner connection.
pub(crate) async fn owner_connection(
    mut stream: UnixStream,
    config: Config,
    store: SharedStore,
    templates: &Templates,
) -> Result<(), Fault> {
    let bytes = tokio::time::timeout(EXCHANGE_TIMEOUT, integrations::read_frame(&mut stream))
        .await
        .map_err(|_| Fault::Unavailable)??;
    let result = match crate::managed_codec::parse_raw(&bytes).and_then(parse::<OwnerRequest>) {
        Ok(request) if OWNER_TOOLS.contains(&request.tool.as_str()) => {
            owner_call(request, &config, &store).await
        }
        _ => Err(Fault::Invalid),
    };
    write(&mut stream, &present(result, templates)).await
}

async fn owner_call(
    request: OwnerRequest,
    config: &Config,
    store: &SharedStore,
) -> Result<ChatReply, Fault> {
    let mut reply = match request.tool.as_str() {
        "pool_start" | "pool_replace" => {
            let batch = stored(store, move |store| {
                if request.tool == "pool_start" {
                    state::start(store, parse(request.arguments)?)
                } else {
                    state::replace(store, parse(request.arguments)?)
                }
            })
            .await?;
            stored(store, move |store| state::launch_read(store, &batch)).await?
        }
        _ => {
            stored(store, move |store| {
                state::owner_call(store, &request.tool, request.arguments)
            })
            .await?
        }
    };
    observe_overview(config, &mut reply).await;
    Ok(reply)
}

/// Advances one batch per resident tick, rotating past unavailable Run work.
pub(crate) async fn reconcile(
    config: &Config,
    store: &SharedStore,
    cursor: &mut String,
) -> Result<(), Fault> {
    if config.run_socket.is_none() {
        return Ok(());
    }
    let after = cursor.clone();
    let Some(mut batch) = stored(store, move |store| state::next_batch(store, &after)).await?
    else {
        cursor.clear();
        return Ok(());
    };
    cursor.clone_from(&batch.id);
    let run_store = if let Some(identity) = &batch.run_store {
        identity.clone()
    } else {
        let Ok(identity) = integrations::run_store_identity(config).await else {
            return Ok(());
        };
        identity
    };
    // Reload under the store lock so close during identity discovery wins.
    let (id, identity) = (batch.id.clone(), run_store.clone());
    batch = stored(store, move |store| state::fence(store, &id, &identity)).await?;
    if batch.state != "pending" {
        return Ok(());
    }
    let fence = batch.run_store.as_deref();
    let rows = if batch.closed {
        match integrations::batch_receipt(config, &batch.id, &batch.jobs, false, fence).await {
            Ok(Some(rows)) => rows,
            Ok(None) | Err(_) => {
                return stored(store, move |store| state::defer_receipt(store, &batch.id)).await;
            }
        }
    } else {
        match integrations::start_batch(config, &batch.id, &batch.jobs, false, fence).await {
            Ok(rows) => rows,
            Err(failure) if failure.known_unadmitted => {
                return stored(store, move |store| {
                    state::settle_batch(store, &batch.id, "refused")
                })
                .await;
            }
            Err(_) => return Ok(()),
        }
    };
    stored(store, move |store| state::admitted(store, &batch, rows)).await
}

/// Adds best-effort Run process observations without making Pool reads depend on Run.
async fn observe_overview(config: &Config, reply: &mut ChatReply) {
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        process_state(config, reply),
    )
    .await;
}

async fn process_state(config: &Config, reply: &mut ChatReply) {
    let ChatReply::Overview(overview) = reply else {
        return;
    };
    if !overview.roster.iter().any(|seat| seat.agent_id.is_some()) {
        return;
    }
    let Ok(run_store) = integrations::run_store_identity(config).await else {
        return;
    };
    let mut observations = tokio::task::JoinSet::new();
    for (index, seat) in overview.roster.iter().enumerate() {
        if let Some(agent) = &seat.agent_id
            && seat.run_store_id.as_deref() == Some(&run_store)
        {
            let (agent, config) = (agent.clone(), config.clone());
            observations.spawn(async move {
                (
                    index,
                    integrations::observe_run(&config, &agent, None).await,
                )
            });
        }
    }
    while let Some(result) = observations.join_next().await {
        if let Ok((index, Ok(observation))) = result {
            overview.roster[index].process = observation.runtime;
            overview.roster[index].sequence = Some(observation.sequence);
        }
    }
}

async fn write(stream: &mut UnixStream, value: &impl Serialize) -> Result<(), Fault> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| Fault::Internal)?;
    if bytes.len() >= integrations::MAX_FRAME {
        return Err(Fault::Internal);
    }
    bytes.push(b'\n');
    tokio::time::timeout(EXCHANGE_TIMEOUT, stream.write_all(&bytes))
        .await
        .map_err(|_| Fault::Unavailable)?
        .map_err(|_| Fault::Unavailable)
}

/// Connects the owner MCP to the expected resident and forwards exactly one owner command.
pub(crate) async fn frontend(
    path: &Path,
    uid: u32,
    tool: String,
    arguments: Value,
) -> Result<CallToolResult, Fault> {
    #[cfg(target_os = "linux")]
    {
        tokio::time::timeout(EXCHANGE_TIMEOUT * 5, async {
            crate::config::identity_uid_map()?;
            let before = crate::config::shared_run_socket(path, uid)?;
            let mut stream = UnixStream::connect(path)
                .await
                .map_err(|_| Fault::Unavailable)?;
            if stream.peer_cred().map_err(|_| Fault::Unauthorized)?.uid() != uid
                || crate::config::shared_run_socket(path, uid)? != before
            {
                return Err(Fault::Unauthorized);
            }
            write(&mut stream, &OwnerRequest { tool, arguments }).await?;
            let bytes = integrations::read_frame(&mut stream).await?;
            if let Ok(reply) = serde_json::from_slice::<CallToolResult>(&bytes) {
                return Ok(reply);
            }
            let envelope: crate::observer::Envelope =
                serde_json::from_slice(&bytes).map_err(|_| Fault::Unavailable)?;
            Err(envelope
                .error
                .map_or(Fault::Unavailable, |error| error.code))
        })
        .await
        .map_err(|_| Fault::Unavailable)?
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, uid, tool, arguments);
        Err(Fault::Unavailable)
    }
}

/// Resolves a member's current native destination, fenced to its Run store.
pub(crate) async fn notice_address(
    config: &Config,
    binding: &crate::domain::Binding,
) -> Option<String> {
    let agent = binding.run_id.as_deref()?;
    let store = binding.run_store_id.as_deref()?;
    if integrations::run_store_identity(config)
        .await
        .ok()?
        .as_str()
        != store
    {
        return None;
    }
    let address = integrations::observe_run(config, agent, None)
        .await
        .ok()?
        .address?;
    if integrations::run_store_identity(config)
        .await
        .ok()?
        .as_str()
        != store
    {
        return None;
    }
    Some(address)
}

#[cfg(all(test, target_os = "linux"))]
#[path = "chat_tests.rs"]
mod tests;
