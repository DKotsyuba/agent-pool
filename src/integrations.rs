//! Bounded public Bridge/Run clients; native assertions are the only caller authority.
use crate::{
    config::{Config, private_socket},
    domain::{Actor, Effect, Fault, Work, id},
};
use bridge_sdk::{Client, bridge_protocol::*};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

/// One finite exchange budget; expiry after a write never means no remote effect.
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum JSON-RPC or resident frame excluding its final newline.
pub const MAX_FRAME: usize = 1_048_576;
/// Unused per-call return routes expire promptly; this does not impose a pool or agent lifetime.
const REGISTRATION_ROUTE_TTL_MS: u64 = 60_000;

/// Short-lived protected transfer from an actual MCP invocation to the resident.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assertion {
    /// Issuer-generated secret; never logged or accepted as domain identity itself.
    pub assertion_key: Secret,
    /// Fresh frontend RPC identity required again by the consuming backend.
    pub invocation_key: String,
}

/// Builds the explicit synchronous SDK after validating both private socket paths.
/// Credentials are re-read only from the configured protected file, never from arguments.
fn bridge(config: &Config, observation: bool) -> Result<Client, Fault> {
    let (registration, credential) = if observation {
        (
            config
                .bridge_observer_socket
                .as_ref()
                .ok_or(Fault::Unavailable)?,
            config
                .bridge_observer_credential_file
                .as_ref()
                .ok_or(Fault::Unavailable)?,
        )
    } else {
        (
            &config.bridge_registration_socket,
            &config.bridge_credential_file,
        )
    };
    private_socket(registration, config.expected_uid)?;
    private_socket(&config.bridge_core_socket, config.expected_uid)?;
    let sdk = bridge_sdk::Config::new(
        registration,
        &config.bridge_core_socket,
        Secret::new(config.credential(credential)?),
        EXCHANGE_TIMEOUT,
    )
    .map_err(|_| Fault::Unavailable)?;
    Client::new(sdk).map_err(|_| Fault::Unavailable)
}

/// Registers original framework metadata in this actual harness-launched process.
/// Metadata only selects a candidate host; the SDK/native adapter authenticates it.
/// Historical registration, shared destinations and missing assertions are rejected.
pub async fn register(config: Config, original_meta: Value) -> Result<Assertion, Fault> {
    tokio::task::spawn_blocking(move || {
        let host = if original_meta.get("threadId").is_some() {
            Host::Codex
        } else if original_meta.get("claudecode/toolUseId").is_some() {
            Host::ClaudeCode
        } else if original_meta.get("ai.opencode/sessionID").is_some() {
            Host::OpenCode
        } else {
            return Err(Fault::Unauthorized);
        };
        let evidence = bridge_sdk::extract_native_evidence(host, &original_meta)
            .map_err(|_| Fault::Unauthorized)?;
        let request_id = id();
        let operation_key = id();
        let invocation_key = id();
        let route_expires_at_ms = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Fault::Unavailable)?
                .as_millis(),
        )
        .map_err(|_| Fault::Unavailable)?
        .checked_add(REGISTRATION_ROUTE_TTL_MS)
        .ok_or(Fault::Unavailable)?;
        let result = bridge(&config, false)?
            .register_call(
                request_id.clone(),
                RegisterCallParams {
                    operation_key: operation_key.clone(),
                    evidence: Some(evidence),
                    reply_policy: ReplyPolicy::SelfActor,
                    allowed_modes: None,
                    allowed_kinds: None,
                    max_payload_bytes: None,
                    route_expires_at_ms: Some(route_expires_at_ms),
                    assertion_audience: Some(config.bridge_audience.clone()),
                    invocation_key: Some(invocation_key.clone()),
                },
            )
            .map_err(|_| Fault::Unauthorized)?;
        if result.evidence_state != CallerEvidenceState::FreshAssertionAvailable
            || result.receipt.producer != config.bridge_producer_id
            || result.receipt.request_id != request_id
            || result.receipt.operation_key != operation_key
            || result.receipt.reply_policy != ReplyPolicy::SelfActor
        {
            return Err(Fault::Unauthorized);
        }
        let assertion = result.assertion.ok_or(Fault::Unauthorized)?;
        if assertion.audience != config.bridge_audience
            || assertion.invocation_key != invocation_key
        {
            return Err(Fault::Unauthorized);
        }
        Ok(Assertion {
            assertion_key: assertion.assertion_key,
            invocation_key,
        })
    })
    .await
    .map_err(|_| Fault::Internal)?
}

/// Consumes the exact forwarded assertion and requires current producer/audience/invocation facts.
/// Historical receipts never authorize reads, mutations or idempotent domain replays.
pub async fn consume(config: Config, assertion: Assertion) -> Result<Actor, Fault> {
    tokio::task::spawn_blocking(move || {
        let request_id = id();
        let result = bridge(&config, false)?
            .consume_assertion(
                request_id.clone(),
                ConsumeAssertionParams {
                    assertion_key: assertion.assertion_key,
                    invocation_key: assertion.invocation_key.clone(),
                },
            )
            .map_err(|_| Fault::Unauthorized)?;
        verified_actor(&config, &assertion.invocation_key, &request_id, result)
    })
    .await
    .map_err(|_| Fault::Internal)?
}

/// Applies Pool's authority fence to a validated SDK result; only Current can produce an Actor.
fn verified_actor(
    config: &Config,
    invocation_key: &str,
    request_id: &str,
    result: ConsumeResult,
) -> Result<Actor, Fault> {
    let context = result.receipt.context;
    if result.state != InvocationValidity::Current
        || result.receipt.producer != config.bridge_producer_id
        || result.receipt.request_id != request_id
        || context.audience != config.bridge_audience
        || context.invocation_key != invocation_key
        || context.caller_address != context.destination_address
        || !NativeAddress::parse(&context.caller_address).is_ok_and(|address| {
            address.canonical() == context.caller_address
                && (context.role != ActorRole::Child || context.native_actor_id == address.session)
        })
    {
        return Err(Fault::Unauthorized);
    }
    Actor::verified(
        context.caller_address,
        &context.native_actor_id,
        match context.role {
            ActorRole::Root => "root",
            ActorRole::Child => "child",
        },
    )
}

/// Creates the complete immutable publication to persist before the first provider write.
/// Every field is explicit; deployments must never regenerate changed defaults on a retry.
pub fn publication(effect: &Effect) -> Result<PublishParams, Fault> {
    let Work::Deliver {
        address,
        scope,
        text,
    } = &effect.work
    else {
        return Err(Fault::Internal);
    };
    let address = NativeAddress::parse(address)
        .map_err(|_| Fault::Invalid)?
        .canonical();
    Ok(PublishParams {
        destination: Destination::Address { address },
        event_id: effect.effect_id.clone(),
        kind: "agent_pool".into(),
        payload: Payload::new(text.clone()).map_err(|_| Fault::Invalid)?,
        mode: Mode::Message,
        policy: Policy::KeepAll,
        metadata: Metadata::new(),
        expires_at_ms: None,
        delivery_scope_key: Some(scope.clone()),
    })
}

/// Validates full receipt identity, including producer, immutable intent and canonical destination.
fn matching_receipt(
    receipt: &EventReceipt,
    producer: &str,
    params: &PublishParams,
) -> Result<(), Fault> {
    let Destination::Address { address } = &params.destination else {
        return Err(Fault::Internal);
    };
    if receipt.producer != producer
        || receipt.event_id != params.event_id
        || receipt.intent_hash
            != publication_intent_fingerprint(params).map_err(|_| Fault::Invalid)?
        || receipt.destination.address != *address
        || receipt.destination.route_key.is_some()
        || receipt.destination.caller_scope.is_some()
        || receipt.destination.destination_scope.is_some()
    {
        return Err(Fault::Unavailable);
    }
    Ok(())
}

/// Publishes frozen intent once, or reads exact status for an uncertain previous attempt.
/// An absent historical receipt remains unknown; no new identity or native resend is created.
pub async fn deliver(
    config: Config,
    producer: String,
    params: PublishParams,
    reconcile: bool,
) -> Result<&'static str, Fault> {
    tokio::task::spawn_blocking(move || {
        if producer != config.bridge_producer_id {
            return Err(Fault::Unavailable);
        }
        let client = bridge(&config, false)?;
        if reconcile {
            match client.status(
                id(),
                StatusSelector::Event {
                    event_id: params.event_id.clone(),
                },
            ) {
                Ok(StatusResult::Event { event: Some(event) }) => {
                    matching_receipt(&event.receipt, &producer, &params)?;
                    Ok(delivery_state(&event.delivery))
                }
                _ => Ok("unknown"),
            }
        } else {
            match client.publish(params.event_id.clone(), params.clone()) {
                Ok(result) => {
                    matching_receipt(&result.receipt, &producer, &params)?;
                    Ok("custody")
                }
                Err(bridge_sdk::ClientError::Service(error))
                    if error.effect == Some(MutationEffect::NotCommitted)
                        && matches!(
                            error.class,
                            ErrorClass::Auth
                                | ErrorClass::Forbidden
                                | ErrorClass::Invalid
                                | ErrorClass::Unsupported
                                | ErrorClass::Conflict
                        ) =>
                {
                    Ok("refused")
                }
                Err(_) => Ok("unknown"),
            }
        }
    })
    .await
    .map_err(|_| Fault::Internal)?
}

/// Classifies separately observed native facts; accepted means handoff/context submission, never processing.
/// Queue custody, held native work and reservations remain monitored; uncertain writes request reconciliation.
fn delivery_state(status: &DeliveryStatus) -> &'static str {
    match status.delivery {
        DeliveryState::Refused => "refused",
        DeliveryState::Disposed => "cancelled",
        DeliveryState::Accepted
            if status.tiers.contains(&EvidenceTier::NativeAccepted)
                || status.attempt_state == Some(AttemptState::NativeAccepted) =>
        {
            "accepted"
        }
        DeliveryState::HookSubmitted
            if status.tiers.contains(&EvidenceTier::HookEmitted)
                || status.attempt_state == Some(AttemptState::HookSubmitted) =>
        {
            "accepted"
        }
        DeliveryState::Review => "unknown",
        _ if matches!(
            status.attempt_state,
            Some(AttemptState::OutcomeUnknown | AttemptState::WrittenNoReceipt)
        ) =>
        {
            "unknown"
        }
        _ => "custody",
    }
}

/// Retires only provably unhanded scope effects using one durable operation identity.
/// Unknown prior native effects remain in Bridge; successful retirement is not recall.
pub async fn retire(
    config: Config,
    effect_id: String,
    scope: String,
) -> Result<&'static str, Fault> {
    tokio::task::spawn_blocking(move || {
        let result = bridge(&config, false)?.retire_delivery_scope(
            effect_id.clone(),
            RetireDeliveryScopeParams {
                scope_key: scope.clone(),
                action: RetirementAction::RetireUnhanded,
            },
        );
        match result {
            Ok(result)
                if result.receipt.producer == config.bridge_producer_id
                    && result.receipt.request_id == effect_id
                    && result.receipt.scope_key == scope
                    && result.receipt.action == RetirementAction::RetireUnhanded =>
            {
                Ok("accepted")
            }
            _ => Ok("unknown"),
        }
    })
    .await
    .map_err(|_| Fault::Internal)?
}

/// Samples one explicitly granted existing recipient without treating absence as completion.
pub async fn observe(config: Config, address: String) -> Result<String, Fault> {
    tokio::task::spawn_blocking(move || {
        let address = NativeAddress::parse(&address)
            .map_err(|_| Fault::Invalid)?
            .canonical();
        let result = bridge(&config, true)?
            .observe_recipient(
                id(),
                ObserveRecipientParams {
                    address: address.clone(),
                },
            )
            .map_err(|_| Fault::Unavailable)?;
        if result.address != address
            || result.sampled_at_ms == 0
            || result.sampled_at_ms > i64::MAX as u64
        {
            return Err(Fault::Unavailable);
        }
        Ok(match result.observation {
            RecipientObservationState::Observed { lifecycle, .. } => match lifecycle {
                RecipientLifecycle::Active => "active",
                RecipientLifecycle::Inactive => "inactive",
                RecipientLifecycle::AwaitingInput => "awaiting_input",
                RecipientLifecycle::Unknown => "unknown",
            },
            RecipientObservationState::Unavailable => "unknown",
        }
        .to_owned())
    })
    .await
    .map_err(|_| Fault::Internal)?
}

/// Reads exactly one bounded newline frame; EOF, extra same-read frames and oversize fail closed.
/// Cancellation discards the connection, so partial I/O is never restarted on the same stream.
pub async fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, Fault> {
    let mut frame = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = stream
            .read(&mut buffer)
            .await
            .map_err(|_| Fault::Unavailable)?;
        if count == 0 {
            return Err(Fault::Unavailable);
        }
        if let Some(end) = buffer[..count].iter().position(|byte| *byte == b'\n') {
            if frame.len() + end > MAX_FRAME || end + 1 != count {
                return Err(Fault::Invalid);
            }
            frame.extend_from_slice(&buffer[..end]);
            return Ok(frame);
        }
        if frame.len() + count > MAX_FRAME {
            return Err(Fault::Invalid);
        }
        frame.extend_from_slice(&buffer[..count]);
    }
}

/// Connects only to a protected same-UID local endpoint; does not send application data.
pub async fn connect(path: &Path, uid: u32) -> Result<UnixStream, Fault> {
    private_socket(path, uid)?;
    let stream = UnixStream::connect(path)
        .await
        .map_err(|_| Fault::Unavailable)?;
    if stream.peer_cred().map_err(|_| Fault::Unavailable)?.uid() != uid {
        return Err(Fault::Unavailable);
    }
    Ok(stream)
}

/// Requires configured UID to equal the current process's effective UID without environment identity.
pub fn own_uid(uid: u32) -> Result<(), Fault> {
    let (left, _right) = UnixStream::pair().map_err(|_| Fault::Unavailable)?;
    if left.peer_cred().map_err(|_| Fault::Unavailable)?.uid() != uid {
        return Err(Fault::Unavailable);
    }
    Ok(())
}

/// Strict Run response envelope; duplicate known keys, null branches and nonnumeric IDs are rejected.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunReply {
    /// Exact JSON-RPC version, required to be 2.0 after decoding.
    jsonrpc: String,
    /// Exact numeric request correlation identifier.
    id: u64,
    /// Successful object projection; mutually exclusive with error.
    result: Option<Value>,
    /// Structured service failure; prose is ignored by the closed classifier.
    error: Option<Value>,
}

/// Sends one exact JSON-RPC request over a fresh connection; errors expose only safe classes.
/// All failures after a possible write remain unknown to the caller; Run start retries use its durable key.
async fn run_rpc(config: &Config, method: &str, params: Value) -> Result<Value, RunFailure> {
    let socket = config.run_socket.as_ref().ok_or(RunFailure::unknown())?;
    let request_id = u64::from_le_bytes(
        uuid::Uuid::new_v4().as_bytes()[..8]
            .try_into()
            .map_err(|_| Fault::Internal)?,
    ) & i64::MAX as u64;
    let mut bytes = serde_json::to_vec(
        &json!({"jsonrpc":"2.0","id":request_id,"method":method,"params":params}),
    )
    .map_err(|_| Fault::Invalid)?;
    if bytes.len() > MAX_FRAME {
        return Err(Fault::Invalid.into());
    }
    bytes.push(b'\n');
    tokio::time::timeout(EXCHANGE_TIMEOUT, async {
        let mut stream = connect(socket, config.expected_uid).await?;
        stream
            .write_all(&bytes)
            .await
            .map_err(|_| Fault::Unavailable)?;
        let frame = read_frame(&mut stream)
            .await
            .map_err(|_| RunFailure::unknown())?;
        let reply: RunReply = serde_json::from_slice(&frame).map_err(|_| RunFailure::unknown())?;
        if reply.jsonrpc != "2.0"
            || reply.id != request_id
            || reply.error.is_some() == reply.result.is_some()
        {
            return Err(RunFailure::unknown());
        }
        if let Some(error) = reply.error {
            if error.get("message").and_then(Value::as_str).is_none() {
                return Err(RunFailure::unknown());
            }
            return Err(RunFailure::from_response(&error));
        }
        reply
            .result
            .filter(Value::is_object)
            .ok_or(RunFailure::unknown())
    })
    .await
    .map_err(|_| RunFailure::unknown())?
}

/// Safe closed Run failure retaining machine codes without provider prose or private payloads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunFailure {
    /// Exact stable machine class, or outcome_unknown when no trustworthy class exists.
    pub code: &'static str,
    /// Positive correlated refusal before admission; false never permits a replacement launch.
    pub known_unadmitted: bool,
}
impl RunFailure {
    /// Represents transport loss, malformed replies or nonauthoritative server failure.
    fn unknown() -> Self {
        Self {
            code: "outcome_unknown",
            known_unadmitted: false,
        }
    }

    /// Maps only protocol numbers and finite machine data; ignores all explanatory prose.
    fn from_response(error: &Value) -> Self {
        let code = match error.get("code").and_then(Value::as_i64) {
            Some(-32602) => "invalid_params",
            Some(-32600) => "invalid_request",
            Some(-32601) => "method_not_found",
            Some(-32700) => "parse_error",
            Some(-32001) => "overload",
            Some(-32002) => {
                return Self {
                    code: "deadline",
                    known_unadmitted: false,
                };
            }
            Some(-32000) => match error.pointer("/data/code").and_then(Value::as_str) {
                Some("RequestConflict") => "RequestConflict",
                Some("CapacityExhausted") => "CapacityExhausted",
                Some("AgentNotFound") => "AgentNotFound",
                Some("selection_busy") => "selection_busy",
                Some("no_eligible_account") => "no_eligible_account",
                Some("quota_exhausted") => "quota_exhausted",
                Some("ValidationError") => "ValidationError",
                _ => return Self::unknown(),
            },
            _ => return Self::unknown(),
        };
        Self {
            code,
            known_unadmitted: true,
        }
    }
}
impl From<Fault> for RunFailure {
    /// Local validation is a known refusal; I/O, malformed responses and internal failures stay uncertain.
    fn from(fault: Fault) -> Self {
        if fault == Fault::Invalid {
            Self {
                code: "invalid_params",
                known_unadmitted: true,
            }
        } else {
            Self::unknown()
        }
    }
}

/// Durable Run admission identity, recorded before any communication lookup.
pub struct Admission {
    /// Stable logical Run agent ID.
    pub agent_id: String,
    /// Exact positive lineage position, never replaced by latest during reconciliation.
    pub sequence: u64,
}

/// Submits the frozen original specification and original service-prefixed admission key.
/// Refuses embedded alternate keys; lost acknowledgements are reconciled with this exact request only.
pub async fn start(
    config: &Config,
    spec: &Value,
    request_key: &str,
) -> Result<Admission, RunFailure> {
    let mut params = spec.clone();
    let object = params.as_object_mut().ok_or(Fault::Invalid)?;
    if object
        .get("request_id")
        .is_some_and(|value| value.as_str() != Some(request_key))
    {
        return Err(Fault::Invalid.into());
    }
    object.insert("request_id".into(), Value::String(request_key.to_owned()));
    let reply = run_rpc(config, "start", params).await?;
    let agent_id = reply
        .get("agent_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .ok_or(Fault::Unavailable)?
        .to_owned();
    let sequence = reply
        .get("sequence")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0 && *value <= u32::MAX as u64)
        .ok_or(Fault::Unavailable)?;
    if reply.get("created").and_then(Value::as_bool).is_none()
        || reply.pointer("/agent/agent_id").and_then(Value::as_str) != Some(&agent_id)
        || reply.pointer("/agent/sequence").and_then(Value::as_u64) != Some(sequence)
    {
        return Err(RunFailure::unknown());
    }
    Ok(Admission { agent_id, sequence })
}

/// Validated generic Run projection containing only address/lifecycle facts needed by Pool.
pub struct RunObservation {
    /// Canonical address only when Run positively proved the exact live execution.
    pub address: Option<String>,
    /// Finite safe state; unknown or unsupported never implies completion.
    pub runtime: String,
}

/// Observes exactly the retained Run sequence and rejects malformed, stale or mismatched projections.
pub async fn run_observe(
    config: &Config,
    agent_id: &str,
    sequence: u64,
) -> Result<RunObservation, Fault> {
    let result = run_rpc(
        config,
        "agent_integration",
        json!({"agent_id":agent_id,"sequence":sequence}),
    )
    .await
    .map_err(|_| Fault::Unavailable)?;
    if result.get("schema_version").and_then(Value::as_u64) != Some(1)
        || result.pointer("/agent/agent_id").and_then(Value::as_str) != Some(agent_id)
        || result.pointer("/agent/sequence").and_then(Value::as_u64) != Some(sequence)
    {
        return Err(Fault::Unavailable);
    }
    let communication = result.get("communication").ok_or(Fault::Unavailable)?;
    let address = match communication.get("state").and_then(Value::as_str) {
        Some("observed")
            if communication
                .as_object()
                .is_some_and(|value| value.len() == 3) =>
        {
            let address = communication
                .get("address")
                .and_then(Value::as_str)
                .ok_or(Fault::Unavailable)?;
            let parsed = NativeAddress::parse(address).map_err(|_| Fault::Unavailable)?;
            if parsed.canonical() != address
                || !communication
                    .get("sampled_at_ms")
                    .and_then(Value::as_u64)
                    .is_some_and(|value| value > 0 && value <= i64::MAX as u64)
            {
                return Err(Fault::Unavailable);
            }
            Some(address.to_owned())
        }
        Some("unknown")
            if communication
                .as_object()
                .is_some_and(|value| value.len() == 2)
                && matches!(
                    communication.get("reason").and_then(Value::as_str),
                    Some(
                        "not_started"
                            | "unavailable"
                            | "identity_changed"
                            | "terminal"
                            | "closing"
                            | "cancelled"
                    )
                ) =>
        {
            None
        }
        Some("unsupported")
            if communication
                .as_object()
                .is_some_and(|value| value.len() == 2)
                && matches!(
                    communication.get("reason").and_then(Value::as_str),
                    Some(
                        "unsupported_harness"
                            | "legacy_completion"
                            | "restricted_role"
                            | "observer_unconfigured"
                            | "observer_forbidden"
                    )
                ) =>
        {
            None
        }
        _ => return Err(Fault::Unavailable),
    };
    let runtime = match result.pointer("/agent/status").and_then(Value::as_str) {
        Some("running") => "active",
        Some("created" | "starting" | "cancelling") => "unknown",
        Some("succeeded") => "succeeded",
        Some("failed" | "timed_out") => "failed",
        Some("lost") => "lost",
        Some("cancelled") => "cancelled",
        _ => "unknown",
    }
    .to_owned();
    Ok(RunObservation { address, runtime })
}

/// Local fixtures exercise framing, correlation and trust fences; they do not certify a real harness.
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    /// Creates explicit fake endpoints solely for local protocol tests, never production identity.
    fn fixture_config(path: &Path, uid: u32) -> Config {
        Config {
            socket_path: path.join("pool.sock"),
            database_path: path.join("pool.db"),
            expected_uid: uid,
            bridge_registration_socket: path.join("bridge.sock"),
            bridge_core_socket: path.join("core.sock"),
            bridge_credential_file: path.join("token"),
            bridge_producer_id: "pool-test".into(),
            bridge_audience: "pool-test-backend".into(),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            run_socket: Some(path.join("run.sock")),
        }
    }

    /// Current evidence succeeds; historical, wrong-audience and shared-destination facts cannot authorize.
    #[test]
    fn current_assertion_is_required_for_every_authorization() {
        let config = fixture_config(Path::new("/unused"), 0);
        let result = ConsumeResult {
            state: InvocationValidity::Current,
            receipt: ConsumptionReceipt {
                producer: "pool-test".into(),
                request_id: "consume".into(),
                consumed_at_ms: 2,
                context: InvocationContext {
                    audience: "pool-test-backend".into(),
                    caller_scope: "scope".into(),
                    destination_scope: "scope".into(),
                    caller_address: "local/codex/store/thread".into(),
                    destination_address: "local/codex/store/thread".into(),
                    role: ActorRole::Root,
                    native_actor_id: "thread".into(),
                    native_call_id: "native-call".into(),
                    invocation_key: "invocation".into(),
                    observed_at_ms: 1,
                    expires_at_ms: 10,
                    issuer_boot: "boot".into(),
                    endpoint_incarnation: "endpoint".into(),
                },
            },
        };
        assert!(verified_actor(&config, "invocation", "consume", result.clone()).is_ok());
        let mut stale = result.clone();
        stale.state = InvocationValidity::Historical;
        assert!(matches!(
            verified_actor(&config, "invocation", "consume", stale),
            Err(Fault::Unauthorized)
        ));
        let mut audience = result.clone();
        audience.receipt.context.audience = "other".into();
        assert!(matches!(
            verified_actor(&config, "invocation", "consume", audience),
            Err(Fault::Unauthorized)
        ));
        let mut child = result.clone();
        child.receipt.context.role = ActorRole::Child;
        child.receipt.context.native_actor_id = "shared-child".into();
        assert!(matches!(
            verified_actor(&config, "invocation", "consume", child),
            Err(Fault::Unauthorized)
        ));
        let mut shared = result.clone();
        shared.receipt.context.destination_address = "local/codex/store/parent".into();
        assert!(matches!(
            verified_actor(&config, "invocation", "consume", shared),
            Err(Fault::Unauthorized)
        ));
        assert!(matches!(
            verified_actor(&config, "another-invocation", "consume", result),
            Err(Fault::Unauthorized)
        ));
    }

    /// One frame succeeds, whereas oversized payloads and concatenated frames fail before decoding.
    #[tokio::test]
    async fn framed_stream_enforces_one_mebibyte_and_one_request()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut reader, mut writer) = UnixStream::pair()?;
        writer.write_all(b"{\"ok\":true}\n").await?;
        assert_eq!(read_frame(&mut reader).await?, b"{\"ok\":true}");
        let (mut reader, mut writer) = UnixStream::pair()?;
        writer.write_all(b"{}\n{}\n").await?;
        assert!(matches!(read_frame(&mut reader).await, Err(Fault::Invalid)));
        let (mut reader, mut writer) = UnixStream::pair()?;
        let producer =
            tokio::spawn(async move { writer.write_all(&vec![b'x'; MAX_FRAME + 1]).await });
        assert!(matches!(read_frame(&mut reader).await, Err(Fault::Invalid)));
        producer.await??;
        Ok(())
    }

    /// Real local Unix fixtures prove numeric correlation, same-key retries and safe rejection.
    #[tokio::test]
    async fn run_transport_preserves_admission_key_and_rejects_wrong_reply_id()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::Builder::new()
            .prefix("pool-transport-")
            .tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let uid = std::fs::metadata(directory.path())?.uid();
        own_uid(uid)?;
        let config = fixture_config(directory.path(), uid);
        let socket = config.run_socket.as_ref().ok_or("missing fixture socket")?;
        let listener = tokio::net::UnixListener::bind(socket)?;
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
        let responder = tokio::spawn(async move {
            let mut requests = Vec::new();
            for index in 0..3 {
                let (mut stream, _) = listener.accept().await?;
                let request: Value = serde_json::from_slice(&read_frame(&mut stream).await?)?;
                requests.push(request["params"].clone());
                let reply_id = if index == 2 {
                    json!("wrong-id")
                } else {
                    request["id"].clone()
                };
                let reply = json!({"jsonrpc":"2.0","id":reply_id,"result":{"agent_id":"logical-agent","sequence":2,"created":index == 0,"agent":{"agent_id":"logical-agent","sequence":2}}});
                let mut bytes = serde_json::to_vec(&reply)?;
                bytes.push(b'\n');
                stream.write_all(&bytes).await?;
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(requests)
        });
        let spec = json!({"provider":"codex","model":"frozen-model","profile":"ordinary","task":"frozen-onboarding","workdir":"/unused"});
        let first = start(&config, &spec, "agent-pool.instance.operation")
            .await
            .map_err(|_| "first fixture start failed")?;
        let second = start(&config, &spec, "agent-pool.instance.operation")
            .await
            .map_err(|_| "replay fixture start failed")?;
        assert_eq!(first.agent_id, second.agent_id);
        assert_eq!(first.sequence, 2);
        let failure = start(&config, &spec, "agent-pool.instance.operation")
            .await
            .err()
            .ok_or("wrong ID accepted")?;
        assert!(!failure.known_unadmitted);
        let requests = responder.await?.map_err(|_| "fixture responder failed")?;
        assert_eq!(requests[0], requests[1]);
        assert_eq!(requests[1], requests[2]);
        assert_eq!(requests[0]["request_id"], "agent-pool.instance.operation");
        Ok(())
    }

    /// Custody and held work remain monitored; only positive native handoff evidence completes delivery.
    #[test]
    fn custody_is_distinct_from_native_handoff_and_unknown_writes() {
        let mut status = DeliveryStatus {
            delivery: DeliveryState::Unhanded,
            attempt_state: None,
            effective_mode: None,
            note: None,
            attempts_made: 0,
            attempt: None,
            tiers: Vec::new(),
            incident: None,
            hold_reason: None,
            blocked_by: None,
        };
        assert_eq!(delivery_state(&status), "custody");
        status.delivery = DeliveryState::Held;
        status.tiers.push(EvidenceTier::NativeHeld);
        assert_eq!(delivery_state(&status), "custody");
        status.delivery = DeliveryState::Accepted;
        assert_eq!(delivery_state(&status), "custody");
        status.tiers.push(EvidenceTier::NativeAccepted);
        assert_eq!(delivery_state(&status), "accepted");
        status.delivery = DeliveryState::Review;
        status.attempt_state = Some(AttemptState::OutcomeUnknown);
        assert_eq!(delivery_state(&status), "unknown");
        status.delivery = DeliveryState::Refused;
        assert_eq!(delivery_state(&status), "refused");
    }

    /// Provider prose never controls recovery; correlated finite domain codes remain distinct.
    #[test]
    fn run_machine_errors_preserve_safe_classes() {
        for code in [
            "RequestConflict",
            "CapacityExhausted",
            "AgentNotFound",
            "selection_busy",
            "no_eligible_account",
            "quota_exhausted",
        ] {
            let error = RunFailure::from_response(
                &json!({"code":-32000,"data":{"code":code,"message":"private-canary"}}),
            );
            assert_eq!(error.code, code);
            assert!(error.known_unadmitted);
            assert!(!format!("{error:?}").contains("private-canary"));
        }
        assert!(!RunFailure::from_response(&json!({"code":-32002})).known_unadmitted);
        assert!(
            !RunFailure::from_response(&json!({"code":-32000,"message":"RequestConflict"}))
                .known_unadmitted
        );
    }
}
