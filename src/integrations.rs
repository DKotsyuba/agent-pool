//! Bounded public Bridge/Run clients; native assertions are the only caller authority.
use crate::{
    config::{Config, private_socket},
    domain::{Actor, Effect, Fault, Work, id},
};
use bridge_sdk::{Client, bridge_protocol::*};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
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
/// The pinned Bridge caps issued assertion lifetime at 30 seconds.
const ASSERTION_MAX_REMAINING_MS: u64 = 30_000;

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
    bridge_with_timeout(config, observation, EXCHANGE_TIMEOUT, true)
}

/// Creates the same SDK with an explicit finite timeout for a bounded wait recheck.
fn bridge_with_timeout(
    config: &Config,
    observation: bool,
    timeout: Duration,
    reconnect_once: bool,
) -> Result<Client, Fault> {
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
    let mut sdk = bridge_sdk::Config::new(
        registration,
        &config.bridge_core_socket,
        Secret::new(config.credential(credential)?),
        timeout,
    )
    .map_err(|_| Fault::Unavailable)?;
    sdk.reconnect_once = reconnect_once;
    Client::new(sdk).map_err(|_| Fault::Unavailable)
}

/// A consumed invocation retained privately for same-consumer validity rechecks during a wait.
#[derive(Clone)]
pub struct ConsumedInvocation {
    actor: Actor,
    assertion: Assertion,
    request_id: String,
    receipt: ConsumptionReceipt,
    expiry: InvocationExpiry,
}
impl ConsumedInvocation {
    /// Returns the actor established by the original current assertion.
    pub fn actor(&self) -> &Actor {
        &self.actor
    }

    /// Returns the original expiry fence, which cannot be extended by a later recheck.
    pub fn expiry(&self) -> InvocationExpiry {
        self.expiry
    }
}

/// The original wall-clock expiry and its conservative monotonic upper bound.
#[derive(Clone, Copy)]
pub struct InvocationExpiry {
    wall_expiry: Duration,
    monotonic_deadline: Instant,
}
impl InvocationExpiry {
    /// Pins the remaining lifetime before consume and against the current wall clock.
    pub(crate) fn new(
        observed_at_ms: u64,
        expires_at_ms: u64,
        consumed_at_ms: u64,
        consume_started: Instant,
        consume_started_wall: Duration,
    ) -> Result<Self, Fault> {
        if observed_at_ms == 0
            || observed_at_ms > consumed_at_ms
            || Duration::from_millis(observed_at_ms) > consume_started_wall
        {
            return Err(Fault::Unauthorized);
        }
        let at_consumption = expires_at_ms
            .checked_sub(consumed_at_ms)
            .map(|remaining| remaining.min(ASSERTION_MAX_REMAINING_MS))
            // Bridge timestamps are whole milliseconds, so discard their rounding margin.
            .and_then(|remaining| remaining.checked_sub(1))
            .filter(|remaining| *remaining > 0)
            .ok_or(Fault::Unauthorized)?;
        let consumption_deadline = consume_started
            .checked_add(Duration::from_millis(at_consumption))
            .ok_or(Fault::Unavailable)?;
        let monotonic = Instant::now();
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Fault::Unavailable)?;
        if Duration::from_millis(observed_at_ms) > wall {
            return Err(Fault::Unauthorized);
        }
        let wall_expiry = Duration::from_millis(expires_at_ms);
        let remaining = wall_expiry
            .checked_sub(wall)
            .filter(|remaining| !remaining.is_zero())
            .ok_or(Fault::Unauthorized)?;
        let wall_deadline = monotonic.checked_add(remaining).ok_or(Fault::Unavailable)?;
        let monotonic_deadline = wall_deadline.min(consumption_deadline);
        Ok(Self {
            wall_expiry,
            monotonic_deadline,
        })
    }

    /// Refuses expiry under either clock, including a backwards wall-clock adjustment.
    pub fn check(self) -> Result<(), Fault> {
        self.remaining().map(|_| ())
    }

    /// Bounds a response write by both the original wall and monotonic deadlines.
    pub fn remaining(self) -> Result<Duration, Fault> {
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Fault::Unavailable)?;
        self.remaining_at(wall, Instant::now())
    }

    /// Uses explicit observations so both clock fences can be tested deterministically.
    fn remaining_at(self, wall: Duration, monotonic: Instant) -> Result<Duration, Fault> {
        let wall = self.wall_expiry.checked_sub(wall).filter(|d| !d.is_zero());
        let monotonic = self
            .monotonic_deadline
            .checked_duration_since(monotonic)
            .filter(|d| !d.is_zero());
        Ok(wall
            .ok_or(Fault::Unauthorized)?
            .min(monotonic.ok_or(Fault::Unauthorized)?))
    }
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
pub async fn consume(config: Config, assertion: Assertion) -> Result<ConsumedInvocation, Fault> {
    let consume_started = Instant::now();
    let consume_started_wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Fault::Unavailable)?;
    tokio::task::spawn_blocking(move || {
        let request_id = id();
        let result = bridge(&config, false)?
            .consume_assertion(
                request_id.clone(),
                ConsumeAssertionParams {
                    assertion_key: assertion.assertion_key.clone(),
                    invocation_key: assertion.invocation_key.clone(),
                },
            )
            .map_err(|_| Fault::Unauthorized)?;
        let receipt = result.receipt.clone();
        let actor = verified_actor(&config, &assertion.invocation_key, &request_id, result)?;
        let expiry = InvocationExpiry::new(
            receipt.context.observed_at_ms,
            receipt.context.expires_at_ms,
            receipt.consumed_at_ms,
            consume_started,
            consume_started_wall,
        )?;
        expiry.check()?;
        Ok(ConsumedInvocation {
            actor,
            assertion,
            request_id,
            receipt,
            expiry,
        })
    })
    .await
    .map_err(|_| Fault::Internal)?
}

/// Rechecks the original assertion without renewing it or changing its consumer/request identity.
pub async fn recheck_invocation(
    config: Config,
    invocation: ConsumedInvocation,
    timeout: Duration,
) -> Result<(), Fault> {
    tokio::task::spawn_blocking(move || {
        invocation.expiry.check()?;
        let result = bridge_with_timeout(&config, false, timeout, false)?
            .consume_assertion(
                invocation.request_id.clone(),
                ConsumeAssertionParams {
                    assertion_key: invocation.assertion.assertion_key.clone(),
                    invocation_key: invocation.assertion.invocation_key.clone(),
                },
            )
            .map_err(|_| Fault::Unauthorized)?;
        if result.receipt != invocation.receipt {
            return Err(Fault::Unauthorized);
        }
        invocation.expiry.check()?;
        let actor = verified_actor(
            &config,
            &invocation.assertion.invocation_key,
            &invocation.request_id,
            result,
        )?;
        if actor.key != invocation.actor.key || actor.address != invocation.actor.address {
            return Err(Fault::Unauthorized);
        }
        Ok(())
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

/// Connects Run with the existing same-user policy or an explicit cross-user Linux policy.
/// Checks peer credentials and path fingerprints before returning a stream for application data.
async fn connect_run(config: &Config, path: &Path) -> Result<UnixStream, Fault> {
    if config.run_peer_uid == Some(u32::MAX)
        || config.run_peer_uid.is_some() && !cfg!(target_os = "linux")
    {
        return Err(Fault::Unavailable);
    }
    let Some(peer_uid) = config
        .run_peer_uid
        .filter(|uid| *uid != config.expected_uid)
    else {
        return connect(path, config.expected_uid).await;
    };
    #[cfg(target_os = "linux")]
    {
        crate::config::identity_uid_map()?;
        let before = crate::config::shared_run_socket(path, peer_uid)?;
        let stream = UnixStream::connect(path)
            .await
            .map_err(|_| Fault::Unavailable)?;
        check_run_peer(&stream, peer_uid)?;
        if crate::config::shared_run_socket(path, peer_uid)? != before {
            return Err(Fault::Unavailable);
        }
        Ok(stream)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = peer_uid;
        Err(Fault::Unavailable)
    }
}

/// Requires the connected Run peer's kernel-reported UID before any request bytes are written.
#[cfg(target_os = "linux")]
fn check_run_peer(stream: &UnixStream, peer_uid: u32) -> Result<(), Fault> {
    if stream.peer_cred().map_err(|_| Fault::Unavailable)?.uid() != peer_uid {
        return Err(Fault::Unavailable);
    }
    Ok(())
}

/// Requires configured UID to equal the current process's effective UID without environment identity.
pub fn own_uid(uid: u32) -> Result<(), Fault> {
    let (left, _right) = UnixStream::pair().map_err(|_| Fault::Unavailable)?;
    if left.peer_cred().map_err(|_| Fault::Unavailable)?.uid() != uid {
        return Err(Fault::Unavailable);
    }
    Ok(())
}

/// Requires an actual JSON object while preserving typed duplicate-field checks.
pub(crate) struct JsonObject<T>(pub(crate) T);
impl<'de, T: Deserialize<'de>> Deserialize<'de> for JsonObject<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor<T>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for ObjectVisitor<T> {
            type Value = JsonObject<T>;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON object")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                map: M,
            ) -> Result<Self::Value, M::Error> {
                T::deserialize(serde::de::value::MapAccessDeserializer::new(map)).map(JsonObject)
            }
        }
        deserializer.deserialize_map(ObjectVisitor(std::marker::PhantomData))
    }
}

/// Decodes one object without accepting a positional JSON array.
pub(crate) fn json_object<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    JsonObject::<T>::deserialize(deserializer).map(|object| object.0)
}

/// Decodes an array whose entries must each be objects.
pub(crate) fn json_objects<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Vec::<JsonObject<T>>::deserialize(deserializer)
        .map(|objects| objects.into_iter().map(|object| object.0).collect())
}

/// Decodes a required nullable object without accepting a positional array.
pub(crate) fn nullable_object<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<JsonObject<T>>::deserialize(deserializer).map(|object| object.map(|object| object.0))
}

/// Strict Run response envelope; duplicate known keys, null branches and nonnumeric IDs are rejected.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunReply<T> {
    /// Exact JSON-RPC version, required to be 2.0 after decoding.
    jsonrpc: String,
    /// Exact numeric request correlation identifier.
    id: u64,
    /// Successful object projection; mutually exclusive with error.
    result: Option<JsonObject<T>>,
    /// Structured service failure; prose is ignored by the closed classifier.
    error: Option<Value>,
}
/// Hold responses require one present object branch; explicit null is not omission.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictHoldEnvelope {
    jsonrpc: String,
    id: u64,
    #[serde(default, deserialize_with = "present_object")]
    result: Option<serde::de::IgnoredAny>,
    #[serde(default, deserialize_with = "present_object")]
    error: Option<serde::de::IgnoredAny>,
}

/// Checks a hold envelope without weakening the typed result's duplicate-key checks.
fn strict_hold_envelope(frame: &[u8], request_id: u64) -> bool {
    let Ok(JsonObject(reply)) = serde_json::from_slice::<JsonObject<StrictHoldEnvelope>>(frame)
    else {
        return false;
    };
    reply.jsonrpc == "2.0"
        && reply.id == request_id
        && (reply.result.is_some() != reply.error.is_some())
}
/// Strictly decoded precondition refusal; duplicate fields cannot manufacture a terminal outcome.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreconditionErrorEnvelope {
    jsonrpc: String,
    id: u64,
    #[serde(deserialize_with = "json_object")]
    error: PreconditionError,
}
/// Only the producer's bounded JSON-RPC error branch can refuse a first submission.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreconditionError {
    code: i64,
    message: String,
    #[serde(deserialize_with = "json_object")]
    data: PreconditionErrorData,
}
/// Closed producer error class and reason, without interpreting its prose.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreconditionErrorData {
    code: String,
    reason: String,
    #[serde(default, rename = "message")]
    _message: Option<String>,
}
/// Correlated single-call admission failure with no ambiguous duplicate fields.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionErrorEnvelope {
    jsonrpc: String,
    id: u64,
    #[serde(deserialize_with = "json_object")]
    error: AdmissionError,
}
/// Only explicit pre-admission errors are eligible for first-call refusal.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionError {
    code: i64,
    message: String,
    #[serde(default, deserialize_with = "present_object")]
    data: Option<AdmissionErrorData>,
}
/// The closed producer machine code, without using its diagnostic prose.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionErrorData {
    code: String,
    #[serde(default, rename = "message")]
    _message: Option<String>,
}
/// Identifies only Run errors proven to reject the current call before admission.
fn strict_initial_refusal(frame: &[u8], request_id: u64) -> bool {
    let Ok(JsonObject(envelope)) =
        serde_json::from_slice::<JsonObject<AdmissionErrorEnvelope>>(frame)
    else {
        return false;
    };
    if envelope.jsonrpc != "2.0" || envelope.id != request_id || envelope.error.message.is_empty() {
        return false;
    }
    let code = envelope.error.data.as_ref().map(|data| data.code.as_str());
    matches!(
        (envelope.error.code, code),
        (-32602, None | Some("ValidationError" | "PathEscapeError"))
            | (
                -32000,
                Some(
                    "ValidationError"
                        | "PathEscapeError"
                        | "selection_busy"
                        | "no_eligible_account"
                        | "quota_exhausted"
                        | "binding_cooldown"
                        | "CapacityExhausted"
                        | "StateTransitionError"
                )
            )
    )
}

/// Run's hold writer returns RequestConflict before inserting any hold, or
/// replays an existing exact receipt. Only an initial call can use this proof.
fn strict_hold_conflict(frame: &[u8], request_id: u64) -> bool {
    let Ok(JsonObject(envelope)) =
        serde_json::from_slice::<JsonObject<AdmissionErrorEnvelope>>(frame)
    else {
        return false;
    };
    envelope.jsonrpc == "2.0"
        && envelope.id == request_id
        && !envelope.error.message.is_empty()
        && envelope.error.code == -32000
        && envelope
            .error
            .data
            .as_ref()
            .is_some_and(|data| data.code == "RequestConflict")
}
/// Accepts only a correlated, structurally unambiguous producer precondition refusal.
fn strict_precondition_failure(frame: &[u8], request_id: u64) -> bool {
    let Ok(JsonObject(envelope)) =
        serde_json::from_slice::<JsonObject<PreconditionErrorEnvelope>>(frame)
    else {
        return false;
    };
    envelope.jsonrpc == "2.0"
        && envelope.id == request_id
        && envelope.error.code == -32000
        && !envelope.error.message.is_empty()
        && envelope.error.data.code == "PreconditionFailed"
        && matches!(envelope.error.data.reason.as_str(), "not_met" | "unknown")
}

/// Sends one exact JSON-RPC request over a fresh connection; errors expose only safe classes.
/// All failures after a possible write remain unknown to the caller; Run start retries use its durable key.
async fn run_rpc(config: &Config, method: &str, params: Value) -> Result<Value, RunFailure> {
    let result: Value = run_rpc_typed(config, method, params).await?;
    if !result.is_object() {
        return Err(RunFailure::unknown());
    }
    Ok(result)
}

/// Decodes a correlated Run result directly into its typed representation.
pub(crate) async fn run_rpc_typed<T: serde::de::DeserializeOwned>(
    config: &Config,
    method: &str,
    params: Value,
) -> Result<T, RunFailure> {
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
        let mut stream = connect_run(config, socket).await?;
        stream
            .write_all(&bytes)
            .await
            .map_err(|_| Fault::Unavailable)?;
        let frame = read_frame(&mut stream)
            .await
            .map_err(|_| RunFailure::unknown())?;
        if method.starts_with("_lineage_hold_") && !strict_hold_envelope(&frame, request_id) {
            return Err(RunFailure::unknown());
        }
        let JsonObject(reply): JsonObject<RunReply<T>> =
            serde_json::from_slice(&frame).map_err(|_| RunFailure::unknown())?;
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
            let mut failure = RunFailure::from_response(&error);
            if method == "start_batch" && strict_initial_refusal(&frame, request_id) {
                failure.known_unadmitted = true;
            }
            if method == "_lineage_hold_acquire" && strict_hold_conflict(&frame, request_id) {
                failure.known_unadmitted = true;
            }
            return Err(
                if failure.code == "PreconditionFailed"
                    && !strict_precondition_failure(&frame, request_id)
                {
                    RunFailure::unknown()
                } else {
                    failure
                },
            );
        }
        reply
            .result
            .map(|result| result.0)
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
    /// Proven pre-admission refusal for this attempt; false never permits a replacement launch.
    pub known_unadmitted: bool,
    /// Closed precondition reason, present only for a correlated Run refusal.
    pub precondition_reason: Option<&'static str>,
}
impl RunFailure {
    /// Represents transport loss, malformed replies or nonauthoritative server failure.
    fn unknown() -> Self {
        Self {
            code: "outcome_unknown",
            known_unadmitted: false,
            precondition_reason: None,
        }
    }

    /// Preserves safe machine classes without inferring pre-commit refusal from an unproven server error.
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
                    precondition_reason: None,
                };
            }
            Some(-32000) => match error.pointer("/data/code").and_then(Value::as_str) {
                Some("RequestConflict") => "RequestConflict",
                Some("CapacityExhausted") => "CapacityExhausted",
                Some("AgentNotFound") => "AgentNotFound",
                Some("selection_busy") => "selection_busy",
                Some("no_eligible_account") => "no_eligible_account",
                Some("quota_exhausted") => "quota_exhausted",
                Some("binding_cooldown") => "binding_cooldown",
                Some("PathEscapeError") => "PathEscapeError",
                Some("StateTransitionError") => "StateTransitionError",
                Some("Unsupported") => "Unsupported",
                Some("ValidationError") => "ValidationError",
                Some("PreconditionFailed")
                    if matches!(
                        error.pointer("/data/reason").and_then(Value::as_str),
                        Some("not_met" | "unknown")
                    ) =>
                {
                    "PreconditionFailed"
                }
                _ => return Self::unknown(),
            },
            _ => return Self::unknown(),
        };
        Self {
            code,
            known_unadmitted: false,
            precondition_reason: if code == "PreconditionFailed" {
                match error.pointer("/data/reason").and_then(Value::as_str) {
                    Some("not_met") => Some("not_met"),
                    Some("unknown") => Some("unknown"),
                    _ => None,
                }
            } else {
                None
            },
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
                precondition_reason: None,
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
/// Batch admission identity, including the immutable Run execution reference.
pub struct BatchAdmission {
    /// Stable logical Run agent ID.
    pub agent_id: String,
    /// Exact positive lineage position.
    pub sequence: u64,
    /// Opaque execution identity, not a credential or a current-attempt proof.
    pub execution_ref: String,
    /// Durable history pin when the original request required retention.
    pub pin_id: Option<String>,
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
        .filter(|value| crate::run_status::valid_agent_id(value))
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

/// Constructs exact Run arguments, omitting retention for legacy frozen intents.
fn batch_params(
    request_key: &str,
    jobs: &[crate::domain::BatchJob],
    retain_history: bool,
    expected_store_id: Option<&str>,
) -> Value {
    let specs: Vec<_> = jobs.iter().map(|job| &job.spec).collect();
    let mut params = json!({"request_id":request_key,"jobs":specs});
    if retain_history {
        params["retain_history"] = Value::Bool(true);
    }
    if let Some(store_id) = expected_store_id {
        params["expected_store_id"] = Value::String(store_id.to_owned());
    }
    params
}

/// Builds a new store-scoped batch intent with exact ordered execution prerequisites.
fn preconditioned_batch_params(
    request_key: &str,
    jobs: &[crate::domain::BatchJob],
    retain_history: bool,
    expected_store_id: &str,
    preconditions: &[crate::run_status::Target],
) -> Result<Value, RunFailure> {
    crate::run_status::validate_request(expected_store_id, preconditions)
        .map_err(|_| RunFailure::unknown())?;
    let mut agents = BTreeSet::new();
    let mut pins = BTreeSet::new();
    let mut references = BTreeSet::new();
    if request_key.is_empty()
        || jobs.is_empty()
        || jobs.len() > crate::domain::MAX_MEMBERS
        || jobs
            .iter()
            .any(|job| !job.spec.is_object() || job.spec.get("request_id").is_some())
        || preconditions.iter().any(|target| {
            !agents.insert(&target.agent_id)
                || !pins.insert(&target.pin_id)
                || !references.insert(&target.execution_ref)
        })
    {
        return Err(RunFailure::unknown());
    }
    let mut params = batch_params(request_key, jobs, retain_history, Some(expected_store_id));
    params["preconditions"] =
        serde_json::to_value(preconditions).map_err(|_| RunFailure::unknown())?;
    Ok(params)
}

/// Reads the non-secret identity of the configured Run database before a fenced mutation.
pub async fn run_store_identity(config: &Config) -> Result<String, RunFailure> {
    let reply = run_rpc(config, "capabilities", json!({"include_store_id":true})).await?;
    if reply.get("schema_version").and_then(Value::as_u64) != Some(1)
        || reply.get("product").and_then(Value::as_str) != Some("agent-run")
    {
        return Err(RunFailure::unknown());
    }
    let id = reply
        .get("store_id")
        .and_then(Value::as_str)
        .ok_or(Fault::Unavailable)?;
    crate::domain::store_id(id).map_err(|_| RunFailure::unknown())?;
    Ok(id.to_owned())
}

/// Releases one exact pin only within the expected Run store; malformed replies remain unknown.
pub async fn release_history_pin(
    config: &Config,
    pin: &str,
    expected_store_id: &str,
) -> Result<(), RunFailure> {
    crate::domain::pin_id(pin).map_err(|_| RunFailure::unknown())?;
    crate::domain::store_id(expected_store_id).map_err(|_| RunFailure::unknown())?;
    let reply = run_rpc(
        config,
        "history_pins",
        json!({"action":"release","pin_id":pin,"expected_store_id":expected_store_id}),
    )
    .await?;
    if reply.get("pin_id").and_then(Value::as_str) != Some(pin)
        || reply.get("status").and_then(Value::as_str) != Some("released")
        || reply
            .get("already_released")
            .and_then(Value::as_bool)
            .is_none()
    {
        return Err(RunFailure::unknown());
    }
    Ok(())
}

/// Sends one frozen group and accepts only a complete, ordered, correlated receipt.
/// Malformed or lost responses remain unknown and may only be replayed with the same key.
pub async fn start_batch(
    config: &Config,
    request_key: &str,
    jobs: &[crate::domain::BatchJob],
    retain_history: bool,
    expected_store_id: Option<&str>,
) -> Result<Vec<BatchAdmission>, RunFailure> {
    if jobs.is_empty() || jobs.len() > crate::domain::MAX_MEMBERS {
        return Err(Fault::Invalid.into());
    }
    let reply: BatchStartResult = run_rpc_typed(
        config,
        "start_batch",
        batch_params(request_key, jobs, retain_history, expected_store_id),
    )
    .await?;
    let reply = serde_json::to_value(reply).map_err(|_| RunFailure::unknown())?;
    parse_batch_receipt(
        &reply,
        request_key,
        jobs.len(),
        retain_history,
        expected_store_id,
        None,
    )
}

/// Submits a store-fenced batch only with exact prerequisites and validates their receipt echo.
pub async fn start_batch_with_preconditions(
    config: &Config,
    request_key: &str,
    jobs: &[crate::domain::BatchJob],
    retain_history: bool,
    expected_store_id: &str,
    preconditions: &[crate::run_status::Target],
) -> Result<Vec<BatchAdmission>, RunFailure> {
    let params = preconditioned_batch_params(
        request_key,
        jobs,
        retain_history,
        expected_store_id,
        preconditions,
    )?;
    let reply: BatchStartResult =
        run_rpc_typed(config, "start_batch", params)
            .await
            .map_err(|error| {
                if error.code == "PreconditionFailed" {
                    error
                } else {
                    RunFailure::unknown()
                }
            })?;
    let reply = serde_json::to_value(reply).map_err(|_| RunFailure::unknown())?;
    parse_batch_receipt(
        &reply,
        request_key,
        jobs.len(),
        retain_history,
        Some(expected_store_id),
        Some(preconditions),
    )
}

/// Distinguishes an absent optional member from a present but invalid null value.
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// Exact v1 receipt row for a read-only batch lookup.
#[derive(Deserialize, Serialize)]
struct BatchLookupJob {
    index: u64,
    agent_id: String,
    sequence: u64,
    execution_ref: String,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pin_id: Option<String>,
}

/// Exact v1 receipt, decoded before any JSON object can collapse duplicate keys.
#[derive(Deserialize, Serialize)]
struct BatchLookupReceipt {
    version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    store_id: Option<String>,
    request_id: String,
    #[serde(deserialize_with = "json_objects")]
    jobs: Vec<BatchLookupJob>,
    #[serde(
        default,
        deserialize_with = "present_objects",
        skip_serializing_if = "Option::is_none"
    )]
    preconditions: Option<Vec<crate::run_status::Target>>,
}

/// Mutating batch acknowledgement, with every receipt object decoded strictly.
#[derive(Deserialize, Serialize)]
struct BatchStartResult {
    replayed: bool,
    #[serde(deserialize_with = "json_object")]
    receipt: BatchLookupReceipt,
}

/// Read-only lookup result; missing and null receipts are deliberately distinct.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchLookupResult {
    found: bool,
    #[serde(default, deserialize_with = "present_object")]
    receipt: Option<BatchLookupReceipt>,
}

/// Accepts a missing object but rejects an explicit null or positional array.
fn present_object<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    json_object(deserializer).map(Some)
}

/// Accepts an omitted list but rejects null or non-object entries.
fn present_objects<'de, D, T>(deserializer: D) -> Result<Option<Vec<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    json_objects(deserializer).map(Some)
}

/// Reads an exact frozen batch receipt without initiating or retrying any Run work.
/// `None` means absent at the read snapshot, not proof of a definitive refusal.
/// The store ID must be part of the original frozen intent, never added to an older request.
pub async fn batch_receipt(
    config: &Config,
    request_key: &str,
    jobs: &[crate::domain::BatchJob],
    retain_history: bool,
    expected_store_id: Option<&str>,
) -> Result<Option<Vec<BatchAdmission>>, RunFailure> {
    let expected_store_id = expected_store_id.ok_or(RunFailure::unknown())?;
    crate::domain::store_id(expected_store_id).map_err(|_| RunFailure::unknown())?;
    if jobs.is_empty() || jobs.len() > crate::domain::MAX_MEMBERS {
        return Err(RunFailure::unknown());
    }
    let reply: BatchLookupResult = run_rpc_typed(
        config,
        "batch_receipt",
        batch_params(request_key, jobs, retain_history, Some(expected_store_id)),
    )
    .await
    .map_err(|_| RunFailure::unknown())?;
    match (reply.found, reply.receipt) {
        (false, None) => Ok(None),
        (true, Some(receipt)) => {
            let receipt = serde_json::to_value(receipt).map_err(|_| RunFailure::unknown())?;
            validate_batch_receipt(
                &receipt,
                request_key,
                jobs.len(),
                retain_history,
                Some(expected_store_id),
                None,
            )
            .map(Some)
        }
        _ => Err(RunFailure::unknown()),
    }
}

/// Looks up one original conditioned batch without admitting or restarting any work.
pub async fn batch_receipt_with_preconditions(
    config: &Config,
    request_key: &str,
    jobs: &[crate::domain::BatchJob],
    retain_history: bool,
    expected_store_id: &str,
    preconditions: &[crate::run_status::Target],
) -> Result<Option<Vec<BatchAdmission>>, RunFailure> {
    let params = preconditioned_batch_params(
        request_key,
        jobs,
        retain_history,
        expected_store_id,
        preconditions,
    )?;
    let reply: BatchLookupResult = run_rpc_typed(config, "batch_receipt", params)
        .await
        .map_err(|_| RunFailure::unknown())?;
    match (reply.found, reply.receipt) {
        (false, None) => Ok(None),
        (true, Some(receipt)) => {
            let receipt = serde_json::to_value(receipt).map_err(|_| RunFailure::unknown())?;
            validate_batch_receipt(
                &receipt,
                request_key,
                jobs.len(),
                retain_history,
                Some(expected_store_id),
                Some(preconditions),
            )
            .map(Some)
        }
        _ => Err(RunFailure::unknown()),
    }
}

/// Reads one fenced Run snapshot; returned evidence is historical and grants no participant authority.
pub async fn run_status(
    config: &Config,
    expected_store_id: &str,
    targets: &[crate::run_status::Target],
) -> Result<crate::run_status::StatusEvidence, RunFailure> {
    crate::run_status::validate_request(expected_store_id, targets)
        .map_err(|_| RunFailure::unknown())?;
    let response: crate::run_status::StatusResponse = run_rpc_typed(
        config,
        "status",
        json!({"version":1,"expected_store_id":expected_store_id,"targets":targets,"include_view":false}),
    )
    .await
    .map_err(|_| RunFailure::unknown())?;
    crate::run_status::validate_response(response, expected_store_id, targets)
        .map_err(|_| RunFailure::unknown())
}

/// Requires a mutation acknowledgement before checking every correlated batch receipt row.
fn parse_batch_receipt(
    reply: &Value,
    request_key: &str,
    expected_count: usize,
    retain_history: bool,
    expected_store_id: Option<&str>,
    preconditions: Option<&[crate::run_status::Target]>,
) -> Result<Vec<BatchAdmission>, RunFailure> {
    if reply.get("replayed").and_then(Value::as_bool).is_none() {
        return Err(RunFailure::unknown());
    }
    let receipt = reply.get("receipt").ok_or(Fault::Unavailable)?;
    validate_batch_receipt(
        receipt,
        request_key,
        expected_count,
        retain_history,
        expected_store_id,
        preconditions,
    )
}

/// Correlates every receipt row and rejects missing, aliased or cross-store identities.
fn validate_batch_receipt(
    receipt: &Value,
    request_key: &str,
    expected_count: usize,
    retain_history: bool,
    expected_store_id: Option<&str>,
    preconditions: Option<&[crate::run_status::Target]>,
) -> Result<Vec<BatchAdmission>, RunFailure> {
    let receipt = receipt.as_object().ok_or(Fault::Unavailable)?;
    if receipt.get("version").and_then(Value::as_u64) != Some(1)
        || receipt.get("request_id").and_then(Value::as_str) != Some(request_key)
    {
        return Err(RunFailure::unknown());
    }
    match (preconditions, receipt.get("preconditions")) {
        (None, None) => {}
        (Some(expected), Some(actual))
            if serde_json::to_value(expected).map_err(|_| RunFailure::unknown())? == *actual => {}
        _ => return Err(RunFailure::unknown()),
    }
    if let Some(expected) = expected_store_id {
        crate::domain::store_id(expected).map_err(|_| RunFailure::unknown())?;
        if receipt.get("store_id").and_then(Value::as_str) != Some(expected) {
            return Err(RunFailure::unknown());
        }
    }
    let results = receipt
        .get("jobs")
        .and_then(Value::as_array)
        .ok_or(Fault::Unavailable)?;
    if results.len() != expected_count {
        return Err(RunFailure::unknown());
    }
    let mut seen = BTreeSet::new();
    let mut seen_refs = BTreeSet::new();
    let mut seen_pins = BTreeSet::new();
    let mut admissions = Vec::with_capacity(results.len());
    for (index, result) in results.iter().enumerate() {
        let agent_id = result
            .get("agent_id")
            .and_then(Value::as_str)
            .filter(|value| crate::run_status::valid_agent_id(value))
            .ok_or(Fault::Unavailable)?;
        let sequence = result
            .get("sequence")
            .and_then(Value::as_u64)
            .filter(|v| *v > 0 && *v <= u32::MAX as u64)
            .ok_or(Fault::Unavailable)?;
        let execution_ref = result
            .get("execution_ref")
            .and_then(Value::as_str)
            .ok_or(Fault::Unavailable)?;
        crate::domain::execution_ref(execution_ref).map_err(|_| RunFailure::unknown())?;
        let pin = match result.get("pin_id") {
            None if !retain_history => None,
            Some(Value::String(value)) if retain_history => {
                crate::domain::pin_id(value).map_err(|_| RunFailure::unknown())?;
                if !seen_pins.insert(value) {
                    return Err(RunFailure::unknown());
                }
                Some(value.clone())
            }
            _ => return Err(RunFailure::unknown()),
        };
        if result.get("index").and_then(Value::as_u64) != Some(index as u64)
            || !seen.insert(agent_id)
            || !seen_refs.insert(execution_ref)
        {
            return Err(RunFailure::unknown());
        }
        admissions.push(BatchAdmission {
            agent_id: agent_id.to_owned(),
            sequence,
            execution_ref: execution_ref.to_owned(),
            pin_id: pin,
        });
    }
    Ok(admissions)
}

/// Sampled generic Run projection; its address is never sufficient authorization.
#[allow(
    dead_code,
    reason = "Diagnostic observation is retained but cannot authorize membership"
)]
pub struct RunObservation {
    /// Canonical sampled address when Run reported an observation.
    pub address: Option<String>,
    /// Finite safe state; unknown or unsupported never implies completion.
    pub runtime: String,
}

/// Samples the selected Run sequence; this alone does not prove execution or attempt identity.
#[allow(
    dead_code,
    reason = "Awaiting attempt-bound identity proof before operational use"
)]
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

    /// Hold envelopes reject null branches while other Run methods retain their prior parser.
    #[test]
    fn hold_envelope_null_branches_do_not_change_legacy_parsing() {
        let success = br#"{"jsonrpc":"2.0","id":7,"result":{}}"#;
        let failure = br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32602,"message":"invalid"}}"#;
        let success_with_null = br#"{"jsonrpc":"2.0","id":7,"result":{},"error":null}"#;
        let failure_with_null = br#"{"jsonrpc":"2.0","id":7,"result":null,"error":{"code":-32602,"message":"invalid"}}"#;
        assert!(strict_hold_envelope(success, 7));
        assert!(strict_hold_envelope(failure, 7));
        assert!(!strict_hold_envelope(success_with_null, 7));
        assert!(!strict_hold_envelope(failure_with_null, 7));
        assert!(serde_json::from_slice::<JsonObject<RunReply<Value>>>(success_with_null).is_ok());
        assert!(serde_json::from_slice::<JsonObject<RunReply<Value>>>(failure_with_null).is_ok());
    }

    #[test]
    fn hold_conflict_requires_exact_correlated_unambiguous_refusal() {
        let good = br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"refused","data":{"code":"RequestConflict"}}}"#;
        let duplicate = br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"refused","data":{"code":"RequestConflict","code":"RequestConflict"}}}"#;
        let other = br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"refused","data":{"code":"StateTransitionError"}}}"#;
        assert!(strict_hold_conflict(good, 7));
        assert!(!strict_hold_conflict(good, 8));
        assert!(!strict_hold_conflict(duplicate, 7));
        assert!(!strict_hold_conflict(other, 7));
    }
    /// A wall-clock rollback cannot extend an invocation beyond its original monotonic lifetime.
    #[test]
    fn invocation_expiry_fences_both_clocks() -> Result<(), Box<dyn std::error::Error>> {
        let now = Instant::now();
        let expiry = InvocationExpiry {
            wall_expiry: Duration::from_secs(1_000),
            monotonic_deadline: now + Duration::from_millis(20),
        };
        assert!(expiry.remaining_at(Duration::from_secs(999), now).is_ok());
        assert!(matches!(
            expiry.remaining_at(Duration::from_secs(900), now + Duration::from_millis(20)),
            Err(Fault::Unauthorized)
        ));
        assert!(matches!(
            expiry.remaining_at(Duration::from_secs(1_000), now),
            Err(Fault::Unauthorized)
        ));
        let wall = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
        let anchored = InvocationExpiry::new(
            wall,
            wall + 5_000,
            wall + 4_900,
            now,
            Duration::from_millis(wall),
        )?;
        assert_eq!(anchored.monotonic_deadline, now + Duration::from_millis(99));
        assert!(matches!(
            InvocationExpiry::new(
                wall,
                wall + 5_000,
                wall + 4_999,
                now,
                Duration::from_millis(wall)
            ),
            Err(Fault::Unauthorized)
        ));
        assert!(matches!(
            InvocationExpiry::new(
                wall + 2,
                wall + 5_000,
                wall + 1,
                now,
                Duration::from_millis(wall + 2)
            ),
            Err(Fault::Unauthorized)
        ));
        assert!(matches!(
            InvocationExpiry::new(
                wall + 1,
                wall + 5_000,
                wall + 2,
                now,
                Duration::from_millis(wall)
            ),
            Err(Fault::Unauthorized)
        ));
        let capped =
            InvocationExpiry::new(wall, wall + 180_000, wall, now, Duration::from_millis(wall))?;
        assert_eq!(
            capped.monotonic_deadline,
            now + Duration::from_millis(29_999)
        );
        Ok(())
    }

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
            bridge_server_executable: "/fixture/bridge".into(),
            bridge_server_sha256: "0".repeat(64),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            owner_observer_credential_file: None,
            run_socket: Some(path.join("run.sock")),
            run_peer_uid: None,
            managed_run_reader: None,
            managed_run_transport: None,
        }
    }

    /// The status transport preserves exact selectors and rejects duplicate proof fields.
    #[tokio::test]
    async fn run_status_transport_validates_typed_snapshot()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory =
            tempfile::tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let uid = std::fs::metadata(directory.path())?.uid();
        let config = fixture_config(directory.path(), uid);
        let socket = config.run_socket.as_ref().ok_or("missing socket")?;
        let listener = tokio::net::UnixListener::bind(socket)?;
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
        let store = format!("store_{}", "1".repeat(32));
        let target = crate::run_status::Target {
            agent_id: "ag-20261107-010101-0123456789".into(),
            sequence: 1,
            execution_ref: format!("ex1_{}", "a".repeat(64)),
            pin_id: format!("pin_{}", uuid::Uuid::new_v4().simple()),
        };
        assert!(run_status(&config, &store, &[]).await.is_err());
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
        let fact =
            json!({"sequence":1,"execution_ref":target.execution_ref,"raw_status":"succeeded"});
        let result = json!({
            "version":1,"store_id":store,"observed_at":1.0,
            "items":[{
                "selector":target,"canonical_agent_id":target.agent_id,"match":"verified",
                "pin_id":target.pin_id,"pin_state":"active","selected":fact,
                "retained_latest":fact,"coverage":"complete","restart_resume":"none",
                "lineage_terminal":true,"terminal_outcome":"succeeded",
                "success_commit":"recorded","cleanup":{"scope":"lineage","state":"confirmed"}
            }]
        });
        let (first, second, third, served) = tokio::time::timeout(Duration::from_secs(20), async {
            let calls = async {
                let first = run_status(&config, &store, std::slice::from_ref(&target)).await;
                let second = run_status(&config, &store, std::slice::from_ref(&target)).await;
                let third = run_status(&config, &store, std::slice::from_ref(&target)).await;
                (first, second, third)
            };
            let server = async {
                for index in 0..3 {
                    let (mut stream, _) = listener.accept().await?;
                    let request: Value = serde_json::from_slice(&read_frame(&mut stream).await?)?;
                    assert_eq!(request["method"], "status");
                    assert_eq!(request["params"], json!({"version":1,"expected_store_id":store,"targets":[target],"include_view":false}));
                    let mut encoded = serde_json::to_string(&result)?;
                    if index == 1 {
                        let duplicate = encoded.replacen("\"version\":1", "\"version\":1,\"version\":1", 1);
                        assert_ne!(duplicate, encoded);
                        encoded = duplicate;
                    } else if index == 2 {
                        encoded = serde_json::to_string(&json!([1, store, 1.0, result["items"], null]))?;
                    }
                    let reply = format!("{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{encoded}}}\n", request["id"]);
                    stream.write_all(reply.as_bytes()).await?;
                }
                Ok::<_, Box<dyn std::error::Error>>(())
            };
            let ((first, second, third), served) = tokio::join!(calls, server);
            (first, second, third, served)
        }).await?;
        served?;
        let evidence = first.map_err(|_| "valid proof rejected")?;
        assert_eq!(evidence.store_id(), store);
        assert!(
            evidence
                .items()
                .next()
                .ok_or("missing item")?
                .proves_historical_success()
        );
        assert!(
            !second
                .err()
                .ok_or("duplicate proof accepted")?
                .known_unadmitted
        );
        assert!(!third.err().ok_or("array proof accepted")?.known_unadmitted);
        Ok(())
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
                let reply = json!({"jsonrpc":"2.0","id":reply_id,"result":{"agent_id":"ag-20261107-010101-0000000008","sequence":2,"created":index == 0,"agent":{"agent_id":"ag-20261107-010101-0000000008","sequence":2}}});
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

    /// Read-only lookup rejects positional arrays and duplicate keys before receipt validation.
    #[test]
    fn batch_receipt_requires_objects_without_duplicate_keys() {
        let valid = r#"{"found":true,"receipt":{"version":1,"store_id":"store","request_id":"key","jobs":[{"index":0,"agent_id":"agent","sequence":1,"execution_ref":"ref","pin_id":"pin"}]}}"#;
        assert!(serde_json::from_str::<JsonObject<BatchLookupResult>>(valid).is_ok());
        let duplicate = valid.replacen(r#""found":true"#, r#""found":true,"found":true"#, 1);
        let duplicate_receipt = valid.replacen(r#""version":1"#, r#""version":1,"version":1"#, 1);
        let result_array =
            r#"[true,{"version":1,"store_id":"store","request_id":"key","jobs":[]}]"#;
        let receipt_array = r#"{"found":true,"receipt":[1,"store","key",[]]}"#;
        let job_array = r#"{"found":true,"receipt":{"version":1,"store_id":"store","request_id":"key","jobs":[[0,"agent",1,"ref","pin"]]}}"#;
        for invalid in [
            duplicate.as_str(),
            duplicate_receipt.as_str(),
            result_array,
            receipt_array,
            job_array,
        ] {
            assert!(serde_json::from_str::<JsonObject<BatchLookupResult>>(invalid).is_err());
        }
        let start = r#"{"replayed":false,"receipt":{"version":1,"request_id":"key","jobs":[{"index":0,"agent_id":"agent","sequence":1,"execution_ref":"ref"}],"future":"ignored"}}"#;
        assert!(serde_json::from_str::<JsonObject<BatchStartResult>>(start).is_ok());
        let duplicate_start = start.replacen(r#""version":1"#, r#""version":1,"version":1"#, 1);
        assert!(serde_json::from_str::<JsonObject<BatchStartResult>>(&duplicate_start).is_err());
    }

    /// Read-only receipt lookup preserves the frozen request and rejects uncertain evidence.
    #[tokio::test]
    async fn batch_receipt_lookup_validates_exact_fenced_snapshot()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::Builder::new()
            .prefix("batch-lookup-")
            .tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let uid = std::fs::metadata(directory.path())?.uid();
        own_uid(uid)?;
        let config = fixture_config(directory.path(), uid);
        let socket = config.run_socket.as_ref().ok_or("missing fixture socket")?;
        let listener = std::os::unix::net::UnixListener::bind(socket)?;
        listener.set_nonblocking(true)?;
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;

        let store = format!("store_{}", "1".repeat(32));
        let pin_one = format!("pin_{}", uuid::Uuid::new_v4().simple());
        let pin_two = format!("pin_{}", uuid::Uuid::new_v4().simple());
        let jobs = vec![
            crate::domain::BatchJob {
                member_id: "local-one".into(),
                spec: json!({"task":"frozen first","model":"one"}),
                original_spec: None,
            },
            crate::domain::BatchJob {
                member_id: "local-two".into(),
                spec: json!({"task":"frozen second","model":"two"}),
                original_spec: None,
            },
        ];
        for fence in [None, Some("not-a-store")] {
            let failure = tokio::time::timeout(
                Duration::from_secs(1),
                batch_receipt(&config, "key", &jobs, true, fence),
            )
            .await?
            .err()
            .ok_or("invalid fence accepted")?;
            assert_eq!(failure, RunFailure::unknown());
        }
        assert!(matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
        let listener = tokio::net::UnixListener::from_std(listener)?;
        let receipt = json!({"version":1,"request_id":"key","store_id":store,"jobs":[
            {"index":0,"agent_id":"ag-20261107-010101-0000000001","sequence":1,"execution_ref":format!("ex1_{}","a".repeat(64)),"pin_id":pin_one},
            {"index":1,"agent_id":"ag-20261107-010101-0000000002","sequence":2,"execution_ref":format!("ex1_{}","b".repeat(64)),"pin_id":pin_two}
        ]});
        let mut unretained = receipt.clone();
        for row in unretained["jobs"].as_array_mut().ok_or("jobs array")? {
            row.as_object_mut().ok_or("job object")?.remove("pin_id");
        }
        let mut wrong_key = receipt.clone();
        wrong_key["request_id"] = json!("other-key");
        let mut wrong_store = receipt.clone();
        wrong_store["store_id"] = json!(format!("store_{}", "2".repeat(32)));
        let mut partial = receipt.clone();
        partial["jobs"].as_array_mut().ok_or("jobs array")?.pop();
        let mut duplicate_pin = receipt.clone();
        duplicate_pin["jobs"][1]["pin_id"] = json!(pin_one);
        let mut invalid_agent = receipt.clone();
        invalid_agent["jobs"][0]["agent_id"] = json!("agent-new");
        let responses = vec![
            Some(json!({"result":{"found":true,"receipt":receipt}})),
            Some(json!({"result":{"found":true,"receipt":unretained}})),
            Some(json!({"result":{"found":false}})),
            Some(json!({"result":{}})),
            Some(json!({"result":{"found":"true"}})),
            Some(json!({"result":{"found":true}})),
            Some(json!({"result":{"found":false,"receipt":null}})),
            Some(json!({"result":{"found":false,"receipt":receipt}})),
            Some(json!({"result":{"found":true,"receipt":wrong_key}})),
            Some(json!({"result":{"found":true,"receipt":wrong_store}})),
            Some(json!({"result":{"found":true,"receipt":partial}})),
            Some(json!({"result":{"found":true,"receipt":duplicate_pin}})),
            Some(json!({"result":{"found":true,"receipt":invalid_agent}})),
            Some(json!({"error":{"code":-32602,"message":"private-canary"}})),
            None,
        ];
        let response_count = responses.len();
        let responder = tokio::spawn(async move {
            let mut requests = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().await?;
                let request: Value = serde_json::from_slice(&read_frame(&mut stream).await?)?;
                if let Some(mut response) = response {
                    response["jsonrpc"] = json!("2.0");
                    response["id"] = request["id"].clone();
                    let mut bytes = serde_json::to_vec(&response)?;
                    bytes.push(b'\n');
                    stream.write_all(&bytes).await?;
                }
                requests.push(request);
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(requests)
        });

        for index in 0..response_count {
            let result = batch_receipt(&config, "key", &jobs, index != 1, Some(&store)).await;
            match index {
                0 | 1 => {
                    let admitted = result
                        .map_err(|_| "valid receipt rejected")?
                        .ok_or("valid receipt absent")?;
                    assert_eq!(admitted.len(), 2);
                    assert_eq!(admitted[0].agent_id, "ag-20261107-010101-0000000001");
                    assert_eq!(admitted[1].sequence, 2);
                    assert_eq!(admitted[0].execution_ref, format!("ex1_{}", "a".repeat(64)));
                    assert_eq!(
                        admitted[0].pin_id.as_deref(),
                        (index == 0).then_some(pin_one.as_str())
                    );
                    assert_eq!(
                        admitted[1].pin_id.as_deref(),
                        (index == 0).then_some(pin_two.as_str())
                    );
                }
                2 => assert!(matches!(result, Ok(None))),
                _ => {
                    let failure = result.err().ok_or("uncertain reply accepted")?;
                    assert_eq!(failure, RunFailure::unknown());
                    assert!(!format!("{failure:?}").contains("private-canary"));
                }
            }
        }
        let requests = responder.await?.map_err(|_| "fixture responder failed")?;
        for (index, request) in requests.iter().enumerate() {
            assert_eq!(request["method"], "batch_receipt");
            let mut expected = json!({"request_id":"key","jobs":[
                {"task":"frozen first","model":"one"},
                {"task":"frozen second","model":"two"}
            ],"expected_store_id":store});
            if index != 1 {
                expected["retain_history"] = json!(true);
            }
            assert_eq!(request["params"], expected);
        }
        Ok(())
    }

    /// Same-user Run connections retain the private policy even when its UID is explicit.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn same_uid_run_peer_keeps_private_socket_policy()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory =
            tempfile::tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let uid = std::fs::metadata(directory.path())?.uid();
        let mut config = fixture_config(directory.path(), uid);
        let socket = directory.path().join("run.sock");
        let _listener = tokio::net::UnixListener::bind(&socket)?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
        drop(connect_run(&config, &socket).await?);
        config.run_peer_uid = Some(uid);
        drop(connect_run(&config, &socket).await?);
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660))?;
        assert!(matches!(
            connect_run(&config, &socket).await,
            Err(Fault::Unavailable)
        ));
        config.run_peer_uid = None;
        assert!(matches!(
            connect_run(&config, &socket).await,
            Err(Fault::Unavailable)
        ));
        Ok(())
    }

    /// A wrong kernel peer UID is rejected before the peer receives any request bytes.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn run_peer_mismatch_sends_no_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let (client, mut server) = UnixStream::pair()?;
        let uid = client.peer_cred()?.uid();
        check_run_peer(&client, uid)?;
        assert!(matches!(
            check_run_peer(&client, uid ^ 1),
            Err(Fault::Unavailable)
        ));
        drop(client);
        let mut bytes = Vec::new();
        server.read_to_end(&mut bytes).await?;
        assert!(bytes.is_empty());
        Ok(())
    }

    /// A remapped UID namespace refuses a cross-user Run connection before reaching its listener.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn remapped_run_uid_is_rejected_before_connect() -> Result<(), Box<dyn std::error::Error>>
    {
        if crate::config::identity_uid_map().is_ok() {
            return Ok(());
        }
        let directory =
            tempfile::tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        let socket = directory.path().join("run.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket)?;
        listener.set_nonblocking(true)?;
        let (local, _peer) = UnixStream::pair()?;
        let uid = local.peer_cred()?.uid();
        let mut config = fixture_config(directory.path(), uid ^ 1);
        config.run_peer_uid = Some(uid);
        assert!(matches!(
            connect_run(&config, &socket).await,
            Err(Fault::Unavailable)
        ));
        assert!(matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
        Ok(())
    }

    /// Opt-in read of one explicitly identified live Run agent through the production client.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires explicitly supplied live Run endpoint and task-owned agent identity"]
    async fn live_run_observe() -> Result<(), Box<dyn std::error::Error>> {
        let socket = std::env::var_os("AGENT_POOL_LIVE_RUN_SOCKET")
            .ok_or("AGENT_POOL_LIVE_RUN_SOCKET is required")?;
        let peer_uid: u32 = std::env::var("AGENT_POOL_LIVE_RUN_PEER_UID")?.parse()?;
        let agent_id = std::env::var("AGENT_POOL_LIVE_RUN_AGENT_ID")?;
        let sequence: u64 = std::env::var("AGENT_POOL_LIVE_RUN_SEQUENCE")?.parse()?;
        let expected = std::env::var("AGENT_POOL_LIVE_RUN_EXPECTED_RUNTIME")?;
        if agent_id.is_empty()
            || agent_id.len() > 256
            || sequence == 0
            || sequence > u64::from(u32::MAX)
            || peer_uid == u32::MAX
            || !matches!(
                expected.as_str(),
                "active" | "unknown" | "succeeded" | "failed" | "lost" | "cancelled"
            )
        {
            return Err("invalid live Run smoke inputs".into());
        }
        let (local, _peer) = UnixStream::pair()?;
        let uid = local.peer_cred()?.uid();
        let mut config = fixture_config(Path::new("/unused"), uid);
        config.run_socket = Some(socket.into());
        config.run_peer_uid = Some(peer_uid);
        let observation = run_observe(&config, &agent_id, sequence).await?;
        assert_eq!(observation.runtime, expected);
        Ok(())
    }

    /// Checks lookup and status against a fresh fake-engine Run owned by an external cleanup runner.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires a task-owned synthetic Run fixture with batch_receipt and status"]
    async fn live_synthetic_run_receipt_and_status() -> Result<(), Box<dyn std::error::Error>> {
        use crate::domain::BatchJob;
        /// Reads a correlated error code from the fixture without invoking a mutating method.
        async fn lookup_error(
            config: &Config,
            key: &str,
            jobs: &[BatchJob],
            store: &str,
        ) -> Result<String, Box<dyn std::error::Error>> {
            let socket = config.run_socket.as_ref().ok_or("fixture socket missing")?;
            let mut stream = connect_run(config, socket).await?;
            let mut request = serde_json::to_vec(&json!({
                "jsonrpc":"2.0","id":1,"method":"batch_receipt",
                "params":batch_params(key, jobs, true, Some(store))
            }))?;
            request.push(b'\n');
            stream.write_all(&request).await?;
            let reply: Value = serde_json::from_slice(&read_frame(&mut stream).await?)?;
            if reply["id"] != 1 || reply.get("result").is_some() {
                return Err("invalid lookup error envelope".into());
            }
            Ok(reply
                .pointer("/error/data/code")
                .and_then(Value::as_str)
                .ok_or("missing lookup error code")?
                .to_owned())
        }
        let root =
            std::fs::canonicalize(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        let home = std::fs::canonicalize(
            std::env::var_os("AGENT_POOL_SYNTHETIC_RUN_HOME").ok_or("fixture home required")?,
        )?;
        if home == root
            || !home.starts_with(&root)
            || std::fs::read_to_string(home.join(".pool-synthetic-run"))?
                != "agent-pool synthetic fixture\n"
        {
            return Err("refusing non-fixture Run home".into());
        }
        let fixture_binary = std::fs::canonicalize(
            std::env::var_os("AGENT_POOL_SYNTHETIC_RUN_FIXTURE_BINARY")
                .ok_or("fake engine binary required")?,
        )?;
        let fixture_settings: toml::Value =
            toml::from_str(&std::fs::read_to_string(home.join("config.toml"))?)?;
        let configured_binary = fixture_settings
            .get("harnesses")
            .and_then(|harnesses| harnesses.get("claude-code"))
            .and_then(|harness| harness.get("binary"))
            .and_then(toml::Value::as_str)
            .ok_or("fake engine configuration missing")?;
        if fixture_binary.file_name().and_then(|name| name.to_str()) != Some("agent-run-fixture")
            || std::fs::canonicalize(configured_binary)? != fixture_binary
            || fixture_settings
                .get("providers")
                .and_then(|providers| providers.get("glm-user"))
                .and_then(|provider| provider.get("harness"))
                .and_then(toml::Value::as_str)
                != Some("claude-code")
        {
            return Err("refusing non-fixture engine configuration".into());
        }
        let counts = || -> rusqlite::Result<Vec<i64>> {
            let db = rusqlite::Connection::open_with_flags(
                home.join("state.db"),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )?;
            ["agents", "attempts", "start_batch_receipts", "history_pins"]
                .into_iter()
                .map(|table| {
                    db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })
                })
                .collect()
        };
        let before = counts()?;
        if before != [0, 0, 0, 0] {
            return Err("fixture Run database must be empty".into());
        }
        let (local, _peer) = UnixStream::pair()?;
        let mut config = fixture_config(&home, local.peer_cred()?.uid());
        config.run_socket = Some(home.join("api.sock"));
        let store = run_store_identity(&config)
            .await
            .map_err(|error| format!("store preflight failed: {}", error.code))?;
        let key = format!("pool-synthetic-lookup-{}", uuid::Uuid::new_v4().simple());
        let jobs = vec![BatchJob {
            member_id: "fixture-single".into(),
            spec: json!({"provider":"glm-user","model":"fixture","profile":"review","explicit_finish":false,"task":"fixture:answer","workdir":home}),
            original_spec: None,
        }];
        assert!(
            batch_receipt(&config, &key, &jobs, true, Some(&store))
                .await
                .map_err(|error| format!("missing lookup failed: {}", error.code))?
                .is_none()
        );
        assert_eq!(
            counts()?,
            before,
            "missing lookup must not create Run state"
        );
        let admitted = start_batch(&config, &key, &jobs, true, Some(&store))
            .await
            .map_err(|error| format!("batch failed: {}", error.code))?;
        let first = admitted.first().ok_or("missing admission")?;
        let pin = first.pin_id.as_deref().ok_or("missing pin")?;
        let lookup = batch_receipt(&config, &key, &jobs, true, Some(&store))
            .await
            .map_err(|error| format!("receipt lookup failed: {}", error.code))?
            .ok_or("accepted receipt absent")?;
        assert_eq!(lookup.len(), 1);
        assert_eq!(lookup[0].agent_id, first.agent_id);
        assert_eq!(lookup[0].sequence, first.sequence);
        assert_eq!(lookup[0].execution_ref, first.execution_ref);
        assert_eq!(lookup[0].pin_id, first.pin_id);
        let mut changed = jobs.clone();
        changed[0].spec["task"] = json!("fixture:different");
        assert!(
            batch_receipt(&config, &key, &changed, true, Some(&store))
                .await
                .is_err()
        );
        assert_eq!(
            lookup_error(&config, &key, &changed, &store).await?,
            "RequestConflict"
        );
        let wrong_store = if store == format!("store_{}", "0".repeat(32)) {
            format!("store_{}", "1".repeat(32))
        } else {
            format!("store_{}", "0".repeat(32))
        };
        assert!(
            batch_receipt(&config, &key, &jobs, true, Some(&wrong_store))
                .await
                .is_err()
        );
        assert_eq!(
            lookup_error(&config, &key, &jobs, &wrong_store).await?,
            "StoreIdentityMismatch"
        );
        let target = crate::run_status::Target {
            agent_id: first.agent_id.clone(),
            sequence: u32::try_from(first.sequence)?,
            execution_ref: first.execution_ref.clone(),
            pin_id: pin.to_owned(),
        };
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let snapshot = run_status(&config, &store, std::slice::from_ref(&target))
                    .await
                    .map_err(|error| format!("status failed: {}", error.code))?;
                if snapshot
                    .items()
                    .all(|item| item.proves_historical_success())
                {
                    break Ok::<_, String>(());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await??;
        assert_eq!(
            counts()?,
            [1, 1, 1, 1],
            "lookup and retry must not create additional work or pins"
        );
        release_history_pin(&config, pin, &store)
            .await
            .map_err(|error| format!("pin release failed: {}", error.code))?;
        let after = batch_receipt(&config, &key, &jobs, true, Some(&store))
            .await
            .map_err(|error| format!("post-release lookup failed: {}", error.code))?
            .ok_or("released receipt absent")?;
        assert_eq!(after[0].pin_id.as_deref(), Some(pin));
        let snapshot = run_status(&config, &store, &[target])
            .await
            .map_err(|error| format!("post-release status failed: {}", error.code))?;
        assert!(
            !snapshot
                .items()
                .any(|item| item.proves_historical_success())
        );
        assert_eq!(counts()?, [1, 1, 1, 1]);
        let db = rusqlite::Connection::open_with_flags(
            home.join("state.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let released: i64 = db.query_row(
            "SELECT released FROM history_pins WHERE pin_id=?1",
            [pin],
            |row| row.get(0),
        )?;
        assert_eq!(released, 1);
        Ok(())
    }

    /// Exercises the production Pool batch client against an explicitly isolated fake-engine Run.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires a task-owned synthetic Run fixture and fake engine"]
    async fn live_synthetic_run_batch() -> Result<(), Box<dyn std::error::Error>> {
        use crate::domain::BatchJob;
        let root =
            std::fs::canonicalize(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        let home = std::fs::canonicalize(
            std::env::var_os("AGENT_POOL_SYNTHETIC_RUN_HOME").ok_or("fixture home required")?,
        )?;
        if home == root
            || !home.starts_with(&root)
            || std::fs::read_to_string(home.join(".pool-synthetic-run"))?
                != "agent-pool synthetic fixture\n"
        {
            return Err("refusing non-fixture Run home".into());
        }
        let (local, _peer) = UnixStream::pair()?;
        let uid = local.peer_cred()?.uid();
        let mut config = fixture_config(&home, uid);
        config.run_socket = Some(home.join("api.sock"));
        let expected_store_id = run_store_identity(&config)
            .await
            .map_err(|error| format!("store preflight failed: {}", error.code))?;
        let wrong_store_id = if expected_store_id == format!("store_{}", "0".repeat(32)) {
            format!("store_{}", "1".repeat(32))
        } else {
            format!("store_{}", "0".repeat(32))
        };
        let job = |index: usize| BatchJob {
            member_id: format!("fixture-{index}"),
            spec: json!({"provider":"glm-user","model":"fixture","profile":"review","explicit_finish":false,"task":"fixture:answer","workdir":home}),
            original_spec: None,
        };
        let failed: Vec<_> = (0..4).map(job).collect();
        let wrong_store_jobs: Vec<_> = (0..1).map(job).collect();
        let mismatch = match start_batch(
            &config,
            "pool-synthetic-mismatch",
            &wrong_store_jobs,
            true,
            Some(&wrong_store_id),
        )
        .await
        {
            Ok(_) => return Err("wrong Run store unexpectedly admitted work".into()),
            Err(error) => error,
        };
        assert!(!mismatch.known_unadmitted);
        let error = match start_batch(
            &config,
            "pool-synthetic-reject",
            &failed,
            true,
            Some(&expected_store_id),
        )
        .await
        {
            Ok(_) => return Err("over-capacity batch unexpectedly admitted".into()),
            Err(error) => error,
        };
        assert_eq!(error.code, "CapacityExhausted");
        assert!(!error.known_unadmitted);
        let db = rusqlite::Connection::open_with_flags(
            home.join("state.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        for table in ["agents", "attempts", "start_batch_receipts", "history_pins"] {
            let count: i64 = db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })?;
            assert_eq!(count, 0, "rejected batch must roll back {table}");
        }
        drop(db);
        let jobs: Vec<_> = (0..2).map(job).collect();
        let first = start_batch(
            &config,
            "pool-synthetic-accept",
            &jobs,
            true,
            Some(&expected_store_id),
        )
        .await
        .map_err(|error| format!("batch failed: {}", error.code))?;
        let replay = start_batch(
            &config,
            "pool-synthetic-accept",
            &jobs,
            true,
            Some(&expected_store_id),
        )
        .await
        .map_err(|error| format!("replay failed: {}", error.code))?;
        assert_eq!(first.len(), 2);
        for (first, replay) in first.iter().zip(&replay) {
            assert_eq!(first.agent_id, replay.agent_id);
            assert_eq!(first.sequence, replay.sequence);
            assert_eq!(first.execution_ref, replay.execution_ref);
            assert_eq!(first.pin_id, replay.pin_id);
            assert!(first.pin_id.is_some());
        }
        assert_ne!(first[0].agent_id, first[1].agent_id);
        assert_ne!(first[0].execution_ref, first[1].execution_ref);
        assert_ne!(first[0].pin_id, first[1].pin_id);
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let db = rusqlite::Connection::open_with_flags(home.join("state.db"), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
                let agents: i64 = db.query_row("SELECT COUNT(*) FROM agents WHERE status='succeeded' AND supervisor_pid IS NOT NULL", [], |row| row.get(0))?;
                let active: i64 = db.query_row("SELECT COUNT(*) FROM attempts WHERE ownership_active=1", [], |row| row.get(0))?;
                let receipts: i64 = db.query_row("SELECT COUNT(*) FROM start_batch_receipts", [], |row| row.get(0))?;
                let pins: i64 = db.query_row("SELECT COUNT(*) FROM history_pins WHERE released=0", [], |row| row.get(0))?;
                drop(db);
                if agents == 2 && active == 0 && receipts == 1 && pins == 2 { break Ok::<_, rusqlite::Error>(()); }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }).await??;
        let pin = first[0].pin_id.as_deref().ok_or("missing retained pin")?;
        assert!(
            run_rpc(
                &config,
                "history_pins",
                json!({"action":"release","pin_id":pin,"expected_store_id":wrong_store_id})
            )
            .await
            .is_err()
        );
        let db = rusqlite::Connection::open_with_flags(
            home.join("state.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let state: i64 = db.query_row(
            "SELECT released FROM history_pins WHERE pin_id=?1",
            [pin],
            |row| row.get(0),
        )?;
        assert_eq!(state, 0, "wrong store must not release a pin");
        drop(db);
        let released = run_rpc(
            &config,
            "history_pins",
            json!({"action":"release","pin_id":pin,"expected_store_id":expected_store_id}),
        )
        .await
        .map_err(|error| format!("release failed: {}", error.code))?;
        assert_eq!(released["pin_id"], pin);
        assert_eq!(released["status"], "released");
        assert_eq!(released["already_released"], false);
        let repeated = run_rpc(
            &config,
            "history_pins",
            json!({"action":"release","pin_id":pin,"expected_store_id":expected_store_id}),
        )
        .await
        .map_err(|error| format!("release retry failed: {}", error.code))?;
        assert_eq!(repeated["pin_id"], pin);
        assert_eq!(repeated["status"], "released");
        assert_eq!(repeated["already_released"], true);
        let after_release = start_batch(
            &config,
            "pool-synthetic-accept",
            &jobs,
            true,
            Some(&expected_store_id),
        )
        .await
        .map_err(|error| format!("post-release replay failed: {}", error.code))?;
        assert_eq!(after_release[0].pin_id.as_deref(), Some(pin));
        let db = rusqlite::Connection::open_with_flags(
            home.join("state.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let state: i64 = db.query_row(
            "SELECT released FROM history_pins WHERE pin_id=?1",
            [pin],
            |row| row.get(0),
        )?;
        assert_eq!(
            state, 1,
            "replaying admission must not reactivate a released pin"
        );
        Ok(())
    }

    /// Opt-in isolated Bridge custody/status smoke; it does not prove native delivery or identity.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires an isolated Bridge daemon and explicitly provisioned fixture grant"]
    async fn live_bridge_custody() -> Result<(), Box<dyn std::error::Error>> {
        /// Limits every configured input to the explicitly selected task-only directory.
        fn task_path(
            name: &str,
            root: &Path,
        ) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
            let path = std::path::PathBuf::from(
                std::env::var_os(name).ok_or("missing Bridge fixture path")?,
            );
            if !path.is_absolute() || !std::fs::canonicalize(&path)?.starts_with(root) {
                return Err("Bridge fixture path is outside the selected task directory".into());
            }
            Ok(path)
        }

        /// Accepts only the synthetic host, store and exact session for this daemon fixture.
        fn fixture_address(
            value: &str,
            session: &str,
        ) -> Result<NativeAddress, Box<dyn std::error::Error>> {
            let address = NativeAddress::parse(value)?;
            let host_suffix = address
                .host
                .strip_prefix("pooltest")
                .ok_or("invalid fixture host")?;
            if host_suffix.len() != 10
                || !host_suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                || address.store != "isolated"
                || address.session != session
                || address.canonical() != value
            {
                return Err("invalid Bridge fixture address".into());
            }
            Ok(address)
        }

        let root = std::path::PathBuf::from(
            std::env::var_os("AGENT_POOL_LIVE_BRIDGE_TEST_ROOT")
                .ok_or("Bridge fixture root is required")?,
        );
        if !root.is_absolute() {
            return Err("Bridge fixture root must be absolute".into());
        }
        let root = std::fs::canonicalize(root)?;
        let channel = task_path("AGENT_POOL_LIVE_BRIDGE_CHANNEL", &root)?;
        let core = task_path("AGENT_POOL_LIVE_BRIDGE_CORE", &root)?;
        let credential = task_path("AGENT_POOL_LIVE_BRIDGE_TOKEN_FILE", &root)?;
        let producer = std::env::var("AGENT_POOL_LIVE_BRIDGE_PRODUCER")?;
        let allowed = std::env::var("AGENT_POOL_LIVE_BRIDGE_ADDRESS")?;
        let denied = std::env::var("AGENT_POOL_LIVE_BRIDGE_DENIED_ADDRESS")?;
        let allowed_address = fixture_address(&allowed, "never-started")?;
        let denied_address = fixture_address(&denied, "never-allowed")?;
        if allowed_address.host != denied_address.host
            || allowed_address.harness != denied_address.harness
            || producer.is_empty()
        {
            return Err("inconsistent Bridge fixture".into());
        }

        let (local, _peer) = UnixStream::pair()?;
        let mut config = fixture_config(Path::new("/unused"), local.peer_cred()?.uid());
        config.bridge_registration_socket = channel;
        config.bridge_core_socket = core;
        config.bridge_credential_file = credential;
        config.bridge_producer_id = producer.clone();
        let scope = format!("agent-pool-fixture-{}", id());
        let effect = Effect {
            effect_id: format!("agent-pool-fixture-{}", id()),
            pool_id: id(),
            member_id: None,
            work: Work::Deliver {
                address: allowed,
                scope: scope.clone(),
                text: "isolated custody fixture".into(),
            },
            state: "inflight".into(),
        };
        let params = publication(&effect)?;
        assert_eq!(
            deliver(config.clone(), producer.clone(), params.clone(), false).await?,
            "custody"
        );
        let client = bridge(&config, false)?;
        let receipt = |event_id: &str| -> Result<EventReceipt, Box<dyn std::error::Error>> {
            match client.status(
                id(),
                StatusSelector::Event {
                    event_id: event_id.into(),
                },
            )? {
                StatusResult::Event { event: Some(event) } => Ok(event.receipt),
                _ => Err("Bridge fixture receipt missing".into()),
            }
        };
        let initial_receipt = receipt(&effect.effect_id)?;
        assert_eq!(
            deliver(config.clone(), producer.clone(), params.clone(), true).await?,
            "custody"
        );
        assert_eq!(
            deliver(config.clone(), producer.clone(), params.clone(), false).await?,
            "custody"
        );
        assert_eq!(receipt(&effect.effect_id)?, initial_receipt);

        let mut changed = effect.clone();
        if let Work::Deliver { text, .. } = &mut changed.work {
            text.push_str(" changed");
        }
        assert_eq!(
            deliver(
                config.clone(),
                producer.clone(),
                publication(&changed)?,
                false
            )
            .await?,
            "refused"
        );
        assert_eq!(receipt(&effect.effect_id)?, initial_receipt);
        let denied_effect = Effect {
            effect_id: format!("agent-pool-fixture-{}", id()),
            work: Work::Deliver {
                address: denied,
                scope: format!("agent-pool-fixture-{}", id()),
                text: "isolated forbidden fixture".into(),
            },
            ..effect.clone()
        };
        assert_eq!(
            deliver(
                config.clone(),
                producer.clone(),
                publication(&denied_effect)?,
                false
            )
            .await?,
            "refused"
        );
        assert_eq!(
            retire(
                config.clone(),
                format!("agent-pool-fixture-{}", id()),
                scope
            )
            .await?,
            "accepted"
        );
        assert_eq!(deliver(config, producer, params, true).await?, "cancelled");
        assert_eq!(receipt(&effect.effect_id)?, initial_receipt);
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

    /// Run's synthetic store-mismatch response remains unknown and never exposes provider prose.
    #[test]
    fn producer_store_identity_mismatch_stays_unknown() -> Result<(), Box<dyn std::error::Error>> {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/run-status-v1.json"))?;
        let error = &fixture["cases"]["store_identity_mismatch"]["response"]["error"];
        assert_eq!(error["data"]["code"], "StoreIdentityMismatch");
        let failure = RunFailure::from_response(error);
        assert_eq!(failure, RunFailure::unknown());
        assert!(!failure.known_unadmitted);
        Ok(())
    }

    /// Only an unambiguous, correlated first-attempt error can establish a precondition refusal.
    #[test]
    fn precondition_refusal_rejects_duplicate_or_malformed_fields() {
        let valid = br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"refused","data":{"code":"PreconditionFailed","reason":"not_met"}}}"#;
        assert!(strict_precondition_failure(valid, 7));
        assert!(!strict_precondition_failure(valid, 8));
        for invalid in [
            br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32000,"code":-32001,"message":"refused","data":{"code":"PreconditionFailed","reason":"not_met"}}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"refused","data":{"code":"Other","code":"PreconditionFailed","reason":"not_met"}}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"refused","data":{"code":"PreconditionFailed","reason":"other"}}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"refused","data":{"code":"PreconditionFailed","reason":"unknown","reason":"not_met"}}}"#.as_slice(),
        ] {
            assert!(!strict_precondition_failure(invalid, 7));
        }
    }
    /// First-call refusal accepts only correlated closed pre-admission classes, never conflict or unknown.
    #[test]
    fn initial_batch_refusal_requires_strict_correlated_error()
    -> Result<(), Box<dyn std::error::Error>> {
        for code in [
            "ValidationError",
            "PathEscapeError",
            "selection_busy",
            "no_eligible_account",
            "quota_exhausted",
            "binding_cooldown",
            "CapacityExhausted",
            "StateTransitionError",
        ] {
            let frame = serde_json::to_vec(
                &json!({"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"refused","data":{"code":code}}}),
            )?;
            assert!(strict_initial_refusal(&frame, 7), "{code}");
            assert!(!strict_initial_refusal(&frame, 8), "{code}");
        }
        assert!(strict_initial_refusal(
            br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32602,"message":"invalid"}}"#,
            7
        ));
        for invalid in [
            br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"x","data":{"code":"RequestConflict"}}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"x","data":{"code":"Unsupported"}}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"x","data":{"code":"BatchOutcomeUnknown"}}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32001,"message":"overload"}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"x","data":{"code":"Other","code":"CapacityExhausted"}}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":7,"error":{"code":-32602,"message":"x","data":null}}"#.as_slice(),
        ] {
            assert!(!strict_initial_refusal(invalid, 7));
        }
        Ok(())
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
            assert!(!error.known_unadmitted);
            assert!(!format!("{error:?}").contains("private-canary"));
        }
        assert!(!RunFailure::from_response(&json!({"code":-32002})).known_unadmitted);
        for code in [-32602, -32600, -32601, -32700, -32001] {
            assert!(!RunFailure::from_response(&json!({"code":code})).known_unadmitted);
        }
        assert!(RunFailure::from(Fault::Invalid).known_unadmitted);
        assert!(
            !RunFailure::from_response(&json!({"code":-32000,"message":"RequestConflict"}))
                .known_unadmitted
        );
    }
    /// Conditioned requests and receipts preserve every ordered prerequisite without changing old wire.
    #[test]
    fn conditioned_batch_requires_exact_ordered_prerequisites()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = format!("store_{}", "1".repeat(32));
        let jobs = vec![crate::domain::BatchJob {
            member_id: "new-member".into(),
            spec: json!({"task":"replacement"}),
            original_spec: Some(json!({"task":"private-original-canary"})),
        }];
        let condition = |suffix: &str, digit: &str| crate::run_status::Target {
            agent_id: format!("ag-20261107-010101-{suffix}"),
            sequence: 1,
            execution_ref: format!("ex1_{}", digit.repeat(64)),
            pin_id: format!("pin_{}", uuid::Uuid::new_v4().simple()),
        };
        let conditions = vec![condition("0123456789", "a"), condition("1123456789", "b")];
        let params = preconditioned_batch_params("key", &jobs, true, &store, &conditions)
            .map_err(|_| "valid intent rejected")?;
        assert_eq!(params["preconditions"], serde_json::to_value(&conditions)?);
        assert_eq!(params["expected_store_id"], store);
        assert!(!params.to_string().contains("private-original-canary"));
        let old = batch_params("key", &jobs, true, Some(&store));
        assert!(old.get("preconditions").is_none());
        let new_pin = format!("pin_{}", uuid::Uuid::new_v4().simple());
        let valid = json!({"replayed":true,"receipt":{
            "version":1,"request_id":"key","store_id":store,"preconditions":conditions,
            "jobs":[{"index":0,"agent_id":"ag-20261107-010101-0000000004","sequence":1,
                "execution_ref":format!("ex1_{}","c".repeat(64)),"pin_id":new_pin}]
        }});
        assert!(
            parse_batch_receipt(&valid, "key", 1, true, Some(&store), Some(&conditions)).is_ok()
        );
        assert!(parse_batch_receipt(&valid, "key", 1, true, Some(&store), None).is_err());
        let mut absent = valid.clone();
        absent["receipt"]
            .as_object_mut()
            .ok_or("receipt")?
            .remove("preconditions");
        let mut reordered = valid.clone();
        reordered["receipt"]["preconditions"]
            .as_array_mut()
            .ok_or("conditions")?
            .reverse();
        let mut changed = valid.clone();
        changed["receipt"]["preconditions"][0]["execution_ref"] =
            json!(format!("ex1_{}", "d".repeat(64)));
        let mut invalid_id = valid.clone();
        invalid_id["receipt"]["jobs"][0]["agent_id"] = json!("agent-new");
        for invalid in [absent, reordered, changed, invalid_id] {
            assert!(
                parse_batch_receipt(&invalid, "key", 1, true, Some(&store), Some(&conditions))
                    .is_err()
            );
        }
        let mut duplicate = conditions.clone();
        duplicate[1].agent_id = duplicate[0].agent_id.clone();
        duplicate[1].sequence = 2;
        assert!(preconditioned_batch_params("key", &jobs, true, &store, &duplicate).is_err());
        let mut duplicate_pin = conditions.clone();
        duplicate_pin[1].pin_id = duplicate_pin[0].pin_id.clone();
        assert!(preconditioned_batch_params("key", &jobs, true, &store, &duplicate_pin).is_err());
        assert!(preconditioned_batch_params("key", &jobs, true, &store, &[]).is_err());
        assert!(preconditioned_batch_params("key", &jobs, true, "invalid", &conditions).is_err());
        Ok(())
    }

    /// Mutation and lookup use the identical fenced intent; errors and altered echoes stay unknown.
    #[tokio::test]
    async fn conditioned_batch_transport_preserves_intent_and_uncertainty()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory =
            tempfile::tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let config = fixture_config(directory.path(), std::fs::metadata(directory.path())?.uid());
        let socket = config.run_socket.as_ref().ok_or("missing socket")?;
        let listener = tokio::net::UnixListener::bind(socket)?;
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
        let store = format!("store_{}", "1".repeat(32));
        let jobs = vec![crate::domain::BatchJob {
            member_id: "new-member".into(),
            spec: json!({"task":"replacement"}),
            original_spec: None,
        }];
        let conditions = vec![crate::run_status::Target {
            agent_id: "ag-20261107-010101-0123456789".into(),
            sequence: 1,
            execution_ref: format!("ex1_{}", "a".repeat(64)),
            pin_id: format!("pin_{}", uuid::Uuid::new_v4().simple()),
        }];
        let new_pin = format!("pin_{}", uuid::Uuid::new_v4().simple());
        let receipt = json!({"version":1,"request_id":"key","store_id":store,
            "preconditions":conditions,"jobs":[{"index":0,"agent_id":"ag-20261107-010101-0000000004","sequence":1,
                "execution_ref":format!("ex1_{}","b".repeat(64)),"pin_id":new_pin}]});
        let expected = preconditioned_batch_params("key", &jobs, true, &store, &conditions)
            .map_err(|_| "valid intent rejected")?;
        assert!(
            start_batch_with_preconditions(&config, "key", &jobs, true, &store, &[])
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
        let (results, served) = tokio::time::timeout(Duration::from_secs(20), async {
            let client = async {
                let first = start_batch_with_preconditions(&config, "key", &jobs, true, &store, &conditions).await;
                let found = batch_receipt_with_preconditions(&config, "key", &jobs, true, &store, &conditions).await;
                let missing = batch_receipt_with_preconditions(&config, "key", &jobs, true, &store, &conditions).await;
                let altered = batch_receipt_with_preconditions(&config, "key", &jobs, true, &store, &conditions).await;
                let refusal = start_batch_with_preconditions(&config, "key", &jobs, true, &store, &conditions).await;
                let absent = start_batch_with_preconditions(&config, "key", &jobs, true, &store, &conditions).await;
                let malformed = start_batch_with_preconditions(&config, "key", &jobs, true, &store, &conditions).await;
                (first, found, missing, altered, refusal, absent, malformed)
            };
            let server = async {
                for index in 0..7 {
                    let (mut stream, _) = listener.accept().await?;
                    let request: Value = serde_json::from_slice(&read_frame(&mut stream).await?)?;
                    assert_eq!(request["params"], expected);
                    assert_eq!(request["method"], if matches!(index, 0 | 4 | 5 | 6) { "start_batch" } else { "batch_receipt" });
                    let reply = match index {
                        0 => json!({"result":{"replayed":false,"receipt":receipt}}),
                        1 => json!({"result":{"found":true,"receipt":receipt}}),
                        2 => json!({"result":{"found":false}}),
                        3 => {
                            let mut wrong = receipt.clone();
                            wrong["preconditions"][0]["execution_ref"] =
                                json!(format!("ex1_{}", "c".repeat(64)));
                            json!({"result":{"found":true,"receipt":wrong}})
                        }
                        4 => json!({"error":{"code":-32000,"message":"fixture","data":{"code":"PreconditionFailed","reason":"not_met"}}}),
                        5 => {
                            let mut missing = receipt.clone();
                            missing.as_object_mut().ok_or("receipt")?.remove("preconditions");
                            json!({"result":{"replayed":true,"receipt":missing}})
                        }
                        _ => {
                            let mut invalid = receipt.clone();
                            invalid["jobs"][0]["agent_id"] = json!("ag-20260230-010101-0123456789");
                            json!({"result":{"replayed":true,"receipt":invalid}})
                        }
                    };
                    let mut reply = reply;
                    reply["jsonrpc"] = json!("2.0");
                    reply["id"] = request["id"].clone();
                    let mut bytes = serde_json::to_vec(&reply)?;
                    bytes.push(b'\n');
                    stream.write_all(&bytes).await?;
                }
                Ok::<_, Box<dyn std::error::Error>>(())
            };
            tokio::join!(client, server)
        }).await?;
        served?;
        let (first, found, missing, altered, refusal, absent, malformed) = results;
        assert_eq!(
            first.map_err(|_| "start failed")?[0].agent_id,
            "ag-20261107-010101-0000000004"
        );
        assert_eq!(
            found
                .map_err(|_| "lookup failed")?
                .ok_or("receipt absent")?[0]
                .agent_id,
            "ag-20261107-010101-0000000004"
        );
        assert!(matches!(missing, Ok(None)));
        for failure in [altered.err(), refusal.err(), absent.err(), malformed.err()] {
            assert!(!failure.ok_or("invalid outcome accepted")?.known_unadmitted);
        }
        Ok(())
    }

    /// Existing persisted batch intents never gain new retention or store fences during replay.
    #[test]
    fn legacy_batch_replay_preserves_original_retention_intent()
    -> Result<(), Box<dyn std::error::Error>> {
        let old = json!({"kind":"start_batch","request_key":"old-key","jobs":[{"member_id":"member","spec":{"task":"original"}}]});
        let work: Work = serde_json::from_value(old.clone())?;
        assert_eq!(serde_json::to_value(&work)?, old);
        let Work::StartBatch {
            request_key,
            jobs,
            retain_history,
            ..
        } = work
        else {
            panic!("batch")
        };
        assert!(!retain_history);
        let params = batch_params(&request_key, &jobs, retain_history, None);
        assert!(params.get("retain_history").is_none());
        assert!(params.get("expected_store_id").is_none());
        let pinned = batch_params(&request_key, &jobs, true, None);
        assert_eq!(pinned["retain_history"], true);
        Ok(())
    }
    /// A partial, aliased or cross-store receipt never becomes a successful admission.
    #[test]
    fn batch_receipt_rejects_missing_or_aliased_proofs() -> Result<(), Box<dyn std::error::Error>> {
        let store = format!("store_{}", "1".repeat(32));
        let pin_one = format!("pin_{}", uuid::Uuid::new_v4().simple());
        let pin_two = format!("pin_{}", uuid::Uuid::new_v4().simple());
        let valid = json!({"replayed":true,"receipt":{"version":1,"request_id":"key","store_id":store,"jobs":[
            {"index":0,"agent_id":"ag-20261107-010101-0000000001","sequence":1,"execution_ref":format!("ex1_{}","a".repeat(64)),"pin_id":pin_one},
            {"index":1,"agent_id":"ag-20261107-010101-0000000002","sequence":1,"execution_ref":format!("ex1_{}","b".repeat(64)),"pin_id":pin_two}
        ]}});
        assert!(parse_batch_receipt(&valid, "key", 2, true, Some(&store), None).is_ok());
        let mut missing_replayed = valid.clone();
        missing_replayed
            .as_object_mut()
            .ok_or("reply object")?
            .remove("replayed");
        assert!(
            parse_batch_receipt(&missing_replayed, "key", 2, true, Some(&store), None).is_err()
        );
        let mut missing_pin = valid.clone();
        missing_pin["receipt"]["jobs"][1]
            .as_object_mut()
            .ok_or("job object")?
            .remove("pin_id");
        let mut duplicate_pin = valid.clone();
        duplicate_pin["receipt"]["jobs"][1]["pin_id"] = json!(pin_one);
        let mut duplicate_ref = valid.clone();
        duplicate_ref["receipt"]["jobs"][1]["execution_ref"] =
            valid["receipt"]["jobs"][0]["execution_ref"].clone();
        let mut wrong_store = valid.clone();
        wrong_store["receipt"]["store_id"] = json!(format!("store_{}", "2".repeat(32)));
        let mut wrong_index = valid.clone();
        wrong_index["receipt"]["jobs"][1]["index"] = json!(0);
        let mut invalid_responses = vec![
            missing_pin,
            duplicate_pin,
            duplicate_ref,
            wrong_store,
            wrong_index,
        ];
        for agent_id in [
            "agent-new",
            "ag-20260230-010101-0123456789",
            "ag-20261107-250101-0123456789",
            "ag-20261107-010101-012345678A",
            "ag-20261107-010101-012345678",
        ] {
            let mut invalid = valid.clone();
            invalid["receipt"]["jobs"][0]["agent_id"] = json!(agent_id);
            invalid_responses.push(invalid);
        }
        for invalid in invalid_responses {
            let error = match parse_batch_receipt(&invalid, "key", 2, true, Some(&store), None) {
                Ok(_) => return Err("malformed receipt accepted".into()),
                Err(error) => error,
            };
            assert!(!error.known_unadmitted);
        }
        Ok(())
    }
}
