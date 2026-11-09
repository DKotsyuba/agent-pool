//! Private single-connection protocol between the managed stdio frontend and resident.
use crate::{
    config::Config,
    domain::{Command, Fault, Reply},
    managed_bridge::{self, BridgeFailure, BridgePin, Registration, SdkBridge},
    managed_state::{Route, SecurityContext},
};
use bridge_sdk::bridge_protocol::{CallEvidence, Host, Secret};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use tokio::{io::AsyncWriteExt, net::UnixStream};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Begin {
    pub version: u8,
    pub bootstrap_id: String,
    pub invocation_key: String,
    pub command: Value,
    pub proof: CallEvidence,
    pub bridge_pin: BridgePin,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BeginEnvelope {
    pub managed_begin: Begin,
}
#[derive(Serialize, Deserialize)]
#[serde(
    tag = "stage",
    content = "data",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(crate) enum ClientFrame {
    Epoch {
        issuer_epoch: String,
    },
    Prepared {
        store_id: String,
        bridge_context_ref: Secret,
        invocation_key: String,
        expires_at_ms: u64,
    },
    StaleEpoch,
    Execute {
        assertion_key: Secret,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FrozenContext {
    pub context_id: String,
    pub registration_request_id: String,
    pub command: Value,
    pub context: SecurityContext,
    pub security_digest: String,
}
#[derive(Serialize, Deserialize)]
#[serde(
    tag = "stage",
    content = "data",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(crate) enum ServerFrame {
    Ready,
    Reserved,
    RetryEpoch,
    Context(Box<FrozenContext>),
    Finished(Result<Reply, Fault>),
    Failure(Fault),
}

pub(crate) async fn send<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<(), Fault> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| Fault::Invalid)?;
    if bytes.len() >= crate::integrations::MAX_FRAME {
        return Err(Fault::Invalid);
    }
    bytes.push(b'\n');
    tokio::time::timeout(
        crate::integrations::EXCHANGE_TIMEOUT,
        stream.write_all(&bytes),
    )
    .await
    .map_err(|_| Fault::Unavailable)?
    .map_err(|_| Fault::Unavailable)
}
pub(crate) async fn receive<T: DeserializeOwned>(stream: &mut UnixStream) -> Result<T, Fault> {
    let bytes = tokio::time::timeout(
        crate::integrations::EXCHANGE_TIMEOUT * 4,
        crate::integrations::read_frame(stream),
    )
    .await
    .map_err(|_| Fault::Unavailable)??;
    let value = crate::managed_codec::parse_raw(&bytes)?;
    serde_json::from_value(value).map_err(|_| Fault::Invalid)
}

/// The frontend registers only the resident's exact validated command and routes.
fn validate_frozen(
    command: &Command,
    frozen: &FrozenContext,
    pin: &BridgePin,
    config: &Config,
    invocation: &str,
) -> Result<(), Fault> {
    let transport = config
        .managed_run_transport
        .as_ref()
        .ok_or(Fault::Unavailable)?;
    let normalized = serde_json::to_value(command).map_err(|_| Fault::Invalid)?;
    let (_, digest) = crate::managed_state::validate_context(command, &frozen.context)?;
    let [binding] = frozen.context.bindings.as_slice() else {
        return Err(Fault::Conflict);
    };
    let valid_id =
        |value: &str| uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value);
    if frozen.command != normalized
        || frozen.security_digest != digest
        || !valid_id(&frozen.context_id)
        || !valid_id(&frozen.registration_request_id)
        || frozen.context_id == frozen.registration_request_id
        || frozen.context.invocation_key != invocation
        || frozen.context.producer != config.bridge_producer_id
        || frozen.context.audience != config.bridge_audience
        || binding.bridge_route != pin.route
        || binding.run_route.component_store_id != transport.run_store_id
        || binding.run_route.route_id != transport.run_route_id
        || binding.run_route.worker_uid != config.expected_uid
    {
        return Err(Fault::Conflict);
    }
    Ok(())
}

/// Only the actual stdio process calls Bridge prepare and registration.
pub(crate) async fn frontend(
    command: &Command,
    metadata: Value,
    config: &Config,
) -> Result<Reply, Fault> {
    managed_bridge::require_stdio_transport().map_err(managed_bridge::fault)?;
    let transport = config
        .managed_run_transport
        .as_ref()
        .ok_or(Fault::Unavailable)?;
    let server = transport.mcp_server.as_deref().ok_or(Fault::Invalid)?;
    let host = if metadata.get("threadId").is_some() {
        Host::Codex
    } else if metadata.get("claudecode/toolUseId").is_some() {
        Host::ClaudeCode
    } else {
        return Err(Fault::Unauthorized);
    };
    let proof =
        bridge_sdk::extract_native_evidence(host, &metadata).map_err(|_| Fault::Unauthorized)?;
    let route = Route {
        component_store_id: transport.bridge_store_id.clone(),
        route_id: transport.bridge_route_id.clone(),
        worker_uid: config.expected_uid,
    };
    let cfg = config.clone();
    let (bridge, pin) = tokio::task::spawn_blocking(move || SdkBridge::capture(&cfg, route))
        .await
        .map_err(|_| Fault::Internal)??;
    let invocation_key = crate::domain::id();
    let normalized = serde_json::to_value(command).map_err(|_| Fault::Invalid)?;
    for retry in 0..2 {
        let bootstrap_id = crate::domain::id();
        let mut stream =
            crate::runtime::connect_managed_peer(&config.socket_path, config.expected_uid).await?;
        send(
            &mut stream,
            &BeginEnvelope {
                managed_begin: Begin {
                    version: 1,
                    bootstrap_id,
                    invocation_key: invocation_key.clone(),
                    command: normalized.clone(),
                    proof: proof.clone(),
                    bridge_pin: pin.clone(),
                },
            },
        )
        .await?;
        match receive::<ServerFrame>(&mut stream).await? {
            ServerFrame::Ready => {}
            ServerFrame::Failure(error) => return Err(error),
            _ => return Err(Fault::Invalid),
        }
        let discovery = bridge.clone();
        let expected = pin.route.component_store_id.clone();
        let epoch =
            tokio::task::spawn_blocking(move || managed_bridge::discover(&discovery, &expected))
                .await
                .map_err(|_| Fault::Internal)?
                .map_err(managed_bridge::fault)?;
        send(
            &mut stream,
            &ClientFrame::Epoch {
                issuer_epoch: epoch.clone(),
            },
        )
        .await?;
        match receive::<ServerFrame>(&mut stream).await? {
            ServerFrame::Reserved => {}
            ServerFrame::Failure(error) => return Err(error),
            _ => return Err(Fault::Invalid),
        }
        let worker = bridge.clone();
        let store_id = pin.route.component_store_id.clone();
        let invocation = invocation_key.clone();
        let epoch_for_prepare = epoch.clone();
        let command_for_prepare = command.clone();
        let proof_for_prepare = proof.clone();
        let prepared = tokio::task::spawn_blocking(move || {
            managed_bridge::prepare_original(
                &worker,
                &crate::domain::id(),
                &store_id,
                &epoch_for_prepare,
                &invocation,
                &command_for_prepare,
                &proof_for_prepare,
            )
        })
        .await
        .map_err(|_| Fault::Internal)?;
        let prepared = match prepared {
            Ok(value) => value,
            Err(BridgeFailure::StaleEpoch) => {
                send(&mut stream, &ClientFrame::StaleEpoch).await?;
                if !matches!(
                    receive::<ServerFrame>(&mut stream).await?,
                    ServerFrame::RetryEpoch
                ) || retry != 0
                {
                    return Err(Fault::Unavailable);
                }
                continue;
            }
            Err(error) => return Err(managed_bridge::fault(error)),
        };
        send(
            &mut stream,
            &ClientFrame::Prepared {
                store_id: prepared.store_id.clone(),
                bridge_context_ref: prepared.bridge_context_ref.clone(),
                invocation_key: prepared.invocation_key.clone(),
                expires_at_ms: prepared.expires_at_ms,
            },
        )
        .await?;
        let frozen = match receive::<ServerFrame>(&mut stream).await? {
            ServerFrame::Context(value) => value,
            ServerFrame::Failure(error) => return Err(error),
            _ => return Err(Fault::Invalid),
        };
        validate_frozen(command, &frozen, &pin, config, &invocation_key)?;
        let worker = bridge.clone();
        let command = command.clone();
        let proof = proof.clone();
        let expected_epoch = epoch.clone();
        let request_id = frozen.registration_request_id.clone();
        let digest = frozen.security_digest.clone();
        let audience = frozen.context.audience.clone();
        let nonce = frozen.context.nonce.clone();
        let registered = tokio::task::spawn_blocking(move || {
            let request = Registration {
                request_id: &request_id,
                expected_store_id: &prepared.store_id,
                bridge_context_ref: prepared.bridge_context_ref.expose(),
                invocation_key: &prepared.invocation_key,
                command_name: &managed_bridge::command_name(&command)
                    .map_err(|_| BridgeFailure::Refused)?,
                security_digest: &digest,
                audience: &audience,
                nonce: &nonce,
                native_proof: &proof,
            };
            managed_bridge::register_original(
                &worker,
                &request,
                &prepared,
                &expected_epoch,
                &command,
            )
        })
        .await
        .map_err(|_| Fault::Internal)?
        .map_err(managed_bridge::fault)?;
        let _ = server;
        send(
            &mut stream,
            &ClientFrame::Execute {
                assertion_key: registered.assertion_key,
            },
        )
        .await?;
        return match receive::<ServerFrame>(&mut stream).await? {
            ServerFrame::Finished(result) => result,
            ServerFrame::Failure(error) => Err(error),
            _ => Err(Fault::Invalid),
        };
    }
    Err(Fault::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed_state::tests::{fake_bridge_pin, fake_config, fixture};

    #[test]
    fn relaunch_refusal_survives_the_private_session_frame()
    -> Result<(), Box<dyn std::error::Error>> {
        let frame = ServerFrame::Failure(Fault::RelaunchRequired);
        let bytes = serde_json::to_vec(&frame)?;
        assert!(matches!(
            serde_json::from_slice::<ServerFrame>(&bytes)?,
            ServerFrame::Failure(Fault::RelaunchRequired)
        ));
        Ok(())
    }

    #[test]
    fn frontend_validates_frozen_command_context_and_routes_before_registration()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, _store, binding, _incarnation, _run) = fixture();
        let config = fake_config(&binding);
        let pin = fake_bridge_pin(&binding);
        let command = Command::Post(crate::domain::Message {
            change: crate::domain::Change {
                pool_id: binding.pool_id.clone(),
                expected_revision: 1,
                request_key: "request".into(),
            },
            body: "test".into(),
        });
        let context = SecurityContext {
            version: 1,
            command_schema: "pool-command-v1".into(),
            pool_store_id: binding.pool_store_id.clone(),
            audience: config.bridge_audience.clone(),
            producer: config.bridge_producer_id.clone(),
            intent_id: "intent".into(),
            invocation_key: "invocation".into(),
            nonce: "nonce".into(),
            bindings: vec![binding],
        };
        let mut frozen = FrozenContext {
            context_id: crate::domain::id(),
            registration_request_id: crate::domain::id(),
            command: serde_json::to_value(&command)?,
            security_digest: crate::managed_state::validate_context(&command, &context)?.1,
            context,
        };
        assert!(validate_frozen(&command, &frozen, &pin, &config, "invocation").is_ok());
        frozen.command["arguments"]["body"] = Value::String("altered".into());
        assert!(validate_frozen(&command, &frozen, &pin, &config, "invocation").is_err());
        frozen.command = serde_json::to_value(&command)?;
        frozen.context.version = 2;
        assert!(validate_frozen(&command, &frozen, &pin, &config, "invocation").is_err());
        frozen.context.version = 1;
        frozen.context.bindings[0].run_route.route_id = "foreign".into();
        frozen.security_digest =
            crate::managed_state::validate_context(&command, &frozen.context)?.1;
        assert!(validate_frozen(&command, &frozen, &pin, &config, "invocation").is_err());
        Ok(())
    }
}
