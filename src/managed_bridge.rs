//! Narrow Bridge B1 seam and typed SDK adapter; managed runtime ingress remains closed.
use crate::{
    domain::{Command, Fault},
    managed_state::{Incarnation, ManagedActor},
};
use bridge_sdk::bridge_protocol::{CallEvidence, Secret};
use serde::{Deserialize, Serialize};

/// Original Bridge route, endpoint, reader build and protected credential reference.
/// This private record is persisted before managed I/O and never rendered or logged.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BridgePin {
    pub route: crate::managed_state::Route,
    pub producer: String,
    pub registration_socket: std::path::PathBuf,
    pub core_socket: std::path::PathBuf,
    pub server_executable: std::path::PathBuf,
    pub server_sha256: String,
    pub credential_file: std::path::PathBuf,
    pub credential_sha256: String,
}

/// Protected original observation returned by Bridge, not reconstructed later.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Observation {
    pub incarnation: Incarnation,
    pub launch_id: String,
    pub actor: ManagedActor,
    pub native_call_id: String,
    pub tool_name: String,
    pub observed_at_ms: u64,
    pub expires_at_ms: u64,
}
/// Exact consumption association retained for Run's independent Bridge lookup.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConsumeReceipt {
    pub producer: String,
    pub consume_request_id: String,
    pub invocation_key: String,
    pub security_digest: String,
    pub observation: Observation,
    pub issuer_epoch: String,
    pub consumed_at_ms: u64,
}
/// Bridge distinguishes a fresh observation from historical recovery evidence.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Validity {
    Current,
    Historical,
}
/// Capability discovery never replaces the separately pinned store identity.
pub(crate) struct Capabilities {
    pub store_id: String,
    pub issuer_epoch: String,
    pub capabilities: Vec<String>,
}
/// The original hook is reserved, not yet spent, for a specific invocation.
pub(crate) struct Prepared {
    pub store_id: String,
    pub bridge_context_ref: Secret,
    pub invocation_key: String,
    pub expires_at_ms: u64,
}
/// Assertion secret is redacted by the SDK type and never enters diagnostics.
pub(crate) struct Registered {
    pub store_id: String,
    pub assertion_key: Secret,
    pub invocation_key: String,
    pub issuer_epoch: String,
    pub expires_at_ms: u64,
}
/// Consumed evidence is usable for new admission only while current and unsealed.
#[derive(Clone)]
pub(crate) struct Consumed {
    pub store_id: String,
    pub receipt: ConsumeReceipt,
    pub validity: Validity,
    pub aborted: bool,
}
/// Durable Bridge abort result; a sealed receipt does not revoke a prior Run admission.
#[derive(Serialize)]
pub(crate) struct Abort {
    pub store_id: String,
    pub aborted: bool,
    pub receipt: Option<ConsumeReceipt>,
}
/// A definitive stale-epoch response precedes reservation; unknown must be reconciled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BridgeFailure {
    StaleEpoch,
    RelaunchRequired,
    Refused,
    Unknown,
}
/// Preserve a definite managed-role refusal through the participant response.
pub(crate) fn fault(error: BridgeFailure) -> Fault {
    match error {
        BridgeFailure::RelaunchRequired => Fault::RelaunchRequired,
        BridgeFailure::Refused => Fault::Unauthorized,
        BridgeFailure::StaleEpoch | BridgeFailure::Unknown => Fault::Unavailable,
    }
}
/// Parameters bind the same frontend call, command and issuer throughout reservation.
pub(crate) struct Prepare<'a> {
    pub request_id: &'a str,
    pub expected_store_id: &'a str,
    pub expected_issuer_epoch: &'a str,
    pub invocation_key: &'a str,
    pub command_name: &'a str,
    pub native_proof: &'a CallEvidence,
}
/// Registration associates the frozen security digest with the reserved original call.
pub(crate) struct Registration<'a> {
    pub request_id: &'a str,
    pub expected_store_id: &'a str,
    pub bridge_context_ref: &'a str,
    pub invocation_key: &'a str,
    pub command_name: &'a str,
    pub security_digest: &'a str,
    pub audience: &'a str,
    pub nonce: &'a str,
    pub native_proof: &'a CallEvidence,
}
/// Original durable intent is retained unchanged when aborting or looking up consume.
pub(crate) struct ConsumeKey<'a> {
    pub abort_request_id: &'a str,
    pub expected_store_id: &'a str,
    pub producer: &'a str,
    pub consume_request_id: &'a str,
    pub invocation_key: &'a str,
    pub security_digest: &'a str,
    pub audience: &'a str,
}
/// Implemented by the future typed Bridge SDK adapter and local synthetic fakes only.
pub(crate) trait BridgeB1Client {
    fn capabilities(&self) -> Result<Capabilities, BridgeFailure>;
    fn prepare(&self, request: &Prepare<'_>) -> Result<Prepared, BridgeFailure>;
    fn register(&self, request: &Registration<'_>) -> Result<Registered, BridgeFailure>;
    fn consume(
        &self,
        request: &ConsumeKey<'_>,
        assertion_key: &Secret,
    ) -> Result<Consumed, BridgeFailure>;
    fn lookup(&self, request_id: &str, request: &ConsumeKey<'_>)
    -> Result<Consumed, BridgeFailure>;
    fn abort(&self, request: &ConsumeKey<'_>) -> Result<Abort, BridgeFailure>;
}
fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|parsed| parsed.to_string() == value)
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
/// Managed proof registration is confined to direct Linux pipe or Unix-socket stdio.
#[cfg(target_os = "linux")]
pub(crate) fn require_stdio_transport() -> Result<(), BridgeFailure> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let process = std::fs::read_to_string("/proc/self/stat").map_err(|_| BridgeFailure::Refused)?;
    let namespace = std::fs::metadata("/proc/self/ns/pid").map_err(|_| BridgeFailure::Refused)?;
    let sockets = std::fs::read_to_string("/proc/net/unix").map_err(|_| BridgeFailure::Refused)?;
    for fd in [0, 1] {
        let metadata =
            std::fs::metadata(format!("/proc/self/fd/{fd}")).map_err(|_| BridgeFailure::Refused)?;
        let kind = metadata.file_type();
        if kind.is_fifo() {
            continue;
        }
        if !kind.is_socket()
            || !sockets.lines().skip(1).any(|line| {
                line.split_whitespace()
                    .nth(6)
                    .and_then(|inode| inode.parse::<u64>().ok())
                    == Some(metadata.ino())
            })
        {
            return Err(BridgeFailure::Refused);
        }
    }
    let current = std::fs::read_to_string("/proc/self/stat").map_err(|_| BridgeFailure::Refused)?;
    let current_namespace =
        std::fs::metadata("/proc/self/ns/pid").map_err(|_| BridgeFailure::Refused)?;
    // Only the stable identity field is compared; counters in /proc stat may change.
    let start = |text: &str| {
        text.rsplit_once(')')
            .and_then(|(_, tail)| tail.split_whitespace().nth(19))
            .and_then(|ticks| ticks.parse::<u64>().ok())
    };
    if start(&process).is_none()
        || start(&process) != start(&current)
        || namespace.ino() != current_namespace.ino()
    {
        return Err(BridgeFailure::Refused);
    }
    Ok(())
}
/// Other transports and platforms have not been qualified for managed proof.
#[cfg(not(target_os = "linux"))]
pub(crate) fn require_stdio_transport() -> Result<(), BridgeFailure> {
    Err(BridgeFailure::Refused)
}
/// Obtain an issuer only from a matching pinned store with the complete B1 capability set.
pub(crate) fn discover(
    client: &impl BridgeB1Client,
    expected_store_id: &str,
) -> Result<String, BridgeFailure> {
    let c = client.capabilities()?;
    if !canonical_uuid(expected_store_id)
        || c.store_id != expected_store_id
        || c.issuer_epoch.is_empty()
        || ![
            "attempt_launch_v1",
            "launch_assertion_v1",
            "namespace_retirement_v1",
        ]
        .iter()
        .all(|required| {
            c.capabilities
                .iter()
                .any(|capability| capability == required)
        })
    {
        return Err(BridgeFailure::Refused);
    }
    Ok(c.issuer_epoch)
}
/// Exact typed command name is what Bridge binds to its original protected hook.
pub(crate) fn command_name(command: &Command) -> Result<String, Fault> {
    command.validate()?;
    let value = serde_json::to_value(command).map_err(|_| Fault::Internal)?;
    Ok(value
        .get("name")
        .and_then(serde_json::Value::as_str)
        .ok_or(Fault::Internal)?
        .to_owned())
}
/// Prepare only after the caller durably reserved the exact issuer and invocation.
pub(crate) fn prepare_original(
    client: &impl BridgeB1Client,
    request_id: &str,
    expected_store_id: &str,
    expected_issuer_epoch: &str,
    invocation_key: &str,
    command: &Command,
    native_proof: &CallEvidence,
) -> Result<Prepared, BridgeFailure> {
    require_stdio_transport()?;
    let name = command_name(command).map_err(|_| BridgeFailure::Refused)?;
    let prepared = client.prepare(&Prepare {
        request_id,
        expected_store_id,
        expected_issuer_epoch,
        invocation_key,
        command_name: &name,
        native_proof,
    })?;
    if prepared.store_id != expected_store_id
        || prepared.invocation_key != invocation_key
        || prepared.bridge_context_ref.expose().is_empty()
        || prepared.expires_at_ms == 0
    {
        return Err(BridgeFailure::Unknown);
    }
    Ok(prepared)
}
/// Register only the exact reserved original and frozen context digest.
pub(crate) fn register_original(
    client: &impl BridgeB1Client,
    request: &Registration<'_>,
    prepared: &Prepared,
    expected_epoch: &str,
    command: &Command,
) -> Result<Registered, BridgeFailure> {
    let name = command_name(command).map_err(|_| BridgeFailure::Refused)?;
    if request.command_name != name
        || request.expected_store_id != prepared.store_id
        || request.bridge_context_ref != prepared.bridge_context_ref.expose()
        || request.invocation_key != prepared.invocation_key
    {
        return Err(BridgeFailure::Refused);
    }
    let result = client.register(request)?;
    if result.store_id != prepared.store_id
        || result.invocation_key != prepared.invocation_key
        || result.issuer_epoch != expected_epoch
        || result.assertion_key.expose().is_empty()
        || result.expires_at_ms > prepared.expires_at_ms
        || result.expires_at_ms == 0
    {
        return Err(BridgeFailure::Unknown);
    }
    Ok(result)
}
/// Consume the original association and recheck every bound field.
pub(crate) fn consume_original(
    client: &impl BridgeB1Client,
    key: &ConsumeKey<'_>,
    assertion: &Secret,
    server: &str,
    command: &Command,
    epoch: &str,
) -> Result<Consumed, BridgeFailure> {
    let consumed = client.consume(key, assertion)?;
    validate_consume(&consumed, key, server, command, epoch)?;
    Ok(consumed)
}
/// Accept a definitive Bridge fence only when it binds the exact original intent.
pub(crate) fn abort_original(
    client: &impl BridgeB1Client,
    key: &ConsumeKey<'_>,
) -> Result<Abort, BridgeFailure> {
    let result = client.abort(key)?;
    if result.store_id != key.expected_store_id || !result.aborted {
        return Err(BridgeFailure::Unknown);
    }
    if result.receipt.as_ref().is_some_and(|receipt| {
        receipt.producer != key.producer
            || receipt.consume_request_id != key.consume_request_id
            || receipt.invocation_key != key.invocation_key
            || receipt.security_digest != key.security_digest
    }) {
        return Err(BridgeFailure::Unknown);
    }
    Ok(result)
}
/// Longest native tool name Codex presents without a hashed substitute.
const MAX_CODEX_TOOL_NAME_BYTES: usize = 128;
/// Codex's MCP name segment: every character outside `[A-Za-z0-9_]` becomes `_`.
fn codex_segment(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}
/// A segment Codex joins without trimming, prefix elision or ambiguity.
fn plain_codex_segment(segment: &str) -> bool {
    !segment.is_empty()
        && !segment.starts_with('_')
        && !segment.ends_with('_')
        && !segment.contains("__")
}
/// A command Codex presents verbatim: a segment fixed point not trimmed by the hook join.
fn plain_codex_command(command: &str) -> bool {
    !command.is_empty() && !command.starts_with('_') && codex_segment(command) == command
}
/// The exact native tool name the attested harness presents for the configured server and
/// command (E16), or `None` when that harness has no unambiguous managed name.
///
/// Claude presents the raw server. Codex presents `mcp__` + seg(server) + `__` + command and
/// substitutes a hash for colliding or overlong names, so only plain segments and fixed-point
/// commands map to a name. Any other harness is refused rather than guessed.
pub(crate) fn managed_tool_name(harness: &str, server: &str, command: &str) -> Option<String> {
    match harness {
        "claude-code" => Some(format!("mcp__{server}__{command}")),
        "codex" => {
            let segment = codex_segment(server);
            let name = format!("mcp__{segment}__{command}");
            (plain_codex_segment(&segment)
                && plain_codex_command(command)
                && name.len() <= MAX_CODEX_TOOL_NAME_BYTES)
                .then_some(name)
        }
        _ => None,
    }
}
/// A configured server Bridge can map without ambiguity: every Pool tool has an exact managed
/// name for both served harnesses.
pub(crate) fn valid_managed_server(server: &str) -> bool {
    !server.is_empty()
        && server.len() <= 128
        && server
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        && !server.contains("__")
        && crate::tools::definitions().iter().all(|tool| {
            tool.get("name")
                .and_then(serde_json::Value::as_str)
                .and_then(|name| managed_tool_name("codex", server, name))
                .is_some()
        })
}
/// Refuse any consumed association that does not exactly match the frozen invocation.
pub(crate) fn validate_consume(
    consumed: &Consumed,
    key: &ConsumeKey<'_>,
    server: &str,
    command: &Command,
    expected_epoch: &str,
) -> Result<(), BridgeFailure> {
    let name = command_name(command).map_err(|_| BridgeFailure::Refused)?;
    let receipt = &consumed.receipt;
    let address =
        bridge_sdk::bridge_protocol::NativeAddress::parse(&receipt.observation.actor.address)
            .ok()
            .filter(|address| {
                address.canonical() == receipt.observation.actor.address
                    && address.host == receipt.observation.incarnation.host_id
                    && address.session == receipt.observation.actor.native_id
            });
    // The harness comes only from Bridge's attested actor address, which Run's binding also
    // fixes; the caller's native metadata never selects the naming rule.
    let tool_name = address
        .as_ref()
        .and_then(|address| managed_tool_name(address.harness.as_str(), server, &name));
    if !canonical_uuid(key.expected_store_id)
        || !valid_digest(key.security_digest)
        || consumed.store_id != key.expected_store_id
        || consumed.validity != Validity::Current
        || consumed.aborted
        || receipt.producer != key.producer
        || receipt.consume_request_id != key.consume_request_id
        || receipt.invocation_key != key.invocation_key
        || receipt.security_digest != key.security_digest
        || receipt.issuer_epoch != expected_epoch
        || tool_name.as_deref() != Some(receipt.observation.tool_name.as_str())
        || receipt.observation.actor.role != "root"
        || address.is_none()
        || receipt.observation.actor.native_id.is_empty()
        || receipt.observation.actor.epoch == 0
        || receipt.observation.incarnation.pid <= 1
        || receipt.observation.incarnation.pid_namespace_inode == 0
        || receipt.observation.incarnation.start_ticks == 0
        || receipt.observation.incarnation.uid == u32::MAX
        || receipt.observation.native_call_id.is_empty()
        || !canonical_uuid(&receipt.observation.incarnation.boot_id)
        || !canonical_uuid(&receipt.observation.launch_id)
        || receipt.observation.observed_at_ms > receipt.observation.expires_at_ms
    {
        return Err(BridgeFailure::Refused);
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::items_after_test_module,
    reason = "The isolated SDK adapter fixture precedes the adapter implementation"
)]
#[allow(clippy::unwrap_used, reason = "Synthetic Bridge evidence fixtures")]
mod tests {
    use super::*;
    use crate::domain::Change;
    const BRIDGE_ID: &str = "00000000-0000-4000-8000-000000000001";
    struct Fake;
    impl BridgeB1Client for Fake {
        fn capabilities(&self) -> Result<Capabilities, BridgeFailure> {
            Ok(Capabilities {
                store_id: BRIDGE_ID.into(),
                issuer_epoch: "epoch".into(),
                capabilities: vec![
                    "attempt_launch_v1".into(),
                    "launch_assertion_v1".into(),
                    "namespace_retirement_v1".into(),
                ],
            })
        }
        fn prepare(&self, _: &Prepare<'_>) -> Result<Prepared, BridgeFailure> {
            Err(BridgeFailure::StaleEpoch)
        }
        fn register(&self, _: &Registration<'_>) -> Result<Registered, BridgeFailure> {
            Err(BridgeFailure::Unknown)
        }
        fn consume(&self, _: &ConsumeKey<'_>, _: &Secret) -> Result<Consumed, BridgeFailure> {
            Err(BridgeFailure::Unknown)
        }
        fn lookup(&self, _: &str, _: &ConsumeKey<'_>) -> Result<Consumed, BridgeFailure> {
            Err(BridgeFailure::Unknown)
        }
        fn abort(&self, _: &ConsumeKey<'_>) -> Result<Abort, BridgeFailure> {
            Err(BridgeFailure::Unknown)
        }
    }
    #[test]
    fn bridge_capability_and_hook_tool_are_bound_to_command() {
        assert_eq!(discover(&Fake, BRIDGE_ID).unwrap(), "epoch");
        assert_eq!(discover(&Fake, "different"), Err(BridgeFailure::Refused));
        let command = Command::Join(Change {
            pool_id: "pool".into(),
            expected_revision: 1,
            request_key: "key".into(),
        });
        let digest = "a".repeat(64);
        let key = ConsumeKey {
            abort_request_id: "abort-1",
            expected_store_id: BRIDGE_ID,
            producer: "pool",
            consume_request_id: "consume",
            invocation_key: "inv",
            security_digest: &digest,
            audience: "audience",
        };
        let mut consumed = Consumed {
            store_id: BRIDGE_ID.into(),
            validity: Validity::Current,
            aborted: false,
            receipt: ConsumeReceipt {
                producer: "pool".into(),
                consume_request_id: "consume".into(),
                invocation_key: "inv".into(),
                security_digest: digest.clone(),
                issuer_epoch: "epoch".into(),
                consumed_at_ms: 1,
                observation: Observation {
                    incarnation: Incarnation {
                        host_id: "host".into(),
                        boot_id: "00000000-0000-4000-8000-000000000002".into(),
                        pid_namespace_inode: 1,
                        uid: 1,
                        pid: 2,
                        start_ticks: 1,
                    },
                    launch_id: "00000000-0000-4000-8000-000000000003".into(),
                    actor: ManagedActor {
                        address: "host/codex/store/session".into(),
                        role: "root".into(),
                        native_id: "session".into(),
                        epoch: 1,
                    },
                    native_call_id: "call".into(),
                    tool_name: "mcp__pool__pool_join".into(),
                    observed_at_ms: 1,
                    expires_at_ms: 2,
                },
            },
        };
        assert!(validate_consume(&consumed, &key, "pool", &command, "epoch").is_ok());
        let mut claude = consumed.clone();
        claude.receipt.observation.actor.address = "host/claude-code/store/session".into();
        assert!(validate_consume(&claude, &key, "pool", &command, "epoch").is_ok());
        consumed.receipt.observation.tool_name = "mcp__pool__pool_vote".into();
        assert_eq!(
            validate_consume(&consumed, &key, "pool", &command, "epoch"),
            Err(BridgeFailure::Refused)
        );
        struct Sim {
            receipt: Consumed,
            aborted: std::cell::Cell<bool>,
        }
        impl BridgeB1Client for Sim {
            fn capabilities(&self) -> Result<Capabilities, BridgeFailure> {
                Fake.capabilities()
            }
            fn prepare(&self, request: &Prepare<'_>) -> Result<Prepared, BridgeFailure> {
                Fake.prepare(request)
            }
            fn register(&self, request: &Registration<'_>) -> Result<Registered, BridgeFailure> {
                Fake.register(request)
            }
            fn consume(&self, _: &ConsumeKey<'_>, _: &Secret) -> Result<Consumed, BridgeFailure> {
                if self.aborted.get() {
                    Err(BridgeFailure::Refused)
                } else {
                    Ok(self.receipt.clone())
                }
            }
            fn lookup(&self, _: &str, _: &ConsumeKey<'_>) -> Result<Consumed, BridgeFailure> {
                Ok(self.receipt.clone())
            }
            fn abort(&self, _: &ConsumeKey<'_>) -> Result<Abort, BridgeFailure> {
                self.aborted.set(true);
                Ok(Abort {
                    store_id: BRIDGE_ID.into(),
                    aborted: true,
                    receipt: Some(self.receipt.receipt.clone()),
                })
            }
        }
        consumed.receipt.observation.tool_name = "mcp__pool__pool_join".into();
        consumed.validity = Validity::Historical;
        assert_eq!(
            validate_consume(&consumed, &key, "pool", &command, "epoch"),
            Err(BridgeFailure::Refused)
        );
        consumed.validity = Validity::Current;
        let sim = Sim {
            receipt: consumed,
            aborted: std::cell::Cell::new(false),
        };
        assert!(
            consume_original(
                &sim,
                &key,
                &Secret::new("fixture"),
                "pool",
                &command,
                "epoch"
            )
            .is_ok()
        );
        assert!(abort_original(&sim, &key).is_ok());
        assert!(matches!(
            consume_original(
                &sim,
                &key,
                &Secret::new("fixture"),
                "pool",
                &command,
                "epoch"
            ),
            Err(BridgeFailure::Refused)
        ));
    }
    /// E16: the attested address's harness selects the one exact presented name.
    #[test]
    fn codex_tool_name_is_normalized_and_claude_stays_raw() {
        let command = Command::Join(Change {
            pool_id: "pool".into(),
            expected_revision: 1,
            request_key: "key".into(),
        });
        let digest = "a".repeat(64);
        let key = ConsumeKey {
            abort_request_id: "abort-1",
            expected_store_id: BRIDGE_ID,
            producer: "pool",
            consume_request_id: "consume",
            invocation_key: "inv",
            security_digest: &digest,
            audience: "audience",
        };
        let consumed = |harness: &str, tool: &str| Consumed {
            store_id: BRIDGE_ID.into(),
            validity: Validity::Current,
            aborted: false,
            receipt: ConsumeReceipt {
                producer: "pool".into(),
                consume_request_id: "consume".into(),
                invocation_key: "inv".into(),
                security_digest: digest.clone(),
                issuer_epoch: "epoch".into(),
                consumed_at_ms: 1,
                observation: Observation {
                    incarnation: Incarnation {
                        host_id: "host".into(),
                        boot_id: "00000000-0000-4000-8000-000000000002".into(),
                        pid_namespace_inode: 1,
                        uid: 1,
                        pid: 2,
                        start_ticks: 1,
                    },
                    launch_id: "00000000-0000-4000-8000-000000000003".into(),
                    actor: ManagedActor {
                        address: format!("host/{harness}/store/session"),
                        role: "root".into(),
                        native_id: "session".into(),
                        epoch: 1,
                    },
                    native_call_id: "call".into(),
                    tool_name: tool.into(),
                    observed_at_ms: 1,
                    expires_at_ms: 2,
                },
            },
        };
        let check = |harness: &str, server: &str, tool: &str| {
            validate_consume(&consumed(harness, tool), &key, server, &command, "epoch")
        };
        let normalized = "mcp__agent_pool__pool_join";
        let raw = "mcp__agent-pool__pool_join";
        assert!(check("codex", "agent-pool", normalized).is_ok());
        assert!(check("claude-code", "agent-pool", raw).is_ok());
        // Harness mismatch between the attested address and the presented name.
        assert_eq!(
            check("codex", "agent-pool", raw),
            Err(BridgeFailure::Refused)
        );
        assert_eq!(
            check("claude-code", "agent-pool", normalized),
            Err(BridgeFailure::Refused)
        );
        // Unserved harnesses never borrow either rule.
        for harness in ["opencode", "gemini", "codex-cli"] {
            for tool in [normalized, raw] {
                assert_eq!(
                    check(harness, "agent-pool", tool),
                    Err(BridgeFailure::Refused)
                );
            }
        }
        // Hashed substitutes, hook-join trims and near variants are not the exact name.
        let sha1 = "0f6a3c2b9d8e7f1a2b3c4d5e6f708192a3b4c5d6";
        for tool in [
            format!("mcp__{sha1}"),
            format!("mcp__agent_pool__{sha1}"),
            format!("mcp__agent_pool_{sha1}__pool_join"),
            format!("mcp__agent_pool__pool_join_{sha1}"),
            "mcp__agent_pool_pool_join".into(),
            "mcp_agent_pool__pool_join".into(),
            "agent_pool__pool_join".into(),
            "mcp__agent_pool__pool_join ".into(),
            " mcp__agent_pool__pool_join".into(),
            "mcp__agent_pool__Pool_join".into(),
            "mcp__agent_pool__pool_vote".into(),
            "mcp__agent_pool___pool_join".into(),
        ] {
            assert_eq!(
                check("codex", "agent-pool", &tool),
                Err(BridgeFailure::Refused),
                "{tool}"
            );
        }
        // Servers whose Codex segment is trimmed or ambiguous have no Codex name at all,
        // including the trimmed form Codex would actually present.
        for server in [
            "-agent-pool",
            "agent-pool-",
            "agent--pool",
            "agent_-pool",
            "",
            "_",
        ] {
            assert!(managed_tool_name("codex", server, "pool_join").is_none());
            assert!(!valid_managed_server(server));
            assert_eq!(
                check("codex", server, normalized),
                Err(BridgeFailure::Refused)
            );
        }
        // Commands must be fixed points that the hook join does not trim.
        assert!(managed_tool_name("codex", "pool", "pool-join").is_none());
        assert!(managed_tool_name("codex", "pool", "_pool_join").is_none());
        assert!(managed_tool_name("codex", "pool", "").is_none());
        // Names over 128 bytes get a hashed substitute, so they are refused.
        let long = "c".repeat(128 - "mcp__pool__".len());
        assert_eq!(
            managed_tool_name("codex", "pool", &long).map(|name| name.len()),
            Some(128)
        );
        assert!(managed_tool_name("codex", "pool", &format!("{long}c")).is_none());
        assert!(valid_managed_server("pool") && valid_managed_server("agent-pool"));
        assert!(!valid_managed_server("a__b") && !valid_managed_server("a.b"));
    }
    #[test]
    fn relaunch_required_is_typed_only_with_no_automatic_recovery() {
        use bridge_sdk::bridge_protocol::attempt::{AttemptErrorV1, RecoveryV1};
        let refusal = |recovery| {
            bridge_sdk::AttemptClientError::Refused(AttemptErrorV1 {
                version: 1,
                store_id: BRIDGE_ID.into(),
                code: "relaunch_required".into(),
                recovery,
            })
        };
        assert_eq!(
            bridge_failure(refusal(RecoveryV1::None)),
            BridgeFailure::RelaunchRequired
        );
        assert_eq!(
            fault(BridgeFailure::RelaunchRequired),
            Fault::RelaunchRequired
        );
        assert_eq!(
            bridge_failure(refusal(RecoveryV1::SameKeyLookup)),
            BridgeFailure::Unknown
        );
    }
    #[tokio::test]
    async fn bridge_recovery_requires_exact_pinned_credential_and_endpoint() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let directory = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let registration = directory.path().join("adapter.sock");
        let core = directory.path().join("core.sock");
        let _registration = tokio::net::UnixListener::bind(&registration).unwrap();
        let _core = tokio::net::UnixListener::bind(&core).unwrap();
        for path in [&registration, &core] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let token = directory.path().join("token");
        std::fs::write(&token, "fixture-one").unwrap();
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
        let uid = std::fs::metadata(directory.path()).unwrap().uid();
        let config = crate::config::Config {
            socket_path: directory.path().join("pool.sock"),
            database_path: directory.path().join("pool.db"),
            expected_uid: uid,
            bridge_registration_socket: registration,
            bridge_core_socket: core,
            bridge_credential_file: token.clone(),
            bridge_producer_id: "pool".into(),
            bridge_audience: "pool".into(),
            bridge_server_executable: "/fixture/bridge".into(),
            bridge_server_sha256: "a".repeat(64),
            bridge_observer_socket: None,
            bridge_observer_credential_file: None,
            owner_observer_credential_file: None,
            run_socket: None,
            run_peer_uid: None,
            managed_run_reader: None,
            managed_run_transport: None,
        };
        let route = crate::managed_state::Route {
            component_store_id: BRIDGE_ID.into(),
            route_id: "bridge-route".into(),
            worker_uid: uid,
        };
        let (_client, pin) = SdkBridge::capture(&config, route).unwrap();
        assert!(SdkBridge::recover(&config, &pin).is_ok());
        std::fs::write(&token, "fixture-two").unwrap();
        assert!(matches!(
            SdkBridge::recover(&config, &pin),
            Err(Fault::Unavailable)
        ));
    }
    /// The managed proof seam accepts pipe stdio and rejects a non-pipe endpoint.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn managed_transport_scope() {
        if let Ok(mode) = std::env::var("POOL_STDIO_SYNTHETIC_MODE") {
            let result = require_stdio_transport();
            if mode == "pipe" {
                assert!(result.is_ok());
            } else {
                assert!(result.is_err());
            }
            return;
        }
        for mode in ["pipe", "null"] {
            let mut child = tokio::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "managed_bridge::tests::managed_transport_scope",
                    "--nocapture",
                ])
                .env_clear()
                .env("POOL_STDIO_SYNTHETIC_MODE", mode)
                .stdin(if mode == "pipe" {
                    std::process::Stdio::piped()
                } else {
                    std::process::Stdio::null()
                })
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let status = tokio::time::timeout(std::time::Duration::from_secs(10), child.wait())
                .await
                .unwrap()
                .unwrap();
            assert!(status.success(), "{mode} stdio fixture failed");
        }
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn typed_sdk_adapter_exchanges_with_isolated_b1_peer() {
        use crate::managed_egress::{OwnerFailure, ScopePlan};
        use sha2::Digest;
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::{fs::PermissionsExt, net::UnixListener};

        // The child is a task-owned, non-writable copy of this test executable.
        // Its separate process is the actual peer whose loaded image the SDK checks.
        if let Some(socket) = std::env::var_os("POOL_B1_SYNTHETIC_SOCKET") {
            let listener = UnixListener::bind(socket).unwrap();
            let issuer = "epoch:opaque";
            let digest = "a".repeat(64);
            for index in 0..11 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut line = String::new();
                let count = BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut line)
                    .unwrap();
                if index < 2 {
                    assert_eq!(count, 0);
                    continue;
                }
                let request: serde_json::Value = serde_json::from_str(&line).unwrap();
                let op = request["op"].as_str().unwrap();
                if index == 8 {
                    assert_eq!(op, "consume_launch_assertion_v1");
                    let response = serde_json::json!({"api_version":1,"request_id":request["request_id"],"success":true,"result":{"op":op,"value":{"status":"error","error":{"version":1,"store_id":BRIDGE_ID,"code":"relaunch_required","recovery":"none"}}}});
                    writeln!(stream, "{response}").unwrap();
                    continue;
                }
                if index >= 9 {
                    assert_eq!(op, "retire_delivery_scope");
                    assert_eq!(request["request_id"], "retire");
                    assert_eq!(request["params"]["action"], "retire_unhanded");
                    let scope = request["params"]["scope_key"].as_str().unwrap();
                    assert!(scope.starts_with("pool/"));
                    if index == 9 {
                        // The retirement may have committed, but its ACK was lost.
                        continue;
                    }
                    let response = serde_json::json!({"api_version":1,"request_id":"retire","success":true,"result":{"op":op,"value":{"receipt":{"producer":"pool","request_id":"retire","scope_key":scope,"action":"retire_unhanded","retired_at_ms":1,"disposed":0,"already_terminal":1,"preserved_possible_effect":0,"preserved_unhanded":0},"replayed":index==10}}});
                    writeln!(stream, "{response}").unwrap();
                    continue;
                }
                let observation = serde_json::json!({"incarnation":{"host_id":"host","boot_id":"00000000-0000-4000-8000-000000000003","pid_namespace_inode":1,"uid":1,"pid":2,"start_ticks":1},"launch_id":"00000000-0000-4000-8000-000000000004","actor":{"address":"host/codex/store/session","role":"root","native_id":"session","epoch":1},"native_call_id":"call","tool_name":"mcp__pool__pool_join","observed_at_ms":1,"expires_at_ms":2});
                let receipt = serde_json::json!({"producer":"pool","consume_request_id":"consume","invocation_key":"inv","security_digest":digest,"observation":observation,"issuer_epoch":issuer,"consumed_at_ms":1});
                let value = match op {
                    "attempt_binding_capabilities_v1" => {
                        serde_json::json!({"version":1,"store_id":BRIDGE_ID,"issuer_epoch":issuer,"capabilities":["attempt_launch_v1","launch_assertion_v1","namespace_retirement_v1"]})
                    }
                    "prepare_native_context_v1" => {
                        serde_json::json!({"version":1,"store_id":BRIDGE_ID,"bridge_context_ref":"ctx","invocation_key":"inv","expires_at_ms":2})
                    }
                    "register_launch_assertion_v1" => {
                        serde_json::json!({"version":1,"store_id":BRIDGE_ID,"assertion_key":"key","invocation_key":"inv","issuer_epoch":issuer,"expires_at_ms":2})
                    }
                    "consume_launch_assertion_v1" => {
                        serde_json::json!({"version":1,"store_id":BRIDGE_ID,"receipt":receipt,"validity":"current","aborted":false})
                    }
                    "observation_lookup_v1" => {
                        serde_json::json!({"version":1,"store_id":BRIDGE_ID,"receipt":receipt,"validity":"historical","aborted":false})
                    }
                    "consume_launch_assertion_abort_v1" => {
                        serde_json::json!({"version":1,"store_id":BRIDGE_ID,"receipt":receipt,"aborted":true})
                    }
                    _ => panic!("unexpected synthetic operation"),
                };
                let response = serde_json::json!({"api_version":1,"request_id":request["request_id"],"success":true,"result":{"op":op,"value":{"status":"ok","value":value}}});
                writeln!(stream, "{response}").unwrap();
            }
            return;
        }

        let _hash_guard = crate::TEST_EXEC_HASH_LOCK.blocking_lock();
        let directory = tempfile::tempdir_in(std::env::var_os("TMPDIR").unwrap()).unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = directory.path().join("bridge.sock");
        let executable = directory.path().join("fake-bridge");
        std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o500)).unwrap();
        let alternate = directory.path().join("other-bridge");
        std::fs::hard_link(&executable, &alternate).unwrap();
        struct ChildGuard(std::process::Child);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let process = std::process::Command::new(&executable)
            .args([
                "--exact",
                "managed_bridge::tests::typed_sdk_adapter_exchanges_with_isolated_b1_peer",
                "--nocapture",
            ])
            .env_clear()
            .env("POOL_B1_SYNTHETIC_SOCKET", &socket)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .unwrap();
        let mut process = ChildGuard(process);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while !socket.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "synthetic Bridge did not bind"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut config = bridge_sdk::Config::new(
            &socket,
            &socket,
            Secret::new("fixture-only"),
            // Each synthetic exchange hashes the full debug test binary.
            std::time::Duration::from_secs(60),
        )
        .unwrap();
        config.reconnect_once = false;
        let sha = format!(
            "{:x}",
            sha2::Sha256::digest(std::fs::read(&executable).unwrap())
        );
        let bridge = SdkBridge {
            client: bridge_sdk::Client::new(config).unwrap(),
            server_pin: bridge_sdk::attempt::AttemptServerPin::new(&executable, sha.clone())
                .unwrap(),
        };
        let wrong = SdkBridge {
            client: bridge.client.clone(),
            server_pin: bridge_sdk::attempt::AttemptServerPin::new(&executable, "0".repeat(64))
                .unwrap(),
        };
        assert!(matches!(wrong.capabilities(), Err(BridgeFailure::Unknown)));
        let wrong_peer = SdkBridge {
            client: bridge.client.clone(),
            server_pin: bridge_sdk::attempt::AttemptServerPin::new(&alternate, sha).unwrap(),
        };
        assert!(matches!(
            wrong_peer.capabilities(),
            Err(BridgeFailure::Unknown)
        ));
        let (_fixture_dir, _fixture_store, binding, _incarnation, _run) =
            crate::managed_state::tests::fixture();
        let scope = ScopePlan {
            producer_scope: crate::managed_egress::producer_scope(
                &binding.pool_store_id,
                "pool",
                "member",
                false,
            )
            .unwrap(),
            bridge_pin: crate::managed_state::tests::fake_bridge_pin(&binding),
            audience: "pool".into(),
            retire_request_id: "retire".into(),
            needs_retire: true,
        };
        assert!(matches!(
            crate::managed_egress::OwnerClient::retire(&wrong_peer, "retire", &scope),
            Err(OwnerFailure::NotSent(_))
        ));
        assert!(matches!(
            crate::managed_egress::OwnerClient::retire(&bridge, "different", &scope),
            Err(OwnerFailure::NotSent(_))
        ));
        let issuer = "epoch:opaque";
        let digest = "a".repeat(64);
        assert_eq!(discover(&bridge, BRIDGE_ID).unwrap(), issuer);
        let proof = CallEvidence::Native {
            host: bridge_sdk::bridge_protocol::Host::Codex,
            metadata: serde_json::Map::new(),
        };
        let prepared = bridge
            .prepare(&Prepare {
                request_id: "prepare",
                expected_store_id: BRIDGE_ID,
                expected_issuer_epoch: issuer,
                invocation_key: "inv",
                command_name: "pool_join",
                native_proof: &proof,
            })
            .unwrap();
        assert_eq!(prepared.bridge_context_ref.expose(), "ctx");
        let registered = bridge
            .register(&Registration {
                request_id: "register",
                expected_store_id: BRIDGE_ID,
                bridge_context_ref: prepared.bridge_context_ref.expose(),
                invocation_key: "inv",
                command_name: "pool_join",
                security_digest: &digest,
                audience: "pool",
                nonce: "nonce",
                native_proof: &proof,
            })
            .unwrap();
        let key = ConsumeKey {
            abort_request_id: "abort",
            expected_store_id: BRIDGE_ID,
            producer: "pool",
            consume_request_id: "consume",
            invocation_key: "inv",
            security_digest: &digest,
            audience: "pool",
        };
        let command = Command::Join(Change {
            pool_id: "pool".into(),
            expected_revision: 1,
            request_key: "key".into(),
        });
        let consumed = consume_original(
            &bridge,
            &key,
            &registered.assertion_key,
            "pool",
            &command,
            issuer,
        )
        .unwrap();
        assert_eq!(consumed.receipt.invocation_key, "inv");
        let recovered = bridge.lookup("lookup", &key).unwrap();
        assert_eq!(recovered.receipt.security_digest, digest);
        assert!(matches!(recovered.validity, Validity::Historical));
        assert_eq!(
            validate_consume(&recovered, &key, "pool", &command, issuer),
            Err(BridgeFailure::Refused)
        );
        assert!(abort_original(&bridge, &key).unwrap().aborted);
        assert!(matches!(
            consume_original(
                &bridge,
                &key,
                &registered.assertion_key,
                "pool",
                &command,
                issuer,
            ),
            Err(BridgeFailure::RelaunchRequired)
        ));
        assert!(matches!(
            crate::managed_egress::OwnerClient::retire(&bridge, "retire", &scope),
            Err(OwnerFailure::Unknown)
        ));
        let replayed =
            crate::managed_egress::OwnerClient::retire(&bridge, "retire", &scope).unwrap();
        assert_eq!(replayed.receipt.scope_key, scope.producer_scope);
        assert_eq!(replayed.receipt.request_id, "retire");
        assert!(replayed.replayed);
        assert!(process.0.wait().unwrap().success());
    }
}

/// Adapter to the typed Bridge SDK; deployment still must enable the managed path separately.
#[derive(Clone)]
pub(crate) struct SdkBridge {
    pub(crate) client: bridge_sdk::Client,
    pub(crate) server_pin: bridge_sdk::attempt::AttemptServerPin,
}
impl SdkBridge {
    /// Capture the exact endpoint, build and credential identity without making a network call.
    pub fn capture(
        config: &crate::config::Config,
        route: crate::managed_state::Route,
    ) -> Result<(Self, BridgePin), Fault> {
        use sha2::Digest;
        crate::integrations::own_uid(config.expected_uid)?;
        if route.worker_uid != config.expected_uid
            || !canonical_uuid(&route.component_store_id)
            || route.route_id.is_empty()
        {
            return Err(Fault::Invalid);
        }
        crate::config::private_socket(&config.bridge_registration_socket, config.expected_uid)?;
        crate::config::private_socket(&config.bridge_core_socket, config.expected_uid)?;
        let credential = config.credential(&config.bridge_credential_file)?;
        let credential_sha256 = format!("{:x}", sha2::Sha256::digest(credential.as_bytes()));
        // The unoptimized synthetic test executable is much larger than a release server.
        #[cfg(test)]
        let timeout = crate::integrations::EXCHANGE_TIMEOUT.saturating_mul(6);
        #[cfg(not(test))]
        let timeout = crate::integrations::EXCHANGE_TIMEOUT;
        let mut sdk = bridge_sdk::Config::new(
            &config.bridge_registration_socket,
            &config.bridge_core_socket,
            Secret::new(credential),
            timeout,
        )
        .map_err(|_| Fault::Unavailable)?;
        sdk.reconnect_once = false;
        let server_pin = bridge_sdk::attempt::AttemptServerPin::new(
            config.bridge_server_executable.clone(),
            config.bridge_server_sha256.clone(),
        )
        .map_err(|_| Fault::Invalid)?;
        let pin = BridgePin {
            route,
            producer: config.bridge_producer_id.clone(),
            registration_socket: config.bridge_registration_socket.clone(),
            core_socket: config.bridge_core_socket.clone(),
            server_executable: config.bridge_server_executable.clone(),
            server_sha256: config.bridge_server_sha256.clone(),
            credential_file: config.bridge_credential_file.clone(),
            credential_sha256,
        };
        Ok((
            Self {
                client: bridge_sdk::Client::new(sdk).map_err(|_| Fault::Unavailable)?,
                server_pin,
            },
            pin,
        ))
    }
    /// Reconstruct only the exact originally persisted Bridge endpoint and credential identity.
    pub fn recover(config: &crate::config::Config, expected: &BridgePin) -> Result<Self, Fault> {
        let (client, actual) = Self::capture(config, expected.route.clone())?;
        if &actual != expected {
            return Err(Fault::Unavailable);
        }
        Ok(client)
    }
}
fn bridge_failure(error: bridge_sdk::AttemptClientError) -> BridgeFailure {
    match error {
        bridge_sdk::AttemptClientError::Refused(refusal) if refusal.code == "relaunch_required" => {
            if matches!(
                refusal.recovery,
                bridge_sdk::bridge_protocol::attempt::RecoveryV1::None
            ) {
                BridgeFailure::RelaunchRequired
            } else {
                BridgeFailure::Unknown
            }
        }
        bridge_sdk::AttemptClientError::Refused(refusal)
            if matches!(
                refusal.recovery,
                bridge_sdk::bridge_protocol::attempt::RecoveryV1::None
                    | bridge_sdk::bridge_protocol::attempt::RecoveryV1::FreshInvocation
            ) =>
        {
            BridgeFailure::Refused
        }
        bridge_sdk::AttemptClientError::InvalidRequest(_) => BridgeFailure::Refused,
        _ => BridgeFailure::Unknown,
    }
}
fn convert_receipt(
    receipt: bridge_sdk::bridge_protocol::attempt::ConsumeReceiptV1,
) -> Result<ConsumeReceipt, BridgeFailure> {
    let value = serde_json::to_value(receipt).map_err(|_| BridgeFailure::Unknown)?;
    serde_json::from_value(value).map_err(|_| BridgeFailure::Unknown)
}
impl BridgeB1Client for SdkBridge {
    fn capabilities(&self) -> Result<Capabilities, BridgeFailure> {
        use bridge_sdk::bridge_protocol::attempt::AttemptCapabilitiesParamsV1;
        let response = self
            .client
            .attempt_binding_capabilities_v1(
                crate::domain::id(),
                &self.server_pin,
                AttemptCapabilitiesParamsV1 { version: 1 },
            )
            .map_err(bridge_failure)?;
        Ok(Capabilities {
            store_id: response.store_id,
            issuer_epoch: response.issuer_epoch,
            capabilities: response.capabilities,
        })
    }
    fn prepare(&self, request: &Prepare<'_>) -> Result<Prepared, BridgeFailure> {
        use bridge_sdk::bridge_protocol::attempt::PrepareNativeContextParamsV1;
        let result = self.client.prepare_native_context_v1(
            request.request_id,
            &self.server_pin,
            PrepareNativeContextParamsV1 {
                version: 1,
                expected_store_id: request.expected_store_id.into(),
                expected_issuer_epoch: request.expected_issuer_epoch.into(),
                invocation_key: request.invocation_key.into(),
                command_name: request.command_name.into(),
                native_proof: request.native_proof.clone(),
            },
        );
        let response = match result {
            Ok(response) => response,
            Err(bridge_sdk::AttemptClientError::Refused(refusal))
                if refusal.code == "assertion_stale" =>
            {
                let fresh = self.capabilities()?;
                if fresh.store_id != request.expected_store_id {
                    return Err(BridgeFailure::Unknown);
                }
                return if fresh.issuer_epoch != request.expected_issuer_epoch {
                    Err(BridgeFailure::StaleEpoch)
                } else {
                    Err(BridgeFailure::Refused)
                };
            }
            Err(error) => return Err(bridge_failure(error)),
        };
        Ok(Prepared {
            store_id: response.store_id,
            bridge_context_ref: response.bridge_context_ref,
            invocation_key: response.invocation_key,
            expires_at_ms: response.expires_at_ms,
        })
    }
    fn register(&self, request: &Registration<'_>) -> Result<Registered, BridgeFailure> {
        use bridge_sdk::bridge_protocol::attempt::RegisterLaunchAssertionParamsV1;
        let response = self
            .client
            .register_launch_assertion_v1(
                request.request_id,
                &self.server_pin,
                RegisterLaunchAssertionParamsV1 {
                    version: 1,
                    expected_store_id: request.expected_store_id.into(),
                    bridge_context_ref: Secret::new(request.bridge_context_ref),
                    invocation_key: request.invocation_key.into(),
                    command_name: request.command_name.into(),
                    security_digest: request.security_digest.into(),
                    audience: request.audience.into(),
                    nonce: request.nonce.into(),
                    native_proof: request.native_proof.clone(),
                },
            )
            .map_err(bridge_failure)?;
        Ok(Registered {
            store_id: response.store_id,
            assertion_key: response.assertion_key,
            invocation_key: response.invocation_key,
            issuer_epoch: response.issuer_epoch,
            expires_at_ms: response.expires_at_ms,
        })
    }
    fn consume(
        &self,
        key: &ConsumeKey<'_>,
        assertion_key: &Secret,
    ) -> Result<Consumed, BridgeFailure> {
        use bridge_sdk::bridge_protocol::attempt::{ConsumeLaunchAssertionParamsV1, ValidityV1};
        let response = self
            .client
            .consume_launch_assertion_v1(
                key.consume_request_id,
                &self.server_pin,
                ConsumeLaunchAssertionParamsV1 {
                    version: 1,
                    expected_store_id: key.expected_store_id.into(),
                    assertion_key: assertion_key.clone(),
                    invocation_key: key.invocation_key.into(),
                    security_digest: key.security_digest.into(),
                },
            )
            .map_err(bridge_failure)?;
        Ok(Consumed {
            store_id: response.store_id,
            receipt: convert_receipt(response.receipt)?,
            validity: match response.validity {
                ValidityV1::Current => Validity::Current,
                ValidityV1::Historical => Validity::Historical,
            },
            aborted: response.aborted,
        })
    }
    fn lookup(&self, request_id: &str, key: &ConsumeKey<'_>) -> Result<Consumed, BridgeFailure> {
        use bridge_sdk::bridge_protocol::attempt::{ObservationLookupParamsV1, ValidityV1};
        let response = self
            .client
            .observation_lookup_v1(
                request_id,
                &self.server_pin,
                ObservationLookupParamsV1 {
                    version: 1,
                    expected_store_id: key.expected_store_id.into(),
                    producer: key.producer.into(),
                    consume_request_id: key.consume_request_id.into(),
                    invocation_key: key.invocation_key.into(),
                    security_digest: key.security_digest.into(),
                },
            )
            .map_err(bridge_failure)?;
        Ok(Consumed {
            store_id: response.store_id,
            receipt: convert_receipt(response.receipt)?,
            validity: match response.validity {
                ValidityV1::Current => Validity::Current,
                ValidityV1::Historical => Validity::Historical,
            },
            aborted: response.aborted,
        })
    }
    fn abort(&self, key: &ConsumeKey<'_>) -> Result<Abort, BridgeFailure> {
        use bridge_sdk::bridge_protocol::attempt::ConsumeAbortParamsV1;
        let response = self
            .client
            .consume_launch_assertion_abort_v1(
                key.abort_request_id,
                &self.server_pin,
                ConsumeAbortParamsV1 {
                    version: 1,
                    expected_store_id: key.expected_store_id.into(),
                    producer: key.producer.into(),
                    consume_request_id: key.consume_request_id.into(),
                    invocation_key: key.invocation_key.into(),
                    security_digest: key.security_digest.into(),
                    audience: key.audience.into(),
                },
            )
            .map_err(bridge_failure)?;
        Ok(Abort {
            store_id: response.store_id,
            aborted: response.aborted,
            receipt: response.receipt.map(convert_receipt).transpose()?,
        })
    }
}
