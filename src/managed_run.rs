//! Isolated Run R2 wire client. It is not enabled by the legacy participant ingress.
use crate::{
    integrations::{EXCHANGE_TIMEOUT, MAX_FRAME, read_frame},
    managed_state::{
        AttemptRef, CurrentIntent, CurrentReceipt, Incarnation, ManagedBinding, Route,
        RunAuthority, RunEndpointPin, RunPin, SuccessorProof, VerifiedBallot, VoterObservation,
        VoterState,
    },
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
use std::{fs, os::unix::fs::MetadataExt, path::PathBuf};
#[cfg(target_os = "linux")]
use std::{fs::File, io::Read};
use tokio::{io::AsyncWriteExt, net::UnixStream};

// The synthetic peer is the debug test binary (>200 MiB), which is hashed on
// every connection. Keep production's ten-second bound while allowing loaded
// parallel test hosts to finish the same full executable verification.
#[cfg(test)]
const RUN_EXCHANGE_TIMEOUT: std::time::Duration = EXCHANGE_TIMEOUT.saturating_mul(6);
#[cfg(not(test))]
const RUN_EXCHANGE_TIMEOUT: std::time::Duration = EXCHANGE_TIMEOUT;

/// A provisioned endpoint and peer build, frozen alongside every durable request.
#[derive(Clone)]
pub(crate) struct RunPeer {
    pub socket: PathBuf,
    pub expected_uid: u32,
    pub executable: PathBuf,
    pub sha256: String,
    pub route: Route,
    pub pool_route: Route,
    pub bridge_route: Route,
    pub producer: String,
    /// Previously verified capabilities retained with the original route for exact recovery.
    pub recovery_capabilities: Vec<String>,
}
/// One authenticated receipt, obtained before the Pool store lock is acquired.
pub(crate) struct CurrentAuthority {
    route: Route,
    endpoint: RunEndpointPin,
    receipt: CurrentReceipt,
    invocation_key: Option<String>,
    request_id: Option<String>,
    request: Option<Value>,
}
/// One bounded collection of Run observations; each entry is tied to its exact voter.
pub(crate) struct ConsensusAuthority {
    entries: Vec<(
        Route,
        AttemptRef,
        Incarnation,
        Result<VoterObservation, crate::domain::Fault>,
    )>,
}
impl ConsensusAuthority {
    /// Combine separately authenticated Run routes without conflating voter identities.
    pub(crate) fn combine(groups: Vec<Self>) -> Result<Self, RunError> {
        let mut entries = Vec::new();
        for group in groups {
            for entry in group.entries {
                if entries.len() == 20
                    || entries
                        .iter()
                        .any(|prior: &(Route, AttemptRef, Incarnation, _)| {
                            prior.0 == entry.0 && prior.1 == entry.1 && prior.2 == entry.2
                        })
                {
                    return Err(RunError::Invalid);
                }
                entries.push(entry);
            }
        }
        Ok(Self { entries })
    }
}
impl RunAuthority for ConsensusAuthority {
    fn current_receipt(&self, _: &Route, _: &str) -> Result<CurrentReceipt, crate::domain::Fault> {
        Err(crate::domain::Fault::Unavailable)
    }
    fn consensus(
        &self,
        route: &Route,
        attempt: &AttemptRef,
        incarnation: &Incarnation,
    ) -> Result<VoterObservation, crate::domain::Fault> {
        self.entries
            .iter()
            .find(|(r, a, i, _)| r == route && a == attempt && i == incarnation)
            .map(|(_, _, _, result)| result.clone())
            .unwrap_or(Err(crate::domain::Fault::Unavailable))
    }
}
/// A separately persisted Run consensus request for one exact ballot.
pub(crate) struct VoterQuery {
    pin: RunPin,
    transport_id: String,
    request_id: String,
    attempt: AttemptRef,
    incarnation: Incarnation,
}

/// A Run egress request staged before contacting the original pinned route.
pub(crate) struct EgressQuery {
    pin: RunPin,
    transport_id: String,
    request_id: String,
    bound: AttemptRef,
}

/// The original protected Bridge reference, never a later process observation.
#[derive(Clone)]
pub(crate) struct IngressInput {
    pub bridge_route: Route,
    pub producer: String,
    pub observation_ref: bridge_sdk::bridge_protocol::Secret,
    pub invocation_key: String,
    pub request_id: String,
    pub transport_id: String,
}
/// An exact ingress request durably staged against one Run endpoint.
pub(crate) struct IngressQuery {
    pin: RunPin,
    input: IngressInput,
}
impl IngressQuery {
    pub(crate) fn stage(
        db: &mut rusqlite::Connection,
        pin: &RunPin,
        input: IngressInput,
    ) -> Result<Self, crate::domain::Fault> {
        if !wire_text(&input.request_id)
            || !wire_text(&input.transport_id)
            || !wire_text(&input.invocation_key)
            || input.observation_ref.expose().is_empty()
            || input.bridge_route.worker_uid != pin.route.worker_uid
        {
            return Err(crate::domain::Fault::Invalid);
        }
        let intent = CurrentIntent::Ingress {
            version: 1,
            expected_store_id: pin.route.component_store_id.clone(),
            request_id: input.request_id.clone(),
            observation_ref: input.observation_ref.clone(),
            invocation_key: input.invocation_key.clone(),
        };
        crate::managed_state::prepare_current_request(db, pin, &intent)?;
        Ok(Self {
            pin: pin.clone(),
            input,
        })
    }
    #[cfg(test)]
    pub(crate) fn fixture_authority(
        &self,
        receipt: CurrentReceipt,
    ) -> Result<CurrentAuthority, crate::domain::Fault> {
        let intent = CurrentIntent::Ingress {
            version: 1,
            expected_store_id: self.pin.route.component_store_id.clone(),
            request_id: self.input.request_id.clone(),
            observation_ref: self.input.observation_ref.clone(),
            invocation_key: self.input.invocation_key.clone(),
        };
        let endpoint = RunEndpointPin {
            route: self.pin.route.clone(),
            socket: self.pin.socket.clone(),
            executable: self.pin.executable.clone(),
            executable_sha256: self.pin.executable_sha256.clone(),
        };
        Ok(CurrentAuthority::fixture(
            endpoint,
            receipt,
            &self.input.invocation_key,
            &self.input.request_id,
            serde_json::to_value(intent).map_err(|_| crate::domain::Fault::Internal)?,
        ))
    }
}
impl EgressQuery {
    pub(crate) fn stage(
        db: &mut rusqlite::Connection,
        pin: &RunPin,
        bound: &AttemptRef,
        request_id: &str,
        transport_id: &str,
    ) -> Result<Self, crate::domain::Fault> {
        if !wire_text(request_id)
            || !wire_text(transport_id)
            || bound.run_store_id != pin.route.component_store_id
        {
            return Err(crate::domain::Fault::Invalid);
        }
        let intent = CurrentIntent::Egress {
            version: 1,
            expected_store_id: pin.route.component_store_id.clone(),
            request_id: request_id.into(),
            lineage_root_id: bound.lineage_root_id.clone(),
            bound_execution_id: bound.execution_id.clone(),
        };
        crate::managed_state::prepare_current_request(db, pin, &intent)?;
        Ok(Self {
            pin: pin.clone(),
            transport_id: transport_id.into(),
            request_id: request_id.into(),
            bound: bound.clone(),
        })
    }
}
impl VoterQuery {
    /// Stage the exact route, voter and permanent request key before any Run I/O.
    pub(crate) fn stage(
        db: &mut rusqlite::Connection,
        pin: &RunPin,
        voter: &VerifiedBallot,
        request_id: &str,
        transport_id: &str,
    ) -> Result<Self, crate::domain::Fault> {
        if !wire_text(request_id)
            || !wire_text(transport_id)
            || pin.route != voter.binding.run_route
            || voter.generation != voter.binding.binding_generation
            || voter.attempt != voter.binding.attempt
            || voter.incarnation.uid != pin.route.worker_uid
        {
            return Err(crate::domain::Fault::Invalid);
        }
        let intent = CurrentIntent::Consensus {
            version: 1,
            expected_store_id: pin.route.component_store_id.clone(),
            request_id: request_id.into(),
            lineage_root_id: voter.attempt.lineage_root_id.clone(),
            bound_execution_id: voter.attempt.execution_id.clone(),
            expected_attempt: voter.attempt.clone(),
            expected_incarnation: voter.incarnation.clone(),
        };
        crate::managed_state::prepare_current_request(db, pin, &intent)?;
        Ok(Self {
            pin: pin.clone(),
            transport_id: transport_id.into(),
            request_id: request_id.into(),
            attempt: voter.attempt.clone(),
            incarnation: voter.incarnation.clone(),
        })
    }
}
impl CurrentAuthority {
    pub(crate) fn receipt(&self) -> &CurrentReceipt {
        &self.receipt
    }
    pub(crate) fn route(&self) -> &Route {
        &self.route
    }
    pub(crate) fn endpoint(&self) -> &RunEndpointPin {
        &self.endpoint
    }
    pub(crate) fn invocation(&self) -> Option<&str> {
        self.invocation_key.as_deref()
    }
    pub(crate) fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }
    pub(crate) fn request(&self) -> Option<&Value> {
        self.request.as_ref()
    }
    pub(crate) fn matches_ingress(
        &self,
        binding: &ManagedBinding,
        incarnation: &Incarnation,
        invocation: &str,
    ) -> bool {
        self.route == binding.run_route
            && self.invocation_key.as_deref() == Some(invocation)
            && crate::managed_state::receipt_matches(
                &self.receipt,
                binding,
                binding,
                incarnation,
                "ingress",
            )
    }
    #[cfg(test)]
    pub(crate) fn fixture(
        endpoint: RunEndpointPin,
        receipt: CurrentReceipt,
        invocation: &str,
        request_id: &str,
        request: Value,
    ) -> Self {
        Self {
            route: endpoint.route.clone(),
            endpoint,
            receipt,
            invocation_key: Some(invocation.into()),
            request_id: Some(request_id.into()),
            request: Some(request),
        }
    }
    #[cfg(test)]
    pub(crate) fn egress_fixture(
        endpoint: RunEndpointPin,
        receipt: CurrentReceipt,
        request_id: &str,
        request: Value,
    ) -> Self {
        Self {
            route: endpoint.route.clone(),
            endpoint,
            receipt,
            invocation_key: None,
            request_id: Some(request_id.into()),
            request: Some(request),
        }
    }
}
impl RunAuthority for CurrentAuthority {
    fn current_receipt(
        &self,
        route: &Route,
        receipt_id: &str,
    ) -> Result<CurrentReceipt, crate::domain::Fault> {
        if route != &self.route || receipt_id != self.receipt.receipt_id {
            return Err(crate::domain::Fault::Unavailable);
        }
        Ok(self.receipt.clone())
    }
    fn consensus(
        &self,
        _: &Route,
        _: &AttemptRef,
        _: &Incarnation,
    ) -> Result<VoterObservation, crate::domain::Fault> {
        Err(crate::domain::Fault::Unavailable)
    }
}
/// Consumption identity pinned to the exact Bridge route and issuer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConsumedRef {
    pub bridge_route: Route,
    pub producer: String,
    pub consume_request_id: String,
    pub invocation_key: String,
    pub security_digest: String,
    pub issuer_epoch: String,
}
/// Exact Run admission, durable before the producer's acknowledgement.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Admission {
    pub admission_id: String,
    pub intent_id: String,
    pub security_digest: String,
    pub policy: String,
    pub binding: ManagedBinding,
    pub incarnation: Incarnation,
    pub successor_proof: SuccessorProof,
    pub consumed_ref: ConsumedRef,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireError {
    version: u8,
    store_id: String,
    code: String,
    recovery: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    id: String,
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<WireError>,
}
/// Transport uncertainty never proves a request had no effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RunError {
    Invalid,
    Refused,
    /// Run definitively has not bound or qualified this original observation yet.
    NotReady,
    Unknown,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tagged<T> {
    version: u8,
    store_id: String,
    #[serde(flatten)]
    value: T,
}
/// Discovery is not authority and must agree with the already pinned store.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Capabilities {
    pub capabilities: Vec<String>,
    pub policy: String,
}
/// Currentness is relative to the supplied voter provenance.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Consensus {
    pub state: VoterState,
    #[serde(deserialize_with = "crate::managed_state::required_option")]
    pub last_attempt: Option<AttemptRef>,
    #[serde(deserialize_with = "crate::managed_state::required_option")]
    pub last_incarnation: Option<Incarnation>,
    #[serde(deserialize_with = "crate::managed_state::required_option")]
    pub successor_proof: Option<SuccessorProof>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Current {
    pub state: String,
    pub receipt: CurrentReceipt,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CurrentLookup {
    pub receipt: CurrentReceipt,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Admitted {
    pub state: String,
    pub admission: Admission,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Lookup {
    pub state: String,
    #[serde(deserialize_with = "crate::managed_state::required_option")]
    pub admission: Option<Admission>,
    #[serde(deserialize_with = "crate::managed_state::required_option")]
    pub outcome_digest: Option<String>,
}

fn wire_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}
fn hash_text(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn classify_error(error: &WireError, expected_store_id: &str) -> RunError {
    if error.version != 1
        || error.store_id != expected_store_id
        || !wire_text(&error.code)
        || !["same_key_lookup", "fresh_invocation", "operator", "none"]
            .contains(&error.recovery.as_str())
    {
        return RunError::Unknown;
    }
    if error.code == "attempt_not_ready" && error.recovery == "same_key_lookup" {
        return RunError::NotReady;
    }
    if matches!(error.recovery.as_str(), "same_key_lookup" | "operator") {
        RunError::Unknown
    } else if [
        "unsupported_version",
        "capability_missing",
        "transport_unsupported",
        "role_unqualified",
        "peer_not_authorized",
        "audience_mismatch",
        "attempt_mismatch",
        "actor_mismatch",
        "route_mismatch",
        "binding_stale",
        "assertion_stale",
        "assertion_historical",
        "invocation_spent",
        "intent_conflict",
        "aborted",
    ]
    .contains(&error.code.as_str())
    {
        RunError::Refused
    } else {
        RunError::Unknown
    }
}

/// Kernel start ticks, read twice to reject a changed process during executable inspection.
fn start_ticks(pid: u32) -> Result<u64, RunError> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|_| RunError::Unknown)?;
    let end = text.rfind(')').ok_or(RunError::Unknown)?;
    text.get(end + 2..)
        .ok_or(RunError::Unknown)?
        .split_whitespace()
        .nth(19)
        .ok_or(RunError::Unknown)?
        .parse()
        .map_err(|_| RunError::Unknown)
}
/// Prove the peer is the configured currently loaded Linux executable before sending any bytes.
#[cfg(target_os = "linux")]
pub(crate) fn verify_peer(pid: u32, peer: &RunPeer) -> Result<(), RunError> {
    if pid <= 1 || !peer.executable.is_absolute() || !hash_text(&peer.sha256) {
        return Err(RunError::Invalid);
    }
    let before = start_ticks(pid)?;
    let process_path = format!("/proc/{pid}");
    if fs::metadata(&process_path)
        .map_err(|_| RunError::Unknown)?
        .uid()
        != peer.expected_uid
    {
        return Err(RunError::Unknown);
    }
    let namespace = fs::metadata(format!("{process_path}/ns/pid"))
        .map_err(|_| RunError::Unknown)?
        .ino();
    if namespace == 0
        || namespace
            != fs::metadata("/proc/self/ns/pid")
                .map_err(|_| RunError::Unknown)?
                .ino()
    {
        return Err(RunError::Unknown);
    }
    let exe = PathBuf::from(format!("/proc/{pid}/exe"));
    let configured = fs::canonicalize(&peer.executable).map_err(|_| RunError::Unknown)?;
    if configured != peer.executable {
        return Err(RunError::Unknown);
    }
    let actual = fs::canonicalize(&exe).map_err(|_| RunError::Unknown)?;
    if actual != configured {
        return Err(RunError::Unknown);
    }
    let metadata = fs::metadata(&exe).map_err(|_| RunError::Unknown)?;
    let expected = fs::metadata(&configured).map_err(|_| RunError::Unknown)?;
    if !metadata.is_file()
        || metadata.len() > 512 * 1024 * 1024
        || (metadata.dev(), metadata.ino()) != (expected.dev(), expected.ino())
    {
        return Err(RunError::Unknown);
    }
    let mut file = File::open(&exe).map_err(|_| RunError::Unknown)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = file.read(&mut buffer).map_err(|_| RunError::Unknown)?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    let after = fs::metadata(&exe).map_err(|_| RunError::Unknown)?;
    if (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    ) != (
        after.dev(),
        after.ino(),
        after.len(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    ) || before != start_ticks(pid)?
        || fs::metadata(&process_path)
            .map_err(|_| RunError::Unknown)?
            .uid()
            != peer.expected_uid
        || fs::metadata(format!("{process_path}/ns/pid"))
            .map_err(|_| RunError::Unknown)?
            .ino()
            != namespace
        || fs::metadata("/proc/self/ns/pid")
            .map_err(|_| RunError::Unknown)?
            .ino()
            != namespace
        || format!("{:x}", digest.finalize()) != peer.sha256
    {
        return Err(RunError::Unknown);
    }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
pub(crate) fn verify_peer(_pid: u32, _peer: &RunPeer) -> Result<(), RunError> {
    Err(RunError::Unknown)
}

impl RunPeer {
    /// Build an endpoint only from explicitly provisioned managed transport values.
    pub fn from_config(
        config: &crate::config::Config,
        pool_store_id: &str,
    ) -> Result<Self, RunError> {
        let transport = config
            .managed_run_transport
            .as_ref()
            .ok_or(RunError::Refused)?;
        if !uuid::Uuid::parse_str(pool_store_id).is_ok_and(|id| id.to_string() == pool_store_id) {
            return Err(RunError::Invalid);
        }
        let uid = config.expected_uid;
        Ok(Self {
            socket: transport.socket.clone(),
            expected_uid: uid,
            executable: transport.executable.clone(),
            sha256: transport.sha256.clone(),
            route: Route {
                component_store_id: transport.run_store_id.clone(),
                route_id: transport.run_route_id.clone(),
                worker_uid: uid,
            },
            pool_route: Route {
                component_store_id: pool_store_id.into(),
                route_id: transport.pool_route_id.clone(),
                worker_uid: uid,
            },
            bridge_route: Route {
                component_store_id: transport.bridge_store_id.clone(),
                route_id: transport.bridge_route_id.clone(),
                worker_uid: uid,
            },
            producer: transport.producer.clone(),
            recovery_capabilities: Vec::new(),
        })
    }
    /// Capture the configured original Run endpoint and build before discovery.
    pub fn endpoint_pin(&self) -> RunEndpointPin {
        RunEndpointPin {
            route: self.route.clone(),
            socket: self.socket.clone(),
            executable: self.executable.clone(),
            executable_sha256: self.sha256.clone(),
        }
    }
    /// Query every supplied voter after callers durably stage their exact request keys.
    pub async fn collect_voters(
        &self,
        queries: &[VoterQuery],
    ) -> Result<ConsensusAuthority, RunError> {
        if queries.len() > 20
            || queries.iter().enumerate().any(|(index, item)| {
                item.pin.route != self.route
                    || item.pin.socket != self.socket
                    || item.pin.executable != self.executable
                    || item.pin.executable_sha256 != self.sha256
                    || !item
                        .pin
                        .capabilities
                        .iter()
                        .any(|cap| cap == "attempt_consensus_v1")
                    || queries[..index].iter().any(|prior| {
                        prior.attempt == item.attempt && prior.incarnation == item.incarnation
                    })
            })
        {
            return Err(RunError::Invalid);
        }
        let mut entries = Vec::with_capacity(queries.len());
        for query in queries {
            let observation = self
                .consensus(
                    &query.transport_id,
                    &query.request_id,
                    &query.attempt,
                    &query.incarnation,
                )
                .await
                .map(|value| VoterObservation {
                    state: value.state,
                    last_attempt: value.last_attempt,
                    last_incarnation: value.last_incarnation,
                    successor_proof: value.successor_proof,
                })
                .map_err(|_| crate::domain::Fault::Unavailable);
            entries.push((
                self.route.clone(),
                query.attempt.clone(),
                query.incarnation.clone(),
                observation,
            ));
        }
        Ok(ConsensusAuthority { entries })
    }
    /// Reconstruct the original Run endpoint and capability fence without rediscovery.
    pub fn from_recovery(
        config: &crate::config::Config,
        recovery: &crate::managed_state::RecoveryIntent,
    ) -> Result<Self, RunError> {
        let pin = &recovery.run_pin;
        if !pin
            .capabilities
            .iter()
            .any(|capability| capability == "attempt_admission_v1")
            || recovery.pool_route.worker_uid != pin.route.worker_uid
            || recovery.consumed_ref.bridge_route.worker_uid != pin.route.worker_uid
        {
            return Err(RunError::Invalid);
        }
        let configured = Self::from_config(config, &recovery.pool_route.component_store_id)?;
        if configured.socket != pin.socket
            || configured.executable != pin.executable
            || configured.sha256 != pin.executable_sha256
            || configured.route != pin.route
            || configured.pool_route != recovery.pool_route
            || configured.bridge_route != recovery.consumed_ref.bridge_route
            || configured.producer != recovery.consumed_ref.producer
        {
            return Err(RunError::Unknown);
        }
        Ok(Self {
            socket: pin.socket.clone(),
            expected_uid: pin.route.worker_uid,
            executable: pin.executable.clone(),
            sha256: pin.executable_sha256.clone(),
            route: pin.route.clone(),
            pool_route: recovery.pool_route.clone(),
            bridge_route: recovery.consumed_ref.bridge_route.clone(),
            producer: recovery.consumed_ref.producer.clone(),
            recovery_capabilities: pin.capabilities.clone(),
        })
    }
    /// Discover and freeze the exact capability and authenticated endpoint before durable I/O staging.
    pub async fn current_pin(&self, capability: &str) -> Result<RunPin, RunError> {
        if !matches!(
            capability,
            "attempt_current_ingress_v1" | "attempt_current_egress_v1" | "attempt_consensus_v1"
        ) {
            return Err(RunError::Invalid);
        }
        let result = self.capabilities(&crate::domain::id()).await?;
        if !result.capabilities.iter().any(|item| item == capability) {
            return Err(RunError::Refused);
        }
        Ok(RunPin {
            route: self.route.clone(),
            socket: self.socket.clone(),
            executable: self.executable.clone(),
            executable_sha256: self.sha256.clone(),
            capabilities: result.capabilities,
        })
    }
    async fn require_current(&self, capability: &str) -> Result<(), RunError> {
        let current = self.capabilities(&crate::domain::id()).await?;
        if current.capabilities.iter().any(|item| item == capability) {
            Ok(())
        } else {
            Err(RunError::Refused)
        }
    }
    fn require_recovery(&self, capability: &str) -> Result<(), RunError> {
        if self
            .recovery_capabilities
            .iter()
            .any(|item| item == capability)
        {
            Ok(())
        } else {
            Err(RunError::Refused)
        }
    }
    /// Open only the pinned private same-UID endpoint and verify executable/build identity.
    async fn connect(&self) -> Result<UnixStream, RunError> {
        if self.route.worker_uid != self.expected_uid
            || !wire_text(&self.route.route_id)
            || crate::domain::store_id(&self.route.component_store_id).is_err()
            || self.pool_route.worker_uid != self.expected_uid
            || self.bridge_route.worker_uid != self.expected_uid
            || !wire_text(&self.pool_route.route_id)
            || !wire_text(&self.bridge_route.route_id)
            || !wire_text(&self.producer)
            || !uuid::Uuid::parse_str(&self.pool_route.component_store_id)
                .is_ok_and(|id| id.to_string() == self.pool_route.component_store_id)
            || !uuid::Uuid::parse_str(&self.bridge_route.component_store_id)
                .is_ok_and(|id| id.to_string() == self.bridge_route.component_store_id)
            || self
                .socket
                .file_name()
                .is_none_or(|name| name != "attempt.sock")
        {
            return Err(RunError::Invalid);
        }
        crate::config::private_socket(&self.socket, self.expected_uid)
            .map_err(|_| RunError::Unknown)?;
        let socket_before = fs::symlink_metadata(&self.socket).map_err(|_| RunError::Unknown)?;
        let parent = self.socket.parent().ok_or(RunError::Invalid)?;
        let parent_before = fs::symlink_metadata(parent).map_err(|_| RunError::Unknown)?;
        let stream = UnixStream::connect(&self.socket)
            .await
            .map_err(|_| RunError::Unknown)?;
        let credentials = stream.peer_cred().map_err(|_| RunError::Unknown)?;
        if credentials.uid() != self.expected_uid {
            return Err(RunError::Unknown);
        }
        let pid = u32::try_from(credentials.pid().ok_or(RunError::Unknown)?)
            .map_err(|_| RunError::Unknown)?;
        let peer = self.clone();
        tokio::task::spawn_blocking(move || verify_peer(pid, &peer))
            .await
            .map_err(|_| RunError::Unknown)??;
        if stream.peer_cred().map_err(|_| RunError::Unknown)?.pid()
            != Some(i32::try_from(pid).map_err(|_| RunError::Unknown)?)
        {
            return Err(RunError::Unknown);
        }
        crate::config::private_socket(&self.socket, self.expected_uid)
            .map_err(|_| RunError::Unknown)?;
        let socket_after = fs::symlink_metadata(&self.socket).map_err(|_| RunError::Unknown)?;
        let parent_after = fs::symlink_metadata(parent).map_err(|_| RunError::Unknown)?;
        if (
            socket_before.dev(),
            socket_before.ino(),
            socket_before.uid(),
            socket_before.mode(),
        ) != (
            socket_after.dev(),
            socket_after.ino(),
            socket_after.uid(),
            socket_after.mode(),
        ) || (
            parent_before.dev(),
            parent_before.ino(),
            parent_before.uid(),
            parent_before.mode(),
        ) != (
            parent_after.dev(),
            parent_after.ino(),
            parent_after.uid(),
            parent_after.mode(),
        ) {
            return Err(RunError::Unknown);
        }
        Ok(stream)
    }
    /// Exact operation and transport ID are internal constants/inputs; never echo unsafe diagnostics.
    async fn exchange<T: DeserializeOwned>(
        &self,
        id: &str,
        method: &str,
        params: Value,
    ) -> Result<T, RunError> {
        if !wire_text(id) {
            return Err(RunError::Invalid);
        }
        let mut encoded =
            serde_json::to_vec(&serde_json::json!({"id":id,"method":method,"params":params}))
                .map_err(|_| RunError::Invalid)?;
        if encoded.len() >= MAX_FRAME {
            return Err(RunError::Invalid);
        }
        encoded.push(b'\n');
        tokio::time::timeout(RUN_EXCHANGE_TIMEOUT, async {
            let mut stream = self.connect().await?;
            stream
                .write_all(&encoded)
                .await
                .map_err(|_| RunError::Unknown)?;
            let bytes = read_frame(&mut stream)
                .await
                .map_err(|_| RunError::Unknown)?;
            if bytes.len() >= MAX_FRAME {
                return Err(RunError::Unknown);
            }
            let decoded = crate::managed_codec::parse_raw(&bytes).map_err(|_| RunError::Unknown)?;
            let object = decoded.as_object().ok_or(RunError::Unknown)?;
            if object.contains_key("result") == object.contains_key("error")
                || object.get("result").is_some_and(Value::is_null)
                || object.get("error").is_some_and(Value::is_null)
            {
                return Err(RunError::Unknown);
            }
            let reply: Envelope = serde_json::from_value(decoded).map_err(|_| RunError::Unknown)?;
            if reply.id != id {
                return Err(RunError::Unknown);
            }
            if let Some(error) = reply.error {
                return Err(classify_error(&error, &self.route.component_store_id));
            }
            let result = reply.result.ok_or(RunError::Unknown)?;
            let fields = result.as_object().ok_or(RunError::Unknown)?;
            let required: &[&str] = match method {
                "_attempt_capabilities_v1" => &["capabilities", "policy"],
                "_attempt_current_receipt_v1" => &["receipt"],
                "_attempt_current_v1"
                    if params.get("purpose").and_then(Value::as_str) == Some("consensus") =>
                {
                    &[
                        "state",
                        "last_attempt",
                        "last_incarnation",
                        "successor_proof",
                    ]
                }
                "_attempt_current_v1" => &["state", "receipt"],
                "_attempt_admit_v1" => &["state", "admission"],
                "_attempt_admission_lookup_v1"
                | "_attempt_admission_abort_v1"
                | "_attempt_settle_v1" => &["state", "admission", "outcome_digest"],
                _ => return Err(RunError::Invalid),
            };
            if required.iter().any(|key| !fields.contains_key(*key)) {
                return Err(RunError::Unknown);
            }
            let tagged: Tagged<T> =
                serde_json::from_value(result).map_err(|_| RunError::Unknown)?;
            if tagged.version != 1 || tagged.store_id != self.route.component_store_id {
                return Err(RunError::Unknown);
            }
            Ok(tagged.value)
        })
        .await
        .map_err(|_| RunError::Unknown)?
    }
    /// Probe only the originally pinned store; no capability response can repin it.
    pub async fn capabilities(&self, id: &str) -> Result<Capabilities, RunError> {
        let result: Capabilities = self
            .exchange(
                id,
                "_attempt_capabilities_v1",
                serde_json::json!({"version":1}),
            )
            .await?;
        if result.policy != "admission_snapshot" {
            return Err(RunError::Unknown);
        }
        Ok(result)
    }
    /// Lookup of a durable current receipt never refreshes its authority.
    async fn current_receipt(
        &self,
        id: &str,
        receipt_id: &str,
    ) -> Result<CurrentReceipt, RunError> {
        let result:CurrentLookup=self.exchange(id,"_attempt_current_receipt_v1",serde_json::json!({"version":1,"expected_store_id":self.route.component_store_id,"receipt_id":receipt_id})).await?;
        if result.receipt.receipt_id != receipt_id {
            return Err(RunError::Unknown);
        }
        Ok(result.receipt)
    }
    /// Re-read an exact receipt over the pinned Run route before local rebind CAS.
    pub async fn verify_current_receipt(
        &self,
        id: &str,
        receipt: CurrentReceipt,
    ) -> Result<CurrentAuthority, RunError> {
        let capability = match receipt.purpose.as_str() {
            "ingress" => "attempt_current_ingress_v1",
            "egress" => "attempt_current_egress_v1",
            _ => return Err(RunError::Invalid),
        };
        self.require_current(capability).await?;
        let actual = self.current_receipt(id, &receipt.receipt_id).await?;
        if actual != receipt || receipt.attempt.run_store_id != self.route.component_store_id {
            return Err(RunError::Unknown);
        }
        Ok(CurrentAuthority {
            route: self.route.clone(),
            endpoint: self.endpoint_pin(),
            receipt,
            invocation_key: None,
            request_id: None,
            request: None,
        })
    }
    /// Read the current Run state relative to one exact previously verified voter.
    pub async fn consensus(
        &self,
        id: &str,
        request_id: &str,
        attempt: &AttemptRef,
        incarnation: &Incarnation,
    ) -> Result<Consensus, RunError> {
        if attempt.run_store_id != self.route.component_store_id
            || incarnation.uid != self.route.worker_uid
        {
            return Err(RunError::Invalid);
        }
        self.require_current("attempt_consensus_v1").await?;
        let params = serde_json::json!({"version":1,"expected_store_id":self.route.component_store_id,"request_id":request_id,"lineage_root_id":attempt.lineage_root_id,"bound_execution_id":attempt.execution_id,"purpose":"consensus","expected_attempt":attempt,"expected_incarnation":incarnation});
        let result: Consensus = self.exchange(id, "_attempt_current_v1", params).await?;
        match result.state {
            VoterState::Live | VoterState::TerminalNoSuccessor
                if result.last_attempt.as_ref() == Some(attempt)
                    && result.last_incarnation.as_ref() == Some(incarnation)
                    && result.successor_proof.is_some() =>
            {
                Ok(result)
            }
            VoterState::Superseded
                if result.last_attempt.is_some()
                    && result.last_incarnation.is_some()
                    && result.successor_proof.is_some() =>
            {
                Ok(result)
            }
            VoterState::Unavailable
                if result.last_attempt.is_none()
                    && result.last_incarnation.is_none()
                    && result.successor_proof.is_none() =>
            {
                Ok(result)
            }
            _ => Err(RunError::Unknown),
        }
    }
    /// Run rechecks the exact Bridge original context and current leader for ingress.
    pub async fn current_ingress(
        &self,
        query: &IngressQuery,
    ) -> Result<CurrentAuthority, RunError> {
        let input = &query.input;
        if query.pin.route != self.route
            || query.pin.socket != self.socket
            || query.pin.executable != self.executable
            || query.pin.executable_sha256 != self.sha256
            || !query
                .pin
                .capabilities
                .iter()
                .any(|cap| cap == "attempt_current_ingress_v1")
            || input.bridge_route != self.bridge_route
            || input.producer != self.producer
        {
            return Err(RunError::Invalid);
        }
        self.require_current("attempt_current_ingress_v1").await?;
        let params = serde_json::json!({"version":1,"expected_store_id":self.route.component_store_id,"request_id":input.request_id,"purpose":"ingress","observation_ref":input.observation_ref,"invocation_key":input.invocation_key});
        let result: Current = self
            .exchange(&input.transport_id, "_attempt_current_v1", params.clone())
            .await?;
        if result.state != "current"
            || !crate::managed_state::valid_ingress_receipt(&result.receipt, &self.route)
        {
            return Err(RunError::Unknown);
        }
        let mut authority = self
            .verify_current_receipt(&crate::domain::id(), result.receipt)
            .await?;
        authority.invocation_key = Some(input.invocation_key.clone());
        authority.request_id = Some(input.request_id.clone());
        authority.request = Some(params);
        Ok(authority)
    }
    /// Run checks the live lineage independently of an ingress context before target freezing.
    pub async fn current_egress(&self, query: &EgressQuery) -> Result<CurrentAuthority, RunError> {
        if query.pin.route != self.route
            || query.pin.socket != self.socket
            || query.pin.executable != self.executable
            || query.pin.executable_sha256 != self.sha256
            || !query
                .pin
                .capabilities
                .iter()
                .any(|cap| cap == "attempt_current_egress_v1")
        {
            return Err(RunError::Invalid);
        }
        self.require_current("attempt_current_egress_v1").await?;
        let params = serde_json::json!({"version":1,"expected_store_id":self.route.component_store_id,"request_id":query.request_id,"lineage_root_id":query.bound.lineage_root_id,"bound_execution_id":query.bound.execution_id,"purpose":"egress"});
        let result: Current = self
            .exchange(&query.transport_id, "_attempt_current_v1", params.clone())
            .await?;
        if result.state != "current"
            || result.receipt.purpose != "egress"
            || result.receipt.lineage_root_id != query.bound.lineage_root_id
            || result.receipt.bound_execution_id != query.bound.execution_id
        {
            return Err(RunError::Unknown);
        }
        let mut authority = self
            .verify_current_receipt(&crate::domain::id(), result.receipt)
            .await?;
        authority.request_id = Some(query.request_id.clone());
        authority.request = Some(params);
        Ok(authority)
    }
    /// Submit only the original intent and exact Bridge consume association.
    pub async fn admit(
        &self,
        id: &str,
        intent_id: &str,
        digest: &str,
        binding: &ManagedBinding,
        consumed: &ConsumedRef,
    ) -> Result<Admission, RunError> {
        self.require_current("attempt_admission_v1").await?;
        if !hash_text(digest)
            || consumed.security_digest != digest
            || binding.run_route != self.route
            || binding.bridge_route != consumed.bridge_route
            || binding.bridge_route != self.bridge_route
            || binding.pool_store_id != self.pool_route.component_store_id
            || consumed.producer != self.producer
        {
            return Err(RunError::Invalid);
        }
        let params = serde_json::json!({"version":1,"expected_store_id":self.route.component_store_id,"request_id":intent_id,"intent_id":intent_id,"security_digest":digest,"binding":binding,"consumed_ref":consumed,"policy":"admission_snapshot"});
        let result: Admitted = self.exchange(id, "_attempt_admit_v1", params).await?;
        let admission = result.admission;
        if result.state != "admitted"
            || admission.intent_id != intent_id
            || admission.security_digest != digest
            || admission.policy != "admission_snapshot"
            || admission.binding != *binding
            || admission.consumed_ref != *consumed
            || !wire_text(&admission.admission_id)
        {
            return Err(RunError::Unknown);
        }
        Ok(admission)
    }
    /// A negative lookup is a point-in-time observation, never an abort fence.
    pub async fn lookup(
        &self,
        id: &str,
        intent_id: &str,
        digest: &str,
    ) -> Result<Lookup, RunError> {
        self.require_recovery("attempt_admission_v1")?;
        if !hash_text(digest) {
            return Err(RunError::Invalid);
        }
        let params = serde_json::json!({"version":1,"expected_store_id":self.route.component_store_id,"intent_id":intent_id,"security_digest":digest});
        let result: Lookup = self
            .exchange(id, "_attempt_admission_lookup_v1", params)
            .await?;
        validate_lookup(result, intent_id, digest)
    }
    /// Install a Run abort fence or settle an already admitted intent through Pool outcome lookup.
    pub async fn abort(
        &self,
        id: &str,
        intent_id: &str,
        digest: &str,
        pool_route: &Route,
        outcome_digest: Option<&str>,
    ) -> Result<Lookup, RunError> {
        self.require_recovery("attempt_admission_v1")?;
        if !hash_text(digest)
            || outcome_digest.is_some_and(|d| !hash_text(d))
            || pool_route != &self.pool_route
        {
            return Err(RunError::Invalid);
        }
        let params = serde_json::json!({"version":1,"expected_store_id":self.route.component_store_id,"request_id":intent_id,"intent_id":intent_id,"security_digest":digest,"pool_route":pool_route,"pool_outcome_digest":outcome_digest});
        let result: Lookup = self
            .exchange(id, "_attempt_admission_abort_v1", params)
            .await?;
        let result = validate_lookup(result, intent_id, digest)?;
        if !matches!(
            result.state.as_str(),
            "aborted_before_admit" | "settled_aborted" | "settled_committed"
        ) || (matches!(
            result.state.as_str(),
            "settled_aborted" | "settled_committed"
        ) && result.outcome_digest.as_deref() != outcome_digest)
        {
            return Err(RunError::Unknown);
        }
        Ok(result)
    }
    /// Settle the original admission against Run's authenticated Pool outcome fetch.
    pub async fn settle(
        &self,
        id: &str,
        admission_id: &str,
        intent_id: &str,
        digest: &str,
        outcome_digest: &str,
    ) -> Result<Lookup, RunError> {
        self.require_recovery("attempt_admission_v1")?;
        if !hash_text(digest) || !hash_text(outcome_digest) {
            return Err(RunError::Invalid);
        }
        let params = serde_json::json!({"version":1,"expected_store_id":self.route.component_store_id,"admission_id":admission_id,"intent_id":intent_id,"security_digest":digest,"pool_outcome_digest":outcome_digest});
        let result: Lookup = self.exchange(id, "_attempt_settle_v1", params).await?;
        let result = validate_lookup(result, intent_id, digest)?;
        if result
            .admission
            .as_ref()
            .is_none_or(|a| a.admission_id != admission_id)
            || result.outcome_digest.as_deref() != Some(outcome_digest)
            || !matches!(
                result.state.as_str(),
                "settled_committed" | "settled_aborted"
            )
        {
            return Err(RunError::Unknown);
        }
        Ok(result)
    }
}

fn validate_lookup(result: Lookup, intent_id: &str, digest: &str) -> Result<Lookup, RunError> {
    if result.admission.as_ref().is_some_and(|a| {
        a.intent_id != intent_id || a.security_digest != digest || a.policy != "admission_snapshot"
    }) || result
        .outcome_digest
        .as_ref()
        .is_some_and(|v| !hash_text(v))
    {
        return Err(RunError::Unknown);
    }
    let valid = match result.state.as_str() {
        "absent" => result.admission.is_none() && result.outcome_digest.is_none(),
        "admitted" => result.admission.is_some() && result.outcome_digest.is_none(),
        "aborted_before_admit" => result.admission.is_none() && result.outcome_digest.is_none(),
        "settled_committed" | "settled_aborted" => {
            result.admission.is_some() && result.outcome_digest.is_some()
        }
        _ => false,
    };
    if valid {
        Ok(result)
    } else {
        Err(RunError::Unknown)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "Isolated synthetic same-process Unix peer fixture"
)]
mod tests {
    use super::*;
    use crate::managed_state::ManagedActor;
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    #[cfg(target_os = "linux")]
    use tokio::{io::AsyncReadExt, net::UnixListener};

    #[cfg(target_os = "linux")]
    fn local_peer(socket: PathBuf, uid: u32, executable: PathBuf, sha256: String) -> RunPeer {
        RunPeer {
            socket,
            expected_uid: uid,
            executable,
            sha256,
            route: Route {
                component_store_id: format!("store_{}", "a".repeat(32)),
                route_id: "route".into(),
                worker_uid: uid,
            },
            pool_route: Route {
                component_store_id: "00000000-0000-4000-8000-000000000001".into(),
                route_id: "pool-route".into(),
                worker_uid: uid,
            },
            bridge_route: Route {
                component_store_id: "00000000-0000-4000-8000-000000000002".into(),
                route_id: "bridge-route".into(),
                worker_uid: uid,
            },
            producer: "pool".into(),
            recovery_capabilities: vec!["attempt_admission_v1".into()],
        }
    }
    #[test]
    fn early_hook_not_ready_is_distinct_from_uncertain_or_foreign_reply() {
        let mut error = WireError {
            version: 1,
            store_id: "store".into(),
            code: "attempt_not_ready".into(),
            recovery: "same_key_lookup".into(),
        };
        assert_eq!(classify_error(&error, "store"), RunError::NotReady);
        assert_eq!(classify_error(&error, "other-store"), RunError::Unknown);
        error.code = "outcome_unknown".into();
        assert_eq!(classify_error(&error, "store"), RunError::Unknown);
        error.code = "attempt_not_ready".into();
        error.recovery = "none".into();
        assert_eq!(classify_error(&error, "store"), RunError::Unknown);
        error.code = "role_unqualified".into();
        assert_eq!(classify_error(&error, "store"), RunError::Refused);
    }
    #[test]
    fn admission_lookup_never_treats_absence_as_abort_fence() {
        let digest = "a".repeat(64);
        assert!(
            validate_lookup(
                Lookup {
                    state: "absent".into(),
                    admission: None,
                    outcome_digest: None
                },
                "intent",
                &digest
            )
            .is_ok()
        );
        assert!(
            validate_lookup(
                Lookup {
                    state: "admitted".into(),
                    admission: None,
                    outcome_digest: None
                },
                "intent",
                &digest
            )
            .is_err()
        );
        assert!(
            validate_lookup(
                Lookup {
                    state: "settled_aborted".into(),
                    admission: None,
                    outcome_digest: Some(digest.clone())
                },
                "intent",
                &digest
            )
            .is_err()
        );
        assert!(
            validate_lookup(
                Lookup {
                    state: "aborted_before_admit".into(),
                    admission: None,
                    outcome_digest: None
                },
                "intent",
                &digest
            )
            .is_ok()
        );
        // A request-side digest on a pre-admission tombstone is only a replay
        // fence. Run must not report it as an authenticated Pool outcome.
        assert!(
            validate_lookup(
                Lookup {
                    state: "aborted_before_admit".into(),
                    admission: None,
                    outcome_digest: Some(digest.clone())
                },
                "intent",
                &digest
            )
            .is_err()
        );
    }
    #[test]
    fn combined_consensus_observations_keep_their_original_routes() {
        let route_a = Route {
            component_store_id: "store-a".into(),
            route_id: "route-a".into(),
            worker_uid: 1000,
        };
        let route_b = Route {
            component_store_id: "store-b".into(),
            route_id: "route-b".into(),
            worker_uid: 1000,
        };
        let attempt = AttemptRef {
            run_store_id: "store-a".into(),
            lineage_root_id: "root".into(),
            execution_id: "execution".into(),
            sequence: 1,
            attempt_id: "attempt".into(),
            launch_id: "launch".into(),
        };
        let incarnation = Incarnation {
            host_id: "host".into(),
            boot_id: "boot".into(),
            pid_namespace_inode: 1,
            uid: 1000,
            pid: 2,
            start_ticks: 1,
        };
        let group = |route: Route, state| ConsensusAuthority {
            entries: vec![(
                route,
                attempt.clone(),
                incarnation.clone(),
                Ok(VoterObservation {
                    state,
                    last_attempt: None,
                    last_incarnation: None,
                    successor_proof: None,
                }),
            )],
        };
        let combined = ConsensusAuthority::combine(vec![
            group(route_a.clone(), VoterState::Live),
            group(route_b.clone(), VoterState::Superseded),
        ])
        .unwrap();
        assert_eq!(
            combined
                .consensus(&route_a, &attempt, &incarnation)
                .unwrap()
                .state,
            VoterState::Live
        );
        assert_eq!(
            combined
                .consensus(&route_b, &attempt, &incarnation)
                .unwrap()
                .state,
            VoterState::Superseded
        );
        let unknown = Route {
            route_id: "unknown".into(),
            ..route_a.clone()
        };
        assert!(
            combined
                .consensus(&unknown, &attempt, &incarnation)
                .is_err()
        );
        assert!(matches!(
            ConsensusAuthority::combine(vec![
                group(route_a.clone(), VoterState::Live),
                group(route_a, VoterState::Live),
            ]),
            Err(RunError::Invalid)
        ));
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn pinned_run_wire_rejects_mismatch_before_authority() {
        let _hash_guard = crate::TEST_EXEC_HASH_LOCK.lock().await;
        let root = std::env::var_os("TMPDIR").unwrap();
        let dir = tempfile::tempdir_in(root).unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket = dir.path().join("attempt.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        let executable = std::env::current_exe().unwrap();
        let sha256 = format!("{:x}", Sha256::digest(fs::read(&executable).unwrap()));
        let uid = fs::metadata(dir.path()).unwrap().uid();
        let peer = local_peer(socket, uid, executable, sha256);
        let server = tokio::spawn(async move {
            for index in 0..5 {
                let (mut stream, _) = listener.accept().await.unwrap();
                if index == 4 {
                    let mut byte = [0u8; 1];
                    assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
                    continue;
                }
                let frame = read_frame(&mut stream).await.unwrap();
                let request: Value = serde_json::from_slice(&frame).unwrap();
                assert_eq!(request["method"], "_attempt_capabilities_v1");
                let reply_id = if index == 0 {
                    "one"
                } else if index == 1 {
                    "wrong"
                } else {
                    request["id"].as_str().unwrap()
                };
                let response = serde_json::json!({"id":reply_id,"result":{"version":1,"store_id":format!("store_{}","a".repeat(32)),"capabilities":["attempt_current_ingress_v1","attempt_admission_v1","attempt_namespace_retirement_v1"],"policy":"admission_snapshot"}});
                stream
                    .write_all(format!("{response}\n").as_bytes())
                    .await
                    .unwrap();
            }
        });
        let capabilities = peer.capabilities("one").await.unwrap();
        assert_eq!(capabilities.capabilities.len(), 3);
        assert!(matches!(
            peer.capabilities("two").await,
            Err(RunError::Unknown)
        ));
        let attempt = AttemptRef {
            run_store_id: peer.route.component_store_id.clone(),
            lineage_root_id: "root".into(),
            execution_id: "root".into(),
            sequence: 1,
            attempt_id: "attempt".into(),
            launch_id: "00000000-0000-4000-8000-000000000003".into(),
        };
        let incarnation = Incarnation {
            host_id: "host".into(),
            boot_id: "00000000-0000-4000-8000-000000000004".into(),
            pid_namespace_inode: 1,
            uid,
            pid: 123,
            start_ticks: 1,
        };
        assert_eq!(
            peer.consensus("consensus", "request", &attempt, &incarnation)
                .await
                .err(),
            Some(RunError::Refused)
        );
        let egress = EgressQuery {
            pin: RunPin {
                route: peer.route.clone(),
                socket: peer.socket.clone(),
                executable: peer.executable.clone(),
                executable_sha256: peer.sha256.clone(),
                capabilities: vec!["attempt_current_egress_v1".into()],
            },
            transport_id: "egress".into(),
            request_id: "egress-request".into(),
            bound: attempt,
        };
        assert_eq!(
            peer.current_egress(&egress).await.err(),
            Some(RunError::Refused)
        );
        let mut wrong = peer.clone();
        wrong.sha256 = "0".repeat(64);
        assert!(matches!(
            wrong.capabilities("three").await,
            Err(RunError::Unknown)
        ));
        server.await.unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn rootless_ingress_egress_and_admission_recovery_use_pinned_wire() {
        use crate::managed_state::SuccessorLink;
        let _hash_guard = crate::TEST_EXEC_HASH_LOCK.lock().await;
        let root = std::env::var_os("TMPDIR").unwrap();
        let dir = tempfile::tempdir_in(root).unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket = dir.path().join("attempt.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        let executable = std::env::current_exe().unwrap();
        let sha256 = format!("{:x}", Sha256::digest(fs::read(&executable).unwrap()));
        let uid = fs::metadata(dir.path()).unwrap().uid();
        let peer = local_peer(socket, uid, executable, sha256);
        let attempt = AttemptRef {
            run_store_id: peer.route.component_store_id.clone(),
            lineage_root_id: "root".into(),
            execution_id: "root".into(),
            sequence: 1,
            attempt_id: "attempt".into(),
            launch_id: "00000000-0000-4000-8000-000000000003".into(),
        };
        let receipt = CurrentReceipt {
            receipt_id: "receipt".into(),
            purpose: "egress".into(),
            lineage_root_id: "root".into(),
            bound_execution_id: "root".into(),
            attempt: attempt.clone(),
            incarnation: Incarnation {
                host_id: "host".into(),
                boot_id: "00000000-0000-4000-8000-000000000004".into(),
                pid_namespace_inode: 1,
                uid,
                pid: 123,
                start_ticks: 1,
            },
            actor: ManagedActor {
                address: "host/codex/store/session".into(),
                role: "root".into(),
                native_id: "session".into(),
                epoch: 1,
            },
            successor_proof: SuccessorProof {
                lineage_root_id: "root".into(),
                bound_execution_id: "root".into(),
                current_execution_id: "root".into(),
                chain: vec![SuccessorLink {
                    execution_id: "root".into(),
                    parent_execution_id: None,
                    sequence: 1,
                }],
            },
        };
        let expected = receipt.clone();
        let mut ingress_receipt = receipt.clone();
        ingress_receipt.receipt_id = "ingress-receipt".into();
        ingress_receipt.purpose = "ingress".into();
        let expected_ingress = ingress_receipt.clone();
        let binding = ManagedBinding {
            pool_store_id: peer.pool_route.component_store_id.clone(),
            pool_id: "pool".into(),
            member_id: "member".into(),
            binding_generation: 1,
            attempt: attempt.clone(),
            actor: receipt.actor.clone(),
            run_route: peer.route.clone(),
            bridge_route: peer.bridge_route.clone(),
        };
        let consumed = ConsumedRef {
            bridge_route: peer.bridge_route.clone(),
            producer: "pool".into(),
            consume_request_id: "intent".into(),
            invocation_key: "invocation".into(),
            security_digest: "a".repeat(64),
            issuer_epoch: "epoch:opaque".into(),
        };
        let admission = Admission {
            admission_id: "admission".into(),
            intent_id: "intent".into(),
            security_digest: consumed.security_digest.clone(),
            policy: "admission_snapshot".into(),
            binding: binding.clone(),
            incarnation: receipt.incarnation.clone(),
            successor_proof: receipt.successor_proof.clone(),
            consumed_ref: consumed.clone(),
        };
        let expected_admission = admission.clone();
        let pool_route = peer.pool_route.clone();
        let store_id = peer.route.component_store_id.clone();
        let server = tokio::spawn(async move {
            for index in 0..13 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request: Value =
                    serde_json::from_slice(&read_frame(&mut stream).await.unwrap()).unwrap();
                let result = match index {
                    0 | 2 | 4 | 9 | 11 => {
                        assert_eq!(request["method"], "_attempt_capabilities_v1");
                        serde_json::json!({"version":1,"store_id":store_id,"capabilities":["attempt_current_ingress_v1","attempt_current_egress_v1","attempt_admission_v1"],"policy":"admission_snapshot"})
                    }
                    1 => {
                        assert_eq!(request["method"], "_attempt_current_v1");
                        assert_eq!(
                            request["params"],
                            serde_json::json!({"version":1,"expected_store_id":store_id,"request_id":"egress-request","lineage_root_id":"root","bound_execution_id":"root","purpose":"egress"})
                        );
                        serde_json::json!({"version":1,"store_id":store_id,"state":"current","receipt":receipt})
                    }
                    3 => {
                        assert_eq!(request["method"], "_attempt_current_receipt_v1");
                        assert_eq!(request["params"]["receipt_id"], "receipt");
                        serde_json::json!({"version":1,"store_id":store_id,"receipt":receipt})
                    }
                    5 => {
                        assert_eq!(request["method"], "_attempt_admit_v1");
                        assert_eq!(
                            request["params"],
                            serde_json::json!({"version":1,"expected_store_id":store_id,"request_id":"intent","intent_id":"intent","security_digest":admission.security_digest,"binding":admission.binding,"consumed_ref":admission.consumed_ref,"policy":"admission_snapshot"})
                        );
                        serde_json::json!({"version":1,"store_id":store_id,"state":"admitted","admission":admission})
                    }
                    6 => {
                        assert_eq!(request["method"], "_attempt_admission_lookup_v1");
                        assert_eq!(request["params"]["intent_id"], "intent");
                        serde_json::json!({"version":1,"store_id":store_id,"state":"admitted","admission":admission,"outcome_digest":null})
                    }
                    7 => {
                        assert_eq!(request["method"], "_attempt_settle_v1");
                        assert_eq!(request["params"]["pool_outcome_digest"], "b".repeat(64));
                        serde_json::json!({"version":1,"store_id":store_id,"state":"settled_committed","admission":admission,"outcome_digest":"b".repeat(64)})
                    }
                    8 => {
                        assert_eq!(request["method"], "_attempt_admission_abort_v1");
                        assert_eq!(
                            request["params"]["pool_route"],
                            serde_json::to_value(&pool_route).unwrap()
                        );
                        assert_eq!(request["params"]["pool_outcome_digest"], "d".repeat(64));
                        serde_json::json!({"version":1,"store_id":store_id,"state":"aborted_before_admit","admission":null,"outcome_digest":null})
                    }
                    10 => {
                        assert_eq!(request["method"], "_attempt_current_v1");
                        assert_eq!(
                            request["params"],
                            serde_json::json!({"version":1,"expected_store_id":store_id,"request_id":"ingress-request","purpose":"ingress","observation_ref":"original-ref","invocation_key":"original-invocation"})
                        );
                        serde_json::json!({"version":1,"store_id":store_id,"state":"current","receipt":ingress_receipt})
                    }
                    _ => {
                        assert_eq!(request["method"], "_attempt_current_receipt_v1");
                        assert_eq!(request["params"]["receipt_id"], "ingress-receipt");
                        serde_json::json!({"version":1,"store_id":store_id,"receipt":ingress_receipt})
                    }
                };
                let response = serde_json::json!({"id":request["id"],"result":result});
                stream
                    .write_all(format!("{response}\n").as_bytes())
                    .await
                    .unwrap();
            }
        });
        let query = EgressQuery {
            pin: RunPin {
                route: peer.route.clone(),
                socket: peer.socket.clone(),
                executable: peer.executable.clone(),
                executable_sha256: peer.sha256.clone(),
                capabilities: vec!["attempt_current_egress_v1".into()],
            },
            transport_id: "egress-rpc".into(),
            request_id: "egress-request".into(),
            bound: attempt,
        };
        let authority = peer.current_egress(&query).await.unwrap();
        assert_eq!(authority.receipt(), &expected);
        assert_eq!(authority.request_id(), Some("egress-request"));
        assert!(authority.invocation().is_none());
        let admitted = peer
            .admit(
                "admit-rpc",
                "intent",
                &consumed.security_digest,
                &binding,
                &consumed,
            )
            .await
            .unwrap();
        assert_eq!(admitted.admission_id, expected_admission.admission_id);
        assert_eq!(admitted.consumed_ref, expected_admission.consumed_ref);
        let lookup = peer
            .lookup("lookup-rpc", "intent", &consumed.security_digest)
            .await
            .unwrap();
        assert_eq!(lookup.state, "admitted");
        let settled = peer
            .settle(
                "settle-rpc",
                "admission",
                "intent",
                &consumed.security_digest,
                &"b".repeat(64),
            )
            .await
            .unwrap();
        assert_eq!(settled.state, "settled_committed");
        let aborted = peer
            .abort(
                "abort-rpc",
                "other-intent",
                &"c".repeat(64),
                &peer.pool_route,
                Some(&"d".repeat(64)),
            )
            .await
            .unwrap();
        assert_eq!(aborted.state, "aborted_before_admit");
        let ingress = IngressQuery {
            pin: RunPin {
                route: peer.route.clone(),
                socket: peer.socket.clone(),
                executable: peer.executable.clone(),
                executable_sha256: peer.sha256.clone(),
                capabilities: vec!["attempt_current_ingress_v1".into()],
            },
            input: IngressInput {
                bridge_route: peer.bridge_route.clone(),
                producer: "pool".into(),
                observation_ref: bridge_sdk::bridge_protocol::Secret::new("original-ref"),
                invocation_key: "original-invocation".into(),
                request_id: "ingress-request".into(),
                transport_id: "ingress-rpc".into(),
            },
        };
        let original = peer.current_ingress(&ingress).await.unwrap();
        assert_eq!(original.receipt(), &expected_ingress);
        assert_eq!(original.invocation(), Some("original-invocation"));
        server.await.unwrap();
    }
}
