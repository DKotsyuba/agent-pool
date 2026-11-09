//! Private Run hold client; it neither persists intent nor authorizes Pool actions.
//!
//! A future caller must durably retain the exact request, trusted ordered roots,
//! signing key, and any known receipt before relying on recovery. Cancellation,
//! transport errors, refusals, and absent lookup snapshots do not prove that an
//! earlier acquire had no effect. No operation here retries a mutation.
//! The caller must also durably freeze and recheck the original Run route and
//! pass its matching configuration to every call. A protected socket and a
//! single store check alone are not a durable route fence.

use crate::{
    config::Config,
    integrations::{JsonObject, json_object, json_objects, run_rpc_typed},
    run_status::{Target, valid_agent_id},
};
use serde::{Deserialize, Deserializer};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

const ACQUIRE_DOMAIN: &[u8] = b"agent-run:lineage-hold:acquire:v1\0";
const MAX_TARGETS: usize = 20;

/// Safe failure class; unknown includes all transport and producer failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HoldError {
    /// The immutable input was rejected locally before a request was sent.
    InvalidInput,
    /// The outcome cannot be established from the received evidence.
    Unknown,
}

/// Immutable acquire input and the separately frozen expected lineage roots.
/// The roots must come from independently validated Run status evidence in the
/// same order; this struct does not establish worker or ballot authorship.
#[derive(Clone)]
pub(crate) struct HoldIntent {
    store_id: String,
    request_id: String,
    targets: Vec<Target>,
    expected_roots: Vec<String>,
    verifying_key: [u8; 32],
    intent_digest: Option<[u8; 32]>,
    fingerprint: String,
}

impl HoldIntent {
    /// Validates exact input and computes Run's v1 fingerprint before any I/O.
    /// The supplied public key is structurally sized; Run validates its curve.
    pub(crate) fn new(
        store_id: String,
        request_id: String,
        targets: Vec<Target>,
        expected_roots: Vec<String>,
        verifying_key: [u8; 32],
        intent_digest: Option<[u8; 32]>,
    ) -> Result<Self, HoldError> {
        if crate::domain::store_id(&store_id).is_err()
            || request_id.trim().is_empty()
            || request_id.contains('\0')
            || request_id.len() > 2048
            || request_id.chars().count() > 512
            || !(1..=MAX_TARGETS).contains(&targets.len())
            || expected_roots.len() != targets.len()
        {
            return Err(HoldError::InvalidInput);
        }
        let mut roots = HashSet::new();
        let mut pins = HashSet::new();
        let mut executions = HashSet::new();
        for (target, root) in targets.iter().zip(&expected_roots) {
            if !valid_agent_id(&target.agent_id)
                || target.sequence == 0
                || crate::domain::execution_ref(&target.execution_ref).is_err()
                || crate::domain::pin_id(&target.pin_id).is_err()
                || !valid_agent_id(root)
                || !roots.insert(root)
                || !pins.insert(&target.pin_id)
                || !executions.insert(&target.execution_ref)
            {
                return Err(HoldError::InvalidInput);
            }
        }
        let mut intent = Self {
            store_id,
            request_id,
            targets,
            expected_roots,
            verifying_key,
            intent_digest,
            fingerprint: String::new(),
        };
        intent.fingerprint = lower_hex(&Sha256::digest(intent.canonical_bytes()?));
        Ok(intent)
    }

    /// Returns the locally computed fingerprint needed for durable recovery.
    pub(crate) fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Constructs the producer's length-prefixed v1 hash preimage without normalization.
    fn canonical_bytes(&self) -> Result<Vec<u8>, HoldError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(ACQUIRE_DOMAIN);
        bytes.extend_from_slice(&decode_id::<16>(&self.store_id, "store_")?);
        let request_len =
            u16::try_from(self.request_id.len()).map_err(|_| HoldError::InvalidInput)?;
        bytes.extend_from_slice(&request_len.to_be_bytes());
        bytes.extend_from_slice(self.request_id.as_bytes());
        bytes.push(u8::try_from(self.targets.len()).map_err(|_| HoldError::InvalidInput)?);
        for target in &self.targets {
            bytes.extend_from_slice(target.agent_id.as_bytes());
            bytes.extend_from_slice(&target.sequence.to_be_bytes());
            bytes.extend_from_slice(&decode_id::<32>(&target.execution_ref, "ex1_")?);
            bytes.extend_from_slice(&decode_id::<16>(&target.pin_id, "pin_")?);
        }
        bytes.extend_from_slice(&self.verifying_key);
        match self.intent_digest {
            None => bytes.push(0),
            Some(digest) => {
                bytes.push(1);
                bytes.extend_from_slice(&digest);
            }
        }
        Ok(bytes)
    }
}

/// Decodes a fixed-length lowercase hexadecimal identifier without echoing input.
fn decode_id<const N: usize>(value: &str, prefix: &str) -> Result<[u8; N], HoldError> {
    let hex = value.strip_prefix(prefix).ok_or(HoldError::InvalidInput)?;
    if hex.len() != N * 2 {
        return Err(HoldError::InvalidInput);
    }
    let mut bytes = [0; N];
    for (out, pair) in bytes.iter_mut().zip(hex.as_bytes().as_chunks::<2>().0) {
        let nibble = |byte| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        *out = (nibble(pair[0]).ok_or(HoldError::InvalidInput)? << 4)
            | nibble(pair[1]).ok_or(HoldError::InvalidInput)?;
    }
    Ok(bytes)
}

/// Encodes exact bytes in the producer's lowercase hexadecimal wire format.
fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(char::from(DIGITS[usize::from(byte >> 4)]));
        result.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    result
}

/// Wire receipt; it is trusted only after correlation with the frozen intent.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HoldReceipt {
    version: u32,
    store_id: String,
    hold_id: String,
    fingerprint: String,
    #[serde(deserialize_with = "json_objects")]
    targets: Vec<Target>,
    canonical_roots: Vec<String>,
}

impl HoldReceipt {
    /// Returns the public hold identifier used to construct an external release proof.
    pub(crate) fn hold_id(&self) -> &str {
        &self.hold_id
    }

    /// Checks every receipt field against the frozen request and expected roots.
    fn matches(&self, intent: &HoldIntent) -> bool {
        let Some(raw) = self.hold_id.strip_prefix("hold_") else {
            return false;
        };
        let Ok(uuid) = uuid::Uuid::parse_str(raw) else {
            return false;
        };
        self.version == 1
            && self.store_id == intent.store_id
            && raw.len() == 32
            && uuid.simple().to_string() == raw
            && uuid.get_version_num() == 4
            && uuid.get_variant() == uuid::Variant::RFC4122
            && self.fingerprint == intent.fingerprint
            && self.targets == intent.targets
            && self.canonical_roots == intent.expected_roots
    }
}

/// The only hold lifecycle states in the v1 contract.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HoldState {
    Active,
    Released,
}

/// Validated receipt and its state in one Run snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HoldObservation {
    receipt: HoldReceipt,
    state: HoldState,
}

impl HoldObservation {
    /// Reconstructs a previously validated observation from its frozen intent.
    /// The caller must durably retain `hold_id` and `state` from an earlier
    /// correlated receipt; this constructor checks shape, not their provenance.
    pub(crate) fn from_persisted(
        intent: &HoldIntent,
        hold_id: &str,
        state: HoldState,
    ) -> Result<Self, HoldError> {
        let receipt = HoldReceipt {
            version: 1,
            store_id: intent.store_id.clone(),
            hold_id: hold_id.to_owned(),
            fingerprint: intent.fingerprint.clone(),
            targets: intent.targets.clone(),
            canonical_roots: intent.expected_roots.clone(),
        };
        if !receipt.matches(intent) {
            return Err(HoldError::InvalidInput);
        }
        Ok(Self { receipt, state })
    }

    /// Returns the already-correlated immutable receipt.
    pub(crate) fn receipt(&self) -> &HoldReceipt {
        &self.receipt
    }

    /// Returns the observed state; it is not worker authorization.
    pub(crate) fn state(&self) -> HoldState {
        self.state
    }

    /// Builds the 98-byte v1 message for a separate signer without handling a key.
    /// Rejects a receipt that does not match the caller's frozen intent.
    pub(crate) fn release_message(&self, intent: &HoldIntent) -> Result<[u8; 98], HoldError> {
        if !self.receipt.matches(intent) {
            return Err(HoldError::InvalidInput);
        }
        let mut message = [0_u8; 98];
        message[..34].copy_from_slice(b"agent-run:lineage-hold:release:v1\0");
        message[34..50].copy_from_slice(&decode_id::<16>(&intent.store_id, "store_")?);
        message[50..66].copy_from_slice(&decode_id::<16>(&self.receipt.hold_id, "hold_")?);
        message[66..].copy_from_slice(&decode_id::<32>(&intent.fingerprint, "")?);
        Ok(message)
    }
}

/// Correlated acquire or exact replay of an earlier acquire.
#[derive(Debug)]
pub(crate) struct AcquireResult {
    pub(crate) observation: HoldObservation,
    pub(crate) replayed: bool,
}

/// Lookup is one snapshot: absence never rules out a later in-flight commit.
#[derive(Debug)]
pub(crate) enum LookupResult {
    AbsentSnapshot,
    Found(HoldObservation),
}

/// A verified release response and whether the hold was already released.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReleaseResult {
    pub(crate) already_released: bool,
}

/// Producer capability projection; unrelated ordinary discovery fields are ignored.
#[derive(Deserialize)]
struct Capabilities {
    schema_version: u32,
    product: String,
    store_id: String,
    #[serde(deserialize_with = "json_object")]
    lineage_holds: HoldMethods,
}

/// Exact operator-only v1 method names; no MCP exposure is assumed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HoldMethods {
    version: u32,
    transport: String,
    acquire: String,
    lookup: String,
    list: String,
    release: String,
}

/// Confirms exact v1 operator methods and the expected store on the protected socket.
pub(crate) async fn discover(config: &Config, store_id: &str) -> Result<(), HoldError> {
    crate::domain::store_id(store_id).map_err(|_| HoldError::InvalidInput)?;
    let result: Capabilities = run_rpc_typed(
        config,
        "capabilities",
        json!({"include_store_id":true,"include_lineage_holds":true}),
    )
    .await
    .map_err(|_| HoldError::Unknown)?;
    let methods = result.lineage_holds;
    if result.schema_version != 1
        || result.product != "agent-run"
        || result.store_id != store_id
        || methods.version != 1
        || methods.transport != "operator_socket"
        || methods.acquire != "_lineage_hold_acquire"
        || methods.lookup != "_lineage_hold_lookup"
        || methods.list != "_lineage_hold_list"
        || methods.release != "_lineage_hold_release"
    {
        return Err(HoldError::Unknown);
    }
    Ok(())
}

/// Wire acquire fields are mandatory and no future or duplicate fields are accepted.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcquireResponse {
    #[serde(deserialize_with = "json_object")]
    receipt: HoldReceipt,
    state: HoldState,
    replayed: bool,
}

/// Makes an optional response field reject an explicit null when present.
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// Makes an optional response field accept an object only, never null or an array.
fn present_object<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    JsonObject::<T>::deserialize(deserializer).map(|object| Some(object.0))
}

/// Decodes both lookup branches without erasing missing-versus-null distinctions.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LookupResponse {
    store_id: String,
    found: bool,
    #[serde(default, deserialize_with = "present_object")]
    receipt: Option<HoldReceipt>,
    #[serde(default, deserialize_with = "present")]
    state: Option<HoldState>,
}

/// Decodes both release branches without accepting missing or extra branch fields.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseResponse {
    store_id: String,
    found: bool,
    #[serde(default, deserialize_with = "present")]
    hold_id: Option<String>,
    #[serde(default, deserialize_with = "present")]
    state: Option<HoldState>,
    #[serde(default, deserialize_with = "present")]
    already_released: Option<bool>,
}

/// Rejects changed receipts or a resurrection after an already released observation.
fn matches_prior(observation: &HoldObservation, prior: Option<&HoldObservation>) -> bool {
    prior.is_none_or(|prior| {
        observation.receipt == prior.receipt
            && !(prior.state == HoldState::Released && observation.state == HoldState::Active)
    })
}

/// Sends one acquire and accepts only a fully correlated receipt.
/// A caller must retain this exact intent before polling: cancellation or any
/// returned unknown may follow a committed hold. No mutation is retried here.
pub(crate) async fn acquire(
    config: &Config,
    intent: &HoldIntent,
    prior: Option<&HoldObservation>,
) -> Result<AcquireResult, HoldError> {
    if prior.is_some_and(|prior| !prior.receipt.matches(intent)) {
        return Err(HoldError::InvalidInput);
    }
    let params = json!({
        "version":1,
        "expected_store_id":intent.store_id,
        "request_id":intent.request_id,
        "targets":intent.targets,
        "verifying_key":lower_hex(&intent.verifying_key),
        "intent_digest":intent.intent_digest.map(|digest| lower_hex(&digest))
    });
    let response: AcquireResponse = run_rpc_typed(config, "_lineage_hold_acquire", params)
        .await
        .map_err(|_| HoldError::Unknown)?;
    let observation = HoldObservation {
        receipt: response.receipt,
        state: response.state,
    };
    if !observation.receipt.matches(intent)
        || !matches_prior(&observation, prior)
        || (!response.replayed && observation.state != HoldState::Active)
        || (prior.is_some() && !response.replayed)
    {
        return Err(HoldError::Unknown);
    }
    Ok(AcquireResult {
        observation,
        replayed: response.replayed,
    })
}

/// Looks up the exact immutable intent; absent is a snapshot, not no-effect proof.
/// When a receipt is already known, its identity and released state are fenced.
pub(crate) async fn lookup(
    config: &Config,
    intent: &HoldIntent,
    prior: Option<&HoldObservation>,
) -> Result<LookupResult, HoldError> {
    if prior.is_some_and(|prior| !prior.receipt.matches(intent)) {
        return Err(HoldError::InvalidInput);
    }
    let response: LookupResponse = run_rpc_typed(
        config,
        "_lineage_hold_lookup",
        json!({"version":1,"expected_store_id":intent.store_id,
            "request_id":intent.request_id,"fingerprint":intent.fingerprint}),
    )
    .await
    .map_err(|_| HoldError::Unknown)?;
    if response.store_id != intent.store_id {
        return Err(HoldError::Unknown);
    }
    match (response.found, response.receipt, response.state) {
        (false, None, None) if prior.is_none() => Ok(LookupResult::AbsentSnapshot),
        (true, Some(receipt), Some(state)) => {
            let observation = HoldObservation { receipt, state };
            if !observation.receipt.matches(intent) || !matches_prior(&observation, prior) {
                return Err(HoldError::Unknown);
            }
            Ok(LookupResult::Found(observation))
        }
        _ => Err(HoldError::Unknown),
    }
}

/// Sends one caller-supplied signature and confirms only a matching released receipt.
/// No signing, private-key handling, automatic retry, or proof diagnostics occur here.
/// Transport errors, refusals, absence, and cancellation leave release unknown.
pub(crate) async fn release(
    config: &Config,
    intent: &HoldIntent,
    prior: &HoldObservation,
    signature: &[u8; 64],
) -> Result<ReleaseResult, HoldError> {
    if !prior.receipt.matches(intent) {
        return Err(HoldError::InvalidInput);
    }
    let response: ReleaseResponse = run_rpc_typed(
        config,
        "_lineage_hold_release",
        json!({"version":1,"expected_store_id":intent.store_id,
            "hold_id":prior.receipt.hold_id,"signature":lower_hex(signature)}),
    )
    .await
    .map_err(|_| HoldError::Unknown)?;
    if response.store_id != intent.store_id {
        return Err(HoldError::Unknown);
    }
    match (
        response.found,
        response.hold_id,
        response.state,
        response.already_released,
    ) {
        (true, Some(hold_id), Some(HoldState::Released), Some(already_released))
            if hold_id == prior.receipt.hold_id
                && (prior.state != HoldState::Released || already_released) =>
        {
            Ok(ReleaseResult { already_released })
        }
        _ => Err(HoldError::Unknown),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integrations::read_frame;
    use serde_json::{Value, json};
    use std::{
        error::Error,
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::Path,
        time::Duration,
    };
    use tokio::{io::AsyncWriteExt, net::UnixListener};

    const STORE: &str = "store_00112233445566778899aabbccddeeff";
    const HOLD: &str = "hold_0123456789ab4cde8f0123456789abcd";
    const AGENT: &str = "ag-20261107-010203-0123456789";
    const PIN: &str = "pin_112233445566478899aabbccddeeff00";
    const PUBLIC_KEY: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const FINGERPRINT: &str = "5407d58ddf96ca0e0b2fe7c7f3a74b363a7b502c121e4b594d7c0aa190d12f66";

    /// Uses the producer's public interoperability vector without a signing key.
    fn intent() -> Result<HoldIntent, HoldError> {
        HoldIntent::new(
            STORE.into(),
            "hold-fixture-1".into(),
            vec![Target {
                agent_id: AGENT.into(),
                sequence: 2,
                execution_ref: format!("ex1_{}", "2".repeat(64)),
                pin_id: PIN.into(),
            }],
            vec![AGENT.into()],
            decode_id(PUBLIC_KEY, "")?,
            None,
        )
    }

    /// Creates a structurally correct public receipt for a frozen test intent.
    fn receipt(intent: &HoldIntent) -> Value {
        json!({"version":1,"store_id":intent.store_id,"hold_id":HOLD,
            "fingerprint":intent.fingerprint,"targets":intent.targets,
            "canonical_roots":intent.expected_roots})
    }

    /// Builds a configuration pointing only to one protected fake local socket.
    fn fixture_config(path: &Path, uid: u32) -> Config {
        Config {
            socket_path: path.join("pool.sock"),
            database_path: path.join("pool.db"),
            expected_uid: uid,
            bridge_registration_socket: path.join("bridge.sock"),
            bridge_core_socket: path.join("core.sock"),
            bridge_credential_file: path.join("token"),
            bridge_producer_id: "test".into(),
            bridge_audience: "test".into(),
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

    /// One fake socket exchange; close simulates loss after receiving a mutation.
    enum Reply {
        Result(String),
        ResultWithNullError(String),
        ErrorWithNullResult,
        Lost,
    }

    /// An expected method, optional exact public parameters, and its scripted reply.
    struct Step {
        method: &'static str,
        params: Option<Value>,
        reply: Reply,
    }

    /// Serves each scripted request once and never prints request or signature material.
    async fn serve(listener: UnixListener, steps: Vec<Step>) -> Result<(), Box<dyn Error>> {
        for step in steps {
            let (mut stream, _) = listener.accept().await?;
            let request: Value = serde_json::from_slice(&read_frame(&mut stream).await?)?;
            assert_eq!(request["method"].as_str(), Some(step.method));
            if let Some(params) = step.params {
                assert!(request["params"] == params);
            }
            let id = request["id"].as_u64().ok_or("missing request id")?;
            let response = match step.reply {
                Reply::Result(body) => {
                    format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{body}}}\n")
                }
                Reply::ResultWithNullError(body) => format!(
                    "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{body},\"error\":null}}\n"
                ),
                Reply::ErrorWithNullResult => format!(
                    "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":null,\"error\":{{\"code\":-32602,\"message\":\"declined\"}}}}\n"
                ),
                Reply::Lost => continue,
            };
            stream.write_all(response.as_bytes()).await?;
        }
        Ok(())
    }

    /// Binds a task-owned socket with the permissions required by the real transport.
    fn listener() -> Result<(tempfile::TempDir, Config, UnixListener), Box<dyn Error>> {
        let base = std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?;
        let directory = tempfile::tempdir_in(base)
            .map_err(|error| std::io::Error::new(error.kind(), "create fixture directory"))?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .map_err(|error| std::io::Error::new(error.kind(), "protect fixture directory"))?;
        let config = fixture_config(directory.path(), std::fs::metadata(directory.path())?.uid());
        let socket = config.run_socket.as_ref().ok_or("missing fake socket")?;
        let listener = UnixListener::bind(socket)
            .map_err(|error| std::io::Error::new(error.kind(), "bind fixture socket"))?;
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| std::io::Error::new(error.kind(), "protect fixture socket"))?;
        Ok((directory, config, listener))
    }

    /// Starts and reaps one isolated fixture consumer without exposing proof data.
    async fn fixture_consumer(
        intent: &HoldIntent,
        phase: &str,
        output: &Path,
    ) -> Result<(), Box<dyn Error>> {
        use std::process::Stdio;

        let mut child = tokio::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "run_hold::tests::hold_fixture_consumer_in_child",
                "--ignored",
            ])
            .env("POOL_HOLD_TEST_CHILD", "1")
            .env("POOL_HOLD_TEST_PHASE", phase)
            .env("POOL_HOLD_TEST_RESULT_PATH", output)
            .env(
                "POOL_HOLD_TEST_PUBLIC_KEY",
                lower_hex(&intent.verifying_key),
            )
            .env("POOL_HOLD_TEST_FINGERPRINT", intent.fingerprint())
            .env_remove("POOL_HOLD_TEST_KEY")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let status = match tokio::time::timeout(Duration::from_secs(30), child.wait()).await {
            Ok(status) => status?,
            Err(_) => {
                let stopping = child.start_kill();
                let reaped = child.wait().await;
                if stopping.is_err() && reaped.is_err() {
                    return Err("fixture consumer could not be reaped".into());
                }
                return Err("fixture consumer timed out".into());
            }
        };
        if !status.success() {
            return Err("fixture consumer failed".into());
        }
        Ok(())
    }

    /// The producer's independent known answer catches any byte framing divergence.
    #[test]
    fn hold_fingerprint_and_input_fences() -> Result<(), Box<dyn Error>> {
        let original = intent().map_err(|_| "fixture invalid")?;
        assert_eq!(original.fingerprint(), FINGERPRINT);
        let known: JsonObject<HoldReceipt> = serde_json::from_str(&receipt(&original).to_string())?;
        let observation = HoldObservation {
            receipt: known.0,
            state: HoldState::Active,
        };
        let message = observation
            .release_message(&original)
            .map_err(|_| "release encoding")?;
        assert_eq!(&message[..34], b"agent-run:lineage-hold:release:v1\0");
        assert_eq!(
            lower_hex(&message[34..50]),
            "00112233445566778899aabbccddeeff"
        );
        assert_eq!(
            lower_hex(&message[50..66]),
            "0123456789ab4cde8f0123456789abcd"
        );
        assert_eq!(lower_hex(&message[66..]), FINGERPRINT);
        let mut changed = original.clone();
        changed.intent_digest = Some([0; 32]);
        assert_ne!(
            lower_hex(&Sha256::digest(
                changed.canonical_bytes().map_err(|_| "encoding")?
            )),
            FINGERPRINT
        );
        for request in ["", " \t", "a\0b"] {
            assert!(matches!(
                HoldIntent::new(
                    STORE.into(),
                    request.into(),
                    original.targets.clone(),
                    original.expected_roots.clone(),
                    original.verifying_key,
                    None
                ),
                Err(HoldError::InvalidInput)
            ));
        }
        assert!(matches!(
            HoldIntent::new(
                STORE.into(),
                "x".repeat(513),
                original.targets.clone(),
                original.expected_roots.clone(),
                original.verifying_key,
                None
            ),
            Err(HoldError::InvalidInput)
        ));
        assert!(
            HoldIntent::new(
                STORE.into(),
                "😀".repeat(512),
                original.targets.clone(),
                original.expected_roots.clone(),
                original.verifying_key,
                None,
            )
            .is_ok()
        );
        assert!(matches!(
            HoldIntent::new(
                STORE.into(),
                "é".repeat(513),
                original.targets.clone(),
                original.expected_roots.clone(),
                original.verifying_key,
                None,
            ),
            Err(HoldError::InvalidInput)
        ));
        assert!(matches!(
            HoldIntent::new(
                STORE.to_uppercase(),
                "id".into(),
                original.targets.clone(),
                original.expected_roots.clone(),
                original.verifying_key,
                None
            ),
            Err(HoldError::InvalidInput)
        ));
        let mut bad = original.targets.clone();
        bad[0].pin_id = "pin_112233445566378899aabbccddeeff00".into();
        assert!(matches!(
            HoldIntent::new(
                STORE.into(),
                "id".into(),
                bad,
                original.expected_roots.clone(),
                original.verifying_key,
                None
            ),
            Err(HoldError::InvalidInput)
        ));
        assert!(matches!(
            HoldIntent::new(
                STORE.into(),
                "id".into(),
                vec![],
                vec![],
                original.verifying_key,
                None
            ),
            Err(HoldError::InvalidInput)
        ));
        assert!(matches!(
            HoldIntent::new(
                STORE.into(),
                "id".into(),
                original.targets.clone(),
                vec!["invalid-root".into()],
                original.verifying_key,
                None
            ),
            Err(HoldError::InvalidInput)
        ));
        assert!(matches!(
            HoldIntent::new(
                STORE.into(),
                "id".into(),
                vec![original.targets[0].clone(), original.targets[0].clone()],
                vec![AGENT.into(), AGENT.into()],
                original.verifying_key,
                None
            ),
            Err(HoldError::InvalidInput)
        ));
        Ok(())
    }

    /// Rejects ambiguous response branches and mismatched or reordered receipt evidence.
    #[test]
    fn hold_strict_decoding_and_correlation() -> Result<(), Box<dyn Error>> {
        let mut original = intent().map_err(|_| "fixture invalid")?;
        let mut second = original.targets[0].clone();
        second.agent_id = "ag-20261107-010204-0123456789".into();
        second.execution_ref = format!("ex1_{}", "3".repeat(64));
        second.pin_id = "pin_212233445566478899aabbccddeeff00".into();
        original = HoldIntent::new(
            original.store_id,
            original.request_id,
            vec![original.targets[0].clone(), second],
            vec![AGENT.into(), "ag-20261107-010205-0123456789".into()],
            original.verifying_key,
            None,
        )
        .map_err(|_| "two-target intent invalid")?;
        let valid = receipt(&original);
        let parse = |value: &Value| -> Result<HoldReceipt, serde_json::Error> {
            serde_json::from_str::<JsonObject<HoldReceipt>>(&value.to_string()).map(|value| value.0)
        };
        assert!(parse(&valid)?.matches(&original));
        let mut mismatches = Vec::new();
        let mut bad = valid.clone();
        bad["version"] = json!(2);
        mismatches.push(bad);
        let mut bad = valid.clone();
        bad["store_id"] = json!("store_10112233445566778899aabbccddeeff");
        mismatches.push(bad);
        let mut bad = valid.clone();
        bad["hold_id"] = json!("hold_0123456789ab3cde8f0123456789abcd");
        mismatches.push(bad);
        let mut bad = valid.clone();
        bad["fingerprint"] = json!("0".repeat(64));
        mismatches.push(bad);
        let mut bad = valid.clone();
        bad["targets"].as_array_mut().ok_or("targets")?.reverse();
        mismatches.push(bad);
        let mut bad = valid.clone();
        bad["canonical_roots"]
            .as_array_mut()
            .ok_or("roots")?
            .reverse();
        mismatches.push(bad);
        for bad in mismatches {
            assert!(!parse(&bad)?.matches(&original));
        }
        let duplicate =
            valid
                .to_string()
                .replacen("\"version\":1", "\"version\":1,\"version\":1", 1);
        assert!(serde_json::from_str::<JsonObject<HoldReceipt>>(&duplicate).is_err());
        let mut extra = valid.clone();
        extra["future"] = json!(true);
        assert!(parse(&extra).is_err());
        let mut array_target = valid.clone();
        array_target["targets"][0] = json!([AGENT, 2, "x", "y"]);
        assert!(parse(&array_target).is_err());
        let found = json!({"store_id":STORE,"found":true,"receipt":valid,"state":"active"});
        assert!(serde_json::from_str::<JsonObject<LookupResponse>>(&found.to_string()).is_ok());
        for bad in [
            json!({"store_id":STORE,"found":false,"receipt":null}),
            json!({"store_id":STORE,"found":true,"state":null}),
            json!({"store_id":STORE,"found":false,"future":true}),
        ] {
            assert!(serde_json::from_str::<JsonObject<LookupResponse>>(&bad.to_string()).is_err());
        }
        assert!(
            serde_json::from_str::<JsonObject<AcquireResponse>>(
                &json!({"receipt":valid,"state":"future","replayed":true}).to_string()
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<JsonObject<ReleaseResponse>>(
                &json!({"store_id":STORE,"found":false,"state":null}).to_string()
            )
            .is_err()
        );
        let known = HoldObservation {
            receipt: parse(&valid)?,
            state: HoldState::Released,
        };
        let resurrected = HoldObservation {
            receipt: known.receipt.clone(),
            state: HoldState::Active,
        };
        assert!(!matches_prior(&resurrected, Some(&known)));
        Ok(())
    }

    /// Restores a known receipt without permitting changed identity or released-state resurrection.
    #[test]
    fn hold_persisted_observation_reconstructs_and_fences_prior() -> Result<(), Box<dyn Error>> {
        let intent = intent().map_err(|_| "fixture invalid")?;
        let JsonObject(receipt): JsonObject<HoldReceipt> =
            serde_json::from_str(&receipt(&intent).to_string())?;
        assert!(receipt.matches(&intent));
        for state in [HoldState::Active, HoldState::Released] {
            let original = HoldObservation {
                receipt: receipt.clone(),
                state,
            };
            let restored =
                HoldObservation::from_persisted(&intent, original.receipt().hold_id(), state)
                    .map_err(|_| "persisted receipt rejected")?;
            assert_eq!(restored, original);
        }
        for bad in [
            "hold_bad",
            "hold_0123456789ab3cde8f0123456789abcd",
            "hold_0123456789ab4cde7f0123456789abcd",
            "hold_0123456789ab4cde8f0123456789abcD",
            "hold_01234567-89ab-4cde-8f01-23456789abcd",
        ] {
            assert!(matches!(
                HoldObservation::from_persisted(&intent, bad, HoldState::Active),
                Err(HoldError::InvalidInput)
            ));
        }
        let restored = HoldObservation::from_persisted(&intent, HOLD, HoldState::Released)
            .map_err(|_| "released receipt rejected")?;
        let changed_id = HoldObservation::from_persisted(
            &intent,
            "hold_1123456789ab4cde8f0123456789abcd",
            HoldState::Released,
        )
        .map_err(|_| "valid alternate id rejected")?;
        let resurrected = HoldObservation::from_persisted(&intent, HOLD, HoldState::Active)
            .map_err(|_| "active receipt rejected")?;
        assert!(!matches_prior(&changed_id, Some(&restored)));
        assert!(!matches_prior(&resurrected, Some(&restored)));
        assert!(matches_prior(&restored, Some(&restored)));
        Ok(())
    }

    /// A lost acknowledgement and an empty snapshot remain unresolved until exact receipt recovery.
    #[tokio::test]
    async fn hold_lost_ack_snapshot_found_and_release_replay() -> Result<(), Box<dyn Error>> {
        let (_directory, config, listener) = listener()?;
        let intent = intent().map_err(|_| "fixture invalid")?;
        let observed = receipt(&intent);
        let mut changed_id = observed.clone();
        changed_id["hold_id"] = json!("hold_1123456789ab4cde8f0123456789abcd");
        let lookup_params = json!({"version":1,"expected_store_id":STORE,
            "request_id":"hold-fixture-1","fingerprint":FINGERPRINT});
        let steps = vec![
            Step { method:"_lineage_hold_acquire", params:None, reply:Reply::Lost },
            Step { method:"_lineage_hold_lookup", params:Some(lookup_params.clone()), reply:Reply::Result(json!({"store_id":STORE,"found":false}).to_string()) },
            Step { method:"_lineage_hold_lookup", params:Some(lookup_params.clone()), reply:Reply::Result(json!({"store_id":STORE,"found":true,"receipt":observed,"state":"active"}).to_string()) },
            Step { method:"_lineage_hold_release", params:None, reply:Reply::Lost },
            Step { method:"_lineage_hold_lookup", params:Some(lookup_params.clone()), reply:Reply::Result(json!({"store_id":STORE,"found":true,"receipt":observed,"state":"released"}).to_string()) },
            Step { method:"_lineage_hold_lookup", params:Some(lookup_params.clone()), reply:Reply::Result(json!({"store_id":STORE,"found":true,"receipt":observed,"state":"active"}).to_string()) },
            Step { method:"_lineage_hold_lookup", params:Some(lookup_params), reply:Reply::Result(json!({"store_id":STORE,"found":true,"receipt":changed_id,"state":"released"}).to_string()) },
            Step { method:"_lineage_hold_release", params:None, reply:Reply::Result(json!({"store_id":STORE,"found":true,"hold_id":HOLD,"state":"released","already_released":true}).to_string()) },
        ];
        let calls = async {
            assert!(matches!(
                acquire(&config, &intent, None).await,
                Err(HoldError::Unknown)
            ));
            assert!(matches!(
                lookup(&config, &intent, None).await,
                Ok(LookupResult::AbsentSnapshot)
            ));
            let found = match lookup(&config, &intent, None).await {
                Ok(LookupResult::Found(value)) => value,
                _ => return Err("exact recovery failed"),
            };
            assert_eq!(found.receipt().hold_id(), HOLD);
            assert_eq!(found.state(), HoldState::Active);
            assert!(matches!(
                release(&config, &intent, &found, &[5; 64]).await,
                Err(HoldError::Unknown)
            ));
            let active_prior =
                HoldObservation::from_persisted(&intent, found.receipt().hold_id(), found.state())
                    .map_err(|_| "active restoration failed")?;
            let released = match lookup(&config, &intent, Some(&active_prior)).await {
                Ok(LookupResult::Found(value)) => value,
                _ => return Err("released recovery failed"),
            };
            assert_eq!(released.state(), HoldState::Released);
            let released_prior = HoldObservation::from_persisted(
                &intent,
                released.receipt().hold_id(),
                released.state(),
            )
            .map_err(|_| "released restoration failed")?;
            assert!(matches!(
                lookup(&config, &intent, Some(&released_prior)).await,
                Err(HoldError::Unknown)
            ));
            assert!(matches!(
                lookup(&config, &intent, Some(&released_prior)).await,
                Err(HoldError::Unknown)
            ));
            assert!(matches!(
                release(&config, &intent, &released_prior, &[5; 64]).await,
                Ok(ReleaseResult {
                    already_released: true
                })
            ));
            Ok(())
        };
        let (calls, server) = tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(calls, serve(listener, steps))
        })
        .await?;
        calls?;
        server?;
        Ok(())
    }

    /// Exercises protected transport and rejects malformed, stale or contradictory replies.
    #[tokio::test]
    async fn hold_transport_rejects_ambiguous_and_mismatched_responses()
    -> Result<(), Box<dyn Error>> {
        let (_directory, config, listener) = listener()?;
        let intent = intent().map_err(|_| "fixture invalid")?;
        let valid = receipt(&intent);
        let methods = json!({"version":1,"transport":"operator_socket",
            "acquire":"_lineage_hold_acquire","lookup":"_lineage_hold_lookup",
            "list":"_lineage_hold_list","release":"_lineage_hold_release"});
        let capabilities = json!({"schema_version":1,"product":"agent-run",
            "store_id":STORE,"lineage_holds":methods,"extra_read_methods":[]});
        let mut unsupported = capabilities.clone();
        unsupported["lineage_holds"]["version"] = json!(2);
        let good_acquire = json!({"receipt":valid,"state":"active","replayed":false});
        let mut mismatched = Vec::new();
        for field in ["store_id", "hold_id", "fingerprint", "canonical_roots"] {
            let mut bad = json!({"receipt":valid,"state":"active","replayed":true});
            bad["receipt"][field] = match field {
                "store_id" => json!("store_10112233445566778899aabbccddeeff"),
                "hold_id" => json!("hold_1123456789ab4cde8f0123456789abcd"),
                "fingerprint" => json!("0".repeat(64)),
                _ => json!(["ag-20261107-010204-0123456789"]),
            };
            mismatched.push(bad.to_string());
        }
        let duplicate = json!({"receipt":valid,"state":"active","replayed":true})
            .to_string()
            .replacen("\"version\":1", "\"version\":1,\"version\":1", 1);
        mismatched.push(duplicate);
        let mut steps = vec![
            Step {
                method: "capabilities",
                params: None,
                reply: Reply::Result(capabilities.to_string()),
            },
            Step {
                method: "capabilities",
                params: None,
                reply: Reply::Result(unsupported.to_string()),
            },
            Step {
                method: "_lineage_hold_acquire",
                params: None,
                reply: Reply::Result(good_acquire.to_string()),
            },
        ];
        let mismatch_count = mismatched.len();
        steps.extend(mismatched.into_iter().map(|body| Step {
            method: "_lineage_hold_acquire",
            params: None,
            reply: Reply::Result(body),
        }));
        for bad in [
            json!({"store_id":STORE,"found":false,"receipt":null}),
            json!({"store_id":STORE,"found":false,"receipt":valid,"state":"active"}),
            json!({"store_id":STORE,"found":true,"receipt":valid}),
            json!({"store_id":STORE,"found":true,"receipt":valid,"state":"future"}),
        ] {
            steps.push(Step {
                method: "_lineage_hold_lookup",
                params: None,
                reply: Reply::Result(bad.to_string()),
            });
        }
        for bad in [
            json!({"store_id":STORE,"found":false}),
            json!({"store_id":STORE,"found":true,"hold_id":HOLD,"state":"active","already_released":false}),
            json!({"store_id":STORE,"found":true,"hold_id":"hold_1123456789ab4cde8f0123456789abcd","state":"released","already_released":false}),
            json!({"store_id":STORE,"found":true,"hold_id":HOLD,"state":"released","already_released":null}),
        ] {
            steps.push(Step {
                method: "_lineage_hold_release",
                params: None,
                reply: Reply::Result(bad.to_string()),
            });
        }
        steps.extend([
            Step {
                method: "_lineage_hold_lookup",
                params: None,
                reply: Reply::ResultWithNullError(
                    json!({"store_id":STORE,"found":false}).to_string(),
                ),
            },
            Step {
                method: "_lineage_hold_lookup",
                params: None,
                reply: Reply::ErrorWithNullResult,
            },
            Step {
                method: "status",
                params: None,
                reply: Reply::ResultWithNullError("{}".into()),
            },
            Step {
                method: "status",
                params: None,
                reply: Reply::ErrorWithNullResult,
            },
        ]);
        let calls = async {
            assert!(discover(&config, STORE).await.is_ok());
            assert!(matches!(
                discover(&config, STORE).await,
                Err(HoldError::Unknown)
            ));
            let acquired = acquire(&config, &intent, None)
                .await
                .map_err(|_| "valid acquire")?;
            assert!(!acquired.replayed);
            for _ in 0..mismatch_count {
                assert!(matches!(
                    acquire(&config, &intent, Some(&acquired.observation)).await,
                    Err(HoldError::Unknown)
                ));
            }
            for _ in 0..4 {
                assert!(matches!(
                    lookup(&config, &intent, Some(&acquired.observation)).await,
                    Err(HoldError::Unknown)
                ));
            }
            for _ in 0..4 {
                assert!(matches!(
                    release(&config, &intent, &acquired.observation, &[5; 64]).await,
                    Err(HoldError::Unknown)
                ));
            }
            for _ in 0..2 {
                assert!(matches!(
                    lookup(&config, &intent, None).await,
                    Err(HoldError::Unknown)
                ));
            }
            let legacy: Value = run_rpc_typed(&config, "status", json!({}))
                .await
                .map_err(|_| "legacy success rejected")?;
            assert!(legacy.is_object());
            let legacy = run_rpc_typed::<Value>(&config, "status", json!({}))
                .await
                .err()
                .ok_or("legacy error accepted")?;
            assert_eq!(legacy.code, "invalid_params");
            Ok::<_, &'static str>(())
        };
        let (calls, server) = tokio::time::timeout(Duration::from_secs(20), async {
            tokio::join!(calls, serve(listener, steps))
        })
        .await?;
        calls?;
        server?;
        Ok(())
    }

    /// Runs only against an explicitly prepared disposable Run fixture and its loss proxy.
    /// The fixture owns the test PEM key; no production signing or service is accessed.
    #[tokio::test]
    #[ignore = "requires an explicitly prepared disposable Run and lost-ACK proxy"]
    async fn hold_real_fixture_lost_ack_and_signed_release() -> Result<(), Box<dyn Error>> {
        use std::{
            io::Write,
            process::{Command, Stdio},
        };

        let socket = std::path::PathBuf::from(
            std::env::var_os("POOL_HOLD_TEST_SOCKET").ok_or("fixture socket required")?,
        );
        let key_path = std::env::var_os("POOL_HOLD_TEST_KEY").ok_or("fixture key required")?;
        let store = std::env::var("POOL_HOLD_TEST_STORE")?;
        let request_id = std::env::var("POOL_HOLD_TEST_REQUEST_ID")?;
        let root = std::env::var("POOL_HOLD_TEST_ROOT")?;
        let target: JsonObject<Target> =
            serde_json::from_str(&std::env::var("POOL_HOLD_TEST_TARGET")?)?;
        let parent = socket.parent().ok_or("fixture socket parent missing")?;
        let mut config = fixture_config(parent, std::fs::metadata(&socket)?.uid());
        config.run_socket = Some(socket);

        let public = Command::new("/usr/bin/openssl")
            .args(["pkey", "-in"])
            .arg(&key_path)
            .args(["-pubout", "-outform", "DER"])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()?;
        let prefix = [
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        if !public.status.success() || public.stdout.len() != 44 || public.stdout[..12] != prefix {
            return Err("fixture key is not an Ed25519 PEM key".into());
        }
        let mut verifying_key = [0_u8; 32];
        verifying_key.copy_from_slice(&public.stdout[12..]);
        let intent = HoldIntent::new(
            store.clone(),
            request_id.clone(),
            vec![target.0],
            vec![root],
            verifying_key,
            None,
        )
        .map_err(|_| "invalid fixture intent")?;
        discover(&config, &store)
            .await
            .map_err(|_| "fixture discovery failed")?;

        let mut wrong_bytes = store.as_bytes().to_vec();
        wrong_bytes[6] = if wrong_bytes[6] == b'0' { b'1' } else { b'0' };
        let wrong_store = String::from_utf8(wrong_bytes)?;
        let wrong = HoldIntent::new(
            wrong_store,
            format!("{request_id}-wrong-store"),
            intent.targets.clone(),
            intent.expected_roots.clone(),
            verifying_key,
            None,
        )
        .map_err(|_| "invalid wrong-store fixture")?;
        assert!(matches!(
            acquire(&config, &wrong, None).await,
            Err(HoldError::Unknown)
        ));
        // This is a snapshot only; the fixture owner checks the stopped store separately.
        let negative: LookupResponse = run_rpc_typed(
            &config,
            "_lineage_hold_lookup",
            json!({
                "version":1,"expected_store_id":store,"request_id":wrong.request_id,
                "fingerprint":wrong.fingerprint
            }),
        )
        .await
        .map_err(|_| "wrong-store snapshot unavailable")?;
        if negative.store_id != store
            || negative.found
            || negative.receipt.is_some()
            || negative.state.is_some()
        {
            return Err("unexpected wrong-store snapshot".into());
        }

        // The first consumer exits after the lost ACK; a fresh process performs lookup.
        let base = std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?;
        let recovered_id = tempfile::NamedTempFile::new_in(&base)?;
        fixture_consumer(&intent, "acquire", recovered_id.path()).await?;
        fixture_consumer(&intent, "lookup", recovered_id.path()).await?;
        let prior = HoldObservation::from_persisted(
            &intent,
            &std::fs::read_to_string(recovered_id.path())?,
            HoldState::Active,
        )
        .map_err(|_| "invalid recovered hold identity")?;
        let observed = match lookup(&config, &intent, Some(&prior)).await {
            Ok(LookupResult::Found(observation)) if observation.state == HoldState::Active => {
                observation
            }
            _ => return Err("exact acquire recovery failed".into()),
        };
        let message = observed
            .release_message(&intent)
            .map_err(|_| "invalid release context")?;
        let mut input = tempfile::NamedTempFile::new_in(&base)?;
        input.write_all(&message)?;
        input.flush()?;
        let signed = Command::new("/usr/bin/openssl")
            .args(["pkeyutl", "-sign", "-rawin", "-inkey"])
            .arg(&key_path)
            .arg("-in")
            .arg(input.path())
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()?;
        if !signed.status.success() || signed.stdout.len() != 64 {
            return Err("fixture signing failed".into());
        }
        let mut signature = [0_u8; 64];
        signature.copy_from_slice(&signed.stdout);
        if !matches!(
            release(&config, &intent, &observed, &signature).await,
            Ok(ReleaseResult {
                already_released: false
            })
        ) {
            return Err("fixture release not confirmed".into());
        }
        if !matches!(
            release(&config, &intent, &observed, &signature).await,
            Ok(ReleaseResult {
                already_released: true
            })
        ) {
            return Err("fixture replay not confirmed".into());
        }
        if !matches!(
            release(&config, &intent, &observed, &[0; 64]).await,
            Err(HoldError::Unknown)
        ) {
            return Err("fixture accepted an invalid release proof".into());
        }
        if !matches!(
            lookup(&config, &intent, Some(&observed)).await,
            Ok(LookupResult::Found(HoldObservation {
                state: HoldState::Released,
                ..
            }))
        ) {
            return Err("fixture released state not confirmed".into());
        }
        Ok(())
    }

    /// One disposable consumer phase reconstructs and checks the exact frozen intent.
    #[tokio::test]
    #[ignore = "invoked only by the disposable lost-ACK fixture supervisor"]
    async fn hold_fixture_consumer_in_child() -> Result<(), Box<dyn Error>> {
        if std::env::var("POOL_HOLD_TEST_CHILD")? != "1" {
            return Err("fixture child marker required".into());
        }
        let socket = std::path::PathBuf::from(
            std::env::var_os("POOL_HOLD_TEST_SOCKET").ok_or("fixture socket required")?,
        );
        let parent = socket.parent().ok_or("fixture socket parent missing")?;
        let mut config = fixture_config(parent, std::fs::metadata(&socket)?.uid());
        config.run_socket = Some(socket);
        let target: JsonObject<Target> =
            serde_json::from_str(&std::env::var("POOL_HOLD_TEST_TARGET")?)?;
        let public_key = decode_id::<32>(&std::env::var("POOL_HOLD_TEST_PUBLIC_KEY")?, "")
            .map_err(|_| "invalid fixture public key")?;
        let intent = HoldIntent::new(
            std::env::var("POOL_HOLD_TEST_STORE")?,
            std::env::var("POOL_HOLD_TEST_REQUEST_ID")?,
            vec![target.0],
            vec![std::env::var("POOL_HOLD_TEST_ROOT")?],
            public_key,
            None,
        )
        .map_err(|_| "invalid child intent")?;
        if intent.fingerprint() != std::env::var("POOL_HOLD_TEST_FINGERPRINT")? {
            return Err("fixture consumer intent changed".into());
        }
        match std::env::var("POOL_HOLD_TEST_PHASE")?.as_str() {
            "acquire" => {
                if !matches!(
                    acquire(&config, &intent, None).await,
                    Err(HoldError::Unknown)
                ) {
                    return Err("fixture did not lose acquire acknowledgement".into());
                }
            }
            "lookup" => {
                let observed = match lookup(&config, &intent, None).await {
                    Ok(LookupResult::Found(observation))
                        if observation.state == HoldState::Active =>
                    {
                        observation
                    }
                    _ => return Err("fixture child recovery failed".into()),
                };
                let path = std::env::var_os("POOL_HOLD_TEST_RESULT_PATH")
                    .ok_or("fixture output required")?;
                std::fs::write(path, observed.receipt.hold_id())?;
            }
            _ => return Err("unknown fixture consumer phase".into()),
        }
        Ok(())
    }
}
