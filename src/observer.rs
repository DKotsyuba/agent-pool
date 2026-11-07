//! Versioned owner-only observation protocol, independent of native participant authority.
use crate::{
    config::Config,
    domain::{self, Fault},
    integrations::{self, EXCHANGE_TIMEOUT, MAX_FRAME},
};
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    path::Path,
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Strict single-line input; unknown operations and extra fields are rejected before dispatch.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Exactly 1; future protocol revisions require explicit support.
    pub schema_version: u32,
    /// Closed read-only operation with operation-specific arguments.
    #[serde(flatten)]
    pub operation: Operation,
}
/// Only owner identity and bounded projections are representable; never a domain command.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "operation", content = "params", rename_all = "snake_case")]
pub enum Operation {
    /// Product capabilities, authenticated against the same resident as pool reads.
    Identity(IdentityParams),
    /// All pools, independent of participant membership, in ascending stable ID order.
    List(domain::List),
    /// One independently paged section; mappings require an explicit opt-in.
    Get(Get),
}
/// Identity takes an explicit empty object, never arbitrary options.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityParams {}
/// Owner-specific arguments; existing participant Get semantics remain unchanged.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Get {
    /// Exact opaque pool ID.
    pub pool_id: String,
    /// Section-local exclusive cursor; zero starts at the beginning.
    #[serde(default, deserialize_with = "cursor")]
    pub after: u64,
    /// Existing section names, plus decisions for the retained proposal archive.
    #[serde(default = "overview")]
    pub section: String,
    /// Exact archived proposal, valid only for proposal or votes.
    #[serde(default)]
    pub proposal_id: Option<String>,
    /// Exact current or removed incarnation, required for binding and Run proof.
    #[serde(default)]
    pub member_id: Option<String>,
    /// Selects the long-content field only for the content section.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<domain::ContentField>,
    /// Include native/Run mappings on roster pages; false omits them entirely.
    #[serde(default)]
    pub include_bindings: bool,
    /// Required on mutable roster/vote continuation; exact revision from the preceding view.
    #[serde(default)]
    pub expected_revision: Option<u64>,
    /// Opt-in history direction; omission preserves the original forward response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<HistoryDirection>,
    /// Exclusive oldest boundary for a backward history page.
    #[serde(
        default,
        deserialize_with = "optional_cursor",
        skip_serializing_if = "Option::is_none"
    )]
    pub before: Option<u64>,
    /// Inclusive, fixed history watermark returned by an earlier page.
    #[serde(
        default,
        deserialize_with = "optional_cursor",
        skip_serializing_if = "Option::is_none"
    )]
    pub through: Option<u64>,
}
/// Direction of an explicitly requested history page.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryDirection {
    /// Read events after the cursor in ascending order.
    Forward,
    /// Read the newest events before the cursor, returning them in ascending order.
    Backward,
}
/// A cursor accepts exact decimal text as well as the original JSON integer.
#[derive(Deserialize)]
#[serde(untagged)]
enum Cursor {
    Integer(u64),
    Text(String),
}
impl Cursor {
    /// Rejects noncanonical or overflowing decimal strings before any read.
    fn value<E: serde::de::Error>(self) -> Result<u64, E> {
        match self {
            Self::Integer(value) => Ok(value),
            Self::Text(value)
                if !value.is_empty()
                    && value.bytes().all(|byte| byte.is_ascii_digit())
                    && (value.len() == 1 || !value.starts_with('0')) =>
            {
                value.parse().map_err(E::custom)
            }
            Self::Text(_) => Err(E::custom("invalid decimal cursor")),
        }
    }
}
/// Deserializes the defaulted forward cursor without losing integer precision.
fn cursor<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    Cursor::deserialize(deserializer)?.value()
}
/// Deserializes an optional exact cursor, including an explicit null.
fn optional_cursor<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u64>, D::Error> {
    Option::<Cursor>::deserialize(deserializer)?
        .map(Cursor::value)
        .transpose()
}
/// Default section matches the existing participant API.
fn overview() -> String {
    "overview".into()
}
impl Get {
    /// Converts existing sections to their reviewed projection contract; decisions is handled separately.
    pub fn projection(&self) -> Result<domain::Get, Fault> {
        let section = serde_json::from_value(serde_json::Value::String(self.section.clone()))
            .map_err(|_| Fault::Invalid)?;
        let get = domain::Get {
            pool_id: self.pool_id.clone(),
            after: self.after,
            section,
            proposal_id: self.proposal_id.clone(),
            member_id: self.member_id.clone(),
            wait_seconds: 0.0,
            reverse: false,
            before: None,
            field: self.field.clone(),
            expected_revision: self.expected_revision,
        };
        domain::Command::Get(get.clone()).validate()?;
        if matches!(
            get.section,
            domain::Section::Overview
                | domain::Section::Members
                | domain::Section::Votes
                | domain::Section::Content
        ) && self.after > 0
            && self.expected_revision.is_none()
        {
            return Err(Fault::Invalid);
        }
        if self.include_bindings
            && !matches!(
                get.section,
                domain::Section::Overview | domain::Section::Members | domain::Section::Binding
            )
        {
            return Err(Fault::Invalid);
        }
        Ok(get)
    }
}
impl Request {
    /// Validates version and bounds without I/O; no mutation or native assertion is accepted.
    pub fn validate(&self) -> Result<(), Fault> {
        if self.schema_version != 1 {
            return Err(Fault::Invalid);
        }
        if let Operation::Get(args) = &self.operation {
            if (args.direction.is_some() || args.before.is_some() || args.through.is_some())
                && args.section != "history"
            {
                return Err(Fault::Invalid);
            }
            if args.direction.is_none() && (args.before.is_some() || args.through.is_some()) {
                return Err(Fault::Invalid);
            }
            if let Some(direction) = args.direction
                && (i64::try_from(args.after).is_err()
                    || args
                        .before
                        .is_some_and(|n| n == 0 || i64::try_from(n).is_err())
                    || args.through.is_some_and(|n| i64::try_from(n).is_err())
                    || (direction == HistoryDirection::Backward && args.after != 0)
                    || (direction == HistoryDirection::Forward && args.before.is_some()))
            {
                return Err(Fault::Invalid);
            }
        }
        match &self.operation {
            Operation::Identity(_) => Ok(()),
            Operation::List(args) => domain::Command::List(args.clone()).validate(),
            Operation::Get(args) if args.section == "decisions" => {
                domain::identifier(&args.pool_id)?;
                i64::try_from(args.after).map_err(|_| Fault::Invalid)?;
                if args.proposal_id.is_some()
                    || args.member_id.is_some()
                    || args.include_bindings
                    || args.field.is_some()
                {
                    return Err(Fault::Invalid);
                }
                Ok(())
            }
            Operation::Get(args) if args.section == "run_proof" => {
                domain::identifier(&args.pool_id)?;
                domain::identifier(args.member_id.as_deref().ok_or(Fault::Invalid)?)?;
                if args.after != 0
                    || args.proposal_id.is_some()
                    || args.include_bindings
                    || args.field.is_some()
                    || args.expected_revision == Some(0)
                {
                    return Err(Fault::Invalid);
                }
                Ok(())
            }
            Operation::Get(args) => args.projection().map(|_| ()),
        }
    }
    /// Stable success/error family; invalid requests with no decoded operation use error instead.
    pub fn kind(&self) -> &'static str {
        match self.operation {
            Operation::Identity(_) => "identity",
            Operation::List(_) => "pool_page",
            Operation::Get(ref args) if args.section == "run_proof" => "run_proof",
            Operation::Get(_) => "pool_detail",
        }
    }
}
/// Separate transport ingress; never deserialized as a participant command or native assertion.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ingress {
    /// Protected owner read grant, never serialized into replies or diagnostics.
    pub observer_credential: String,
    /// Versioned read-only request, with no invocation metadata.
    pub observe: Request,
}
/// Fixed safe typed error, with no raw storage, transport, or rejected input content.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Error {
    /// Existing stable domain error code.
    pub code: Fault,
    /// blocked for input/authority, unavailable for source/transport failure.
    pub outcome: String,
    /// Fixed explanatory text, never a credential or backend diagnostic.
    pub detail: String,
}
/// One exclusive success or error envelope; constructors and client validation enforce branch identity.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    /// Current observer schema version.
    pub schema_version: u32,
    /// identity, pool_page or pool_detail; error if operation could not be decoded.
    pub kind: String,
    /// Present only on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Data>,
    /// Present only on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Error>,
}
/// Closed typed projections; no credential-bearing input enters response rendering.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum Data {
    /// Authenticated product identity.
    Identity(Identity),
    /// Complete metadata rows for one pool inventory page.
    Pools(PoolPage),
    /// Existing safe section projection plus explicit owner-only mappings when requested.
    Detail(Box<Detail>),
    /// Historical Run evidence for one exact owner-selected membership.
    RunProof(#[serde(deserialize_with = "crate::integrations::json_object")] Box<RunProof>),
}
/// Whether the status source returned a validated snapshot for this membership.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunProofState {
    /// Run returned a correlated status snapshot, which may itself report mismatch or unknown.
    Observed,
    /// No exact status snapshot is available.
    Unknown,
}
/// Safe explanation for an unavailable proof, without paths or provider messages.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunProofReason {
    /// The membership has no complete Run identity and retained pin.
    IncompleteBinding,
    /// Its original accepted store route is missing, ambiguous, or differs from configuration.
    OriginUnavailable,
    /// The scoped Run status call failed or its response was not trustworthy.
    RunUnavailable,
}
/// Run status does not prove who made a Pool call.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunProofAuthority {
    /// Caller and current attempt have not been established by this observation.
    Unknown,
}
/// Owner-only historical execution evidence; it never establishes the caller's authority.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunProof {
    /// Exact pool and membership selected by the owner.
    pub pool_id: String,
    /// Exact membership selected by the owner.
    pub member_id: String,
    /// Pool revision rechecked after any Run read.
    pub pool_revision: u64,
    /// Whether this membership remains in the current roster.
    pub current: bool,
    /// Pool's own observation time in Unix milliseconds.
    pub observed_at_unix_ms: u64,
    /// Result availability, distinct from the execution's Run match state.
    pub state: RunProofState,
    /// Reason when no trustworthy Run snapshot is available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<RunProofReason>,
    /// Original Run store identity, when known from the binding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub store_id: Option<String>,
    /// Run's own snapshot time in Unix seconds, not a Pool revision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_observed_at: Option<f64>,
    /// Exact validated execution evidence, when available.
    #[serde(
        default,
        deserialize_with = "crate::integrations::nullable_object",
        skip_serializing_if = "Option::is_none"
    )]
    pub proof: Option<crate::run_status::ProofProjection>,
    /// Caller and current attempt are not established by this read-only observation.
    pub author_identity: RunProofAuthority,
}
impl RunProof {
    /// Checks the observer envelope without turning missing evidence into a positive proof.
    fn valid(&self) -> bool {
        domain::identifier(&self.pool_id).is_ok()
            && domain::identifier(&self.member_id).is_ok()
            && self.pool_revision > 0
            && self
                .store_id
                .as_deref()
                .is_none_or(|id| domain::store_id(id).is_ok())
            && match self.state {
                RunProofState::Observed => {
                    self.reason.is_none()
                        && self.store_id.is_some()
                        && self
                            .run_observed_at
                            .is_some_and(|time| time.is_finite() && time >= 0.0)
                        && self
                            .proof
                            .as_ref()
                            .is_some_and(crate::run_status::ProofProjection::valid)
                }
                RunProofState::Unknown => {
                    self.reason.is_some() && self.run_observed_at.is_none() && self.proof.is_none()
                }
            }
    }
}
/// Authenticated resident identity, without an invented installed/source revision.
#[derive(Serialize, Deserialize)]
pub struct Identity {
    /// Fixed product name.
    pub product: String,
    /// Package version compiled into this binary.
    pub version: String,
    /// Actual embedded qualification, never promoted by local tests.
    pub qualification: String,
    /// Supported owner API operations.
    pub capabilities: Vec<String>,
    /// Unix milliseconds when the resident built this answer.
    pub observed_at_unix_ms: u64,
}
/// Stable leader identity remains outside all roster counts and rows.
#[derive(Serialize, Deserialize)]
pub struct PoolRow {
    /// Existing metadata; proposal body is retrieved separately.
    pub pool: domain::Pool,
    /// Native tuple digest already retained as leader identity; no native address.
    pub leader_id: String,
}
/// All pages disclose coverage, exact continuation and observed freshness.
#[derive(Serialize, Deserialize)]
pub struct Page {
    /// Cursor after the final returned row, reused with the same operation/section.
    pub cursor: Option<String>,
    /// True only when a subsequent row was observed.
    pub has_more: bool,
    /// Exact number of rows represented in this page.
    pub returned: usize,
    /// Source snapshot observation time, in Unix milliseconds.
    pub observed_at_unix_ms: u64,
    /// Historical timestamps are absent from Store schema v5, explicitly null.
    pub source_timestamp: Option<u64>,
    /// Explicit paging/snapshot and missing timestamp limitations.
    pub coverage: String,
}
/// Inventory is complete only after following all pages; order is ascending opaque pool ID.
#[derive(Serialize, Deserialize)]
pub struct PoolPage {
    /// Bounded complete pool metadata and separate leader IDs.
    pub pools: Vec<PoolRow>,
    /// Paging and freshness metadata.
    #[serde(flatten)]
    pub page: Page,
}
/// One independent section; execution, voting, acceptance and delivery retain their own states.
#[derive(Serialize, Deserialize)]
pub struct Detail {
    /// Exact requested section, including decisions.
    pub section: String,
    /// Existing typed section; absent only for archive enumeration.
    pub view: Option<Box<domain::View>>,
    /// Separate stable leader ID; never counted as a member.
    pub leader_id: String,
    /// Explicitly requested private mappings only; absent by default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bindings: Option<Vec<domain::Binding>>,
    /// Retained proposal metadata without votes, retrieved via proposal_id and votes pages.
    pub decisions: Vec<domain::Proposal>,
    /// Exact fixed upper event ID for opt-in history paging; absent on legacy reads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_watermark: Option<String>,
    /// Paging and freshness metadata for the selected section only.
    #[serde(flatten)]
    pub page: Page,
}
impl Page {
    /// Constructs truthful metadata; each request is a current resident snapshot, not a cross-page snapshot.
    pub fn new(cursor: Option<String>, has_more: bool, returned: usize) -> Result<Self, Fault> {
        Ok(Self { cursor, has_more, returned, observed_at_unix_ms: now()?, source_timestamp:None,
            coverage:"Selected section only; follow cursor while has_more. Pages observe current state independently. Historical source timestamps are not recorded in Store schema v5.".into() })
    }
}
/// Returns current Unix milliseconds, refusing clocks before the epoch or unrepresentable values.
pub(crate) fn now() -> Result<u64, Fault> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Fault::Unavailable)?
        .as_millis()
        .try_into()
        .map_err(|_| Fault::Unavailable)
}
impl Envelope {
    /// Wraps a verified typed result with no error branch.
    pub fn success(kind: &str, data: Data) -> Self {
        Self {
            schema_version: 1,
            kind: kind.into(),
            data: Some(data),
            error: None,
        }
    }
    /// Maps domain failures to safe deterministic errors; a read never implies uncertain external effects.
    pub fn failure(kind: &str, code: Fault) -> Self {
        let unavailable = matches!(code, Fault::Internal | Fault::Unavailable);
        Self { schema_version:1, kind:kind.into(), data:None, error:Some(Error { code, outcome:if unavailable { "unavailable" } else { "blocked" }.into(), detail:if unavailable { "Observation source unavailable; no read result is implied." } else { "Observation refused; check request and separately provisioned owner read grant." }.into() }) }
    }
    /// Authenticated resident identity requires no database mutation or integration call.
    pub fn identity() -> Result<Data, Fault> {
        Ok(Data::Identity(Identity {
            product: "agent-pool".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            qualification: crate::qualification().into(),
            capabilities: vec![
                "identity".into(),
                "list".into(),
                "get".into(),
                "history_window_v1".into(),
                "structured_acceptance_v1".into(),
                "message_parts_v1".into(),
                "content_pages_v1".into(),
                "run_proof_v1".into(),
            ],
            observed_at_unix_ms: now()?,
        }))
    }
}
/// Bounded output buffer rejects the whole envelope rather than publishing a partial JSON value.
struct Buffer(Vec<u8>);
impl Write for Buffer {
    /// Reserves one byte for the newline so the entire encoded response stays within 1 MiB.
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.0.len().saturating_add(bytes.len()) >= MAX_FRAME {
            return Err(std::io::Error::other("observer envelope limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    /// In-memory output needs no flushing.
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
/// Encodes one complete bounded JSON line; overflow becomes an explicit unavailable error.
pub fn encode(envelope: &Envelope) -> Result<Vec<u8>, Fault> {
    let mut buffer = Buffer(Vec::new());
    serde_json::to_writer(&mut buffer, envelope).map_err(|_| Fault::Unavailable)?;
    buffer.0.push(b'\n');
    Ok(buffer.0)
}
/// Calls only the existing resident; loads no Bridge token and never opens a SQLite writer.
pub async fn frontend(request: Request, path: &Path) -> Result<Envelope, Fault> {
    request.validate()?;
    if !path.is_absolute() {
        return Err(Fault::Invalid);
    }
    let path = path.to_owned();
    let (config, credential) = tokio::task::spawn_blocking(move || {
        let config = Config::load(&path)?;
        integrations::own_uid(config.expected_uid)?;
        let credential_path = config
            .owner_observer_credential_file
            .as_deref()
            .ok_or(Fault::Unauthorized)?;
        crate::config::private_parent(credential_path, config.expected_uid)?;
        let token = config.credential(credential_path)?;
        Ok::<_, Fault>((config, token))
    })
    .await
    .map_err(|_| Fault::Internal)??;
    let expected_kind = request.kind();
    let expected_proof = match &request.operation {
        Operation::Get(args) if args.section == "run_proof" => Some((
            args.pool_id.clone(),
            args.member_id.clone().ok_or(Fault::Invalid)?,
            args.expected_revision,
        )),
        _ => None,
    };
    let bytes = serde_json::to_vec(&Ingress {
        observer_credential: credential,
        observe: request,
    })
    .map_err(|_| Fault::Invalid)?;
    if bytes.len() >= MAX_FRAME {
        return Err(Fault::Invalid);
    }
    tokio::time::timeout(EXCHANGE_TIMEOUT * 3, async {
        let mut stream = integrations::connect(&config.socket_path, config.expected_uid).await?;
        stream
            .write_all(&bytes)
            .await
            .map_err(|_| Fault::Unavailable)?;
        stream
            .write_all(b"\n")
            .await
            .map_err(|_| Fault::Unavailable)?;
        let envelope: Envelope =
            serde_json::from_slice(&integrations::read_frame(&mut stream).await?)
                .map_err(|_| Fault::Unavailable)?;
        if envelope.schema_version != 1
            || envelope.kind != expected_kind
            || envelope.data.is_some() == envelope.error.is_some()
        {
            return Err(Fault::Unavailable);
        }
        if envelope.data.as_ref().is_some_and(|data| {
            !matches!(
                (expected_kind, data),
                ("identity", Data::Identity(_))
                    | ("pool_page", Data::Pools(_))
                    | ("pool_detail", Data::Detail(_))
                    | ("run_proof", Data::RunProof(_))
            )
        }) {
            return Err(Fault::Unavailable);
        }
        if let Some(Data::RunProof(proof)) = &envelope.data {
            let Some((pool_id, member_id, revision)) = &expected_proof else {
                return Err(Fault::Unavailable);
            };
            if !proof.valid()
                || &proof.pool_id != pool_id
                || &proof.member_id != member_id
                || revision.is_some_and(|revision| revision != proof.pool_revision)
            {
                return Err(Fault::Unavailable);
            }
        }
        Ok(envelope)
    })
    .await
    .map_err(|_| Fault::Unavailable)?
}
/// Reads exactly one bounded UTF-8 JSON line through EOF; rejects trailing lines or bytes.
/// EOF is required to prove there was no second line; source acquisition has no execution deadline.
async fn input() -> Result<Request, Fault> {
    let mut bytes = Vec::new();
    tokio::io::stdin()
        .take(MAX_FRAME as u64 + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| Fault::Unavailable)?;
    if bytes.len() > MAX_FRAME
        || bytes.last() != Some(&b'\n')
        || bytes[..bytes.len() - 1].contains(&b'\n')
    {
        return Err(Fault::Invalid);
    }
    serde_json::from_slice(&bytes).map_err(|_| Fault::Invalid)
}
/// Fixed structured CLI branch; emits exactly one JSON line and no human prose.
pub async fn cli(path: Option<&Path>) -> ExitCode {
    let request = input().await;
    let kind = request.as_ref().map_or("error", Request::kind);
    let result = match (request, path) {
        (Ok(request), Some(path)) => frontend(request, path).await,
        (Err(error), _) => Err(error),
        (_, None) => Err(Fault::Unavailable),
    };
    let envelope = result.unwrap_or_else(|error| Envelope::failure(kind, error));
    let mut failed = envelope.error.is_some();
    let bytes = encode(&envelope).or_else(|error| {
        failed = true;
        encode(&Envelope::failure(kind, error))
    });
    let Ok(bytes) = bytes else {
        return ExitCode::FAILURE;
    };
    let mut stdout = tokio::io::stdout();
    if stdout.write_all(&bytes).await.is_err() || stdout.flush().await.is_err() {
        return ExitCode::FAILURE;
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Observer parser and complete-envelope byte bounds, without configured services.
#[cfg(test)]
mod tests {
    use super::*;
    /// Owned input rejects malformed fields, unknown operations/sections and native assertion reuse.
    #[test]
    fn observer_contract_is_strict() -> Result<(), Box<dyn std::error::Error>> {
        for operation in ["identity", "list"] {
            let request: Request = serde_json::from_value(
                serde_json::json!({"schema_version":1,"operation":operation,"params":{}}),
            )?;
            request.validate()?;
        }
        for value in [
            serde_json::json!({"schema_version":1,"operation":"identity","params":{"extra":true}}),
            serde_json::json!({"schema_version":1,"operation":"identity","params":{},"assertion":{}}),
            serde_json::json!({"schema_version":1,"operation":"pool_create","params":{}}),
            serde_json::json!({"schema_version":1,"operation":"identity"}),
        ] {
            assert!(serde_json::from_value::<Request>(value).is_err());
        }
        for params in [
            serde_json::json!({"pool_id":"pool","section":"unknown"}),
            serde_json::json!({"pool_id":"pool","section":"history","include_bindings":true}),
            serde_json::json!({"pool_id":"pool","section":"binding"}),
            serde_json::json!({"pool_id":"pool","section":"decisions","after":u64::MAX}),
            serde_json::json!({"pool_id":"pool","section":"run_proof"}),
            serde_json::json!({"pool_id":"pool","section":"run_proof","member_id":"member","after":1}),
            serde_json::json!({"pool_id":"pool","section":"run_proof","member_id":"member","include_bindings":true}),
            serde_json::json!({"pool_id":"pool","section":"run_proof","member_id":"member","expected_revision":0}),
        ] {
            let request: Request = serde_json::from_value(
                serde_json::json!({"schema_version":1,"operation":"get","params":params}),
            )?;
            assert!(matches!(request.validate(), Err(Fault::Invalid)));
        }
        let proof: Request = serde_json::from_value(serde_json::json!({
            "schema_version":1,"operation":"get","params":{
                "pool_id":"pool","section":"run_proof","member_id":"member","expected_revision":1
            }
        }))?;
        proof.validate()?;
        assert_eq!(proof.kind(), "run_proof");
        let request: Request = serde_json::from_value(
            serde_json::json!({"schema_version":2,"operation":"identity","params":{}}),
        )?;
        assert!(matches!(request.validate(), Err(Fault::Invalid)));
        let request: Request = serde_json::from_value(serde_json::json!({
            "schema_version":1,"operation":"get","params":{
                "pool_id":"pool","section":"history","direction":"forward",
                "after":"9007199254740993","through":"9007199254740993"
            }
        }))?;
        let decoded: Request = serde_json::from_slice(&serde_json::to_vec(&request)?)?;
        decoded.validate()?;
        let Operation::Get(args) = decoded.operation else {
            return Err("history request changed operation".into());
        };
        assert_eq!(args.after, 9_007_199_254_740_993);
        assert_eq!(args.through, Some(9_007_199_254_740_993));
        Ok(())
    }

    /// A decoded owner proof cannot claim stronger evidence or caller authority than its status.
    #[test]
    fn run_proof_envelope_rejects_contradictory_fields() -> Result<(), Box<dyn std::error::Error>> {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/run-status-v1-success.json"))?;
        let request = &fixture["socket"]["request"];
        let store = request["expected_store_id"].as_str().ok_or("store")?;
        let targets: Vec<crate::run_status::Target> =
            serde_json::from_value(request["targets"].clone())?;
        let bytes = serde_json::to_vec(&fixture["socket"]["result"])?;
        let evidence = crate::run_status::parse(&bytes, store, &targets)
            .map_err(|error| format!("{error:?}"))?;
        let proof = evidence.items().next().ok_or("item")?.projection();
        let valid = RunProof {
            pool_id: "pool".into(),
            member_id: "member".into(),
            pool_revision: 1,
            current: true,
            observed_at_unix_ms: 1,
            state: RunProofState::Observed,
            reason: None,
            store_id: Some(store.into()),
            run_observed_at: Some(evidence.observed_at()),
            proof: Some(proof),
            author_identity: RunProofAuthority::Unknown,
        };
        assert!(valid.valid());
        let mut value = serde_json::to_value(valid)?;
        value["proof"]["historical_success"] = serde_json::json!(false);
        assert!(!serde_json::from_value::<RunProof>(value.clone())?.valid());
        value["proof"]["historical_success"] = serde_json::json!(true);
        value["author_identity"] = serde_json::json!("verified");
        assert!(serde_json::from_value::<RunProof>(value).is_err());
        Ok(())
    }

    /// The real frontend refuses a valid proof for another requested member, pool or revision.
    #[tokio::test]
    async fn run_proof_frontend_correlates_request() -> Result<(), Box<dyn std::error::Error>> {
        use std::{
            fs,
            os::unix::fs::{MetadataExt, PermissionsExt},
        };
        let directory =
            tempfile::tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path();
        let socket = path.join("pool.sock");
        let listener = tokio::net::UnixListener::bind(&socket)?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
        let token = path.join("observer.token");
        fs::write(&token, "fixture-observer")?;
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600))?;
        let config = path.join("config.toml");
        fs::write(
            &config,
            format!(
                "socket_path={socket:?}\ndatabase_path={:?}\nexpected_uid={}\nbridge_registration_socket={:?}\nbridge_core_socket={:?}\nbridge_credential_file={:?}\nbridge_producer_id=\"fixture\"\nbridge_audience=\"fixture\"\nowner_observer_credential_file={token:?}\n",
                path.join("unused.db"),
                fs::metadata(path)?.uid(),
                path.join("registration"),
                path.join("bridge"),
                path.join("bridge.token")
            ),
        )?;
        for (pool, member, reply_revision, requested_revision, succeeds) in [
            ("pool", "member", 7, Some(7), true),
            ("other", "member", 7, Some(7), false),
            ("pool", "other", 7, Some(7), false),
            ("pool", "member", 8, Some(7), false),
            ("pool", "member", 8, None, true),
        ] {
            let request: Request = serde_json::from_value(serde_json::json!({
                "schema_version":1,"operation":"get","params":{
                    "pool_id":"pool","section":"run_proof","member_id":"member",
                    "expected_revision":requested_revision
                }
            }))?;
            let response = serde_json::json!({
                "schema_version":1,"kind":"run_proof","data":{
                    "pool_id":pool,"member_id":member,"pool_revision":reply_revision,
                    "current":true,"observed_at_unix_ms":1,"state":"unknown",
                    "reason":"incomplete_binding","author_identity":"unknown"
                }
            });
            let (received, served) =
                tokio::time::timeout(std::time::Duration::from_secs(5), async {
                    tokio::join!(frontend(request, &config), async {
                        let (mut stream, _) = listener.accept().await?;
                        let bytes = integrations::read_frame(&mut stream)
                            .await
                            .map_err(std::io::Error::other)?;
                        let forwarded: serde_json::Value = serde_json::from_slice(&bytes)?;
                        assert_eq!(forwarded["observer_credential"], "fixture-observer");
                        let mut bytes = serde_json::to_vec(&response)?;
                        bytes.push(b'\n');
                        stream.write_all(&bytes).await?;
                        Ok::<_, Box<dyn std::error::Error>>(())
                    })
                })
                .await?;
            served?;
            assert_eq!(received.is_ok(), succeeds);
            if !succeeds {
                assert!(matches!(received, Err(Fault::Unavailable)));
            }
        }
        assert!(!path.join("unused.db").exists());
        Ok(())
    }
    /// Byte accounting includes UTF-8, JSON escaping and newline; no partial result escapes on overflow.
    #[test]
    fn observer_unicode_envelope_budget_and_error_branch() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut envelope = Envelope::failure("pool_detail", Fault::Unavailable);
        let error = envelope.error.as_mut().ok_or("error branch")?;
        error.detail = "🦀\"\\".repeat(MAX_FRAME / 6);
        assert!(matches!(encode(&envelope), Err(Fault::Unavailable)));
        let bytes = encode(&Envelope::failure("pool_detail", Fault::Unavailable))?;
        assert!(bytes.len() <= MAX_FRAME && bytes.last() == Some(&b'\n'));
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert!(value.get("data").is_none());
        assert_eq!(value["error"]["outcome"], "unavailable");
        let success = encode(&Envelope::success("identity", Envelope::identity()?))?;
        let value: serde_json::Value = serde_json::from_slice(&success)?;
        assert!(value.get("error").is_none());
        assert_eq!(value["data"]["product"], "agent-pool");
        assert!(
            value["data"]["capabilities"]
                .as_array()
                .is_some_and(|items| items.iter().any(|item| item == "history_window_v1"))
        );
        assert!(
            value["data"]["capabilities"]
                .as_array()
                .is_some_and(|items| items.iter().any(|item| item == "structured_acceptance_v1"))
        );
        assert!(
            value["data"]["capabilities"]
                .as_array()
                .is_some_and(|items| items.iter().any(|item| item == "message_parts_v1"))
        );
        assert!(
            value["data"]["capabilities"]
                .as_array()
                .is_some_and(|items| items.iter().any(|item| item == "content_pages_v1"))
        );
        assert!(value["data"].get("source_revision").is_none());
        Ok(())
    }
}
