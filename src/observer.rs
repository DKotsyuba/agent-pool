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
    #[serde(default)]
    pub after: u64,
    /// Existing section names, plus decisions for the retained proposal archive.
    #[serde(default = "overview")]
    pub section: String,
    /// Exact archived proposal, valid only for proposal or votes.
    #[serde(default)]
    pub proposal_id: Option<String>,
    /// Exact current or removed incarnation, required only for binding.
    #[serde(default)]
    pub member_id: Option<String>,
    /// Include native/Run mappings on roster pages; false omits them entirely.
    #[serde(default)]
    pub include_bindings: bool,
    /// Required on mutable roster/vote continuation; exact revision from the preceding view.
    #[serde(default)]
    pub expected_revision: Option<u64>,
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
        };
        domain::Command::Get(get.clone()).validate()?;
        if matches!(
            get.section,
            domain::Section::Overview | domain::Section::Members | domain::Section::Votes
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
        match &self.operation {
            Operation::Identity(_) => Ok(()),
            Operation::List(args) => domain::Command::List(args.clone()).validate(),
            Operation::Get(args) if args.section == "decisions" => {
                domain::identifier(&args.pool_id)?;
                i64::try_from(args.after).map_err(|_| Fault::Invalid)?;
                if args.proposal_id.is_some() || args.member_id.is_some() || args.include_bindings {
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
    /// Historical timestamps are absent from Store schema v1, explicitly null.
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
    /// Paging and freshness metadata for the selected section only.
    #[serde(flatten)]
    pub page: Page,
}
impl Page {
    /// Constructs truthful metadata; each request is a current resident snapshot, not a cross-page snapshot.
    pub fn new(cursor: Option<String>, has_more: bool, returned: usize) -> Result<Self, Fault> {
        Ok(Self { cursor, has_more, returned, observed_at_unix_ms: now()?, source_timestamp:None,
            coverage:"Selected section only; follow cursor while has_more. Pages observe current state independently. Historical source timestamps are not recorded in Store schema v1.".into() })
    }
}
/// Returns current Unix milliseconds, refusing clocks before the epoch or unrepresentable values.
fn now() -> Result<u64, Fault> {
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
            capabilities: vec!["identity".into(), "list".into(), "get".into()],
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
            )
        }) {
            return Err(Fault::Unavailable);
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
        ] {
            let request: Request = serde_json::from_value(
                serde_json::json!({"schema_version":1,"operation":"get","params":params}),
            )?;
            assert!(matches!(request.validate(), Err(Fault::Invalid)));
        }
        let request: Request = serde_json::from_value(
            serde_json::json!({"schema_version":2,"operation":"identity","params":{}}),
        )?;
        assert!(matches!(request.validate(), Err(Fault::Invalid)));
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
        assert!(value["data"].get("source_revision").is_none());
        Ok(())
    }
}
