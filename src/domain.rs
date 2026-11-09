//! Typed pool commands, safe public views, and private durable delivery intents.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Maximum current members, including pending invitations, in one pool.
pub const MAX_MEMBERS: usize = 20;
/// Maximum message part, proposal result, or vote evidence size in UTF-8 bytes.
pub const MAX_TEXT: usize = 2048;
/// Maximum complete participant message size, stored in bounded journal parts.
pub const MAX_MESSAGE: usize = 8192;

/// Authenticated native identity; constructed only after a current Bridge assertion.
#[derive(Clone)]
pub struct Actor {
    /// Stable digest of the verified native tuple; never accepted from tool arguments.
    pub key: String,
    /// Canonical verified delivery address, private to the resident and owner.
    pub address: String,
}
impl Actor {
    /// Derives identity from a verified canonical address, native actor ID and role wire value.
    /// Empty components are refused; callers must first consume a current assertion.
    pub fn verified(address: String, native_actor: &str, role: &str) -> Result<Self, Fault> {
        if address.is_empty() || native_actor.is_empty() || role.is_empty() {
            return Err(Fault::Unauthorized);
        }
        let tuple = serde_json::to_vec(&["agent-pool.actor.v1", &address, native_actor, role])
            .map_err(|_| Fault::Internal)?;
        Ok(Self {
            key: format!("{:x}", Sha256::digest(tuple)),
            address,
        })
    }
}

/// Closed errors safe to return to any caller without private addresses or storage paths.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Fault {
    /// The request is malformed or outside the documented size bounds.
    Invalid,
    /// Fresh trusted native identity could not be established.
    Unauthorized,
    /// The caller cannot access the requested pool or operation.
    Forbidden,
    /// The expected pool version or proposal identity is no longer current.
    Stale,
    /// A global role, membership, capacity, or idempotency invariant conflicts.
    Conflict,
    /// The pool is closed and cannot be changed.
    Closed,
    /// A configured dependency is unavailable; no success is implied.
    Unavailable,
    /// The Pool resident must be relaunched after Bridge enabled its managed role.
    RelaunchRequired,
    /// An internal storage or serialization failure occurred; details stay private.
    Internal,
}
impl std::fmt::Display for Fault {
    /// Formats only the fixed safe code, never an underlying diagnostic.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Fault {}
impl From<rusqlite::Error> for Fault {
    /// Hides SQL statements, paths, bindings and implementation details.
    fn from(_: rusqlite::Error) -> Self {
        Self::Internal
    }
}

/// Common optimistic and idempotency preconditions for pool mutations.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Change {
    /// Opaque pool ID returned by creation or invitation.
    pub pool_id: String,
    /// Current version read from pool_get; checked before first execution.
    pub expected_revision: u64,
    /// Caller-selected key, 1–128 ASCII identifier bytes; retained for exact retries.
    pub request_key: String,
}
/// Creation arguments; successful creation permanently assigns the caller leader status.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Create {
    /// Stable idempotency key for this creation intent.
    pub request_key: String,
    /// Pool label, 1–80 UTF-8 bytes.
    pub name: String,
    /// Pool purpose, 1–8192 UTF-8 bytes.
    pub purpose: String,
    /// Optional structured acceptance; an explicitly empty list selects the default goal criterion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acceptance: Option<Vec<Criterion>>,
}
/// Immutable, individually checkable condition for a pool's result.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Criterion {
    /// Unique ASCII identifier, at most 32 bytes.
    pub id: String,
    /// Condition text, at most 1024 UTF-8 bytes.
    pub text: String,
}
/// Bounded history read; returns at most 12 events after the exclusive cursor.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Get {
    /// Accessible pool ID.
    pub pool_id: String,
    /// Last displayed event ID; zero or omitted starts at the beginning.
    #[serde(default)]
    pub after: u64,
    /// Selects one bounded section; cursors resume only within that section.
    #[serde(default)]
    pub section: Section,
    /// Optional retained proposal ID for proposal/votes sections; omitted selects the latest.
    #[serde(default)]
    pub proposal_id: Option<String>,
    /// Exact membership ID for the owner-only binding section, including removed incarnations.
    #[serde(default)]
    pub member_id: Option<String>,
    /// Wait up to 25 seconds for forward history after the supplied cursor.
    #[serde(default, skip_serializing_if = "zero_wait")]
    pub wait_seconds: f64,
    /// Read the newest available history page, or older entries before `before`.
    #[serde(default, skip_serializing_if = "false_value")]
    pub reverse: bool,
    /// Exclusive decimal event cursor for a reverse history page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<String>,
    /// Selects an exact long-content field for the content section.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<ContentField>,
    /// Current pool revision, required when continuing a content page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_revision: Option<u64>,
}
/// Preserves the original read wire when no wait was requested.
fn zero_wait(seconds: &f64) -> bool {
    *seconds == 0.0
}
/// Omits the opt-in reverse flag from legacy read requests.
fn false_value(value: &bool) -> bool {
    !value
}
/// Independently paged sections keep complete assignments and evidence retrievable.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Section {
    /// Pool metadata and first roster page.
    #[default]
    Overview,
    /// Five complete assignments per page.
    Members,
    /// Up to three full journal events per page.
    History,
    /// Proposal result, criteria and frozen voters, without ballot evidence.
    Proposal,
    /// Three complete ballots per page.
    Votes,
    /// Up to three immutable structured acceptance criteria per page.
    Criteria,
    /// Bounded UTF-8 pages of a long purpose or proposal snapshot.
    Content,
    /// Twenty safe delivery/admission states per page, with no native bindings.
    Deliveries,
    /// Owner-only exact native/Run mapping selected by member_id, including historical membership.
    Binding,
}
/// Long text selected for independently paged reading.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContentField {
    /// Pool purpose, current at the fenced revision.
    Purpose,
    /// Snapshot of the selected or current proposal.
    Snapshot,
}
/// Owner list pagination uses an exclusive opaque pool ID cursor.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct List {
    /// Last displayed pool ID, absent for the first page.
    #[serde(default)]
    pub after: Option<String>,
}
/// Owner update of a pool's name and purpose.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Update {
    /// Mutation version and replay identity.
    #[serde(flatten)]
    pub change: Change,
    /// Replacement label.
    pub name: String,
    /// Replacement purpose.
    pub purpose: String,
}
/// Invitation of an existing native agent; address is owner-only input.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Add {
    /// Mutation version and replay identity.
    #[serde(flatten)]
    pub change: Change,
    /// Existing canonical Bridge address; validated by the transport before admission.
    pub address: String,
    /// Safe display label, 1–80 UTF-8 bytes.
    pub name: String,
    /// Role, 1–160 UTF-8 bytes.
    pub role: String,
    /// Task, 1–512 UTF-8 bytes.
    pub task: String,
}
/// Start one Run agent with a persisted original specification and onboarding snapshot.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Start {
    /// Mutation version and replay identity.
    #[serde(flatten)]
    pub change: Change,
    /// Safe display label.
    pub name: String,
    /// Assigned role.
    pub role: String,
    /// Assigned task.
    pub task: String,
    /// Run's versioned external specification; validated by Run, never exposed to members.
    pub spec: serde_json::Value,
}
/// One member and its ordinary Run start specification within an atomic admission group.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartMember {
    /// Safe display label.
    pub name: String,
    /// Assigned role.
    pub role: String,
    /// Assigned task.
    pub task: String,
    /// Original Run start specification without a separate request ID.
    pub spec: serde_json::Value,
}
/// Reserves a group for one durable all-or-nothing Run admission.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartBatch {
    /// Mutation version and replay identity.
    #[serde(flatten)]
    pub change: Change,
    /// Ordered new members; all receive one Run batch admission or none do.
    pub members: Vec<StartMember>,
}
/// Requests a durable replacement of one Run-managed membership.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Replace {
    /// Mutation version and replay identity.
    #[serde(flatten)]
    pub change: Change,
    /// Exact current membership to replace after Run confirms its lineage is clean.
    pub member_id: String,
    /// Optional new ordinary Run start; omission reuses the original admission specification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec: Option<serde_json::Value>,
}
/// Cancels a replacement only while no Run admission could have been submitted.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelReplacement {
    /// Mutation version and replay identity.
    #[serde(flatten)]
    pub change: Change,
    /// Exact replacement operation returned by pool_replace.
    pub operation_id: String,
}
/// Owner change of an existing member's safe public assignment.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberUpdate {
    /// Mutation version and replay identity.
    #[serde(flatten)]
    pub change: Change,
    /// Exact current membership incarnation.
    pub member_id: String,
    /// Replacement display label.
    pub name: String,
    /// Replacement role.
    pub role: String,
    /// Replacement task.
    pub task: String,
}
/// Removal by owner, or voluntary removal of the authenticated caller only.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Remove {
    /// Mutation version and replay identity.
    #[serde(flatten)]
    pub change: Change,
    /// Exact current membership incarnation, never a display label.
    pub member_id: String,
}
/// Owner request to release one retained Run history after the pool is closed.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseHistory {
    /// Mutation version and replay identity.
    #[serde(flatten)]
    pub change: Change,
    /// Exact current or historical membership whose Run pin is to be released.
    pub member_id: String,
}
/// Shared-history message with a tool-defined delivery audience.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    /// Mutation version and replay identity.
    #[serde(flatten)]
    pub change: Change,
    /// Plain text, 1–8192 UTF-8 bytes.
    pub body: String,
}
/// Shared-history message delivered only to one current peer.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Direct {
    /// Mutation version and replay identity.
    #[serde(flatten)]
    pub change: Change,
    /// Exact current recipient membership incarnation.
    pub member_id: String,
    /// Plain message text.
    pub body: String,
}
/// Proposal fixes both the desired result and acceptance criteria.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Propose {
    /// Mutation version and replay identity.
    #[serde(flatten)]
    pub change: Change,
    /// Proposed result, 1–2048 bytes.
    pub result: String,
    /// Acceptance criteria, 1–2048 bytes.
    pub criteria: String,
    /// Optional exact result snapshot, at most 65536 UTF-8 bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<String>,
}
/// Vote against one exact proposal and its frozen voting roster.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vote {
    /// Mutation version and replay identity.
    #[serde(flatten)]
    pub change: Change,
    /// Exact proposal ID returned by pool_get.
    pub proposal_id: String,
    /// Exact frozen roster fingerprint returned with the proposal.
    pub roster_key: String,
    /// Ready, blocking, or withdrawal; readiness requires evidence.
    pub choice: Choice,
    /// Evidence or explanation, 1–2048 bytes for ready/block; optional for withdrawal.
    #[serde(default)]
    pub evidence: String,
    /// Per-criterion checks for pools created with structured acceptance.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checks: Vec<CriterionCheck>,
}
/// Result of checking a single acceptance criterion.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// The criterion was verified.
    Met,
    /// The criterion was not met or could not be verified.
    Unmet,
}
/// A member's evidence for one structured criterion.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CriterionCheck {
    /// Identifier of the checked criterion.
    pub criterion_id: String,
    /// Whether this condition was met.
    pub status: CheckStatus,
    /// Supporting evidence, at most 1024 UTF-8 bytes.
    pub evidence: String,
}
/// Recorded voting intent; blocking and withdrawal never imply acceptance.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Choice {
    /// The member confirms all criteria with supporting evidence.
    Ready,
    /// The member records an explicit obstacle.
    Block,
    /// The member withdraws their previous readiness or block.
    Revoke,
}
/// Tool-selected command; identity is deliberately absent from this wire model.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "name", content = "arguments")]
pub enum Command {
    /// Creates an owner-controlled persistent pool.
    #[serde(rename = "pool_create")]
    Create(Create),
    /// Lists the caller's accessible pools only.
    #[serde(rename = "pool_list")]
    List(List),
    /// Reads a safe snapshot and bounded shared history.
    #[serde(rename = "pool_get")]
    Get(Get),
    /// Changes pool metadata.
    #[serde(rename = "pool_update")]
    Update(Update),
    /// Explicitly closes a pool without killing agents or clearing leader status.
    #[serde(rename = "pool_close")]
    Close(Change),
    /// Reserves an existing native agent pending verified join.
    #[serde(rename = "pool_add")]
    Add(Add),
    /// Persists one exact Run start intent.
    #[serde(rename = "pool_start_agent")]
    Start(Start),
    /// Persists one exact all-or-nothing Run batch admission intent.
    #[serde(rename = "pool_start_batch")]
    StartBatch(StartBatch),
    /// Durably requests one guarded Run-member replacement.
    #[serde(rename = "pool_replace")]
    Replace(Replace),
    /// Cancels one provably unsubmitted replacement intent.
    #[serde(rename = "pool_cancel_replacement")]
    CancelReplacement(CancelReplacement),
    /// Updates a current assignment.
    #[serde(rename = "pool_member_update")]
    MemberUpdate(MemberUpdate),
    /// Removes one incarnation without terminating its process.
    #[serde(rename = "pool_remove")]
    Remove(Remove),
    /// Durably requests release of a closed pool member's Run history pin.
    #[serde(rename = "pool_release_history")]
    ReleaseHistory(ReleaseHistory),
    /// Acknowledges the current onboarding snapshot under verified native identity.
    #[serde(rename = "pool_join")]
    Join(Change),
    /// Posts to current members excluding the sender's extra wakeup.
    #[serde(rename = "pool_post")]
    Post(Message),
    /// Delivers to one current member and records shared history.
    #[serde(rename = "pool_send_member")]
    Send(Direct),
    /// Delivers to the external owner without accepting its address.
    #[serde(rename = "pool_notify_owner")]
    Notify(Message),
    /// Opens the single current proposal.
    #[serde(rename = "pool_propose")]
    Propose(Propose),
    /// Records a vote and accepts only unanimous current readiness.
    #[serde(rename = "pool_vote")]
    Vote(Vote),
}
impl Command {
    /// Returns common write preconditions, absent for creation and reads.
    pub fn change(&self) -> Option<&Change> {
        match self {
            Self::Update(x) => Some(&x.change),
            Self::Close(x) | Self::Join(x) => Some(x),
            Self::Add(x) => Some(&x.change),
            Self::Start(x) => Some(&x.change),
            Self::StartBatch(x) => Some(&x.change),
            Self::Replace(x) => Some(&x.change),
            Self::CancelReplacement(x) => Some(&x.change),
            Self::MemberUpdate(x) => Some(&x.change),
            Self::Remove(x) => Some(&x.change),
            Self::ReleaseHistory(x) => Some(&x.change),
            Self::Post(x) | Self::Notify(x) => Some(&x.change),
            Self::Send(x) => Some(&x.change),
            Self::Propose(x) => Some(&x.change),
            Self::Vote(x) => Some(&x.change),
            _ => None,
        }
    }
    /// Validates bounded fields before persistence or any external effect.
    pub fn validate(&self) -> Result<(), Fault> {
        if let Some(c) = self.change() {
            identifier(&c.pool_id)?;
            identifier(&c.request_key)?;
            if c.expected_revision == 0 {
                return Err(Fault::Invalid);
            }
        }
        match self {
            Self::Create(x) => {
                identifier(&x.request_key)?;
                text(&x.name, 80)?;
                text(&x.purpose, 8192)?;
                if let Some(criteria) = &x.acceptance {
                    if criteria.len() > 10 {
                        return Err(Fault::Invalid);
                    }
                    let mut ids = BTreeSet::new();
                    for criterion in criteria {
                        criterion_id(&criterion.id)?;
                        text(&criterion.text, 1024)?;
                        if !ids.insert(&criterion.id) {
                            return Err(Fault::Invalid);
                        }
                    }
                }
                Ok(())
            }
            Self::Update(x) => {
                text(&x.name, 80)?;
                text(&x.purpose, 8192)
            }
            Self::Get(x) => {
                identifier(&x.pool_id)?;
                if !x.wait_seconds.is_finite()
                    || !(0.0..=25.0).contains(&x.wait_seconds)
                    || (x.wait_seconds > 0.0 && x.section != Section::History)
                    || (x.reverse
                        && (x.section != Section::History || x.after != 0 || x.wait_seconds > 0.0))
                    || (x.before.is_some() && !x.reverse)
                {
                    return Err(Fault::Invalid);
                }
                if let Some(before) = &x.before {
                    let value = before.parse::<i64>().map_err(|_| Fault::Invalid)?;
                    if value <= 0 || value.to_string() != *before {
                        return Err(Fault::Invalid);
                    }
                }
                if x.proposal_id.is_some()
                    && !matches!(
                        x.section,
                        Section::Proposal | Section::Votes | Section::Content
                    )
                {
                    return Err(Fault::Invalid);
                }
                if (x.section == Section::Content) != x.field.is_some()
                    || (x.section == Section::Content
                        && x.after > 0
                        && x.expected_revision.is_none())
                    || (x.field == Some(ContentField::Purpose) && x.proposal_id.is_some())
                    || x.expected_revision == Some(0)
                {
                    return Err(Fault::Invalid);
                }
                x.proposal_id.as_deref().map_or(Ok(()), identifier)?;
                if x.member_id.is_some() != matches!(x.section, Section::Binding)
                    || (matches!(x.section, Section::Binding) && x.after != 0)
                {
                    return Err(Fault::Invalid);
                }
                x.member_id.as_deref().map_or(Ok(()), identifier)
            }
            Self::List(x) => x.after.as_deref().map_or(Ok(()), identifier),
            Self::Add(x) => {
                text(&x.address, 1024)?;
                assignment(&x.name, &x.role, &x.task)
            }
            Self::Start(x) => validate_start(&x.name, &x.role, &x.task, &x.spec),
            Self::StartBatch(x) => {
                if x.members.is_empty() || x.members.len() > MAX_MEMBERS {
                    return Err(Fault::Invalid);
                }
                for member in &x.members {
                    validate_start(&member.name, &member.role, &member.task, &member.spec)?;
                }
                Ok(())
            }
            Self::Replace(x) => {
                identifier(&x.member_id)?;
                if let Some(spec) = &x.spec {
                    validate_start("replacement", "replacement", "replacement", spec)?;
                }
                Ok(())
            }
            Self::CancelReplacement(x) => identifier(&x.operation_id),
            Self::MemberUpdate(x) => {
                identifier(&x.member_id)?;
                assignment(&x.name, &x.role, &x.task)
            }
            Self::Remove(x) => identifier(&x.member_id),
            Self::ReleaseHistory(x) => identifier(&x.member_id),
            Self::Post(x) | Self::Notify(x) => text(&x.body, MAX_MESSAGE),
            Self::Send(x) => {
                identifier(&x.member_id)?;
                text(&x.body, MAX_MESSAGE)
            }
            Self::Propose(x) => {
                text(&x.result, MAX_TEXT)?;
                text(&x.criteria, MAX_TEXT)?;
                if let Some(snapshot) = &x.snapshot {
                    text(snapshot, 65536)?;
                }
                Ok(())
            }
            Self::Vote(x) => {
                identifier(&x.proposal_id)?;
                identifier(&x.roster_key)?;
                if !x.evidence.is_empty() {
                    text(&x.evidence, MAX_TEXT)?;
                }
                if x.checks.len() > 10
                    || (x.choice == Choice::Revoke && !x.checks.is_empty())
                    || serde_json::to_vec(&x.checks)
                        .map_err(|_| Fault::Invalid)?
                        .len()
                        > 16384
                {
                    return Err(Fault::Invalid);
                }
                let mut ids = BTreeSet::new();
                for check in &x.checks {
                    criterion_id(&check.criterion_id)?;
                    text(&check.evidence, 1024)?;
                    if !ids.insert(&check.criterion_id) {
                        return Err(Fault::Invalid);
                    }
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
    /// Hashes normalized typed intent; expected pool revision is a first-execution fence only.
    /// Proposal and roster IDs remain in the digest, preventing a retry against new voters.
    pub fn digest(&self) -> Result<String, Fault> {
        let mut v = serde_json::to_value(self).map_err(|_| Fault::Internal)?;
        if let Some(a) = v
            .get_mut("arguments")
            .and_then(serde_json::Value::as_object_mut)
        {
            a.remove("expected_revision");
        }
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&v).map_err(|_| Fault::Internal)?)
        ))
    }
}
/// Requires a nonempty bounded plain-text value without terminal control characters.
pub fn text(s: &str, max: usize) -> Result<(), Fault> {
    if s.trim().is_empty()
        || s.len() > max
        || s.chars().any(|c| {
            (c.is_control() && c != '\n' && c != '\t')
                || matches!(c,'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}')
        })
    {
        Err(Fault::Invalid)
    } else {
        Ok(())
    }
}
/// Requires an opaque ASCII identifier without path, whitespace or wildcard syntax.
pub fn identifier(s: &str) -> Result<(), Fault> {
    if s.is_empty()
        || s.len() > 128
        || !s
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.:".contains(&c))
    {
        Err(Fault::Invalid)
    } else {
        Ok(())
    }
}
/// Validates a criterion identifier without accepting colon or a long opaque ID.
pub fn criterion_id(s: &str) -> Result<(), Fault> {
    if s.is_empty()
        || s.len() > 32
        || !s
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
    {
        Err(Fault::Invalid)
    } else {
        Ok(())
    }
}
/// Validates the opaque versioned Run execution reference without treating it as a credential.
pub fn execution_ref(value: &str) -> Result<(), Fault> {
    let Some(hash) = value.strip_prefix("ex1_") else {
        return Err(Fault::Invalid);
    };
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Fault::Invalid);
    }
    Ok(())
}
/// Validates Run's canonical permanent history-pin identity.
pub fn pin_id(value: &str) -> Result<(), Fault> {
    let raw = value.strip_prefix("pin_").ok_or(Fault::Invalid)?;
    let id = uuid::Uuid::parse_str(raw).map_err(|_| Fault::Invalid)?;
    if raw.len() != 32
        || id.simple().to_string() != raw
        || id.get_version_num() != 4
        || id.get_variant() != uuid::Variant::RFC4122
    {
        return Err(Fault::Invalid);
    }
    Ok(())
}
/// Validates the durable Run database identity without treating it as a credential.
pub fn store_id(value: &str) -> Result<(), Fault> {
    let raw = value.strip_prefix("store_").ok_or(Fault::Invalid)?;
    if raw.len() != 32
        || !raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Fault::Invalid);
    }
    Ok(())
}
/// Validates the three bounded public assignment fields together.
pub fn assignment(name: &str, role: &str, task: &str) -> Result<(), Fault> {
    text(name, 80)?;
    text(role, 160)?;
    text(task, 512)
}
/// Applies the same local bounds to each individual or grouped Run start.
fn validate_start(
    name: &str,
    role: &str,
    task: &str,
    spec: &serde_json::Value,
) -> Result<(), Fault> {
    assignment(name, role, task)?;
    if !spec.is_object()
        || spec.get("orchestrator").is_some()
        || spec.get("request_id").is_some()
        || serde_json::to_vec(spec).map_err(|_| Fault::Invalid)?.len() > 65536
    {
        Err(Fault::Invalid)
    } else {
        Ok(())
    }
}
/// Creates a fresh opaque ID; never reused for readmission or proposal replacement.
pub fn id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Membership state; removed incarnations appear only in the owner's historical binding view.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MemberState {
    /// Awaiting explicit verified onboarding acknowledgment.
    Pending,
    /// Confirmed member eligible to act and vote.
    Active,
    /// Archived incarnation with no pool access, regardless of its last observed process state.
    Removed,
}
/// Transport-free member projection used in every participant response and event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// Opaque membership incarnation, not a native or Run identifier.
    pub member_id: String,
    /// Display name selected by the owner.
    pub name: String,
    /// Current assignment role.
    pub role: String,
    /// Current assigned task.
    pub task: String,
    /// Pending or confirmed status.
    pub state: MemberState,
    /// Observed execution state; unknown is never treated as completion.
    pub runtime: String,
}
/// Proposal lifecycle; accepted proposals are immutable and independent of pool lifetime.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProposalState {
    /// Still accepting votes for the frozen roster.
    Open,
    /// Every frozen voter supplied readiness evidence.
    Accepted,
    /// Membership, assignment or pool closure invalidated the open proposal.
    Stale,
}
/// One member's durable vote, including block or revocation evidence.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ballot {
    /// Recorded vote choice.
    pub choice: Choice,
    /// Evidence associated with this choice.
    pub evidence: String,
    /// For structured ready votes, whether every criterion was met.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checks_met: Option<bool>,
    /// Exact event cursor anchoring this structured vote's immediately following checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vote_event_id: Option<String>,
    /// Number of check records associated with the structured vote.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checks_count: Option<usize>,
    /// Unknown when a stored Run-managed vote lacks current author proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validity: Option<VoteValidity>,
}
/// A stored vote whose author cannot currently be proven must not count toward a new consensus.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VoteValidity {
    /// The prior Run execution or author has not been verified.
    Unknown,
}
/// Safe proposal view, including its immutable voting roster and latest ballots.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proposal {
    /// Fresh opaque proposal identifier.
    pub proposal_id: String,
    /// Fingerprint of membership IDs, roles and tasks frozen at proposal creation.
    pub roster_key: String,
    /// Exact current confirmed membership IDs entitled to vote.
    pub voters: Vec<String>,
    /// Result proposed for acceptance.
    pub result: String,
    /// Criteria against which readiness is asserted.
    pub criteria: String,
    /// Full snapshot retained internally; public views retrieve it through content pages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<String>,
    /// Exact snapshot size when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_bytes: Option<usize>,
    /// Open, accepted or stale status.
    pub state: ProposalState,
    /// Latest choice for each voter; all changes remain in shared event history.
    pub votes: BTreeMap<String, Ballot>,
}
/// Bounded current pool metadata; roster and history are independently stored.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pool {
    /// Opaque pool identifier.
    pub pool_id: String,
    /// Public label.
    pub name: String,
    /// Public purpose.
    pub purpose: String,
    /// Full UTF-8 byte length when the public purpose is a shortened preview.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose_bytes: Option<usize>,
    /// Structured acceptance, if selected at creation; paged separately in public views.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acceptance: Option<Vec<Criterion>>,
    /// Monotonic pool-command revision; background private binding updates may leave it unchanged.
    pub revision: u64,
    /// Explicit closure flag, never inferred from completion or votes.
    pub closed: bool,
    /// Latest proposal; superseded proposals remain in the event journal.
    pub proposal: Option<Proposal>,
}
/// Safe identity in shared history, deliberately excluding native addresses.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "member_id", rename_all = "snake_case")]
pub enum Author {
    /// External pool owner, never a member.
    Leader,
    /// Confirmed member incarnation.
    Member(String),
    /// Service-authored membership or execution event.
    Service,
}
/// Append-only safe journal entry; audience controls delivery, not history visibility.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    /// Global monotonic event cursor, stable across restart.
    pub event_id: u64,
    /// Exact decimal identity on opt-in observer history pages; omitted elsewhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id_exact: Option<String>,
    /// Pool revision after this event's transaction.
    pub revision: u64,
    /// Closed service-defined event label.
    pub kind: String,
    /// Safe author role or member ID.
    pub author: Author,
    /// Safe message or change text; never includes private transport metadata.
    pub body: String,
    /// Optional exact member target; owner targets are represented by event kind.
    pub recipient: Option<String>,
    /// Structured check carried by this journal event, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<Box<CriterionCheck>>,
    /// Exact event ID of the vote that owns this check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vote_event_id: Option<String>,
    /// Exact first event ID of a multi-part message, omitted for ordinary events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_event_id: Option<String>,
    /// One-based position in the multi-part message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub part_index: Option<usize>,
    /// Total number of parts required to reconstruct the exact message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub part_count: Option<usize>,
}
/// Participant-safe snapshot and bounded history page.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct View {
    /// Section displayed; continuation reuses this section.
    pub section: Section,
    /// Pool metadata and latest proposal.
    pub pool: Pool,
    /// Current pending and confirmed members only.
    pub members: Vec<Member>,
    /// Explicit confirmed count; leader excluded.
    pub active: usize,
    /// Explicit pending count; leader excluded.
    pub pending: usize,
    /// At most three events and a bounded total text budget.
    pub events: Vec<Event>,
    /// Bounded safe outbox status rows, populated only for the deliveries section.
    pub deliveries: Vec<Delivery>,
    /// Exclusive cursor after the last displayed event, or input cursor for an empty page.
    pub next_after: u64,
    /// Whether later events remain available.
    pub has_more: bool,
    /// Exclusive exact cursor for the next older reverse-history page, when selected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_before: Option<String>,
    /// Exact byte-offset page for the selected long-content field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<ContentPage>,
}
/// One UTF-8-safe contiguous slice of an independently paged long text.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContentPage {
    /// Selected purpose or proposal snapshot.
    pub field: ContentField,
    /// Inclusive starting byte offset.
    pub offset: usize,
    /// Full text length in UTF-8 bytes.
    pub total_bytes: usize,
    /// Exact contiguous text at this offset; concatenation reconstructs the original.
    pub text: String,
}
/// Safe durable operation status; custody is distinct from native handoff and comprehension.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Delivery {
    /// Service-local opaque operation ID, never a Bridge address or Run agent ID.
    pub operation_id: String,
    /// Exact member incarnation, absent for owner/service effects.
    pub member_id: Option<String>,
    /// Closed operation category: deliver, retire, start, start_batch, replace or release_pin.
    pub operation: String,
    /// Durable state including awaiting_binding, custody and unknown.
    pub state: String,
    /// Owner-only bounded managed-egress attention, absent when not applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attention: Option<String>,
    /// Whether a relaunch applies to the removed/current member or the Pool resident.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attention_subject: Option<String>,
}
/// Mutation receipt remains safe for all participants and exact retries.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Receipt {
    /// Pool affected by the successful durable transaction.
    pub pool_id: String,
    /// Resulting pool revision.
    pub revision: u64,
    /// Created member, proposal or batch operation identifier when applicable.
    pub created_id: Option<String>,
    /// Ordered member IDs for a grouped admission, omitted for ordinary mutations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub created_ids: Vec<String>,
    /// Recorded safe event, returned to the sender without a duplicate wakeup.
    pub event: Event,
    /// Transport-independent status: committed, external deliveries remain asynchronous.
    pub status: String,
}
/// Closed public reply shape; private transport state cannot be serialized through it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Reply {
    /// Safe bounded history and current snapshot.
    View(Box<View>),
    /// Owner-only mappings for the displayed roster page.
    OwnerView {
        /// Same bounded public view.
        view: Box<View>,
        /// Private records are returned only after owner authorization.
        bindings: Vec<Binding>,
    },
    /// Accessible pool metadata, ten rows per page.
    List {
        /// Safe metadata with proposals omitted.
        pools: Vec<Pool>,
        /// Exclusive cursor of the last displayed pool.
        next_after: Option<String>,
        /// Whether more accessible pools remain.
        has_more: bool,
    },
    /// An authenticated identical domain request is still being reconciled.
    Pending {
        /// Exact pool selected by the original mutation.
        pool_id: String,
        /// Original domain replay key; retry only this key with fresh proof.
        request_key: String,
    },
    /// Durable mutation acknowledgment.
    Receipt(Box<Receipt>),
}

/// Private membership record stored separately from its public projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    /// Safe projection.
    pub member: Member,
    /// Owning pool.
    pub pool_id: String,
    /// Native actor digest, bound only by a current join assertion.
    pub actor: Option<String>,
    /// Canonical native delivery destination, absent until Run resolves it.
    pub address: Option<String>,
    /// Run agent admission identity, never a public field.
    pub run_id: Option<String>,
    /// Run sequence associated with the persisted admission.
    pub run_sequence: Option<u64>,
    /// Immutable Run execution reference from admission; not an authorization or live proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_execution_ref: Option<String>,
    /// Run's durable retention pin ID; it does not itself prove current pin state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_pin_id: Option<String>,
    /// Original Run database identity, when atomically bound to the admission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_store_id: Option<String>,
}
/// Immutable work submitted by the single durable outbox worker.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Work {
    /// Deliver exact safe text to a private destination using one stable Bridge event ID.
    Deliver {
        /// Canonical destination.
        address: String,
        /// Stable membership scope, or independent service notice scope.
        scope: String,
        /// Frozen payload text.
        text: String,
    },
    /// Retire a membership scope, cancelling only Bridge work not yet handed off.
    Retire {
        /// Exact scope originally used for this membership.
        scope: String,
    },
    /// Submit an exact original Run request; request key and onboarding are frozen before I/O.
    Start {
        /// Original Run specification enriched with onboarding and MCP requirements.
        spec: serde_json::Value,
        /// Stable global Run idempotency key.
        request_key: String,
        /// True when this intent was created with a mandatory pre-I/O route fence.
        #[serde(default, skip_serializing_if = "false_value")]
        route_fence: bool,
        /// Frozen Run endpoint and peer identity, captured before the first possible request.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        route: Option<RunRoute>,
    },
    /// One frozen all-or-nothing Run admission with its ordered membership mapping.
    StartBatch {
        /// Stable Run-wide replay identity.
        request_key: String,
        /// Whether history retention was part of the original frozen Run intent.
        #[serde(default, skip_serializing_if = "false_value")]
        retain_history: bool,
        /// True when this intent requires Run's atomic expected-store fence.
        #[serde(default, skip_serializing_if = "false_value")]
        store_fence: bool,
        /// True when this intent was created with a mandatory pre-I/O route fence.
        #[serde(default, skip_serializing_if = "false_value")]
        route_fence: bool,
        /// Frozen Run endpoint and peer identity, captured before the first possible request.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        route: Option<RunRoute>,
        /// Exact ordered specifications and locally reserved members.
        jobs: Vec<BatchJob>,
    },
    /// One recoverable replacement; the original membership stays current until the Run receipt commits.
    Replace {
        /// Stable Run-wide admission and receipt-lookup key.
        request_key: String,
        /// Exact old membership against which the request was frozen.
        old: Box<Binding>,
        /// New pending membership, not installed in the roster until admission is known.
        new: Box<Binding>,
        /// Frozen start specification for the replacement.
        job: BatchJob,
        /// Original Run endpoint, peer and durable store identity.
        route: RunRoute,
        /// Exact latest execution prerequisite, persisted before any Run admission call.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        condition: Option<crate::run_status::Target>,
        /// Whether an admission may already have been submitted.
        #[serde(default, skip_serializing_if = "false_value")]
        submitted: bool,
        /// Current Pool worker claim; stale claims are replaced only after crash recovery.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        claim: Option<String>,
        /// Whether this claim's single send is the first possible admission.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        send_first: Option<bool>,
    },
    /// Resolve the native address of a Run agent whose batch admission is already recorded.
    ResolveRun,
    /// Release one exact durable Run pin after explicit owner intent.
    ReleasePin {
        /// Original canonical pin identity, also its idempotency key.
        pin_id: String,
        /// Original fenced admission route; absent legacy intents remain on hold.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        route: Option<RunRoute>,
    },
}
/// Run endpoint configuration frozen before one durable external admission.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunRoute {
    /// Absolute Run socket path selected by the operator.
    pub socket: String,
    /// Pool's local UID, checked on every connection.
    pub expected_uid: u32,
    /// Optional explicit trusted Run peer UID.
    pub peer_uid: Option<u32>,
    /// Run database identity recorded after read-only preflight and before admission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_id: Option<String>,
}
/// One private frozen Run batch specification and its local membership incarnation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchJob {
    /// Locally reserved membership, never supplied to Run.
    pub member_id: String,
    /// Frozen ordinary Run start specification.
    pub spec: serde_json::Value,
    /// Original caller specification before onboarding, retained privately for safe replacement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_spec: Option<serde_json::Value>,
}
/// One durable private outbox effect; status remains uncertain until transport reconciliation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Effect {
    /// Stable opaque ID also used as provider operation/event identity.
    pub effect_id: String,
    /// Owning pool.
    pub pool_id: String,
    /// Exact membership incarnation when applicable.
    pub member_id: Option<String>,
    /// Frozen external work; never included in public views.
    pub work: Work,
    /// queued, inflight, unknown, accepted, refused, or cancelled.
    pub state: String,
}
impl Effect {
    /// Distinguishes a pinned single-member admission from a grouped batch and rejects malformed markers.
    pub fn is_single_batch(&self) -> Result<bool, Fault> {
        match (&self.work, &self.member_id) {
            (
                Work::StartBatch {
                    jobs,
                    retain_history: true,
                    store_fence: true,
                    route_fence: true,
                    ..
                },
                Some(member),
            ) if jobs.len() == 1 && jobs[0].member_id == *member => Ok(true),
            (Work::StartBatch { .. }, Some(_)) => Err(Fault::Internal),
            _ => Ok(false),
        }
    }
}
