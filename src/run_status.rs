//! Draft Run status receipt validation; these historical facts are not authorization.

use serde::{Deserialize, Deserializer, Serialize, de::IgnoredAny};
use std::collections::HashMap;

/// An exact Run execution and the permanent pin supplied with the request.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    /// Stable lineage ID or retained execution alias.
    pub agent_id: String,
    /// Positive execution sequence.
    pub sequence: u32,
    /// Versioned execution incarnation, required by Pool.
    pub execution_ref: String,
    /// Permanent lineage pin, required by Pool.
    pub pin_id: String,
}

/// Rejection of an invalid request, malformed JSON, or inconsistent response.
#[derive(Debug)]
pub(crate) enum StatusError {
    /// Pool's expected store or selectors were invalid or duplicated.
    InvalidRequest,
    /// JSON did not match the draft's required types and fields.
    #[cfg(test)]
    Malformed(serde_json::Error),
    /// The response was oversized, mismatched, or contradicted itself.
    InvalidResponse,
}
impl std::fmt::Display for StatusError {
    /// Reports a fixed class without exposing provider data.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidRequest => "invalid status request",
            #[cfg(test)]
            Self::Malformed(_) => "malformed status response",
            Self::InvalidResponse => "invalid status response",
        };
        formatter.write_str(message)
    }
}
impl std::error::Error for StatusError {
    /// Preserves the decoder cause without placing it in the public message.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            #[cfg(test)]
            Self::Malformed(error) => Some(error),
            _ => None,
        }
    }
}

/// Exact Run selector verification state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Match {
    Verified,
    Unverified,
    Missing,
    Mismatch,
    Unknown,
}

/// Relationship of the requested pin to the observed lineage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PinState {
    Active,
    Released,
    Missing,
    Mismatch,
    Unknown,
}

/// Completeness of the retained lineage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Coverage {
    Complete,
    Unknown,
}

/// Pending technical continuation after restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RestartResume {
    None,
    Pending,
    Unknown,
}

/// Raw execution status; only terminal variants can be a lineage outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawStatus {
    Created,
    Starting,
    Running,
    Cancelling,
    Succeeded,
    Failed,
    TimedOut,
    Cancelled,
    Lost,
}

impl RawStatus {
    /// Whether this status is terminal in the Run draft.
    fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::TimedOut | Self::Cancelled | Self::Lost
        )
    }
}

/// Historical successful-commit evidence for the retained latest execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SuccessCommit {
    Recorded,
    Unknown,
    NotSucceeded,
}

/// Lineage-wide cleanup verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CleanupState {
    Confirmed,
    Pending,
    Unknown,
}

/// A required nullable field must appear even when its value is null.
fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// Stored fact for a single retained execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionFact {
    sequence: u32,
    #[serde(deserialize_with = "required_nullable")]
    execution_ref: Option<String>,
    raw_status: RawStatus,
}

/// Cleanup is scoped to the lineage, not an individual process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cleanup {
    scope: String,
    state: CleanupState,
}

/// Unvalidated wire item, kept private until its entire snapshot is checked.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusItem {
    #[serde(deserialize_with = "crate::integrations::json_object")]
    selector: Target,
    #[serde(deserialize_with = "required_nullable")]
    canonical_agent_id: Option<String>,
    r#match: Match,
    pin_id: String,
    pin_state: PinState,
    #[serde(deserialize_with = "crate::integrations::nullable_object")]
    selected: Option<ExecutionFact>,
    #[serde(deserialize_with = "crate::integrations::nullable_object")]
    retained_latest: Option<ExecutionFact>,
    coverage: Coverage,
    restart_resume: RestartResume,
    #[serde(deserialize_with = "required_nullable")]
    lineage_terminal: Option<bool>,
    #[serde(deserialize_with = "required_nullable")]
    terminal_outcome: Option<RawStatus>,
    success_commit: SuccessCommit,
    #[serde(deserialize_with = "crate::integrations::json_object")]
    cleanup: Cleanup,
}

impl StatusItem {
    /// Proves the requested execution is the successful terminal lineage tail.
    /// This is a historical database fact, not artifact availability or authorization.
    fn proves_historical_success(&self) -> bool {
        self.r#match == Match::Verified
            && self.pin_id == self.selector.pin_id
            && self.pin_state == PinState::Active
            && self.coverage == Coverage::Complete
            && self.restart_resume == RestartResume::None
            && self.lineage_terminal == Some(true)
            && self.terminal_outcome == Some(RawStatus::Succeeded)
            && self.success_commit == SuccessCommit::Recorded
            && self.cleanup.scope == "lineage"
            && self.cleanup.state == CleanupState::Confirmed
            && self.selected.as_ref().is_some_and(|selected| {
                selected.sequence == self.selector.sequence
                    && selected.execution_ref.as_deref() == Some(&self.selector.execution_ref)
                    && self.retained_latest.as_ref() == Some(selected)
            })
    }
}

/// Wire snapshot; deserialization alone does not validate its facts.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StatusResponse {
    version: u32,
    store_id: String,
    observed_at: Box<serde_json::value::RawValue>,
    #[serde(deserialize_with = "crate::integrations::json_objects")]
    items: Vec<StatusItem>,
    // The optional view has a separate contract and never contributes to proof.
    #[serde(default, rename = "view")]
    _view: Option<IgnoredAny>,
}

/// One bounded snapshot returned only after validation of every item.
#[derive(Debug)]
pub(crate) struct StatusEvidence(StatusResponse);

/// An owner-only historical status snapshot, never an authorization or current process guarantee.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofProjection {
    /// Fully validated Run status fields for the exact requested member.
    #[serde(deserialize_with = "crate::integrations::json_object")]
    pub status: StatusItem,
    /// True only when the selected latest execution meets the documented historical completion proof.
    pub historical_success: bool,
    /// Terminal outcome and successful commit describe this retained execution, not the selected view.
    pub outcome_scope: ProofOutcomeScope,
}
/// Scope of the terminal outcome and successful-commit evidence.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofOutcomeScope {
    /// The retained latest execution in this Run snapshot.
    RetainedLatest,
}
impl ProofProjection {
    /// Exact validated selector of this projection.
    pub(crate) fn selector(&self) -> &Target {
        &self.status.selector
    }

    /// Rejects contradictory proof fields when the owner frontend decodes a resident response.
    pub(crate) fn valid(&self) -> bool {
        valid_target(&self.status.selector)
            && valid_item(&self.status)
            && self.historical_success == self.status.proves_historical_success()
    }
}

/// Read-only access to an item in a validated snapshot.
pub(crate) struct ItemEvidence<'a>(&'a StatusItem);

impl<'a> ItemEvidence<'a> {
    /// Returns the original validated request selector.
    #[cfg(test)]
    pub(crate) fn selector(&self) -> &'a Target {
        &self.0.selector
    }

    /// Reports historical success only for the exact fully verified lineage tail.
    /// Does not establish file availability, identity, or authorization.
    pub(crate) fn proves_historical_success(&self) -> bool {
        self.0.proves_historical_success()
    }

    /// Copies only validated status facts, with their explicit historical scope.
    pub(crate) fn projection(&self) -> ProofProjection {
        ProofProjection {
            status: self.0.clone(),
            historical_success: self.proves_historical_success(),
            outcome_scope: ProofOutcomeScope::RetainedLatest,
        }
    }

    /// Selects a proven terminal lineage tip for a later atomic Run precondition.
    /// This snapshot cannot prevent a subsequent resume; Run must check it at admission.
    pub(crate) fn replacement_precondition(&self) -> Option<Target> {
        let item = self.0;
        if item.r#match != Match::Verified
            || item.pin_state != PinState::Active
            || item.coverage != Coverage::Complete
            || item.restart_resume != RestartResume::None
            || item.lineage_terminal != Some(true)
            || item.cleanup.state != CleanupState::Confirmed
        {
            return None;
        }
        let latest = item.retained_latest.as_ref()?;
        Some(Target {
            agent_id: item.canonical_agent_id.clone()?,
            sequence: latest.sequence,
            execution_ref: latest.execution_ref.clone()?,
            pin_id: item.selector.pin_id.clone(),
        })
    }

    /// Identifies a proven currently unmet prerequisite without treating missing evidence as refusal.
    pub(crate) fn replacement_not_ready(&self) -> bool {
        let item = self.0;
        item.r#match == Match::Mismatch
            || matches!(item.pin_state, PinState::Released | PinState::Mismatch)
            || item.restart_resume == RestartResume::Pending
            || item.lineage_terminal == Some(false)
            || item.cleanup.state == CleanupState::Pending
    }
}

impl StatusEvidence {
    /// Returns the fenced store identity.
    pub(crate) fn store_id(&self) -> &str {
        &self.0.store_id
    }

    /// Returns the producer's nonnegative Unix timestamp, not a freshness guarantee.
    pub(crate) fn observed_at(&self) -> f64 {
        self.0.observed_at.get().parse().unwrap_or(f64::NAN)
    }

    /// Returns the exact numeric text received from Run.
    pub(crate) fn observed_at_text(&self) -> &str {
        self.0.observed_at.get()
    }

    /// Returns the validated items in the original target order.
    pub(crate) fn items(&self) -> impl ExactSizeIterator<Item = ItemEvidence<'_>> {
        self.0.items.iter().map(ItemEvidence)
    }
}

/// Matches Run's exact timestamped agent-ID grammar, including its calendar parsing.
pub(crate) fn valid_agent_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    bytes.len() == 29
        && id.is_ascii()
        && &bytes[..3] == b"ag-"
        && bytes[18] == b'-'
        && bytes[19..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        && chrono::NaiveDateTime::parse_from_str(&id[3..18], "%Y%m%d-%H%M%S").is_ok()
}

/// Validates exact identities in the expected request before inspecting evidence.
fn valid_target(target: &Target) -> bool {
    valid_agent_id(&target.agent_id)
        && target.sequence > 0
        && crate::domain::execution_ref(&target.execution_ref).is_ok()
        && crate::domain::pin_id(&target.pin_id).is_ok()
}

/// Validates an optional retained execution without accepting a malformed incarnation.
fn valid_fact(fact: &ExecutionFact) -> bool {
    fact.sequence > 0
        && fact
            .execution_ref
            .as_deref()
            .is_none_or(|reference| crate::domain::execution_ref(reference).is_ok())
}

/// Rejects internally inconsistent claims without upgrading unknown states to proof.
fn valid_item(item: &StatusItem) -> bool {
    if item.pin_id != item.selector.pin_id
        || item.cleanup.scope != "lineage"
        || item
            .canonical_agent_id
            .as_deref()
            .is_some_and(|id| !valid_agent_id(id))
        || item.selected.as_ref().is_some_and(|fact| !valid_fact(fact))
        || item
            .retained_latest
            .as_ref()
            .is_some_and(|fact| !valid_fact(fact))
    {
        return false;
    }
    let selected = item.selected.as_ref();
    let latest = item.retained_latest.as_ref();
    if selected.is_some_and(|fact| fact.sequence != item.selector.sequence)
        || (selected.is_some() || latest.is_some()) && item.canonical_agent_id.is_none()
        || item.pin_state != PinState::Unknown && item.canonical_agent_id.is_none()
    {
        return false;
    }
    match item.r#match {
        Match::Verified => {
            if item.canonical_agent_id.is_none()
                || !selected.is_some_and(|fact| {
                    fact.execution_ref.as_deref() == Some(&item.selector.execution_ref)
                })
            {
                return false;
            }
        }
        // Pool always supplies an incarnation, so an unverified selector is contradictory.
        Match::Unverified => return false,
        Match::Missing | Match::Mismatch if selected.is_some() => return false,
        Match::Unknown if selected.is_some_and(|fact| fact.execution_ref.is_some()) => {
            return false;
        }
        _ => {}
    }
    if item.r#match != Match::Verified
        && (latest.is_some()
            || item.coverage != Coverage::Unknown
            || item.restart_resume != RestartResume::Unknown
            || item.cleanup.state != CleanupState::Unknown)
    {
        return false;
    }
    if let (Some(selected), Some(latest)) = (selected, latest)
        && (latest.sequence < selected.sequence
            || (latest.sequence == selected.sequence && latest != selected)
            || (latest.sequence != selected.sequence
                && latest.execution_ref.is_some()
                && latest.execution_ref == selected.execution_ref))
    {
        return false;
    }
    if item.coverage == Coverage::Complete
        && (item.r#match != Match::Verified
            || item.pin_state != PinState::Active
            || !latest.is_some_and(|fact| fact.execution_ref.is_some())
            || matches!((selected, latest), (Some(selected), Some(latest))
                if selected.sequence < latest.sequence && !selected.raw_status.is_terminal()))
    {
        return false;
    }
    if item.restart_resume == RestartResume::None && item.coverage != Coverage::Complete {
        return false;
    }
    match item.lineage_terminal {
        Some(true) => {
            if item.coverage != Coverage::Complete
                || item.restart_resume != RestartResume::None
                || !latest.is_some_and(|fact| {
                    fact.raw_status.is_terminal() && item.terminal_outcome == Some(fact.raw_status)
                })
            {
                return false;
            }
        }
        Some(false) => {
            if item.terminal_outcome.is_some()
                || item.success_commit != SuccessCommit::Unknown
                || !latest.is_some_and(|fact| {
                    item.restart_resume == RestartResume::Pending
                        || (item.coverage == Coverage::Complete
                            && item.restart_resume == RestartResume::None
                            && !fact.raw_status.is_terminal())
                })
            {
                return false;
            }
        }
        None => {
            if item.terminal_outcome.is_some()
                || item.success_commit != SuccessCommit::Unknown
                || (latest.is_some()
                    && (item.restart_resume == RestartResume::Pending
                        || (item.coverage == Coverage::Complete
                            && item.restart_resume == RestartResume::None)))
            {
                return false;
            }
        }
    }
    if (item.success_commit == SuccessCommit::Recorded
        && item.terminal_outcome != Some(RawStatus::Succeeded))
        || (item.success_commit == SuccessCommit::NotSucceeded
            && !item
                .terminal_outcome
                .is_some_and(|status| status != RawStatus::Succeeded))
        || (item.cleanup.state != CleanupState::Unknown && item.coverage != Coverage::Complete)
        || (item.cleanup.state == CleanupState::Confirmed && item.lineage_terminal != Some(true))
        || (item.cleanup.state == CleanupState::Pending && item.lineage_terminal.is_none())
    {
        return false;
    }
    true
}

/// Ensures multiple selectors cannot give incompatible facts for one snapshot.
fn consistent_items(items: &[StatusItem]) -> bool {
    let mut refs = HashMap::new();
    let mut selector_roots = HashMap::new();
    for item in items {
        if let Some(root) = &item.canonical_agent_id
            && selector_roots
                .insert(&item.selector.agent_id, root)
                .is_some_and(|old| old != root)
        {
            return false;
        }
        for fact in [item.selected.as_ref(), item.retained_latest.as_ref()]
            .into_iter()
            .flatten()
        {
            if let (Some(reference), Some(root)) = (&fact.execution_ref, &item.canonical_agent_id)
                && refs
                    .insert(reference, (root, fact.sequence))
                    .is_some_and(|old| old != (root, fact.sequence))
            {
                return false;
            }
        }
    }
    for (index, left) in items.iter().enumerate() {
        for right in &items[index + 1..] {
            let same_pin = left.pin_id == right.pin_id;
            if same_pin {
                let left_owner = matches!(left.pin_state, PinState::Active | PinState::Released);
                let right_owner = matches!(right.pin_state, PinState::Active | PinState::Released);
                if (left_owner
                    && right_owner
                    && left.canonical_agent_id != right.canonical_agent_id)
                    || (left.pin_state == PinState::Missing
                        && !matches!(right.pin_state, PinState::Missing | PinState::Unknown))
                    || (right.pin_state == PinState::Missing
                        && !matches!(left.pin_state, PinState::Missing | PinState::Unknown))
                {
                    return false;
                }
            }
            if left.canonical_agent_id.is_none()
                || left.canonical_agent_id != right.canonical_agent_id
            {
                continue;
            }
            if left.selector.sequence == right.selector.sequence {
                return false;
            }
            if same_pin
                && left.pin_state != PinState::Unknown
                && right.pin_state != PinState::Unknown
                && left.pin_state != right.pin_state
            {
                return false;
            }
            if let (Some(a), Some(b)) = (&left.retained_latest, &right.retained_latest)
                && a != b
            {
                return false;
            }
            for (selected, latest) in [
                (&left.selected, &right.retained_latest),
                (&right.selected, &left.retained_latest),
            ] {
                if matches!((selected, latest), (Some(selected), Some(latest)) if selected.sequence > latest.sequence)
                {
                    return false;
                }
            }
            for a in [left.selected.as_ref(), left.retained_latest.as_ref()]
                .into_iter()
                .flatten()
            {
                for b in [right.selected.as_ref(), right.retained_latest.as_ref()]
                    .into_iter()
                    .flatten()
                {
                    if a.sequence == b.sequence && a != b {
                        return false;
                    }
                }
            }
            if (left.restart_resume != RestartResume::Unknown
                && right.restart_resume != RestartResume::Unknown
                && left.restart_resume != right.restart_resume)
                || matches!((left.lineage_terminal, right.lineage_terminal), (Some(a), Some(b)) if a != b)
                || matches!((left.terminal_outcome, right.terminal_outcome), (Some(a), Some(b)) if a != b)
                || (left.cleanup.state != CleanupState::Unknown
                    && right.cleanup.state != CleanupState::Unknown
                    && left.cleanup.state != right.cleanup.state)
                || matches!(
                    (left.success_commit, right.success_commit),
                    (SuccessCommit::Recorded, SuccessCommit::NotSucceeded)
                        | (SuccessCommit::NotSucceeded, SuccessCommit::Recorded)
                )
            {
                return false;
            }
        }
    }
    true
}

/// Validates the exact requested store and selectors before any provider I/O.
pub(crate) fn validate_request(
    expected_store_id: &str,
    expected: &[Target],
) -> Result<(), StatusError> {
    if crate::domain::store_id(expected_store_id).is_err() || !(1..=20).contains(&expected.len()) {
        return Err(StatusError::InvalidRequest);
    }
    let mut selectors = std::collections::HashSet::new();
    let mut refs = HashMap::new();
    for target in expected {
        if !valid_target(target)
            || !selectors.insert((&target.agent_id, target.sequence))
            || refs
                .insert(&target.execution_ref, target.sequence)
                .is_some_and(|old| old != target.sequence)
        {
            return Err(StatusError::InvalidRequest);
        }
    }
    Ok(())
}

/// Validates a decoded snapshot from a bounded trusted transport against its exact request.
pub(crate) fn validate_response(
    response: StatusResponse,
    expected_store_id: &str,
    expected: &[Target],
) -> Result<StatusEvidence, StatusError> {
    validate_request(expected_store_id, expected)?;
    if response.version != 1
        || response.store_id != expected_store_id
        || !response
            .observed_at
            .get()
            .parse::<f64>()
            .is_ok_and(|value| value.is_finite() && value >= 0.0)
        || response.items.len() != expected.len()
        || response
            .items
            .iter()
            .zip(expected)
            .any(|(item, target)| item.selector != *target || !valid_item(item))
        || !consistent_items(&response.items)
    {
        return Err(StatusError::InvalidResponse);
    }
    Ok(StatusEvidence(response))
}

/// Parses one bounded response and correlates every ordered item with its exact request.
/// All expected selectors must include a valid store, incarnation, and pin. No I/O occurs.
#[cfg(test)]
pub(crate) fn parse(
    bytes: &[u8],
    expected_store_id: &str,
    expected: &[Target],
) -> Result<StatusEvidence, StatusError> {
    validate_request(expected_store_id, expected)?;
    if bytes.len() > crate::integrations::MAX_FRAME {
        return Err(StatusError::InvalidResponse);
    }
    let crate::integrations::JsonObject(response): crate::integrations::JsonObject<StatusResponse> =
        serde_json::from_slice(bytes).map_err(StatusError::Malformed)?;
    validate_response(response, expected_store_id, expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    const STORE: &str = "store_0123456789abcdef0123456789abcdef";

    /// Creates a distinct canonical selector using valid Run identity spellings.
    fn target(number: u32) -> Target {
        Target {
            agent_id: format!("ag-20261106-200000-{number:010x}"),
            sequence: 1,
            execution_ref: format!("ex1_{number:064x}"),
            pin_id: format!("pin_00000000000040008000{number:012x}"),
        }
    }

    /// Produces the draft's complete successful fact without any I/O.
    fn item(target: &Target) -> Value {
        let execution = json!({
            "sequence": target.sequence,
            "execution_ref": target.execution_ref,
            "raw_status": "succeeded"
        });
        json!({
            "selector": target,
            "canonical_agent_id": target.agent_id,
            "match": "verified",
            "pin_id": target.pin_id,
            "pin_state": "active",
            "selected": execution,
            "retained_latest": execution,
            "coverage": "complete",
            "restart_resume": "none",
            "lineage_terminal": true,
            "terminal_outcome": "succeeded",
            "success_commit": "recorded",
            "cleanup": {"scope": "lineage", "state": "confirmed"}
        })
    }

    /// Wraps ordered fixture items as a single Run store snapshot.
    fn response(targets: &[Target]) -> Value {
        json!({
            "version": 1,
            "store_id": STORE,
            "observed_at": 1_792_000_000.25,
            "items": targets.iter().map(item).collect::<Vec<_>>()
        })
    }

    /// Exercises the actual JSON entrypoint for a synthetic response.
    fn check(value: &Value, targets: &[Target]) -> Result<StatusEvidence, StatusError> {
        parse(value.to_string().as_bytes(), STORE, targets)
    }

    /// Positive snapshots produced by both Run handlers prove only the exact historical execution.
    #[test]
    fn run_status_accepts_success_from_real_producer_handlers()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/run-status-v1-success.json"))?;
        assert_eq!(
            fixture["source_sha256"],
            "c23eac98fd405fbdab01113eae600589597ce5d14c1c30255065780e281b83e9"
        );
        for transport in ["socket", "mcp"] {
            let request = &fixture[transport]["request"];
            let result = &fixture[transport]["result"];
            let store = request["expected_store_id"]
                .as_str()
                .ok_or("missing store")?;
            let targets: Vec<Target> = serde_json::from_value(request["targets"].clone())?;
            let bytes = serde_json::to_vec(result)?;
            let evidence = parse(&bytes, store, &targets).map_err(|error| format!("{error:?}"))?;
            assert_eq!(evidence.items().len(), 1);
            assert!(
                evidence
                    .items()
                    .all(|item| item.proves_historical_success())
            );
            assert_eq!(
                result["items"][0]["selected"],
                result["items"][0]["retained_latest"]
            );

            let mut pending = result.clone();
            pending["items"][0]["cleanup"]["state"] = json!("pending");
            let bytes = serde_json::to_vec(&pending)?;
            let pending = parse(&bytes, store, &targets).map_err(|error| format!("{error:?}"))?;
            assert!(!pending.items().any(|item| item.proves_historical_success()));
        }
        Ok(())
    }

    /// Run's synthetic socket examples must never turn stale or unverified evidence into success.
    #[test]
    fn run_status_accepts_scoped_producer_examples_without_claiming_success()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/run-status-v1.json"))?;
        assert_eq!(
            fixture["source_sha256"],
            "f75302fe1a94653422dacda732238ef8826b8a17ae372810b453ff1abeb64ba2"
        );
        for name in ["verified_selected_not_tail", "mismatch"] {
            let case = &fixture["cases"][name];
            let request = &case["request"];
            let targets: Vec<Target> = serde_json::from_value(request["targets"].clone())?;
            let store = request["expected_store_id"]
                .as_str()
                .ok_or("missing store")?;
            let bytes = serde_json::to_vec(&case["response"]["result"])?;
            let evidence = parse(&bytes, store, &targets).map_err(|error| format!("{error:?}"))?;
            assert_eq!(evidence.items().len(), targets.len());
            assert!(
                !evidence
                    .items()
                    .any(|item| item.proves_historical_success())
            );
        }
        let stale = &fixture["cases"]["verified_selected_not_tail"]["response"]["result"];
        assert_eq!(stale["view"]["agent"]["status"], "succeeded");
        assert_eq!(
            stale["items"][0]["retained_latest"]["raw_status"],
            "running"
        );
        Ok(())
    }

    /// Missing request fences and execution refs cannot be inferred from the response.
    #[test]
    fn run_status_producer_examples_keep_unfenced_and_unverified_unknown()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/run-status-v1.json"))?;
        for name in ["unverified", "missing"] {
            let case = &fixture["cases"][name];
            let request = &case["request"];
            assert!(request["targets"][0].get("execution_ref").is_none());
            assert!(serde_json::from_value::<Vec<Target>>(request["targets"].clone()).is_err());
            let mut inferred = request["targets"][0].clone();
            inferred["execution_ref"] =
                case["response"]["result"]["items"][0]["selected"]["execution_ref"]
                    .as_str()
                    .map_or_else(
                        || json!(format!("ex1_{}", "0".repeat(64))),
                        |value| json!(value),
                    );
            let target: Target = serde_json::from_value(inferred)?;
            let bytes = serde_json::to_vec(&case["response"]["result"])?;
            assert!(
                parse(
                    &bytes,
                    request["expected_store_id"]
                        .as_str()
                        .ok_or("missing store")?,
                    &[target]
                )
                .is_err()
            );
        }
        let case = &fixture["cases"]["restart_pending_raw_terminal"];
        assert!(case["request"].get("expected_store_id").is_none());
        let targets: Vec<Target> = serde_json::from_value(case["request"]["targets"].clone())?;
        assert!(validate_request("", &targets).is_err());
        // This checks only the wire shape, not the original unfenced request's identity.
        let result = &case["response"]["result"];
        let bytes = serde_json::to_vec(result)?;
        let evidence = parse(
            &bytes,
            result["store_id"].as_str().ok_or("missing store")?,
            &targets,
        )
        .map_err(|error| format!("{error:?}"))?;
        assert_eq!(result["view"]["agent"]["status"], "succeeded");
        assert_eq!(result["items"][0]["restart_resume"], "pending");
        assert!(
            !evidence
                .items()
                .any(|item| item.proves_historical_success())
        );
        Ok(())
    }

    #[test]
    fn run_status_success_is_correlated_and_view_is_ignored() {
        let targets = vec![target(1), target(2)];
        let mut value = response(&targets);
        value["view"] = json!({"success_commit": "not_succeeded", "untrusted": [1, 2]});
        let Ok(evidence) = check(&value, &targets) else {
            panic!("valid evidence rejected")
        };
        assert_eq!(evidence.store_id(), STORE);
        assert_eq!(evidence.observed_at(), 1_792_000_000.25);
        assert_eq!(evidence.items().len(), 2);
        assert_eq!(
            evidence.items().next().map(|item| item.selector()),
            Some(&targets[0])
        );
        assert!(
            evidence
                .items()
                .all(|item| item.proves_historical_success())
        );
    }

    #[test]
    fn status_observed_at_retains_exact_run_decimal_text() {
        let targets = vec![target(1)];
        let bytes = response(&targets)
            .to_string()
            .replace("1792000000.25", "1792000000.250000000000");
        let Ok(evidence) = parse(bytes.as_bytes(), STORE, &targets) else {
            panic!("valid exact decimal timestamp rejected")
        };
        assert_eq!(evidence.observed_at_text(), "1792000000.250000000000");
    }

    #[test]
    fn run_status_rejects_positional_arrays_at_every_proof_boundary() {
        let targets = vec![target(1)];
        let value = response(&targets);
        let original = value["items"][0].clone();
        let execution = json!([1, targets[0].execution_ref, "succeeded"]);
        let selector = json!([
            targets[0].agent_id,
            1,
            targets[0].execution_ref,
            targets[0].pin_id
        ]);
        let mut variants = vec![
            json!([1, STORE, 1.0, [original.clone()], null]),
            json!({"version":1,"store_id":STORE,"observed_at":1.0,"items":[[
                original["selector"], original["canonical_agent_id"], "verified",
                original["pin_id"], "active", original["selected"], original["retained_latest"],
                "complete", "none", true, "succeeded", "recorded", original["cleanup"]
            ]]}),
        ];
        for (field, array) in [
            ("selector", selector),
            ("selected", execution.clone()),
            ("retained_latest", execution),
            ("cleanup", json!(["lineage", "confirmed"])),
        ] {
            let mut invalid = value.clone();
            invalid["items"][0][field] = array;
            variants.push(invalid);
        }
        for invalid in variants {
            assert!(matches!(
                check(&invalid, &targets),
                Err(StatusError::Malformed(_))
            ));
        }
    }

    #[test]
    fn run_status_old_selected_execution_never_proves_latest_success() {
        let targets = vec![target(1)];
        let mut value = response(&targets);
        value["items"][0]["retained_latest"]["sequence"] = json!(2);
        value["items"][0]["retained_latest"]["execution_ref"] = json!(target(2).execution_ref);
        let Ok(evidence) = check(&value, &targets) else {
            panic!("valid older selection rejected")
        };
        assert_eq!(
            evidence
                .items()
                .map(|item| item.proves_historical_success())
                .collect::<Vec<_>>(),
            vec![false]
        );
    }

    /// A replacement can target a newer terminal tip, but incomplete cleanup or restart cannot.
    #[test]
    fn run_status_replacement_precondition_uses_verified_latest() -> Result<(), StatusError> {
        let original = target(1);
        let mut value = response(std::slice::from_ref(&original));
        value["items"][0]["retained_latest"]["sequence"] = json!(2);
        value["items"][0]["retained_latest"]["execution_ref"] = json!(target(2).execution_ref);
        value["items"][0]["retained_latest"]["raw_status"] = json!("failed");
        value["items"][0]["terminal_outcome"] = json!("failed");
        value["items"][0]["success_commit"] = json!("not_succeeded");
        value["items"][0]["canonical_agent_id"] = json!(target(3).agent_id);
        let evidence = check(&value, std::slice::from_ref(&original))?;
        let actual = evidence
            .items()
            .next()
            .and_then(|item| item.replacement_precondition());
        assert_eq!(
            actual,
            Some(Target {
                agent_id: target(3).agent_id,
                sequence: 2,
                execution_ref: target(2).execution_ref,
                pin_id: original.pin_id.clone(),
            })
        );

        let mut pending_cleanup = value.clone();
        pending_cleanup["items"][0]["cleanup"]["state"] = json!("pending");
        let mut released_pin = value.clone();
        released_pin["items"][0]["pin_state"] = json!("released");
        released_pin["items"][0]["coverage"] = json!("unknown");
        released_pin["items"][0]["restart_resume"] = json!("unknown");
        released_pin["items"][0]["lineage_terminal"] = Value::Null;
        released_pin["items"][0]["terminal_outcome"] = Value::Null;
        released_pin["items"][0]["success_commit"] = json!("unknown");
        released_pin["items"][0]["cleanup"]["state"] = json!("unknown");
        let mut pending_restart = value;
        pending_restart["items"][0]["restart_resume"] = json!("pending");
        pending_restart["items"][0]["lineage_terminal"] = json!(false);
        pending_restart["items"][0]["terminal_outcome"] = Value::Null;
        pending_restart["items"][0]["success_commit"] = json!("unknown");
        pending_restart["items"][0]["cleanup"]["state"] = json!("pending");
        for incomplete in [pending_cleanup, pending_restart, released_pin] {
            let evidence = check(&incomplete, std::slice::from_ref(&original))?;
            assert!(
                evidence
                    .items()
                    .all(|item| item.replacement_precondition().is_none())
            );
        }
        Ok(())
    }

    #[test]
    fn run_status_incomplete_cleanup_never_proves_success() {
        let targets = vec![target(1)];
        for state in ["pending", "unknown"] {
            let mut value = response(&targets);
            value["items"][0]["cleanup"]["state"] = json!(state);
            let Ok(evidence) = check(&value, &targets) else {
                panic!("valid cleanup state rejected")
            };
            assert_eq!(
                evidence
                    .items()
                    .map(|item| item.proves_historical_success())
                    .collect::<Vec<_>>(),
                vec![false]
            );
        }
        let mut value = response(&targets);
        value["items"][0]["cleanup"]["state"] = json!("failed");
        assert!(matches!(
            check(&value, &targets),
            Err(StatusError::Malformed(_))
        ));
    }

    #[test]
    fn run_status_rejects_wrong_store_selector_and_order() {
        let targets = vec![target(1), target(2)];
        let mut value = response(&targets);
        value["store_id"] = json!("store_ffffffffffffffffffffffffffffffff");
        assert!(matches!(
            check(&value, &targets),
            Err(StatusError::InvalidResponse)
        ));
        value = response(&targets);
        value["items"][0]["selector"]["execution_ref"] = json!(target(3).execution_ref);
        assert!(matches!(
            check(&value, &targets),
            Err(StatusError::InvalidResponse)
        ));
        value = response(&targets);
        let first = value["items"][0].clone();
        value["items"][0] = value["items"][1].clone();
        value["items"][1] = first;
        assert!(matches!(
            check(&value, &targets),
            Err(StatusError::InvalidResponse)
        ));
    }

    #[test]
    fn run_status_rejects_missing_duplicate_or_excess_targets() {
        let targets = vec![target(1), target(2)];
        let mut missing = response(&targets);
        missing["items"] = json!([item(&targets[0])]);
        assert!(matches!(
            check(&missing, &targets),
            Err(StatusError::InvalidResponse)
        ));
        let mut duplicate = response(&targets);
        duplicate["items"][1] = duplicate["items"][0].clone();
        assert!(matches!(
            check(&duplicate, &targets),
            Err(StatusError::InvalidResponse)
        ));
        let repeated = vec![target(1), target(1)];
        assert!(matches!(
            check(&response(&repeated), &repeated),
            Err(StatusError::InvalidRequest)
        ));
        let many: Vec<_> = (1..=21).map(target).collect();
        assert!(matches!(
            check(&response(&many), &many),
            Err(StatusError::InvalidRequest)
        ));
        assert!(matches!(
            check(&response(&[]), &[]),
            Err(StatusError::InvalidRequest)
        ));
        let maximum: Vec<_> = (1..=20).map(target).collect();
        assert!(check(&response(&maximum), &maximum).is_ok());
    }

    #[test]
    fn run_status_rejects_invalid_identities_and_timestamps() {
        let valid = target(1);
        for invalid in [
            Target {
                agent_id: "ag-2026/230-200000-0000000001".into(),
                ..valid.clone()
            },
            Target {
                agent_id: "ag-20261106-200000-000000000G".into(),
                ..valid.clone()
            },
            Target {
                agent_id: "ag-20261106-2000x1-0000000001".into(),
                ..valid.clone()
            },
            Target {
                agent_id: "ag-20260230-010101-0000000001".into(),
                ..valid.clone()
            },
            Target {
                agent_id: "ag-20261106-250000-0000000001".into(),
                ..valid.clone()
            },
            Target {
                sequence: 0,
                ..valid.clone()
            },
            Target {
                execution_ref: "ex1_bad".into(),
                ..valid.clone()
            },
            Target {
                pin_id: "pin_00000000000010008000000000000001".into(),
                ..valid.clone()
            },
        ] {
            assert!(matches!(
                check(&response(std::slice::from_ref(&invalid)), &[invalid]),
                Err(StatusError::InvalidRequest)
            ));
        }
        let targets = vec![valid];
        let mut value = response(&targets);
        value["items"][0]["canonical_agent_id"] = json!("ag-2026/230-200000-0000000001");
        assert!(matches!(
            check(&value, &targets),
            Err(StatusError::InvalidResponse)
        ));
        value = response(&targets);
        value["observed_at"] = json!(-1.0);
        assert!(matches!(
            check(&value, &targets),
            Err(StatusError::InvalidResponse)
        ));
        value["observed_at"] = json!(0.0);
        assert!(check(&value, &targets).is_ok());
        let leap_second = Target {
            agent_id: "ag-20261106-200060-0000000001".into(),
            ..target(1)
        };
        assert!(
            check(
                &response(std::slice::from_ref(&leap_second)),
                &[leap_second]
            )
            .is_ok()
        );
        let spaced = Target {
            agent_id: "ag-20261106-2 0000-0000000001".into(),
            ..target(1)
        };
        assert!(check(&response(std::slice::from_ref(&spaced)), &[spaced]).is_ok());
        assert!(matches!(
            parse(
                response(&targets).to_string().as_bytes(),
                "store_bad",
                &targets
            ),
            Err(StatusError::InvalidRequest)
        ));
    }

    #[test]
    fn run_status_rejects_missing_unknown_and_duplicate_wire_fields() {
        let targets = vec![target(1)];
        let mut value = response(&targets);
        value["items"][0]
            .as_object_mut()
            .map(|obj| obj.remove("terminal_outcome"));
        assert!(matches!(
            check(&value, &targets),
            Err(StatusError::Malformed(_))
        ));
        value = response(&targets);
        value["items"][0]["unsupported"] = json!(true);
        assert!(matches!(
            check(&value, &targets),
            Err(StatusError::Malformed(_))
        ));
        value = response(&targets);
        value["items"][0]["restart_resume"] = json!("future_state");
        assert!(matches!(
            check(&value, &targets),
            Err(StatusError::Malformed(_))
        ));
        let text = response(&targets).to_string();
        let duplicate_version = format!("{{\"version\":1,{}", &text[1..]);
        assert!(matches!(
            parse(duplicate_version.as_bytes(), STORE, &targets),
            Err(StatusError::Malformed(_))
        ));
    }

    #[test]
    fn run_status_unknown_incarnation_is_valid_but_not_proof() {
        let targets = vec![target(1)];
        let mut value = response(&targets);
        let item = &mut value["items"][0];
        item["match"] = json!("unknown");
        item["selected"]["execution_ref"] = Value::Null;
        item["retained_latest"] = Value::Null;
        item["coverage"] = json!("unknown");
        item["restart_resume"] = json!("unknown");
        item["lineage_terminal"] = Value::Null;
        item["terminal_outcome"] = Value::Null;
        item["success_commit"] = json!("unknown");
        item["cleanup"]["state"] = json!("unknown");
        let Ok(evidence) = check(&value, &targets) else {
            panic!("valid unknown evidence rejected")
        };
        assert_eq!(
            evidence
                .items()
                .map(|item| item.proves_historical_success())
                .collect::<Vec<_>>(),
            vec![false]
        );
    }

    #[test]
    fn run_status_negative_but_well_formed_states_are_not_success() {
        let targets = vec![target(1)];
        let mut mismatch = response(&targets);
        let item = &mut mismatch["items"][0];
        item["match"] = json!("mismatch");
        item["selected"] = Value::Null;
        item["retained_latest"] = Value::Null;
        item["coverage"] = json!("unknown");
        item["restart_resume"] = json!("unknown");
        item["lineage_terminal"] = Value::Null;
        item["terminal_outcome"] = Value::Null;
        item["success_commit"] = json!("unknown");
        item["cleanup"]["state"] = json!("unknown");

        let mut released = response(&targets);
        let item = &mut released["items"][0];
        item["pin_state"] = json!("released");
        item["coverage"] = json!("unknown");
        item["restart_resume"] = json!("unknown");
        item["lineage_terminal"] = Value::Null;
        item["terminal_outcome"] = Value::Null;
        item["success_commit"] = json!("unknown");
        item["cleanup"]["state"] = json!("unknown");

        let mut pending = response(&targets);
        let item = &mut pending["items"][0];
        item["restart_resume"] = json!("pending");
        item["lineage_terminal"] = json!(false);
        item["terminal_outcome"] = Value::Null;
        item["success_commit"] = json!("unknown");
        item["cleanup"]["state"] = json!("pending");

        let mut failed = response(&targets);
        let item = &mut failed["items"][0];
        item["selected"]["raw_status"] = json!("failed");
        item["retained_latest"]["raw_status"] = json!("failed");
        item["terminal_outcome"] = json!("failed");
        item["success_commit"] = json!("not_succeeded");

        for value in [mismatch, released, pending, failed] {
            let Ok(evidence) = check(&value, &targets) else {
                panic!("valid negative state rejected")
            };
            assert_eq!(
                evidence
                    .items()
                    .map(|item| item.proves_historical_success())
                    .collect::<Vec<_>>(),
                vec![false]
            );
        }
    }

    #[test]
    fn run_status_rejects_conflicting_success_and_execution_facts() {
        let targets = vec![target(1)];
        let mut value = response(&targets);
        value["items"][0]["terminal_outcome"] = json!("failed");
        assert!(matches!(
            check(&value, &targets),
            Err(StatusError::InvalidResponse)
        ));
        value = response(&targets);
        value["items"][0]["success_commit"] = json!("not_succeeded");
        assert!(matches!(
            check(&value, &targets),
            Err(StatusError::InvalidResponse)
        ));
        value = response(&targets);
        value["items"][0]["lineage_terminal"] = Value::Null;
        assert!(matches!(
            check(&value, &targets),
            Err(StatusError::InvalidResponse)
        ));
        value = response(&targets);
        value["items"][0]["retained_latest"]["raw_status"] = json!("failed");
        assert!(matches!(
            check(&value, &targets),
            Err(StatusError::InvalidResponse)
        ));
        value = response(&targets);
        value["items"][0]["retained_latest"]["sequence"] = json!(2);
        assert!(matches!(
            check(&value, &targets),
            Err(StatusError::InvalidResponse)
        ));
        value = response(&targets);
        value["items"][0]["retained_latest"]["sequence"] = json!(2);
        value["items"][0]["retained_latest"]["execution_ref"] = Value::Null;
        assert!(matches!(
            check(&value, &targets),
            Err(StatusError::InvalidResponse)
        ));
        value = response(&targets);
        value["items"][0]["selected"]["raw_status"] = json!("running");
        value["items"][0]["retained_latest"]["sequence"] = json!(2);
        value["items"][0]["retained_latest"]["execution_ref"] = json!(target(2).execution_ref);
        assert!(matches!(
            check(&value, &targets),
            Err(StatusError::InvalidResponse)
        ));
        value = response(&targets);
        value["items"][0]["cleanup"]["scope"] = json!("process");
        assert!(matches!(
            check(&value, &targets),
            Err(StatusError::InvalidResponse)
        ));
    }

    #[test]
    fn run_status_checks_correlated_lineages_across_items() {
        let first = target(1);
        let mut second = target(2);
        second.agent_id = first.agent_id.clone();
        second.pin_id = first.pin_id.clone();
        second.sequence = 2;
        let targets = vec![first, second];
        let mut value = response(&targets);
        value["items"][0]["retained_latest"] = value["items"][1]["selected"].clone();
        let Ok(evidence) = check(&value, &targets) else {
            panic!("consistent lineage rejected")
        };
        assert_eq!(
            evidence
                .items()
                .map(|item| item.proves_historical_success())
                .collect::<Vec<_>>(),
            vec![false, true]
        );
        value["items"][1]["selected"]["raw_status"] = json!("failed");
        value["items"][1]["retained_latest"]["raw_status"] = json!("failed");
        value["items"][1]["terminal_outcome"] = json!("failed");
        value["items"][1]["success_commit"] = json!("not_succeeded");
        assert!(matches!(
            check(&value, &targets),
            Err(StatusError::InvalidResponse)
        ));
    }

    /// Sets a pin state whose relationship cannot establish lineage coverage.
    fn unproven_pin(item: &mut Value, state: &str) {
        item["pin_state"] = json!(state);
        item["coverage"] = json!("unknown");
        item["restart_resume"] = json!("unknown");
        item["lineage_terminal"] = Value::Null;
        item["terminal_outcome"] = Value::Null;
        item["success_commit"] = json!("unknown");
        item["cleanup"]["state"] = json!("unknown");
    }

    #[test]
    fn run_status_pin_has_one_owner_but_other_roots_may_report_mismatch() {
        let first = target(1);
        let mut second = target(2);
        second.pin_id = first.pin_id.clone();
        let targets = vec![first, second];
        let value = response(&targets);
        assert!(matches!(
            check(&value, &targets),
            Err(StatusError::InvalidResponse)
        ));

        let mut released = response(&targets);
        unproven_pin(&mut released["items"][1], "released");
        assert!(matches!(
            check(&released, &targets),
            Err(StatusError::InvalidResponse)
        ));
        unproven_pin(&mut released["items"][0], "released");
        assert!(matches!(
            check(&released, &targets),
            Err(StatusError::InvalidResponse)
        ));

        for first_state in ["active", "released", "mismatch"] {
            let mut valid = response(&targets);
            if first_state != "active" {
                unproven_pin(&mut valid["items"][0], first_state);
            }
            unproven_pin(&mut valid["items"][1], "mismatch");
            let Ok(evidence) = check(&valid, &targets) else {
                panic!("valid pin mismatch was rejected")
            };
            assert_eq!(
                evidence
                    .items()
                    .map(|item| item.proves_historical_success())
                    .collect::<Vec<_>>(),
                vec![first_state == "active", false]
            );
        }
        let mut missing = response(&targets);
        unproven_pin(&mut missing["items"][0], "missing");
        unproven_pin(&mut missing["items"][1], "missing");
        assert!(check(&missing, &targets).is_ok());
    }

    #[test]
    fn run_status_lineage_facts_agree_across_different_pins() {
        let mut first = target(1);
        first.sequence = 2;
        let mut second = target(2);
        second.agent_id = first.agent_id.clone();
        let targets = vec![first, second];
        let mut value = response(&targets);
        value["items"][1]["retained_latest"] = value["items"][0]["selected"].clone();

        let mut unknown = value.clone();
        unknown["items"][1]["restart_resume"] = json!("unknown");
        unknown["items"][1]["lineage_terminal"] = Value::Null;
        unknown["items"][1]["terminal_outcome"] = Value::Null;
        unknown["items"][1]["success_commit"] = json!("unknown");
        unknown["items"][1]["cleanup"]["state"] = json!("unknown");
        let Ok(evidence) = check(&unknown, &targets) else {
            panic!("less informative evidence rejected")
        };
        assert_eq!(
            evidence
                .items()
                .map(|item| item.proves_historical_success())
                .collect::<Vec<_>>(),
            vec![true, false]
        );

        let mut pending = unknown;
        pending["items"][1]["restart_resume"] = json!("pending");
        pending["items"][1]["lineage_terminal"] = json!(false);
        pending["items"][1]["cleanup"]["state"] = json!("pending");
        assert!(matches!(
            check(&pending, &targets),
            Err(StatusError::InvalidResponse)
        ));

        value["items"][1]["cleanup"]["state"] = json!("pending");
        assert!(matches!(
            check(&value, &targets),
            Err(StatusError::InvalidResponse)
        ));
    }

    #[test]
    fn run_status_selected_fact_cannot_be_newer_than_another_items_tail() {
        let first = target(1);
        let mut second = target(2);
        second.agent_id = first.agent_id.clone();
        second.pin_id = first.pin_id.clone();
        second.sequence = 2;
        let targets = vec![first, second];
        let mut value = response(&targets);
        let item = &mut value["items"][1];
        item["match"] = json!("unknown");
        item["selected"]["execution_ref"] = Value::Null;
        item["retained_latest"] = Value::Null;
        item["coverage"] = json!("unknown");
        item["restart_resume"] = json!("unknown");
        item["lineage_terminal"] = Value::Null;
        item["terminal_outcome"] = Value::Null;
        item["success_commit"] = json!("unknown");
        item["cleanup"]["state"] = json!("unknown");
        assert!(matches!(
            check(&value, &targets),
            Err(StatusError::InvalidResponse)
        ));

        let mut newer = targets[0].clone();
        newer.sequence = 2;
        let mut older = targets[1].clone();
        older.sequence = 1;
        let targets = vec![newer, older];
        let mut value = response(&targets);
        let item = &mut value["items"][1];
        item["match"] = json!("unknown");
        item["selected"]["execution_ref"] = Value::Null;
        item["retained_latest"] = Value::Null;
        item["coverage"] = json!("unknown");
        item["restart_resume"] = json!("unknown");
        item["lineage_terminal"] = Value::Null;
        item["terminal_outcome"] = Value::Null;
        item["success_commit"] = json!("unknown");
        item["cleanup"]["state"] = json!("unknown");
        let Ok(evidence) = check(&value, &targets) else {
            panic!("less informative older selection rejected")
        };
        assert_eq!(
            evidence
                .items()
                .map(|item| item.proves_historical_success())
                .collect::<Vec<_>>(),
            vec![true, false]
        );
    }

    #[test]
    fn run_status_rejects_shared_incarnation_between_roots_and_oversize() {
        let first = target(1);
        let mut second = target(2);
        second.execution_ref = first.execution_ref.clone();
        let targets = vec![first, second];
        assert!(matches!(
            check(&response(&targets), &targets),
            Err(StatusError::InvalidResponse)
        ));
        let oversized = vec![b' '; crate::integrations::MAX_FRAME + 1];
        assert!(matches!(
            parse(&oversized, STORE, &targets),
            Err(StatusError::InvalidResponse)
        ));
    }

    #[test]
    fn run_status_rejects_duplicate_canonical_selectors() {
        let first = target(1);
        let mut second = target(2);
        second.execution_ref = first.execution_ref.clone();
        second.pin_id = first.pin_id.clone();
        let targets = vec![first, second];
        let mut value = response(&targets);
        value["items"][1]["canonical_agent_id"] = json!(targets[0].agent_id);
        assert!(matches!(
            check(&value, &targets),
            Err(StatusError::InvalidResponse)
        ));
    }

    #[test]
    fn run_status_same_agent_cannot_resolve_to_different_roots() {
        let first = target(1);
        let mut second = target(2);
        second.agent_id = first.agent_id.clone();
        second.sequence = 2;
        let targets = vec![first, second];
        let mut value = response(&targets);
        value["items"][1]["canonical_agent_id"] = json!(target(3).agent_id);
        assert!(matches!(
            check(&value, &targets),
            Err(StatusError::InvalidResponse)
        ));

        let item = &mut value["items"][1];
        item["canonical_agent_id"] = Value::Null;
        item["match"] = json!("unknown");
        item["selected"] = Value::Null;
        item["retained_latest"] = Value::Null;
        unproven_pin(item, "unknown");
        let Ok(evidence) = check(&value, &targets) else {
            panic!("unknown root was rejected")
        };
        assert_eq!(
            evidence
                .items()
                .map(|item| item.proves_historical_success())
                .collect::<Vec<_>>(),
            vec![true, false]
        );
    }
}
