//! Observes ordinary Run chat failures and resumes the same lineage after fresh quota evidence.

use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;

use crate::{
    config::Config,
    domain::{Binding, Fault},
    integrations,
    runtime::{SharedStore, stored},
    store::{chat::receipt_clock, chat_recovery as state},
};

/// Maximum number of distinct resume requests for one failed execution.
pub(crate) const MAX_ATTEMPTS: u8 = 3;

const RESUME_TASK: &str = "Quota restored. Re-read the pool chat tail and continue your role.";

/// Orders ordinary owner close/replacement against the scheduler's bounded Run admission.
pub(crate) static ADMISSION: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Default for the global and per-pool switches, including older data.
pub(crate) fn enabled_by_default() -> bool {
    true
}

/// Omits a default-true override to preserve prior start request fingerprints.
pub(crate) fn is_enabled(value: &bool) -> bool {
    *value
}

/// Exact enrolled incarnation and its original provider selection.
#[derive(Clone)]
pub(crate) struct Seat {
    pub binding: Binding,
    pub provider: String,
    pub enabled: bool,
}

impl Seat {
    /// Returns the Pool membership incarnation, independent of its Run sequence.
    pub fn id(&self) -> &str {
        &self.binding.member.member_id
    }
}

/// Safe Run facts used for failure notification and recovery.
#[derive(Clone, PartialEq)]
pub(crate) struct Failure {
    pub sequence: u32,
    finished_at: f64,
    kind: &'static str,
    failover_blocked: bool,
    model: String,
}

impl Failure {
    /// Extracts a terminal failure with a supported recovery path without copying Run prose.
    pub(crate) fn observed(agent: &Value, sequence: u64) -> Option<Self> {
        if !matches!(agent["status"].as_str(), Some("failed" | "lost")) {
            return None;
        }
        let kind = match agent["failure_kind"].as_str()? {
            "quota_exhausted" | "codex_usageLimitExceeded" => "quota_exhausted",
            "provider_overloaded" => "provider_overloaded",
            "engine_transport_eof" => "engine_transport_eof",
            "engine_transport_failure" => "engine_transport_failure",
            "runtime_transport_failed" => "runtime_transport_failed",
            "runtime_ownership_observation_failed" => "runtime_ownership_observation_failed",
            "ended_without_finish" => "ended_without_finish",
            // Run >= 0.36: the runtime did not confirm a wake; resuming reconciles it.
            "native_owner_input_uncertain" => "native_owner_input_uncertain",
            "supervisor_dead" if agent["status"] == "lost" => "supervisor_dead",
            "supervisor_identity_mismatch" if agent["status"] == "lost" => {
                "supervisor_identity_mismatch"
            }
            _ => return None,
        };
        let model = agent["model"].as_str()?;
        if model.is_empty() || model.len() > 256 || model.chars().any(char::is_control) {
            return None;
        }
        let finished_at = agent["finished_at"].as_f64().filter(|at| *at > 0.0)?;
        Some(Self {
            sequence: u32::try_from(sequence).ok()?,
            finished_at,
            kind,
            model: model.into(),
            failover_blocked: kind == "quota_exhausted"
                && agent["failure_text"] == "failover_blocked: no_eligible_account",
        })
    }

    /// Projects quota exhaustion independently of membership and auto-resume settings.
    pub(crate) fn waiting_for_quota(&self) -> bool {
        self.kind == "quota_exhausted"
    }

    /// Uses stored display identity and the sampled Run model in each audit message.
    pub fn label(&self, seat: &Seat) -> String {
        format!(
            "{} ({}, {}) · {} · execution {}",
            seat.binding.member.name,
            seat.binding.member.role,
            self.model,
            seat.binding.run_id.as_deref().unwrap_or_else(|| seat.id()),
            self.sequence
        )
    }

    /// Includes a UTC estimate only when Quota reports one.
    pub fn notice(&self, seat: &Seat, settings: Decision) -> String {
        let failover = if self.failover_blocked {
            " · failover_blocked: no_eligible_account"
        } else {
            ""
        };
        let recovery = settings.reset_at_ms.map_or_else(
            || "Recovery time unknown.".into(),
            |ms| format!("Expected quota recovery {}.", utc(ms)),
        );
        let next = if settings.enabled {
            "Pool will check for fresh quota capacity and request resume."
        } else {
            "Auto-resume is unavailable or disabled. Resume through Run when ready."
        };
        let status = if self.waiting_for_quota() {
            " Waiting for quota."
        } else {
            ""
        };
        format!(
            "{} failed · {}{failover}.{status} {recovery} {next}",
            self.label(seat),
            self.kind
        )
    }
}

/// Quota and policy decision for a single scheduler observation.
#[derive(Clone, Copy)]
pub(crate) struct Decision {
    pub enabled: bool,
    usable_until: Option<f64>,
    pub reset_at_ms: Option<i64>,
    pub now_ms: i64,
}

impl Decision {
    /// Rejects evidence that expired while Pool was checking the leader or waiting to claim.
    pub fn recovered(self) -> bool {
        self.usable_until
            .is_some_and(|at| self.now_ms as f64 / 1_000.0 < at)
    }
}

/// Closed outcome from Run, independent of the presentation or delivery of its notice.
#[derive(Clone, Copy)]
pub(crate) enum Outcome {
    Resumed(u32),
    Superseded,
    Unsupported,
    Retry(&'static str),
    Refused(&'static str),
    Unknown,
}

impl Outcome {
    /// Produces the bounded retry time and the next action for the audit entry.
    pub fn next(self, attempt: u8, now_ms: i64) -> (Option<i64>, String) {
        match self {
            Self::Resumed(sequence) => (None, format!(
                "Run admitted execution {sequence}. The resumed member will re-read the pool chat."
            )),
            Self::Superseded => (None, "Run reports a newer execution. Pool stopped auto-resume.".into()),
            Self::Unsupported => (None, "Auto-resume unavailable. This Run does not accept the execution precondition. Use Run to inspect and resume manually.".into()),
            Self::Retry(reason) if attempt < MAX_ATTEMPTS => {
                let next = now_ms + 30_000 * (1_i64 << (attempt - 1));
                (Some(next), format!("Run is not ready ({reason}). Pool will retry after {} if quota remains usable.", utc(next)))
            }
            Self::Retry(reason) => (None, format!("Run is not ready ({reason}). Pool reached its resume attempt limit. Inspect the execution in Run.")),
            Self::Refused(reason) => (None, format!("Run refused resume ({reason}). Inspect the execution in Run.")),
            Self::Unknown => (None, "Run has not confirmed the resume outcome. Pool stopped automatic attempts. Inspect the latest execution in Run.".into()),
        }
    }
}

/// Displays an epoch millisecond as ISO UTC.
fn utc(ms: i64) -> String {
    DateTime::<Utc>::from_timestamp_millis(ms).map_or_else(
        || "at an unknown time".into(),
        |date| date.to_rfc3339_opts(SecondsFormat::Secs, true),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QuotaReply {
    version: u8,
    result: QuotaSnapshot,
}

#[derive(Deserialize)]
struct QuotaSnapshot {
    schema_version: u8,
    revision: u64,
    evaluated_at: f64,
    accounts: Vec<QuotaAccount>,
}

#[derive(Deserialize)]
struct QuotaAccount {
    models: Vec<QuotaModel>,
}

#[derive(Deserialize)]
struct QuotaModel {
    provider: String,
    model: String,
    state: String,
    state_validity: QuotaValidity,
    evidence: String,
    newest_observed_at: Option<f64>,
    remaining_percent: Option<f64>,
    reset_at: Option<f64>,
    exhausted_until: Option<f64>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum QuotaValidity {
    Until { at: f64 },
    LatchedNoReset,
    Unknown,
}

impl QuotaSnapshot {
    /// Matches exact provider/model and requires a positive, unexpired observation after failure.
    fn decision(&self, provider: &str, failure: &Failure, decision: &mut Decision) {
        let now = decision.now_ms as f64 / 1_000.0;
        if self.schema_version != 2
            || self.revision == 0
            || !(0.0..=now).contains(&self.evaluated_at)
        {
            return;
        }
        for model in self
            .accounts
            .iter()
            .flat_map(|account| &account.models)
            .filter(|row| row.provider == provider && row.model == failure.model)
        {
            let QuotaValidity::Until { at: valid_until } = model.state_validity else {
                continue;
            };
            if !valid_until.is_finite() || valid_until <= now {
                continue;
            }
            if model.state == "known"
                && model.evidence == "fresh"
                && model
                    .remaining_percent
                    .is_some_and(|percent| percent > 0.0 && percent <= 100.0)
                && model
                    .newest_observed_at
                    .is_some_and(|at| at > failure.finished_at && at <= self.evaluated_at)
            {
                decision.usable_until = Some(
                    decision
                        .usable_until
                        .map_or(valid_until, |old| old.max(valid_until)),
                );
            }
            if model.state == "exhausted"
                && let Some(reset) = model.exhausted_until.or(model.reset_at)
                && reset > now
                && reset < 253_402_300_800.0
            {
                let ms = (reset * 1_000.0) as i64;
                decision.reset_at_ms = Some(decision.reset_at_ms.map_or(ms, |old| old.min(ms)));
            }
        }
    }
}

/// Reads one bounded Quota snapshot through its protected local socket.
async fn quota(config: &Config, model: &str) -> Option<QuotaSnapshot> {
    let path = config.quota_socket.as_ref()?;
    let result = tokio::time::timeout(Duration::from_secs(2), async {
        let uid = config.quota_peer_uid.unwrap_or(config.expected_uid);
        if uid != config.expected_uid {
            #[cfg(target_os = "linux")]
            crate::config::identity_uid_map().ok()?;
            #[cfg(not(target_os = "linux"))]
            return None;
        }
        let before = quota_socket_identity(path, uid).await?;
        let mut stream = tokio::net::UnixStream::connect(path).await.ok()?;
        if stream.peer_cred().ok()?.uid() != uid
            || quota_socket_identity(path, uid).await? != before
        {
            return None;
        }
        let mut request = serde_json::to_vec(
            &json!({"version":1,"method":"snapshot","accounts":[],"model":model}),
        )
        .ok()?;
        request.push(b'\n');
        stream.write_all(&request).await.ok()?;
        stream.shutdown().await.ok()?;
        let frame = integrations::read_frame(&mut stream).await.ok()?;
        let reply: QuotaReply = serde_json::from_slice(&frame).ok()?;
        (reply.version == 1).then_some(reply.result)
    })
    .await;
    result.ok().flatten()
}

/// Checks socket ownership and identity without following a symlink.
async fn quota_socket_identity(path: &std::path::Path, uid: u32) -> Option<(u64, u64)> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let meta = std::fs::symlink_metadata(path).ok()?;
        (meta.file_type().is_socket() && meta.uid() == uid).then_some((meta.dev(), meta.ino()))
    })
    .await
    .ok()
    .flatten()
}

#[derive(Deserialize)]
struct Receipt {
    agent_id: String,
    sequence: u32,
}

/// Resumes an execution only under Run's exact-parent or expected-sequence admission fence.
async fn resume(config: &Config, agent: &str, failure: &Failure, request: &str) -> Outcome {
    let mut args = json!({"agent_id":agent,"task":RESUME_TASK,"request_id":request});
    if failure.sequence == 1 {
        args["run_id"] = json!(agent);
    } else {
        args["expected_sequence"] = json!(failure.sequence);
    }
    match integrations::run_rpc_typed::<Receipt>(config, "resume", args).await {
        Ok(receipt)
            if receipt.agent_id == agent
                && failure.sequence.checked_add(1) == Some(receipt.sequence) =>
        {
            Outcome::Resumed(receipt.sequence)
        }
        Err(error) => match error.code {
            "sequence_mismatch" => Outcome::Superseded,
            "unknown_resume_argument" if failure.sequence > 1 => Outcome::Unsupported,
            "binding_cooldown"
            | "no_eligible_account"
            | "quota_exhausted"
            | "selection_busy"
            | "CapacityExhausted"
            | "overload" => Outcome::Retry(error.code),
            "outcome_unknown" | "deadline" => Outcome::Unknown,
            code => Outcome::Refused(code),
        },
        Ok(_) => Outcome::Unknown,
    }
}

/// Rotating cursor for one bounded member observation per resident tick.
#[derive(Default)]
pub(crate) struct Schedule {
    cursor: String,
}

impl Schedule {
    /// Observes a current seat, queues its failure, and conditionally claims one resume.
    pub(crate) async fn tick(&mut self, config: &Config, store: &SharedStore) -> Result<(), Fault> {
        if config.run_socket.is_none() {
            return Ok(());
        }
        let after = self.cursor.clone();
        let Some(seat) = stored(store, move |store| state::next(store, &after)).await? else {
            self.cursor.clear();
            return Ok(());
        };
        self.cursor = seat.id().into();
        let (Some(agent), Some(run_store)) = (&seat.binding.run_id, &seat.binding.run_store_id)
        else {
            return Ok(());
        };
        if !same_run_store(config, run_store).await {
            return Ok(());
        }
        let Some(observed) = observe(config, agent).await else {
            return Ok(());
        };
        let Ok(latest) = u32::try_from(observed.sequence) else {
            return Ok(());
        };
        let member = seat.id().to_owned();
        if let Some(prior) =
            stored(store, move |store| state::advanced(store, &member, latest)).await?
        {
            let leader = active_leader(config, store, &seat).await?;
            if same_run_store(config, run_store).await {
                stored(store, move |store| {
                    state::settle_advanced(store, &seat, leader.as_deref(), prior, latest)
                })
                .await?;
            }
            return Ok(());
        }
        let Some(failure) = observed.failure else {
            return Ok(());
        };
        let now = receipt_clock()?;
        let sequence = failure.sequence;
        let member = seat.id().to_owned();
        if !stored(store, move |store| {
            state::due(store, &member, sequence, now)
        })
        .await?
        {
            return Ok(());
        }
        let mut decision = Decision {
            enabled: config.auto_resume && seat.enabled && config.quota_socket.is_some(),
            usable_until: None,
            reset_at_ms: None,
            now_ms: now,
        };
        if let Some(quota) = quota(config, &failure.model).await {
            decision.now_ms = receipt_clock()?;
            quota.decision(&seat.provider, &failure, &mut decision);
        }
        let leader = active_leader(config, store, &seat).await?;
        if decision.enabled
            && decision.recovered()
            && !observe(config, agent)
                .await
                .is_some_and(|sample| sample.failure.as_ref() == Some(&failure))
        {
            decision.usable_until = None;
        }
        if !same_run_store(config, run_store).await {
            return Ok(());
        }
        let agent = agent.clone();
        let seat = std::sync::Arc::new(seat);
        let _guard = ADMISSION.lock().await;
        let claim_now = receipt_clock()?;
        if claim_now < decision.now_ms {
            decision.usable_until = None;
        }
        decision.now_ms = claim_now;
        let claim = {
            let (seat, failure, leader) = (seat.clone(), failure.clone(), leader.clone());
            stored(store, move |store| {
                state::claim(store, &seat, &failure, leader.as_deref(), decision)
            })
            .await?
        };
        if let Some(request) = claim {
            let outcome = resume(config, &agent, &failure, &request).await;
            let now = receipt_clock()?;
            stored(store, move |store| {
                state::settle(
                    store,
                    &seat,
                    &failure,
                    leader.as_deref(),
                    &request,
                    outcome,
                    now,
                )
            })
            .await?;
        }
        Ok(())
    }
}

/// Bounds a scheduler read so an unavailable Run cannot monopolize a resident tick.
async fn observe(config: &Config, agent_id: &str) -> Option<integrations::RunObservation> {
    tokio::time::timeout(
        Duration::from_secs(2),
        integrations::observe_run(config, agent_id, None),
    )
    .await
    .ok()?
    .ok()
}

/// Checks the exact Run store under the scheduler's read budget.
async fn same_run_store(config: &Config, expected: &str) -> bool {
    tokio::time::timeout(
        Duration::from_secs(2),
        integrations::run_store_identity(config),
    )
    .await
    .is_ok_and(|reply| reply.is_ok_and(|id| id == expected))
}

/// Selects the current leader's membership ID only with recent running evidence.
async fn active_leader(
    config: &Config,
    store: &SharedStore,
    seat: &Seat,
) -> Result<Option<String>, Fault> {
    let seat = seat.clone();
    let leader = stored(store, move |store| state::leader(store, &seat)).await?;
    if let Some(leader) = leader
        && let Some(agent) = &leader.run_id
        && observe(config, agent)
            .await
            .is_some_and(|sample| sample.runtime == "active")
    {
        return Ok(Some(leader.member.member_id));
    }
    Ok(None)
}

#[cfg(test)]
mod owner_input_kind_tests {
    use super::Failure;

    /// An unconfirmed wake is a supported recovery kind, not a quota wait.
    #[test]
    fn unconfirmed_wake_is_recoverable() {
        let agent = serde_json::json!({"status":"failed","failure_kind":"native_owner_input_uncertain",
            "model":"deepseek-v4.1-flash","finished_at":1.0});
        let failure = Failure::observed(&agent, 3).expect("recoverable kind");
        assert_eq!(failure.kind, "native_owner_input_uncertain");
        assert!(!failure.waiting_for_quota());
    }
}
