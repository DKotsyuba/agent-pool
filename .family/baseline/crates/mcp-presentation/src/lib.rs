//! Pure Rust reference for compact MCP text, not a network or workflow framework.
//!
//! Only allowlisted typed views reach trusted embedded MiniJinja templates.
//! The raw-page example is read-only. Mutation receipts are supplied by the
//! application after execution; this crate never performs or retries a mutation.
#![forbid(unsafe_code)]

use minijinja::{AutoEscape, Environment, UndefinedBehavior};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::{self, Write};

/// Maximum UTF-8 bytes in one reference text response (not a token count).
pub const MAX_TEXT_BYTES: usize = 8 * 1024;
/// Maximum external JSON bytes decoded by the example adapter.
pub const MAX_SOURCE_BYTES: usize = 64 * 1024;
/// The example rejects oversized pages rather than skipping unshown rows.
pub const MAX_PAGE_ROWS: usize = 20;
const MAX_LABEL_BYTES: usize = 160;
const MAX_CURSOR_BYTES: usize = 512;

/// MiniJinja prints booleans Python-style (`True`); agent text uses JSON-style `true`/`false`.
pub fn json_bool_formatter(
    out: &mut minijinja::Output,
    state: &minijinja::State,
    value: &minijinja::Value,
) -> Result<(), minijinja::Error> {
    if value.kind() == minijinja::value::ValueKind::Bool {
        Ok(out.write_str(if value.is_true() { "true" } else { "false" })?)
    } else {
        minijinja::escape_formatter(out, state, value)
    }
}
/// Safe categories; deliberately carry no raw context, source bytes or credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresentationError {
    /// A trusted embedded template could not be registered.
    TemplateSetup,
    /// A required source field, type or pagination invariant is invalid.
    InvalidSource,
    /// An input, page or output exceeded its declared budget.
    BudgetExceeded,
    /// An actionable identifier cannot be represented without changing it.
    InvalidReference,
    /// Rendering failed; partial output must be discarded.
    RenderFailed,
}

impl fmt::Display for PresentationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self {
            Self::TemplateSetup => "template_setup_failed",
            Self::InvalidSource => "invalid_upstream_data",
            Self::BudgetExceeded => "response_too_large",
            Self::InvalidReference => "invalid_reference",
            Self::RenderFailed => "presentation_failed",
        };
        f.write_str(code)
    }
}

impl std::error::Error for PresentationError {}

/// A validated ASCII identifier, not a URL, path or secret bearer capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reference(String);

impl Reference {
    /// Preserve the exact identifier or reject it; never sanitize or shorten it.
    pub fn new(value: impl Into<String>) -> Result<Self, PresentationError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
        {
            return Err(PresentationError::InvalidReference);
        }
        Ok(Self(value))
    }

    /// Return the original validated bytes as UTF-8.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An immutable application receipt, independent of formatting success.
#[derive(Clone, Debug)]
pub enum MutationReceipt {
    /// The provider confirmed the effect.
    Committed {
        /// Exact target identity.
        entity: Reference,
        /// Original request identity, retained for reconciliation.
        request: Reference,
    },
    /// The desired state already held; no new effect was applied.
    Noop {
        /// Exact target identity.
        entity: Reference,
        /// Original request identity.
        request: Reference,
    },
    /// The provider may have applied an effect; confirmation is unavailable.
    OutcomeUnknown {
        /// Preserve this identity before considering a retry.
        request: Reference,
    },
}

/// Text and execution-error flag travel together; transport never parses prose.
#[derive(Clone, Debug)]
pub struct TextReply {
    text: String,
    is_error: bool,
    degraded: bool,
}

impl TextReply {
    /// Complete text, safe to put in one MCP text block.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Execution semantics for MCP `isError`.
    #[must_use]
    pub fn is_error(&self) -> bool {
        self.is_error
    }

    /// Local diagnostic fact, separate from confirmed execution outcome.
    #[must_use]
    pub fn presentation_degraded(&self) -> bool {
        self.degraded
    }
}

/// An immutable environment of trusted templates, reusable without per-call I/O.
pub struct Renderer {
    env: Environment<'static>,
}

impl Renderer {
    /// Register and parse every embedded template before admitting requests.
    pub fn new() -> Result<Self, PresentationError> {
        let mut env = Environment::empty();
        env.set_undefined_behavior(UndefinedBehavior::Strict);
        env.set_auto_escape_callback(|_| AutoEscape::None);
        env.set_trim_blocks(true);
        env.set_lstrip_blocks(true);
        env.set_keep_trailing_newline(true);
        env.set_recursion_limit(16);
        env.set_fuel(Some(50_000));
        env.set_formatter(json_bool_formatter);
        for (name, source) in [
            ("status", include_str!("../templates/status.txt.j2")),
            ("jobs", include_str!("../templates/jobs.txt.j2")),
            ("ack", include_str!("../templates/ack.txt.j2")),
            ("error", include_str!("../templates/error.txt.j2")),
        ] {
            env.add_template(name, source)
                .map_err(|_| PresentationError::TemplateSetup)?;
        }
        Ok(Self { env })
    }

    /// Render compile-time product identity with the family manifest's
    /// qualification, so the status tool reports the recorded truth.
    #[must_use]
    pub fn identity(&self, product: &str, version: &str, qualification: &str) -> TextReply {
        let (Ok(product), Ok(version), Ok(qualification)) = (
            Reference::new(product),
            Reference::new(version),
            Reference::new(qualification),
        ) else {
            return self.failure(PresentationError::InvalidReference);
        };
        let view = IdentityView {
            product: product.as_str(),
            version: version.as_str(),
            qualification: qualification.as_str(),
        };
        self.read_reply("status", &view)
    }

    /// Safe, fixed error for the product's parameterless identity tool.
    #[must_use]
    pub fn invalid_arguments(&self) -> TextReply {
        self.error_reply(
            "invalid_arguments",
            "get_status accepts no arguments.",
            Some("Call get_status with an empty arguments object."),
        )
    }

    /// Decode a bounded reference provider page and render all its rows.
    ///
    /// This is an example library API, not a newly registered MCP tool. It does
    /// not establish visibility of job titles; authorization precedes this call.
    #[must_use]
    pub fn jobs_json(&self, raw: &[u8]) -> TextReply {
        match JobPage::decode(raw).and_then(|page| page.into_view()) {
            Ok(view) => self.read_reply("jobs", &view),
            Err(error) => self.failure(error),
        }
    }

    /// Render a confirmed/unknown application receipt without changing its facts.
    #[must_use]
    pub fn acknowledgement(&self, receipt: &MutationReceipt) -> TextReply {
        let (status, entity, request, next, is_error) = match receipt {
            MutationReceipt::Committed { entity, request } => (
                "COMMITTED",
                Some(entity.as_str()),
                request.as_str(),
                None,
                false,
            ),
            MutationReceipt::Noop { entity, request } => {
                ("NOOP", Some(entity.as_str()), request.as_str(), None, false)
            }
            MutationReceipt::OutcomeUnknown { request } => (
                "OUTCOME_UNKNOWN",
                None,
                request.as_str(),
                Some("Reconcile this request_id. Do not create a replacement request."),
                true,
            ),
        };
        let view = AckView {
            status,
            entity,
            request,
            next,
        };
        match self.render("ack", &view) {
            Ok(text) => TextReply {
                text,
                is_error,
                degraded: false,
            },
            Err(_) => {
                // Bounded validated references and fixed text keep this fallback
                // independent of the failed template and the raw provider body.
                let target = entity.map_or_else(String::new, |id| format!(" entity {id}"));
                let recovery = if is_error {
                    "Reconcile this request_id before any retry."
                } else {
                    "Do not repeat the mutation to repair this response."
                };
                TextReply {
                    text: format!(
                        "{status}{target}\nRequest: {request}\nPresentation: degraded (presentation_failed).\n{recovery}\n"
                    ),
                    is_error,
                    degraded: true,
                }
            }
        }
    }

    fn render<T: Serialize>(&self, name: &str, view: &T) -> Result<String, PresentationError> {
        let template = self
            .env
            .get_template(name)
            .map_err(|_| PresentationError::RenderFailed)?;
        let mut writer = BoundedWriter::new(MAX_TEXT_BYTES);
        template
            .render_captured_to(view, &mut writer)
            .map_err(|_| PresentationError::RenderFailed)?;
        String::from_utf8(writer.bytes).map_err(|_| PresentationError::RenderFailed)
    }

    fn read_reply<T: Serialize>(&self, name: &str, view: &T) -> TextReply {
        match self.render(name, view) {
            Ok(text) => TextReply {
                text,
                is_error: false,
                degraded: false,
            },
            Err(_) => read_fallback(),
        }
    }

    fn failure(&self, error: PresentationError) -> TextReply {
        match error {
            PresentationError::BudgetExceeded => self.error_reply(
                "response_too_large",
                "The provider page cannot be safely presented.",
                Some("Request a smaller page; no rows from this page were shown."),
            ),
            _ => self.error_reply(
                "invalid_upstream_data",
                "Required result fields or references are invalid.",
                Some("Inspect the provider adapter; no successful result is claimed."),
            ),
        }
    }

    fn error_reply(
        &self,
        code: &'static str,
        message: &'static str,
        next: Option<&'static str>,
    ) -> TextReply {
        let view = ErrorView {
            code,
            message,
            next,
        };
        match self.render("error", &view) {
            Ok(text) => TextReply {
                text,
                is_error: true,
                degraded: false,
            },
            Err(_) => read_fallback(),
        }
    }
}

fn read_fallback() -> TextReply {
    TextReply {
        text: "ERROR presentation_failed: the read-only result could not be formatted.\nEffect: none.\nNext: inspect local presentation diagnostics.\n".to_owned(),
        is_error: true,
        degraded: true,
    }
}

#[derive(Serialize)]
struct IdentityView<'a> {
    product: &'a str,
    version: &'a str,
    qualification: &'a str,
}

#[derive(Serialize)]
struct ErrorView {
    code: &'static str,
    message: &'static str,
    next: Option<&'static str>,
}

#[derive(Serialize)]
struct AckView<'a> {
    status: &'static str,
    entity: Option<&'a str>,
    request: &'a str,
    next: Option<&'static str>,
}

// External DTOs intentionally do not derive Serialize. Unknown extra provider
// fields are ignored; required fields still have to exist with the right types.
#[derive(Deserialize)]
struct RawPage {
    jobs: Vec<RawJob>,
    has_more: bool,
    next_cursor: Option<String>,
}

#[derive(Deserialize)]
struct RawJob {
    id: String,
    status: JobState,
    title: Option<String>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum JobState {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
    #[serde(other)]
    Unknown,
}

impl JobState {
    fn label(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Unknown => "unknown",
        }
    }
}

struct Job {
    id: Reference,
    state: JobState,
    title: Option<String>,
}

struct JobPage {
    jobs: Vec<Job>,
    cursor: Option<String>,
}

impl JobPage {
    fn decode(raw: &[u8]) -> Result<Self, PresentationError> {
        if raw.len() > MAX_SOURCE_BYTES {
            return Err(PresentationError::BudgetExceeded);
        }
        let page: RawPage =
            serde_json::from_slice(raw).map_err(|_| PresentationError::InvalidSource)?;
        if page.jobs.len() > MAX_PAGE_ROWS {
            return Err(PresentationError::BudgetExceeded);
        }
        if page.has_more != page.next_cursor.is_some() {
            return Err(PresentationError::InvalidSource);
        }
        if page.next_cursor.as_ref().is_some_and(|cursor| {
            cursor.is_empty()
                || cursor.len() > MAX_CURSOR_BYTES
                || !cursor
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.:+/=-".contains(&b))
        }) {
            return Err(PresentationError::InvalidReference);
        }
        let jobs = page
            .jobs
            .into_iter()
            .map(|job| {
                Ok(Job {
                    id: Reference::new(job.id)?,
                    state: job.status,
                    title: job.title,
                })
            })
            .collect::<Result<Vec<_>, PresentationError>>()?;
        Ok(Self {
            jobs,
            cursor: page.next_cursor,
        })
    }

    fn into_view(self) -> Result<JobsView, PresentationError> {
        let unknown_statuses = self
            .jobs
            .iter()
            .filter(|job| matches!(job.state, JobState::Unknown))
            .count();
        let rows = self
            .jobs
            .into_iter()
            .map(|job| {
                Ok(JobRowView {
                    id: job.id.0,
                    state: job.state.label(),
                    title: quoted_label(job.title.as_deref())?,
                })
            })
            .collect::<Result<Vec<_>, PresentationError>>()?;
        Ok(JobsView {
            returned: rows.len(),
            has_more: self.cursor.is_some(),
            unknown_statuses,
            rows,
            cursor: self.cursor,
        })
    }
}

#[derive(Serialize)]
struct JobsView {
    returned: usize,
    has_more: bool,
    unknown_statuses: usize,
    rows: Vec<JobRowView>,
    cursor: Option<String>,
}

#[derive(Serialize)]
struct JobRowView {
    id: String,
    state: &'static str,
    title: String,
}

fn quoted_label(input: Option<&str>) -> Result<String, PresentationError> {
    let Some(input) = input else {
        return Ok("(not provided)".to_owned());
    };
    let mut output = String::from("\"");
    for ch in input.chars() {
        let visible = if matches!(
            ch,
            '\u{007f}'..='\u{009f}'
                | '\u{061c}'
                | '\u{200e}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        ) {
            format!("\\u{{{:x}}}", u32::from(ch))
        } else {
            ch.to_string()
        };
        let encoded =
            serde_json::to_string(&visible).map_err(|_| PresentationError::RenderFailed)?;
        // A JSON string always starts/ends with an ASCII quote; only that
        // deliberate wrapper is removed. Unicode/escape sequences remain whole.
        let piece = &encoded[1..encoded.len() - 1];
        if output.len() + piece.len() + 4 > MAX_LABEL_BYTES {
            output.push_str("...");
            break;
        }
        output.push_str(piece);
    }
    output.push('"');
    Ok(output)
}

struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl BoundedWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("rendered text budget exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
