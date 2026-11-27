//! Closed embedded templates for product tools. Only typed views cross this boundary.
use minijinja::{AutoEscape, Environment, UndefinedBehavior};
use serde::Serialize;
use std::io::{self, Write};

/// Bounds a display label in UTF-8 bytes and keeps it on one visible line.
pub(crate) fn one_line(value: &str, limit: usize) -> String {
    let end = value.floor_char_boundary(limit.min(value.len()));
    let mut label: String = value[..end]
        .chars()
        .map(|c| {
            if c.is_control()
                || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
            {
                ' '
            } else {
                c
            }
        })
        .collect();
    if end < value.len() {
        label.push('…');
    }
    label
}

/// Formats events from the past hour relative to the render time.
fn event_time(recorded_at_ms: u64, now_ms: u64) -> String {
    match now_ms.checked_sub(recorded_at_ms).map(|age| age / 1000) {
        Some(0..=59) => "just now".into(),
        Some(age @ 60..=3599) => format!("{}m ago", age / 60),
        _ => i64::try_from(recorded_at_ms)
            .ok()
            .and_then(chrono::DateTime::from_timestamp_millis)
            .map_or_else(
                || "time unavailable".into(),
                |time| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            ),
    }
}

/// Closed immutable MiniJinja environment; rendering has no I/O or domain side effects.
pub struct Templates {
    /// Embedded templates and explicitly registered formatting-only filters.
    env: Environment<'static>,
}
impl Templates {
    /// Registers static templates with strict missing fields and bounded execution.
    pub fn new(entries: &[(&'static str, &'static str)]) -> Result<Self, &'static str> {
        let mut env = Environment::empty();
        env.set_undefined_behavior(UndefinedBehavior::Strict);
        env.set_auto_escape_callback(|_| AutoEscape::None);
        env.set_trim_blocks(true);
        env.set_lstrip_blocks(true);
        env.set_keep_trailing_newline(true);
        env.set_fuel(Some(50_000));
        env.set_recursion_limit(16);
        env.set_formatter(mcp_presentation::json_bool_formatter);
        env.add_test("defined", |value: minijinja::Value| !value.is_undefined());
        env.add_filter("one_line", |value: String, limit: usize| {
            one_line(&value, limit)
        });
        env.add_filter("quote", |value: String| {
            serde_json::to_string(&value).unwrap_or_else(|_| "\"unavailable\"".into())
        });
        env.add_filter("event_time", event_time);
        for (name, source) in entries {
            env.add_template(name, source)
                .map_err(|_| "template_invalid")?;
        }
        Ok(Self { env })
    }
    /// Renders a bounded typed view privately, discarding bytes on failure or output over 16 KiB.
    pub fn render<T: Serialize>(&self, name: &str, view: &T) -> Result<String, &'static str> {
        let mut writer = Limit(Vec::new());
        self.env
            .get_template(name)
            .map_err(|_| "template_missing")?
            .render_captured_to(
                minijinja::context!(now_ms => crate::observer::now().unwrap_or_default(), ..minijinja::Value::from_serialize(view)),
                &mut writer,
            )
            .map_err(|_| "presentation_failed")?;
        String::from_utf8(writer.0).map_err(|_| "presentation_encoding")
    }
}
/// Private all-or-error buffer; partial template output never reaches MCP.
struct Limit(
    /// Private accumulated UTF-8 bytes, published only after the complete render succeeds.
    Vec<u8>,
);
impl Write for Limit {
    /// Rejects an entire chunk if it would exceed the product's 16 KiB cap.
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.0.len().saturating_add(bytes.len()) > 16384 {
            return Err(io::Error::other("response limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    /// In-memory output has no external buffer to flush.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
/// Pure template safety checks; no provider or file access occurs.
#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "Test assertions")]
mod tests {
    use super::*;
    /// Recent times are relative. Older or future times use absolute UTC.
    #[test]
    fn event_time_uses_relative_or_utc() {
        assert_eq!(event_time(0, 59_999), "just now");
        assert_eq!(event_time(0, 60_000), "1m ago");
        assert_eq!(event_time(0, 3_599_999), "59m ago");
        assert_eq!(event_time(0, 3_600_000), "1970-01-01T00:00:00Z");
        assert_eq!(event_time(1_000, 0), "1970-01-01T00:00:01Z");
    }
    /// Display labels keep UTF-8 boundaries and cannot create additional lines.
    #[test]
    fn display_label_is_bounded_and_single_line() {
        assert_eq!(one_line("Name\n\trole\u{2028}next", 80), "Name  role next");
        assert_eq!(one_line("A🦀Z", 4), "A…");
    }
    #[test]
    /// Missing required values fail despite successful startup template parsing.
    fn strict_missing_rejected() {
        let r = Templates::new(&[("test", "{{ missing }}")]).unwrap();
        assert!(r.render("test", &()).is_err());
    }
    #[test]
    /// One byte over the hard cap produces no partial answer.
    fn cap_discards_output() {
        let r = Templates::new(&[("test", "{{ data }}")]).unwrap();
        assert!(
            r.render("test", &serde_json::json!({"data":"x".repeat(16385)}))
                .is_err()
        );
    }
}
