//! Closed embedded templates for product tools. Only typed views cross this boundary.
use minijinja::{AutoEscape, Environment, UndefinedBehavior};
use serde::Serialize;
use std::io::{self, Write};

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
        env.add_filter("quote", |value: String| {
            serde_json::to_string(&value).unwrap_or_else(|_| "\"unavailable\"".into())
        });
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
            .render_captured_to(view, &mut writer)
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
