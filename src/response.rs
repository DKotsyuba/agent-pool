//! Closed embedded templates for product tools. Only typed views cross this boundary.
use minijinja::{AutoEscape, Environment, UndefinedBehavior};
use serde::Serialize;
use std::io::{self, Write};

pub struct Templates {
    env: Environment<'static>,
}
impl Templates {
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
        for (name, source) in entries {
            env.add_template(name, source)
                .map_err(|_| "template_invalid")?;
        }
        Ok(Self { env })
    }
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
struct Limit(Vec<u8>);
impl Write for Limit {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.0.len().saturating_add(bytes.len()) > 8192 {
            return Err(io::Error::other("response limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "Test assertions")]
mod tests {
    use super::*;
    #[test]
    fn strict_missing_rejected() {
        let r = Templates::new(&[("test", "{{ missing }}")]).unwrap();
        assert!(r.render("test", &()).is_err());
    }
    #[test]
    fn cap_discards_output() {
        let r = Templates::new(&[("test", "{{ data }}")]).unwrap();
        assert!(
            r.render("test", &serde_json::json!({"data":"x".repeat(8193)}))
                .is_err()
        );
    }
}
