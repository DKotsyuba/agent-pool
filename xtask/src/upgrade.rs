//! Three-way, read-only update plans. Never execute code from the proposed template.
use crate::{Project, Result, files};
use clap::Subcommand;
use serde::Serialize;
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};
#[derive(Subcommand)]
pub enum Template {
    /// Compare managed infrastructure with another trusted template checkout.
    Diff {
        #[arg(long)]
        from: PathBuf,
    },
    /// The first implementation deliberately requires dry-run; apply via a reviewed Git change.
    Upgrade {
        #[arg(long)]
        from: PathBuf,
        #[arg(long, required = true)]
        dry_run: bool,
    },
}
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Decision {
    Unchanged,
    Add,
    Update,
    Delete,
    KeepLocal,
    Conflict,
}
fn classify(base: Option<&[u8]>, local: Option<&[u8]>, next: Option<&[u8]>) -> Decision {
    if local == next {
        return Decision::Unchanged;
    }
    if local == base {
        return match (base, next) {
            (None, Some(_)) => Decision::Add,
            (Some(_), None) => Decision::Delete,
            _ => Decision::Update,
        };
    }
    if next == base {
        return Decision::KeepLocal;
    }
    Decision::Conflict
}
fn managed(path: &Path) -> bool {
    path.starts_with("xtask")
        || path.starts_with("crates/mcp-presentation")
        || path.starts_with("crates/family-delivery")
        || path.starts_with(".cargo")
        || path.starts_with(".github")
        || [
            "deny.toml",
            "rust-toolchain.toml",
            "install.sh",
            "tests/protocol.rs",
        ]
        .iter()
        .any(|s| path == Path::new(s))
}
pub fn execute(project: &Project, command: Template) -> Result<()> {
    let from = match command {
        Template::Diff { from } | Template::Upgrade { from, .. } => from,
    };
    let baseline = files(&project.root.join(".family/baseline"))?;
    if baseline.is_empty() {
        return Err("no recorded template baseline; refuse to guess ownership".into());
    }
    let mut next = files(&from.join("scaffold"))?;
    if next.is_empty() {
        return Err("candidate scaffold is empty or missing".into());
    }
    let repo = project.family["repository"]
        .as_str()
        .ok_or("repository missing")?;
    for bytes in next.values_mut() {
        *bytes = std::str::from_utf8(bytes)?
            .replace("agent-pool", &project.name)
            .replace("", repo)
            .replace("AGENT_POOL", &project.name.replace('-', "_").to_uppercase())
            .into_bytes();
    }
    let paths: BTreeSet<_> = baseline
        .keys()
        .chain(next.keys())
        .filter(|p| managed(p))
        .cloned()
        .collect();
    let mut plan = Vec::new();
    for path in paths {
        let local_path = project.root.join(&path);
        // Reject every symlink ancestor, not just the leaf.
        let mut prefix = project.root.clone();
        for part in path.components() {
            if !matches!(part, std::path::Component::Normal(_)) {
                return Err("invalid managed path".into());
            }
            prefix.push(part);
            if fs::symlink_metadata(&prefix).is_ok_and(|m| m.file_type().is_symlink()) {
                return Err("symlink in managed destination".into());
            }
        }
        let local = match fs::read(&local_path) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        plan.push(serde_json::json!({"path":path, "decision":classify(baseline.get(&path).map(Vec::as_slice), local.as_deref(), next.get(&path).map(Vec::as_slice))}));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(
            &serde_json::json!({"dry_run":true,"writes":0,"plan":plan,"manual_review":["Cargo.toml dependency changes", "family.toml profiles and versions", "product source and state migrations"]})
        )?
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn same() {
        assert_eq!(
            classify(Some(b"a"), Some(b"a"), Some(b"a")),
            Decision::Unchanged
        );
    }
    #[test]
    fn update() {
        assert_eq!(
            classify(Some(b"a"), Some(b"a"), Some(b"b")),
            Decision::Update
        );
    }
    #[test]
    fn preserve_local() {
        assert_eq!(
            classify(Some(b"a"), Some(b"x"), Some(b"a")),
            Decision::KeepLocal
        );
    }
    #[test]
    fn conflict() {
        assert_eq!(
            classify(Some(b"a"), Some(b"x"), Some(b"b")),
            Decision::Conflict
        );
    }
    #[test]
    fn add() {
        assert_eq!(classify(None, None, Some(b"a")), Decision::Add);
    }
    #[test]
    fn delete() {
        assert_eq!(classify(Some(b"a"), Some(b"a"), None), Decision::Delete);
    }
    #[test]
    fn local_delete_conflict() {
        assert_eq!(classify(Some(b"a"), None, Some(b"b")), Decision::Conflict);
    }
    #[test]
    fn product_not_owned() {
        assert!(!managed(Path::new("src/main.rs")));
        assert!(!managed(Path::new("Cargo.toml")));
    }
}
