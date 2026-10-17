//! Rust-only product automation; no implicit remote writes or runtime interpreter.
#![allow(clippy::print_stdout, reason = "Developer CLI, not MCP")]
mod release;
mod upgrade;

use clap::{Parser, Subcommand};
use family_delivery::{Manifest, Result};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Task,
}
#[derive(Subcommand)]
enum Task {
    /// Network preparation without changing Cargo.lock.
    Prepare,
    /// Check the canonical source without formatting or updating snapshots.
    Check,
    /// Check declarative Rust family invariants.
    Standard {
        #[command(subcommand)]
        command: Standard,
    },
    /// Verify or explicitly update the real tool-discovery snapshot.
    Contract {
        #[command(subcommand)]
        command: Contract,
    },
    /// Add a typed, registered, non-executing tool skeleton and fixture.
    AddTool {
        name: String,
        #[arg(long, default_value = "read")]
        effect: String,
        #[arg(long, default_value = "entity")]
        response: String,
        #[arg(long)]
        idempotent: bool,
    },
    /// Focused tests: protocol, presentation or delivery.
    Test { suite: String },
    /// Build a new immutable single-binary directory, or verify an existing one.
    Package {
        #[command(subcommand)]
        command: Option<PackageCommand>,
    },
    /// Version preparation, authenticated publishing or release observation.
    Release {
        #[command(subcommand)]
        command: release::Release,
    },
    /// Read-only three-way template update plan.
    Template {
        #[command(subcommand)]
        command: upgrade::Template,
    },
}
#[derive(Subcommand)]
enum Standard {
    Check,
}
#[derive(Subcommand)]
enum Contract {
    Check,
    Update,
}
#[derive(Subcommand)]
enum PackageCommand {
    Verify { directory: PathBuf },
}

/// Workspace identity and gate inputs loaded once for a developer command.
pub(crate) struct Project {
    /// Product root containing the Cargo and family manifests.
    pub root: PathBuf,
    /// Root application package and executable name.
    pub name: String,
    /// Shared application version declared by the workspace.
    pub version: String,
    /// Cargo's effective build output directory, including environment overrides.
    pub target_dir: PathBuf,
    /// Whether workspace features or incomplete metadata require both feature gates.
    has_features: bool,
    /// Parsed root Cargo manifest used for structural checks.
    pub manifest: toml::Value,
    /// Parsed product profiles, identity and qualification declarations.
    pub family: toml::Value,
}

fn helper(root: &Path, program: &str) -> Command {
    let mut command = Command::new(program);
    command.current_dir(root);
    // Only gh needs these transport credentials. This does not sandbox credential files.
    if program != "gh" {
        for name in [
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "GH_ENTERPRISE_TOKEN",
            "GITHUB_ENTERPRISE_TOKEN",
        ] {
            command.env_remove(name);
        }
    }
    command
}

/// Capture bounded output and stop a hung direct helper; no descendant-tree guarantee.
pub(crate) fn capture(root: &Path, program: &str, args: &[&str], seconds: u64) -> Result<Vec<u8>> {
    let mut child = helper(root, program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdout = child.stdout.take().ok_or("helper stdout unavailable")?;
    let too_large = Arc::new(AtomicBool::new(false));
    let flag = too_large.clone();
    let reader = std::thread::spawn(move || -> std::io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        stdout
            .by_ref()
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 4 * 1024 * 1024 {
            flag.store(true, Ordering::Relaxed);
        }
        Ok(bytes)
    });
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let status = loop {
        if Instant::now() >= deadline || too_large.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            return Err("helper deadline or output budget exceeded".into());
        }
        if let Some(status) = child.try_wait()? {
            break status;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    if !status.success() {
        return Err(format!("{program} failed; rerun it locally to inspect diagnostics").into());
    }
    while !reader.is_finished() {
        if Instant::now() >= deadline {
            return Err("helper output did not close".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let result = reader.join().map_err(|_| "helper output thread failed")??;
    if too_large.load(Ordering::Relaxed) {
        return Err("helper output too large".into());
    }
    Ok(result)
}
pub(crate) fn text(root: &Path, program: &str, args: &[&str]) -> Result<String> {
    Ok(String::from_utf8(capture(root, program, args, 60)?)?
        .trim()
        .to_owned())
}
pub(crate) fn run(root: &Path, program: &str, args: &[&str]) -> Result<()> {
    eprintln!("xtask: {program} {}", args.join(" "));
    if !helper(root, program).args(args).status()?.success() {
        return Err(format!("{program} failed").into());
    }
    Ok(())
}

fn tool_name_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 40
        && name.as_bytes()[0].is_ascii_lowercase()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}
fn check_destination(root: &Path, relative: &Path) -> Result<()> {
    let mut path = root.to_path_buf();
    for component in relative.components() {
        if !matches!(component, std::path::Component::Normal(_)) {
            return Err("invalid generated path".into());
        }
        path.push(component);
        if fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err("generated path has a symlink ancestor".into());
        }
    }
    Ok(())
}

/// Detect whether default and all-feature gates can differ from Cargo metadata v1.
/// Only nonempty, complete workspace membership with empty feature maps returns false;
/// dependency features are irrelevant, while implicit optional features count as features.
fn workspace_has_features(metadata: &Value) -> bool {
    let Some(members) = metadata["workspace_members"]
        .as_array()
        .filter(|members| !members.is_empty())
    else {
        return true;
    };
    let Some(packages) = metadata["packages"].as_array() else {
        return true;
    };
    members.iter().any(|member| {
        member.as_str().is_none()
            || !packages
                .iter()
                .find(|package| package["id"] == *member)
                .and_then(|package| package["features"].as_object())
                .is_some_and(|features| features.is_empty())
    })
}

impl Project {
    /// Read product manifests and locked Cargo metadata without changing the lockfile.
    /// Reuse that metadata for output paths and feature gates; propagate I/O, parsing,
    /// missing identity and helper errors before running the requested command.
    fn load() -> Result<Self> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .ok_or("missing project root")?
            .to_path_buf();
        let manifest: toml::Value = toml::from_str(&fs::read_to_string(root.join("Cargo.toml"))?)?;
        let family: toml::Value = toml::from_str(&fs::read_to_string(root.join("family.toml"))?)?;
        let name = manifest["package"]["name"]
            .as_str()
            .ok_or("package name missing")?
            .to_owned();
        let version = manifest["workspace"]["package"]["version"]
            .as_str()
            .ok_or("workspace version missing")?
            .to_owned();
        let metadata: Value = serde_json::from_slice(&capture(
            &root,
            "cargo",
            &["metadata", "--locked", "--no-deps", "--format-version", "1"],
            120,
        )?)?;
        let target_dir = PathBuf::from(
            metadata["target_directory"]
                .as_str()
                .ok_or("target_directory missing")?,
        );
        let has_features = workspace_has_features(&metadata);
        Ok(Self {
            root,
            name,
            version,
            target_dir,
            has_features,
            manifest,
            family,
        })
    }
    pub(crate) fn binary(&self, release: bool) -> PathBuf {
        self.target_dir
            .join(if release { "release" } else { "debug" })
            .join(&self.name)
    }
    fn build(&self, release: bool) -> Result<()> {
        let mut args = vec![
            "build",
            "--frozen",
            "--package",
            &self.name,
            "--bin",
            &self.name,
        ];
        if release {
            args.push("--release");
        }
        run(&self.root, "cargo", &args)
    }
    fn catalog(&self) -> Result<Value> {
        self.build(false)?;
        let binary = self.binary(false);
        Ok(serde_json::from_slice(&capture(
            &self.root,
            binary.to_str().ok_or("non-UTF8 binary path")?,
            &["contract", "export"],
            10,
        )?)?)
    }
    fn contract(&self, update: bool) -> Result<()> {
        let catalog = self.catalog()?;
        let path = self.root.join("schemas/tools.json");
        check_destination(&self.root, Path::new("schemas/tools.json"))?;
        if update {
            fs::write(
                path,
                format!("{}\n", serde_json::to_string_pretty(&catalog)?),
            )?;
        } else {
            let snapshot: Value = serde_json::from_slice(&fs::read(path)?)?;
            if catalog != snapshot {
                return Err("contract drift: review cargo xtask contract update".into());
            }
        }
        Ok(())
    }
    fn standard(&self) -> Result<()> {
        let w = &self.manifest["workspace"];
        if w["resolver"].as_str() != Some("3")
            || w["package"]["edition"].as_str() != Some("2024")
            || self.manifest["package"]["publish"].as_bool() != Some(false)
            || self.manifest["lints"]["workspace"].as_bool() != Some(true)
        {
            return Err("Rust workspace invariant failed".into());
        }
        if self.family["product"].as_str() != Some(self.name.as_str())
            || self.family["standard_version"].as_str() != Some("1.0.0-rc.2")
            || self.family["response_profile"].as_str() != Some("rust-minijinja-v1")
        {
            return Err("family identity/standard mismatch".into());
        }
        let toolchain: toml::Value =
            toml::from_str(&fs::read_to_string(self.root.join("rust-toolchain.toml"))?)?;
        if toolchain["toolchain"]["channel"].as_str() != w["package"]["rust-version"].as_str() {
            return Err("candidate compiler baseline mismatch".into());
        }
        for file in [
            "Cargo.lock",
            "AGENTS.md",
            "SECURITY.md",
            "CHANGELOG.md",
            "deny.toml",
            "schemas/tools.json",
            "docs/MCP_RESPONSE_STANDARD.md",
        ] {
            if !self.root.join(file).is_file() {
                return Err(format!("required file absent: {file}").into());
            }
        }
        for directory in ["src", "xtask", "crates"] {
            for path in files(&self.root.join(directory))?.keys() {
                if matches!(
                    path.extension().and_then(|s| s.to_str()),
                    Some("py" | "js" | "ts" | "rb")
                ) {
                    return Err("non-Rust tooling source".into());
                }
            }
        }
        println!("standard: structural checks passed (not a semantic or security certificate)");
        Ok(())
    }
    /// Run structural, formatting, Clippy, test, rustdoc and catalog gates in order.
    /// Always check all features; also check defaults unless metadata proves every
    /// workspace member has no features. Stop on the first failed gate without fixing it.
    fn check(&self) -> Result<()> {
        self.standard()?;
        run(&self.root, "cargo", &["fmt", "--all", "--check"])?;
        for args in [
            vec![
                "clippy",
                "--frozen",
                "--workspace",
                "--all-targets",
                "--",
                "-D",
                "warnings",
            ],
            vec![
                "clippy",
                "--frozen",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
            ],
            vec!["test", "--frozen", "--workspace"],
            vec!["test", "--frozen", "--workspace", "--all-features"],
        ] {
            if self.has_features || args.contains(&"--all-features") {
                run(&self.root, "cargo", &args)?;
            }
        }
        if !helper(&self.root, "cargo")
            .args([
                "doc",
                "--frozen",
                "--workspace",
                "--all-features",
                "--no-deps",
            ])
            .env("RUSTDOCFLAGS", "-D warnings")
            .status()?
            .success()
        {
            return Err("rustdoc failed".into());
        }
        self.contract(false)
    }
    fn add_tool(&self, name: &str, effect: &str, response: &str, idempotent: bool) -> Result<()> {
        if !tool_name_valid(name) {
            return Err("invalid tool name".into());
        }
        if !["read", "write", "external-write"].contains(&effect)
            || !["entity", "page", "ack"].contains(&response)
        {
            return Err("unsupported tool effect/response profile".into());
        }
        check_destination(&self.root, Path::new("src/tools/mod.rs"))?;
        let registry_path = self.root.join("src/tools/mod.rs");
        let mut registry = fs::read_to_string(&registry_path)?;
        if self
            .catalog()?
            .as_array()
            .ok_or("catalog not array")?
            .iter()
            .any(|t| t["name"] == name)
        {
            return Err("tool already exists".into());
        }
        let source = include_str!("../templates/tool.rs.txt")
            .replace("@@TOOL@@", name)
            .replace("@@EFFECT@@", effect)
            .replace(
                "@@READ_ONLY@@",
                if effect == "read" { "true" } else { "false" },
            )
            .replace(
                "@@DESTRUCTIVE@@",
                if effect == "read" { "false" } else { "true" },
            )
            .replace("@@IDEMPOTENT@@", if idempotent { "true" } else { "false" })
            .replace(
                "@@OPEN_WORLD@@",
                if effect == "external-write" {
                    "true"
                } else {
                    "false"
                },
            );
        // Prefix Rust module names, so an MCP name such as `match` is not a Rust keyword.
        let module = format!("tool_{name}");
        let edits = [
            (
                "// xtask:modules",
                format!("#[path = \"{name}.rs\"]\nmod {module};"),
            ),
            ("// xtask:definitions", format!("{module}::definition(),")),
            (
                "// xtask:templates",
                format!("(\"{name}\", {module}::TEMPLATE),"),
            ),
            (
                "// xtask:readiness",
                format!("(\"{name}\", {module}::IMPLEMENTED),"),
            ),
            (
                "// xtask:routes",
                format!("\"{name}\" => Some({module}::call(args, _templates).await),"),
            ),
        ];
        for (marker, line) in edits {
            if registry.matches(marker).count() != 1 {
                return Err("registry marker missing or duplicated".into());
            }
            registry = registry.replace(marker, &format!("{line}\n        {marker}"));
        }
        let additions = [
            (format!("src/tools/{name}.rs"), source),
            (
                format!("assets/mcp/tools/{name}.txt.j2"),
                "ERROR {{ code }}: {{ message }}\n".to_owned(),
            ),
            (
                format!("tests/fixtures/{name}.txt"),
                format!(
                    "ERROR not_implemented: {name} has no implementation. No effect was performed.\n"
                ),
            ),
            (
                format!("docs/tools/{name}.md"),
                format!(
                    "# {name}\n\nEffect: {effect}. Intended response: {response}.\n\nStatus: not implemented. Define arguments, DTO, outcome, view and recovery policy before setting IMPLEMENTED=true. No effects or success are fabricated by this skeleton.\n"
                ),
            ),
        ];
        for (path, _) in &additions {
            check_destination(&self.root, Path::new(path))?;
            if fs::symlink_metadata(self.root.join(path)).is_ok() {
                return Err("generated path already exists".into());
            }
        }
        for (path, contents) in additions {
            let path = self.root.join(path);
            fs::create_dir_all(path.parent().ok_or("missing parent")?)?;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)?;
            std::io::Write::write_all(&mut file, contents.as_bytes())?;
        }
        fs::write(registry_path, registry)?;
        run(&self.root, "cargo", &["fmt", "--all"])?;
        self.contract(true)?;
        run(
            &self.root,
            "cargo",
            &["test", "--frozen", "--package", &self.name],
        )?;
        println!(
            "tool generated and registered; release remains blocked until IMPLEMENTED and its evidence are reviewed"
        );
        Ok(())
    }
    pub(crate) fn package(&self) -> Result<PathBuf> {
        self.standard()?;
        if !text(&self.root, "git", &["status", "--porcelain"])?.is_empty() {
            return Err("commit product changes before packaging".into());
        }
        let commit = text(&self.root, "git", &["rev-parse", "HEAD"])?;
        let target = text(&self.root, "rustc", &["-vV"])?
            .lines()
            .find_map(|s| s.strip_prefix("host: "))
            .ok_or("host target missing")?
            .to_owned();
        let state_schema = match self.family["profiles"]["state"].as_str() {
            Some("local") => family_delivery::CURRENT_STATE_SCHEMA,
            Some("none") => 0,
            other => {
                return Err(format!("unsupported state profile for packaging: {other:?}").into());
            }
        };
        self.build(true)?;
        let output = self
            .root
            .join("dist")
            .join(format!("{}-{}-{}", self.name, self.version, target));
        fs::create_dir_all(output.parent().ok_or("package parent absent")?)?;
        let manifest = Manifest {
            schema_version: 1,
            profile: "single-binary-v1".into(),
            product: self.name.clone(),
            version: self.version.clone(),
            source_commit: commit,
            target: target.clone(),
            binary: format!("{}-{target}", self.name),
            size: 1,
            sha256: "0".repeat(64),
            state_schema,
            run_id: std::env::var("GITHUB_RUN_ID")
                .ok()
                .and_then(|s| s.parse().ok()),
            run_attempt: std::env::var("GITHUB_RUN_ATTEMPT")
                .ok()
                .and_then(|s| s.parse().ok()),
        };
        family_delivery::package(&self.binary(true), &output, manifest)?;
        println!("{}", output.display());
        Ok(output)
    }
}
pub(crate) fn files(root: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>> {
    fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) -> Result<()> {
        if !dir.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                return Err("managed trees must not contain symlinks".into());
            }
            if entry.file_name() == "target" || entry.file_name() == ".git" {
                continue;
            }
            if kind.is_dir() {
                walk(base, &path, out)?;
            } else if kind.is_file() {
                if entry.metadata()?.len() > 4 * 1024 * 1024 {
                    return Err("managed file too large".into());
                }
                out.insert(path.strip_prefix(base)?.to_owned(), fs::read(path)?);
            } else {
                return Err("special managed file".into());
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out)?;
    Ok(out)
}
fn main_result() -> Result<()> {
    let command = Cli::parse().command;
    let project = Project::load()?;
    match command {
        Task::Prepare => run(&project.root, "cargo", &["fetch", "--locked"]),
        Task::Check => project.check(),
        Task::Standard {
            command: Standard::Check,
        } => project.standard(),
        Task::Contract { command } => project.contract(matches!(command, Contract::Update)),
        Task::AddTool {
            name,
            effect,
            response,
            idempotent,
        } => project.add_tool(&name, &effect, &response, idempotent),
        Task::Test { suite } => match suite.as_str() {
            "presentation" => run(
                &project.root,
                "cargo",
                &["test", "--frozen", "-p", "mcp-presentation"],
            ),
            "delivery" => run(
                &project.root,
                "cargo",
                &["test", "--frozen", "-p", "family-delivery"],
            ),
            "protocol" => run(
                &project.root,
                "cargo",
                &[
                    "test",
                    "--frozen",
                    "-p",
                    &project.name,
                    "--test",
                    "protocol",
                ],
            ),
            _ => Err("unknown test suite".into()),
        },
        Task::Package { command: None } => project.package().map(|_| ()),
        Task::Package {
            command: Some(PackageCommand::Verify { directory }),
        } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&family_delivery::verify(&directory)?)?
            );
            Ok(())
        }
        Task::Release { command } => release::execute(&project, command),
        Task::Template { command } => upgrade::execute(&project, command),
    }
}
fn main() -> ExitCode {
    match main_result() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask: {e}");
            ExitCode::FAILURE
        }
    }
}
/// Regression checks for developer-tool input and feature-gate boundaries.
#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "Test assertions")]
mod tests {
    use super::*;

    /// Skip duplicate gates only when every workspace member is provably featureless.
    #[test]
    fn workspace_feature_gates_are_conservative() {
        let mut metadata = json!({
            "workspace_members": ["application", "xtask"],
            "packages": [
                {"id": "application", "features": {}},
                {"id": "xtask", "features": {}},
                {"id": "dependency", "features": {"default": ["serde"]}}
            ]
        });
        assert!(!workspace_has_features(&metadata));
        for features in [
            json!({"default": []}),
            json!({"optional_dep": ["dep:optional_dep"]}),
        ] {
            metadata["packages"][1]["features"] = features;
            assert!(workspace_has_features(&metadata));
        }
        metadata["packages"][1]["features"] = Value::Null;
        assert!(workspace_has_features(&metadata));
        metadata["packages"][1]["features"] = json!({});
        metadata["workspace_members"] = json!(["missing-member"]);
        assert!(workspace_has_features(&metadata));
        metadata["workspace_members"] = json!([]);
        assert!(workspace_has_features(&metadata));
        assert!(workspace_has_features(&json!({})));
    }

    #[test]
    fn tool_identifiers() {
        for name in ["list_items", "match", "self"] {
            assert!(tool_name_valid(name));
        }
        for name in ["", "../../x", "X", "1x", "x;bad"] {
            assert!(!tool_name_valid(name));
        }
    }
    #[test]
    fn unsafe_relative_paths_rejected() {
        let dir = tempfile::tempdir().unwrap();
        assert!(check_destination(dir.path(), Path::new("../escape")).is_err());
        assert!(check_destination(dir.path(), Path::new("/absolute")).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn linked_destination_parent_rejected() {
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("missing", dir.path().join("src")).unwrap();
        assert!(check_destination(dir.path(), Path::new("src/tools/x.rs")).is_err());
    }
}
