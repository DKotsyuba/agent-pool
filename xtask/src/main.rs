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
        /// Explicit new artifact directory; omitted uses the product's dist directory.
        #[arg(long)]
        out: Option<PathBuf>,
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
            "ACTIONS_RUNTIME_TOKEN",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            "GITHUB_OUTPUT",
            "GITHUB_ENV",
            "GITHUB_PATH",
            "GITHUB_STATE",
            "GITHUB_STEP_SUMMARY",
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
/// Private directory for test temporaries on tmpfs (`/dev/shm`), so
/// filesystem-heavy tests avoid slow disk sync. Tests keep the inherited `TMPDIR`
/// when tmpfs is absent, cannot execute files, has less than 1 GiB free, or
/// `XTASK_TEST_TMPFS=0` is set. The directory is removed on drop; directories
/// left by exited runs of the same PID namespace are removed on the next start.
struct TestScratch(Option<PathBuf>);

impl TestScratch {
    /// Creates a fresh `0700` directory, or none when tmpfs is unsuitable.
    fn create() -> Self {
        if std::env::var_os("XTASK_TEST_TMPFS").is_some_and(|value| value == "0") {
            return Self(None);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let base = Path::new("/dev/shm");
            if base.is_dir() {
                let namespace = pid_namespace();
                remove_stale_scratch(base, &namespace);
                let dir = base.join(format!(
                    "xtask-{}-{namespace}-{}",
                    std::process::id(),
                    random_suffix()
                ));
                if fs::DirBuilder::new().mode(0o700).create(&dir).is_ok() {
                    if scratch_usable(&dir) {
                        return Self(Some(dir));
                    }
                    drop(fs::remove_dir_all(&dir));
                }
            }
        }
        Self(None)
    }

    /// Runs `cargo <args>` with `TMPDIR`, `TMP` and `TEMP` set to the directory.
    fn cargo(&self, root: &Path, args: &[&str]) -> Result<()> {
        eprintln!("xtask: cargo {}", args.join(" "));
        let mut command = helper(root, "cargo");
        command.args(args);
        if let Some(dir) = &self.0 {
            for name in ["TMPDIR", "TMP", "TEMP"] {
                command.env(name, dir);
            }
        }
        if !command.status()?.success() {
            return Err("cargo failed".into());
        }
        Ok(())
    }
}

impl Drop for TestScratch {
    fn drop(&mut self) {
        if let Some(dir) = &self.0 {
            owner_writable(dir);
            // Best effort: a leftover is removed by the next run's stale cleanup.
            drop(fs::remove_dir_all(dir));
        }
    }
}

/// True when a script in `dir` can execute and at least 1 GiB is free there.
#[cfg(unix)]
fn scratch_usable(dir: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let probe = dir.join("probe");
    let executes = fs::write(&probe, "#!/bin/sh\nexit 0\n").is_ok()
        && fs::set_permissions(&probe, fs::Permissions::from_mode(0o700)).is_ok()
        && Command::new(&probe)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
    drop(fs::remove_file(&probe));
    // POSIX `df -Pk`: the second line's fourth column is the free space in KiB.
    let free_kib = Command::new("df")
        .arg("-Pk")
        .arg(dir)
        .output()
        .ok()
        .and_then(|output| {
            String::from_utf8(output.stdout)
                .ok()?
                .lines()
                .nth(1)?
                .split_whitespace()
                .nth(3)?
                .parse::<u64>()
                .ok()
        });
    executes && free_kib.is_some_and(|kib| kib >= 1024 * 1024)
}

/// The inode of this process's PID namespace (`/proc/self/ns/pid`), or `0`
/// when unavailable, so stale cleanup never judges another namespace's PIDs.
#[cfg(unix)]
fn pid_namespace() -> String {
    fs::read_link("/proc/self/ns/pid")
        .ok()
        .and_then(|link| {
            link.to_str()?
                .strip_prefix("pid:[")?
                .strip_suffix(']')
                .map(str::to_owned)
        })
        .filter(|inode| !inode.is_empty() && inode.bytes().all(|byte| byte.is_ascii_digit()))
        .unwrap_or_else(|| "0".to_owned())
}

/// Sixteen hex digits from `/dev/urandom`, falling back to the clock.
#[cfg(unix)]
fn random_suffix() -> String {
    use std::io::Read as _;
    let mut bytes = [0_u8; 8];
    let random = fs::File::open("/dev/urandom").and_then(|mut file| file.read_exact(&mut bytes));
    if random.is_err() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        bytes = (nanos as u64).to_le_bytes();
    }
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Removes this user's scratch directories from the same PID namespace whose
/// creating process has exited.
#[cfg(unix)]
fn remove_stale_scratch(base: &Path, namespace: &str) {
    use std::os::unix::fs::MetadataExt;
    let Ok(me) = fs::metadata("/proc/self") else {
        return;
    };
    let Ok(entries) = fs::read_dir(base) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let mut parts = name
            .to_str()
            .and_then(|name| name.strip_prefix("xtask-"))
            .unwrap_or_default()
            .split('-');
        let (Some(pid), Some(owner_namespace)) = (parts.next(), parts.next()) else {
            continue;
        };
        // Only a canonical decimal PID names a process; `0` means the namespace
        // is unknown, so nothing can be judged stale.
        if pid.parse::<u32>().map(|value| value.to_string()).as_deref() != Ok(pid)
            || namespace == "0"
            || owner_namespace != namespace
        {
            continue;
        }
        let owned = entry
            .metadata()
            .is_ok_and(|meta| meta.is_dir() && meta.uid() == me.uid());
        if owned && !Path::new("/proc").join(pid).exists() {
            owner_writable(&entry.path());
            drop(fs::remove_dir_all(entry.path()));
        }
    }
}

/// Restores owner access on directories so read-only trees left by tests
/// do not block removal.
fn owner_writable(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        drop(fs::set_permissions(dir, fs::Permissions::from_mode(0o700)));
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                    owner_writable(&entry.path());
                }
            }
        }
    }
}

/// Every test taking the in-process `TEST_EXEC_HASH_LOCK` must be in the nextest
/// `exec-hash` group, and every group entry must name such a test: nextest runs
/// each test in its own process, so the lock alone no longer serializes them.
fn exec_hash_tests_grouped(root: &Path) -> Result<()> {
    let config = fs::read_to_string(root.join(".config/nextest.toml"))?;
    let end = config
        .find("test-group = \"exec-hash\"")
        .ok_or("no nextest override assigns the exec-hash group")?;
    let start = config[..end]
        .rfind("[[profile.default.overrides]]")
        .ok_or("the exec-hash group is assigned outside a nextest override")?;
    let filter = &config[start..end];
    let mut users = std::collections::BTreeSet::new();
    let mut stack = vec![root.join("src")];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|extension| extension != "rs") {
                continue;
            }
            let source = fs::read_to_string(&path)?;
            for (at, _) in source.match_indices("TEST_EXEC_HASH_LOCK.") {
                let name = source[..at]
                    .rfind("fn ")
                    .and_then(|start| source[start + 3..].split(['(', '<']).next())
                    .ok_or("TEST_EXEC_HASH_LOCK used outside a function")?;
                users.insert(name.to_owned());
                if !filter.contains(&format!("::{name})")) {
                    return Err(format!(
                        "{name} takes TEST_EXEC_HASH_LOCK but is not in the exec-hash nextest group"
                    )
                    .into());
                }
            }
        }
    }
    for listed in filter.split("test(=").skip(1) {
        let name = listed
            .split(')')
            .next()
            .and_then(|path| path.rsplit("::").next())
            .unwrap_or_default();
        if !users.contains(name) {
            return Err(format!(
                "exec-hash nextest group lists {name}, which does not take TEST_EXEC_HASH_LOCK"
            )
            .into());
        }
    }
    Ok(())
}

/// With `autotests = false` a `tests/*.rs` file that is not a module of
/// `tests/it/main.rs` would silently never build; reject that, a commented-out
/// module line, and a manifest that lets Cargo build each file separately again.
fn integration_tests_included(root: &Path) -> Result<()> {
    let manifest = fs::read_to_string(root.join("Cargo.toml"))?;
    if !manifest
        .lines()
        .any(|line| line.trim() == "autotests = false")
    {
        return Err(
            "Cargo.toml must set `autotests = false` for the single `it` test binary".into(),
        );
    }
    let index = fs::read_to_string(root.join("tests/it/main.rs"))?;
    let modules: Vec<&str> = index
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("#[path = \"../"))
        .collect();
    for entry in fs::read_dir(root.join("tests"))? {
        let path = entry?.path();
        if path.extension().is_some_and(|extension| extension == "rs") {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or("non-UTF8 integration-test file name")?;
            if !modules.contains(&format!("#[path = \"../{name}\"]").as_str()) {
                return Err(format!("tests/{name} is not a module of tests/it/main.rs").into());
            }
        }
    }
    Ok(())
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
        integration_tests_included(&self.root)?;
        exec_hash_tests_grouped(&self.root)?;
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
        ] {
            if self.has_features || args.contains(&"--all-features") {
                run(&self.root, "cargo", &args)?;
            }
        }
        // nextest runs each test in its own process; doctests need cargo's runner.
        let scratch = TestScratch::create();
        for args in [
            vec![
                "nextest",
                "run",
                "--frozen",
                "--workspace",
                "--no-fail-fast",
            ],
            vec![
                "nextest",
                "run",
                "--frozen",
                "--workspace",
                "--all-features",
                "--no-fail-fast",
            ],
            vec!["test", "--frozen", "--workspace", "--doc", "--no-fail-fast"],
            vec![
                "test",
                "--frozen",
                "--workspace",
                "--all-features",
                "--doc",
                "--no-fail-fast",
            ],
        ] {
            if self.has_features || args.contains(&"--all-features") {
                scratch.cargo(&self.root, &args)?;
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
    /// Resolves the one state schema expected by packaging and release verification.
    pub(crate) fn state_schema(&self) -> Result<u32> {
        match self.family["profiles"]["state"].as_str() {
            Some("local") => Ok(family_delivery::CURRENT_STATE_SCHEMA),
            Some("none") => Ok(0),
            other => Err(format!("unsupported state profile for packaging: {other:?}").into()),
        }
    }
    /// Builds and verifies an immutable bundle from committed source, returning its directory.
    /// `out` selects an explicit new artifact path; omission retains the standard dist layout.
    /// Existing bundle directories are refused; packaging never activates or restarts a service.
    pub(crate) fn package(&self, out: Option<PathBuf>) -> Result<PathBuf> {
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
        let state_schema = self.state_schema()?;
        self.build(true)?;
        let output = out.unwrap_or_else(|| {
            self.root
                .join("dist")
                .join(format!("{}-{}-{}", self.name, self.version, target))
        });
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
                    "it",
                    "protocol::",
                ],
            ),
            _ => Err("unknown test suite".into()),
        },
        Task::Package { command: None, out } => project.package(out).map(|_| ()),
        Task::Package {
            command: Some(PackageCommand::Verify { directory }),
            out: None,
        } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&family_delivery::verify(&directory)?)?
            );
            Ok(())
        }
        Task::Package {
            command: Some(_),
            out: Some(_),
        } => Err("--out is only accepted when creating a package".into()),
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
