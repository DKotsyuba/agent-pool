//! Explicit release operations. Local preparation never commits, tags or pushes.
use crate::{Project, Result, capture, helper, json, run, text};
use clap::Subcommand;
use family_delivery::{Manifest, verify};
use serde_json::Value;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
const MAC_TARGET: &str = "aarch64-apple-darwin";
const LINUX_TARGET: &str = "x86_64-unknown-linux-gnu";
const LOCAL_MANIFEST: &str = "release-manifest.json";
const LINUX_MANIFEST: &str = "release-manifest-x86_64-unknown-linux-gnu.json";

#[derive(Subcommand)]
pub enum Release {
    /// Show version/CHANGELOG edits; --apply performs local edits only.
    Prepare {
        version: String,
        #[arg(long)]
        apply: bool,
    },
    /// Publish an accepted CI bundle through a complete draft; never replace a release.
    Publish {
        directory: PathBuf,
        #[arg(long)]
        linux_directory: Option<PathBuf>,
        /// Publish only the native Linux bundle supplied as DIRECTORY.
        #[arg(long, conflicts_with = "linux_directory")]
        linux_only: bool,
    },
    /// Observe one exact tag/commit and validate its run and bytes. No install or wake claim.
    Wait {
        #[arg(long)]
        repo: String,
        #[arg(long)]
        tag: String,
        #[arg(long)]
        commit: String,
        #[arg(long, default_value = MAC_TARGET)]
        target: String,
        #[arg(long, default_value_t = 1800)]
        timeout: u64,
        #[arg(long)]
        result_file: Option<PathBuf>,
    },
}
/// Return the published manifest name for a supported target.
fn manifest_asset(target: &str) -> Result<&'static str> {
    match target {
        MAC_TARGET => Ok(LOCAL_MANIFEST),
        LINUX_TARGET => Ok(LINUX_MANIFEST),
        _ => Err("unsupported release target".into()),
    }
}

/// Require a Linux bundle when the family declares Linux as a candidate.
fn linux_candidate(family: &toml::Value) -> bool {
    family["compatibility"]["candidate_targets"]
        .as_array()
        .is_some_and(|targets| {
            targets
                .iter()
                .any(|target| target.as_str() == Some(LINUX_TARGET))
        })
}

/// Reconcile already verified bundles before accepting them as one release.
fn reconcile_bundles(mac: &Manifest, linux: Option<&Manifest>, linux_required: bool) -> Result<()> {
    if mac.target != MAC_TARGET || (linux_required && linux.is_none()) {
        return Err("release requires the macOS bundle and the configured Linux bundle".into());
    }
    if let Some(linux) = linux
        && (linux.target != LINUX_TARGET
            || linux.binary == mac.binary
            || linux.product != mac.product
            || linux.version != mac.version
            || linux.source_commit != mac.source_commit
            || linux.state_schema != mac.state_schema
            || linux.run_id != mac.run_id
            || linux.run_attempt != mac.run_attempt)
    {
        return Err("release bundle identities do not match".into());
    }
    Ok(())
}
/// Require the explicitly selected target set and the configured Linux candidacy.
fn select_bundles(
    primary: &Manifest,
    linux: Option<&Manifest>,
    linux_candidate: bool,
    linux_only: bool,
) -> Result<()> {
    if linux_only {
        if primary.target != LINUX_TARGET || linux.is_some() || !linux_candidate {
            return Err("Linux-only release requires the declared Linux candidate alone".into());
        }
        Ok(())
    } else {
        reconcile_bundles(primary, linux, linux_candidate)
    }
}

/// A release must declare the actual schema expected by this source tree.
fn require_state_schema(manifest: &Manifest, expected: u32) -> Result<()> {
    if manifest.state_schema != expected {
        return Err("release bundle state schema does not match this project".into());
    }
    Ok(())
}

/// Correlates the downloaded Linux bundle to the exact bytes accepted by its native CI job.
fn verify_linux_acceptance(
    directory: &Path,
    manifest: &Manifest,
    binary_sha: &str,
    manifest_sha: &str,
) -> Result<()> {
    let lower_sha = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    if !lower_sha(binary_sha) || !lower_sha(manifest_sha) {
        return Err("Linux native acceptance digest missing or invalid".into());
    }
    let (size, actual_binary) = family_delivery::digest(&directory.join(&manifest.binary))?;
    let (_, actual_manifest) = family_delivery::digest(&directory.join(LOCAL_MANIFEST))?;
    if size != manifest.size
        || actual_binary != manifest.sha256
        || actual_binary != binary_sha
        || actual_manifest != manifest_sha
    {
        return Err("Linux payload differs from native acceptance".into());
    }
    Ok(())
}

/// Write a new staged file without replacing an existing path.
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Read bounded manifest bytes and check their decoded identity.
fn manifest_bytes(directory: &Path, manifest: &Manifest) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(directory.join(LOCAL_MANIFEST))?
        .take(16_385)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 16_384 || serde_json::from_slice::<Manifest>(&bytes)? != *manifest {
        return Err("payload manifest changed after acceptance".into());
    }
    Ok(bytes)
}

/// Stage bounded manifest bytes under the published name and check their identity.
fn stage_manifest(directory: &Path, manifest: &Manifest, destination: &Path) -> Result<()> {
    write_new(destination, &manifest_bytes(directory, manifest)?)
}

/// Reads one release input from the exact source commit, not from the mutable checkout.
fn committed_blob(root: &Path, commit: &str, name: &str) -> Result<Vec<u8>> {
    if !matches!(name, "install.sh" | "CHANGELOG.md") {
        return Err("unsupported committed release input".into());
    }
    let entry = text(root, "git", &["ls-tree", commit, "--", name])?;
    let mut fields = entry.split_whitespace();
    let mode = fields.next();
    let kind = fields.next();
    let object = fields.next();
    let path = fields.next();
    if !matches!(mode, Some("100644" | "100755"))
        || kind != Some("blob")
        || object.is_none_or(|id| id.len() != 40 || !id.bytes().all(|b| b.is_ascii_hexdigit()))
        || path != Some(name)
        || fields.next().is_some()
    {
        return Err("committed release input is not a regular Git blob".into());
    }
    let source = format!("{commit}:{name}");
    let bytes = capture(root, "git", &["show", &source], 60)?;
    if bytes.is_empty() {
        return Err("committed release input is empty".into());
    }
    Ok(bytes)
}

/// Restore the local manifest name for strict two-file bundle verification.
fn localize_manifest(directory: &Path, remote_name: &str) -> Result<()> {
    if remote_name != LOCAL_MANIFEST {
        let remote = directory.join(remote_name);
        fs::hard_link(&remote, directory.join(LOCAL_MANIFEST))?;
        fs::remove_file(remote)?;
    }
    Ok(())
}

/// Check binary digests and produce checksums using the exact published asset names.
fn asset_checksums(
    assets: &[(&str, &Path)],
    primary: &Manifest,
    linux: Option<&Manifest>,
) -> Result<String> {
    let mut sums = String::new();
    for (name, file) in assets {
        let digest = family_delivery::digest(file)?.1;
        if (*name == primary.binary && digest != primary.sha256)
            || linux.is_some_and(|manifest| *name == manifest.binary && digest != manifest.sha256)
        {
            return Err("payload changed while calculating checksums".into());
        }
        sums.push_str(&format!("{digest}  {name}\n"));
    }
    Ok(sums)
}

/// Looks up one exact immutable prepared checksum, refusing malformed or duplicate entries.
fn prepared_checksum<'a>(sums: &'a str, name: &str) -> Result<&'a str> {
    let mut matches = sums.lines().filter_map(|line| {
        let (digest, asset) = line.split_once("  ")?;
        (asset == name).then_some(digest)
    });
    let digest = matches.next().ok_or("prepared checksum missing")?;
    if matches.next().is_some()
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("prepared checksum invalid or duplicated".into());
    }
    Ok(digest)
}

/// Immutable release inputs retained independently of mutable staging paths.
struct PreparedAssets<'a> {
    files: &'a [(&'a str, &'a Path)],
    sums: &'a str,
    primary_manifest: &'a [u8],
    linux_manifest_sha: Option<&'a str>,
    installer: &'a [u8],
    notes: &'a str,
}

/// Compares a downloaded file without reading more than one byte beyond the pinned input.
fn matches_pinned_bytes(path: &Path, expected: &[u8]) -> Result<bool> {
    let limit = u64::try_from(expected.len())?
        .checked_add(1)
        .ok_or("pinned input too large")?;
    let mut actual = Vec::new();
    File::open(path)?.take(limit).read_to_end(&mut actual)?;
    Ok(actual == expected)
}

/// Create one draft and open it only after every downloaded asset matches.
fn complete_draft(
    tag: &str,
    repo: &str,
    stage: &Path,
    prepared: PreparedAssets<'_>,
    primary: &Manifest,
    linux: Option<&Manifest>,
    mut gh: impl FnMut(&[&str]) -> Result<()>,
) -> Result<()> {
    let sums_path = stage.join("SHA256SUMS");
    let mut args = vec!["release", "create", tag];
    for (_, path) in prepared.files {
        args.push(path.to_str().ok_or("asset path")?);
    }
    args.extend([
        sums_path.to_str().ok_or("checksum path")?,
        "--repo",
        repo,
        "--verify-tag",
        "--draft",
        "--title",
        tag,
        "--notes",
        prepared.notes,
    ]);
    // Existing releases (including drafts) cause create to fail. No --clobber path exists.
    gh(&args)?;
    for manifest in std::iter::once(primary).chain(linux) {
        let remote_name = manifest_asset(&manifest.target)?;
        let verify_dir = stage.join(format!("upload-verify-{}", manifest.target));
        fs::create_dir(&verify_dir)?;
        gh(&[
            "release",
            "download",
            tag,
            "--repo",
            repo,
            "--dir",
            verify_dir.to_str().ok_or("verify path")?,
            "--pattern",
            &manifest.binary,
            "--pattern",
            remote_name,
        ])?;
        localize_manifest(&verify_dir, remote_name)?;
        if verify(&verify_dir)? != *manifest
            || family_delivery::digest(&verify_dir.join(LOCAL_MANIFEST))?.1
                != prepared_checksum(prepared.sums, remote_name)?
            || family_delivery::digest(&verify_dir.join(&manifest.binary))?.1
                != prepared_checksum(prepared.sums, &manifest.binary)?
            || (manifest.target == primary.target
                && !matches_pinned_bytes(
                    &verify_dir.join(LOCAL_MANIFEST),
                    prepared.primary_manifest,
                )?)
            || (manifest.target == LINUX_TARGET
                && family_delivery::digest(&verify_dir.join(LOCAL_MANIFEST))?.1
                    != prepared
                        .linux_manifest_sha
                        .ok_or("Linux native manifest digest missing")?)
        {
            return Err("uploaded payload differs; draft left unpublished".into());
        }
    }
    let bootstrap_dir = stage.join("bootstrap-verify");
    fs::create_dir(&bootstrap_dir)?;
    gh(&[
        "release",
        "download",
        tag,
        "--repo",
        repo,
        "--dir",
        bootstrap_dir.to_str().ok_or("verify path")?,
        "--pattern",
        "install.sh",
        "--pattern",
        "SHA256SUMS",
    ])?;
    if family_delivery::digest(&bootstrap_dir.join("install.sh"))?.1
        != prepared_checksum(prepared.sums, "install.sh")?
        || !matches_pinned_bytes(&bootstrap_dir.join("install.sh"), prepared.installer)?
        || !matches_pinned_bytes(&bootstrap_dir.join("SHA256SUMS"), prepared.sums.as_bytes())?
    {
        return Err("bootstrap assets differ; draft left unpublished".into());
    }
    let mut args = vec!["release", "edit", tag, "--repo", repo, "--draft=false"];
    if !semver::Version::parse(&primary.version)?.pre.is_empty() {
        args.push("--prerelease");
    }
    gh(&args)
}

fn repo_valid(repo: &str) -> bool {
    let parts: Vec<_> = repo.split('/').collect();
    parts.len() == 2
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 100
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
}
/// Accept both `## Unreleased` and the bracketed Keep-a-Changelog heading form.
fn unreleased_heading(changelog: &str) -> Result<&'static str> {
    ["## Unreleased", "## [Unreleased]"]
        .into_iter()
        .find(|h| changelog.matches(h).count() == 1)
        .ok_or("expected exactly one Unreleased section".into())
}
/// Replace the `version` key of `[workspace.package]` in place, preserving key
/// order, inline tables and comments; None when that exact line is absent.
fn bump_workspace_version(source: &str, from: &str, to: &str) -> Option<String> {
    let mut in_package = false;
    let mut bumped = false;
    let mut out = source
        .lines()
        .map(|line| {
            if line.trim_start().starts_with('[') {
                in_package = line.trim() == "[workspace.package]";
            }
            if in_package && !bumped && line.trim() == format!("version = \"{from}\"") {
                bumped = true;
                format!("version = \"{to}\"")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    if source.ends_with('\n') {
        out.push('\n');
    }
    bumped.then_some(out)
}
fn prepare(project: &Project, version: &str, apply: bool) -> Result<()> {
    let old = semver::Version::parse(&project.version)?;
    let new = semver::Version::parse(version)?;
    if new <= old || !new.build.is_empty() {
        return Err("version must increase and cannot contain build metadata".into());
    }
    if !text(&project.root, "git", &["status", "--porcelain"])?.is_empty() {
        return Err("prepare requires a clean checkout".into());
    }
    let changelog = fs::read_to_string(project.root.join("CHANGELOG.md"))?;
    let unreleased = unreleased_heading(&changelog)?;
    println!(
        "{}",
        json!({"dry_run":!apply,"old":project.version,"new":version,"files":["Cargo.toml","Cargo.lock","CHANGELOG.md"],"remote_writes":0})
    );
    if !apply {
        return Ok(());
    }
    let cargo_toml = fs::read_to_string(project.root.join("Cargo.toml"))?;
    let bumped = bump_workspace_version(&cargo_toml, &project.version, version)
        .ok_or("expected the workspace version line in [workspace.package]")?;
    fs::write(project.root.join("Cargo.toml"), bumped)?;
    fs::write(
        project.root.join("CHANGELOG.md"),
        changelog.replacen(unreleased, &format!("{unreleased}\n\n## {version}"), 1),
    )?;
    capture(
        &project.root,
        "cargo",
        &[
            "metadata",
            "--offline",
            "--no-deps",
            "--format-version",
            "1",
        ],
        120,
    )?;
    run(
        &project.root,
        "cargo",
        &["update", "--workspace", "--offline"],
    )?;
    println!(
        "Review changes and Cargo.lock, run checks, commit, then create an annotated version tag explicitly."
    );
    Ok(())
}
/// Selects exactly one Cargo-built protocol test executable from machine-readable output.
fn protocol_executable(output: &[u8], source: &Path) -> Result<PathBuf> {
    let mut result = None;
    for line in output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let value: Value = serde_json::from_slice(line)?;
        let target = &value["target"];
        if value["reason"] != "compiler-artifact"
            || target["name"] != "protocol"
            || target["src_path"].as_str().map(Path::new) != Some(source)
            || !target["kind"]
                .as_array()
                .is_some_and(|kinds| kinds.iter().any(|kind| kind == "test"))
            || value["profile"]["test"] != true
        {
            continue;
        }
        let path = PathBuf::from(
            value["executable"]
                .as_str()
                .ok_or("protocol executable missing")?,
        );
        if !path.is_absolute() || result.replace(path).is_some() {
            return Err("protocol executable is ambiguous or relative".into());
        }
    }
    result.ok_or_else(|| "protocol executable missing".into())
}

/// A clean checkout must also point at the exact commit named by the payload.
fn source_identity_matches(head: &str, expected: &str, status: &str) -> bool {
    head == expected && status.is_empty()
}

/// Reads both source identity facts before and after executing acceptance code.
fn exact_checkout(root: &Path, expected: &str) -> Result<bool> {
    let head = text(root, "git", &["rev-parse", "HEAD"])?;
    let status = text(root, "git", &["status", "--porcelain"])?;
    Ok(source_identity_matches(&head, expected, &status))
}

/// Bind publication to an explicitly dispatched exact tag.
fn publish_trigger_valid(event: &str, reference: &str, tag: &str) -> bool {
    event == "workflow_dispatch" && reference == format!("refs/tags/{tag}")
}

/// Keep observing historical push releases as well as manually dispatched releases.
fn observable_release_event(event: Option<&str>) -> bool {
    matches!(event, Some("push" | "workflow_dispatch"))
}

/// Publish accepted paired bundles, or an explicitly selected Linux-only bundle.
fn publish(
    project: &Project,
    directory: PathBuf,
    linux_directory: Option<PathBuf>,
    linux_only: bool,
) -> Result<()> {
    let directory = fs::canonicalize(directory)?;
    let m = verify(&directory)?;
    let primary_manifest = manifest_bytes(&directory, &m)?;
    let linux = linux_directory
        .map(|path| -> Result<_> {
            let path = fs::canonicalize(path)?;
            let manifest = verify(&path)?;
            Ok((path, manifest))
        })
        .transpose()?;
    select_bundles(
        &m,
        linux.as_ref().map(|(_, manifest)| manifest),
        linux_candidate(&project.family),
        linux_only,
    )?;
    require_state_schema(&m, project.state_schema()?)?;
    let linux_payload = if linux_only {
        Some((&directory, &m))
    } else {
        linux
            .as_ref()
            .map(|(directory, manifest)| (directory, manifest))
    };
    let linux_acceptance = linux_payload
        .map(|(directory, manifest)| -> Result<_> {
            let binary_sha = std::env::var("AGENT_POOL_LINUX_BINARY_SHA256")
                .map_err(|_| "Linux native binary acceptance digest missing")?;
            let manifest_sha = std::env::var("AGENT_POOL_LINUX_MANIFEST_SHA256")
                .map_err(|_| "Linux native manifest acceptance digest missing")?;
            verify_linux_acceptance(directory, manifest, &binary_sha, &manifest_sha)?;
            Ok((binary_sha, manifest_sha))
        })
        .transpose()?;
    let tag = format!("v{}", m.version);
    let repo = project.family["repository"]
        .as_str()
        .ok_or("repository missing")?;
    if !repo_valid(repo)
        || project.family["release"]["enabled"].as_bool() != Some(true)
        || project.family["qualification"].as_str() != Some("verified")
        || !project.family["compatibility"]["qualified_targets"]
            .as_array()
            .is_some_and(|targets| {
                std::iter::once(&m)
                    .chain(linux.iter().map(|(_, manifest)| manifest))
                    .all(|manifest| {
                        targets
                            .iter()
                            .any(|target| target.as_str() == Some(manifest.target.as_str()))
                    })
            })
        || !project.family["compatibility"]["qualified_hosts"]
            .as_array()
            .is_some_and(|a| !a.is_empty())
    {
        return Err("release is disabled or lacks reviewed native/host qualification".into());
    }
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || !publish_trigger_valid(
            &std::env::var("GITHUB_EVENT_NAME").unwrap_or_default(),
            &std::env::var("GITHUB_REF").unwrap_or_default(),
            &tag,
        )
        || std::env::var("GITHUB_REPOSITORY").as_deref() != Ok(repo)
        || std::env::var("GITHUB_REF_NAME").as_deref() != Ok(tag.as_str())
        || std::env::var("GITHUB_SHA").as_deref() != Ok(m.source_commit.as_str())
        || std::env::var("GITHUB_RUN_ID")
            .ok()
            .and_then(|v| v.parse().ok())
            != m.run_id
        || std::env::var("GITHUB_RUN_ATTEMPT")
            .ok()
            .and_then(|v| v.parse().ok())
            != m.run_attempt
        || m.run_id.is_none()
        || m.product != project.name
        || m.version != project.version
    {
        return Err("CI/tag/source/run identity mismatch".into());
    }
    if text(&project.root, "git", &["cat-file", "-t", &tag])? != "tag"
        || text(&project.root, "git", &["rev-parse", &format!("{tag}^{{}}")])? != m.source_commit
        || !exact_checkout(&project.root, &m.source_commit)?
    {
        return Err("release requires clean exact source and an annotated immutable tag".into());
    }
    let installer_bytes = committed_blob(&project.root, &m.source_commit, "install.sh")?;
    let changelog = String::from_utf8(committed_blob(
        &project.root,
        &m.source_commit,
        "CHANGELOG.md",
    )?)?;
    let test_output = capture(
        &project.root,
        "cargo",
        &[
            "test",
            "--frozen",
            "-p",
            &project.name,
            "--test",
            "protocol",
            "--no-run",
            "--message-format=json",
        ],
        600,
    )?;
    let protocol = protocol_executable(&test_output, &project.root.join("tests/protocol.rs"))?;
    let protocol_digest = family_delivery::digest(&protocol)?;
    if !helper(&project.root, "cargo")
        .args(["deny", "--locked", "check"])
        .status()?
        .success()
    {
        return Err("supply-chain check failed".into());
    }
    if !exact_checkout(&project.root, &m.source_commit)?
        || verify(&directory)? != m
        || manifest_bytes(&directory, &m)? != primary_manifest
    {
        return Err("source or primary payload changed before acceptance".into());
    }
    let binary = directory.join(&m.binary);
    let binary_str = binary.to_str().ok_or("non-UTF8 binary path")?;
    if text(&project.root, binary_str, &["--version"])? != format!("{} {}", m.product, m.version) {
        return Err("packaged binary identity mismatch".into());
    }
    let incomplete: Vec<String> = serde_json::from_slice(&capture(
        &project.root,
        binary_str,
        &["contract", "readiness"],
        10,
    )?)?;
    if !incomplete.is_empty() {
        return Err("unimplemented tools block release".into());
    }
    if family_delivery::digest(&protocol)? != protocol_digest
        || !exact_checkout(&project.root, &m.source_commit)?
        || verify(&directory)? != m
    {
        return Err("acceptance inputs changed before protocol test".into());
    }
    let protocol_str = protocol.to_str().ok_or("non-UTF8 protocol test path")?;
    if !helper(&project.root, protocol_str)
        .env("MCP_TEST_BINARY", &binary)
        .status()?
        .success()
    {
        return Err("shipped-binary acceptance failed".into());
    }
    if family_delivery::digest(&protocol)? != protocol_digest
        || !exact_checkout(&project.root, &m.source_commit)?
    {
        return Err("source or protocol test changed during acceptance".into());
    }
    if verify(&directory)? != m || manifest_bytes(&directory, &m)? != primary_manifest {
        return Err("payload changed after acceptance".into());
    }
    // Linux acceptance runs natively in a required CI job, which uploads this
    // same immutable bundle. This trusts CI; it is not cryptographic provenance.
    if let Some((directory, manifest)) = linux_payload
        && verify(directory)? != *manifest
    {
        return Err("Linux payload changed after acceptance".into());
    }
    if let (Some((directory, manifest)), Some((binary_sha, manifest_sha))) =
        (linux_payload, &linux_acceptance)
    {
        verify_linux_acceptance(directory, manifest, binary_sha, manifest_sha)?;
    }
    let headings = [format!("## {}", m.version), format!("## [{}]", m.version)];
    let section = changelog
        .lines()
        .skip_while(|l| headings.iter().all(|h| *l != h.as_str()))
        .skip(1)
        .take_while(|l| !l.starts_with("## "))
        .collect::<Vec<_>>()
        .join("\n");
    if section.trim().is_empty() || section.len() > 65536 {
        return Err("release CHANGELOG section is empty or too large".into());
    }
    fs::create_dir_all(&project.target_dir)?;
    let stage = project
        .target_dir
        .join(format!("release-publish-{}", std::process::id()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(&stage)?;
    }
    #[cfg(not(unix))]
    fs::create_dir(&stage)?;
    let primary_manifest_name = manifest_asset(&m.target)?;
    let manifest = stage.join(primary_manifest_name);
    write_new(&manifest, &primary_manifest)?;
    if linux_only
        && family_delivery::digest(&manifest)?.1
            != linux_acceptance
                .as_ref()
                .ok_or("Linux native acceptance digest missing")?
                .1
    {
        return Err("Linux manifest differs from native acceptance".into());
    }
    let installer = stage.join("install.sh");
    write_new(&installer, &installer_bytes)?;
    let sums_path = stage.join("SHA256SUMS");
    let mut assets = vec![
        (m.binary.as_str(), binary.as_path()),
        (primary_manifest_name, manifest.as_path()),
    ];
    let linux_binary = linux.as_ref().map(|(dir, m)| dir.join(&m.binary));
    let linux_manifest = linux.as_ref().map(|_| stage.join(LINUX_MANIFEST));
    if let (Some((dir, manifest)), Some(binary), Some(staged_manifest)) =
        (&linux, &linux_binary, &linux_manifest)
    {
        stage_manifest(dir, manifest, staged_manifest)?;
        if let Some((_, accepted_manifest_sha)) = &linux_acceptance
            && family_delivery::digest(staged_manifest)?.1 != *accepted_manifest_sha
        {
            return Err("Linux manifest differs from native acceptance".into());
        }
        assets.extend([
            (manifest.binary.as_str(), binary.as_path()),
            (LINUX_MANIFEST, staged_manifest.as_path()),
        ]);
    }
    assets.push(("install.sh", installer.as_path()));
    let sums = asset_checksums(&assets, &m, linux.as_ref().map(|(_, manifest)| manifest))?;
    write_new(&sums_path, sums.as_bytes())?;
    complete_draft(
        &tag,
        repo,
        &stage,
        PreparedAssets {
            files: &assets,
            sums: &sums,
            primary_manifest: &primary_manifest,
            linux_manifest_sha: linux_acceptance.as_ref().map(|(_, sha)| sha.as_str()),
            installer: &installer_bytes,
            notes: &section,
        },
        &m,
        linux.as_ref().map(|(_, manifest)| manifest),
        |args| run(&project.root, "gh", args),
    )?;
    println!(
        "{}",
        json!({"status":"published","tag":tag,"commit":m.source_commit,"artifact_integrity":"verified","provenance_verification":"not_performed"})
    );
    Ok(())
}
/// Observe the selected target's published bytes and the CI run that produced them.
fn wait(
    project: &Project,
    repo: &str,
    tag: &str,
    commit: &str,
    target: &str,
    timeout: u64,
    result_file: Option<PathBuf>,
) -> Result<()> {
    let remote_manifest = manifest_asset(target)?;
    if !repo_valid(repo)
        || commit.len() != 40
        || !commit.bytes().all(|b| b.is_ascii_hexdigit())
        || timeout == 0
        || timeout > 86400
    {
        return Err("invalid release wait scope or deadline".into());
    }
    let version = semver::Version::parse(tag.strip_prefix('v').ok_or("tag must start with v")?)?;
    if !version.build.is_empty() {
        return Err("release build metadata is unsupported".into());
    }
    fs::create_dir_all(&project.target_dir)?;
    let dir = project
        .target_dir
        .join(format!("release-wait-{}", std::process::id()));
    fs::create_dir(&dir)?;
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let remaining = || -> Result<u64> {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            Err("release wait deadline exceeded".into())
        } else {
            Ok(left.as_secs().clamp(1, 60))
        }
    };
    loop {
        remaining()?;
        let response = capture(
            &project.root,
            "gh",
            &[
                "api",
                "--hostname",
                "github.com",
                &format!("repos/{repo}/releases/tags/{tag}"),
            ],
            remaining()?,
        );
        let data: Value = match response {
            Ok(bytes) => serde_json::from_slice(&bytes)?,
            Err(_) => {
                std::thread::sleep(
                    Duration::from_secs(2).min(deadline.saturating_duration_since(Instant::now())),
                );
                continue;
            }
        };
        if data["draft"] != false {
            std::thread::sleep(Duration::from_secs(1));
            continue;
        }
        let assets = data["assets"]
            .as_array()
            .ok_or("release asset inventory absent")?;
        let meta = assets
            .iter()
            .find(|a| a["name"] == remote_manifest)
            .ok_or("published manifest absent")?;
        if meta["size"].as_u64().is_none_or(|s| s > 16384) {
            return Err("published manifest too large".into());
        }
        let meta_id = meta["id"].as_u64().ok_or("manifest asset ID missing")?;
        let bytes = capture(
            &project.root,
            "gh",
            &[
                "api",
                "--hostname",
                "github.com",
                &format!("repos/{repo}/releases/assets/{meta_id}"),
                "-H",
                "Accept: application/octet-stream",
            ],
            remaining()?,
        )?;
        let m: Manifest = serde_json::from_slice(&bytes)?;
        m.validate()?;
        if m.source_commit != commit || format!("v{}", m.version) != tag || m.target != target {
            return Err("release manifest identity mismatch".into());
        }
        let run_id = m.run_id.ok_or("release has no CI run identity")?;
        let run: Value = serde_json::from_slice(&capture(
            &project.root,
            "gh",
            &[
                "api",
                "--hostname",
                "github.com",
                &format!("repos/{repo}/actions/runs/{run_id}"),
            ],
            remaining()?,
        )?)?;
        if run["head_sha"] != commit
            || run["run_attempt"].as_u64() != m.run_attempt
            || !observable_release_event(run["event"].as_str())
            || run["path"] != ".github/workflows/release.yml"
        {
            return Err("release workflow identity mismatch".into());
        }
        if run["status"] != "completed" {
            std::thread::sleep(Duration::from_secs(1));
            continue;
        }
        if run["conclusion"] != "success" {
            return Err("release workflow failed".into());
        }
        let mut object = serde_json::from_slice::<Value>(&capture(
            &project.root,
            "gh",
            &[
                "api",
                "--hostname",
                "github.com",
                &format!("repos/{repo}/git/ref/tags/{tag}"),
            ],
            remaining()?,
        )?)?["object"]
            .clone();
        for _ in 0..4 {
            if object["type"] == "commit" {
                break;
            }
            if object["type"] != "tag" {
                return Err("unsupported tag target".into());
            }
            let sha = object["sha"].as_str().ok_or("tag SHA missing")?;
            object = serde_json::from_slice::<Value>(&capture(
                &project.root,
                "gh",
                &[
                    "api",
                    "--hostname",
                    "github.com",
                    &format!("repos/{repo}/git/tags/{sha}"),
                ],
                remaining()?,
            )?)?["object"]
                .clone();
        }
        if object["type"] != "commit" || object["sha"] != commit {
            return Err("tag no longer resolves to expected source".into());
        }
        let asset = assets
            .iter()
            .find(|a| a["name"] == m.binary)
            .ok_or("binary asset absent")?;
        if asset["size"].as_u64() != Some(m.size) {
            return Err("asset inventory size mismatch".into());
        }
        capture(
            &project.root,
            "gh",
            &[
                "release",
                "download",
                tag,
                "--repo",
                repo,
                "--dir",
                dir.to_str().ok_or("wait path")?,
                "--pattern",
                &m.binary,
                "--pattern",
                remote_manifest,
            ],
            remaining()?,
        )?;
        localize_manifest(&dir, remote_manifest)?;
        if verify(&dir)? != m || fs::read(dir.join(LOCAL_MANIFEST))? != bytes {
            return Err("downloaded bytes differ from observed manifest".into());
        }
        let event = json!({"schema_version":1,"status":"published","repo":repo,"tag":tag,"commit":commit,"run_id":run_id,"run_attempt":m.run_attempt,"verified_assets":[m.binary,remote_manifest],"artifact_integrity":"verified","provenance_verification":"not_performed","installed":false,"agent_awakened":false});
        let text = serde_json::to_string(&event)?;
        if let Some(path) = result_file {
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut file = opts.open(path)?;
            file.write_all(text.as_bytes())?;
            file.sync_all()?;
        }
        println!("{text}");
        return Ok(());
    }
}
/// Dispatch a release command without changing its authorization requirements.
pub fn execute(project: &Project, command: Release) -> Result<()> {
    match command {
        Release::Prepare { version, apply } => prepare(project, &version, apply),
        Release::Publish {
            directory,
            linux_directory,
            linux_only,
        } => publish(project, directory, linux_directory, linux_only),
        Release::Wait {
            repo,
            tag,
            commit,
            target,
            timeout,
            result_file,
        } => wait(project, &repo, &tag, &commit, &target, timeout, result_file),
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "Test assertions fail explicitly")]
mod tests {
    use super::*;
    use std::process::Command;

    /// Give each target the same valid release identity for reconciliation tests.
    fn manifest(target: &str) -> Manifest {
        Manifest {
            schema_version: 1,
            profile: "single-binary-v1".into(),
            product: "agent-test".into(),
            version: "1.2.3".into(),
            source_commit: "a".repeat(40),
            target: target.into(),
            binary: format!("agent-test-{target}"),
            size: 1,
            sha256: "b".repeat(64),
            state_schema: 1,
            run_id: Some(123),
            run_attempt: Some(2),
        }
    }

    /// Both verified targets must describe the same source and CI attempt.
    #[test]
    fn reconciles_only_matching_release_bundles() {
        let mac = manifest(MAC_TARGET);
        let linux = manifest(LINUX_TARGET);
        mac.validate().unwrap();
        linux.validate().unwrap();
        assert!(reconcile_bundles(&mac, Some(&linux), true).is_ok());
        assert!(reconcile_bundles(&mac, None, false).is_ok());
        assert!(reconcile_bundles(&mac, None, true).is_err());
        assert!(reconcile_bundles(&linux, Some(&mac), true).is_err());

        for field in [
            "target", "binary", "product", "version", "commit", "schema", "run", "attempt",
        ] {
            let mut other = linux.clone();
            match field {
                "target" => other.target = MAC_TARGET.into(),
                "binary" => other.binary = mac.binary.clone(),
                "product" => other.product = "agent-other".into(),
                "version" => other.version = "1.2.4".into(),
                "commit" => other.source_commit = "c".repeat(40),
                "schema" => other.state_schema += 1,
                "run" => other.run_id = Some(124),
                "attempt" => other.run_attempt = Some(3),
                _ => unreachable!(),
            }
            assert!(
                reconcile_bundles(&mac, Some(&other), true).is_err(),
                "accepted mismatch in {field}"
            );
        }
    }

    /// Linux-only needs an explicit mode and a declared Linux candidate; paired rules remain.
    #[test]
    fn selects_only_authorized_release_targets() {
        let mac = manifest(MAC_TARGET);
        let linux = manifest(LINUX_TARGET);
        assert!(select_bundles(&mac, Some(&linux), true, false).is_ok());
        assert!(select_bundles(&mac, None, true, false).is_err());
        assert!(select_bundles(&linux, None, true, false).is_err());
        assert!(select_bundles(&linux, None, true, true).is_ok());
        assert!(select_bundles(&linux, None, false, true).is_err());
        assert!(select_bundles(&mac, None, true, true).is_err());
        assert!(select_bundles(&linux, Some(&mac), true, true).is_err());
    }

    /// Both publication modes require manual dispatch on the exact tag.
    #[test]
    fn publication_requires_manual_dispatch_on_exact_tag() {
        let tag = "v1.2.3";
        assert!(publish_trigger_valid(
            "workflow_dispatch",
            "refs/tags/v1.2.3",
            tag
        ));
        assert!(!publish_trigger_valid("push", "refs/tags/v1.2.3", tag));
        assert!(!publish_trigger_valid(
            "workflow_dispatch",
            "refs/heads/v1.2.3",
            tag
        ));
        assert!(!publish_trigger_valid(
            "workflow_dispatch",
            "refs/tags/v1.2.4",
            tag
        ));
        assert!(!publish_trigger_valid("schedule", "refs/tags/v1.2.3", tag));
    }

    /// Historical push runs and current manual runs remain observable, but other events do not.
    #[test]
    fn observes_historical_push_and_manual_release_runs() {
        assert!(observable_release_event(Some("push")));
        assert!(observable_release_event(Some("workflow_dispatch")));
        assert!(!observable_release_event(Some("schedule")));
        assert!(!observable_release_event(None));
    }

    /// Equal manifests with an outdated schema still cannot describe the current executable.
    #[test]
    fn release_schema_must_match_project_state() {
        let mac = manifest(MAC_TARGET);
        let linux = manifest(LINUX_TARGET);
        assert!(reconcile_bundles(&mac, Some(&linux), true).is_ok());
        assert!(require_state_schema(&mac, family_delivery::CURRENT_STATE_SCHEMA).is_err());
        assert!(require_state_schema(&mac, mac.state_schema).is_ok());
    }

    /// A clean tree on a different commit is not the source named by the payload.
    #[test]
    fn checkout_must_be_clean_and_match_the_payload_commit() {
        assert!(source_identity_matches("abc", "abc", ""));
        assert!(!source_identity_matches("def", "abc", ""));
        assert!(!source_identity_matches("abc", "abc", " M file"));
    }

    /// Native CI's recorded binary and manifest digests must match the uploaded Linux bundle.
    #[test]
    fn linux_acceptance_is_bound_to_exact_bundle_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path();
        let mut linux = manifest(LINUX_TARGET);
        let binary = directory.join(&linux.binary);
        fs::write(&binary, b"synthetic linux executable").unwrap();
        (linux.size, linux.sha256) = family_delivery::digest(&binary).unwrap();
        let manifest_path = directory.join(LOCAL_MANIFEST);
        fs::write(&manifest_path, serde_json::to_vec_pretty(&linux).unwrap()).unwrap();
        let manifest_sha = family_delivery::digest(&manifest_path).unwrap().1;
        assert!(verify_linux_acceptance(directory, &linux, &linux.sha256, &manifest_sha).is_ok());
        assert!(verify_linux_acceptance(directory, &linux, "", &manifest_sha).is_err());
        assert!(
            verify_linux_acceptance(directory, &linux, &"0".repeat(64), &manifest_sha).is_err()
        );
        assert!(
            verify_linux_acceptance(directory, &linux, &linux.sha256, &"0".repeat(64)).is_err()
        );
        let mut bytes = fs::read(&manifest_path).unwrap();
        bytes.push(b' ');
        fs::write(&manifest_path, bytes).unwrap();
        assert!(
            verify(directory).is_ok(),
            "whitespace preserves manifest semantics"
        );
        assert!(verify_linux_acceptance(directory, &linux, &linux.sha256, &manifest_sha).is_err());
    }

    /// The staged installer comes from the selected Git object, not a subsequently edited worktree.
    #[test]
    fn installer_bytes_are_pinned_to_git_object() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let initialized = Command::new("git")
            .current_dir(root)
            .args(["init", "--quiet", "--object-format=sha1"])
            .status()
            .unwrap();
        assert!(initialized.success());
        let git_input = |args: &[&str], input: &[u8]| -> String {
            let mut child = Command::new("git")
                .current_dir(root)
                .args(args)
                .env_remove("GH_TOKEN")
                .env_remove("GITHUB_TOKEN")
                .env_remove("GH_ENTERPRISE_TOKEN")
                .env_remove("GITHUB_ENTERPRISE_TOKEN")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(input).unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(output.status.success());
            String::from_utf8(output.stdout).unwrap().trim().to_owned()
        };
        let blob = git_input(&["hash-object", "-w", "--stdin"], b"verified installer\n");
        let tree = git_input(
            &["mktree"],
            format!("100644 blob {blob}\tinstall.sh\n").as_bytes(),
        );
        fs::write(root.join("install.sh"), b"modified worktree\n").unwrap();
        assert_eq!(
            committed_blob(root, &tree, "install.sh").unwrap(),
            b"verified installer\n"
        );
        let link = git_input(
            &["mktree"],
            format!("120000 blob {blob}\tinstall.sh\n").as_bytes(),
        );
        assert!(committed_blob(root, &link, "install.sh").is_err());
    }

    /// Publication and observation use distinct remote names but the same local name.
    #[test]
    fn maps_only_supported_targets_to_manifest_assets() {
        assert_eq!(manifest_asset(MAC_TARGET).unwrap(), "release-manifest.json");
        assert_eq!(
            manifest_asset(LINUX_TARGET).unwrap(),
            "release-manifest-x86_64-unknown-linux-gnu.json"
        );
        assert!(manifest_asset("aarch64-unknown-linux-gnu").is_err());
        assert!(manifest_asset("").is_err());
    }

    /// Only one exact Cargo protocol-test artifact can be selected for native acceptance.
    #[test]
    fn selects_exact_protocol_test_artifact() {
        let source = Path::new("/fixture/tests/protocol.rs");
        let artifact = json!({
            "reason":"compiler-artifact",
            "target":{"name":"protocol","src_path":"/fixture/tests/protocol.rs","kind":["test"]},
            "profile":{"test":true},"executable":"/fixture/target/protocol-test"
        });
        let bytes = serde_json::to_vec(&artifact).unwrap();
        assert_eq!(
            protocol_executable(&bytes, source).unwrap(),
            PathBuf::from("/fixture/target/protocol-test")
        );
        let duplicate = format!("{}\n{}\n", artifact, artifact);
        assert!(protocol_executable(duplicate.as_bytes(), source).is_err());
        let mut relative = artifact.clone();
        relative["executable"] = json!("protocol-test");
        assert!(protocol_executable(&serde_json::to_vec(&relative).unwrap(), source).is_err());
        assert!(protocol_executable(&bytes, Path::new("/different/protocol.rs")).is_err());
    }

    /// A legacy macOS-only family needs no Linux argument; a Linux candidate does.
    #[test]
    fn linux_bundle_is_required_only_for_a_declared_candidate() {
        let mac_only: toml::Value =
            toml::from_str("[compatibility]\ncandidate_targets = ['aarch64-apple-darwin']\n")
                .unwrap();
        let both: toml::Value = toml::from_str(
            "[compatibility]\ncandidate_targets = ['aarch64-apple-darwin', 'x86_64-unknown-linux-gnu']\n",
        )
        .unwrap();
        assert!(!linux_candidate(&mac_only));
        assert!(linux_candidate(&both));
    }

    /// Staging preserves the source and refuses a pre-existing destination.
    #[test]
    fn stages_and_localizes_manifest_without_overwriting() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let stage = temp.path().join("stage");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&stage).unwrap();
        let linux = manifest(LINUX_TARGET);
        let bytes = serde_json::to_vec_pretty(&linux).unwrap();
        fs::write(source.join(LOCAL_MANIFEST), &bytes).unwrap();
        let staged = stage.join(LINUX_MANIFEST);
        stage_manifest(&source, &linux, &staged).unwrap();
        assert!(stage_manifest(&source, &linux, &staged).is_err());
        assert_eq!(fs::read(source.join(LOCAL_MANIFEST)).unwrap(), bytes);
        localize_manifest(&stage, LINUX_MANIFEST).unwrap();
        assert_eq!(fs::read(stage.join(LOCAL_MANIFEST)).unwrap(), bytes);
        assert!(!staged.exists());

        fs::write(&staged, b"remote").unwrap();
        assert!(localize_manifest(&stage, LINUX_MANIFEST).is_err());
        assert_eq!(fs::read(stage.join(LOCAL_MANIFEST)).unwrap(), bytes);
        assert_eq!(fs::read(&staged).unwrap(), b"remote");
    }

    /// Simulate immutable asset upload/download in memory without running gh.
    fn exercise_draft(
        linux_only: bool,
        damage: Option<(&str, bool)>,
        mutate_local: Option<&str>,
        mutate_before_sums: Option<&str>,
    ) {
        use std::collections::BTreeMap;

        let temp = tempfile::tempdir().unwrap();
        let stage = temp.path().join("stage");
        let source = temp.path().join("source");
        fs::create_dir(&stage).unwrap();
        fs::create_dir(&source).unwrap();
        let mut mac = manifest(MAC_TARGET);
        let mut linux = manifest(LINUX_TARGET);
        let mac_binary = source.join(&mac.binary);
        let linux_binary = source.join(&linux.binary);
        fs::write(&mac_binary, b"mac executable").unwrap();
        fs::write(&linux_binary, b"linux executable").unwrap();
        (mac.size, mac.sha256) = family_delivery::digest(&mac_binary).unwrap();
        (linux.size, linux.sha256) = family_delivery::digest(&linux_binary).unwrap();
        let mac_manifest = stage.join(LOCAL_MANIFEST);
        let linux_manifest = stage.join(LINUX_MANIFEST);
        let installer = stage.join("install.sh");
        let checksums = stage.join("SHA256SUMS");
        fs::write(&mac_manifest, serde_json::to_vec_pretty(&mac).unwrap()).unwrap();
        fs::write(&linux_manifest, serde_json::to_vec_pretty(&linux).unwrap()).unwrap();
        fs::write(&installer, b"installer").unwrap();
        let pinned_mac = fs::read(&mac_manifest).unwrap();
        let pinned_linux_bytes = fs::read(&linux_manifest).unwrap();
        let pinned_linux = family_delivery::digest(&linux_manifest).unwrap().1;
        let pinned_installer = fs::read(&installer).unwrap();
        if let Some(name) = mutate_before_sums {
            let path = match name {
                LOCAL_MANIFEST => &mac_manifest,
                LINUX_MANIFEST => &linux_manifest,
                "install.sh" => &installer,
                _ => panic!("unsupported pre-sums mutation"),
            };
            OpenOptions::new()
                .append(true)
                .open(path)
                .unwrap()
                .write_all(b" ")
                .unwrap();
        }
        let primary = if linux_only { &linux } else { &mac };
        let extra_linux = if linux_only { None } else { Some(&linux) };
        let mut assets = Vec::new();
        if !linux_only {
            assets.extend([
                (mac.binary.as_str(), mac_binary.as_path()),
                (LOCAL_MANIFEST, mac_manifest.as_path()),
            ]);
        }
        assets.extend([
            (linux.binary.as_str(), linux_binary.as_path()),
            (LINUX_MANIFEST, linux_manifest.as_path()),
            ("install.sh", installer.as_path()),
        ]);
        let sums = asset_checksums(&assets, primary, extra_linux).unwrap();
        assert_eq!(sums.lines().count(), assets.len());
        for (name, path) in &assets {
            let expected = format!("{}  {name}", family_delivery::digest(path).unwrap().1);
            assert!(sums.lines().any(|line| line == expected));
        }
        let mut wrong_digest = linux.clone();
        wrong_digest.sha256 = "0".repeat(64);
        if linux_only {
            assert!(asset_checksums(&assets, &wrong_digest, None).is_err());
        } else {
            assert!(asset_checksums(&assets, &mac, Some(&wrong_digest)).is_err());
        }
        fs::write(&checksums, &sums).unwrap();
        let mut remote = BTreeMap::new();
        let mut operations = Vec::new();
        let result = complete_draft(
            "v1.2.3",
            "x/y",
            &stage,
            PreparedAssets {
                files: &assets,
                sums: &sums,
                primary_manifest: if linux_only {
                    &pinned_linux_bytes
                } else {
                    &pinned_mac
                },
                linux_manifest_sha: Some(&pinned_linux),
                installer: &pinned_installer,
                notes: "notes",
            },
            primary,
            extra_linux,
            |args| {
                assert_eq!(args[0], "release");
                match args[1] {
                    "create" => {
                        assert!(args.contains(&"--draft"));
                        assert!(args.contains(&"--verify-tag"));
                        assert!(!args.contains(&"--clobber"));
                        let notes = args.iter().position(|arg| *arg == "--notes").unwrap();
                        assert_eq!(args[notes + 1], "notes");
                        let end = args.iter().position(|arg| *arg == "--repo").unwrap();
                        let uploaded: Vec<_> = args[3..end]
                            .iter()
                            .map(|path| Path::new(path).file_name().unwrap().to_str().unwrap())
                            .collect();
                        let expected = if linux_only {
                            vec![
                                linux.binary.as_str(),
                                LINUX_MANIFEST,
                                "install.sh",
                                "SHA256SUMS",
                            ]
                        } else {
                            vec![
                                mac.binary.as_str(),
                                LOCAL_MANIFEST,
                                linux.binary.as_str(),
                                LINUX_MANIFEST,
                                "install.sh",
                                "SHA256SUMS",
                            ]
                        };
                        assert_eq!(uploaded, expected);
                        if let Some(name) = mutate_local {
                            let path = if name == "SHA256SUMS" {
                                checksums.as_path()
                            } else {
                                assets.iter().find(|(asset, _)| *asset == name).unwrap().1
                            };
                            let mut file = OpenOptions::new().append(true).open(path)?;
                            file.write_all(b" ")?;
                        }
                        for (name, path) in &assets {
                            remote.insert((*name).to_owned(), fs::read(path)?);
                        }
                        remote.insert("SHA256SUMS".into(), fs::read(&checksums)?);
                        operations.push("create".to_owned());
                    }
                    "download" => {
                        let dir = Path::new(
                            args[args.iter().position(|arg| *arg == "--dir").unwrap() + 1],
                        );
                        let patterns: Vec<_> = args
                            .windows(2)
                            .filter_map(|pair| (pair[0] == "--pattern").then_some(pair[1]))
                            .collect();
                        operations.push(format!("download:{}", patterns.join(",")));
                        for name in patterns {
                            let mut bytes = remote.get(name).unwrap().clone();
                            if let Some((bad, omit)) = damage
                                && bad == name
                            {
                                if omit {
                                    continue;
                                }
                                // Whitespace leaves a JSON manifest valid but changes its bytes.
                                bytes.push(b' ');
                            }
                            fs::write(dir.join(name), bytes)?;
                        }
                    }
                    "edit" => {
                        assert!(args.contains(&"--draft=false"));
                        operations.push("open".to_owned());
                    }
                    _ => panic!("unexpected command"),
                }
                Ok(())
            },
        );
        assert_eq!(operations.first().map(String::as_str), Some("create"));
        if damage.is_some() || mutate_local.is_some() || mutate_before_sums.is_some() {
            assert!(result.is_err());
            assert!(!operations.iter().any(|operation| operation == "open"));
        } else {
            result.unwrap();
            let mut expected = vec!["create".to_owned()];
            if !linux_only {
                expected.push(format!("download:{},{}", mac.binary, LOCAL_MANIFEST));
            }
            expected.extend([
                format!("download:{},{}", linux.binary, LINUX_MANIFEST),
                "download:install.sh,SHA256SUMS".to_owned(),
                "open".to_owned(),
            ]);
            assert_eq!(operations, expected);
        }
    }

    /// Any missing or changed asset keeps the draft closed; all six are checked first.
    #[test]
    fn opens_draft_only_after_both_bundles_and_bootstrap_match() {
        exercise_draft(false, None, None, None);
        for asset in [
            "agent-test-aarch64-apple-darwin",
            LOCAL_MANIFEST,
            "agent-test-x86_64-unknown-linux-gnu",
            LINUX_MANIFEST,
            "install.sh",
            "SHA256SUMS",
        ] {
            for omit in [true, false] {
                exercise_draft(false, Some((asset, omit)), None, None);
            }
            exercise_draft(false, None, Some(asset), None);
        }
        for asset in [LOCAL_MANIFEST, LINUX_MANIFEST, "install.sh"] {
            exercise_draft(false, None, None, Some(asset));
        }
    }

    /// A Linux-only draft also stays closed if any published or staged asset changes.
    #[test]
    fn opens_linux_only_draft_after_linux_and_bootstrap_match() {
        exercise_draft(true, None, None, None);
        for asset in [
            "agent-test-x86_64-unknown-linux-gnu",
            LINUX_MANIFEST,
            "install.sh",
            "SHA256SUMS",
        ] {
            for omit in [true, false] {
                exercise_draft(true, Some((asset, omit)), None, None);
            }
            exercise_draft(true, None, Some(asset), None);
        }
        for asset in [LINUX_MANIFEST, "install.sh"] {
            exercise_draft(true, None, None, Some(asset));
        }
    }

    /// Legacy publish and wait arguments keep their existing defaults.
    #[test]
    fn parses_release_cli_defaults_and_linux_arguments() {
        use clap::Parser;
        #[derive(Parser)]
        struct Cli {
            #[command(subcommand)]
            release: Release,
        }
        let legacy = Cli::try_parse_from(["xtask", "publish", "mac"]).unwrap();
        assert!(matches!(
            legacy.release,
            Release::Publish {
                linux_directory: None,
                linux_only: false,
                ..
            }
        ));
        let both =
            Cli::try_parse_from(["xtask", "publish", "mac", "--linux-directory", "linux"]).unwrap();
        assert!(
            matches!(both.release, Release::Publish { linux_directory: Some(path), .. } if path == Path::new("linux"))
        );
        let linux_only =
            Cli::try_parse_from(["xtask", "publish", "linux", "--linux-only"]).unwrap();
        assert!(matches!(
            linux_only.release,
            Release::Publish {
                linux_only: true,
                linux_directory: None,
                ..
            }
        ));
        assert!(
            Cli::try_parse_from([
                "xtask",
                "publish",
                "linux",
                "--linux-only",
                "--linux-directory",
                "other"
            ])
            .is_err()
        );
        let legacy_wait = Cli::try_parse_from([
            "xtask", "wait", "--repo", "x/y", "--tag", "v1.2.3", "--commit", "abc",
        ])
        .unwrap();
        assert!(
            matches!(legacy_wait.release, Release::Wait { target, .. } if target == MAC_TARGET)
        );
        let linux_wait = Cli::try_parse_from([
            "xtask",
            "wait",
            "--repo",
            "x/y",
            "--tag",
            "v1.2.3",
            "--commit",
            "abc",
            "--target",
            LINUX_TARGET,
        ])
        .unwrap();
        assert!(
            matches!(linux_wait.release, Release::Wait { target, .. } if target == LINUX_TARGET)
        );
    }

    #[test]
    fn repository_scope() {
        assert!(repo_valid("DKotsyuba/agent-example"));
        for r in ["x", "x/y/z", "x/y?token=a", "/x", "https://github.com/x/y"] {
            assert!(!repo_valid(r));
        }
    }
    #[test]
    fn unreleased_heading_forms() {
        assert_eq!(
            unreleased_heading("# C\n\n## Unreleased\n\n### Added\n- x\n").unwrap(),
            "## Unreleased"
        );
        assert_eq!(
            unreleased_heading("# C\n\n## [Unreleased]\n\n### Added\n- x\n").unwrap(),
            "## [Unreleased]"
        );
        assert!(unreleased_heading("# C\nno headings\n").is_err());
    }
    #[test]
    fn version_bump_changes_exactly_one_line() {
        let source = "# top comment\n[workspace]\nmembers = [\"xtask\"]\n\n[workspace.package]\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dependencies]\nclap = { version = \"4.5\", features = [\"derive\"] }\n";
        let bumped = bump_workspace_version(source, "0.1.0", "0.1.1").unwrap();
        assert_eq!(
            bumped
                .lines()
                .zip(source.lines())
                .filter(|(a, b)| a != b)
                .count(),
            1
        );
        assert_eq!(
            bumped,
            source.replacen("version = \"0.1.0\"", "version = \"0.1.1\"", 1)
        );
        assert!(bump_workspace_version(source, "9.9.9", "1.0.0").is_none());
    }
}
