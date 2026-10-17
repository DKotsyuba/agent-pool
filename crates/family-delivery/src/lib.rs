//! Immutable local delivery for the single-binary profile, with or without
//! local state. A release declares the state schema it expects; activation
//! refuses to run an older schema against newer on-disk state, and never
//! touches anything outside `<home>/standalone/`.
//! Hash verification proves integrity, not provenance. Callers authenticate downloads.
#![forbid(unsafe_code)]
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Delivery errors never contain credentials or raw provider bodies.
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
/// Only one bounded executable and a small manifest are accepted.
pub const MAX_BINARY_BYTES: u64 = 512 * 1024 * 1024;
/// The product's current on-disk state schema (`state/v1`). Packaging stamps
/// this into new manifests; keep it in lockstep with the store layout.
pub const CURRENT_STATE_SCHEMA: u32 = 1;

/// The explicit single-binary profile is separate from the older bundle manifest.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Version of this file contract.
    pub schema_version: u32,
    /// Must equal single-binary-v1.
    pub profile: String,
    /// Product/binary identity.
    pub product: String,
    /// Immutable product release version.
    pub version: String,
    /// Exact source commit, not a branch.
    pub source_commit: String,
    /// Rust target triple.
    pub target: String,
    /// Bare release asset name.
    pub binary: String,
    /// Exact byte length.
    pub size: u64,
    /// SHA-256 of the executable.
    pub sha256: String,
    /// State schema the release expects: 0 = stateless, 1 = `CURRENT_STATE_SCHEMA`.
    pub state_schema: u32,
    /// GitHub run identity, when built there.
    pub run_id: Option<u64>,
    /// GitHub run attempt, when built there.
    pub run_attempt: Option<u64>,
}
/// Restrict path components; callers must never sanitize a component into a different identity.
pub fn component(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn regular(path: &Path) -> Result<()> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err("expected a regular file, not a link".into());
    }
    Ok(())
}
/// Compute a bounded streaming digest without reading the entire binary into memory.
pub fn digest(path: &Path) -> Result<(u64, String)> {
    regular(path)?;
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let (mut total, mut buffer) = (0u64, [0u8; 65536]);
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total = total.checked_add(n as u64).ok_or("size overflow")?;
        if total > MAX_BINARY_BYTES {
            return Err("binary exceeds size limit".into());
        }
        hasher.update(&buffer[..n]);
    }
    Ok((total, format!("{:x}", hasher.finalize())))
}
impl Manifest {
    /// Check owned fields before using any path or identity from the manifest.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.profile != "single-binary-v1"
            || self.state_schema > CURRENT_STATE_SCHEMA
        {
            return Err("unsupported delivery or state profile".into());
        }
        if !self.product.starts_with("agent-")
            || !component(&self.product)
            || !component(&self.version)
            || !component(&self.target)
            || !component(&self.binary)
            || self.binary != format!("{}-{}", self.product, self.target)
            || self.source_commit.len() != 40
            || !self.source_commit.bytes().all(|b| b.is_ascii_hexdigit())
            || self.sha256.len() != 64
            || !self.sha256.bytes().all(|b| b.is_ascii_hexdigit())
            || self.size == 0
            || self.size > MAX_BINARY_BYTES
            || self.run_id.is_some() != self.run_attempt.is_some()
            || self.run_id == Some(0)
            || self.run_attempt == Some(0)
        {
            return Err("invalid delivery manifest".into());
        }
        Ok(())
    }
}
/// Validate a downloaded directory. Extra files, links and mismatching bytes are refused.
pub fn verify(bundle: &Path) -> Result<Manifest> {
    if !fs::symlink_metadata(bundle)?.is_dir() {
        return Err("bundle must be a real directory".into());
    }
    let manifest_path = bundle.join("release-manifest.json");
    regular(&manifest_path)?;
    if fs::metadata(&manifest_path)?.len() > 16384 {
        return Err("manifest too large".into());
    }
    let m: Manifest = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    m.validate()?;
    let entries: Vec<_> = fs::read_dir(bundle)?.collect::<std::io::Result<_>>()?;
    if entries.len() != 2
        || entries
            .iter()
            .any(|e| e.file_name() != "release-manifest.json" && e.file_name() != m.binary.as_str())
    {
        return Err("unexpected bundle inventory".into());
    }
    let (size, sha) = digest(&bundle.join(&m.binary))?;
    if size != m.size || sha != m.sha256 {
        return Err("binary integrity mismatch".into());
    }
    Ok(m)
}
/// Write a newly built binary to a NEW bundle directory. No existing version is overwritten.
pub fn package(binary: &Path, output: &Path, mut manifest: Manifest) -> Result<Manifest> {
    let (size, sha) = digest(binary)?;
    manifest.size = size;
    manifest.sha256 = sha;
    manifest.validate()?;
    fs::create_dir(output)?;
    fs::copy(binary, output.join(&manifest.binary))?;
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output.join("release-manifest.json"))?;
    out.write_all(&serde_json::to_vec_pretty(&manifest)?)?;
    out.sync_all()?;
    verify(output)
}
fn private_dir(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(m) if !m.is_dir() => return Err("installation path is a link or non-directory".into()),
        Ok(_) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => fs::create_dir(path)?,
        Err(e) => return Err(e.into()),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
fn layout(home: &Path) -> Result<(PathBuf, File)> {
    if !home.is_absolute() {
        return Err("installation home must be absolute".into());
    }
    private_dir(home)?;
    let base = home.join("standalone");
    private_dir(&base)?;
    private_dir(&base.join("releases"))?;
    let lock_path = base.join("install.lock");
    if fs::symlink_metadata(&lock_path).is_ok() {
        regular(&lock_path)?;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)?;
    FileExt::lock_exclusive(&file)?;
    Ok((base, file))
}
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
#[cfg(unix)]
fn activate(base: &Path, manifest: &Manifest, bin_dir: &Path) -> Result<()> {
    use std::os::unix::{fs::PermissionsExt, fs::symlink};
    if !bin_dir.is_absolute() {
        return Err("bin directory must be absolute".into());
    }
    if !bin_dir.is_dir() {
        return Err("create the bin directory explicitly before installation".into());
    }
    let launcher = bin_dir.join(&manifest.product);
    let marker = format!("#!/bin/sh\n# {} managed launcher v1\n", manifest.product);
    if fs::symlink_metadata(&launcher).is_ok() {
        regular(&launcher)?;
        if fs::metadata(&launcher)?.len() > 8192
            || !fs::read_to_string(&launcher)?.starts_with(&marker)
        {
            return Err("refusing to replace an unmanaged launcher".into());
        }
    }
    let current = base.join("current");
    if let Ok(m) = fs::symlink_metadata(&current) {
        if !m.file_type().is_symlink() {
            return Err("current must be a managed symlink".into());
        }
        let previous = fs::read_link(&current)?;
        if previous.is_absolute()
            || !previous.starts_with("releases")
            || previous.components().count() != 2
        {
            return Err("unmanaged current target".into());
        }
        let old = verify(&base.join(previous))?;
        if old.product != manifest.product || old.target != manifest.target {
            return Err("incompatible previous installation".into());
        }
        // Never run an older state schema against newer on-disk state; same or
        // newer is fine (newer code reads or migrates the older state).
        if manifest.state_schema < old.state_schema {
            return Err("release predates the state schema already in use".into());
        }
    }
    // Preserve executable identity for every new process; it does not repeatedly resolve current.
    let body = format!(
        "{marker}set -eu\nbase={}\nrelease=$(readlink \"$base/current\")\nexec \"$base/$release/{}\" \"$@\"\n",
        shell_quote(base.to_str().ok_or("non-UTF8 installation path")?),
        manifest.binary
    );
    let temp_launcher = bin_dir.join(format!(
        ".{}.install-{}",
        manifest.product,
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_launcher)?;
    file.write_all(body.as_bytes())?;
    file.sync_all()?;
    fs::set_permissions(&temp_launcher, fs::Permissions::from_mode(0o755))?;
    let next = base.join(format!(".current-{}", std::process::id()));
    symlink(Path::new("releases").join(&manifest.version), &next)?;
    // Both versions use the same target-specific asset name. Existing services are not restarted.
    fs::rename(&temp_launcher, &launcher)?;
    fs::rename(&next, current)?;
    Ok(())
}
#[cfg(not(unix))]
fn activate(_: &Path, _: &Manifest, _: &Path) -> Result<()> {
    Err("installer supports Unix only".into())
}
/// Install without migration, pruning, stopping services or changing host configuration.
pub fn install(bundle: &Path, home: &Path, bin_dir: &Path) -> Result<Manifest> {
    let manifest = verify(bundle)?;
    let (base, _lock) = layout(home)?;
    let destination = base.join("releases").join(&manifest.version);
    if fs::symlink_metadata(&destination).is_ok() {
        if verify(&destination)? != manifest {
            return Err("immutable version already exists with different bytes or metadata".into());
        }
    } else {
        let stage = base.join(format!(".install-{}", std::process::id()));
        fs::create_dir(&stage)?;
        fs::copy(bundle.join(&manifest.binary), stage.join(&manifest.binary))?;
        fs::copy(
            bundle.join("release-manifest.json"),
            stage.join("release-manifest.json"),
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                stage.join(&manifest.binary),
                fs::Permissions::from_mode(0o755),
            )?;
        }
        verify(&stage)?;
        fs::rename(stage, &destination)?;
    }
    activate(&base, &manifest, bin_dir)?;
    Ok(manifest)
}
/// Activate a retained version only after verifying its integrity and state profile.
pub fn use_version(home: &Path, bin_dir: &Path, version: &str) -> Result<Manifest> {
    if !component(version) {
        return Err("invalid version component".into());
    }
    let (base, _lock) = layout(home)?;
    let manifest = verify(&base.join("releases").join(version))?;
    activate(&base, &manifest, bin_dir)?;
    Ok(manifest)
}
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "Test fixtures fail explicitly"
)]
mod tests {
    use super::*;
    fn fixture(root: &Path, version: &str, state_schema: u32) -> PathBuf {
        let binary = root.join(format!("source-{version}"));
        fs::write(&binary, b"fixture, not executable").unwrap();
        let bundle = root.join(format!("bundle-{version}"));
        package(
            &binary,
            &bundle,
            Manifest {
                schema_version: 1,
                profile: "single-binary-v1".into(),
                product: "agent-test".into(),
                version: version.into(),
                source_commit: "a".repeat(40),
                target: "aarch64-apple-darwin".into(),
                binary: "agent-test-aarch64-apple-darwin".into(),
                size: 1,
                sha256: "0".repeat(64),
                state_schema,
                run_id: None,
                run_attempt: None,
            },
        )
        .unwrap();
        bundle
    }
    #[test]
    fn verified_bundle() {
        let t = tempfile::tempdir().unwrap();
        assert_eq!(
            verify(&fixture(t.path(), "0.1.0", 0)).unwrap().version,
            "0.1.0"
        );
    }
    #[test]
    fn tampered_binary_rejected() {
        let t = tempfile::tempdir().unwrap();
        let b = fixture(t.path(), "0.1.0", 0);
        fs::write(b.join("agent-test-aarch64-apple-darwin"), b"tampered").unwrap();
        assert!(verify(&b).is_err());
    }
    #[test]
    fn extra_file_rejected() {
        let t = tempfile::tempdir().unwrap();
        let b = fixture(t.path(), "0.1.0", 0);
        fs::write(b.join("extra"), b"x").unwrap();
        assert!(verify(&b).is_err());
    }
    #[test]
    fn traversal_rejected() {
        for s in ["..", "../x", "/tmp/x", "x/y", "x\\y", ""] {
            assert!(!component(s));
        }
    }
    #[cfg(unix)]
    #[test]
    fn binary_symlink_rejected() {
        let t = tempfile::tempdir().unwrap();
        let b = fixture(t.path(), "0.1.0", 0);
        let p = b.join("agent-test-aarch64-apple-darwin");
        fs::remove_file(&p).unwrap();
        std::os::unix::fs::symlink(t.path().join("source-0.1.0"), p).unwrap();
        assert!(verify(&b).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn install_noop_and_rollback() {
        let t = tempfile::tempdir().unwrap();
        let h = t.path().join("home");
        let bin = t.path().join("bin");
        fs::create_dir(&bin).unwrap();
        let a = fixture(t.path(), "0.1.0", 0);
        let b = fixture(t.path(), "0.2.0", 0);
        install(&a, &h, &bin).unwrap();
        install(&a, &h, &bin).unwrap();
        install(&b, &h, &bin).unwrap();
        use_version(&h, &bin, "0.1.0").unwrap();
        assert_eq!(
            fs::read_link(h.join("standalone/current")).unwrap(),
            PathBuf::from("releases/0.1.0")
        );
    }
    #[cfg(unix)]
    #[test]
    fn stateful_upgrade_and_rollback_keep_owner_state_intact() {
        let t = tempfile::tempdir().unwrap();
        let h = t.path().join("home");
        // The owner's pre-existing local state, outside `standalone/`.
        fs::create_dir_all(h.join("state/v1")).unwrap();
        fs::write(h.join("config.toml"), b"[storage]\nroot = \"/tmp/wt\"\n").unwrap();
        fs::write(h.join("state/v1/registry.json"), b"{\"entries\":[]}\n").unwrap();
        let (config, registry) = (
            fs::read(h.join("config.toml")).unwrap(),
            fs::read(h.join("state/v1/registry.json")).unwrap(),
        );
        let bin = t.path().join("bin");
        fs::create_dir(&bin).unwrap();
        install(&fixture(t.path(), "0.1.0", CURRENT_STATE_SCHEMA), &h, &bin).unwrap();
        install(&fixture(t.path(), "0.2.0", CURRENT_STATE_SCHEMA), &h, &bin).unwrap();
        use_version(&h, &bin, "0.1.0").unwrap();
        assert_eq!(
            fs::read_link(h.join("standalone/current")).unwrap(),
            PathBuf::from("releases/0.1.0")
        );
        assert_eq!(fs::read(h.join("config.toml")).unwrap(), config);
        assert_eq!(
            fs::read(h.join("state/v1/registry.json")).unwrap(),
            registry
        );
    }
    #[cfg(unix)]
    #[test]
    fn older_state_schema_cannot_run_over_newer_state() {
        let t = tempfile::tempdir().unwrap();
        let h = t.path().join("home");
        let bin = t.path().join("bin");
        fs::create_dir(&bin).unwrap();
        install(&fixture(t.path(), "0.1.0", CURRENT_STATE_SCHEMA), &h, &bin).unwrap();
        assert!(install(&fixture(t.path(), "0.2.0", 0), &h, &bin).is_err());
        assert!(use_version(&h, &bin, "0.2.0").is_err());
        assert_eq!(
            fs::read_link(h.join("standalone/current")).unwrap(),
            PathBuf::from("releases/0.1.0")
        );
    }
    #[cfg(unix)]
    #[test]
    fn unmanaged_launcher_preserved() {
        let t = tempfile::tempdir().unwrap();
        let b = fixture(t.path(), "0.1.0", 0);
        let bin = t.path().join("bin");
        fs::create_dir(&bin).unwrap();
        fs::write(bin.join("agent-test"), b"mine").unwrap();
        assert!(install(&b, &t.path().join("home"), &bin).is_err());
        assert_eq!(fs::read(bin.join("agent-test")).unwrap(), b"mine");
    }
}
