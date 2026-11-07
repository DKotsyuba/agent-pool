//! Strict local service configuration and private-file boundary checks.
use crate::domain::Fault;
use serde::Deserialize;
use std::{
    fs,
    io::Read,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

/// Maximum accepted configuration or credential file size in bytes.
const MAX_CONFIG: u64 = 65_536;

/// Explicit operator-provisioned endpoints; none of these values identifies a caller.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Resident's absolute private Unix socket path.
    pub socket_path: PathBuf,
    /// Resident's absolute SQLite path, under an owner-only directory.
    pub database_path: PathBuf,
    /// Required local UID for the resident, Bridge endpoints and private credentials.
    pub expected_uid: u32,
    /// Bridge adapter endpoint used by the actual MCP process to register calls.
    pub bridge_registration_socket: PathBuf,
    /// Bridge core endpoint used to consume fresh assertions and deliver effects.
    pub bridge_core_socket: PathBuf,
    /// Owner-only producer credential file; never a tool argument or environment token.
    pub bridge_credential_file: PathBuf,
    /// Provisioned Bridge producer ID; also frozen into every publication.
    pub bridge_producer_id: String,
    /// Exact configured audience required on every consumed assertion.
    pub bridge_audience: String,
    /// Optional separately authorized Bridge host-observation endpoint.
    pub bridge_observer_socket: Option<PathBuf>,
    /// Optional owner-only credential carrying the separate observation grant.
    pub bridge_observer_credential_file: Option<PathBuf>,
    /// Optional separate owner read-only Pool grant; absence disables owner observation.
    pub owner_observer_credential_file: Option<PathBuf>,
    /// Optional resident Run public API; absence leaves external-agent pools usable.
    pub run_socket: Option<PathBuf>,
    /// Optional trusted Linux Run server UID; absent keeps the same-user private socket policy.
    pub run_peer_uid: Option<u32>,
}
impl Config {
    /// Reads a bounded TOML file and rejects relative paths, unknown keys and incomplete grants.
    /// Does not connect, create files, infer identities or modify endpoint permissions.
    pub fn load(path: &Path) -> Result<Self, Fault> {
        let raw = read_bounded(path, MAX_CONFIG)?;
        let config: Self = toml::from_str(std::str::from_utf8(&raw).map_err(|_| Fault::Invalid)?)
            .map_err(|_| Fault::Invalid)?;
        for path in [
            &config.socket_path,
            &config.database_path,
            &config.bridge_registration_socket,
            &config.bridge_core_socket,
            &config.bridge_credential_file,
        ]
        .into_iter()
        .chain(config.bridge_observer_socket.iter())
        .chain(config.bridge_observer_credential_file.iter())
        .chain(config.owner_observer_credential_file.iter())
        .chain(config.run_socket.iter())
        {
            if !path.is_absolute()
                || path
                    .components()
                    .any(|part| matches!(part, std::path::Component::ParentDir))
            {
                return Err(Fault::Invalid);
            }
        }
        if config.bridge_producer_id.is_empty()
            || config.bridge_producer_id.len() > 128
            || config.bridge_audience.is_empty()
            || config.bridge_audience.len() > 256
            || config.bridge_producer_id.chars().any(char::is_control)
            || config.bridge_audience.chars().any(char::is_control)
            || config.bridge_observer_socket.is_some()
                != config.bridge_observer_credential_file.is_some()
            || config.run_peer_uid.is_some() && config.run_socket.is_none()
            || config.run_peer_uid.is_some() && !cfg!(target_os = "linux")
            || config.run_peer_uid == Some(u32::MAX)
        {
            return Err(Fault::Invalid);
        }
        Ok(config)
    }

    /// Reads a nonempty owner-only credential without printing or retaining its path in errors.
    pub fn credential(&self, path: &Path) -> Result<String, Fault> {
        private_file(path, self.expected_uid)?;
        let bytes = read_bounded(path, MAX_CONFIG)?;
        let token = std::str::from_utf8(&bytes)
            .map_err(|_| Fault::Unavailable)?
            .trim();
        if token.is_empty() || token.chars().any(char::is_control) {
            return Err(Fault::Unavailable);
        }
        Ok(token.to_owned())
    }
}

/// Reads at most `maximum` bytes plus a sentinel; oversized files fail before unbounded allocation.
fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, Fault> {
    let file = fs::File::open(path).map_err(|_| Fault::Unavailable)?;
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Fault::Unavailable)?;
    if bytes.len() as u64 > maximum {
        return Err(Fault::Invalid);
    }
    Ok(bytes)
}

/// Requires an existing nonsymlink owner-only parent directory; never silently chmods user files.
pub fn private_parent(path: &Path, uid: u32) -> Result<(), Fault> {
    let parent = path.parent().ok_or(Fault::Invalid)?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| Fault::Unavailable)?;
    if !metadata.is_dir() || metadata.uid() != uid || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(Fault::Unavailable);
    }
    Ok(())
}

/// Requires an owner-only parent and nonsymlink regular file owned by `uid` with exact mode 0600.
pub fn private_file(path: &Path, uid: u32) -> Result<(), Fault> {
    private_parent(path, uid)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| Fault::Unavailable)?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(Fault::Unavailable);
    }
    Ok(())
}

/// Requires an owner-only Unix socket and directory before connecting; peer UID is checked separately.
pub fn private_socket(path: &Path, uid: u32) -> Result<(), Fault> {
    private_parent(path, uid)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| Fault::Unavailable)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(Fault::Unavailable);
    }
    Ok(())
}

/// Verifies the full identity UID map before trusting cross-user Linux peer credentials.
#[cfg(target_os = "linux")]
pub(crate) fn identity_uid_map() -> Result<(), Fault> {
    let map =
        read_bounded(Path::new("/proc/self/uid_map"), 4096).map_err(|_| Fault::Unavailable)?;
    if !is_identity_uid_map(&map) {
        return Err(Fault::Unavailable);
    }
    Ok(())
}

/// Accepts only the single full-range identity mapping, including optional whitespace.
#[cfg(target_os = "linux")]
fn is_identity_uid_map(map: &[u8]) -> bool {
    std::str::from_utf8(map).is_ok_and(|map| map.split_whitespace().eq(["0", "0", "4294967295"]))
}

/// Stable filesystem identity and access bits for one checked Run path component.
#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RunPathFingerprint {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

/// Captures identity and mode after the caller has checked the component's type and policy.
#[cfg(target_os = "linux")]
fn run_fingerprint(metadata: &fs::Metadata) -> RunPathFingerprint {
    RunPathFingerprint {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode(),
    }
}

/// Rejects replaceable ancestors and other-user access to the immediate Run directory.
#[cfg(target_os = "linux")]
fn run_directory(metadata: &fs::Metadata, peer_uid: u32, immediate: bool) -> Result<(), Fault> {
    if !metadata.is_dir()
        || !run_directory_attributes(metadata.uid(), metadata.mode(), peer_uid, immediate)
    {
        return Err(Fault::Unavailable);
    }
    Ok(())
}

/// Allows root or the peer to own directories that other principals cannot replace.
#[cfg(target_os = "linux")]
fn run_directory_attributes(owner: u32, mode: u32, peer_uid: u32, immediate: bool) -> bool {
    (owner == 0 || owner == peer_uid) && mode & 0o022 == 0 && (!immediate || mode & 0o007 == 0)
}

/// Rejects links, foreign owners, special bits and world-accessible Run sockets.
#[cfg(target_os = "linux")]
fn run_endpoint(metadata: &fs::Metadata, peer_uid: u32) -> Result<(), Fault> {
    if !metadata.file_type().is_socket()
        || metadata.uid() != peer_uid
        || metadata.mode() & 0o7007 != 0
    {
        return Err(Fault::Unavailable);
    }
    Ok(())
}

/// Checks every absolute Run path component and returns identities to recheck after connecting.
#[cfg(target_os = "linux")]
pub(crate) fn shared_run_socket(
    path: &Path,
    peer_uid: u32,
) -> Result<Vec<RunPathFingerprint>, Fault> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(Fault::Invalid);
    }
    let parent = path.parent().ok_or(Fault::Invalid)?;
    let mut ancestors: Vec<_> = parent.ancestors().collect();
    ancestors.reverse();
    let mut fingerprints = Vec::with_capacity(ancestors.len() + 1);
    for ancestor in ancestors {
        let metadata = fs::symlink_metadata(ancestor).map_err(|_| Fault::Unavailable)?;
        run_directory(&metadata, peer_uid, ancestor == parent)?;
        fingerprints.push(run_fingerprint(&metadata));
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| Fault::Unavailable)?;
    run_endpoint(&metadata, peer_uid)?;
    fingerprints.push(run_fingerprint(&metadata));
    Ok(fingerprints)
}

/// Local permission fixtures; they never touch configured live credentials or service sockets.
#[cfg(test)]
mod tests {
    use super::*;

    /// Credential files and parents must be private; wrong ownership, modes and symlinks are refused.
    #[test]
    fn private_credentials_reject_permissions_owner_and_symlink()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory =
            tempfile::tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path().join("credential");
        fs::write(&path, "fixture-secret")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let uid = fs::metadata(&path)?.uid();
        private_file(&path, uid)?;
        assert!(matches!(
            private_file(&path, uid.wrapping_add(1)),
            Err(Fault::Unavailable)
        ));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        assert!(matches!(private_file(&path, uid), Err(Fault::Unavailable)));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let alias = directory.path().join("alias");
        std::os::unix::fs::symlink(&path, &alias)?;
        assert!(matches!(private_file(&alias, uid), Err(Fault::Unavailable)));
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755))?;
        assert!(matches!(private_file(&path, uid), Err(Fault::Unavailable)));
        assert!(matches!(
            private_parent(&path, uid),
            Err(Fault::Unavailable)
        ));
        Ok(())
    }

    /// Run peer configuration is opt-in, paired with a socket and restricted to Linux.
    #[test]
    fn run_peer_configuration_is_explicit_and_validated() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory =
            tempfile::tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        let path = directory.path().join("config.toml");
        let base = r#"
socket_path = "/pool.sock"
database_path = "/pool.sqlite"
expected_uid = 1001
bridge_registration_socket = "/adapter.sock"
bridge_core_socket = "/core.sock"
bridge_credential_file = "/token"
bridge_producer_id = "fixture"
bridge_audience = "fixture"
"#;
        fs::write(&path, base)?;
        assert!(Config::load(&path)?.run_peer_uid.is_none());
        fs::write(&path, format!("{base}\nrun_peer_uid = 1000\n"))?;
        assert!(matches!(Config::load(&path), Err(Fault::Invalid)));
        fs::write(
            &path,
            format!("{base}\nrun_socket = \"/run.sock\"\nrun_peer_uid = 4294967295\n"),
        )?;
        assert!(matches!(Config::load(&path), Err(Fault::Invalid)));
        fs::write(
            &path,
            format!("{base}\nrun_socket = \"/run.sock\"\nrun_peer_uid = 1000\n"),
        )?;
        if cfg!(target_os = "linux") {
            assert_eq!(Config::load(&path)?.run_peer_uid, Some(1000));
        } else {
            assert!(matches!(Config::load(&path), Err(Fault::Invalid)));
        }
        Ok(())
    }

    /// Only the complete kernel identity map authorizes cross-user credential comparisons.
    #[cfg(target_os = "linux")]
    #[test]
    fn run_peer_requires_full_identity_uid_map() {
        assert!(is_identity_uid_map(b"         0          0 4294967295\n"));
        for map in [
            &b"1001 0 1\n"[..],
            &b"0 0 1\n"[..],
            &b"0 0 4294967295\n1000 1000 1\n"[..],
            &b"0 0 4294967296\n"[..],
            &b"0 0 4294967295\n\xff"[..],
            &b""[..],
        ] {
            assert!(!is_identity_uid_map(map));
        }
    }

    /// Run ancestors reject replaceable ownership, unsafe modes and symlink components.
    #[cfg(target_os = "linux")]
    #[test]
    fn shared_run_directory_rejects_unsafe_owners_modes_and_symlinks()
    -> Result<(), Box<dyn std::error::Error>> {
        assert!(run_directory_attributes(0, 0o755, 1000, false));
        assert!(run_directory_attributes(1000, 0o2750, 1000, true));
        assert!(!run_directory_attributes(1001, 0o700, 1000, true));
        assert!(!run_directory_attributes(1000, 0o770, 1000, false));
        assert!(!run_directory_attributes(1000, 0o707, 1000, false));
        assert!(!run_directory_attributes(1000, 0o755, 1000, true));

        let directory =
            tempfile::tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o2750))?;
        let metadata = fs::symlink_metadata(directory.path())?;
        let uid = metadata.uid();
        run_directory(&metadata, uid, true)?;
        let alias = directory.path().join("alias");
        std::os::unix::fs::symlink(directory.path(), &alias)?;
        assert!(matches!(
            run_directory(&fs::symlink_metadata(&alias)?, uid, true),
            Err(Fault::Unavailable)
        ));
        Ok(())
    }

    /// Run sockets reject foreign owners, world access, special bits and symlinks.
    #[cfg(target_os = "linux")]
    #[test]
    fn shared_run_socket_rejects_unsafe_metadata_and_symlinks()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory =
            tempfile::tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        let uid = fs::symlink_metadata(directory.path())?.uid();
        let socket = directory.path().join("run.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket)?;
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o770))?;
        let socket_metadata = fs::symlink_metadata(&socket)?;
        run_endpoint(&socket_metadata, uid)?;
        assert!(matches!(
            run_endpoint(&socket_metadata, uid ^ 1),
            Err(Fault::Unavailable)
        ));
        let before = run_fingerprint(&socket_metadata);
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o660))?;
        let after = fs::symlink_metadata(&socket)?;
        run_endpoint(&after, uid)?;
        assert_ne!(before, run_fingerprint(&after));
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o666))?;
        assert!(matches!(
            run_endpoint(&fs::symlink_metadata(&socket)?, uid),
            Err(Fault::Unavailable)
        ));
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o1770))?;
        assert!(matches!(
            run_endpoint(&fs::symlink_metadata(&socket)?, uid),
            Err(Fault::Unavailable)
        ));
        let socket_alias = directory.path().join("socket-alias");
        std::os::unix::fs::symlink(&socket, &socket_alias)?;
        assert!(matches!(
            run_endpoint(&fs::symlink_metadata(&socket_alias)?, uid),
            Err(Fault::Unavailable)
        ));
        Ok(())
    }
}
