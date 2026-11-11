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
    /// Absolute canonical Bridge managed server executable, explicitly pinned by the operator.
    pub bridge_server_executable: PathBuf,
    /// Lowercase SHA-256 of that exact Bridge managed server build.
    pub bridge_server_sha256: String,
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
    /// Optional separately provisioned Run reader for managed outcome and namespace operations.
    pub managed_run_reader: Option<ManagedRunReader>,
    /// Optional separately provisioned private Run attempt transport; absence disables it.
    pub managed_run_transport: Option<ManagedRunTransport>,
}
/// Exact same-UID Run reader build and Bridge namespace grant for private P1 reads.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedRunReader {
    /// Absolute executable path; its loaded inode and hash are checked for every request.
    pub executable: PathBuf,
    /// Lowercase SHA-256 of the provisioned reader executable.
    pub sha256: String,
    /// Bridge store UUID whose namespaces this reader may seal.
    pub bridge_store_id: String,
    /// Exact configured Bridge route ID.
    pub bridge_route_id: String,
    /// Exact configured Bridge producer name.
    pub producer: String,
    /// Exact Run store identity whose admission outcomes this reader may query.
    pub run_store_id: String,
    /// Exact configured Run route identity.
    pub run_route_id: String,
}
/// Pinned same-UID Run attempt endpoint and cross-service route identities.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedRunTransport {
    /// Explicitly select the managed stdio frontend; absent keeps legacy routing.
    #[serde(default)]
    pub frontend_enabled: bool,
    /// Exact MCP server name registered in Bridge's managed tool mapping.
    pub mcp_server: Option<String>,
    /// Explicitly enable managed owner egress; omission keeps it disabled.
    #[serde(default)]
    pub egress_enabled: bool,
    /// Exact `pool/<pool-store-uuid>/` prefix provisioned in Bridge and Run.
    pub producer_scope_prefix: Option<String>,
    /// Absolute Run `attempt.sock`, distinct from the legacy Run socket.
    pub socket: PathBuf,
    /// Absolute canonical Run broker executable.
    pub executable: PathBuf,
    /// Lowercase SHA-256 of that broker build.
    pub sha256: String,
    /// Durable Run store ID.
    pub run_store_id: String,
    /// Original Run route ID.
    pub run_route_id: String,
    /// Pool route ID provisioned in Run.
    pub pool_route_id: String,
    /// Durable Bridge store UUID.
    pub bridge_store_id: String,
    /// Original Bridge route ID.
    pub bridge_route_id: String,
    /// Bridge producer identity pinned on both sides.
    pub producer: String,
    /// Explicitly route owner start, batch and replacement through P3 managed
    /// enrollment; omission keeps the switch off and new enrollment closed.
    #[serde(default)]
    pub enrollment_enabled: bool,
    /// Exact Run managed role selected for every P3 enrollment job.
    pub managed_role: Option<String>,
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
            &config.bridge_server_executable,
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
            || config.bridge_server_sha256.len() != 64
            || !config
                .bridge_server_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || config.bridge_observer_socket.is_some()
                != config.bridge_observer_credential_file.is_some()
            || config.run_peer_uid.is_some() && config.run_socket.is_none()
            || config.run_peer_uid.is_some() && !cfg!(target_os = "linux")
            || config.run_peer_uid == Some(u32::MAX)
        {
            return Err(Fault::Invalid);
        }
        if let Some(reader) = &config.managed_run_reader {
            let valid_string = |value: &str| {
                !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
            };
            if !cfg!(target_os = "linux")
                || !reader.executable.is_absolute()
                || reader
                    .executable
                    .components()
                    .any(|part| matches!(part, std::path::Component::ParentDir))
                || reader.sha256.len() != 64
                || !reader
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                || !uuid::Uuid::parse_str(&reader.bridge_store_id)
                    .is_ok_and(|id| id.to_string() == reader.bridge_store_id)
                || !valid_string(&reader.bridge_route_id)
                || !valid_string(&reader.producer)
                || crate::domain::store_id(&reader.run_store_id).is_err()
                || !valid_string(&reader.run_route_id)
            {
                return Err(Fault::Invalid);
            }
        }
        if let Some(transport) = &config.managed_run_transport {
            if transport.egress_enabled {
                let prefix = transport
                    .producer_scope_prefix
                    .as_deref()
                    .ok_or(Fault::Invalid)?;
                let store = prefix
                    .strip_prefix("pool/")
                    .and_then(|value| value.strip_suffix('/'))
                    .ok_or(Fault::Invalid)?;
                if !uuid::Uuid::parse_str(store).is_ok_and(|id| id.to_string() == store) {
                    return Err(Fault::Invalid);
                }
            } else if transport.producer_scope_prefix.is_some() {
                return Err(Fault::Invalid);
            }
            if transport.frontend_enabled
                && (config.managed_run_reader.is_none()
                    || transport.mcp_server.as_ref().is_none_or(|server| {
                        server.is_empty()
                            || server.len() > 128
                            || !server
                                .bytes()
                                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
                    }))
            {
                return Err(Fault::Invalid);
            }
            if transport.enrollment_enabled
                && (!transport.frontend_enabled
                    || transport
                        .managed_role
                        .as_deref()
                        .is_none_or(|role| crate::domain::identifier(role).is_err()))
            {
                return Err(Fault::Invalid);
            }
            if !transport.enrollment_enabled && transport.managed_role.is_some() {
                return Err(Fault::Invalid);
            }
            let valid_string = |value: &str| {
                !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
            };
            let valid_path = |path: &Path| {
                path.is_absolute()
                    && !path
                        .components()
                        .any(|part| matches!(part, std::path::Component::ParentDir))
            };
            if !cfg!(target_os = "linux")
                || !valid_path(&transport.socket)
                || transport
                    .socket
                    .file_name()
                    .is_none_or(|name| name != "attempt.sock")
                || !valid_path(&transport.executable)
                || transport.sha256.len() != 64
                || !transport
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                || crate::domain::store_id(&transport.run_store_id).is_err()
                || !uuid::Uuid::parse_str(&transport.bridge_store_id)
                    .is_ok_and(|id| id.to_string() == transport.bridge_store_id)
                || !valid_string(&transport.run_route_id)
                || !valid_string(&transport.pool_route_id)
                || !valid_string(&transport.bridge_route_id)
                || transport.producer != config.bridge_producer_id
            {
                return Err(Fault::Invalid);
            }
        }
        if let (Some(reader), Some(transport)) =
            (&config.managed_run_reader, &config.managed_run_transport)
            && (reader.run_store_id != transport.run_store_id
                || reader.run_route_id != transport.run_route_id
                || reader.bridge_store_id != transport.bridge_store_id
                || reader.bridge_route_id != transport.bridge_route_id
                || reader.producer != transport.producer)
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

/// Largest executable whose digest an operator re-pin computes.
const MAX_EXECUTABLE: u64 = 512 * 1024 * 1024;

/// Proves a candidate pinned executable before an operator re-pin adopts it: the
/// absolute path is already canonical, names a regular file owned by `uid` or root
/// that group and other cannot write, and the opened file's digest equals `sha256`.
/// The live peer proof stays with each authenticated exchange. Returns a fixed
/// nonsecret reason for the operator.
pub(crate) fn trusted_executable(path: &Path, sha256: &str, uid: u32) -> Result<(), &'static str> {
    use sha2::{Digest, Sha256};
    if !path.is_absolute() || fs::canonicalize(path).ok().as_deref() != Some(path) {
        return Err("not_canonical");
    }
    let named = fs::symlink_metadata(path).map_err(|_| "unreadable")?;
    if !named.is_file() || named.len() > MAX_EXECUTABLE {
        return Err("not_regular_file");
    }
    if named.uid() != uid && named.uid() != 0 {
        return Err("untrusted_owner");
    }
    if named.permissions().mode() & 0o022 != 0 {
        return Err("writable_by_others");
    }
    let mut file = fs::File::open(path).map_err(|_| "unreadable")?;
    let opened = file.metadata().map_err(|_| "unreadable")?;
    let identity = |meta: &fs::Metadata| {
        (
            meta.dev(),
            meta.ino(),
            meta.uid(),
            meta.mode(),
            meta.len(),
            meta.mtime(),
            meta.mtime_nsec(),
            meta.ctime(),
            meta.ctime_nsec(),
        )
    };
    if identity(&opened) != identity(&named) {
        return Err("changed_during_check");
    }
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 65_536];
    loop {
        let read = file.read(&mut buffer).map_err(|_| "unreadable")?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let after = fs::symlink_metadata(path).map_err(|_| "unreadable")?;
    if identity(&file.metadata().map_err(|_| "unreadable")?) != identity(&opened)
        || identity(&after) != identity(&opened)
    {
        return Err("changed_during_check");
    }
    if format!("{:x}", digest.finalize()) != sha256 {
        return Err("digest_mismatch");
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

    /// A re-pinned executable must be canonical, trusted-owned, not writable by others and exact.
    #[test]
    fn trusted_executable_rejects_alias_owner_mode_and_digest()
    -> Result<(), Box<dyn std::error::Error>> {
        use sha2::{Digest, Sha256};
        let directory =
            tempfile::tempdir_in(std::env::var_os("TMPDIR").ok_or("task TMPDIR required")?)?;
        let root = fs::canonicalize(directory.path())?;
        let path = root.join("bridge-native-daemon");
        fs::write(&path, "fixture-build-0.7.1")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
        let uid = fs::metadata(&path)?.uid();
        let sha = format!("{:x}", Sha256::digest(fs::read(&path)?));
        trusted_executable(&path, &sha, uid)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o500))?;
        trusted_executable(&path, &sha, uid)?;
        if uid != 0 {
            assert_eq!(
                trusted_executable(&path, &sha, uid.wrapping_add(1)),
                Err("untrusted_owner")
            );
        }
        for mode in [0o775, 0o757, 0o722] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
            assert_eq!(
                trusted_executable(&path, &sha, uid),
                Err("writable_by_others")
            );
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
        assert_eq!(
            trusted_executable(&path, &"0".repeat(64), uid),
            Err("digest_mismatch")
        );
        let alias = root.join("current");
        std::os::unix::fs::symlink(&path, &alias)?;
        assert_eq!(trusted_executable(&alias, &sha, uid), Err("not_canonical"));
        let nested = root.join("releases");
        fs::create_dir(&nested)?;
        assert_eq!(
            trusted_executable(&nested.join("..").join("bridge-native-daemon"), &sha, uid),
            Err("not_canonical")
        );
        assert_eq!(
            trusted_executable(Path::new("bridge-native-daemon"), &sha, uid),
            Err("not_canonical")
        );
        assert_eq!(
            trusted_executable(&root.join("absent"), &sha, uid),
            Err("not_canonical")
        );
        assert_eq!(
            trusted_executable(&root, &sha, uid),
            Err("not_regular_file")
        );
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
bridge_server_executable = "/fixture/bridge"
bridge_server_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
"#;
        fs::write(&path, base)?;
        assert!(Config::load(&path)?.run_peer_uid.is_none());
        fs::write(
            &path,
            base.replace("bridge_server_executable = \"/fixture/bridge\"\n", ""),
        )?;
        assert!(matches!(Config::load(&path), Err(Fault::Invalid)));
        fs::write(&path, base.replace("/fixture/bridge", "relative-bridge"))?;
        assert!(matches!(Config::load(&path), Err(Fault::Invalid)));
        fs::write(&path, base.replace(&"0".repeat(64), &"A".repeat(64)))?;
        assert!(matches!(Config::load(&path), Err(Fault::Invalid)));
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
        let managed = r#"
[managed_run_transport]
socket = "/run/attempt.sock"
executable = "/fixture/run"
sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
run_store_id = "store_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
run_route_id = "run-route"
pool_route_id = "pool-route"
bridge_store_id = "00000000-0000-4000-8000-000000000001"
bridge_route_id = "bridge-route"
producer = "fixture"
"#;
        fs::write(&path, format!("{base}\n{managed}"))?;
        if cfg!(target_os = "linux") {
            assert!(Config::load(&path)?.managed_run_transport.is_some());
        } else {
            assert!(matches!(Config::load(&path), Err(Fault::Invalid)));
        }
        let missing_prefix = managed.replace(
            "[managed_run_transport]",
            "[managed_run_transport]\negress_enabled = true",
        );
        fs::write(&path, format!("{base}\n{missing_prefix}"))?;
        assert!(matches!(Config::load(&path), Err(Fault::Invalid)));
        let with_prefix=managed.replace("[managed_run_transport]","[managed_run_transport]\negress_enabled = true\nproducer_scope_prefix = \"pool/00000000-0000-4000-8000-000000000001/\"");
        fs::write(&path, format!("{base}\n{with_prefix}"))?;
        if cfg!(target_os = "linux") {
            assert!(
                Config::load(&path)?
                    .managed_run_transport
                    .is_some_and(|value| value.egress_enabled)
            );
        }
        fs::write(
            &path,
            format!(
                "{base}\n{}",
                with_prefix.replace("000000000001/\"", "000000000001//\"")
            ),
        )?;
        assert!(matches!(Config::load(&path), Err(Fault::Invalid)));
        let enabled = managed.replace(
            "[managed_run_transport]",
            "[managed_run_transport]\nfrontend_enabled = true\nmcp_server = \"pool\"",
        );
        fs::write(&path, format!("{base}\n{enabled}"))?;
        assert!(matches!(Config::load(&path), Err(Fault::Invalid)));
        let reader = r#"
[managed_run_reader]
executable = "/fixture/run"
sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
run_store_id = "store_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
run_route_id = "run-route"
bridge_store_id = "00000000-0000-4000-8000-000000000001"
bridge_route_id = "bridge-route"
producer = "fixture"
"#;
        fs::write(&path, format!("{base}\n{enabled}\n{reader}"))?;
        if cfg!(target_os = "linux") {
            assert!(
                Config::load(&path)?
                    .managed_run_transport
                    .is_some_and(|value| value.frontend_enabled)
            );
        }
        // P3 enrollment fails closed: it needs the managed frontend and an exact
        // role, and a role without the explicit switch is refused.
        let enrolled = enabled.replace(
            "frontend_enabled = true",
            "frontend_enabled = true\nenrollment_enabled = true\nmanaged_role = \"managed\"",
        );
        fs::write(&path, format!("{base}\n{enrolled}\n{reader}"))?;
        if cfg!(target_os = "linux") {
            assert!(
                Config::load(&path)?
                    .managed_run_transport
                    .is_some_and(|value| value.enrollment_enabled
                        && value.managed_role.as_deref() == Some("managed"))
            );
        }
        for refused in [
            enrolled.replace("\nmanaged_role = \"managed\"", ""),
            enrolled.replace("managed_role = \"managed\"", "managed_role = \"bad role\""),
            enrolled.replace("frontend_enabled = true\n", ""),
            enabled.replace(
                "frontend_enabled = true",
                "frontend_enabled = true\nmanaged_role = \"managed\"",
            ),
        ] {
            fs::write(&path, format!("{base}\n{refused}\n{reader}"))?;
            assert!(matches!(Config::load(&path), Err(Fault::Invalid)));
        }
        fs::write(
            &path,
            format!(
                "{base}\n{}",
                managed.replace("/run/attempt.sock", "/run/legacy.sock")
            ),
        )?;
        assert!(matches!(Config::load(&path), Err(Fault::Invalid)));
        fs::write(
            &path,
            format!(
                "{base}\n{}",
                managed.replace("producer = \"fixture\"", "producer = \"other\"")
            ),
        )?;
        assert!(matches!(Config::load(&path), Err(Fault::Invalid)));
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
