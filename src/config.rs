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
    /// Required UID for all endpoint, credential and peer ownership checks.
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

/// Requires a nonsymlink regular credential/data file owned by `uid` with exact mode 0600.
pub fn private_file(path: &Path, uid: u32) -> Result<(), Fault> {
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

/// Local permission fixtures; they never touch configured live credentials or service sockets.
#[cfg(test)]
mod tests {
    use super::*;

    /// Credential files must have exact ownership/mode; readable copies and symlinks are refused.
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
        assert!(matches!(
            private_parent(&path, uid),
            Err(Fault::Unavailable)
        ));
        Ok(())
    }
}
