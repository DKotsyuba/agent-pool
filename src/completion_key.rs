//! Protected per-saga Ed25519 release-key custody for completion holds.
//!
//! Each settlement saga owns one fresh key file, mode 0600, in a private
//! resident-owned directory beside the Pool database. Only an opaque key
//! reference and the public key enter SQLite. Key bytes, signatures and paths
//! never enter model arguments, process arguments, logs, records or replies.
//! A missing or substituted key is reported as unavailable: it is never
//! regenerated, and no time-based unlock exists.
use crate::domain::Fault;
use ed25519_dalek::{Signer, SigningKey};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

/// Subdirectory of the private database directory reserved for release keys.
const KEY_DIRECTORY: &str = "completion-keys";
/// Exact raw Ed25519 seed length stored in each key file.
const SEED_BYTES: usize = 32;

/// Private key directory checked on every operation; it holds no other state.
#[derive(Clone)]
pub(crate) struct KeyStore {
    directory: PathBuf,
    uid: u32,
}

/// Validates an opaque key reference: one canonical lowercase UUID, never a path.
fn valid_reference(reference: &str) -> Result<(), Fault> {
    let parsed = uuid::Uuid::parse_str(reference).map_err(|_| Fault::Invalid)?;
    if parsed.hyphenated().to_string() != reference {
        return Err(Fault::Invalid);
    }
    Ok(())
}

/// Flushes directory entries so a created or removed key survives a crash.
fn sync_directory(directory: &Path) -> Result<(), Fault> {
    File::open(directory)
        .and_then(|handle| handle.sync_all())
        .map_err(|_| Fault::Unavailable)
}

impl KeyStore {
    /// Opens or creates the key directory below an already protected database directory.
    pub(crate) fn open(database_path: &Path, uid: u32) -> Result<Self, Fault> {
        crate::config::private_parent(database_path, uid)?;
        let parent = database_path.parent().ok_or(Fault::Invalid)?;
        let directory = parent.join(KEY_DIRECTORY);
        match fs::symlink_metadata(&directory) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&directory)
                    .map_err(|_| Fault::Unavailable)?;
                sync_directory(parent)?;
            }
            Err(_) => return Err(Fault::Unavailable),
        }
        let store = Self { directory, uid };
        store.check_directory()?;
        Ok(store)
    }

    /// Requires a real owner-only directory, never a symlink or shared location.
    fn check_directory(&self) -> Result<(), Fault> {
        let metadata = fs::symlink_metadata(&self.directory).map_err(|_| Fault::Unavailable)?;
        if !metadata.is_dir()
            || metadata.uid() != self.uid
            || metadata.permissions().mode() & 0o777 != 0o700
        {
            return Err(Fault::Unavailable);
        }
        Ok(())
    }

    fn path(&self, reference: &str, suffix: &str) -> Result<PathBuf, Fault> {
        valid_reference(reference)?;
        Ok(self.directory.join(format!("{reference}.{suffix}")))
    }

    /// Durably creates one fresh key before its reference is stored; returns only the public key.
    /// An existing reference is never overwritten.
    pub(crate) fn create(&self, reference: &str) -> Result<[u8; 32], Fault> {
        self.check_directory()?;
        let staged = self.path(reference, "tmp")?;
        let target = self.path(reference, "key")?;
        if fs::symlink_metadata(&target).is_ok() {
            return Err(Fault::Conflict);
        }
        let mut seed = Zeroizing::new([0_u8; SEED_BYTES]);
        File::open("/dev/urandom")
            .and_then(|mut source| source.read_exact(&mut *seed))
            .map_err(|_| Fault::Unavailable)?;
        let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let written = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&staged)
            .and_then(|mut file| {
                file.write_all(&*seed)?;
                file.sync_all()
            });
        if written.is_err() {
            let _ = fs::remove_file(&staged);
            return Err(Fault::Unavailable);
        }
        // A hard link refuses an existing target, unlike rename.
        let linked = fs::hard_link(&staged, &target);
        let removed = fs::remove_file(&staged);
        if linked.is_err() || removed.is_err() {
            return Err(Fault::Unavailable);
        }
        sync_directory(&self.directory)?;
        Ok(public)
    }

    /// Loads one key only if it is the exact private file and matches the frozen public key.
    fn load(&self, reference: &str, public: &[u8; 32]) -> Result<SigningKey, Fault> {
        self.check_directory()?;
        let path = self.path(reference, "key")?;
        let before = fs::symlink_metadata(&path).map_err(|_| Fault::Unavailable)?;
        if !before.is_file()
            || before.uid() != self.uid
            || before.permissions().mode() & 0o777 != 0o600
            || before.len() != SEED_BYTES as u64
            || before.nlink() != 1
        {
            return Err(Fault::Unavailable);
        }
        let mut file = File::open(&path).map_err(|_| Fault::Unavailable)?;
        let opened = file.metadata().map_err(|_| Fault::Unavailable)?;
        if opened.dev() != before.dev() || opened.ino() != before.ino() {
            return Err(Fault::Unavailable);
        }
        let mut seed = Zeroizing::new([0_u8; SEED_BYTES]);
        file.read_exact(&mut *seed)
            .map_err(|_| Fault::Unavailable)?;
        let key = SigningKey::from_bytes(&seed);
        if key.verifying_key().to_bytes() != *public {
            return Err(Fault::Unavailable);
        }
        Ok(key)
    }

    /// Signs one exact release message with the saga key; the signature stays in memory.
    pub(crate) fn sign(
        &self,
        reference: &str,
        public: &[u8; 32],
        message: &[u8],
    ) -> Result<[u8; 64], Fault> {
        Ok(self.load(reference, public)?.sign(message).to_bytes())
    }

    /// Whether a usable matching key is present, without exposing it.
    pub(crate) fn available(&self, reference: &str, public: &[u8; 32]) -> bool {
        self.load(reference, public).is_ok()
    }

    /// Removes a key only after its release was verified and durably recorded.
    pub(crate) fn destroy(&self, reference: &str) -> Result<(), Fault> {
        self.check_directory()?;
        let path = self.path(reference, "key")?;
        match fs::remove_file(&path) {
            Ok(()) => sync_directory(&self.directory),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(Fault::Unavailable),
        }
    }

    /// Remove crash leftovers while retaining every key still needed by a saga.
    pub(crate) fn sweep(&self, referenced: &HashSet<String>) -> Result<(), Fault> {
        self.check_directory()?;
        let mut changed = false;
        for entry in fs::read_dir(&self.directory).map_err(|_| Fault::Unavailable)? {
            let entry = entry.map_err(|_| Fault::Unavailable)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some((reference, suffix)) = name.rsplit_once('.') else {
                continue;
            };
            if !matches!(suffix, "tmp" | "key") {
                continue;
            }
            if suffix == "key" && referenced.contains(reference) {
                continue;
            }
            let metadata = fs::symlink_metadata(entry.path()).map_err(|_| Fault::Unavailable)?;
            if !metadata.is_file() || metadata.uid() != self.uid {
                continue;
            }
            fs::remove_file(entry.path()).map_err(|_| Fault::Unavailable)?;
            changed = true;
        }
        if changed {
            sync_directory(&self.directory)?;
        }
        Ok(())
    }

    /// Test-only fixture access to simulate loss or substitution.
    #[cfg(test)]
    pub(crate) fn key_path(&self, reference: &str) -> PathBuf {
        self.directory.join(format!("{reference}.key"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "Isolated key-custody fixtures")]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, VerifyingKey};

    fn fixture() -> (tempfile::TempDir, KeyStore) {
        let base = std::env::var_os("TMPDIR").unwrap();
        let dir = tempfile::tempdir_in(base).unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();
        let keys = KeyStore::open(&dir.path().join("pool.db"), uid).unwrap();
        (dir, keys)
    }

    /// Keys are private, never overwritten, strictly verifiable and never regenerated.
    #[test]
    fn completion_key_custody_is_private_and_fail_closed() {
        let (_dir, keys) = fixture();
        let reference = crate::domain::id();
        let public = keys.create(&reference).unwrap();
        let path = keys.key_path(&reference);
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.len(), 32);
        assert_eq!(
            fs::symlink_metadata(&keys.directory)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(keys.create(&reference), Err(Fault::Conflict));
        let message = b"agent-run:lineage-hold:release:v1\0fixture";
        let signature = keys.sign(&reference, &public, message).unwrap();
        VerifyingKey::from_bytes(&public)
            .unwrap()
            .verify_strict(message, &Signature::from_bytes(&signature))
            .unwrap();
        // A different public key, path traversal or widened mode is refused.
        assert!(keys.sign(&reference, &[7; 32], message).is_err());
        assert!(keys.sign("../escape", &public, message).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(!keys.available(&reference, &public));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(keys.available(&reference, &public));
        // Loss is permanent until operator recovery; nothing regenerates the key.
        keys.destroy(&reference).unwrap();
        assert!(!keys.available(&reference, &public));
        assert!(keys.sign(&reference, &public, message).is_err());
        keys.destroy(&reference).unwrap();
        assert!(fs::read_dir(&keys.directory).unwrap().next().is_none());
    }

    #[test]
    fn startup_sweep_keeps_referenced_keys_and_removes_crash_files() {
        let (_dir, keys) = fixture();
        let retained = crate::domain::id();
        let orphan = crate::domain::id();
        let public = keys.create(&retained).unwrap();
        keys.create(&orphan).unwrap();
        fs::write(keys.path(&retained, "tmp").unwrap(), [1_u8; 32]).unwrap();
        let unrecognized = keys.directory.join("unrelated.txt");
        fs::write(&unrecognized, b"keep").unwrap();
        keys.sweep(&std::collections::HashSet::from([retained.clone()]))
            .unwrap();
        assert!(keys.available(&retained, &public));
        assert!(!keys.key_path(&orphan).exists());
        assert!(!keys.path(&retained, "tmp").unwrap().exists());
        assert!(unrecognized.exists());
    }

    #[test]
    fn signing_keys_and_seed_buffers_have_zeroize_guards() {
        fn requires_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        requires_zeroize_on_drop::<SigningKey>();
        let mut seed = Zeroizing::new([0x5a_u8; SEED_BYTES]);
        zeroize::Zeroize::zeroize(&mut *seed);
        assert_eq!(*seed, [0_u8; SEED_BYTES]);
    }
}
