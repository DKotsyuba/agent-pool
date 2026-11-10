//! Protected per-saga Ed25519 release-key custody for completion holds.
//!
//! Each settlement saga owns one fresh key file, mode 0600, in a private
//! resident-owned directory `<database dir>/completion-keys/<Pool store UUID>/`.
//! Several Pool databases may share one private parent; each store's keys,
//! startup sweep and migration stay inside its own subdirectory. Only an opaque
//! key reference and the public key enter SQLite. Key bytes, signatures and
//! paths never enter model arguments, process arguments, logs, records or
//! replies. A missing or substituted key is reported as unavailable: it is
//! never regenerated, and no time-based unlock exists.
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
/// Its direct `<reference>.key` files are the legacy shared layout; current
/// keys live one level below, in the owning Pool store's subdirectory.
const KEY_DIRECTORY: &str = "completion-keys";
/// Exact raw Ed25519 seed length stored in each key file.
const SEED_BYTES: usize = 32;

/// Private per-store key directory checked on every operation; it holds no other state.
#[derive(Clone)]
pub(crate) struct KeyStore {
    /// Shared owner-only root, possibly still holding legacy flat keys.
    root: PathBuf,
    /// This Pool store's own owner-only key directory below `root`.
    directory: PathBuf,
    /// Device and inode of `directory` pinned at open; a replaced directory is refused.
    identity: (u64, u64),
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

/// Flushes directory entries so a created, moved or removed key survives a crash.
fn sync_directory(directory: &Path) -> Result<(), Fault> {
    File::open(directory)
        .and_then(|handle| handle.sync_all())
        .map_err(|_| Fault::Unavailable)
}

/// Requires a real owner-only directory, never a symlink or shared location.
fn private_directory(directory: &Path, uid: u32) -> Result<fs::Metadata, Fault> {
    let metadata = fs::symlink_metadata(directory).map_err(|_| Fault::Unavailable)?;
    if !metadata.is_dir() || metadata.uid() != uid || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(Fault::Unavailable);
    }
    Ok(metadata)
}

/// Creates a missing owner-only directory durably, then checks it without following links.
fn ensure_directory(directory: &Path, parent: &Path, uid: u32) -> Result<fs::Metadata, Fault> {
    match fs::symlink_metadata(directory) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match fs::DirBuilder::new().mode(0o700).create(directory) {
                Ok(()) => sync_directory(parent)?,
                // A concurrent opener of the same shared root may win the creation.
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(Fault::Unavailable),
            }
        }
        Err(_) => return Err(Fault::Unavailable),
    }
    private_directory(directory, uid)
}

/// Whether a file is exactly the private seed file a saga key must be.
fn private_seed(metadata: &fs::Metadata, uid: u32) -> bool {
    metadata.is_file()
        && metadata.uid() == uid
        && metadata.permissions().mode() & 0o777 == 0o600
        && metadata.len() == SEED_BYTES as u64
        && metadata.nlink() == 1
}

impl KeyStore {
    /// Opens or creates this Pool store's key directory below an already
    /// protected database directory. `store_id` is the durable Pool store UUID.
    pub(crate) fn open(database_path: &Path, uid: u32, store_id: &str) -> Result<Self, Fault> {
        valid_reference(store_id)?;
        crate::config::private_parent(database_path, uid)?;
        let parent = database_path.parent().ok_or(Fault::Invalid)?;
        let root = parent.join(KEY_DIRECTORY);
        ensure_directory(&root, parent, uid)?;
        let directory = root.join(store_id);
        let metadata = ensure_directory(&directory, &root, uid)?;
        let store = Self {
            root,
            directory,
            identity: (metadata.dev(), metadata.ino()),
            uid,
        };
        store.check_directory()?;
        Ok(store)
    }

    /// Rechecks the shared root and this store's pinned directory before every operation.
    fn check_directory(&self) -> Result<(), Fault> {
        private_directory(&self.root, self.uid)?;
        let metadata = private_directory(&self.directory, self.uid)?;
        if (metadata.dev(), metadata.ino()) != self.identity {
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
        if !private_seed(&before, self.uid) {
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

    /// One-time migration from the legacy shared flat layout. Moves only the
    /// `<reference>.key` files this store's sagas still own, by atomic rename
    /// into this store's directory (never over an existing key), then fsyncs
    /// both directories. Nothing in the shared root is ever deleted or swept;
    /// returns how many legacy key or staging files were left in place.
    pub(crate) fn migrate_legacy(&self, owned: &HashSet<String>) -> Result<usize, Fault> {
        self.check_directory()?;
        let mut moved = false;
        let mut left = 0;
        for entry in fs::read_dir(&self.root).map_err(|_| Fault::Unavailable)? {
            let entry = entry.map_err(|_| Fault::Unavailable)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some((reference, suffix)) = name.rsplit_once('.') else {
                continue;
            };
            if !matches!(suffix, "tmp" | "key") || valid_reference(reference).is_err() {
                continue;
            }
            let source = entry.path();
            let metadata = fs::symlink_metadata(&source).map_err(|_| Fault::Unavailable)?;
            let target = self.path(reference, "key")?;
            if suffix != "key"
                || !owned.contains(reference)
                || !private_seed(&metadata, self.uid)
                || fs::symlink_metadata(&target).is_ok()
            {
                left += 1;
                continue;
            }
            // Only this store's writer lease holder writes its directory, so the
            // absence check above cannot race another writer of the target.
            fs::rename(&source, &target).map_err(|_| Fault::Unavailable)?;
            moved = true;
        }
        if moved {
            sync_directory(&self.directory)?;
            sync_directory(&self.root)?;
        }
        Ok(left)
    }

    /// Remove crash leftovers in this store's own directory while retaining
    /// every key still needed by one of its sagas. Other stores' directories and
    /// the shared legacy root are never touched.
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

    /// Test-only view of this store's own key directory.
    #[cfg(test)]
    pub(crate) fn directory(&self) -> &Path {
        &self.directory
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "Isolated key-custody fixtures")]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, VerifyingKey};

    fn private_dir() -> (tempfile::TempDir, u32) {
        let base = std::env::var_os("TMPDIR").unwrap();
        let dir = tempfile::tempdir_in(base).unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(dir.path()).unwrap().uid();
        (dir, uid)
    }

    fn fixture() -> (tempfile::TempDir, KeyStore) {
        let (dir, uid) = private_dir();
        let keys = KeyStore::open(&dir.path().join("pool.db"), uid, &crate::domain::id()).unwrap();
        (dir, keys)
    }

    /// Writes one key file in the legacy shared flat layout and returns its public key.
    fn legacy_key(root: &Path, reference: &str, byte: u8) -> [u8; 32] {
        let path = root.join(format!("{reference}.key"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(&[byte; SEED_BYTES]).unwrap();
        SigningKey::from_bytes(&[byte; SEED_BYTES])
            .verifying_key()
            .to_bytes()
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

    /// Two Pool databases in one private parent: starting B never touches A's
    /// active key, and each store's sweep stays inside its own directory.
    #[test]
    fn completion_keys_are_isolated_per_store_in_one_parent() {
        let (dir, uid) = private_dir();
        let a = KeyStore::open(&dir.path().join("a.db"), uid, &crate::domain::id()).unwrap();
        let active = crate::domain::id();
        let public = a.create(&active).unwrap();
        let b = KeyStore::open(&dir.path().join("b.db"), uid, &crate::domain::id()).unwrap();
        assert_ne!(a.directory, b.directory);
        assert_eq!(a.root, b.root);
        // B's startup: migration and sweep with none of A's references.
        assert_eq!(b.migrate_legacy(&HashSet::new()).unwrap(), 0);
        b.sweep(&HashSet::new()).unwrap();
        assert!(a.available(&active, &public));
        // B cannot see or destroy A's key through its own references.
        assert!(!b.available(&active, &public));
        b.destroy(&active).unwrap();
        assert!(a.available(&active, &public));
        // A store directory replaced after open is refused, never followed.
        let moved = dir.path().join("moved");
        fs::rename(&b.directory, &moved).unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&b.directory)
            .unwrap();
        assert_eq!(b.create(&crate::domain::id()), Err(Fault::Unavailable));
        // A symlinked or widened store directory is refused at open.
        let c_id = crate::domain::id();
        std::os::unix::fs::symlink(&moved, a.root.join(&c_id)).unwrap();
        assert!(KeyStore::open(&dir.path().join("c.db"), uid, &c_id).is_err());
        fs::set_permissions(&a.directory, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(!a.available(&active, &public));
        fs::set_permissions(&a.directory, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(a.available(&active, &public));
        assert!(KeyStore::open(&dir.path().join("d.db"), uid, "../escape").is_err());
    }

    /// A key created in store A while store B repeatedly starts is never removed.
    #[test]
    fn concurrent_key_creation_survives_other_store_startup() {
        let (dir, uid) = private_dir();
        let a = KeyStore::open(&dir.path().join("a.db"), uid, &crate::domain::id()).unwrap();
        let b_path = dir.path().join("b.db");
        let b_id = crate::domain::id();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let creator = {
            let barrier = std::sync::Arc::clone(&barrier);
            let a = a.clone();
            std::thread::spawn(move || {
                barrier.wait();
                (0..64)
                    .map(|_| {
                        let reference = crate::domain::id();
                        let public = a.create(&reference).unwrap();
                        (reference, public)
                    })
                    .collect::<Vec<_>>()
            })
        };
        barrier.wait();
        for _ in 0..64 {
            let b = KeyStore::open(&b_path, uid, &b_id).unwrap();
            b.migrate_legacy(&HashSet::new()).unwrap();
            b.sweep(&HashSet::new()).unwrap();
        }
        let created = creator.join().unwrap();
        for (reference, public) in &created {
            assert!(a.available(reference, public));
        }
        assert_eq!(fs::read_dir(&a.directory).unwrap().count(), created.len());
    }

    /// Migration renames only keys this store still owns; every other legacy
    /// file, including staging files and keys of other stores, stays in place.
    #[test]
    fn legacy_flat_keys_migrate_only_when_owned() {
        let (dir, uid) = private_dir();
        let root = dir.path().join(KEY_DIRECTORY);
        fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
        let owned = crate::domain::id();
        let owned_public = legacy_key(&root, &owned, 1);
        let foreign = crate::domain::id();
        let foreign_public = legacy_key(&root, &foreign, 2);
        let widened = crate::domain::id();
        legacy_key(&root, &widened, 3);
        fs::set_permissions(
            root.join(format!("{widened}.key")),
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        let staged = root.join(format!("{owned}.tmp"));
        fs::write(&staged, [4_u8; SEED_BYTES]).unwrap();
        let unrelated = root.join("unrelated.txt");
        fs::write(&unrelated, b"keep").unwrap();
        let keys = KeyStore::open(&dir.path().join("pool.db"), uid, &crate::domain::id()).unwrap();
        let references = HashSet::from([owned.clone(), widened.clone()]);
        assert!(!keys.available(&owned, &owned_public));
        // Foreign key, widened key and staging file are left; unrelated names are not counted.
        assert_eq!(keys.migrate_legacy(&references).unwrap(), 3);
        assert!(keys.available(&owned, &owned_public));
        assert!(!root.join(format!("{owned}.key")).exists());
        let foreign_path = root.join(format!("{foreign}.key"));
        assert_eq!(fs::read(&foreign_path).unwrap(), [2_u8; SEED_BYTES]);
        assert!(root.join(format!("{widened}.key")).exists());
        assert!(staged.exists() && unrelated.exists());
        // The own-directory sweep never reaches the shared root.
        keys.sweep(&HashSet::new()).unwrap();
        assert!(foreign_path.exists() && staged.exists());
        assert!(!keys.available(&owned, &owned_public));
        // Repeating is idempotent and never overwrites an existing store key.
        let again = keys.create(&foreign).unwrap();
        assert_eq!(
            keys.migrate_legacy(&HashSet::from([foreign.clone()]))
                .unwrap(),
            3
        );
        assert!(keys.available(&foreign, &again));
        assert!(!keys.available(&foreign, &foreign_public));
        assert_eq!(fs::read(&foreign_path).unwrap(), [2_u8; SEED_BYTES]);
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
