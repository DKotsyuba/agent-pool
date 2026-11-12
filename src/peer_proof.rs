//! Loaded-build evidence for a connected same-UID peer process (errata E13/E14).
//!
//! These checks reject a genuine pinned executable whose code is not the pinned
//! build in effect: a dynamic-loader override, a tracer, or a loaded file that
//! the kernel does not protect from writes while it runs. Every unreadable or
//! ambiguous fact fails closed. No wall clock or file timestamp grants authority.
use std::path::Path;
#[cfg(target_os = "linux")]
use std::{fs::File, io::Read};

/// Largest initial environment read from procfs.
#[cfg(target_os = "linux")]
const MAX_ENVIRON: u64 = 1024 * 1024;
/// Largest status record read from procfs.
#[cfg(target_os = "linux")]
const MAX_STATUS: u64 = 64 * 1024;
/// Largest `/etc/ld.so.preload` accepted as blank.
#[cfg(target_os = "linux")]
const MAX_PRELOAD: u64 = 64 * 1024;

/// Generic interpreters run whatever program they are given, so their
/// executable digest does not identify the peer's code. Matches the exact name
/// or the name followed by a version separator, case-insensitively.
pub(crate) fn forbidden_interpreter(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
        return true;
    };
    let name = name.to_ascii_lowercase();
    [
        "python",
        "pypy",
        "awk",
        "gawk",
        "mawk",
        "nawk",
        "expect",
        "rscript",
        "julia",
        "erl",
        "escript",
        "ld",
        "ld.so",
        "ld-linux",
        "ld-musl",
        "node",
        "nodejs",
        "deno",
        "bun",
        "bash",
        "dash",
        "zsh",
        "ksh",
        "fish",
        "sh",
        "csh",
        "tcsh",
        "pwsh",
        "powershell",
        "perl",
        "ruby",
        "lua",
        "php",
        "tclsh",
        "wish",
        "gjs",
        "qjs",
        "jsc",
        "wasmtime",
        "wasmer",
        "env",
        "busybox",
        "java",
        "dotnet",
    ]
    .iter()
    .any(|prefix| {
        name == *prefix
            || (name.starts_with(prefix)
                && name
                    .as_bytes()
                    .get(prefix.len())
                    .is_some_and(|b| b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')))
    })
}

/// Reads at most `limit` bytes; a longer file is an error, never a truncation.
#[cfg(target_os = "linux")]
fn bounded(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::other("procfs fact oversized"));
    }
    Ok(bytes)
}

/// A NUL-terminated environment block without any dynamic-loader variable.
#[cfg(target_os = "linux")]
fn clean_environment(bytes: &[u8]) -> bool {
    (bytes.is_empty() || bytes.last() == Some(&0))
        && !bytes
            .split(|byte| *byte == 0)
            .any(|entry| entry.starts_with(b"LD_"))
}

/// Exactly one `TracerPid` line, and it names no tracer.
#[cfg(target_os = "linux")]
fn untraced(status: &str) -> bool {
    let mut values = status
        .lines()
        .filter_map(|line| line.strip_prefix("TracerPid:"));
    matches!((values.next(), values.next()), (Some(value), None) if value.trim() == "0")
}

/// The peer started without a loader override and is not traced now. Call it
/// before and after hashing so a tracer attached during the proof is seen.
/// The initial environment is what the loader consumed at exec; a peer that
/// rewrites its own environment memory already runs foreign code, which the
/// other checks exclude.
#[cfg(target_os = "linux")]
pub(crate) fn clean_process(pid: u32) -> bool {
    let environment = bounded(Path::new(&format!("/proc/{pid}/environ")), MAX_ENVIRON);
    let status = bounded(Path::new(&format!("/proc/{pid}/status")), MAX_STATUS);
    environment.is_ok_and(|bytes| clean_environment(&bytes))
        && status.is_ok_and(|bytes| std::str::from_utf8(&bytes).is_ok_and(untraced))
}

/// A global loader preload list would inject code into every peer; only an
/// absent or blank `/etc/ld.so.preload` is accepted.
#[cfg(target_os = "linux")]
pub(crate) fn loader_preload_safe() -> bool {
    blank_preload_list(Path::new("/etc/ld.so.preload"))
}

/// An absent, or present and blank, bounded preload list; anything unreadable fails closed.
#[cfg(target_os = "linux")]
fn blank_preload_list(path: &Path) -> bool {
    match bounded(path, MAX_PRELOAD) {
        Ok(bytes) => bytes.iter().all(u8::is_ascii_whitespace),
        Err(error) => error.kind() == std::io::ErrorKind::NotFound,
    }
}

/// The opened loaded executable lives on a filesystem where the kernel denies
/// writes to a running executable. The open descriptor's `mnt_id` is resolved
/// to exactly one record of this process's mountinfo (E14(a)); a hidden or
/// detached mount, an ambiguous record or any other filesystem type fails
/// closed. Overlay is refused: its type alone does not prove the upper
/// filesystem's write exclusion.
#[cfg(target_os = "linux")]
pub(crate) fn write_excluded(file: &File) -> bool {
    use std::os::fd::AsRawFd;
    let info = bounded(
        Path::new(&format!("/proc/self/fdinfo/{}", file.as_raw_fd())),
        MAX_STATUS,
    );
    let mounts = bounded(Path::new("/proc/self/mountinfo"), 4 * 1024 * 1024);
    match (info, mounts) {
        (Ok(info), Ok(mounts)) => {
            match (std::str::from_utf8(&info), std::str::from_utf8(&mounts)) {
                (Ok(info), Ok(mounts)) => mount_allowed(info, mounts),
                _ => false,
            }
        }
        _ => false,
    }
}

/// Exactly one `mnt_id` naming exactly one mountinfo record of an allowed type.
#[cfg(target_os = "linux")]
fn mount_allowed(info: &str, mounts: &str) -> bool {
    let mut ids = info.lines().filter_map(|line| line.strip_prefix("mnt_id:"));
    let Some(id) = ids
        .next()
        .and_then(|value| value.trim().parse::<u64>().ok())
    else {
        return false;
    };
    if ids.next().is_some() {
        return false;
    }
    let mut matching = mounts.lines().filter(|line| {
        line.split_ascii_whitespace()
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            == Some(id)
    });
    let (Some(line), None) = (matching.next(), matching.next()) else {
        return false;
    };
    // Kernel mountinfo names for the statfs magic allowlist of E13.
    matches!(
        line.split_once(" - ")
            .and_then(|(_, tail)| tail.split_ascii_whitespace().next()),
        Some("ext2" | "ext3" | "ext4" | "xfs" | "btrfs" | "tmpfs")
    )
}

/// Test fixture that lets the shared test executable pass the owner/mode proof:
/// a target directory with a default ACL can leave it group-writable. Group and
/// other write bits (the ACL mask) are cleared while held and the original mode
/// is restored on drop. Hold `TEST_EXEC_HASH_LOCK` for the guard's lifetime.
#[cfg(all(test, target_os = "linux"))]
pub(crate) struct TrustedTestExecutable {
    path: std::path::PathBuf,
    mode: u32,
}
#[cfg(all(test, target_os = "linux"))]
impl TrustedTestExecutable {
    /// Clears group/other write on the canonical current test executable.
    pub(crate) fn current() -> std::io::Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        let path = std::fs::canonicalize(std::env::current_exe()?)?;
        let mode = std::fs::metadata(&path)?.permissions().mode() & 0o7777;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode & !0o022))?;
        Ok(Self { path, mode })
    }
    /// The canonical executable path to pin.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}
#[cfg(all(test, target_os = "linux"))]
impl Drop for TrustedTestExecutable {
    /// Best-effort restore of the original mode.
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(self.mode));
    }
}

/// Runs a positive self-peer test in a process whose environment has no
/// dynamic-loader variable: test runners such as nextest export
/// `LD_LIBRARY_PATH`, which the peer proof correctly refuses. Returns `false`
/// when the current process is already clean and the caller should continue;
/// otherwise re-executes exactly `test` with the same environment minus `LD_*`,
/// asserts that it passed, and returns `true` so the caller returns.
#[cfg(all(test, target_os = "linux"))]
#[allow(clippy::expect_used, reason = "Test fixture fails the calling test")]
pub(crate) fn rerun_without_loader_environment(test: &str) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let loader = |key: &std::ffi::OsStr| key.as_bytes().starts_with(b"LD_");
    if !std::env::vars_os().any(|(key, _)| loader(&key)) {
        return false;
    }
    let status = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env_clear()
        .envs(std::env::vars_os().filter(|(key, _)| !loader(key)))
        .stdin(std::process::Stdio::null())
        .status()
        .expect("clean-environment test process");
    assert!(status.success(), "{test} failed without loader variables");
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpreter_names_are_refused_by_name_and_version() {
        for name in [
            "python3",
            "Python3.12",
            "bash",
            "node",
            "env",
            "ld-linux-x86-64.so.2",
        ] {
            assert!(forbidden_interpreter(
                Path::new("/usr/bin").join(name).as_path()
            ));
        }
        for name in [
            "agent-run",
            "agent-pool",
            "environment",
            "nodeps",
            "shell-tool",
        ] {
            assert!(!forbidden_interpreter(
                Path::new("/opt/bin").join(name).as_path()
            ));
        }
        assert!(forbidden_interpreter(Path::new("/")));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn procfs_filters_reject_loader_and_tracer_evidence() {
        assert!(clean_environment(b""));
        assert!(clean_environment(b"PATH=/usr/bin\0HOME=/h\0"));
        assert!(!clean_environment(b"LD_PRELOAD=/fixture.so\0"));
        assert!(!clean_environment(b"A=1\0LD_LIBRARY_PATH=\0"));
        assert!(!clean_environment(b"LD_AUDIT\0"));
        assert!(!clean_environment(b"PATH=/usr/bin"));
        assert!(untraced("Name:\tx\nTracerPid:\t0\n"));
        assert!(!untraced("TracerPid:\t42\n"));
        assert!(!untraced("TracerPid:\t0\nTracerPid:\t0\n"));
        assert!(!untraced("Name:\tx\n"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn preload_list_must_be_absent_or_blank() -> std::io::Result<()> {
        let directory =
            tempfile::tempdir_in(std::env::var_os("TMPDIR").ok_or(std::io::ErrorKind::NotFound)?)?;
        let list = directory.path().join("ld.so.preload");
        assert!(blank_preload_list(&list));
        std::fs::write(&list, b" \n\t\n")?;
        assert!(blank_preload_list(&list));
        std::fs::write(&list, b"/fixture/synthetic-preload.so\n")?;
        assert!(!blank_preload_list(&list));
        std::fs::write(&list, vec![b' '; 64 * 1024 + 1])?;
        assert!(!blank_preload_list(&list));
        assert!(!blank_preload_list(directory.path()));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unsupported_or_ambiguous_mounts_fail_closed() {
        for kind in ["ext2", "ext3", "ext4", "xfs", "btrfs", "tmpfs"] {
            let mounts = format!("42 1 0:1 / / rw - {kind} source rw\n");
            assert!(mount_allowed("pos:\t0\nmnt_id:\t42\n", &mounts));
        }
        for (info, mounts) in [
            ("mnt_id: 42", "42 1 0:1 / / rw - overlay source rw"),
            ("mnt_id: 42", "42 1 0:1 / / rw - nfs4 source rw"),
            ("mnt_id: 42", "42 1 0:1 / / rw - fuse.sshfs source rw"),
            ("mnt_id: 42", "43 1 0:1 / / rw - ext4 source rw"),
            ("mnt_id: 42\nmnt_id: 42", "42 1 0:1 / / rw - ext4 source rw"),
            (
                "mnt_id: 42",
                "42 1 0:1 / / rw - ext4 source rw\n42 1 0:1 / / rw - tmpfs source rw",
            ),
            ("mnt_id: 42", "42 1 0:1 / / rw shared:1 ext4 source rw"),
            ("mnt_id: invalid", "42 1 0:1 / / rw - ext4 source rw"),
            ("", ""),
        ] {
            assert!(!mount_allowed(info, mounts), "{info} / {mounts}");
        }
    }
}
