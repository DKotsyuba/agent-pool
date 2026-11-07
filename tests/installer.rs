//! Isolated bootstrap asset selection and integrity checks; no network or real installation.
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "Explicit fixture failures"
)]

use family_delivery::{Manifest, digest, package};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};

/// Creates a private executable shell fixture.
fn script(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

/// Provides two synthetic release bundles and local-only gh/uname shims.
struct Fixture {
    root: tempfile::TempDir,
    assets: PathBuf,
    tools: PathBuf,
    marker: PathBuf,
    home: PathBuf,
    bin: PathBuf,
}
impl Fixture {
    /// Constructs isolated assets; no compiled application or credential is used as a payload.
    fn new() -> Self {
        let root = tempfile::tempdir_in(std::env::var_os("TMPDIR").expect("task TMPDIR required"))
            .unwrap();
        let assets = root.path().join("assets");
        let tools = root.path().join("tools");
        fs::create_dir(&assets).unwrap();
        fs::create_dir(&tools).unwrap();
        for (target, remote_manifest) in [
            ("aarch64-apple-darwin", "release-manifest.json"),
            (
                "x86_64-unknown-linux-gnu",
                "release-manifest-x86_64-unknown-linux-gnu.json",
            ),
        ] {
            let source = root.path().join(format!("source-{target}"));
            script(
                &source,
                &format!(
                    "[ -z \"${{GH_TOKEN+x}}${{GITHUB_TOKEN+x}}${{GH_ENTERPRISE_TOKEN+x}}${{GITHUB_ENTERPRISE_TOKEN+x}}\" ] || exit 41\nprintf '%s\\n' '{target}' > \"$FIXTURE_MARKER\""
                ),
            );
            let bundle = root.path().join(format!("bundle-{target}"));
            let binary = format!("agent-pool-{target}");
            package(
                &source,
                &bundle,
                Manifest {
                    schema_version: 1,
                    profile: "single-binary-v1".into(),
                    product: "agent-pool".into(),
                    version: "0.1.0".into(),
                    source_commit: "a".repeat(40),
                    target: target.into(),
                    binary: binary.clone(),
                    size: 1,
                    sha256: "0".repeat(64),
                    state_schema: 0,
                    run_id: None,
                    run_attempt: None,
                },
            )
            .unwrap();
            fs::copy(bundle.join(&binary), assets.join(&binary)).unwrap();
            fs::copy(
                bundle.join("release-manifest.json"),
                assets.join(remote_manifest),
            )
            .unwrap();
        }
        let mut sums = String::new();
        for name in [
            "agent-pool-aarch64-apple-darwin",
            "release-manifest.json",
            "agent-pool-x86_64-unknown-linux-gnu",
            "release-manifest-x86_64-unknown-linux-gnu.json",
        ] {
            sums.push_str(&format!(
                "{}  {name}\n",
                digest(&assets.join(name)).unwrap().1
            ));
        }
        fs::write(assets.join("SHA256SUMS"), sums).unwrap();
        script(
            &tools.join("uname"),
            "case \"$1\" in -s) printf '%s\\n' \"$FIXTURE_OS\";; -m) printf '%s\\n' \"$FIXTURE_ARCH\";; *) exit 1;; esac",
        );
        script(
            &tools.join("sha256sum"),
            "exec /usr/bin/shasum -a 256 \"$@\"",
        );
        script(
            &tools.join("gh"),
            r#"
case "$1:$2" in
  auth:status) [ "$FIXTURE_AUTH" = 1 ]; exit $?;;
  release:view) printf '1\n'; exit 0;;
  release:download)
    pattern= output=
    while [ "$#" -gt 0 ]; do
      case "$1" in --pattern) pattern=$2; shift 2;; --output) output=$2; shift 2;; *) shift;; esac
    done
    [ -f "$FIXTURE_ASSETS/$pattern" ] || exit 1
    cp "$FIXTURE_ASSETS/$pattern" "$output";;
  *) exit 1;;
esac
"#,
        );
        script(
            &tools.join("curl"),
            r#"
output= url=
while [ "$#" -gt 0 ]; do
  case "$1" in --output) output=$2; shift 2;; https://*) url=$1; shift;; *) shift;; esac
done
name=${url##*/}
[ -f "$FIXTURE_ASSETS/$name" ] || exit 1
cp "$FIXTURE_ASSETS/$name" "$output"
"#,
        );
        Self {
            marker: root.path().join("executed"),
            home: root.path().join("home"),
            bin: root.path().join("bin"),
            root,
            assets,
            tools,
        }
    }
    /// Runs the real bootstrap against only the local fixture release.
    fn run(&self, os: &str, arch: &str) -> Output {
        self.run_with_auth(os, arch, true)
    }
    /// Exercises either local authenticated or unauthenticated download shim.
    fn run_with_auth(&self, os: &str, arch: &str, authenticated: bool) -> Output {
        Command::new("/bin/bash")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("install.sh"))
            .args(["--version", "0.1.0", "--repo", "fixture/repo", "--home"])
            .arg(&self.home)
            .arg("--bin-dir")
            .arg(&self.bin)
            .env_clear()
            .env(
                "HOME",
                std::env::var_os("HOME").expect("existing HOME required"),
            )
            .env("TMPDIR", self.root.path())
            .env("PATH", format!("{}:/usr/bin:/bin", self.tools.display()))
            .env("FIXTURE_OS", os)
            .env("FIXTURE_ARCH", arch)
            .env("FIXTURE_AUTH", if authenticated { "1" } else { "0" })
            .env("FIXTURE_ASSETS", &self.assets)
            .env("FIXTURE_MARKER", &self.marker)
            .env("GH_TOKEN", "synthetic-token")
            .env("GITHUB_TOKEN", "synthetic-token")
            .env("GH_ENTERPRISE_TOKEN", "synthetic-token")
            .env("GITHUB_ENTERPRISE_TOKEN", "synthetic-token")
            .output()
            .unwrap()
    }
}

/// The same release selects each platform's manifest and strips download credentials before execution.
#[test]
fn bootstrap_selects_platform_manifest() {
    for (os, arch, target) in [
        ("Darwin", "arm64", "aarch64-apple-darwin"),
        ("Linux", "x86_64", "x86_64-unknown-linux-gnu"),
    ] {
        for authenticated in [true, false] {
            let fixture = Fixture::new();
            let output = fixture.run_with_auth(os, arch, authenticated);
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(fs::read_to_string(&fixture.marker).unwrap().trim(), target);
        }
    }
}

/// A Linux-only release is installable through either supported download path.
#[test]
fn bootstrap_accepts_linux_only_release() {
    for authenticated in [true, false] {
        let fixture = Fixture::new();
        fs::remove_file(fixture.assets.join("agent-pool-aarch64-apple-darwin")).unwrap();
        fs::remove_file(fixture.assets.join("release-manifest.json")).unwrap();
        let sums_path = fixture.assets.join("SHA256SUMS");
        let sums = fs::read_to_string(&sums_path).unwrap();
        let linux_sums = sums
            .lines()
            .filter(|line| line.contains("x86_64-unknown-linux-gnu"))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(sums_path, format!("{linux_sums}\n")).unwrap();
        let output = fixture.run_with_auth("Linux", "x86_64", authenticated);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read_to_string(&fixture.marker).unwrap().trim(),
            "x86_64-unknown-linux-gnu"
        );
    }
}

/// Duplicate checksums, altered manifests and missing platform assets refuse before executing bytes.
#[test]
fn bootstrap_refuses_incomplete_or_tampered_release() {
    for (os, arch, manifest, case) in [
        (
            "Linux",
            "x86_64",
            "release-manifest-x86_64-unknown-linux-gnu.json",
            "duplicate",
        ),
        (
            "Linux",
            "x86_64",
            "release-manifest-x86_64-unknown-linux-gnu.json",
            "tampered",
        ),
        (
            "Linux",
            "x86_64",
            "release-manifest-x86_64-unknown-linux-gnu.json",
            "missing",
        ),
        ("Darwin", "arm64", "release-manifest.json", "tampered"),
    ] {
        let fixture = Fixture::new();
        match case {
            "duplicate" => {
                let path = fixture.assets.join("SHA256SUMS");
                let mut sums = fs::read_to_string(&path).unwrap();
                sums.push_str(&format!(
                    "{}  {manifest}\n",
                    digest(&fixture.assets.join(manifest)).unwrap().1
                ));
                fs::write(path, sums).unwrap();
            }
            "tampered" => fs::write(fixture.assets.join(manifest), b"tampered").unwrap(),
            "missing" => fs::remove_file(fixture.assets.join(manifest)).unwrap(),
            _ => unreachable!(),
        }
        let output = fixture.run(os, arch);
        assert!(!output.status.success(), "case {case}");
        assert!(!fixture.marker.exists(), "case {case}");
        assert!(!fixture.bin.exists(), "case {case}");
    }
}
