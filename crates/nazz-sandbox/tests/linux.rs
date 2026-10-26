#![cfg(target_os = "linux")]

use nazz_sandbox::{Observation, SandboxError, SandboxSpec, UnknownReason, spawn_in_grant};
use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

struct Fixture {
    root: PathBuf,
    executable: PathBuf,
    grant: PathBuf,
    profile: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "agent-linux-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let grant = root.join("grant");
        let profile = root.join("profile");
        fs::create_dir(&grant).unwrap();
        fs::create_dir(&profile).unwrap();
        let source = root.join("probe.c");
        fs::write(&source, include_str!("fixtures/probe_child.c")).unwrap();
        let executable = root.join("probe");
        assert!(
            Command::new("cc")
                .args(["-O2", "-o"])
                .arg(&executable)
                .arg(source)
                .status()
                .unwrap()
                .success()
        );
        Self {
            root,
            executable,
            grant,
            profile,
        }
    }
    fn spec(&self) -> SandboxSpec {
        SandboxSpec::new(&self.executable, &self.grant, &self.profile)
            .timeout(Duration::from_secs(2))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[tokio::test]
async fn grants_are_not_union_and_symlinks_do_not_widen_them() {
    let fixture = Fixture::new();
    let other = fixture.root.join("grant-b");
    fs::create_dir(&other).unwrap();
    let outside = other.join("owned.txt");
    fs::write(&outside, b"untouched").unwrap();
    let link = fixture.grant.join("escape");
    std::os::unix::fs::symlink(&outside, &link).unwrap();
    let inside = fixture.grant.join("owned.txt");
    for (path, allowed) in [(&inside, true), (&outside, false), (&link, false)] {
        let mut child = spawn_in_grant(fixture.spec().arg("--marker").arg(path))
            .await
            .unwrap();
        assert!(child.capability().tool_host_integration_ready());
        let observation = child.observe().await;
        assert!(
            matches!(observation, Observation::Exited { code, .. } if code == if allowed { 0 } else { 1 }),
            "{observation:?}"
        );
        drop(child);
    }
    assert_eq!(fs::read(inside).unwrap(), b"spawned");
    assert_eq!(fs::read(outside).unwrap(), b"untouched");
}

#[tokio::test]
async fn timeout_and_output_limit_stop_the_owned_linux_child() {
    let fixture = Fixture::new();
    for (mode, reason) in [
        ("--sleep", UnknownReason::Timeout),
        ("--flood", UnknownReason::OutputLimit),
    ] {
        let mut child = spawn_in_grant(
            fixture
                .spec()
                .arg(mode)
                .limit(1024)
                .timeout(Duration::from_millis(150)),
        )
        .await
        .unwrap();
        assert!(
            matches!(child.observe().await, Observation::Unknown { reason: actual, .. } if actual == reason)
        );
        assert!(child.stop_owned().await.unwrap().observed_stop);
        drop(child);
    }
}

#[tokio::test]
async fn non_elf_and_secret_environment_never_run() {
    let fixture = Fixture::new();
    let script = fixture.root.join("script");
    fs::write(&script, b"#!/bin/sh\nexit 0\n").unwrap();
    assert!(matches!(
        spawn_in_grant(SandboxSpec::new(script, &fixture.grant, &fixture.profile)).await,
        Err(SandboxError::Unavailable(_))
    ));
    assert!(matches!(
        spawn_in_grant(fixture.spec().env_pair("LD_PRELOAD", "bad")).await,
        Err(SandboxError::EnvRejected(_))
    ));
    assert!(!fixture.profile.join("sandbox.launcher").exists());
}
