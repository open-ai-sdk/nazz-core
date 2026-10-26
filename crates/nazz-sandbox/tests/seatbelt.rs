#![cfg(target_os = "macos")]

use std::fs;
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nazz_sandbox::{
    Observation, SandboxBackend, SandboxError, SandboxSpec, UnknownReason, available_backend,
    spawn_in_grant,
};

const CANARY: &str = "canary-value-9f3a";

struct Layout {
    root: PathBuf,
    grant: PathBuf,
    profile_dir: PathBuf,
    bin: PathBuf,
    outside: PathBuf,
    probe: PathBuf,
    marker: PathBuf,
    unrelated: PathBuf,
    symlink_read: PathBuf,
    symlink_write: PathBuf,
    write_target: PathBuf,
    unix_path: PathBuf,
    ssh_path: PathBuf,
    port: u16,
    _tcp: TcpListener,
    _unix: UnixListener,
    _ssh: UnixListener,
}

impl Layout {
    fn create(prefix: &str) -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = PathBuf::from(format!("/tmp/{prefix} {stamp}"));
        let grant = root.join("grant dir");
        let profile_dir = root.join("profile dir");
        let bin = root.join("bin dir");
        let outside = root.join("outside");
        fs::create_dir_all(&grant).unwrap();
        fs::create_dir_all(&profile_dir).unwrap();
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let source = bin.join("probe_child.c");
        fs::write(&source, include_str!("fixtures/probe_child.c")).unwrap();
        let probe = compile(&source, &bin.join("probe"));
        let marker = compile(&source, &bin.join("marker"));
        let unrelated = outside.join("secret.txt");
        fs::write(&unrelated, b"secret-outside").unwrap();
        let write_target = outside.join("target.txt");
        fs::write(&write_target, b"keep-me").unwrap();
        let symlink_read = grant.join("escape");
        let symlink_write = grant.join("outlink");
        std::os::unix::fs::symlink(&unrelated, &symlink_read).unwrap();
        std::os::unix::fs::symlink(&write_target, &symlink_write).unwrap();
        let unix_path = PathBuf::from(format!("/tmp/agent-u-{stamp}"));
        let ssh_path = PathBuf::from(format!("/tmp/agent-a-{stamp}"));
        let _ = fs::remove_file(&unix_path);
        let _ = fs::remove_file(&ssh_path);
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        tcp.set_nonblocking(true).unwrap();
        let port = tcp.local_addr().unwrap().port();
        let unix = UnixListener::bind(&unix_path).unwrap();
        unix.set_nonblocking(true).unwrap();
        let ssh = UnixListener::bind(&ssh_path).unwrap();
        ssh.set_nonblocking(true).unwrap();
        Self {
            root,
            grant,
            profile_dir,
            bin,
            outside,
            probe,
            marker,
            unrelated,
            symlink_read,
            symlink_write,
            write_target,
            unix_path,
            ssh_path,
            port,
            _tcp: tcp,
            _unix: unix,
            _ssh: ssh,
        }
    }
}

impl Drop for Layout {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.unix_path);
        let _ = fs::remove_file(&self.ssh_path);
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn compile(source: &Path, out: &Path) -> PathBuf {
    let status = Command::new("cc")
        .args(["-O2", "-o"])
        .arg(out)
        .arg(source)
        .status()
        .unwrap();
    assert!(status.success(), "cc failed");
    out.canonicalize().unwrap()
}

fn spec(layout: &Layout) -> SandboxSpec {
    SandboxSpec::new(&layout.probe, &layout.grant, &layout.profile_dir)
        .arg(layout.grant.canonicalize().unwrap())
        .arg(&layout.unrelated)
        .arg(&layout.unix_path)
        .arg(&layout.ssh_path)
        .arg(layout.port.to_string())
        .arg(layout.profile_dir.join("sandbox.sb"))
        .arg(&layout.probe)
        .arg(&layout.marker)
        .arg(&layout.symlink_read)
        .arg(&layout.symlink_write)
        .arg(layout.outside.join("spawned.txt"))
}

fn text(obs: &Observation) -> String {
    match obs {
        Observation::Exited { stdout, .. } | Observation::Unknown { stdout, .. } => {
            String::from_utf8_lossy(stdout).to_string()
        }
    }
}

fn agent_alive(pid: u32) -> bool {
    let output = Command::new("/bin/ps")
        .args(["-p", &pid.to_string(), "-o", "pid="])
        .output()
        .unwrap();
    !String::from_utf8_lossy(&output.stdout).trim().is_empty()
}

#[tokio::test]
async fn invalid_paths_never_spawn() {
    let layout = Layout::create("agent-sb-invalid");
    let quoted = SandboxSpec::new(
        "/tmp/foo\" ) (allow default)",
        &layout.grant,
        &layout.profile_dir,
    );
    let err = spawn_in_grant(quoted).await.unwrap_err();
    assert!(matches!(err, SandboxError::InvalidPath(_)), "{err}");
    let relative = SandboxSpec::new("probe", &layout.grant, &layout.profile_dir);
    assert!(matches!(
        spawn_in_grant(relative).await.unwrap_err(),
        SandboxError::InvalidPath(_)
    ));
    let root = SandboxSpec::new(&layout.probe, "/", &layout.profile_dir);
    assert!(matches!(
        spawn_in_grant(root).await.unwrap_err(),
        SandboxError::InvalidPath(_)
            | SandboxError::GrantNotScoped(_)
            | SandboxError::SymlinkEscape(_)
    ));
    let link = layout.root.join("grant-link");
    std::os::unix::fs::symlink(&layout.outside, &link).unwrap();
    let escaped = SandboxSpec::new(&layout.probe, &link, &layout.profile_dir);
    assert!(matches!(
        spawn_in_grant(escaped).await.unwrap_err(),
        SandboxError::SymlinkEscape(_)
    ));
    let inside = SandboxSpec::new(&layout.probe, &layout.grant, &layout.grant);
    assert!(matches!(
        spawn_in_grant(inside).await.unwrap_err(),
        SandboxError::Profile(_)
    ));
}

#[tokio::test]
async fn secret_env_is_rejected_before_spawn() {
    let layout = Layout::create("agent-sb-env");
    let spec = spec(&layout).env_pair("SSH_AUTH_SOCK", &layout.ssh_path);
    let err = spawn_in_grant(spec).await.unwrap_err();
    assert!(matches!(err, SandboxError::EnvRejected(_)), "{err}");
    assert!(!layout.profile_dir.join("sandbox.sb").exists());
}

#[tokio::test]
async fn seatbelt_denies_escape_and_unsandboxed_control_allows() {
    assert_eq!(available_backend(), SandboxBackend::MacosSeatbelt);
    let layout = Layout::create("agent-sb-live");
    let parent_ssh = std::env::var("SSH_AUTH_SOCK").ok();
    let parent_home = std::env::var("HOME").ok();
    let control_grant = layout.root.join("control grant");
    fs::create_dir_all(&control_grant).unwrap();
    let control_exe = layout.bin.join("probe copy");
    fs::copy(&layout.probe, &control_exe).unwrap();
    let control_profile = layout.root.join("control-profile");
    fs::write(&control_profile, b"control").unwrap();
    let control_link = control_grant.join("escape");
    let control_write = control_grant.join("outlink");
    let control_target = layout.outside.join("control-target.txt");
    fs::write(&control_target, b"keep-control").unwrap();
    std::os::unix::fs::symlink(&layout.unrelated, &control_link).unwrap();
    std::os::unix::fs::symlink(&control_target, &control_write).unwrap();
    let control_marker_out = layout.outside.join("control-spawned.txt");
    let control = Command::new(&layout.probe)
        .arg(control_grant.canonicalize().unwrap())
        .arg(&layout.unrelated)
        .arg(&layout.unix_path)
        .arg(&layout.ssh_path)
        .arg(layout.port.to_string())
        .arg(&control_profile)
        .arg(&control_exe)
        .arg(&layout.marker)
        .arg(&control_link)
        .arg(&control_write)
        .arg(&control_marker_out)
        .env("NAZZ_PARENT_CANARY", CANARY)
        .env("SSH_AUTH_SOCK", &layout.ssh_path)
        .env("HOME", "/tmp/control-home")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    let control_out = String::from_utf8_lossy(&control.stdout).to_string();
    assert!(control.status.success(), "{control_out}");
    assert!(control_out.contains("grant_write=allowed"), "{control_out}");
    assert!(
        control_out.contains("unrelated_file=allowed"),
        "{control_out}"
    );
    assert!(control_out.contains("tcp=allowed"), "{control_out}");
    assert!(control_out.contains("unix=allowed"), "{control_out}");
    assert!(control_out.contains("ssh_agent=allowed"), "{control_out}");
    assert!(
        control_out.contains(&format!("env={CANARY}")),
        "{control_out}"
    );
    assert!(control_out.contains("ssh_env=present"), "{control_out}");
    assert!(control_out.contains("home=present"), "{control_out}");
    assert!(
        control_out.contains("symlink_read=allowed"),
        "{control_out}"
    );
    assert!(
        control_out.contains("symlink_write=allowed"),
        "{control_out}"
    );
    assert!(control_out.contains("other_exec=allowed"), "{control_out}");
    assert!(control_out.contains("exec_write=allowed"), "{control_out}");
    assert!(
        control_out.contains("profile_write=allowed"),
        "{control_out}"
    );
    assert_eq!(fs::read(&control_marker_out).unwrap(), b"spawned");
    assert_eq!(fs::read(&control_target).unwrap(), b"ok");

    let mut child = spawn_in_grant(spec(&layout)).await.unwrap();
    assert!(child.capability().tool_host_integration_ready());
    assert_eq!(child.capability().backend(), SandboxBackend::MacosSeatbelt);
    assert!(!child.executable().starts_with(child.grant_dir()));
    let profile = fs::read_to_string(child.profile_path()).unwrap();
    assert!(profile.contains("(deny default)"));
    assert!(!profile.contains("(allow default)"));
    assert!(!profile.contains("(allow network"));
    assert!(!profile.contains("(subpath \"/usr\")"));
    assert!(!profile.contains("(subpath \"/System\")"));
    assert!(!profile.contains("(subpath \"/Library\")"));
    let before = fs::read(child.executable()).unwrap();
    let obs = child.observe().await;
    let stdout = text(&obs);
    let Observation::Exited { code, .. } = &obs else {
        panic!("ambiguous sandbox outcome: {obs:?} stdout={stdout}");
    };
    assert_eq!(*code, 0, "{stdout}");
    assert!(stdout.contains("grant_write=allowed"), "{stdout}");
    assert_eq!(fs::read(layout.grant.join("owned.txt")).unwrap(), b"ok");
    assert!(stdout.contains("unrelated_file=denied"), "{stdout}");
    assert!(stdout.contains("tcp=denied"), "{stdout}");
    assert!(stdout.contains("unix=denied"), "{stdout}");
    assert!(stdout.contains("ssh_agent=denied"), "{stdout}");
    assert!(stdout.contains("env=absent"), "{stdout}");
    assert!(stdout.contains("ssh_env=absent"), "{stdout}");
    assert!(stdout.contains("home=absent"), "{stdout}");
    assert!(stdout.contains("path=/usr/bin:/bin"), "{stdout}");
    assert!(stdout.contains("profile_write=denied"), "{stdout}");
    assert!(stdout.contains("exec_write=denied"), "{stdout}");
    assert!(stdout.contains("symlink_read=denied"), "{stdout}");
    assert!(stdout.contains("symlink_write=denied"), "{stdout}");
    assert!(stdout.contains("made_symlink_read=denied"), "{stdout}");
    assert!(stdout.contains("other_exec=denied"), "{stdout}");
    assert!(!stdout.contains(CANARY), "{stdout}");
    if let Some(sock) = parent_ssh {
        assert!(!stdout.contains(&sock), "{stdout}");
    }
    if let Some(home) = parent_home {
        assert!(!stdout.contains(&home), "{stdout}");
    }
    assert_eq!(fs::read(&layout.unrelated).unwrap(), b"secret-outside");
    assert_eq!(fs::read(&layout.write_target).unwrap(), b"keep-me");
    assert!(!layout.outside.join("spawned.txt").exists());
    assert_eq!(fs::read(child.executable()).unwrap(), before);
    assert!(
        fs::read_to_string(child.profile_path())
            .unwrap()
            .contains("(deny default)")
    );
    assert!(TcpStream::connect(("127.0.0.1", layout.port)).is_ok());
    assert!(UnixStream::connect(&layout.unix_path).is_ok());
    assert!(UnixStream::connect(&layout.ssh_path).is_ok());
}

#[tokio::test]
async fn generic_sleep_runs_and_stop_spares_bystander() {
    let layout = Layout::create("agent-sb-stop");
    let mut bystander = Command::new("/bin/sleep")
        .arg("30")
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let bystander_pid = bystander.id();
    let mut child = spawn_in_grant(
        SandboxSpec::new("/bin/sleep", &layout.grant, &layout.profile_dir).arg("30"),
    )
    .await
    .unwrap();
    let pgid = child.pgid();
    assert_ne!(pgid, bystander_pid);
    let stopped = child.stop_owned().await.unwrap();
    assert!(stopped.observed_stop, "{stopped:?}");
    assert_eq!(stopped.pgid, pgid);
    assert!(matches!(
        stopped.outcome,
        Observation::Unknown {
            reason: UnknownReason::Stopped,
            ..
        }
    ));
    assert!(!agent_alive(pgid), "sandbox group survived");
    assert!(agent_alive(bystander_pid), "bystander was killed");
    let _ = Command::new("/bin/kill")
        .args(["-KILL", &bystander_pid.to_string()])
        .status();
    let _ = bystander.wait();
}

#[tokio::test]
async fn drop_timeout_and_output_limit_leave_no_orphan() {
    let layout = Layout::create("agent-sb-limit");
    let sleeper = spawn_in_grant(
        SandboxSpec::new("/bin/sleep", &layout.grant, &layout.profile_dir).arg("30"),
    )
    .await
    .unwrap();
    let pid = sleeper.pid();
    drop(sleeper);
    assert!(!agent_alive(pid), "drop left an orphan");

    let timeout_dir = layout.root.join("profile timeout");
    let flood_dir = layout.root.join("profile flood");
    fs::create_dir_all(&timeout_dir).unwrap();
    fs::create_dir_all(&flood_dir).unwrap();
    let mut timed = spawn_in_grant(
        SandboxSpec::new("/bin/sleep", &layout.grant, &timeout_dir)
            .arg("30")
            .timeout(Duration::from_millis(300)),
    )
    .await
    .unwrap();
    let timed_pid = timed.pid();
    let obs = timed.observe().await;
    assert!(
        matches!(
            obs,
            Observation::Unknown {
                reason: UnknownReason::Timeout,
                ..
            }
        ),
        "{obs:?}"
    );
    assert!(!agent_alive(timed_pid), "timeout left an orphan");

    let mut flood = spawn_in_grant(
        SandboxSpec::new(&layout.probe, &layout.grant, &flood_dir)
            .arg("--flood")
            .limit(1024),
    )
    .await
    .unwrap();
    let flood_pid = flood.pid();
    let obs = flood.observe().await;
    match &obs {
        Observation::Unknown {
            reason: UnknownReason::OutputLimit,
            stdout,
            ..
        } => {
            assert!(stdout.len() <= 1024, "{}", stdout.len());
        }
        other => panic!("expected output limit, got {other:?}"),
    }
    assert!(!agent_alive(flood_pid), "output limit left an orphan");
}

#[tokio::test]
async fn executable_inside_grant_is_rejected() {
    let layout = Layout::create("agent-sb-inside");
    let planted = layout.grant.join("planted");
    fs::copy(&layout.probe, &planted).unwrap();
    let err = spawn_in_grant(SandboxSpec::new(
        planted,
        &layout.grant,
        &layout.profile_dir,
    ))
    .await
    .unwrap_err();
    assert!(matches!(err, SandboxError::ExecutableInsideGrant), "{err}");
}
