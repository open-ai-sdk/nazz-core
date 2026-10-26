//! Host-approved OS sandbox.
//!
//! The host supplies the executable, grant directory, profile directory, and
//! argv array. This crate does not interpolate a shell, does not accept a
//! model whitelist, and does not record an effect ledger.
//!
//! Linux requires `/usr/bin/bwrap`, permitted unprivileged user namespaces,
//! seccomp and Landlock ABI >= 3. A sparse read-only root contains only the
//! embedded launcher, a private snapshot of the approved ELF64 executable, and
//! its exact trusted system loader/libraries; only the directory grant is
//! writable. No host `/proc`, `/dev`, home, or broad system tree is mounted.
//! Landlock denies execution from the writable grant; seccomp denies sockets
//! (including Unix), process/fd attacks and io_uring. Descendants inherit all
//! restrictions. Stdin is null; stdout/stderr remain bounded host-owned pipes.
//! Missing prerequisites or a failed enforcement handshake return an error:
//! there is no unrestricted fallback or privileged relaunch.
//!
//! The host owns the profile directory and system runtime outside every
//! untrusted grant. Scripts, non-system loaders/libraries and audit/filter
//! hooks are unsupported. On Ubuntu with restricted user namespaces, the host
//! administrator must permit the trusted bwrap binary via its AppArmor profile;
//! this crate never changes host policy. macOS retains Seatbelt; Windows and
//! other platforms remain unsupported.

#[cfg(target_os = "linux")]
mod linux;
mod policy;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[cfg(any(target_os = "macos", test))]
use policy::render_profile;
use policy::{
    DEFAULT_OUTPUT_BYTES, MAX_OUTPUT_BYTES, grant_is_scoped, path_chars_ok, scrub_env,
    supplied_symlink_escape,
};

/// Proven on macOS 15.7.5, 2026-10-14, with `sandbox-exec` deny-default.
/// Literal `/` read and these two sysctls were required for startup. This is
/// not a grant of `/usr`, `/System`, or `/Library`.
pub const PROVEN_STARTUP_DENIAL: &str = "deny(1) file-read-data / ; deny(1) sysctl-read security.mac.lockdown_mode_state ; deny(1) sysctl-read kern.bootargs";

#[derive(Debug)]
pub enum SandboxError {
    Unsupported,
    Unavailable(String),
    InvalidPath(String),
    SymlinkEscape(String),
    ExecutableInsideGrant,
    GrantNotScoped(String),
    Profile(String),
    EnvRejected(String),
    Spawn(String),
    Io(String),
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported => write!(f, "sandbox backend unsupported"),
            Self::Unavailable(msg) => write!(f, "sandbox unavailable: {msg}"),
            Self::InvalidPath(path) => write!(f, "invalid sandbox path: {path}"),
            Self::SymlinkEscape(path) => write!(f, "symlink escape: {path}"),
            Self::ExecutableInsideGrant => write!(f, "executable is inside the writable grant"),
            Self::GrantNotScoped(path) => write!(f, "grant is not scoped: {path}"),
            Self::Profile(msg) => write!(f, "sandbox profile: {msg}"),
            Self::EnvRejected(key) => write!(f, "env rejected: {key}"),
            Self::Spawn(msg) => write!(f, "sandbox spawn: {msg}"),
            Self::Io(msg) => write!(f, "sandbox io: {msg}"),
        }
    }
}

impl std::error::Error for SandboxError {}

/// What this process can enforce. Not an attestation. A caller cannot turn
/// this enum into proof that a child was sandboxed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxBackend {
    MacosSeatbelt,
    LinuxBubblewrapLandlock,
    Unsupported,
}

pub fn available_backend() -> SandboxBackend {
    #[cfg(target_os = "macos")]
    {
        SandboxBackend::MacosSeatbelt
    }
    #[cfg(target_os = "linux")]
    {
        SandboxBackend::LinuxBubblewrapLandlock
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        SandboxBackend::Unsupported
    }
}

/// Network is a separate grant. This crate only has deny. A directory grant
/// never implies TCP, Unix sockets, or raw IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkGrant {
    Deny,
}

#[derive(Debug, Clone)]
pub struct SandboxSpec {
    pub executable: PathBuf,
    pub grant_dir: PathBuf,
    pub profile_dir: PathBuf,
    pub args: Vec<OsString>,
    pub env: Vec<(OsString, OsString)>,
    pub network: NetworkGrant,
    pub stdout_limit: usize,
    pub stderr_limit: usize,
    pub timeout: Option<Duration>,
}

impl SandboxSpec {
    pub fn new(
        executable: impl Into<PathBuf>,
        grant_dir: impl Into<PathBuf>,
        profile_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            executable: executable.into(),
            grant_dir: grant_dir.into(),
            profile_dir: profile_dir.into(),
            args: Vec::new(),
            env: Vec::new(),
            network: NetworkGrant::Deny,
            stdout_limit: DEFAULT_OUTPUT_BYTES,
            stderr_limit: DEFAULT_OUTPUT_BYTES,
            timeout: None,
        }
    }

    pub fn arg(mut self, arg: impl Into<OsString>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn args<I, T>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub fn env_pair(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    pub fn limit(mut self, bytes: usize) -> Self {
        self.stdout_limit = bytes;
        self.stderr_limit = bytes;
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnknownReason {
    StillRunning,
    Timeout,
    OutputLimit,
    WaitFailed,
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observation {
    Exited {
        code: i32,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
    Unknown {
        reason: UnknownReason,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopObservation {
    pub pgid: u32,
    pub observed_stop: bool,
    pub outcome: Observation,
}

/// Minted by a successful OS sandbox launch, never by backend availability.
/// Linux additionally requires the launcher's kernel-enforcement handshake.
pub struct SandboxCapability {
    backend: SandboxBackend,
    pgid: u32,
    seal: Seal,
}

impl std::fmt::Debug for SandboxCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxCapability")
            .field("backend", &self.backend)
            .field("pgid", &self.pgid)
            .finish_non_exhaustive()
    }
}

impl SandboxCapability {
    pub fn backend(&self) -> SandboxBackend {
        self.backend
    }

    pub fn pgid(&self) -> u32 {
        self.pgid
    }

    /// Shared policy for the next tool host. True only for a token this crate
    /// minted after OS sandbox launch. There is no enum the adapter can set.
    pub fn tool_host_integration_ready(&self) -> bool {
        let _ = &self.seal;
        self.backend != SandboxBackend::Unsupported && self.pgid > 1
    }
}

struct Seal;

struct PipeRead {
    bytes: Arc<Mutex<Vec<u8>>>,
    hit: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

pub struct SandboxChild {
    child: Option<Child>,
    stdout: PipeRead,
    stderr: PipeRead,
    capability: SandboxCapability,
    pid: u32,
    executable: PathBuf,
    grant_dir: PathBuf,
    profile_path: PathBuf,
    #[cfg(target_os = "linux")]
    executable_snapshot: PathBuf,
    timeout: Option<Duration>,
    started: Instant,
    finished: Option<Observation>,
    armed: bool,
}

impl std::fmt::Debug for SandboxChild {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxChild")
            .field("pid", &self.pid)
            .field("pgid", &self.capability.pgid)
            .field("executable", &self.executable)
            .field("grant_dir", &self.grant_dir)
            .finish_non_exhaustive()
    }
}

impl SandboxChild {
    pub fn capability(&self) -> &SandboxCapability {
        &self.capability
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn pgid(&self) -> u32 {
        self.capability.pgid
    }

    pub fn executable(&self) -> &Path {
        &self.executable
    }

    pub fn grant_dir(&self) -> &Path {
        &self.grant_dir
    }

    pub fn profile_path(&self) -> &Path {
        &self.profile_path
    }

    pub async fn try_observe(&mut self) -> Observation {
        if let Some(obs) = &self.finished {
            return obs.clone();
        }
        self.poll_once(false).await
    }

    pub async fn observe(&mut self) -> Observation {
        if let Some(obs) = &self.finished {
            return obs.clone();
        }
        loop {
            let obs = self.poll_once(true).await;
            if !matches!(
                obs,
                Observation::Unknown {
                    reason: UnknownReason::StillRunning,
                    ..
                }
            ) {
                return obs;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    pub async fn stop_owned(&mut self) -> Result<StopObservation, SandboxError> {
        let pgid = self.pgid();
        if self.armed {
            signal_group(pgid, "-TERM")?;
            let deadline = Instant::now() + Duration::from_millis(400);
            while Instant::now() < deadline
                && self.child.is_some()
                && pgid_alive(pgid).unwrap_or(true)
            {
                if self
                    .child
                    .as_mut()
                    .and_then(|child| child.try_wait().ok())
                    .flatten()
                    .is_some()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            if pgid_alive(pgid).unwrap_or(true) {
                signal_group(pgid, "-KILL")?;
            }
            self.reap();
            if self.finished.is_none() {
                let (stdout, stderr) = self.buffers();
                self.finished = Some(unknown(UnknownReason::Stopped, &stdout, &stderr));
            }
        }
        let observed_stop = !pgid_alive(pgid)?;
        Ok(StopObservation {
            pgid,
            observed_stop,
            outcome: self
                .finished
                .clone()
                .unwrap_or_else(|| unknown(UnknownReason::Stopped, &[], &[])),
        })
    }

    async fn poll_once(&mut self, enforce_timeout: bool) -> Observation {
        if self.stdout.hit.load(Ordering::SeqCst) || self.stderr.hit.load(Ordering::SeqCst) {
            return self.finish(UnknownReason::OutputLimit, None);
        }
        let status = match self.child.as_mut() {
            Some(child) => child.try_wait(),
            None => return self.finish(UnknownReason::WaitFailed, None),
        };
        match status {
            Ok(Some(status)) => {
                let code = status.code();
                self.reap();
                let (stdout, stderr) = self.buffers();
                let obs = match code {
                    Some(code) => Observation::Exited {
                        code,
                        stdout,
                        stderr,
                    },
                    None => unknown(UnknownReason::Stopped, &stdout, &stderr),
                };
                self.finished = Some(obs.clone());
                obs
            }
            Ok(None) => {
                if enforce_timeout
                    && self
                        .timeout
                        .is_some_and(|limit| self.started.elapsed() >= limit)
                {
                    return self.finish(UnknownReason::Timeout, None);
                }
                let (stdout, stderr) = self.buffers();
                unknown(UnknownReason::StillRunning, &stdout, &stderr)
            }
            Err(_) => self.finish(UnknownReason::WaitFailed, None),
        }
    }

    fn finish(&mut self, reason: UnknownReason, _code: Option<i32>) -> Observation {
        self.reap();
        let (stdout, stderr) = self.buffers();
        let obs = unknown(reason, &stdout, &stderr);
        self.finished = Some(obs.clone());
        obs
    }

    fn reap(&mut self) {
        if self.armed {
            let _ = signal_group(self.pgid(), "-KILL");
        }
        if let Some(mut child) = self.child.take() {
            let deadline = Instant::now() + Duration::from_secs(1);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) | Err(_) => break,
                    Ok(None) if Instant::now() >= deadline => break,
                    Ok(None) => thread::sleep(Duration::from_millis(20)),
                }
            }
        }
        self.armed = false;
        if let Some(handle) = self.stdout.thread.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.stderr.thread.take() {
            let _ = handle.join();
        }
    }

    fn buffers(&self) -> (Vec<u8>, Vec<u8>) {
        let stdout = self
            .stdout
            .bytes
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();
        let stderr = self
            .stderr
            .bytes
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();
        (stdout, stderr)
    }
}

impl Drop for SandboxChild {
    fn drop(&mut self) {
        if self.armed {
            let _ = signal_group(self.pgid(), "-KILL");
            if let Some(mut child) = self.child.take() {
                let deadline = Instant::now() + Duration::from_secs(1);
                loop {
                    match child.try_wait() {
                        Ok(Some(_)) | Err(_) => break,
                        Ok(None) if Instant::now() >= deadline => break,
                        Ok(None) => thread::sleep(Duration::from_millis(20)),
                    }
                }
            }
            if let Some(handle) = self.stdout.thread.take() {
                let _ = handle.join();
            }
            if let Some(handle) = self.stderr.thread.take() {
                let _ = handle.join();
            }
            self.armed = false;
        }
        let _ = std::fs::remove_file(&self.profile_path);
        #[cfg(target_os = "linux")]
        let _ = std::fs::remove_file(&self.executable_snapshot);
    }
}

pub async fn spawn_in_grant(spec: SandboxSpec) -> Result<SandboxChild, SandboxError> {
    let prepared = prepare(spec)?;
    #[cfg(target_os = "macos")]
    {
        spawn_seatbelt(prepared).await
    }
    #[cfg(target_os = "linux")]
    {
        linux::spawn(prepared)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = prepared;
        Err(SandboxError::Unsupported)
    }
}

struct Prepared {
    executable: PathBuf,
    grant_dir: PathBuf,
    profile_dir: PathBuf,
    args: Vec<OsString>,
    env: Vec<(String, String)>,
    stdout_limit: usize,
    stderr_limit: usize,
    timeout: Option<Duration>,
    #[cfg(target_os = "macos")]
    profile: String,
}

fn prepare(spec: SandboxSpec) -> Result<Prepared, SandboxError> {
    if spec.network != NetworkGrant::Deny {
        return Err(SandboxError::Unsupported);
    }
    if spec.stdout_limit == 0
        || spec.stderr_limit == 0
        || spec.stdout_limit > MAX_OUTPUT_BYTES
        || spec.stderr_limit > MAX_OUTPUT_BYTES
    {
        return Err(SandboxError::InvalidPath("output limit".into()));
    }
    for arg in &spec.args {
        let text = arg
            .to_str()
            .ok_or_else(|| SandboxError::InvalidPath("non-utf8 argv".into()))?;
        if text.contains('\0') {
            return Err(SandboxError::InvalidPath("nul argv".into()));
        }
    }
    let executable = resolve_file(&spec.executable)?;
    let grant_dir = resolve_dir(&spec.grant_dir)?;
    let profile_dir = resolve_dir(&spec.profile_dir)?;
    if !grant_is_scoped(&grant_dir.to_string_lossy())
        || !path_chars_ok(&grant_dir.to_string_lossy())
    {
        return Err(SandboxError::GrantNotScoped(
            grant_dir.display().to_string(),
        ));
    }
    if executable.starts_with(&grant_dir) {
        return Err(SandboxError::ExecutableInsideGrant);
    }
    if profile_dir.starts_with(&grant_dir) || grant_dir.starts_with(&profile_dir) {
        return Err(SandboxError::Profile(
            "profile dir is inside the grant".into(),
        ));
    }
    if !path_chars_ok(&executable.to_string_lossy())
        || !path_chars_ok(&profile_dir.to_string_lossy())
    {
        return Err(SandboxError::InvalidPath(executable.display().to_string()));
    }
    #[cfg(target_os = "macos")]
    let profile = render_profile(&executable.to_string_lossy(), &grant_dir.to_string_lossy())?;
    let env = scrub_env(&spec.env)?;
    Ok(Prepared {
        executable,
        grant_dir,
        profile_dir,
        args: spec.args,
        env,
        stdout_limit: spec.stdout_limit,
        stderr_limit: spec.stderr_limit,
        timeout: spec.timeout,
        #[cfg(target_os = "macos")]
        profile,
    })
}

fn resolve_file(path: &Path) -> Result<PathBuf, SandboxError> {
    supplied_symlink_escape(path)?;
    if path_rejected_early(path) {
        return Err(SandboxError::InvalidPath(path.display().to_string()));
    }
    let meta = std::fs::metadata(path).map_err(|err| SandboxError::Io(err.to_string()))?;
    if !meta.is_file() {
        return Err(SandboxError::InvalidPath(path.display().to_string()));
    }
    let canonical = path
        .canonicalize()
        .map_err(|err| SandboxError::Io(err.to_string()))?;
    if !path_chars_ok(&canonical.to_string_lossy()) {
        return Err(SandboxError::InvalidPath(canonical.display().to_string()));
    }
    Ok(canonical)
}

fn resolve_dir(path: &Path) -> Result<PathBuf, SandboxError> {
    supplied_symlink_escape(path)?;
    if path_rejected_early(path) {
        return Err(SandboxError::InvalidPath(path.display().to_string()));
    }
    let meta = std::fs::metadata(path).map_err(|err| SandboxError::Io(err.to_string()))?;
    if !meta.is_dir() {
        return Err(SandboxError::InvalidPath(path.display().to_string()));
    }
    let canonical = path
        .canonicalize()
        .map_err(|err| SandboxError::Io(err.to_string()))?;
    if !path_chars_ok(&canonical.to_string_lossy()) {
        return Err(SandboxError::InvalidPath(canonical.display().to_string()));
    }
    Ok(canonical)
}

fn path_rejected_early(path: &Path) -> bool {
    let text = path.to_string_lossy();
    !path.is_absolute()
        || text.contains('"')
        || text.contains('\\')
        || text.contains('(')
        || text.contains(')')
        || text.contains('\n')
        || text.contains('\0')
}

#[cfg(target_os = "macos")]
async fn spawn_seatbelt(prepared: Prepared) -> Result<SandboxChild, SandboxError> {
    let sandbox_exec = Path::new("/usr/bin/sandbox-exec");
    if !sandbox_exec.is_file() {
        return Err(SandboxError::Unavailable(
            "missing /usr/bin/sandbox-exec".into(),
        ));
    }
    let profile_path = prepared.profile_dir.join("sandbox.sb");
    if profile_path.exists() {
        return Err(SandboxError::Profile("profile file already exists".into()));
    }
    write_profile(&profile_path, &prepared.profile)?;
    match spawn_process(&prepared, &profile_path) {
        Ok(child) => Ok(child),
        Err(err) => {
            let _ = std::fs::remove_file(&profile_path);
            Err(err)
        }
    }
}

#[cfg(target_os = "macos")]
fn write_profile(path: &Path, profile: &str) -> Result<(), SandboxError> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| SandboxError::Io(err.to_string()))?;
    std::io::Write::write_all(&mut file, profile.as_bytes())
        .map_err(|err| SandboxError::Io(err.to_string()))?;
    file.sync_all()
        .map_err(|err| SandboxError::Io(err.to_string()))?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn spawn_process(prepared: &Prepared, profile_path: &Path) -> Result<SandboxChild, SandboxError> {
    use std::os::unix::process::CommandExt;
    let mut cmd = Command::new("/usr/bin/sandbox-exec");
    cmd.arg("-f")
        .arg(profile_path)
        .arg(&prepared.executable)
        .args(&prepared.args)
        .current_dir(&prepared.grant_dir)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();
    for (key, value) in &prepared.env {
        cmd.env(key, value);
    }
    let mut child = cmd
        .spawn()
        .map_err(|err| SandboxError::Spawn(err.to_string()))?;
    let pid = child.id();
    if pid <= 1 {
        let _ = child.kill();
        let _ = child.wait();
        return Err(SandboxError::Spawn("refusing unscoped pid".into()));
    }
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| SandboxError::Spawn("missing stdout".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| SandboxError::Spawn("missing stderr".into()))?;
    Ok(SandboxChild {
        child: Some(child),
        stdout: spawn_reader(stdout, prepared.stdout_limit),
        stderr: spawn_reader(stderr, prepared.stderr_limit),
        capability: SandboxCapability {
            backend: SandboxBackend::MacosSeatbelt,
            pgid: pid,
            seal: Seal,
        },
        pid,
        executable: prepared.executable.clone(),
        grant_dir: prepared.grant_dir.clone(),
        profile_path: profile_path.to_path_buf(),
        timeout: prepared.timeout,
        started: Instant::now(),
        finished: None,
        armed: true,
    })
}

fn spawn_reader<R>(mut pipe: R, limit: usize) -> PipeRead
where
    R: std::io::Read + Send + 'static,
{
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let hit = Arc::new(AtomicBool::new(false));
    let bytes_bg = Arc::clone(&bytes);
    let hit_bg = Arc::clone(&hit);
    let thread = thread::spawn(move || {
        let mut tmp = [0u8; 8192];
        loop {
            match pipe.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    let mut guard = bytes_bg.lock().unwrap_or_else(|err| err.into_inner());
                    let room = limit.saturating_sub(guard.len());
                    if n > room {
                        guard.extend_from_slice(&tmp[..room]);
                        hit_bg.store(true, Ordering::SeqCst);
                        break;
                    }
                    guard.extend_from_slice(&tmp[..n]);
                }
                Err(_) => break,
            }
        }
    });
    PipeRead {
        bytes,
        hit,
        thread: Some(thread),
    }
}

fn signal_group(pgid: u32, sig: &str) -> Result<(), SandboxError> {
    if pgid <= 1 {
        return Err(SandboxError::Spawn("refusing unscoped signal".into()));
    }
    let mut command = Command::new("/bin/kill");
    command.arg(sig);
    // procps kill otherwise parses a negative PGID as another option.
    #[cfg(target_os = "linux")]
    command.arg("--");
    let _ = command
        .arg(format!("-{pgid}"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    Ok(())
}

fn pgid_alive(pgid: u32) -> Result<bool, SandboxError> {
    if pgid <= 1 {
        return Err(SandboxError::Spawn("refusing unscoped pgid".into()));
    }
    let output = Command::new("/bin/ps")
        .args(["-ax", "-o", "pid=,pgid="])
        .stdin(Stdio::null())
        .output()
        .map_err(|err| SandboxError::Io(err.to_string()))?;
    if !output.status.success() {
        return Err(SandboxError::Io("ps failed".into()));
    }
    let alive = String::from_utf8_lossy(&output.stdout).lines().any(|line| {
        let mut cols = line.split_whitespace();
        let _pid = cols.next();
        cols.next().and_then(|value| value.parse::<u32>().ok()) == Some(pgid)
    });
    Ok(alive)
}

fn unknown(reason: UnknownReason, stdout: &[u8], stderr: &[u8]) -> Observation {
    Observation::Unknown {
        reason,
        stdout: stdout.to_vec(),
        stderr: stderr.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_rejects_injection_and_keeps_spaces() {
        let err =
            render_profile("/tmp/a\" ) (allow default) (literal \"/b", "/tmp/grant").unwrap_err();
        assert!(matches!(err, SandboxError::InvalidPath(_)));
        let profile =
            render_profile("/private/tmp/bin dir/probe", "/private/tmp/grant dir").unwrap();
        assert!(profile.contains("(deny default)"));
        assert!(profile.contains("(literal \"/private/tmp/bin dir/probe\")"));
        assert!(profile.contains("(subpath \"/private/tmp/grant dir\")"));
        assert!(!profile.contains("(allow default)"));
        assert!(!profile.contains("(allow network"));
        assert!(!profile.contains("(subpath \"/usr\")"));
        assert!(!profile.contains("(subpath \"/System\")"));
        assert!(!profile.contains("(subpath \"/Library\")"));
        assert!(
            !profile
                .lines()
                .any(|line| line.contains("file-write")
                    && line.contains("/private/tmp/bin dir/probe"))
        );
    }

    #[test]
    fn env_scrub_rejects_secrets_and_personal_paths() {
        let err = scrub_env(&[("SSH_AUTH_SOCK".into(), "/tmp/agent".into())]).unwrap_err();
        assert!(matches!(err, SandboxError::EnvRejected(_)));
        for key in ["NAZZ_PARENT_CANARY", "HERDR_CONFIG", "OMP_CONFIG"] {
            assert!(scrub_env(&[(key.into(), "x".into())]).is_err());
        }
        assert!(scrub_env(&[("HOME".into(), "/Users/canary".into())]).is_err());
        assert!(scrub_env(&[("FOO".into(), "/Users/canary/.omp".into())]).is_err());
        assert!(scrub_env(&[("FOO".into(), "sk-test".into())]).is_err());
        let ok = scrub_env(&[
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("LANG".into(), "C".into()),
        ])
        .unwrap();
        assert_eq!(
            ok,
            vec![
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("LANG".into(), "C".into())
            ]
        );
    }

    #[test]
    fn availability_is_not_a_token() {
        #[cfg(target_os = "macos")]
        assert_eq!(available_backend(), SandboxBackend::MacosSeatbelt);
        #[cfg(target_os = "linux")]
        assert_eq!(available_backend(), SandboxBackend::LinuxBubblewrapLandlock);
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        assert_eq!(available_backend(), SandboxBackend::Unsupported);
    }
}
