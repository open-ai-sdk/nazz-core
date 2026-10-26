use super::*;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;

const LAUNCHER: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/sandbox-launcher"));

// Only the trusted system ELF loader may resolve runtime dependencies. Never run
// ldd (or the supplied program) outside the sandbox. RPATH-selected private libs
// are deliberately unsupported: they would create additional filesystem grants.
fn runtime_files(executable: &Path) -> Result<Vec<PathBuf>, SandboxError> {
    let invalid = || SandboxError::Unavailable("invalid or unsupported ELF64".into());
    let mut file = std::fs::File::open(executable).map_err(|e| SandboxError::Io(e.to_string()))?;
    let file_len = file
        .metadata()
        .map_err(|e| SandboxError::Io(e.to_string()))?
        .len();
    let mut header = [0u8; 64];
    file.read_exact(&mut header).map_err(|_| invalid())?;
    if &header[..6] != b"\x7fELF\x02\x01" {
        return Err(invalid());
    }
    let start = u64::from_le_bytes(header[32..40].try_into().unwrap());
    let size = u16::from_le_bytes(header[54..56].try_into().unwrap()) as u64;
    let count = u16::from_le_bytes(header[56..58].try_into().unwrap()) as u64;
    if size < 56
        || count > 1024
        || start
            .checked_add(size * count)
            .is_none_or(|end| end > file_len)
    {
        return Err(invalid());
    }
    let mut interpreter = None;
    for i in 0..count {
        let mut program = [0u8; 56];
        file.seek(SeekFrom::Start(start + i * size))
            .and_then(|_| file.read_exact(&mut program))
            .map_err(|_| invalid())?;
        let kind = u32::from_le_bytes(program[..4].try_into().unwrap());
        if kind != 2 && kind != 3 {
            continue;
        }
        let offset = u64::from_le_bytes(program[8..16].try_into().unwrap());
        let len = u64::from_le_bytes(program[32..40].try_into().unwrap());
        if offset.checked_add(len).is_none_or(|end| end > file_len) {
            return Err(invalid());
        }
        file.seek(SeekFrom::Start(offset)).map_err(|_| invalid())?;
        if kind == 3 {
            if len == 0 || len > 1024 || interpreter.is_some() {
                return Err(invalid());
            }
            let mut data = vec![0u8; len as usize];
            file.read_exact(&mut data).map_err(|_| invalid())?;
            interpreter = Some(
                std::str::from_utf8(data.strip_suffix(&[0]).ok_or_else(invalid)?)
                    .map_err(|_| invalid())?
                    .to_owned(),
            );
        } else {
            if len > 1024 * 1024 || len % 16 != 0 {
                return Err(invalid());
            }
            for _ in 0..len / 16 {
                let mut entry = [0u8; 16];
                file.read_exact(&mut entry).map_err(|_| invalid())?;
                let tag = u64::from_le_bytes(entry[..8].try_into().unwrap());
                if tag == 0 {
                    break;
                }
                // GNU audit/filter hooks can execute code even during --list.
                if matches!(tag, 0x6ffffefb | 0x6ffffefc | 0x7ffffffd | 0x7fffffff) {
                    return Err(SandboxError::Unavailable(
                        "ELF audit/filter hooks are not supported".into(),
                    ));
                }
            }
        }
    }
    let Some(interpreter) = interpreter else {
        return Ok(Vec::new());
    };
    let expected = if cfg!(target_arch = "aarch64") {
        "/lib/ld-linux-aarch64.so.1"
    } else if cfg!(target_arch = "x86_64") {
        "/lib64/ld-linux-x86-64.so.2"
    } else {
        return Err(SandboxError::Unsupported);
    };
    if interpreter != expected {
        return Err(SandboxError::Unavailable(
            "non-system ELF interpreter".into(),
        ));
    }
    let out = Command::new(expected)
        .arg("--list")
        .arg(executable)
        .env_clear()
        .output()
        .map_err(|e| SandboxError::Unavailable(e.to_string()))?;
    if !out.status.success() {
        return Err(SandboxError::Unavailable(format!(
            "ELF dependency resolution: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    let mut files = vec![PathBuf::from(expected)];
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let value = line.split_once("=>").map_or(line, |(_, tail)| tail).trim();
        let path = value.split_whitespace().next().unwrap_or("");
        if !path.starts_with('/') {
            continue;
        }
        let path = PathBuf::from(path);
        let canonical = path
            .canonicalize()
            .map_err(|e| SandboxError::Unavailable(e.to_string()))?;
        if !["/usr/lib", "/usr/lib64", "/lib", "/lib64"]
            .iter()
            .any(|root| canonical.starts_with(root))
            || !path_chars_ok(&path.to_string_lossy())
            || !canonical.is_file()
        {
            return Err(SandboxError::Unavailable(
                "non-system ELF dependency".into(),
            ));
        }
        if !files.contains(&path) {
            files.push(path);
        }
    }
    Ok(files)
}

pub(super) fn spawn(prepared: Prepared) -> Result<SandboxChild, SandboxError> {
    if ["/proc", "/sys", "/dev"]
        .iter()
        .any(|root| prepared.grant_dir.starts_with(root))
    {
        return Err(SandboxError::GrantNotScoped(
            "Linux kernel pseudo-filesystem".into(),
        ));
    }
    let bwrap = Path::new("/usr/bin/bwrap");
    if !bwrap.is_file() {
        return Err(SandboxError::Unavailable("missing /usr/bin/bwrap".into()));
    }
    let launcher = prepared.profile_dir.join("sandbox.launcher");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o500)
        .open(&launcher)
        .map_err(|e| SandboxError::Profile(e.to_string()))?;
    let written = file.write_all(LAUNCHER).and_then(|_| file.sync_all());
    drop(file);
    if let Err(error) = written {
        let _ = std::fs::remove_file(&launcher);
        return Err(SandboxError::Io(error.to_string()));
    }
    // Resolve dependencies and bind the same private snapshot. Replacing the
    // host executable between ELF inspection and spawn cannot bypass inspection.
    let snapshot = prepared.profile_dir.join("sandbox.executable");
    let mut output = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o500)
        .open(&snapshot)
    {
        Ok(file) => file,
        Err(error) => {
            let _ = std::fs::remove_file(&launcher);
            return Err(SandboxError::Profile(error.to_string()));
        }
    };
    let copied = std::fs::File::open(&prepared.executable)
        .and_then(|mut input| std::io::copy(&mut input, &mut output))
        .and_then(|_| output.sync_all());
    drop(output);
    let result = copied
        .map_err(|e| SandboxError::Io(e.to_string()))
        .and_then(|_| spawn_inner(&prepared, &launcher, &snapshot));
    if result.is_err() {
        let _ = std::fs::remove_file(&launcher);
        let _ = std::fs::remove_file(&snapshot);
    }
    result
}

fn spawn_inner(
    prepared: &Prepared,
    launcher: &Path,
    snapshot: &Path,
) -> Result<SandboxChild, SandboxError> {
    let mut runtime = runtime_files(launcher)?;
    for path in runtime_files(snapshot)? {
        if !runtime.contains(&path) {
            runtime.push(path);
        }
    }
    // Never let a runtime bind overlap the writable grant or its ancestors.
    if runtime
        .iter()
        .any(|path| path.starts_with(&prepared.grant_dir) || prepared.grant_dir.starts_with(path))
    {
        return Err(SandboxError::GrantNotScoped("runtime overlap".into()));
    }
    let mut cmd = Command::new("/usr/bin/bwrap");
    cmd.args([
        "--unshare-all",
        "--unshare-user",
        "--die-with-parent",
        "--disable-userns",
        "--cap-drop",
        "ALL",
        "--clearenv",
    ])
    .arg("--ro-bind")
    .arg(launcher)
    .arg(launcher)
    .arg("--ro-bind")
    .arg(snapshot)
    .arg(&prepared.executable);
    for path in &runtime {
        cmd.arg("--ro-bind").arg(path).arg(path);
    }
    cmd.arg("--bind")
        .arg(&prepared.grant_dir)
        .arg(&prepared.grant_dir)
        .arg("--chdir")
        .arg(&prepared.grant_dir)
        .args(["--remount-ro", "/"]);
    for (key, value) in &prepared.env {
        cmd.arg("--setenv").arg(key).arg(value);
    }
    cmd.arg("--")
        .arg(launcher)
        .arg(&prepared.grant_dir)
        .arg(&prepared.executable)
        .arg(runtime.len().to_string())
        .args(&runtime)
        .arg(&prepared.executable)
        .args(&prepared.args)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();
    let mut child = cmd
        .spawn()
        .map_err(|e| SandboxError::Spawn(e.to_string()))?;
    let pid = child.id();
    if pid <= 1 {
        let _ = child.kill();
        let _ = child.wait();
        return Err(SandboxError::Spawn("unscoped pid".into()));
    }
    let stderr = spawn_reader(child.stderr.take().unwrap(), prepared.stderr_limit);
    let mut stdout = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let handshake = thread::spawn(move || {
        let mut marker = [0; 8];
        let ready = stdout.read_exact(&mut marker).is_ok() && &marker == b"SBOXv1!\n";
        let _ = tx.send((ready, stdout));
    });
    let ready = rx.recv_timeout(Duration::from_secs(5));
    let stdout = match ready {
        Ok((true, stdout)) => stdout,
        _ => {
            let _ = signal_group(pid, "-KILL");
            let _ = child.kill();
            let _ = child.wait();
            let _ = handshake.join();
            let mut stderr = stderr;
            if let Some(thread) = stderr.thread.take() {
                let _ = thread.join();
            }
            let message = stderr.bytes.lock().unwrap_or_else(|e| e.into_inner());
            return Err(SandboxError::Unavailable(format!(
                "kernel enforcement handshake failed: {}",
                String::from_utf8_lossy(&message)
            )));
        }
    };
    let _ = handshake.join();
    Ok(SandboxChild {
        child: Some(child),
        stdout: spawn_reader(stdout, prepared.stdout_limit),
        stderr,
        capability: SandboxCapability {
            backend: SandboxBackend::LinuxBubblewrapLandlock,
            pgid: pid,
            seal: Seal,
        },
        pid,
        executable: prepared.executable.clone(),
        grant_dir: prepared.grant_dir.clone(),
        profile_path: launcher.to_path_buf(),
        timeout: prepared.timeout,
        started: Instant::now(),
        executable_snapshot: snapshot.to_path_buf(),
        finished: None,
        armed: true,
    })
}
