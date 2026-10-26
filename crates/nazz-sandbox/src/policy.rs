use std::path::{Component, Path};

use crate::SandboxError;

pub const MAX_PATH_BYTES: usize = 1024;
pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
pub const DEFAULT_OUTPUT_BYTES: usize = 64 * 1024;
pub const DEFAULT_PATH: &str = "/usr/bin:/bin";

const UNSCOPED: &[&str] = &[
    "/",
    "/usr",
    "/System",
    "/Library",
    "/bin",
    "/sbin",
    "/opt",
    "/Users",
    "/home",
    "/var",
    "/private",
    "/tmp",
    "/private/tmp",
    "/dev",
    "/etc",
    "/Applications",
    "/Volumes",
];

#[cfg(any(target_os = "macos", test))]
pub fn quote_sbpl(path: &str) -> Result<String, SandboxError> {
    if !path_chars_ok(path) {
        return Err(SandboxError::InvalidPath(path.to_string()));
    }
    Ok(format!("\"{path}\""))
}

pub fn path_chars_ok(path: &str) -> bool {
    !path.is_empty()
        && path.starts_with('/')
        && path.len() <= MAX_PATH_BYTES
        && !path.contains("//")
        && path
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '_' | '-' | '+' | ' '))
        && !path.split('/').any(|part| part == "." || part == "..")
}

#[cfg(any(target_os = "macos", test))]
pub fn render_profile(executable: &str, grant: &str) -> Result<String, SandboxError> {
    let exe = quote_sbpl(executable)?;
    let grant = quote_sbpl(grant)?;
    if executable == grant || grant.starts_with(&format!("{executable}/")) {
        return Err(SandboxError::ExecutableInsideGrant);
    }
    let profile = format!(
        "(version 1)\n\
         (deny default)\n\
         (debug deny)\n\
         (allow process-exec (literal {exe}))\n\
         (allow process-fork)\n\
         (allow signal (target self))\n\
         (allow file-read-data (literal {exe}))\n\
         (allow file-read-metadata (literal {exe}))\n\
         (allow file-map-executable (literal {exe}))\n\
         (allow file-read* (subpath {grant}))\n\
         (allow file-write* (subpath {grant}))\n\
         (allow sysctl-read (sysctl-name \"security.mac.lockdown_mode_state\"))\n\
         (allow sysctl-read (sysctl-name \"kern.bootargs\"))\n\
         (allow file-read-data (literal \"/\"))\n"
    );
    if profile.contains("(allow default)")
        || profile.contains("(allow network")
        || profile.contains("(subpath \"/usr\")")
        || profile.contains("(subpath \"/System\")")
        || profile.contains("(subpath \"/Library\")")
    {
        return Err(SandboxError::Profile("refusing widened profile".into()));
    }
    for line in profile.lines() {
        if line.contains("file-write") && line.contains(executable) {
            return Err(SandboxError::Profile("executable is writable".into()));
        }
    }
    Ok(profile)
}

pub fn grant_is_scoped(canonical: &str) -> bool {
    path_chars_ok(canonical) && !UNSCOPED.contains(&canonical)
}

pub fn supplied_symlink_escape(path: &Path) -> Result<(), SandboxError> {
    if !path.is_absolute() {
        return Err(SandboxError::InvalidPath(path.display().to_string()));
    }
    let mut cursor = std::path::PathBuf::new();
    let parts: Vec<_> = path.components().collect();
    for (index, component) in parts.iter().enumerate() {
        match component {
            Component::RootDir => cursor.push("/"),
            Component::Normal(part) => {
                cursor.push(part);
                let is_link = cursor
                    .symlink_metadata()
                    .map(|meta| meta.file_type().is_symlink())
                    .unwrap_or(false);
                let last = index + 1 == parts.len();
                if is_link && (last || !is_platform_symlink(&cursor)) {
                    return Err(SandboxError::SymlinkEscape(path.display().to_string()));
                }
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(SandboxError::InvalidPath(path.display().to_string()));
            }
        }
    }
    Ok(())
}

fn is_platform_symlink(path: &Path) -> bool {
    path == Path::new("/tmp") || path == Path::new("/var")
}

pub fn scrub_env(
    pairs: &[(std::ffi::OsString, std::ffi::OsString)],
) -> Result<Vec<(String, String)>, SandboxError> {
    let mut out = Vec::new();
    let mut saw_path = false;
    for (key, value) in pairs {
        let key = key
            .to_str()
            .ok_or_else(|| SandboxError::EnvRejected("non-utf8 key".into()))?;
        let value = value
            .to_str()
            .ok_or_else(|| SandboxError::EnvRejected("non-utf8 value".into()))?;
        if key_rejected(key) || value_rejected(value) {
            return Err(SandboxError::EnvRejected(key.to_string()));
        }
        if key == "PATH" {
            saw_path = true;
        }
        out.push((key.to_string(), value.to_string()));
    }
    if !saw_path {
        out.push(("PATH".into(), DEFAULT_PATH.into()));
    }
    Ok(out)
}

fn key_rejected(key: &str) -> bool {
    if key.is_empty()
        || key.contains('=')
        || key.contains('\0')
        || !key
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return true;
    }
    let upper = key.to_ascii_uppercase();
    const EXACT: &[&str] = &[
        "SSH_AUTH_SOCK",
        "SSH_AGENT_PID",
        "HOME",
        "USER",
        "LOGNAME",
        "TMPDIR",
        "PWD",
        "OLDPWD",
        "SHELL",
        "MAIL",
    ];
    EXACT.contains(&upper.as_str())
        || upper.starts_with("NAZZ_")
        || upper.starts_with("HERDR_")
        || upper.starts_with("OMP_")
        || upper.starts_with("DYLD_")
        || upper.starts_with("LD_")
        || upper.starts_with("AWS_")
        || upper.starts_with("OPENAI_")
        || upper.starts_with("ANTHROPIC_")
        || upper.starts_with("XAI_")
        || upper.contains("SECRET")
        || upper.contains("TOKEN")
        || upper.contains("PASSWORD")
        || upper.contains("CREDENTIAL")
        || upper.contains("COOKIE")
        || upper.contains("SESSION")
        || upper.contains("_KEY")
        || upper.ends_with("KEY")
}

fn value_rejected(value: &str) -> bool {
    if value.is_empty() || value.contains('\0') || value.contains('\n') || value.contains('\r') {
        return true;
    }
    let lower = value.to_ascii_lowercase();
    lower.contains("/users/")
        || lower.contains("/home/")
        || lower.contains(".ssh")
        || lower.contains(".aws")
        || lower.contains(".omp")
        || lower.contains("id_rsa")
        || lower.contains("credentials")
        || lower.contains("begin private")
        || lower.contains("begin openssh")
        || lower.contains("sk-")
        || lower.contains("akia")
        || value.contains('~')
}
