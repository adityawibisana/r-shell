//! Copy a file or directory from one connection to another.
//!
//! The two servers never talk to each other: the data comes down to a local
//! temp file over the source connection and goes up over the target one, so
//! each side keeps using its own already-authenticated session (its own
//! `.pem` key, authenticator code, jump host...). Nothing logs in again.
//!
//! A directory travels as one tar archive, which keeps modes, symlinks and
//! the round-trip count independent of how many files it holds. The final
//! write on the target goes through `sudo -n` when the login user cannot
//! write there, the same fallback plain uploads use.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio_util::sync::CancellationToken;

use crate::ssh::Client;
use crate::sudo_upload::{exec, quote};

type Session = Arc<russh::client::Handle<Client>>;

/// Local staging file, removed however the copy ends.
struct LocalTemp(tempfile::TempPath);

impl LocalTemp {
    fn new() -> Result<Self> {
        let file = tempfile::Builder::new().prefix("rshell-copy-").tempfile()?;
        Ok(Self(file.into_temp_path()))
    }

    fn path(&self) -> Result<&str> {
        self.0
            .to_str()
            .ok_or_else(|| anyhow!("Temp path is not valid UTF-8: {}", self.0.display()))
    }
}

/// Split a POSIX path into (parent, name). `/a/b` → (`/a`, `b`), `/b` → (`/`, `b`).
pub(crate) fn split_remote(path: &str) -> Result<(&str, &str)> {
    let trimmed = path.trim_end_matches('/');
    let idx = trimmed
        .rfind('/')
        .ok_or_else(|| anyhow!("Expected an absolute path, got '{}'", path))?;
    let name = &trimmed[idx + 1..];
    if name.is_empty() || name == "." || name == ".." {
        return Err(anyhow!("Cannot copy '{}'", path));
    }
    let parent = if idx == 0 { "/" } else { &trimmed[..idx] };
    Ok((parent, name))
}

/// Run `command`, turning a non-zero exit into an error carrying its output.
pub(crate) async fn run(session: &Session, command: &str, what: &str) -> Result<String> {
    let (code, out) = exec(session, command).await?;
    if code != 0 {
        let out = out.trim();
        return Err(if out.is_empty() {
            anyhow!("{} failed (exit {})", what, code)
        } else {
            anyhow!("{} failed: {}", what, out)
        });
    }
    Ok(out)
}

async fn remote_mktemp(session: &Session) -> Result<String> {
    let out = run(session, "mktemp /tmp/.rshell-copy.XXXXXXXXXX", "mktemp").await?;
    let path = out.trim().to_string();
    if path.is_empty() || path.contains('\n') {
        return Err(anyhow!("mktemp returned an unexpected path: {:?}", out));
    }
    Ok(path)
}

pub(crate) async fn copy(
    source: &Session,
    source_path: &str,
    is_directory: bool,
    target: &Session,
    target_path: &str,
    cancel: &CancellationToken,
) -> Result<u64> {
    if is_directory {
        copy_directory(source, source_path, target, target_path, cancel).await
    } else {
        copy_file(source, source_path, target, target_path, cancel).await
    }
}

async fn copy_file(
    source: &Session,
    source_path: &str,
    target: &Session,
    target_path: &str,
    cancel: &CancellationToken,
) -> Result<u64> {
    let local = LocalTemp::new()?;
    crate::sftp_transfer::download_file(
        std::slice::from_ref(source),
        source_path,
        local.path()?,
        None,
        cancel,
    )
    .await?;
    crate::sudo_upload::upload_file(
        std::slice::from_ref(target),
        local.path()?,
        target_path,
        None,
        cancel,
    )
    .await
}

async fn copy_directory(
    source: &Session,
    source_path: &str,
    target: &Session,
    target_path: &str,
    cancel: &CancellationToken,
) -> Result<u64> {
    let local = LocalTemp::new()?;
    let bytes = download_directory_archive(source, source_path, local.path()?, cancel).await?;
    let (_, src_name) = split_remote(source_path)?;
    upload_directory_archive(target, local.path()?, src_name, target_path, cancel).await?;
    Ok(bytes)
}

/// Pack `source_path` on the source server and fetch it as one tar archive
/// to `local_path`. The archive holds a single top-level entry named after
/// the directory.
pub(crate) async fn download_directory_archive(
    source: &Session,
    source_path: &str,
    local_path: &str,
    cancel: &CancellationToken,
) -> Result<u64> {
    let (src_parent, src_name) = split_remote(source_path)?;
    // Pack on the source into a private temp archive, fetch it, drop it.
    let archive = remote_mktemp(source).await?;
    let packed = async {
        run(
            source,
            &format!(
                "tar -C {} -cf {} -- {}",
                quote(src_parent),
                quote(&archive),
                quote(src_name)
            ),
            "tar on the source server",
        )
        .await?;
        crate::sftp_transfer::download_file(
            std::slice::from_ref(source),
            &archive,
            local_path,
            None,
            cancel,
        )
        .await
    }
    .await;
    let _ = exec(source, &format!("rm -f -- {}", quote(&archive))).await;
    packed
}

/// Upload a tar archive made by [`download_directory_archive`] (top-level
/// entry `src_name`) and install it at `target_path`.
pub(crate) async fn upload_directory_archive(
    target: &Session,
    local_path: &str,
    src_name: &str,
    target_path: &str,
    cancel: &CancellationToken,
) -> Result<()> {
    let (dst_parent, dst_name) = split_remote(target_path)?;
    // Unpack on the target. Extract into a private staging dir first so the
    // entry can be renamed when the destination name differs, then move it
    // into place — retried with sudo when the parent is not writable.
    let staging = run(
        target,
        "mktemp -d /tmp/.rshell-copy.XXXXXXXXXX",
        "mktemp on the target server",
    )
    .await?
    .trim()
    .to_string();
    let archive = format!("{}/a.tar", staging);
    let result = async {
        crate::sftp_transfer::upload_file(
            std::slice::from_ref(target),
            local_path,
            &archive,
            None,
            cancel,
        )
        .await?;
        run(
            target,
            &install_directory_command(&staging, &archive, src_name, dst_parent, dst_name),
            "Installing on the target server",
        )
        .await
    }
    .await;
    let _ = exec(target, &format!("rm -rf -- {}", quote(&staging))).await;
    result.map(|_| ())
}

/// Extract `archive` (which lives inside `staging`) into `staging/d`, then
/// move `d/src_name` to `dst_parent/dst_name`; when the login user may not
/// write `dst_parent`, copy it there with `sudo -n` instead. An existing
/// destination is refused rather than merged: `cp -R` onto an existing
/// directory would silently nest the copy inside it.
fn install_directory_command(
    staging: &str,
    archive: &str,
    src_name: &str,
    dst_parent: &str,
    dst_name: &str,
) -> String {
    let script = concat!(
        "set -e; ",
        "mkdir \"$1/d\"; ",
        "tar -C \"$1/d\" -xf \"$2\"; ",
        "dest=\"$4/$5\"; ",
        "if [ -e \"$dest\" ] || [ -L \"$dest\" ]; then echo \"$dest already exists\" >&2; exit 1; fi; ",
        "if [ -w \"$4\" ]; then mv -- \"$1/d/$3\" \"$dest\"; ",
        "else sudo -n cp -R -- \"$1/d/$3\" \"$dest\" 2>&1; fi"
    );
    format!(
        "sh -c {} sh {} {} {} {} {}",
        quote(script),
        quote(staging),
        quote(archive),
        quote(src_name),
        quote(dst_parent),
        quote(dst_name),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_remote_handles_root_and_trailing_slash() {
        assert_eq!(split_remote("/etc/ssl/certs/").unwrap(), ("/etc/ssl", "certs"));
        assert_eq!(split_remote("/srv").unwrap(), ("/", "srv"));
        assert!(split_remote("/").is_err());
        assert!(split_remote("relative").is_err());
        assert!(split_remote("/a/..").is_err());
    }

    #[test]
    fn install_directory_command_quotes_every_argument() {
        let cmd = install_directory_command("/tmp/s", "/tmp/s.tar", "my dir", "/opt/a'b", "my dir");
        assert!(cmd.starts_with("sh -c '"));
        assert!(cmd.ends_with(" sh '/tmp/s' '/tmp/s.tar' 'my dir' '/opt/a'\\''b' 'my dir'"));
        assert!(cmd.contains("sudo -n cp -R"));
    }

    #[test]
    fn local_temp_is_removed_on_drop() {
        let temp = LocalTemp::new().unwrap();
        let path = std::path::PathBuf::from(temp.path().unwrap());
        assert!(path.exists());
        drop(temp);
        assert!(!path.exists());
    }
}
