//! Upload into directories the login user cannot write.
//!
//! Key-based logins (an EC2 `.pem`, often with an authenticator code on top)
//! usually land as an unprivileged user with passwordless sudo, so dropping a
//! certificate into `/etc/ssl` or `/etc/nginx` fails with SFTP
//! `PERMISSION_DENIED`. When that happens the upload is retried as: stream
//! into a private temp file the user owns, then `sudo -n cp` it into place
//! on the same already-authenticated session — no second login, so the key
//! and the one-time code are not needed again.
//!
//! `sudo -n` never prompts: a server that needs a sudo password fails fast
//! with a clear error instead of hanging the transfer.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use russh::ChannelMsg;
use tokio_util::sync::CancellationToken;

use crate::sftp_transfer::{self, ProgressCallback, RemoteCreateDenied};
use crate::ssh::Client;

/// Deadline for the helper commands (`mktemp`, `sudo cp`). The copy is
/// server-local, so even a large file finishes well inside this.
const HELPER_TIMEOUT: Duration = Duration::from_secs(120);

/// Cap on helper output kept for error messages.
const MAX_HELPER_OUTPUT: usize = 64 * 1024;

/// [`sftp_transfer::upload_file`], retried through `sudo` when the server
/// refuses to create `remote_path`.
pub(crate) async fn upload_file(
    sessions: &[Arc<russh::client::Handle<Client>>],
    local_path: &str,
    remote_path: &str,
    progress: ProgressCallback<'_>,
    cancel: &CancellationToken,
) -> Result<u64> {
    let denied = match sftp_transfer::upload_file(sessions, local_path, remote_path, progress, cancel)
        .await
    {
        Err(e) if e.downcast_ref::<RemoteCreateDenied>().is_some() => e,
        other => return other,
    };
    let session = &sessions[0];

    // mktemp creates the file 0600 and owned by the login user, so nobody
    // else can swap it out between the upload and the copy.
    let (code, out) = exec(session, "mktemp /tmp/.rshell-upload.XXXXXXXXXX").await?;
    let temp = out.trim().to_string();
    if code != 0 || temp.is_empty() || temp.contains('\n') {
        return Err(denied);
    }

    let uploaded =
        sftp_transfer::upload_file(sessions, local_path, &temp, progress, cancel).await;
    let bytes = match uploaded {
        Ok(bytes) => bytes,
        Err(e) => {
            let _ = exec(session, &format!("rm -f -- {}", quote(&temp))).await;
            return Err(e);
        }
    };

    let (code, out) = exec(session, &install_command(&temp, remote_path)).await?;
    if code == 0 {
        tracing::info!(remote_path, "upload installed with sudo after permission denied");
        return Ok(bytes);
    }
    Err(sudo_failure(remote_path, &out))
}

/// Copy the temp file over `dest` as root, then remove the temp file as the
/// login user. `cp` writes into an existing `dest`, so a replaced file keeps
/// its owner and mode; a new file gets 0644, like a normal SFTP upload under
/// the usual umask. Runs under `sh` so a fish or csh login shell does not
/// matter.
fn install_command(temp: &str, dest: &str) -> String {
    format!(
        "sh -c {} sh {} {}",
        quote(
            "chmod 644 \"$1\" && sudo -n cp -- \"$1\" \"$2\" 2>&1; rc=$?; rm -f -- \"$1\"; exit $rc"
        ),
        quote(temp),
        quote(dest),
    )
}

fn sudo_failure(remote_path: &str, output: &str) -> anyhow::Error {
    let output = output.trim();
    if output.contains("password is required") || output.contains("a terminal is required") {
        anyhow!(
            "Permission denied writing '{}'. The login user cannot write there and sudo needs a \
             password on this server, so the file could not be installed as root. Upload to a \
             writable folder and move it with sudo in the terminal.",
            remote_path
        )
    } else if output.is_empty() {
        anyhow!("Permission denied writing '{}', and sudo cp failed.", remote_path)
    } else {
        anyhow!(
            "Permission denied writing '{}', and sudo cp failed: {}",
            remote_path,
            output
        )
    }
}

/// Wrap `s` as one POSIX single-quoted shell word.
pub(crate) fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Run `command` on `session`, returning its exit code and combined output.
pub(crate) async fn exec(session: &russh::client::Handle<Client>, command: &str) -> Result<(u32, String)> {
    let mut channel = session.channel_open_session().await?;
    channel.exec(true, command).await?;
    let mut output = Vec::new();
    let mut code = None;
    let exchange = async {
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { ref data } | ChannelMsg::ExtendedData { ref data, .. } => {
                    if output.len() < MAX_HELPER_OUTPUT {
                        output.extend_from_slice(data);
                    }
                }
                ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
    };
    let timed_out = tokio::time::timeout(HELPER_TIMEOUT, exchange).await.is_err();
    crate::ssh::bounded_channel_close(&channel).await;
    if timed_out {
        return Err(anyhow!("Command timed out: {}", command));
    }
    Ok((code.unwrap_or(1), String::from_utf8_lossy(&output).into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_escapes_single_quotes() {
        assert_eq!(quote("a'b"), "'a'\\''b'");
        assert_eq!(quote("/etc/ssl/my cert.crt"), "'/etc/ssl/my cert.crt'");
    }

    #[test]
    fn install_command_passes_paths_as_arguments() {
        let cmd = install_command("/tmp/.rshell-upload.abc", "/etc/ssl/it's.crt");
        assert!(cmd.starts_with("sh -c '"));
        assert!(cmd.contains("sudo -n cp -- \"$1\" \"$2\""));
        assert!(cmd.ends_with(" sh '/tmp/.rshell-upload.abc' '/etc/ssl/it'\\''s.crt'"));
    }

    #[test]
    fn sudo_password_prompt_gets_a_clear_message() {
        let e = sudo_failure("/etc/ssl/x.crt", "sudo: a password is required\n");
        assert!(e.to_string().contains("sudo needs a password"));
        let e = sudo_failure("/etc/ssl/x.crt", "cp: cannot stat: No such file");
        assert!(e.to_string().contains("cp: cannot stat"));
    }
}
