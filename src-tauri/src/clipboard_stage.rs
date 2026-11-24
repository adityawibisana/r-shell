//! Local staging for the file browser clipboard.
//!
//! Copy (or cut) in the file browser downloads the selection right away into
//! ONE fixed folder, `<app-data>/clipboard-stage/`. Paste into another
//! connection then only uploads from there, so the source session may be
//! gone by then and the same copy can be pasted many times.
//!
//! There is only ever one staged copy: every new copy cancels a staging still
//! in flight, empties the folder and refills it. The folder is also emptied
//! when the clipboard is cleared, after a cut lands, and on app start/exit, so
//! nothing piles up locally.
//!
//! Selections above [`STAGE_LIMIT_BYTES`] are not staged; the frontend keeps a
//! reference instead and pastes them live through `cross_copy::copy`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::ssh::Client;
use crate::sudo_upload::quote;

type Session = Arc<russh::client::Handle<Client>>;

/// Largest selection staged locally (500 MB).
pub(crate) const STAGE_LIMIT_BYTES: u64 = 500 * 1024 * 1024;

const STAGE_DIR: &str = "clipboard-stage";
const MANIFEST: &str = "manifest.json";

/// The staging in flight, so a newer copy can cancel it.
static RUNNING: Mutex<Option<(u64, CancellationToken)>> = Mutex::new(None);
static GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Serialises filling, pasting from and clearing the folder.
static FOLDER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub(crate) const SUPERSEDED: &str = "Superseded by a newer copy";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct StagedEntry {
    name: String,
    is_directory: bool,
    /// File name inside the stage folder.
    local: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    /// Token of the copy that filled the folder; paste must present it, so a
    /// late-arriving older copy can never be pasted in place of the newer one.
    stage_token: String,
    source_connection_id: String,
    entries: Vec<StagedEntry>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum StageOutcome {
    /// Staged; paste uploads from the local copy.
    Ready { bytes: u64 },
    /// Larger than [`STAGE_LIMIT_BYTES`]; nothing staged.
    TooLarge { bytes: u64 },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StageRequestEntry {
    pub path: String,
    pub is_directory: bool,
}

pub(crate) fn stage_dir(app_data: &Path) -> PathBuf {
    app_data.join(STAGE_DIR)
}

/// Remove the stage folder and everything in it.
pub(crate) fn wipe(dir: &Path) -> Result<()> {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow!("Cannot clear {}: {}", dir.display(), e)),
    }
}

/// Cancel any staging in flight and empty the folder.
pub(crate) async fn clear(dir: &Path) -> Result<()> {
    if let Some((_, token)) = RUNNING.lock().unwrap().take() {
        token.cancel();
    }
    let _folder = FOLDER.lock().await;
    wipe(dir)
}

fn local_name(index: usize, is_directory: bool) -> String {
    format!("{}.{}", index, if is_directory { "tar" } else { "bin" })
}

/// Sum of `du -sk` over `paths`, in bytes.
fn parse_du_total(out: &str) -> Result<u64> {
    let mut total = 0u64;
    for line in out.lines().filter(|l| !l.trim().is_empty()) {
        let kb: u64 = line
            .split_whitespace()
            .next()
            .and_then(|n| n.parse().ok())
            .ok_or_else(|| anyhow!("Unexpected du output: {:?}", line))?;
        total = total.saturating_add(kb.saturating_mul(1024));
    }
    Ok(total)
}

async fn remote_size(source: &Session, entries: &[StageRequestEntry]) -> Result<u64> {
    let args: Vec<String> = entries.iter().map(|e| quote(&e.path)).collect();
    let out = crate::cross_copy::run(
        source,
        &format!("du -sk -- {}", args.join(" ")),
        "Measuring the selection",
    )
    .await?;
    parse_du_total(&out)
}

fn path_str(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| anyhow!("Path is not valid UTF-8: {}", path.display()))
}

/// Replace the staged copy with `entries` downloaded from `source`.
pub(crate) async fn stage(
    dir: &Path,
    source: &Session,
    source_connection_id: &str,
    stage_token: &str,
    entries: &[StageRequestEntry],
) -> Result<StageOutcome> {
    let generation = GENERATION.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
    let token = CancellationToken::new();
    if let Some((_, old)) = RUNNING.lock().unwrap().replace((generation, token.clone())) {
        old.cancel();
    }

    let result = async {
        let _folder = FOLDER.lock().await;
        wipe(dir)?;
        if token.is_cancelled() {
            return Err(anyhow!(SUPERSEDED));
        }
        let bytes = remote_size(source, entries).await?;
        if bytes > STAGE_LIMIT_BYTES {
            return Ok(StageOutcome::TooLarge { bytes });
        }
        std::fs::create_dir_all(dir)?;
        let filled = fill(dir, source, source_connection_id, stage_token, entries, &token).await;
        match filled {
            Ok(bytes) => Ok(StageOutcome::Ready { bytes }),
            Err(e) => {
                let _ = wipe(dir);
                Err(if token.is_cancelled() { anyhow!(SUPERSEDED) } else { e })
            }
        }
    }
    .await;

    let mut running = RUNNING.lock().unwrap();
    if matches!(&*running, Some((g, _)) if *g == generation) {
        *running = None;
    }
    result
}

async fn fill(
    dir: &Path,
    source: &Session,
    source_connection_id: &str,
    stage_token: &str,
    entries: &[StageRequestEntry],
    cancel: &CancellationToken,
) -> Result<u64> {
    let mut staged = Vec::with_capacity(entries.len());
    let mut bytes = 0u64;
    for (index, entry) in entries.iter().enumerate() {
        let (_, name) = crate::cross_copy::split_remote(&entry.path)?;
        let local = local_name(index, entry.is_directory);
        let local_path = dir.join(&local);
        let local_path = path_str(&local_path)?;
        bytes += if entry.is_directory {
            crate::cross_copy::download_directory_archive(source, &entry.path, local_path, cancel)
                .await?
        } else {
            crate::sftp_transfer::download_file(
                std::slice::from_ref(source),
                &entry.path,
                local_path,
                None,
                cancel,
            )
            .await?
        };
        staged.push(StagedEntry {
            name: name.to_string(),
            is_directory: entry.is_directory,
            local,
        });
    }
    let manifest = Manifest {
        stage_token: stage_token.to_string(),
        source_connection_id: source_connection_id.to_string(),
        entries: staged,
    };
    std::fs::write(dir.join(MANIFEST), serde_json::to_vec(&manifest)?)?;
    Ok(bytes)
}

fn read_manifest(dir: &Path) -> Result<Manifest> {
    let raw = std::fs::read(dir.join(MANIFEST))
        .map_err(|_| anyhow!("Nothing is staged on the clipboard"))?;
    Ok(serde_json::from_slice(&raw)?)
}

fn join_remote(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        format!("{}{}", dir, name)
    } else {
        format!("{}/{}", dir, name)
    }
}

/// Upload the staged copy into `target_dir` on `target`. The stage stays, so
/// it can be pasted again.
pub(crate) async fn paste(
    dir: &Path,
    stage_token: &str,
    target: &Session,
    target_dir: &str,
) -> Result<u64> {
    let _folder = FOLDER.lock().await;
    let manifest = read_manifest(dir)?;
    if manifest.stage_token != stage_token {
        return Err(anyhow!("The staged clipboard was replaced by another copy"));
    }
    let cancel = CancellationToken::new();
    let mut bytes = 0u64;
    for entry in &manifest.entries {
        let local_path = dir.join(&entry.local);
        let local_path = path_str(&local_path)?;
        let dest = join_remote(target_dir, &entry.name);
        if entry.is_directory {
            crate::cross_copy::upload_directory_archive(
                target,
                local_path,
                &entry.name,
                &dest,
                &cancel,
            )
            .await?;
            bytes += std::fs::metadata(local_path).map(|m| m.len()).unwrap_or(0);
        } else {
            bytes += crate::sudo_upload::upload_file(
                std::slice::from_ref(target),
                local_path,
                &dest,
                None,
                &cancel,
            )
            .await?;
        }
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn du_total_sums_every_line_in_bytes() {
        assert_eq!(parse_du_total("4\t/a\n12\t/b dir\n").unwrap(), 16 * 1024);
        assert_eq!(parse_du_total("").unwrap(), 0);
        assert!(parse_du_total("du: cannot access\n").is_err());
    }

    #[test]
    fn limit_is_500_mb() {
        assert_eq!(STAGE_LIMIT_BYTES, 524_288_000);
    }

    #[test]
    fn manifest_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = Manifest {
            stage_token: "t1".into(),
            source_connection_id: "c1".into(),
            entries: vec![StagedEntry {
                name: "my dir".into(),
                is_directory: true,
                local: local_name(0, true),
            }],
        };
        std::fs::write(tmp.path().join(MANIFEST), serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert_eq!(read_manifest(tmp.path()).unwrap(), manifest);
        assert_eq!(manifest.entries[0].local, "0.tar");
    }

    #[test]
    fn missing_manifest_reports_nothing_staged() {
        let tmp = tempfile::tempdir().unwrap();
        let err = read_manifest(tmp.path()).unwrap_err().to_string();
        assert!(err.contains("Nothing is staged"));
    }

    #[tokio::test]
    async fn clear_removes_the_previous_copy_and_tolerates_absence() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = stage_dir(tmp.path());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("0.bin"), b"old").unwrap();
        std::fs::write(dir.join(MANIFEST), b"{}").unwrap();
        clear(&dir).await.unwrap();
        assert!(!dir.exists());
        clear(&dir).await.unwrap();
    }

    #[tokio::test]
    async fn clear_cancels_a_staging_in_flight() {
        let token = CancellationToken::new();
        *RUNNING.lock().unwrap() = Some((u64::MAX, token.clone()));
        let tmp = tempfile::tempdir().unwrap();
        clear(&stage_dir(tmp.path())).await.unwrap();
        assert!(token.is_cancelled());
        assert!(RUNNING.lock().unwrap().is_none());
    }

    #[test]
    fn join_remote_handles_root() {
        assert_eq!(join_remote("/", "a"), "/a");
        assert_eq!(join_remote("/srv", "a"), "/srv/a");
    }
}
