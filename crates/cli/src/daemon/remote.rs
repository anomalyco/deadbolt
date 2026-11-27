//! A vault's blind remote (S3/R2/MinIO or WebDAV): its config and
//! credentials, the sync anchor, `remote-sync` ([`sync`]) and zero-state
//! `recover` ([`recover`]).
//!
//! Everything here lives in the vault's own sealed local state
//! (`v/<vault>/local-<m>.sealed`, `vault/<id>/<name>` metadata):
//!
//! ```text
//! vault/<id>/remote   JSON {remote, last_sync}: where, and the credentials
//! vault/<id>/anchor   SyncAnchor: every stream tip this device accepted
//! vault/<id>/proofs   fraud proofs fetched from x/ (engine-owned)
//! ```
//!
//! Credentials arrive in [`Secret`]s, are sealed at rest, and never leave
//! the daemon: [`RemoteInfo`] says only whether one is set.

mod recover;
mod store;
mod sync;
#[cfg(test)]
mod tests;

use anyhow::{Context, Result, bail};
use deadbolt_core::VaultId;
use deadbolt_proto::daemon::{RemoteInfo, RemoteInput, VaultState};
use deadbolt_remote::SyncAnchor;
use serde::{Deserialize, Serialize};

use super::session::{get_json, set_json};
use super::{Daemon, Session};
use crate::protocol::{Command, Reply};

pub(super) use store::Remote;

/// A vault's remote as stored.
#[derive(Serialize, Deserialize)]
pub(super) struct Saved {
    pub remote: RemoteInput,
    #[serde(default)]
    pub last_sync: Option<u64>,
}

fn meta(vault: &VaultId, name: &str) -> String {
    format!("vault/{vault}/{name}")
}

pub(super) fn load(s: &Session, vault: &VaultId) -> Result<Option<Saved>> {
    Ok(get_json::<Option<Saved>>(s.store(), &meta(vault, "remote"))?.flatten())
}

pub(super) fn save(s: &Session, vault: &VaultId, saved: Option<&Saved>) -> Result<()> {
    set_json(s.store(), &meta(vault, "remote"), &saved)
}

pub(super) fn load_anchor(s: &Session, vault: &VaultId) -> Result<SyncAnchor> {
    match s.store().meta_get(&meta(vault, "anchor"))? {
        Some(bytes) if !bytes.is_empty() => {
            SyncAnchor::decode(&bytes).context("reading the sync anchor")
        }
        _ => Ok(SyncAnchor::default()),
    }
}

pub(super) fn save_anchor(s: &Session, vault: &VaultId, anchor: &SyncAnchor) -> Result<()> {
    s.store().meta_set(&meta(vault, "anchor"), &anchor.encode())
}

/// Which store `saved` names (credentials aside).
fn target(
    vault: &VaultId,
    saved: &Saved,
) -> (String, String, Option<String>, Option<String>, String, bool) {
    let i = info(vault, saved, &SyncAnchor::default());
    let path_style = matches!(
        &saved.remote,
        RemoteInput::S3 {
            path_style: true,
            ..
        }
    );
    (i.kind, i.url, i.bucket, i.region, i.prefix, path_style)
}

/// What `remote show` says: where, never the secrets.
pub(super) fn info(vault: &VaultId, saved: &Saved, anchor: &SyncAnchor) -> RemoteInfo {
    let mut info = RemoteInfo {
        vault: vault.to_string(),
        kind: String::new(),
        url: String::new(),
        bucket: None,
        region: None,
        prefix: String::new(),
        username: None,
        credentials: true,
        anchored: anchor.seen.len(),
        last_sync: saved.last_sync,
    };
    match &saved.remote {
        RemoteInput::S3 {
            endpoint,
            bucket,
            region,
            prefix,
            ..
        } => {
            info.kind = "s3".into();
            info.url = endpoint.clone();
            info.bucket = Some(bucket.clone());
            info.region = Some(region.clone());
            info.prefix = prefix.clone();
        }
        RemoteInput::Webdav {
            url,
            username,
            password,
        } => {
            info.kind = "webdav".into();
            info.url = url.clone();
            info.username = username.clone();
            info.credentials = password.is_some();
        }
    }
    info
}

/// A vault's whole state: the engine's, plus its pack and its remote.
pub(super) fn vault_state(s: &Session, vault: &VaultId) -> Result<VaultState> {
    let mut state = s.vault_state(vault);
    state.generation = s.store.pack_generation(*vault)?;
    state.remote = load(s, vault)?
        .map(|saved| info(vault, &saved, &load_anchor(s, vault).unwrap_or_default()));
    Ok(state)
}

impl Daemon {
    pub(super) async fn remote_command(&self, command: Command) -> Result<Reply> {
        match command {
            Command::RemoteSet { vault, remote } => {
                // Refuse a config no request could be made with, before storing it.
                Remote::open(&remote)?;
                self.with(|s| {
                    let id = s.resolve(vault.as_deref())?;
                    let before = load(s, &id)?.map(|old| target(&id, &old));
                    let saved = Saved {
                        remote,
                        last_sync: None,
                    };
                    save(s, &id, Some(&saved))?;
                    // Another store: what this device accepted from the old
                    // one says nothing about it.
                    if before != Some(target(&id, &saved)) {
                        save_anchor(s, &id, &SyncAnchor::default())?;
                    }
                    let info = info(&id, &saved, &load_anchor(s, &id)?);
                    Ok(Reply::Remote { remote: Some(info) })
                })
            }
            Command::RemoteShow { vault } => self.with(|s| {
                let id = s.resolve(vault.as_deref())?;
                let anchor = load_anchor(s, &id)?;
                let remote = load(s, &id)?.map(|saved| info(&id, &saved, &anchor));
                Ok(Reply::Remote { remote })
            }),
            Command::RemoteRemove { vault } => self.with(|s| {
                let id = s.resolve(vault.as_deref())?;
                save(s, &id, None)?;
                save_anchor(s, &id, &SyncAnchor::default())?;
                Ok(Reply::Remote { remote: None })
            }),
            Command::RemoteSync { vault } => {
                let id = self.with(|s| s.resolve(vault.as_deref()))?;
                let report = self.remote_sync(id).await?;
                Ok(Reply::RemoteSynced { report })
            }
            Command::Recover {
                vault,
                words,
                remote,
            } => self.recover(&vault, &words, remote).await,
            _ => bail!("not a remote command"),
        }
    }
}
