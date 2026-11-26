//! A vault's blind remote (S3/R2 or WebDAV), its sync report, and what the
//! daemon says about a vault beyond [`super::VaultInfo`]: why it is parked.
//!
//! Credentials go to the daemon in [`Secret`]s and never come back:
//! [`RemoteInfo`] says only whether one is set.

use serde::{Deserialize, Serialize};

use super::{Secret, VaultInfo};

/// A remote as a client sets it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum RemoteInput {
    /// S3, R2 or MinIO, signed with SigV4.
    S3 {
        /// `https://<account>.r2.cloudflarestorage.com`, `https://s3.<region>.amazonaws.com`.
        endpoint: String,
        bucket: String,
        region: String,
        /// Lowercase `[0-9a-z._/-]` ending in `/`, or empty.
        #[serde(default)]
        prefix: String,
        /// Path-style addressing (`<endpoint>/<bucket>/<key>`), as R2 and
        /// MinIO want; virtual-hosted otherwise.
        #[serde(default)]
        path_style: bool,
        access_key_id: Secret,
        secret_access_key: Secret,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_token: Option<Secret>,
    },
    /// A WebDAV collection, its URL ending in `/`.
    Webdav {
        url: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        password: Option<Secret>,
    },
}

/// A vault's remote as the daemon shows it: where, never the secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteInfo {
    pub vault: String,
    /// `s3` or `webdav`.
    pub kind: String,
    /// The endpoint or collection URL.
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default)]
    pub prefix: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Whether a credential is stored (always redacted).
    pub credentials: bool,
    /// Streams the sync anchor holds: what this device has accepted.
    pub anchored: usize,
    /// Unix seconds of the last sync that finished.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sync: Option<u64>,
}

/// What one `remote-sync` did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteReport {
    pub vault: String,
    /// Frames fetched and applied.
    pub pulled: usize,
    /// Objects the push stored (frames, packs, proofs).
    pub pushed: usize,
    /// Fraud proofs fetched.
    pub proofs: usize,
    /// Checkpoints whose packs were fetched and adopted.
    pub checkpoints: usize,
    /// Remote objects garbage-collected behind a checkpoint.
    pub collected: usize,
    /// What the store did that an honest one never does, one line each.
    pub anomalies: Vec<String>,
}

/// One vault's state beyond its [`VaultInfo`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultState {
    pub vault: VaultInfo,
    /// Why this device won't write here; empty when it will.
    /// `vault confirm-reinstated` or the recovery kit settles each.
    pub parked: Vec<ParkedReason>,
    /// Data frames held that no reachable key opens yet.
    pub sealed: usize,
    /// The generation of the newest local checkpoint pack, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<RemoteInfo>,
}

/// Why a vault is parked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParkedReason {
    /// `reinstated`, `mutual-removal` or `recovery-frozen`.
    pub kind: String,
    /// The devices it concerns (ids).
    pub devices: Vec<String>,
    /// One line for a person.
    pub message: String,
}
