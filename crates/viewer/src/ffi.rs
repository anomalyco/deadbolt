//! The UniFFI surface the iOS Credential Provider extension calls.
//!
//! Swift reads the bundle from the Keychain, opens a [`ViewerHandle`] on the
//! App Group's vault directory, and asks it for hits and fills. Secrets cross
//! to Swift only through [`ViewerSecret`]'s getters, one value per call, so
//! nothing is copied out that the fill doesn't use.

use std::path::PathBuf;
use std::sync::Arc;

use deadbolt_pack::FsBlocks;
use deadbolt_pack::blocks::FsReader;
use zeroize::Zeroizing;

use crate::bundle::ViewerKeyBundle;
use crate::error::Result;
use crate::item::{ViewerHit, ViewerSecret};
use crate::outbox::{OutboxMutation, queue_save};
use crate::reader::PackViewer;

/// A login the user chose to save from the extension. Swift's copy of the
/// password is its own; the viewer moves it into wiped memory at once.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct OutboxLogin {
    pub url: String,
    pub username: String,
    pub password: String,
    #[uniffi(default = None)]
    pub title: Option<String>,
}

impl std::fmt::Debug for OutboxLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboxLogin")
            .field("url", &self.url)
            .field("username", &self.username)
            .field("title", &self.title)
            .finish_non_exhaustive()
    }
}

/// One pack generation, open in the extension.
#[derive(uniffi::Object)]
pub struct ViewerHandle {
    viewer: PackViewer<FsReader>,
    dir: PathBuf,
}

#[uniffi::export]
impl ViewerHandle {
    /// Opens the vault directory `vault_dir` with the Keychain bundle's bytes.
    #[uniffi::constructor]
    pub fn open(vault_dir: String, bundle: Vec<u8>, now_unix: u64) -> Result<Arc<Self>> {
        let bundle = Zeroizing::new(bundle);
        let bundle = ViewerKeyBundle::decode(&bundle)?;
        let dir = PathBuf::from(vault_dir);
        let viewer = PackViewer::open_dir(&dir, &bundle, now_unix)?;
        Ok(Arc::new(Self { viewer, dir }))
    }

    pub fn generation(&self) -> u64 {
        self.viewer.generation()
    }

    pub fn item_count(&self) -> u64 {
        self.viewer.item_count() as u64
    }

    /// Logins and passkeys on the site of a URL, host or domain.
    pub fn lookup_site(&self, query: String) -> Result<Vec<ViewerHit>> {
        self.viewer.lookup_site(&query)
    }

    /// Passkeys for one relying party id.
    pub fn lookup_rp(&self, rp_id: String) -> Result<Vec<ViewerHit>> {
        self.viewer.lookup_rp(&rp_id)
    }

    /// One item's Head, by its 32-hex-digit id (an `ASCredentialIdentity`'s
    /// record identifier).
    pub fn lookup_item(&self, item_id: String) -> Result<Option<ViewerHit>> {
        self.viewer.lookup_item(&item_id)
    }

    /// One item's secrets, after checking its Head is live and autofillable.
    pub fn fill_secret(&self, item_id: String) -> Result<Arc<ViewerSecret>> {
        self.viewer.fill_secret(&item_id).map(Arc::new)
    }

    /// Queues a login at Unix milliseconds `now_ms`. Returns the entry's name.
    pub fn queue_login(&self, login: OutboxLogin, now_ms: u64) -> Result<String> {
        let OutboxLogin {
            url,
            username,
            password,
            title,
        } = login;
        self.queue(
            &OutboxMutation::SaveLogin {
                url,
                username,
                password: Zeroizing::new(password),
                title,
            },
            now_ms,
        )
    }

    /// Records that an item was filled, for the app's "last used".
    pub fn touch_used(&self, item_id: String, used_unix: u64, now_ms: u64) -> Result<String> {
        crate::item::parse_item_id(&item_id)?;
        self.queue(&OutboxMutation::TouchUsed { item_id, used_unix }, now_ms)
    }
}

impl ViewerHandle {
    fn queue(&self, mutation: &OutboxMutation, now_ms: u64) -> Result<String> {
        let blocks = FsBlocks::open(&self.dir)?;
        let kem = deadbolt_core::v2::KemPublic::from_bytes(*self.viewer.device_kem());
        queue_save(&blocks, self.viewer.vault(), &kem, mutation, now_ms)
    }
}

#[uniffi::export]
impl ViewerSecret {
    pub fn item_id(&self) -> String {
        self.item_id.clone()
    }

    pub fn password(&self) -> Option<String> {
        self.password.as_ref().map(|p| p.to_string())
    }

    pub fn has_passkey(&self) -> bool {
        self.passkey.is_some()
    }

    pub fn passkey_credential_id(&self) -> Option<String> {
        self.passkey.as_ref().map(|p| p.credential_id.clone())
    }

    pub fn passkey_user_handle(&self) -> Option<String> {
        self.passkey.as_ref().map(|p| p.user_handle.clone())
    }

    /// Base64url PKCS#8 of the passkey's P-256 key.
    pub fn passkey_private_key(&self) -> Option<String> {
        self.passkey.as_ref().map(|p| p.private_key.to_string())
    }
}

/// Whether the Keychain bundle's bytes are malformed or past their expiry,
/// so Swift can ask the user to open the app before it shows a picker.
#[uniffi::export]
pub fn viewer_bundle_usable(bundle: Vec<u8>, now_unix: u64) -> bool {
    let bundle = Zeroizing::new(bundle);
    ViewerKeyBundle::decode(&bundle).is_ok_and(|bundle| !bundle.is_expired(now_unix))
}
