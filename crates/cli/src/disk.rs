//! This device's storage: sealed local state and each vault's frame logs, in
//! `deadbolt-pack` directories.
//!
//! ```text
//! <data>/                       mode 0700
//!   device/                     the device's own directory (a pseudo-vault, id 0)
//!     local-<m>.sealed          seed + metadata, sealed under the device root,
//!                               with the passphrase slot in its header
//!     biometric.slot            the root wrapped under a platform key, beside
//!                               its opaque token; created and deleted whole
//!     activity-<k>.log          sealed Activity rows
//!     LOCK                      held while unlocked
//!   v/<vault>/                  one vault (see `deadbolt_pack`)
//!     members.log, wal-<n>.log  its frames
//!     local-<m>.sealed          this device's state for the vault: parking
//!                               memory, remote config and credentials
//! ```
//!
//! The device root is a random 256-bit key. The passphrase slot wraps it
//! under Argon2id of the passphrase (parameters and salt beside it, bound as
//! AAD), and the biometric slot under a key the Secure Enclave guards. A
//! wrong passphrase fails the slot's AEAD ([`Error::WrongPassphrase`]); no
//! passphrase hash is stored. Changing the passphrase rewrites only the
//! slot. Member frames are plaintext and data frames sealed under epoch
//! keys, both signed, so the logs need no sealing of their own.
//!
//! The root and seed live, while unlocked, in `deadbolt_os::mem::LockedSecret`s:
//! pages of their own, locked in RAM and wiped before they're freed.

mod activity;
mod kdf;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use deadbolt_core::VaultId;
use deadbolt_core::v2::{Frame, LogKind};
use deadbolt_pack::local::{self, LocalState};
use deadbolt_pack::{Blocks, DeviceRoot, FsBlocks, NoopAnchor, VaultDir};
pub use zeroize::Zeroizing;

pub use activity::{Budget, Dropped};
pub use kdf::KdfParams;
use kdf::{KEY_LEN, KdfHeader, SecretKey};

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The passphrase did not open its slot. A tampered slot is
    /// indistinguishable from a wrong passphrase and also lands here.
    #[error("wrong passphrase")]
    WrongPassphrase,
    #[error("biometric unlock is not enrolled or its key was rejected")]
    InvalidBiometric,
    #[error("a store already exists at {}", .0.display())]
    AlreadyExists(PathBuf),
    #[error("no store at {}", .0.display())]
    NotInitialized(PathBuf),
    #[error("store is already open")]
    InUse,
    #[error("store is corrupted or was tampered with: {0}")]
    Corrupt(String),
    #[error("invalid KDF parameters: {0}")]
    InvalidKdfParams(String),
    #[error("system random number generator failed: {0}")]
    Rng(getrandom::Error),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("storage error: {0}")]
    Pack(deadbolt_pack::Error),
    /// A frame append was attempted but not acknowledged: some of the
    /// frames may be durable. Discard derived state and reopen.
    #[error("frame append outcome is uncertain: {0}")]
    AppendUncertain(String),
}

impl From<deadbolt_pack::Error> for Error {
    fn from(error: deadbolt_pack::Error) -> Self {
        match error {
            deadbolt_pack::Error::Locked => Error::InUse,
            deadbolt_pack::Error::Rng(e) => Error::Rng(e),
            e @ (deadbolt_pack::Error::CorruptLocal { .. }
            | deadbolt_pack::Error::CorruptLog { .. }
            | deadbolt_pack::Error::CorruptPack { .. }
            | deadbolt_pack::Error::Decrypt) => Error::Corrupt(e.to_string()),
            e => Error::Pack(e),
        }
    }
}

impl Error {
    /// Safe for operator diagnostics: only the class and I/O kind.
    pub fn append_diagnostic(&self) -> Option<String> {
        match self {
            Self::AppendUncertain(diagnostic) => Some(diagnostic.clone()),
            _ => None,
        }
    }

    pub(crate) fn corrupt(msg: impl Into<String>) -> Self {
        Error::Corrupt(msg.into())
    }
}

const DEVICE: &str = "device";
const VAULTS: &str = "v";
const BIOMETRIC: &str = "biometric.slot";
/// The device directory's local state is bound to this pseudo-vault id.
const NO_VAULT: [u8; 32] = [0; 32];
const SLOT_PASSPHRASE: u8 = 1;
const AAD_PASSPHRASE: &[u8] = b"deadbolt/v2 passphrase slot";
const AAD_BIOMETRIC: &[u8] = b"deadbolt/v2 biometric slot";

#[cfg(unix)]
type LiveKey = deadbolt_os::mem::LockedSecret<KEY_LEN>;
#[cfg(not(unix))]
type LiveKey = Zeroizing<[u8; KEY_LEN]>;

#[cfg(unix)]
fn live_key(key: &[u8; KEY_LEN]) -> LiveKey {
    LiveKey::from_bytes(key)
}
#[cfg(not(unix))]
fn live_key(key: &[u8; KEY_LEN]) -> LiveKey {
    Zeroizing::new(*key)
}

/// Metadata values by name, as sealed in a local state body.
type Meta = BTreeMap<String, Zeroizing<Vec<u8>>>;

fn encode_meta(out: &mut Zeroizing<Vec<u8>>, meta: &Meta) {
    out.extend_from_slice(&(meta.len() as u32).to_be_bytes());
    for (name, value) in meta {
        out.extend_from_slice(&(name.len() as u16).to_be_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
    }
}

fn decode_meta(mut bytes: &[u8]) -> Result<Meta> {
    let corrupt = || Error::corrupt("local state body is malformed");
    let mut take = |n: usize| -> Result<&[u8]> {
        let (head, rest) = bytes.split_at_checked(n).ok_or_else(corrupt)?;
        bytes = rest;
        Ok(head)
    };
    let count = u32::from_be_bytes(take(4)?.try_into().map_err(|_| corrupt())?);
    let mut meta = Meta::new();
    for _ in 0..count {
        let len = u16::from_be_bytes(take(2)?.try_into().map_err(|_| corrupt())?);
        let name = String::from_utf8(take(len.into())?.to_vec()).map_err(|_| corrupt())?;
        let len = u32::from_be_bytes(take(4)?.try_into().map_err(|_| corrupt())?);
        meta.insert(name, Zeroizing::new(take(len as usize)?.to_vec()));
    }
    if !bytes.is_empty() {
        return Err(corrupt());
    }
    Ok(meta)
}

/// The passphrase slot: `1 || kdf header || sealed root`.
fn passphrase_slot(kdf: &KdfHeader, passphrase: &[u8], root: &[u8; KEY_LEN]) -> Result<Vec<u8>> {
    let header = kdf.encode();
    let key = kdf.derive(passphrase)?;
    let sealed = kdf::seal(&key, &[AAD_PASSPHRASE, &header].concat(), root)?;
    Ok([&[SLOT_PASSPHRASE][..], &header, &sealed].concat())
}

fn read_slot(slots: &[u8]) -> Result<(KdfHeader, &[u8])> {
    let (tag, rest) = slots
        .split_first()
        .ok_or_else(|| Error::corrupt("no key slot"))?;
    if *tag != SLOT_PASSPHRASE || rest.len() < kdf::ENCODED_LEN {
        return Err(Error::corrupt("unknown key slot"));
    }
    let (header, sealed) = rest.split_at(kdf::ENCODED_LEN);
    Ok((KdfHeader::decode(header)?, sealed))
}

fn open_slot(slots: &[u8], passphrase: &[u8]) -> Result<SecretKey> {
    let (kdf, sealed) = read_slot(slots)?;
    let key = kdf.derive(passphrase)?;
    kdf::open(&key, &[AAD_PASSPHRASE, &kdf.encode()].concat(), sealed)
        .and_then(|plain| kdf::key_of(&plain))
        .ok_or(Error::WrongPassphrase)
}

fn open_biometric(file: &[u8], key: &[u8; KEY_LEN]) -> Result<SecretKey> {
    let (token, sealed) = split_biometric(file)?;
    kdf::open(key, &[AAD_BIOMETRIC, token].concat(), sealed)
        .and_then(|plain| kdf::key_of(&plain))
        .ok_or(Error::InvalidBiometric)
}

fn split_biometric(file: &[u8]) -> Result<(&[u8], &[u8])> {
    let corrupt = || Error::corrupt("biometric slot is malformed");
    let (len, rest) = file.split_first_chunk::<4>().ok_or_else(corrupt)?;
    rest.split_at_checked(u32::from_be_bytes(*len) as usize)
        .ok_or_else(corrupt)
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)
}

fn device_blocks(dir: &Path) -> Result<FsBlocks> {
    create_private_dir(&dir.join(DEVICE))?;
    Ok(FsBlocks::open(dir.join(DEVICE))?)
}

/// Whether `dir` holds a device.
pub fn is_initialized(dir: &Path) -> bool {
    fs::read_dir(dir.join(DEVICE)).is_ok_and(|entries| {
        entries.flatten().any(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            name.starts_with("local-") && name.ends_with(".sealed")
        })
    })
}

/// Creates a device in `dir` holding `seed`, its root behind `passphrase`.
/// An existing device is never modified.
pub fn init_with_params(
    dir: &Path,
    passphrase: &[u8],
    seed: &[u8; 32],
    params: KdfParams,
) -> Result<Unlocked> {
    params.validate()?;
    create_private_dir(dir)?;
    let (device, _) = VaultDir::open(device_blocks(dir)?)?;
    if local::peek_slots(device.blocks())?.is_some() {
        return Err(Error::AlreadyExists(dir.to_path_buf()));
    }
    let root = kdf::random_key()?;
    let slots = passphrase_slot(&KdfHeader::generate(params)?, passphrase, &root)?;
    let device_root = DeviceRoot::from_bytes(&root);
    let mut body = Zeroizing::new(seed.to_vec());
    encode_meta(&mut body, &Meta::new());
    let state = local::commit(
        device.blocks(),
        &NoopAnchor,
        &NO_VAULT,
        &device_root,
        None,
        &slots,
        &body,
    )?;
    Ok(Unlocked::new(dir, device, &root, seed, state, Meta::new()))
}

/// Opens the device in `dir` with `passphrase`.
pub fn unlock(dir: &Path, passphrase: &[u8]) -> Result<Unlocked> {
    open_with(dir, |device| {
        let slots = local::peek_slots(device.blocks())?
            .ok_or_else(|| Error::NotInitialized(dir.to_path_buf()))?;
        open_slot(&slots, passphrase)
    })
}

/// Opens the device in `dir` with the key the platform released for its
/// biometric slot.
pub fn unlock_biometric(dir: &Path, key: &[u8; KEY_LEN]) -> Result<Unlocked> {
    open_with(dir, |device| {
        let file = match device.blocks().read_all(BIOMETRIC) {
            Ok(file) => file,
            Err(e) if e.is_not_found() => return Err(Error::InvalidBiometric),
            Err(e) => return Err(e.into()),
        };
        open_biometric(&file, key)
    })
}

fn open_with(
    dir: &Path,
    root: impl FnOnce(&VaultDir<FsBlocks>) -> Result<SecretKey>,
) -> Result<Unlocked> {
    if !is_initialized(dir) {
        return Err(Error::NotInitialized(dir.to_path_buf()));
    }
    let (device, _) = VaultDir::open(device_blocks(dir)?)?;
    let root = root(&device)?;
    let state = local::open(
        device.blocks(),
        &NoopAnchor,
        &NO_VAULT,
        &DeviceRoot::from_bytes(&root),
    )?
    .ok_or_else(|| Error::NotInitialized(dir.to_path_buf()))?;
    let (seed, meta) = state
        .body
        .split_first_chunk::<32>()
        .ok_or_else(|| Error::corrupt("local state has no seed"))?;
    let meta = decode_meta(meta)?;
    let seed = Zeroizing::new(*seed);
    Ok(Unlocked::new(dir, device, &root, &seed, state, meta))
}

/// The opaque token enrolled beside the biometric slot, read while locked.
pub fn biometric_token(dir: &Path) -> Result<Option<Vec<u8>>> {
    if !is_initialized(dir) {
        return Err(Error::NotInitialized(dir.to_path_buf()));
    }
    match device_blocks(dir)?.read_all(BIOMETRIC) {
        Ok(file) => Ok(Some(split_biometric(&file)?.0.to_vec())),
        Err(e) if e.is_not_found() => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Removes the biometric slot, locked or not. Returns whether there was one.
pub fn clear_biometric(dir: &Path) -> Result<bool> {
    if !is_initialized(dir) {
        return Err(Error::NotInitialized(dir.to_path_buf()));
    }
    Ok(device_blocks(dir)?.delete(BIOMETRIC)?)
}

/// A fresh 256-bit wrapping key for [`Unlocked::set_biometric`].
pub fn generate_biometric_key() -> Result<SecretKey> {
    kdf::random_key()
}

/// One vault's directory and this device's state for it.
struct Held {
    dir: VaultDir<FsBlocks>,
    local: Option<LocalState>,
    meta: Meta,
}

struct Inner {
    device: VaultDir<FsBlocks>,
    local: LocalState,
    meta: Meta,
    vaults: BTreeMap<VaultId, Held>,
    activity: Option<activity::Index>,
}

/// An open device. Holds the root and seed in locked memory and the device
/// directory's writer lock; dropping it locks the device.
pub struct Unlocked {
    dir: PathBuf,
    root: LiveKey,
    seed: LiveKey,
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for Unlocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Unlocked")
            .field("dir", &self.dir)
            .finish_non_exhaustive()
    }
}

/// A vault's per-device metadata name: `vault/<id>/<rest>`.
fn vault_meta(name: &str) -> Option<(VaultId, &str)> {
    let rest = name.strip_prefix("vault/")?;
    let (id, rest) = rest.split_once('/')?;
    let bytes = data_encoding::HEXLOWER.decode(id.as_bytes()).ok()?;
    Some((VaultId::from_bytes(bytes.try_into().ok()?), rest))
}

impl Unlocked {
    fn new(
        dir: &Path,
        device: VaultDir<FsBlocks>,
        root: &[u8; KEY_LEN],
        seed: &[u8; 32],
        local: LocalState,
        meta: Meta,
    ) -> Self {
        Self {
            dir: dir.to_path_buf(),
            root: live_key(root),
            seed: live_key(seed),
            inner: Mutex::new(Inner {
                device,
                local,
                meta,
                vaults: BTreeMap::new(),
                activity: None,
            }),
        }
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn device_root(&self) -> DeviceRoot {
        DeviceRoot::from_bytes(&self.root)
    }

    /// The seed this device's keys derive from.
    pub fn device_seed(&self) -> &[u8; 32] {
        &self.seed
    }

    fn vault_dir(&self, vault: &VaultId) -> PathBuf {
        self.dir.join(VAULTS).join(vault.to_string())
    }

    /// The vault's directory, opened (and created) on first use.
    fn held<'a>(&self, inner: &'a mut Inner, vault: VaultId) -> Result<&'a mut Held> {
        if !inner.vaults.contains_key(&vault) {
            let path = self.vault_dir(&vault);
            create_private_dir(&path)?;
            let (dir, _) = VaultDir::open(FsBlocks::open(path)?)?;
            let local = local::open(
                dir.blocks(),
                &NoopAnchor,
                vault.as_bytes(),
                &self.device_root(),
            )?;
            let meta = match &local {
                Some(state) => decode_meta(&state.body)?,
                None => Meta::new(),
            };
            inner.vaults.insert(vault, Held { dir, local, meta });
        }
        inner
            .vaults
            .get_mut(&vault)
            .ok_or_else(|| Error::corrupt("vault directory vanished"))
    }

    /// Calls `each` with every stored frame, vault by vault, membership
    /// first. Stops at the first error.
    pub fn for_each_frame(
        &self,
        each: &mut dyn FnMut(VaultId, &[u8]) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let mut ids = Vec::new();
        match fs::read_dir(self.dir.join(VAULTS)) {
            Ok(entries) => {
                for entry in entries {
                    let name = entry?.file_name();
                    let name = name.to_string_lossy();
                    if let Ok(bytes) = data_encoding::HEXLOWER.decode(name.as_bytes())
                        && let Ok(bytes) = <[u8; 32]>::try_from(bytes)
                    {
                        ids.push(VaultId::from_bytes(bytes));
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        ids.sort();
        for id in ids {
            let frames = {
                let mut inner = self.inner();
                let held = self.held(&mut inner, id)?;
                let reader = deadbolt_pack::VaultReader::open(held.dir.blocks())?;
                let mut frames = reader.members()?;
                frames.extend(reader.wal()?);
                frames
            };
            for frame in &frames {
                each(id, frame)?;
            }
        }
        Ok(())
    }

    /// Appends `frames` to `vault`'s logs, each durable before the next.
    /// A crash part way keeps a prefix, every frame of which stands alone.
    pub fn append_frames(&self, vault: VaultId, frames: &mut dyn Iterator<Item = &Frame>) -> Result<()> {
        let mut inner = self.inner();
        let held = self.held(&mut inner, vault)?;
        for frame in frames {
            let bytes = frame.encode();
            let result = match frame.header().kind.log_kind() {
                LogKind::Member => held.dir.append_member(&bytes),
                LogKind::Data => held.dir.append_wal(&bytes),
            };
            result.map_err(|e| {
                Error::AppendUncertain(match &e {
                    deadbolt_pack::Error::Io { source, .. } => {
                        format!("io kind={:?} os={:?}", source.kind(), source.raw_os_error())
                    }
                    _ => "append".into(),
                })
            })?;
        }
        Ok(())
    }

    /// Reads a metadata value.
    pub fn meta_get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let mut inner = self.inner();
        let meta = match vault_meta(name) {
            Some((vault, rest)) => self.held(&mut inner, vault)?.meta.get(rest),
            None => inner.meta.get(name),
        };
        Ok(meta.cloned())
    }

    /// Sets a metadata value, sealing a new local state.
    pub fn meta_set(&self, name: &str, value: &[u8]) -> Result<()> {
        let mut inner = self.inner();
        let root = self.device_root();
        match vault_meta(name) {
            Some((vault, rest)) => {
                let held = self.held(&mut inner, vault)?;
                held.meta.insert(rest.into(), Zeroizing::new(value.to_vec()));
                let mut body = Zeroizing::new(Vec::new());
                encode_meta(&mut body, &held.meta);
                let state = local::commit(
                    held.dir.blocks(),
                    &NoopAnchor,
                    vault.as_bytes(),
                    &root,
                    held.local.as_ref(),
                    &[],
                    &body,
                )?;
                held.local = Some(state);
            }
            None => {
                inner.meta.insert(name.into(), Zeroizing::new(value.to_vec()));
                let slots = inner.local.slots.clone();
                self.commit_device(&mut inner, &slots)?;
            }
        }
        Ok(())
    }

    fn commit_device(&self, inner: &mut Inner, slots: &[u8]) -> Result<()> {
        let mut body = Zeroizing::new(self.seed.to_vec());
        encode_meta(&mut body, &inner.meta);
        inner.local = local::commit(
            inner.device.blocks(),
            &NoopAnchor,
            &NO_VAULT,
            &self.device_root(),
            Some(&inner.local),
            slots,
            &body,
        )?;
        Ok(())
    }

    /// What checks a passphrase against this device without holding it
    /// while the KDF runs.
    pub fn passphrase_check(&self) -> Result<PassphraseCheck> {
        Ok(PassphraseCheck {
            slots: self.inner().local.slots.clone(),
            root: Zeroizing::new(*self.root),
        })
    }

    /// Wraps the root under `key`, beside the opaque platform `token`,
    /// replacing any earlier biometric slot.
    pub fn set_biometric(&self, key: &[u8; KEY_LEN], token: &[u8]) -> Result<()> {
        if token.is_empty() {
            return Err(Error::InvalidBiometric);
        }
        let sealed = kdf::seal(key, &[AAD_BIOMETRIC, token].concat(), self.root.as_ref())?;
        let file = [&(token.len() as u32).to_be_bytes()[..], token, &sealed].concat();
        let inner = self.inner();
        inner.device.blocks().delete(BIOMETRIC)?;
        inner.device.blocks().create_new(BIOMETRIC, &file)?;
        Ok(())
    }

    /// The enrolled biometric token, if any.
    pub fn biometric_token(&self) -> Result<Option<Vec<u8>>> {
        match self.inner().device.blocks().read_all(BIOMETRIC) {
            Ok(file) => Ok(Some(split_biometric(&file)?.0.to_vec())),
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Whether `key` opens the biometric slot, as [`unlock_biometric`]
    /// would, while the device stays open.
    pub fn check_biometric(&self, key: &[u8; KEY_LEN]) -> Result<bool> {
        let file = match self.inner().device.blocks().read_all(BIOMETRIC) {
            Ok(file) => file,
            Err(e) if e.is_not_found() => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        Ok(open_biometric(&file, key).is_ok_and(|root| *root == *self.root))
    }

    /// Removes the biometric slot. Returns whether there was one.
    pub fn clear_biometric(&self) -> Result<bool> {
        Ok(self.inner().device.blocks().delete(BIOMETRIC)?)
    }
}

/// The passphrase slot of an open device, from [`Unlocked::passphrase_check`].
pub struct PassphraseCheck {
    slots: Vec<u8>,
    root: SecretKey,
}

impl PassphraseCheck {
    /// Whether `passphrase` opens the open device's slot. Runs the KDF.
    pub fn matches(&self, passphrase: &[u8]) -> bool {
        open_slot(&self.slots, passphrase).is_ok_and(|root| *root == *self.root)
    }
}

#[cfg(test)]
mod tests;
