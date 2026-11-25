//! `local-<m>.sealed`: the device's own state, one file per commit, plus a
//! two-phase rollback anchor in the OS keystore.
//!
//! ```text
//! file = "DBLS\x02\0\0\0" || m u64_be || prev_mac 24 || slots_len u32_be || slots || nonce 24 || AEAD(K_seal, body)
//! aad  = "deadbolt/v2 local\0" || vault 32 || m u64_be || prev_mac 24 || slots
//! cur_mac = BLAKE3-keyed(K_mac, file)[..24]        K_seal, K_mac = KDF(DeviceRoot)
//! ```
//!
//! `slots` are the plaintext key slots that unwrap `DeviceRoot` (Argon2id,
//! Secure Enclave, PRF, Hello); they're opaque here but bound into the AAD.
//!
//! Commit `s` never renames or overwrites:
//!
//! 1. create-new and sync `local-<s>.sealed`;
//! 2. store `RollbackToken { s, prev_mac, cur_mac }` in the anchor;
//! 3. delete `local-<s-1>.sealed` (best effort).
//!
//! Open takes the newest file that decrypts and checks it against the anchor:
//! the same commit is accepted; the next commit whose `prev_mac` is the
//! anchor's `cur_mac` is a power cut between steps 1 and 2, and the anchor is
//! healed forward; anything else is [`Error::RollbackDetected`].
//!
//! An anchor without a hardware counter can't stop a restore that rolls the
//! disk and the keychain back together (Time Machine). The remote stream
//! comparison and the self-rollback check cover that case.

use std::sync::{Mutex, PoisonError};

use zeroize::Zeroizing;

use crate::blocks::Blocks;
use crate::crypto::{self, KEY_LEN, Key};
use crate::error::{Error, Result};
use crate::names::{LOCAL_PREFIX, LOCAL_SUFFIX, local_sealed, numbered};
use crate::pack::Cursor;

pub const LOCAL_MAGIC: [u8; 8] = *b"DBLS\x02\0\0\0";
const AAD_PREFIX: &[u8] = b"deadbolt/v2 local\0";
pub const MAC_LEN: usize = 24;
pub type Mac = [u8; MAC_LEN];

/// The anchor's record of the newest commit: 56 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RollbackToken {
    pub commit_seq: u64,
    pub prev_mac: Mac,
    pub cur_mac: Mac,
}

impl RollbackToken {
    pub const LEN: usize = 8 + 2 * MAC_LEN;

    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut out = [0; Self::LEN];
        out[..8].copy_from_slice(&self.commit_seq.to_be_bytes());
        out[8..8 + MAC_LEN].copy_from_slice(&self.prev_mac);
        out[8 + MAC_LEN..].copy_from_slice(&self.cur_mac);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::LEN {
            return None;
        }
        let mut cursor = Cursor { bytes };
        Some(Self {
            commit_seq: u64::from_be_bytes(cursor.take()?),
            prev_mac: cursor.take()?,
            cur_mac: cursor.take()?,
        })
    }
}

/// Where the newest [`RollbackToken`] lives: the OS keystore on a device.
pub trait RollbackAnchor {
    fn load(&self) -> Result<Option<RollbackToken>>;
    fn store(&self, token: &RollbackToken) -> Result<()>;
}

impl<A: RollbackAnchor + ?Sized> RollbackAnchor for &A {
    fn load(&self) -> Result<Option<RollbackToken>> {
        (**self).load()
    }

    fn store(&self, token: &RollbackToken) -> Result<()> {
        (**self).store(token)
    }
}

/// No anchor (tests, headless hosts with no keystore): open accepts the
/// newest valid file.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopAnchor;

impl RollbackAnchor for NoopAnchor {
    fn load(&self) -> Result<Option<RollbackToken>> {
        Ok(None)
    }

    fn store(&self, _token: &RollbackToken) -> Result<()> {
        Ok(())
    }
}

/// An in-memory anchor that can fail its next store, for crash tests.
#[derive(Debug, Default)]
pub struct MemAnchor {
    state: Mutex<(Option<RollbackToken>, bool)>,
}

impl MemAnchor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn token(&self) -> Option<RollbackToken> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).0
    }

    pub fn set(&self, token: Option<RollbackToken>) {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).0 = token;
    }

    /// The next [`RollbackAnchor::store`] fails and changes nothing, like a
    /// power cut between commit steps 1 and 2.
    pub fn fail_next_store(&self) {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).1 = true;
    }
}

impl RollbackAnchor for MemAnchor {
    fn load(&self) -> Result<Option<RollbackToken>> {
        Ok(self.token())
    }

    fn store(&self, token: &RollbackToken) -> Result<()> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if std::mem::take(&mut state.1) {
            return Err(Error::Anchor("simulated keystore failure".to_owned()));
        }
        state.0 = Some(*token);
        Ok(())
    }
}

/// The device's root secret, as the two keys local state needs.
pub struct DeviceRoot {
    seal: Key,
    mac: Key,
}

impl DeviceRoot {
    pub fn from_bytes(root: &[u8; KEY_LEN]) -> Self {
        Self {
            seal: crypto::kdf("deadbolt/v2 local seal", &[root]),
            mac: crypto::kdf("deadbolt/v2 local mac", &[root]),
        }
    }
}

/// One opened commit.
pub struct LocalState {
    pub seq: u64,
    pub prev_mac: Mac,
    pub cur_mac: Mac,
    pub slots: Vec<u8>,
    pub body: Zeroizing<Vec<u8>>,
}

impl LocalState {
    pub fn token(&self) -> RollbackToken {
        RollbackToken {
            commit_seq: self.seq,
            prev_mac: self.prev_mac,
            cur_mac: self.cur_mac,
        }
    }
}

fn aad(vault: &[u8; 32], seq: u64, prev_mac: &Mac, slots: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_PREFIX.len() + 32 + 8 + MAC_LEN + slots.len());
    aad.extend_from_slice(AAD_PREFIX);
    aad.extend_from_slice(vault);
    aad.extend_from_slice(&seq.to_be_bytes());
    aad.extend_from_slice(prev_mac);
    aad.extend_from_slice(slots);
    aad
}

fn mac(root: &DeviceRoot, file: &[u8]) -> Mac {
    let hash = crypto::keyed_hash(&root.mac, &[file]);
    let mut out = [0; MAC_LEN];
    out.copy_from_slice(&hash[..MAC_LEN]);
    out
}

/// A commit's file bytes and MAC.
pub fn encode(
    vault: &[u8; 32],
    root: &DeviceRoot,
    seq: u64,
    prev_mac: &Mac,
    slots: &[u8],
    body: &[u8],
) -> Result<(Vec<u8>, Mac)> {
    let slots_len =
        u32::try_from(slots.len()).map_err(|_| Error::InvalidInput("key slots too large"))?;
    let sealed = crypto::seal(&root.seal, &aad(vault, seq, prev_mac, slots), body)?;
    let mut file = Vec::with_capacity(8 + 8 + MAC_LEN + 4 + slots.len() + sealed.len());
    file.extend_from_slice(&LOCAL_MAGIC);
    file.extend_from_slice(&seq.to_be_bytes());
    file.extend_from_slice(prev_mac);
    file.extend_from_slice(&slots_len.to_be_bytes());
    file.extend_from_slice(slots);
    file.extend_from_slice(&sealed);
    let cur_mac = mac(root, &file);
    Ok((file, cur_mac))
}

/// Parses and opens one file that should hold commit `seq`.
pub fn decode(
    name: &str,
    vault: &[u8; 32],
    root: &DeviceRoot,
    seq: u64,
    file: &[u8],
) -> Result<LocalState> {
    let corrupt = |reason| Error::corrupt_local(name, reason);
    let mut cursor = Cursor { bytes: file };
    if cursor.take::<8>() != Some(LOCAL_MAGIC) {
        return Err(corrupt("bad magic"));
    }
    let file_seq = cursor
        .take()
        .map(u64::from_be_bytes)
        .ok_or_else(|| corrupt("short header"))?;
    if file_seq != seq {
        return Err(corrupt("sequence does not match the name"));
    }
    let prev_mac: Mac = cursor.take().ok_or_else(|| corrupt("short header"))?;
    let slots_len = cursor
        .take()
        .map(u32::from_be_bytes)
        .ok_or_else(|| corrupt("short header"))?;
    let slots_len = usize::try_from(slots_len).map_err(|_| corrupt("key slots too large"))?;
    let (slots, sealed) = cursor
        .bytes
        .split_at_checked(slots_len)
        .ok_or_else(|| corrupt("short key slots"))?;
    let body = crypto::open(&root.seal, &aad(vault, seq, &prev_mac, slots), sealed)?;
    Ok(LocalState {
        seq,
        prev_mac,
        cur_mac: mac(root, file),
        slots: slots.to_vec(),
        body,
    })
}

/// Opens the newest local state and checks it against the anchor. The caller
/// is the single writer: once a state is accepted, torn or unreadable files
/// above it and superseded files below it are deleted. `Ok(None)`: no state
/// yet and no anchor.
pub fn open<B: Blocks, A: RollbackAnchor>(
    blocks: &B,
    anchor: &A,
    vault: &[u8; 32],
    root: &DeviceRoot,
) -> Result<Option<LocalState>> {
    let present = numbered(blocks, LOCAL_PREFIX, LOCAL_SUFFIX)?;
    let mut unreadable = Vec::new();
    let mut newest = None;
    for &seq in present.iter().rev() {
        let name = local_sealed(seq);
        let bytes = match blocks.read_all(&name) {
            Ok(bytes) => bytes,
            Err(err) if err.is_not_found() => continue,
            Err(err) => return Err(err),
        };
        match decode(&name, vault, root, seq, &bytes) {
            Ok(state) => {
                newest = Some(state);
                break;
            }
            Err(Error::Decrypt | Error::CorruptLocal { .. }) => unreadable.push(seq),
            Err(err) => return Err(err),
        }
    }
    let Some(disk) = newest else {
        return match anchor.load()? {
            Some(token) => Err(Error::RollbackDetected {
                disk: None,
                anchor: token.commit_seq,
            }),
            // Every file failed: a wrong root, not a reason to delete them.
            None if !unreadable.is_empty() => Err(Error::Decrypt),
            None => Ok(None),
        };
    };
    match anchor.load()? {
        Some(token) if disk.seq == token.commit_seq && disk.cur_mac == token.cur_mac => {}
        Some(token)
            if Some(disk.seq) == token.commit_seq.checked_add(1)
                && disk.prev_mac == token.cur_mac =>
        {
            // Power cut between commit steps 1 and 2: finish step 2.
            anchor.store(&disk.token())?;
        }
        Some(token) => {
            return Err(Error::RollbackDetected {
                disk: Some(disk.seq),
                anchor: token.commit_seq,
            });
        }
        // A fresh keystore (or none): start anchoring from here.
        None => anchor.store(&disk.token())?,
    }
    for seq in unreadable {
        blocks.delete(&local_sealed(seq))?;
    }
    for &seq in present.iter().filter(|&&seq| seq < disk.seq) {
        blocks.delete(&local_sealed(seq))?;
    }
    Ok(Some(disk))
}

/// Commits a new local state after `prev` (`None` for the first). If the
/// anchor fails to store, the error comes back but the new file is on disk;
/// the next [`open`] heals the anchor forward, so reopen before committing
/// again.
pub fn commit<B: Blocks, A: RollbackAnchor>(
    blocks: &B,
    anchor: &A,
    vault: &[u8; 32],
    root: &DeviceRoot,
    prev: Option<&LocalState>,
    slots: &[u8],
    body: &[u8],
) -> Result<LocalState> {
    let (seq, prev_mac) = match prev {
        Some(prev) => (
            prev.seq
                .checked_add(1)
                .ok_or(Error::InvalidInput("commit sequence overflow"))?,
            prev.cur_mac,
        ),
        None => (1, [0; MAC_LEN]),
    };
    let (file, cur_mac) = encode(vault, root, seq, &prev_mac, slots, body)?;
    blocks.create_new(&local_sealed(seq), &file)?;
    let state = LocalState {
        seq,
        prev_mac,
        cur_mac,
        slots: slots.to_vec(),
        body: Zeroizing::new(body.to_vec()),
    };
    anchor.store(&state.token())?;
    // Best effort: open deletes any superseded file this misses.
    let older = numbered(blocks, LOCAL_PREFIX, LOCAL_SUFFIX).unwrap_or_default();
    for old in older.into_iter().filter(|&old| old < seq) {
        if blocks.delete(&local_sealed(old)).is_err() {
            break;
        }
    }
    Ok(state)
}
