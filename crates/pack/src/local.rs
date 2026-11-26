//! `local-<m>.sealed`: the device's own state, one file per commit, plus a
//! two-phase rollback anchor in the OS keystore.
//!
//! ```text
//! file = "DBLS\x02\0\0\0" || m u64_be || prev_mac 24 || slots_len u32_be || slots
//!        || sealed_len u32_be || sealed            sealed = nonce 24 || AEAD(K_seal, body)
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
//! Every length is explicit, so a file cut short anywhere (the ciphertext
//! included) is [`Error::CorruptLocal`], never [`Error::Decrypt`]: a torn
//! step 1 is told apart from a wrong root. With nothing anchored yet, torn
//! files alone are a first commit that never finished, and open clears them
//! so the next commit can take their names.
//!
//! An anchor without a hardware counter can't stop a restore that rolls the
//! disk and the keychain back together (Time Machine). The remote stream
//! comparison and the self-rollback check cover that case.

use std::cmp::Ordering;
use std::sync::{Mutex, PoisonError};

use zeroize::Zeroizing;

use crate::blocks::Blocks;
use crate::crypto::{self, KEY_LEN, Key, SEAL_OVERHEAD};
use crate::error::{Error, Result};
use crate::names::{LOCAL_PREFIX, LOCAL_SUFFIX, local_sealed, numbered};
use crate::pack::Cursor;

pub const LOCAL_MAGIC: [u8; 8] = *b"DBLS\x02\0\0\0";
const AAD_PREFIX: &[u8] = b"deadbolt/v2 local\0";
pub const MAC_LEN: usize = 24;
pub type Mac = [u8; MAC_LEN];
/// Magic, sequence, `prev_mac` and the key slots' length.
const HEADER_LEN: usize = 8 + 8 + MAC_LEN + 4;

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
    let sealed_len =
        u32::try_from(sealed.len()).map_err(|_| Error::InvalidInput("local state too large"))?;
    let mut file = Vec::with_capacity(HEADER_LEN + slots.len() + 4 + sealed.len());
    file.extend_from_slice(&LOCAL_MAGIC);
    file.extend_from_slice(&seq.to_be_bytes());
    file.extend_from_slice(prev_mac);
    file.extend_from_slice(&slots_len.to_be_bytes());
    file.extend_from_slice(slots);
    file.extend_from_slice(&sealed_len.to_be_bytes());
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
    let (slots, rest) = cursor
        .bytes
        .split_at_checked(slots_len)
        .ok_or_else(|| corrupt("short key slots"))?;
    let mut cursor = Cursor { bytes: rest };
    let sealed_len = cursor
        .take()
        .map(u32::from_be_bytes)
        .ok_or_else(|| corrupt("short sealed length"))?;
    let sealed = cursor.bytes;
    match usize::try_from(sealed_len).map(|len| len.cmp(&sealed.len())) {
        Ok(Ordering::Equal) => {}
        Ok(Ordering::Greater) | Err(_) => return Err(corrupt("short sealed body")),
        Ok(Ordering::Less) => return Err(corrupt("bytes after the sealed body")),
    }
    if sealed.len() < SEAL_OVERHEAD {
        return Err(corrupt("sealed body too short"));
    }
    // Every byte is present: from here a failure is a wrong key or tampering.
    let body = crypto::open(&root.seal, &aad(vault, seq, &prev_mac, slots), sealed)?;
    Ok(LocalState {
        seq,
        prev_mac,
        cur_mac: mac(root, file),
        slots: slots.to_vec(),
        body,
    })
}

/// Whether `file` is a strict prefix of a commit-`seq` file: what a power
/// cut during commit step 1 leaves behind.
fn is_torn(seq: u64, file: &[u8]) -> bool {
    let fixed = [LOCAL_MAGIC.as_slice(), &seq.to_be_bytes()].concat();
    if !fixed.starts_with(&file[..file.len().min(fixed.len())]) {
        return false;
    }
    let full_len = (|| {
        let slots_len = u32::from_be_bytes(file.get(HEADER_LEN - 4..HEADER_LEN)?.try_into().ok()?);
        let at = HEADER_LEN.checked_add(usize::try_from(slots_len).ok()?)?;
        let sealed_len = u32::from_be_bytes(file.get(at..at.checked_add(4)?)?.try_into().ok()?);
        at.checked_add(4)?
            .checked_add(usize::try_from(sealed_len).ok()?)
    })();
    full_len.is_none_or(|len| file.len() < len)
}

/// The key slots of the newest complete local state, read without any key:
/// what a passphrase or platform key unwraps the root from before [`open`].
/// `None` when no file holds a complete slot section.
pub fn peek_slots<B: Blocks>(blocks: &B) -> Result<Option<Vec<u8>>> {
    for seq in numbered(blocks, LOCAL_PREFIX, LOCAL_SUFFIX)?
        .into_iter()
        .rev()
    {
        let bytes = match blocks.read_all(&local_sealed(seq)) {
            Ok(bytes) => bytes,
            Err(err) if err.is_not_found() => continue,
            Err(err) => return Err(err),
        };
        if is_torn(seq, &bytes) {
            continue;
        }
        let slots = (|| {
            let len = u32::from_be_bytes(bytes.get(HEADER_LEN - 4..HEADER_LEN)?.try_into().ok()?);
            bytes.get(HEADER_LEN..HEADER_LEN.checked_add(usize::try_from(len).ok()?)?)
        })();
        if let Some(slots) = slots {
            return Ok(Some(slots.to_vec()));
        }
    }
    Ok(None)
}

/// Opens the newest local state and checks it against the anchor. The caller
/// is the single writer: once a state is accepted, torn or unreadable files
/// above it and superseded files below it are deleted.
///
/// With no state on disk and nothing anchored: `Ok(None)` when there are no
/// files, or only torn ones (a first commit cut short, deleted here so the
/// next commit succeeds); [`Error::Decrypt`] when a complete file fails
/// authentication (a wrong root), and [`Error::CorruptLocal`] for any other
/// damaged file, both leaving every file in place.
pub fn open<B: Blocks, A: RollbackAnchor>(
    blocks: &B,
    anchor: &A,
    vault: &[u8; 32],
    root: &DeviceRoot,
) -> Result<Option<LocalState>> {
    let present = numbered(blocks, LOCAL_PREFIX, LOCAL_SUFFIX)?;
    let mut torn = Vec::new();
    let mut unreadable = Vec::new();
    let mut failure = None;
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
            Err(Error::CorruptLocal { .. }) if is_torn(seq, &bytes) => torn.push(seq),
            Err(err @ (Error::Decrypt | Error::CorruptLocal { .. })) => {
                unreadable.push(seq);
                // A wrong root explains every file; report it first.
                if !matches!(failure, Some(Error::Decrypt)) {
                    failure = Some(err);
                }
            }
            Err(err) => return Err(err),
        }
    }
    let Some(disk) = newest else {
        return match (anchor.load()?, failure) {
            (Some(token), _) => Err(Error::RollbackDetected {
                disk: None,
                anchor: token.commit_seq,
            }),
            // A complete file that won't open: never a reason to delete it.
            (None, Some(err)) => Err(err),
            (None, None) => {
                for seq in torn {
                    blocks.delete(&local_sealed(seq))?;
                }
                Ok(None)
            }
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
    for seq in torn.into_iter().chain(unreadable) {
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
