//! DELETABLE(v1-migrate): remove once existing v1 users have migrated to v2.
//!
//! The v1 `store.redb`, read only: its header, its sealed log of signed
//! entries and the few metadata values a migration carries over.
//!
//! ```text
//! header  "format"   u32 LE, 2
//!         "kdf"      alg(1) = 1 (Argon2id v1.3) || m_cost_kib || t_cost || p_cost (u32 LE) || salt(16)
//!         "keyset"   AEAD(Argon2id(passphrase), data key(32) || device secret(32)),
//!                    aad "deadbolt-store/v1/keyset" || format || kdf
//!         "log_len"  AEAD(data, entry count u64 LE), aad "deadbolt-store/v1/log-len"
//! log     seq u64 -> AEAD(data, entry), aad "deadbolt-store/v1/log" || seq (u64 BE)
//! meta    keyed-hash(meta key, name) -> AEAD(data, value), aad "deadbolt-store/v1/meta" || hash
//! ```
//!
//! AEAD is XChaCha20-Poly1305, `nonce(24) || ciphertext || tag(16)`; the data
//! and meta keys are BLAKE3 subkeys of the data key.
//!
//! redb never opens the file itself: it is copied, under a shared lock a
//! live v1 process would refuse, and redb opens (and, after an unclean
//! shutdown, repairs) the copy.

use std::fs::File;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::{AeadInOut, KeyInit, XChaCha20Poly1305};
use redb::{ReadableDatabase, TableDefinition};
use zeroize::Zeroizing;

const HEADER: TableDefinition<&str, &[u8]> = TableDefinition::new("header");
const LOG: TableDefinition<u64, &[u8]> = TableDefinition::new("log");
const META: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("meta");

const FORMAT_VERSION: u32 = 2;
const AAD_KEYSET: &[u8] = b"deadbolt-store/v1/keyset";
const AAD_LOG: &[u8] = b"deadbolt-store/v1/log";
const AAD_LOG_LEN: &[u8] = b"deadbolt-store/v1/log-len";
const AAD_META: &[u8] = b"deadbolt-store/v1/meta";
const CTX_DATA: &str = "deadbolt-store v1 2026-10-15 data encryption";
const CTX_META_INDEX: &str = "deadbolt-store v1 2026-10-15 meta key blinding";

const KDF_LEN: usize = 29;
const ALG_ARGON2ID_V13: u8 = 1;
// The bounds v1 checked every header against: 4x memory, 8x passes and
// 8x work over its 64 MiB, 3-pass default.
const MAX_M_COST_KIB: u32 = 4 * 64 * 1024;
const MAX_T_COST: u32 = 8 * 3;
const MAX_P_COST: u32 = 64;
const MAX_WORK_KIB: u64 = 8 * 64 * 1024 * 3;

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

const META_DEVICE_NAME: &str = "cli/device-name";
const META_DEFAULT_VAULT: &str = "cli/default-vault";

/// What an unlocked v1 store holds that a migration needs.
pub(super) struct V1Store {
    /// Every signed entry, in append order.
    pub entries: Vec<Zeroizing<Vec<u8>>>,
    pub device_name: Option<String>,
    /// The default vault's id, in hex.
    pub default_vault: Option<String>,
}

/// Reads the store at `path` with `passphrase`, through a copy at `copy`
/// (removed again). A wrong passphrase fails as
/// [`crate::disk::Error::WrongPassphrase`].
pub(super) fn read(path: &Path, copy: &Path, passphrase: &[u8]) -> Result<V1Store> {
    {
        let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        file.try_lock_shared().map_err(|_| {
            anyhow!(
                "{} is open in another Deadbolt: quit it and try again",
                path.display()
            )
        })?;
        std::fs::copy(path, copy).with_context(|| format!("copying {}", path.display()))?;
    }
    let read = read_copy(copy, passphrase);
    if let Err(error) = std::fs::remove_file(copy) {
        tracing::warn!("removing {}: {error}", copy.display());
    }
    read
}

fn read_copy(copy: &Path, passphrase: &[u8]) -> Result<V1Store> {
    // redb can panic on a structurally damaged file instead of failing.
    let db = std::panic::catch_unwind(|| -> Result<redb::Database> {
        let mut db = redb::Builder::new().open(copy)?;
        db.check_integrity()?;
        Ok(db)
    })
    .unwrap_or_else(|_| Err(anyhow!("the file is damaged")))
    .context("opening store.redb")?;
    let txn = db.begin_read()?;
    let header = txn.open_table(HEADER)?;
    let field = |name: &str| -> Result<Vec<u8>> {
        Ok(header
            .get(name)?
            .with_context(|| format!("store.redb's header has no {name:?}"))?
            .value()
            .to_vec())
    };
    let format = field("format")?;
    if format.as_slice() != FORMAT_VERSION.to_le_bytes() {
        bail!("store.redb has an unsupported format {format:?}");
    }
    let kdf = field("kdf")?;
    let unlock = derive(&kdf, passphrase)?;
    let keyset_aad = [AAD_KEYSET, &FORMAT_VERSION.to_le_bytes(), &kdf].concat();
    let keyset =
        open(&unlock, &keyset_aad, &field("keyset")?).ok_or(crate::disk::Error::WrongPassphrase)?;
    if keyset.len() != 64 {
        bail!("store.redb's key set has the wrong length");
    }
    let mut data_key = Zeroizing::new([0u8; 32]);
    data_key.copy_from_slice(&keyset[..32]);
    let data = Zeroizing::new(blake3::derive_key(CTX_DATA, &data_key[..]));
    let meta_index = Zeroizing::new(blake3::derive_key(CTX_META_INDEX, &data_key[..]));

    let len = open(&data, AAD_LOG_LEN, &field("log_len")?)
        .context("store.redb's log length failed authentication")?;
    let len = u64::from_le_bytes(
        len.as_slice()
            .try_into()
            .map_err(|_| anyhow!("store.redb's log length has the wrong size"))?,
    );
    let mut entries = Vec::new();
    for (next, row) in txn.open_table(LOG)?.range::<u64>(..)?.enumerate() {
        let (seq, row) = row?;
        let seq = seq.value();
        if seq != next as u64 || seq >= len {
            bail!("store.redb's log entries are missing or out of order");
        }
        let aad = [AAD_LOG, &seq.to_be_bytes()].concat();
        entries.push(
            open(&data, &aad, row.value())
                .with_context(|| format!("store.redb's log entry {seq} failed authentication"))?,
        );
    }
    if entries.len() as u64 != len {
        bail!("store.redb's log is missing entries");
    }

    let meta = txn.open_table(META)?;
    let meta_text = |name: &str| -> Result<Option<String>> {
        let mut hasher = blake3::Hasher::new_keyed(&meta_index);
        hasher.update(name.as_bytes());
        let blinded: [u8; 32] = hasher.finalize().into();
        let Some(sealed) = meta.get(&blinded)? else {
            return Ok(None);
        };
        let aad = [AAD_META, &blinded].concat();
        let value = open(&data, &aad, sealed.value())
            .with_context(|| format!("store.redb's {name:?} failed authentication"))?;
        // JSON: a string, or null where nothing was set.
        let value: Option<String> =
            serde_json::from_slice(&value).with_context(|| format!("reading {name}"))?;
        Ok(value)
    };
    Ok(V1Store {
        entries,
        device_name: meta_text(META_DEVICE_NAME)?,
        default_vault: meta_text(META_DEFAULT_VAULT)?,
    })
}

/// Argon2id of `passphrase` under the stored KDF header, refusing
/// parameters beyond what v1 allowed.
fn derive(kdf: &[u8], passphrase: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let kdf: &[u8; KDF_LEN] = kdf
        .try_into()
        .map_err(|_| anyhow!("store.redb's KDF header has the wrong length"))?;
    if kdf[0] != ALG_ARGON2ID_V13 {
        bail!("store.redb uses an unknown KDF {}", kdf[0]);
    }
    let at = |i: usize| u32::from_le_bytes([kdf[i], kdf[i + 1], kdf[i + 2], kdf[i + 3]]);
    let (m_cost, t_cost, p_cost) = (at(1), at(5), at(9));
    if m_cost > MAX_M_COST_KIB
        || t_cost > MAX_T_COST
        || p_cost > MAX_P_COST
        || u64::from(m_cost) * u64::from(t_cost) > MAX_WORK_KIB
    {
        bail!("store.redb's KDF parameters exceed what v1 allowed");
    }
    let params = Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| anyhow!("store.redb's KDF parameters: {e}"))?;
    // Ours, not argon2's, so the passphrase-derived state is wiped.
    let mut memory = Zeroizing::new(Vec::new());
    memory
        .try_reserve_exact(params.block_count())
        .map_err(|_| anyhow!("not enough memory to unlock store.redb"))?;
    memory.resize(params.block_count(), Block::new());
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(
            passphrase,
            &kdf[13..],
            key.as_mut_slice(),
            memory.as_mut_slice(),
        )
        .map_err(|e| anyhow!("unlocking store.redb: {e}"))?;
    Ok(key)
}

/// Opens one sealed record; `None` if it fails authentication.
fn open(key: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return None;
    }
    let (nonce, rest) = sealed.split_at(NONCE_LEN);
    let (ciphertext, tag) = rest.split_at(rest.len() - TAG_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().ok()?;
    let tag: [u8; TAG_LEN] = tag.try_into().ok()?;
    let mut buf = Zeroizing::new(ciphertext.to_vec());
    XChaCha20Poly1305::new(key.into())
        .decrypt_inout_detached(&nonce.into(), aad, buf.as_mut_slice().into(), &tag.into())
        .ok()?;
    Some(buf)
}
