//! File names inside one vault directory, `<base>/v/<vault>/`. Names are never
//! reused: a generation, a WAL or an outbox entry that was deleted is never
//! created again under the same name, so a delete-pending file on Windows
//! blocks nothing.

use crate::blocks::Blocks;
use crate::error::Result;

pub const MEMBERS_LOG: &str = "members.log";
pub const LOCK: &str = "LOCK";
pub const BLOB_DIR: &str = "blob/";
pub const OUTBOX_DIR: &str = "outbox/";

pub const GEN_PREFIX: &str = "gen-";
pub const GEN_SUFFIX: &str = ".pack";
pub const WAL_PREFIX: &str = "wal-";
pub const WAL_SUFFIX: &str = ".log";
pub const LOCAL_PREFIX: &str = "local-";
pub const LOCAL_SUFFIX: &str = ".sealed";
pub const ACTIVITY_PREFIX: &str = "activity-";
pub const ACTIVITY_SUFFIX: &str = ".log";
pub const OUTBOX_SUFFIX: &str = ".wrap";

pub fn gen_pack(n: u64) -> String {
    format!("{GEN_PREFIX}{n}{GEN_SUFFIX}")
}

pub fn wal_log(n: u64) -> String {
    format!("{WAL_PREFIX}{n}{WAL_SUFFIX}")
}

pub fn local_sealed(m: u64) -> String {
    format!("{LOCAL_PREFIX}{m}{LOCAL_SUFFIX}")
}

pub fn activity_log(k: u64) -> String {
    format!("{ACTIVITY_PREFIX}{k}{ACTIVITY_SUFFIX}")
}

pub fn blob(hash: &[u8; 32]) -> String {
    format!("{BLOB_DIR}{}", hex(hash))
}

pub fn outbox(id: &[u8; 16]) -> String {
    format!("{OUTBOX_DIR}{}{OUTBOX_SUFFIX}", hex(id))
}

/// `n` from `<prefix><n><suffix>`, with `n` in canonical decimal.
pub fn parse_numbered(name: &str, prefix: &str, suffix: &str) -> Option<u64> {
    let digits = name.strip_prefix(prefix)?.strip_suffix(suffix)?;
    let canonical = !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'));
    if canonical { digits.parse().ok() } else { None }
}

/// Every `n` with a `<prefix><n><suffix>` file present, ascending.
pub(crate) fn numbered<B: Blocks>(blocks: &B, prefix: &str, suffix: &str) -> Result<Vec<u64>> {
    let mut out: Vec<u64> = blocks
        .list_prefix(prefix)?
        .iter()
        .filter_map(|name| parse_numbered(name, prefix, suffix))
        .collect();
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0xf)]));
    }
    out
}
