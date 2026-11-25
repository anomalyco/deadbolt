//! Canonical remote object names (Fable §3.3).
//!
//! ```text
//! <vault>/m/<author>/<seq:016x>      Member frame
//! <vault>/d/<author>/<seq:016x>      Data frame
//! <vault>/d/<author>/<seq:016x>.c    Checkpoint frame
//! <vault>/p/<pack_hash>              checkpoint pack
//! <vault>/b/<blob_hash>              immutable attachment
//! <vault>/x/<proof_hash>             keyless fraud proof
//! <vault>/s/<send_name>              store-backed Send payload
//! ```
//!
//! Every id is canonical lowercase hex of a fixed width, so one object has
//! exactly one name and lexicographic order within a stream is `seq` order.

use std::fmt::Write as _;

use deadbolt_core::v2::{FrameKind, LogKind};
use deadbolt_core::{DeviceId, VaultId};

/// The longest object name any backend is asked to store.
pub const MAX_NAME_LEN: usize = 512;

/// Bytes in a store-backed Send name: `KDF("send name", key)[..16]`.
pub const SEND_NAME_LEN: usize = 16;

/// Why a name or prefix was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    #[error("empty object name")]
    Empty,
    #[error("object name longer than {MAX_NAME_LEN} bytes")]
    TooLong,
    #[error("object name may not start with '/'")]
    LeadingSlash,
    #[error("object name has an empty, '.' or '..' segment")]
    BadSegment,
    #[error("object name has a byte outside [0-9a-z._/-]: {0:#04x}")]
    BadByte(u8),
    #[error("not a canonical Deadbolt object name: {0}")]
    NotCanonical(&'static str),
}

/// The plane an object lives in, by its directory letter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Area {
    /// `m/`: Member frames.
    Member,
    /// `d/`: Data and Checkpoint frames.
    Data,
    /// `p/`: checkpoint packs.
    Pack,
    /// `b/`: attachment blobs.
    Blob,
    /// `x/`: fraud proofs.
    Fraud,
    /// `s/`: Send payloads.
    Send,
}

impl Area {
    /// The directory letter.
    pub const fn letter(self) -> char {
        match self {
            Self::Member => 'm',
            Self::Data => 'd',
            Self::Pack => 'p',
            Self::Blob => 'b',
            Self::Fraud => 'x',
            Self::Send => 's',
        }
    }

    /// The area of a log's frames.
    pub const fn of_log(log: LogKind) -> Self {
        match log {
            LogKind::Member => Self::Member,
            LogKind::Data => Self::Data,
        }
    }

    fn from_segment(segment: &str) -> Option<Self> {
        Some(match segment {
            "m" => Self::Member,
            "d" => Self::Data,
            "p" => Self::Pack,
            "b" => Self::Blob,
            "x" => Self::Fraud,
            "s" => Self::Send,
            _ => return None,
        })
    }
}

/// A parsed canonical object name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RemotePath {
    /// A frame at `m/<author>/<seq>` or `d/<author>/<seq>[.c]`.
    Frame {
        vault: VaultId,
        kind: FrameKind,
        author: DeviceId,
        seq: u64,
    },
    /// A checkpoint pack, `p/<pack_hash>`.
    Pack { vault: VaultId, hash: [u8; 32] },
    /// An attachment blob, `b/<blob_hash>`.
    Blob { vault: VaultId, hash: [u8; 32] },
    /// A fraud proof, `x/<proof_hash>`.
    Fraud { vault: VaultId, hash: [u8; 32] },
    /// A store-backed Send payload, `s/<send_name>`.
    Send {
        vault: VaultId,
        name: [u8; SEND_NAME_LEN],
    },
}

impl RemotePath {
    /// A frame's name.
    pub const fn frame(vault: VaultId, kind: FrameKind, author: DeviceId, seq: u64) -> Self {
        Self::Frame {
            vault,
            kind,
            author,
            seq,
        }
    }

    /// The vault the object belongs to.
    pub const fn vault(&self) -> &VaultId {
        match self {
            Self::Frame { vault, .. }
            | Self::Pack { vault, .. }
            | Self::Blob { vault, .. }
            | Self::Fraud { vault, .. }
            | Self::Send { vault, .. } => vault,
        }
    }

    /// The object's area.
    pub const fn area(&self) -> Area {
        match self {
            Self::Frame { kind, .. } => Area::of_log(kind.log_kind()),
            Self::Pack { .. } => Area::Pack,
            Self::Blob { .. } => Area::Blob,
            Self::Fraud { .. } => Area::Fraud,
            Self::Send { .. } => Area::Send,
        }
    }

    /// True for names derived from their content (`p/`, `b/`, `x/`): a
    /// second PUT of the same name carries the same bytes.
    pub const fn is_content_addressed(&self) -> bool {
        matches!(
            self,
            Self::Pack { .. } | Self::Blob { .. } | Self::Fraud { .. }
        )
    }

    /// The canonical object name.
    pub fn to_name(&self) -> String {
        let mut out = area_prefix(self.vault(), self.area());
        match self {
            Self::Frame {
                kind, author, seq, ..
            } => {
                push_hex(&mut out, author.as_bytes());
                out.push('/');
                push_seq(&mut out, *seq);
                if *kind == FrameKind::Checkpoint {
                    out.push_str(".c");
                }
            }
            Self::Pack { hash, .. } | Self::Blob { hash, .. } | Self::Fraud { hash, .. } => {
                push_hex(&mut out, hash);
            }
            Self::Send { name, .. } => push_hex(&mut out, name),
        }
        out
    }

    /// Parses a canonical object name, refusing every non-canonical spelling.
    pub fn parse(name: &str) -> Result<Self, PathError> {
        validate_name(name)?;
        let mut parts = name.split('/');
        let vault = VaultId::from_bytes(parse_hex::<32>(next(&mut parts)?)?);
        let area = Area::from_segment(next(&mut parts)?).ok_or(PathError::NotCanonical("area"))?;
        let id = next(&mut parts)?;
        let path = match area {
            Area::Member | Area::Data => {
                let author = DeviceId::from_bytes(parse_hex::<32>(id)?);
                let leaf = next(&mut parts)?;
                let (seq, kind) = match (area, leaf.strip_suffix(".c")) {
                    (Area::Data, Some(seq)) => (seq, FrameKind::Checkpoint),
                    (Area::Data, None) => (leaf, FrameKind::Data),
                    (_, None) => (leaf, FrameKind::Member),
                    (_, Some(_)) => return Err(PathError::NotCanonical("checkpoint outside d/")),
                };
                Self::Frame {
                    vault,
                    kind,
                    author,
                    seq: parse_seq(seq)?,
                }
            }
            Area::Pack => Self::Pack {
                vault,
                hash: parse_hex(id)?,
            },
            Area::Blob => Self::Blob {
                vault,
                hash: parse_hex(id)?,
            },
            Area::Fraud => Self::Fraud {
                vault,
                hash: parse_hex(id)?,
            },
            Area::Send => Self::Send {
                vault,
                name: parse_hex(id)?,
            },
        };
        if parts.next().is_some() {
            return Err(PathError::NotCanonical("trailing segment"));
        }
        Ok(path)
    }
}

/// `<vault>/`.
pub fn vault_prefix(vault: &VaultId) -> String {
    let mut out = String::with_capacity(65);
    push_hex(&mut out, vault.as_bytes());
    out.push('/');
    out
}

/// `<vault>/<letter>/`.
pub fn area_prefix(vault: &VaultId, area: Area) -> String {
    let mut out = vault_prefix(vault);
    out.push(area.letter());
    out.push('/');
    out
}

/// `<vault>/<m|d>/<author>/`: one author's stream in one log.
pub fn stream_prefix(vault: &VaultId, log: LogKind, author: &DeviceId) -> String {
    let mut out = area_prefix(vault, Area::of_log(log));
    push_hex(&mut out, author.as_bytes());
    out.push('/');
    out
}

/// The bare (non-checkpoint) frame name at `seq` in one author's stream.
pub fn stream_seq_name(vault: &VaultId, log: LogKind, author: &DeviceId, seq: u64) -> String {
    let mut out = stream_prefix(vault, log, author);
    push_seq(&mut out, seq);
    out
}

/// A LIST `after` cursor that returns every frame of the stream with
/// `seq >= from` (both the bare and the `.c` spelling), or the whole
/// stream for `from == 0`.
pub fn stream_cursor(
    vault: &VaultId,
    log: LogKind,
    author: &DeviceId,
    from: u64,
) -> Option<String> {
    let prev = from.checked_sub(1)?;
    // "<prev>.c" is the greatest name a frame at `prev` can have.
    let mut out = stream_seq_name(vault, log, author, prev);
    out.push_str(".c");
    Some(out)
}

/// Checks a name every backend accepts: 1..=512 bytes of `[0-9a-z._/-]`,
/// no leading `/`, no empty, `.` or `..` segment. Rejects control
/// characters, uppercase, percent signs and every other escape a backend
/// might interpret.
pub fn validate_name(name: &str) -> Result<(), PathError> {
    if name.is_empty() {
        return Err(PathError::Empty);
    }
    validate_prefix(name)?;
    if name.ends_with('/') {
        return Err(PathError::BadSegment);
    }
    Ok(())
}

/// Checks a LIST prefix: like [`validate_name`], but it may be empty and may
/// end in `/`.
pub fn validate_prefix(prefix: &str) -> Result<(), PathError> {
    if prefix.len() > MAX_NAME_LEN {
        return Err(PathError::TooLong);
    }
    if prefix.starts_with('/') {
        return Err(PathError::LeadingSlash);
    }
    if let Some(&bad) = prefix
        .as_bytes()
        .iter()
        .find(|b| !matches!(b, b'0'..=b'9' | b'a'..=b'z' | b'.' | b'_' | b'-' | b'/'))
    {
        return Err(PathError::BadByte(bad));
    }
    let body = prefix.strip_suffix('/').unwrap_or(prefix);
    if !body.is_empty()
        && body
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == "..")
    {
        return Err(PathError::BadSegment);
    }
    Ok(())
}

/// Appends lowercase hex.
pub(crate) fn push_hex(out: &mut String, bytes: &[u8]) {
    for b in bytes {
        // Writing to a String cannot fail.
        let _ignored = write!(out, "{b:02x}");
    }
}

/// Lowercase hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    push_hex(&mut out, bytes);
    out
}

fn push_seq(out: &mut String, seq: u64) {
    let _ignored = write!(out, "{seq:016x}");
}

fn next<'a>(parts: &mut impl Iterator<Item = &'a str>) -> Result<&'a str, PathError> {
    parts
        .next()
        .ok_or(PathError::NotCanonical("missing segment"))
}

fn parse_seq(text: &str) -> Result<u64, PathError> {
    if text.len() != 16 {
        return Err(PathError::NotCanonical("seq is not 16 hex digits"));
    }
    Ok(u64::from_be_bytes(parse_hex::<8>(text)?))
}

fn parse_hex<const N: usize>(text: &str) -> Result<[u8; N], PathError> {
    if text.len() != N * 2 {
        return Err(PathError::NotCanonical("wrong hex length"));
    }
    let mut out = [0u8; N];
    let (pairs, _) = text.as_bytes().as_chunks::<2>();
    for (slot, pair) in out.iter_mut().zip(pairs) {
        *slot = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(out)
}

fn nibble(b: u8) -> Result<u8, PathError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(PathError::NotCanonical("not lowercase hex")),
    }
}
