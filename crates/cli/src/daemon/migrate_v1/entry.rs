//! DELETABLE(v1-migrate): remove once existing v1 users have migrated to v2.
//!
//! Decodes v1 signed entries, as `deadbolt-core` wrote them before v2:
//!
//! ```text
//! entry   = body signature[64]
//! body    = vault[32] author[32] seq:u64 n:u32 dep[32]*n payload   (deps strictly ascending)
//! payload = 0x00 membership | 0x01 n:u32 data_op*n
//! membership = 0x00 device[32] nonce[32] name:str        Create
//!            | 0x01 device[32] consent[64]               Add
//!            | 0x02 device[32] (0x00 | 0x01 seq:u64)     Remove
//!            | 0x03 name:str                             Rename
//! data_op = (0x00 | 0x02 | 0x03) type:str opt_str n:u32 (name:str field)*n extra   Create
//!         | 0x01 item[16] change                                                  Edit
//! extra   = (tag 0x02) source_id:str source_version:str
//!         | (tag 0x03) opt_source favorite:u8 n:u32 tag:str*n
//! change  = 0x00 name:str field | 0x01 name:str | 0x02 opt_str | 0x03 | 0x04 opt_source
//!         | 0x05 at:u64 | 0x06 | 0x07 u8 | 0x08 str | 0x09 str
//!         | 0x0a kind:str (0x00 | 0x01 hash[32]) | 0x0b opt_str
//! field   = field_type:str value:str
//! str     = len:u32 utf8[len]                   integers big-endian
//! hash    = blake3::derive_key("deadbolt 2026-10-15 entry hash v2", body)
//! ```
//!
//! The changes and their fields are those of today's [`Change`], so ops
//! decode straight into today's [`DataOp`]. Signatures aren't checked: the
//! entries come out of the user's own authenticated store, where v1 kept
//! only entries it had verified.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow, bail};
use deadbolt_core::{Change, DataOp, DeviceId, Field, FieldType, Hash, ItemId, Source};

const HASH_CONTEXT: &str = "deadbolt 2026-10-15 entry hash v2";

/// One v1 signed entry.
pub(super) struct Entry {
    pub vault: [u8; 32],
    pub author: DeviceId,
    pub seq: u64,
    pub deps: Vec<Hash>,
    pub payload: Payload,
    pub hash: Hash,
}

pub(super) enum Payload {
    Membership(MembershipOp),
    Data(Vec<DataOp>),
}

pub(super) enum MembershipOp {
    Create {
        device: DeviceId,
        name: String,
    },
    Add {
        device: DeviceId,
    },
    Remove {
        device: DeviceId,
        last_seen_seq: Option<u64>,
    },
    Rename {
        name: String,
    },
}

impl Entry {
    pub fn is_data(&self) -> bool {
        matches!(self.payload, Payload::Data(_))
    }

    /// Strictly decodes one stored entry.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let split = bytes
            .len()
            .checked_sub(64)
            .ok_or_else(|| anyhow!("a v1 entry is too short"))?;
        let body = &bytes[..split];
        let mut r = Reader(body);
        let vault = r.array()?;
        let author = DeviceId::from_bytes(r.array()?);
        let seq = r.u64()?;
        let mut deps: Vec<Hash> = Vec::new();
        for _ in 0..r.u32()? {
            let dep = Hash::from_bytes(r.array()?);
            if deps.last().is_some_and(|last| *last >= dep) {
                bail!("a v1 entry's dependencies are out of order");
            }
            deps.push(dep);
        }
        let payload = r.payload()?;
        if !r.0.is_empty() {
            bail!("a v1 entry has trailing bytes");
        }
        Ok(Self {
            vault,
            author,
            seq,
            deps,
            payload,
            hash: Hash::from_bytes(blake3::derive_key(HASH_CONTEXT, body)),
        })
    }
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        if self.0.len() < n {
            bail!("a v1 entry ends early");
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn string(&mut self) -> Result<String> {
        let len = self.u32()? as usize;
        let bytes = self.take(len)?;
        Ok(std::str::from_utf8(bytes)
            .map_err(|_| anyhow!("a v1 entry holds invalid UTF-8"))?
            .to_owned())
    }

    fn opt_string(&mut self) -> Result<Option<String>> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.string()?)),
            tag => bail!("a v1 entry has an unknown tag {tag}"),
        }
    }

    fn flag(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            tag => bail!("a v1 entry has an unknown tag {tag}"),
        }
    }

    fn source(&mut self) -> Result<Option<Source>> {
        Ok(match self.flag()? {
            false => None,
            true => Some(Source {
                id: self.string()?,
                version: self.string()?,
            }),
        })
    }

    fn field(&mut self) -> Result<Field> {
        Ok(Field {
            kind: FieldType::parse(&self.string()?),
            value: self.string()?,
        })
    }

    fn payload(&mut self) -> Result<Payload> {
        Ok(match self.u8()? {
            0 => Payload::Membership(match self.u8()? {
                0 => {
                    let device = DeviceId::from_bytes(self.array()?);
                    let _nonce: [u8; 32] = self.array()?;
                    MembershipOp::Create {
                        device,
                        name: self.string()?,
                    }
                }
                1 => {
                    let device = DeviceId::from_bytes(self.array()?);
                    let _consent: [u8; 64] = self.array()?;
                    MembershipOp::Add { device }
                }
                2 => MembershipOp::Remove {
                    device: DeviceId::from_bytes(self.array()?),
                    last_seen_seq: match self.flag()? {
                        false => None,
                        true => Some(self.u64()?),
                    },
                },
                3 => MembershipOp::Rename {
                    name: self.string()?,
                },
                tag => bail!("a v1 entry has an unknown membership tag {tag}"),
            }),
            1 => {
                let mut ops = Vec::new();
                for _ in 0..self.u32()? {
                    ops.push(self.data_op()?);
                }
                Payload::Data(ops)
            }
            tag => bail!("a v1 entry has an unknown payload tag {tag}"),
        })
    }

    fn data_op(&mut self) -> Result<DataOp> {
        Ok(match self.u8()? {
            tag @ (0 | 2 | 3) => {
                let kind = self.string()?;
                let name = self.opt_string()?;
                let mut fields = BTreeMap::new();
                for _ in 0..self.u32()? {
                    let name = self.string()?;
                    if fields
                        .last_key_value()
                        .is_some_and(|(last, _)| *last >= name)
                    {
                        bail!("a v1 item's fields are out of order");
                    }
                    let field = self.field()?;
                    fields.insert(name, field);
                }
                let (source, favorite, tags) = match tag {
                    2 => (
                        Some(Source {
                            id: self.string()?,
                            version: self.string()?,
                        }),
                        false,
                        BTreeSet::new(),
                    ),
                    3 => {
                        let source = self.source()?;
                        let favorite = self.flag()?;
                        let mut tags = BTreeSet::new();
                        for _ in 0..self.u32()? {
                            let tag = self.string()?;
                            if tags.last().is_some_and(|last| *last >= tag) {
                                bail!("a v1 item's tags are out of order");
                            }
                            tags.insert(tag);
                        }
                        (source, favorite, tags)
                    }
                    _ => (None, false, BTreeSet::new()),
                };
                DataOp::Create {
                    kind,
                    name,
                    fields,
                    source,
                    favorite,
                    tags,
                }
            }
            1 => {
                let item = ItemId::from_bytes(self.array()?);
                let change = match self.u8()? {
                    0 => Change::Set {
                        field: self.string()?,
                        value: self.field()?,
                    },
                    1 => Change::Remove {
                        field: self.string()?,
                    },
                    2 => Change::Name(self.opt_string()?),
                    3 => Change::Delete { at: None },
                    4 => Change::Source(self.source()?),
                    5 => Change::Delete {
                        at: Some(self.u64()?),
                    },
                    6 => Change::Restore,
                    7 => Change::Favorite(self.flag()?),
                    8 => Change::TagAdd(self.string()?),
                    9 => Change::TagRemove(self.string()?),
                    10 => Change::Ignore {
                        kind: self.string()?,
                        at: match self.flag()? {
                            false => None,
                            true => Some(Hash::from_bytes(self.array()?)),
                        },
                    },
                    11 => Change::PasswordChanged(self.opt_string()?),
                    tag => bail!("a v1 entry has an unknown change tag {tag}"),
                };
                DataOp::Edit { item, change }
            }
            tag => bail!("a v1 entry has an unknown op tag {tag}"),
        })
    }
}
