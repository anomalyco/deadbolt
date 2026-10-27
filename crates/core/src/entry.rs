use std::collections::BTreeMap;

use crate::encoding::{Reader, Writer};
use crate::error::{DecodeError, Error};
use crate::id::{DeviceId, DeviceSecret, Hash, ItemId, Signature, VaultId};
use crate::item::{Field, FieldType};

const HASH_CONTEXT: &str = "deadbolt 2026-10-15 entry hash v2";
const SIGNATURE_DOMAIN: &[u8] = b"deadbolt entry signature v1\0";
const CONSENT_DOMAIN: &[u8] = b"deadbolt join consent v2\0";

pub(crate) fn consent_message(vault: &VaultId, inviter: &DeviceId, device: &DeviceId) -> Vec<u8> {
    [
        CONSENT_DOMAIN,
        vault.as_bytes(),
        inviter.as_bytes(),
        device.as_bytes(),
    ]
    .concat()
}

fn signature_message(hash: &Hash) -> Vec<u8> {
    [SIGNATURE_DOMAIN, hash.as_bytes()].concat()
}

/// Which of an author's two logs an entry belongs to.
///
/// Each device keeps a membership log and a data log, each with its own
/// sequence numbers, so membership can always be synced before data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Log {
    Membership,
    Data,
}

/// One author's log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LogId {
    pub author: DeviceId,
    pub log: Log,
}

/// What an entry does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    Membership(MembershipOp),
    /// Data ops, applied in order.
    Data(Vec<DataOp>),
}

impl Payload {
    /// The log this payload is written to.
    pub fn log(&self) -> Log {
        match self {
            Payload::Membership(_) => Log::Membership,
            Payload::Data(_) => Log::Data,
        }
    }
}

/// A change to the member set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MembershipOp {
    /// Genesis. The vault id is derived from `device` and `nonce`.
    Create {
        device: DeviceId,
        nonce: [u8; 32],
        name: String,
    },
    /// Adds `device`; `consent` is its [`DeviceSecret::join_consent`] for this
    /// vault and the entry's author.
    Add {
        device: DeviceId,
        consent: Signature,
    },
    /// Removes `device`. Its data entries with seq above `last_seen_seq` are ignored.
    Remove {
        device: DeviceId,
        last_seen_seq: Option<u64>,
    },
    /// Renames the vault. See [`valid_name`].
    Rename { name: String },
}

/// Whether `name` is a valid vault name: 1–64 characters of lowercase ASCII
/// letters, digits, `-` and `_`, starting with a letter.
pub fn valid_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
}

/// One data op. See [`crate::item`] for the rules ops must follow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataOp {
    /// Creates an item of type `kind` with all its required fields. The new
    /// item's id is [`ItemId::of_create`] of the entry hash and op index.
    Create {
        kind: String,
        name: Option<String>,
        fields: BTreeMap<String, Field>,
        /// Set when the item mirrors one held elsewhere.
        source: Option<Source>,
    },
    /// Changes an existing item.
    Edit { item: ItemId, change: Change },
}

/// Where a mirrored item comes from: its id in another password manager
/// and the version mirrored, both opaque here. Kept apart from the fields,
/// so it is never shown, copied or edited as one. An item without a source
/// is the user's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub id: String,
    pub version: String,
}

/// A change to an existing item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// Sets a field's type and value.
    Set { field: String, value: Field },
    /// Removes a field that is not required.
    Remove { field: String },
    /// Sets or clears the item's name.
    Name(Option<String>),
    /// Marks the item deleted. A later edit restores it.
    Delete,
    /// Sets or clears where the item is mirrored from.
    Source(Option<Source>),
}

impl DataOp {
    pub fn create(
        kind: impl Into<String>,
        name: Option<String>,
        fields: impl IntoIterator<Item = (String, Field)>,
    ) -> Self {
        Self::Create {
            kind: kind.into(),
            name,
            fields: fields.into_iter().collect(),
            source: None,
        }
    }

    /// A `Create` that mirrors an item held elsewhere.
    pub fn create_mirror(
        kind: impl Into<String>,
        name: Option<String>,
        fields: impl IntoIterator<Item = (String, Field)>,
        source: Source,
    ) -> Self {
        Self::Create {
            kind: kind.into(),
            name,
            fields: fields.into_iter().collect(),
            source: Some(source),
        }
    }

    pub fn source(item: ItemId, source: Option<Source>) -> Self {
        Self::edit(item, Change::Source(source))
    }

    pub fn set(item: ItemId, field: impl Into<String>, value: Field) -> Self {
        let field = field.into();
        Self::edit(item, Change::Set { field, value })
    }

    pub fn remove(item: ItemId, field: impl Into<String>) -> Self {
        let field = field.into();
        Self::edit(item, Change::Remove { field })
    }

    pub fn name(item: ItemId, name: Option<String>) -> Self {
        Self::edit(item, Change::Name(name))
    }

    pub fn delete(item: ItemId) -> Self {
        Self::edit(item, Change::Delete)
    }

    fn edit(item: ItemId, change: Change) -> Self {
        Self::Edit { item, change }
    }
}

/// A signed entry in one author's log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    vault: VaultId,
    author: DeviceId,
    seq: u64,
    deps: Vec<Hash>,
    payload: Payload,
    signature: Signature,
    hash: Hash,
}

impl Entry {
    /// Builds and signs an entry. `deps` are sorted and deduplicated.
    pub fn sign(
        secret: &DeviceSecret,
        vault: VaultId,
        seq: u64,
        deps: impl IntoIterator<Item = Hash>,
        payload: Payload,
    ) -> Self {
        let mut deps: Vec<Hash> = deps.into_iter().collect();
        deps.sort();
        deps.dedup();
        let author = secret.device_id();
        let mut w = Writer::default();
        write_body(&mut w, &vault, &author, seq, &deps, &payload);
        let hash = Hash(blake3::derive_key(HASH_CONTEXT, &w.finish()));
        let signature = secret.sign(&signature_message(&hash));
        Self {
            vault,
            author,
            seq,
            deps,
            payload,
            signature,
            hash,
        }
    }

    /// Checks the author's signature.
    pub fn verify(&self) -> Result<(), Error> {
        if self
            .author
            .verify(&signature_message(&self.hash), &self.signature)
        {
            Ok(())
        } else {
            Err(Error::BadSignature)
        }
    }

    /// Canonical wire/storage encoding: body followed by the 64-byte signature.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        write_body(
            &mut w,
            &self.vault,
            &self.author,
            self.seq,
            &self.deps,
            &self.payload,
        );
        w.bytes(self.signature.as_bytes());
        w.finish()
    }

    /// Strictly decodes [`Entry::encode`] output. Does not check the signature.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let split = bytes
            .len()
            .checked_sub(64)
            .ok_or(DecodeError::UnexpectedEnd)?;
        let (body, signature) = bytes.split_at(split);
        let mut r = Reader::new(body);
        let vault = VaultId(r.array()?);
        let author = DeviceId(r.array()?);
        let seq = r.u64()?;
        let mut deps = Vec::new();
        for _ in 0..r.u32()? {
            let dep = Hash(r.array()?);
            if deps.last().is_some_and(|last| *last >= dep) {
                return Err(DecodeError::NotCanonical);
            }
            deps.push(dep);
        }
        let payload = read_payload(&mut r)?;
        r.finish()?;
        Ok(Self {
            vault,
            author,
            seq,
            deps,
            payload,
            signature: Signature(Reader::new(signature).array()?),
            hash: Hash(blake3::derive_key(HASH_CONTEXT, body)),
        })
    }

    /// Hash of the encoding without the signature; the entry's identity.
    pub fn hash(&self) -> Hash {
        self.hash
    }

    pub fn vault(&self) -> VaultId {
        self.vault
    }

    pub fn author(&self) -> DeviceId {
        self.author
    }

    /// Position in the author's log for [`Entry::log`], starting at 0.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Hashes of the entries this one was based on, sorted.
    pub fn deps(&self) -> &[Hash] {
        &self.deps
    }

    pub fn payload(&self) -> &Payload {
        &self.payload
    }

    pub fn signature(&self) -> Signature {
        self.signature
    }

    pub fn log(&self) -> Log {
        self.payload.log()
    }

    pub fn log_id(&self) -> LogId {
        LogId {
            author: self.author,
            log: self.log(),
        }
    }
}

fn write_body(
    w: &mut Writer,
    vault: &VaultId,
    author: &DeviceId,
    seq: u64,
    deps: &[Hash],
    payload: &Payload,
) {
    w.bytes(vault.as_bytes());
    w.bytes(author.as_bytes());
    w.u64(seq);
    w.len(deps.len());
    deps.iter().for_each(|dep| w.bytes(dep.as_bytes()));
    match payload {
        Payload::Membership(op) => {
            w.u8(0);
            match op {
                MembershipOp::Create {
                    device,
                    nonce,
                    name,
                } => {
                    w.u8(0);
                    w.bytes(device.as_bytes());
                    w.bytes(nonce);
                    w.str(name);
                }
                MembershipOp::Add { device, consent } => {
                    w.u8(1);
                    w.bytes(device.as_bytes());
                    w.bytes(consent.as_bytes());
                }
                MembershipOp::Remove {
                    device,
                    last_seen_seq,
                } => {
                    w.u8(2);
                    w.bytes(device.as_bytes());
                    match last_seen_seq {
                        None => w.u8(0),
                        Some(seq) => {
                            w.u8(1);
                            w.u64(*seq);
                        }
                    }
                }
                MembershipOp::Rename { name } => {
                    w.u8(3);
                    w.str(name);
                }
            }
        }
        Payload::Data(ops) => {
            w.u8(1);
            w.len(ops.len());
            ops.iter().for_each(|op| write_data_op(w, op));
        }
    }
}

fn write_opt_str(w: &mut Writer, v: Option<&str>) {
    match v {
        None => w.u8(0),
        Some(v) => {
            w.u8(1);
            w.str(v);
        }
    }
}

fn write_field(w: &mut Writer, field: &Field) {
    w.str(field.kind.as_str());
    w.str(&field.value);
}

fn write_data_op(w: &mut Writer, op: &DataOp) {
    match op {
        DataOp::Create {
            kind,
            name,
            fields,
            source,
        } => {
            // A mirror's `Create` has its own tag, so every other entry
            // encodes (and hashes) as it did before sources existed.
            w.u8(if source.is_some() { 2 } else { 0 });
            w.str(kind);
            write_opt_str(w, name.as_deref());
            w.len(fields.len());
            for (name, field) in fields {
                w.str(name);
                write_field(w, field);
            }
            if let Some(source) = source {
                w.str(&source.id);
                w.str(&source.version);
            }
        }
        DataOp::Edit { item, change } => {
            w.u8(1);
            w.bytes(item.as_bytes());
            match change {
                Change::Set { field, value } => {
                    w.u8(0);
                    w.str(field);
                    write_field(w, value);
                }
                Change::Remove { field } => {
                    w.u8(1);
                    w.str(field);
                }
                Change::Name(name) => {
                    w.u8(2);
                    write_opt_str(w, name.as_deref());
                }
                Change::Delete => w.u8(3),
                Change::Source(source) => {
                    w.u8(4);
                    write_source(w, source.as_ref());
                }
            }
        }
    }
}

fn write_source(w: &mut Writer, source: Option<&Source>) {
    match source {
        None => w.u8(0),
        Some(source) => {
            w.u8(1);
            w.str(&source.id);
            w.str(&source.version);
        }
    }
}

fn read_source(r: &mut Reader<'_>) -> Result<Option<Source>, DecodeError> {
    match r.u8()? {
        0 => Ok(None),
        1 => Ok(Some(Source {
            id: r.string()?,
            version: r.string()?,
        })),
        tag => Err(DecodeError::InvalidTag(tag)),
    }
}

fn read_opt_str(r: &mut Reader<'_>) -> Result<Option<String>, DecodeError> {
    match r.u8()? {
        0 => Ok(None),
        1 => Ok(Some(r.string()?)),
        tag => Err(DecodeError::InvalidTag(tag)),
    }
}

fn read_field(r: &mut Reader<'_>) -> Result<Field, DecodeError> {
    Ok(Field {
        kind: FieldType::parse(&r.string()?),
        value: r.string()?,
    })
}

fn read_data_op(r: &mut Reader<'_>) -> Result<DataOp, DecodeError> {
    Ok(match r.u8()? {
        tag @ (0 | 2) => {
            let kind = r.string()?;
            let name = read_opt_str(r)?;
            let mut fields = BTreeMap::new();
            for _ in 0..r.u32()? {
                let name = r.string()?;
                if fields
                    .last_key_value()
                    .is_some_and(|(last, _)| *last >= name)
                {
                    return Err(DecodeError::NotCanonical);
                }
                fields.insert(name, read_field(r)?);
            }
            let source = match tag {
                2 => Some(Source {
                    id: r.string()?,
                    version: r.string()?,
                }),
                _ => None,
            };
            DataOp::Create {
                kind,
                name,
                fields,
                source,
            }
        }
        1 => {
            let item = ItemId(r.array()?);
            let change = match r.u8()? {
                0 => Change::Set {
                    field: r.string()?,
                    value: read_field(r)?,
                },
                1 => Change::Remove { field: r.string()? },
                2 => Change::Name(read_opt_str(r)?),
                3 => Change::Delete,
                4 => Change::Source(read_source(r)?),
                tag => return Err(DecodeError::InvalidTag(tag)),
            };
            DataOp::Edit { item, change }
        }
        tag => return Err(DecodeError::InvalidTag(tag)),
    })
}

fn read_payload(r: &mut Reader<'_>) -> Result<Payload, DecodeError> {
    Ok(match r.u8()? {
        0 => Payload::Membership(match r.u8()? {
            0 => MembershipOp::Create {
                device: DeviceId(r.array()?),
                nonce: r.array()?,
                name: r.string()?,
            },
            1 => MembershipOp::Add {
                device: DeviceId(r.array()?),
                consent: Signature(r.array()?),
            },
            2 => MembershipOp::Remove {
                device: DeviceId(r.array()?),
                last_seen_seq: match r.u8()? {
                    0 => None,
                    1 => Some(r.u64()?),
                    tag => return Err(DecodeError::InvalidTag(tag)),
                },
            },
            3 => MembershipOp::Rename { name: r.string()? },
            tag => return Err(DecodeError::InvalidTag(tag)),
        }),
        1 => {
            let mut ops = Vec::new();
            for _ in 0..r.u32()? {
                ops.push(read_data_op(r)?);
            }
            Payload::Data(ops)
        }
        tag => return Err(DecodeError::InvalidTag(tag)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(secret: &DeviceSecret) -> Entry {
        let item = ItemId::from_bytes([7; 16]);
        Entry::sign(
            secret,
            VaultId::from_bytes([1; 32]),
            3,
            [
                Hash::from_bytes([9; 32]),
                Hash::from_bytes([2; 32]),
                Hash::from_bytes([9; 32]),
            ],
            Payload::Data(vec![
                DataOp::create(
                    "login",
                    Some("Work".into()),
                    [
                        ("username".into(), Field::new(FieldType::Text, "dax")),
                        ("password".into(), Field::new(FieldType::Secret, "hunter2")),
                    ],
                ),
                DataOp::set(
                    item,
                    "x",
                    Field::new(FieldType::Other("future".into()), "v"),
                ),
                DataOp::remove(item, "notes"),
                DataOp::name(item, None),
                DataOp::name(item, Some("n".into())),
                DataOp::delete(item),
                DataOp::create_mirror(
                    "note",
                    Some("Mirrored".into()),
                    [],
                    Source {
                        id: "op/a/v/i".into(),
                        version: "2026-10-26T00:00:00Z".into(),
                    },
                ),
                DataOp::source(
                    item,
                    Some(Source {
                        id: "op/a/v/i".into(),
                        version: String::new(),
                    }),
                ),
                DataOp::source(item, None),
            ]),
        )
    }

    #[test]
    fn round_trip_is_canonical() {
        let secret = DeviceSecret::generate();
        let entry = sample(&secret);
        assert_eq!(
            entry.deps(),
            &[Hash::from_bytes([2; 32]), Hash::from_bytes([9; 32])]
        );
        let bytes = entry.encode();
        let decoded = Entry::decode(&bytes).unwrap();
        assert_eq!(decoded, entry);
        assert_eq!(decoded.encode(), bytes);
        decoded.verify().unwrap();

        for op in [
            MembershipOp::Create {
                device: secret.device_id(),
                nonce: [4; 32],
                name: "personal".into(),
            },
            MembershipOp::Add {
                device: secret.device_id(),
                consent: Signature([5; 64]),
            },
            MembershipOp::Remove {
                device: secret.device_id(),
                last_seen_seq: None,
            },
            MembershipOp::Remove {
                device: secret.device_id(),
                last_seen_seq: Some(8),
            },
            MembershipOp::Rename {
                name: "work".into(),
            },
        ] {
            let entry = Entry::sign(&secret, VaultId([0; 32]), 0, [], Payload::Membership(op));
            assert_eq!(Entry::decode(&entry.encode()).unwrap(), entry);
        }
    }

    #[test]
    fn validates_names() {
        for name in ["a", "personal", "work-2026", "a_b", &"x".repeat(64)] {
            assert!(valid_name(name), "{name}");
        }
        let long = "x".repeat(65);
        for name in ["", "1abc", "-a", "_a", "Abc", "a b", "a.b", "café", &long] {
            assert!(!valid_name(name), "{name}");
        }
    }

    #[test]
    fn hash_excludes_signature_and_is_deterministic() {
        let secret = DeviceSecret::from_bytes(&[42; 32]);
        let a = sample(&secret);
        let b = sample(&secret);
        assert_eq!(a.hash(), b.hash());
        let mut bytes = a.encode();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let tampered = Entry::decode(&bytes).unwrap();
        assert_eq!(tampered.hash(), a.hash());
        assert_eq!(tampered.verify(), Err(Error::BadSignature));
    }

    #[test]
    fn tampered_body_fails_verification() {
        let secret = DeviceSecret::generate();
        let bytes = sample(&secret).encode();
        let at = bytes.windows(7).position(|w| w == b"hunter2").unwrap();
        let mut tampered = bytes.clone();
        tampered[at] = b'H';
        let entry = Entry::decode(&tampered).unwrap();
        assert_eq!(entry.verify(), Err(Error::BadSignature));
    }

    #[test]
    fn decode_rejects_malformed_input() {
        let secret = DeviceSecret::generate();
        let bytes = sample(&secret).encode();
        assert_eq!(Entry::decode(&bytes[..10]), Err(DecodeError::UnexpectedEnd));
        let mut trailing = bytes.clone();
        trailing.splice(bytes.len() - 64..bytes.len() - 64, [0]);
        assert_eq!(Entry::decode(&trailing), Err(DecodeError::TrailingBytes));
        let mut unsorted = bytes.clone();
        let deps = 32 + 32 + 8 + 4;
        unsorted[deps..deps + 32].copy_from_slice(&[0xff; 32]);
        assert_eq!(Entry::decode(&unsorted), Err(DecodeError::NotCanonical));

        // Create fields must be in ascending name order.
        let mut swapped = bytes.clone();
        let user = bytes.windows(8).position(|w| w == b"username").unwrap();
        let pass = bytes.windows(8).position(|w| w == b"password").unwrap();
        swapped[user..user + 8].copy_from_slice(b"password");
        swapped[pass..pass + 8].copy_from_slice(b"username");
        assert_eq!(Entry::decode(&swapped), Err(DecodeError::NotCanonical));
    }

    #[test]
    fn unknown_field_types_survive_decoding() {
        let entry = sample(&DeviceSecret::generate());
        let Payload::Data(ops) = Entry::decode(&entry.encode()).unwrap().payload().clone() else {
            unreachable!()
        };
        let DataOp::Edit {
            change: Change::Set { value, .. },
            ..
        } = &ops[1]
        else {
            unreachable!()
        };
        assert_eq!(value.kind, FieldType::Other("future".into()));
    }
}
