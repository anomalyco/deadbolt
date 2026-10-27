//! What a share carries. Everything here, names and types included, is sealed.
//!
//! ```text
//! bundle = version(1) || opt_str title || opt_str note || nodes
//! nodes  = count(u32) || node*
//! node   = 1 || str name || opt_str mime || sensitive(1) || bytes data     an entry
//!        | 2 || opt_str name || nodes                                    a group
//! str    = len(u32) || utf-8       opt_str = 0 | 1 || str       bytes = len(u32) || bytes
//! ```

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};

const VERSION: u8 = 1;
const ENTRY: u8 = 1;
const GROUP: u8 = 2;
/// Deepest group nesting a receiver accepts.
const MAX_DEPTH: usize = 32;

/// A titled set of entries and groups.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Bundle {
    pub title: Option<String>,
    /// Shown to the receiver as is; never sensitive.
    pub note: Option<String>,
    pub entries: Vec<Node>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize),
    serde(tag = "kind", rename_all = "kebab-case")
)]
pub enum Node {
    Entry(Entry),
    Group(Group),
}

/// One value: a secret, some text, or a file.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Entry {
    pub name: String,
    #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))]
    pub data: Vec<u8>,
    /// The media type, if known (`text/plain`, `application/pdf`, ...).
    pub mime: Option<String>,
    /// Hidden until the receiver asks to see it.
    pub sensitive: bool,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("name", &self.name)
            .field("data", &format_args!("<{} bytes>", self.data.len()))
            .field("mime", &self.mime)
            .field("sensitive", &self.sensitive)
            .finish()
    }
}

/// Named entries that belong together: a folder, or an item's fields.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Group {
    pub name: Option<String>,
    pub entries: Vec<Node>,
}

impl Entry {
    /// A text value.
    pub fn text(name: impl Into<String>, value: impl Into<String>, sensitive: bool) -> Self {
        Self {
            name: name.into(),
            data: value.into().into_bytes(),
            mime: Some("text/plain".into()),
            sensitive,
        }
    }
}

impl Bundle {
    /// Every entry, however deep.
    pub fn entry_count(&self) -> usize {
        fn count(nodes: &[Node]) -> usize {
            nodes
                .iter()
                .map(|n| match n {
                    Node::Entry(_) => 1,
                    Node::Group(g) => count(&g.entries),
                })
                .sum()
        }
        count(&self.entries)
    }

    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::new());
        out.push(VERSION);
        opt_str(&mut out, self.title.as_deref());
        opt_str(&mut out, self.note.as_deref());
        nodes(&mut out, &self.entries);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader(bytes);
        if r.u8()? != VERSION {
            return Err(Error::Corrupt("unsupported bundle version".into()));
        }
        let bundle = Self {
            title: r.opt_str()?,
            note: r.opt_str()?,
            entries: r.nodes(0)?,
        };
        if !r.0.is_empty() {
            return Err(Error::Corrupt("trailing bytes".into()));
        }
        Ok(bundle)
    }
}

fn len(out: &mut Vec<u8>, n: usize) {
    // Bundles are capped far below 4 GiB (see `MAX_SEALED_LEN`).
    out.extend_from_slice(&(n as u32).to_be_bytes());
}

fn str(out: &mut Vec<u8>, s: &str) {
    len(out, s.len());
    out.extend_from_slice(s.as_bytes());
}

fn opt_str(out: &mut Vec<u8>, s: Option<&str>) {
    match s {
        None => out.push(0),
        Some(s) => {
            out.push(1);
            str(out, s);
        }
    }
}

fn nodes(out: &mut Vec<u8>, list: &[Node]) {
    len(out, list.len());
    for node in list {
        match node {
            Node::Entry(e) => {
                out.push(ENTRY);
                str(out, &e.name);
                opt_str(out, e.mime.as_deref());
                out.push(u8::from(e.sensitive));
                len(out, e.data.len());
                out.extend_from_slice(&e.data);
            }
            Node::Group(g) => {
                out.push(GROUP);
                opt_str(out, g.name.as_deref());
                nodes(out, &g.entries);
            }
        }
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(Error::Corrupt("truncated bundle".into()));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn len(&mut self) -> Result<usize> {
        let mut b = [0u8; 4];
        b.copy_from_slice(self.take(4)?);
        Ok(u32::from_be_bytes(b) as usize)
    }

    fn bytes(&mut self) -> Result<&'a [u8]> {
        let n = self.len()?;
        self.take(n)
    }

    fn str(&mut self) -> Result<String> {
        String::from_utf8(self.bytes()?.to_vec())
            .map_err(|_| Error::Corrupt("a name is not utf-8".into()))
    }

    fn opt_str(&mut self) -> Result<Option<String>> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.str()?)),
            _ => Err(Error::Corrupt("bad option".into())),
        }
    }

    fn nodes(&mut self, depth: usize) -> Result<Vec<Node>> {
        if depth > MAX_DEPTH {
            return Err(Error::Corrupt("groups nested too deep".into()));
        }
        let count = self.len()?;
        // Every node takes at least 2 bytes, so a lying count can't over-allocate.
        let mut list = Vec::with_capacity(count.min(self.0.len() / 2));
        for _ in 0..count {
            list.push(match self.u8()? {
                ENTRY => Node::Entry(Entry {
                    name: self.str()?,
                    mime: self.opt_str()?,
                    sensitive: match self.u8()? {
                        0 => false,
                        1 => true,
                        _ => return Err(Error::Corrupt("bad flag".into())),
                    },
                    data: self.bytes()?.to_vec(),
                }),
                GROUP => Node::Group(Group {
                    name: self.opt_str()?,
                    entries: self.nodes(depth + 1)?,
                }),
                _ => return Err(Error::Corrupt("unknown node".into())),
            });
        }
        Ok(list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle() -> Bundle {
        Bundle {
            title: Some("Staging".into()),
            note: Some("rotate after use".into()),
            entries: vec![
                Node::Entry(Entry::text("token", "s3cret", true)),
                Node::Group(Group {
                    name: Some("github".into()),
                    entries: vec![
                        Node::Entry(Entry::text("username", "dax", false)),
                        Node::Group(Group::default()),
                    ],
                }),
                Node::Entry(Entry {
                    name: "logo.png".into(),
                    data: vec![0x89, b'P', b'N', b'G', 0, 255],
                    mime: None,
                    sensitive: false,
                }),
            ],
        }
    }

    #[test]
    fn bundles_round_trip() {
        let b = bundle();
        assert_eq!(Bundle::decode(&b.encode()).unwrap(), b);
        assert_eq!(b.entry_count(), 3);
        let empty = Bundle::default();
        assert_eq!(Bundle::decode(&empty.encode()).unwrap(), empty);
    }

    #[test]
    fn debug_hides_entry_data() {
        let debug = format!("{:?}", bundle());
        assert!(!debug.contains("s3cret"), "{debug}");
    }

    #[test]
    fn malformed_bundles_fail() {
        let bytes = bundle().encode();
        for cut in 0..bytes.len() {
            assert!(Bundle::decode(&bytes[..cut]).is_err(), "cut at {cut}");
        }
        let mut extra = bytes.to_vec();
        extra.push(0);
        assert!(Bundle::decode(&extra).is_err());
        // A huge count with nothing behind it.
        assert!(Bundle::decode(&[1, 0, 0, 255, 255, 255, 255]).is_err());
    }

    #[test]
    fn nesting_is_bounded() {
        let mut node = Node::Group(Group::default());
        for _ in 0..MAX_DEPTH + 2 {
            node = Node::Group(Group {
                name: None,
                entries: vec![node],
            });
        }
        let deep = Bundle {
            entries: vec![node],
            ..Bundle::default()
        };
        assert!(Bundle::decode(&deep.encode()).is_err());
    }
}
