//! What one device tells another about how to reach a device: its name and
//! address, learned at pairing and gossiped during sync. Hints, never
//! authority, and not part of the signed vault log.

use core::net::SocketAddr;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// How to reach a device. Addresses and names are hints, never authority.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Addr {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub direct: Vec<SocketAddr>,
}

/// What one device knows about another, passed on to a third.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hint {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub addr: Option<Addr>,
    #[serde(default)]
    pub addr_seen: u64,
}

/// Hints by device id (lowercase hex).
pub type Hints = BTreeMap<String, Hint>;

/// A device name as stored and shown: trimmed, without control characters,
/// at most 64 characters.
pub fn clean_name(name: &str) -> String {
    name.trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect()
}
