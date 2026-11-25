//! A Deadbolt Send share, as its sender sees it, and how receivers reach the
//! daemon that serves it.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A Deadbolt Send share, as its sender sees it. Never its secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendInfo {
    pub id: String,
    pub label: String,
    /// Sealed bytes.
    pub size: u64,
    /// Unix seconds.
    pub created: u64,
    pub expires: u64,
    /// How many times it may be opened.
    pub opens: u32,
    /// When each open happened, Unix seconds.
    pub opened: Vec<u64>,
    pub revoked: Option<u64>,
    pub state: SendState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SendState {
    Open,
    PickedUp,
    Expired,
    Revoked,
}

impl fmt::Display for SendState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Open => "open",
            Self::PickedUp => "picked up",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        })
    }
}

/// The address of the daemon's send endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderInfo {
    /// The endpoint id, 64 hex digits: a key of its own, not the device's.
    pub id: String,
    pub relay_url: Option<String>,
    pub direct_addrs: Vec<String>,
}
