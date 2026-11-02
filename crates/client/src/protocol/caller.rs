//! Who is on the other end of the daemon's socket (`docs/agent-control.md`,
//! "Who is asking"), and the Activity list of what callers did. Never values.

use serde::{Deserialize, Serialize};

/// What a client says about who is driving it, from `DEADBOLT_CALLER` and
/// `OPENCODE_SESSION_ID`. Shown as claimed and never trusted: it labels an
/// entry, and never changes a caller's [`CallerClass`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub caller: Option<String>,
    pub opencode_session: Option<String>,
}

impl Claim {
    pub fn is_empty(&self) -> bool {
        self.caller.is_none() && self.opencode_session.is_none()
    }
}

/// How the daemon sorts a connection, from what it verified about the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CallerClass {
    /// Deadbolt.app, from the daemon's own bundle.
    App,
    /// This build's `deadbolt browser-host`, run by a browser.
    BrowserHost,
    /// Deadbolt's macOS AutoFill Credential Provider extension
    /// (`Contents/PlugIns/DeadboltAutoFill.appex`).
    AutoFill,
    /// Anything else, Kit's own terminal included.
    Caller,
}

/// What the class rests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Check {
    /// The peer's code signature, looked up by its audit token (macOS).
    Signature,
    /// Nothing verified, on Linux: the program and its parents come from
    /// `/proc`, which a process can race, so they label it and no more.
    Unverified,
    /// Nothing could be verified: the peer is a caller.
    None,
}

/// How a Linux caller is marked, in its label and by whoami.
pub const UNVERIFIED_LINUX: &str = "unverified (Linux)";

/// A code signature as the daemon verified it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub signing_id: Option<String>,
    /// Only when the signature chains to Apple for this team.
    pub team_id: Option<String>,
    /// The running code directory's hash, hex.
    pub cdhash: Option<String>,
    /// Whether the signature checks out (ad-hoc signatures can).
    pub valid: bool,
}

/// One of the peer's parents, nearest first. Read by pid: a hint for the
/// label, never a basis for trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ancestor {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
}

/// How the daemon sees one connection's peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallerInfo {
    pub class: CallerClass,
    pub check: Check,
    pub pid: u32,
    /// With `pid`, names the process even after the pid is reused: the audit
    /// token's pid version on macOS, the start time in clock ticks on Linux.
    pub pid_version: Option<u64>,
    pub uid: Option<u32>,
    pub program: Option<String>,
    pub signature: Option<Signature>,
    /// The controlling terminal.
    pub tty: Option<String>,
    /// When the process started, Unix seconds.
    pub started: Option<u64>,
    /// When its session (its terminal tab, for a shell) started, Unix seconds.
    pub session_started: Option<u64>,
    pub ancestry: Vec<Ancestor>,
    /// Who it is in a few words ("OpenCode › zsh"), from verified facts and
    /// ancestry, never from the claim.
    pub label: String,
    pub claimed: Option<Claim>,
}

impl CallerInfo {
    /// A caller nothing is known about but `label`.
    pub fn unverified(label: &str) -> CallerInfo {
        CallerInfo {
            class: CallerClass::Caller,
            check: Check::None,
            pid: 0,
            pid_version: None,
            uid: None,
            program: None,
            signature: None,
            tty: None,
            started: None,
            session_started: None,
            ancestry: Vec::new(),
            label: label.into(),
            claimed: None,
        }
    }
}

/// What a command could expose (`docs/agent-control.md`, "Tiers").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tier {
    Look,
    Use,
    Read,
    Add,
    Write,
    Never,
    /// `status`, `stop`, `lock`, `generate`, `sync`.
    Always,
    /// Site commands, for the browser host.
    Browser,
    /// Agent sign-ins: a paired client using its standing grants.
    Agent,
}

/// How a request ended. Only agent sign-ins are refused so far: a client
/// that isn't paired, a grant that doesn't cover the request, a client past
/// its rate limit, or an AI pairing or granting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Allowed,
    Locked,
    Refused,
    Failed,
}

/// Something the app showed or copied, which the daemon can't see itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AppAction {
    Reveal,
    Copy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityItem {
    /// The vault as the request named it, or its id; `None` for the default.
    pub vault: Option<String>,
    pub id: Option<String>,
    /// The item's title, or the query that named it when none matched.
    pub title: String,
}

/// One Activity entry. Never a value: field names only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityEntry {
    /// Increasing; assigned when the entry is stored.
    pub id: u64,
    /// Unix seconds.
    pub time: u64,
    pub caller: CallerInfo,
    pub tier: Tier,
    /// The protocol command (`item-get`), or `reveal`/`copy` for the app.
    pub command: String,
    pub items: Vec<ActivityItem>,
    pub fields: Vec<String>,
    pub outcome: Outcome,
    /// How many requests this entry stands for that aren't listed one by
    /// one: past a caller's limit (`more-past-limit`), while locked
    /// (`more-while-locked`), or dropped to keep within the store's budget
    /// (`more-past-budget`). 0 for an ordinary entry.
    #[serde(default)]
    pub more: u64,
    /// The paired agent client the request came from (its name, else its
    /// id), for agent sign-ins: the token proved it, unlike a claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
}
