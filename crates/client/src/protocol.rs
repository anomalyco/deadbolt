//! The control protocol between the CLI and the agent.
//!
//! Line-delimited JSON over the agent's Unix socket, one request per
//! connection:
//!
//! ```text
//! client -> agent   Request   {"v":1,"cmd":"...",...}
//! agent  -> client  Message*  {"type":"event",...}         pairing only
//! client -> agent   Answer    {"answer":true}               after an event that asks
//! agent  -> client  Message   {"type":"ok",...} | {"type":"error",...}   final
//! ```
//!
//! Pairing events ask for an answer only when the request set `confirm`;
//! otherwise the code is accepted automatically. A client hanging up cancels
//! a pending `join`/`pair`.
//!
//! `watch` keeps the connection open and streams what changed:
//!
//! ```text
//! client -> agent   Request   {"v":2,"cmd":"watch"}
//! agent  -> client  Message*  {"type":"change","change":"watching"}   first
//!                             {"type":"change","change":"items","vault":"…"}
//! agent  -> client  Message   {"type":"ok","reply":"done"}   after "stopping"
//! ```
//!
//! Changes name what changed, never values: clients refetch. They are
//! coalesced, so a burst (a sync batch, an import) arrives as one change per
//! vault. A watcher that can't keep up gets `resync`, or is dropped if it
//! stops reading. The stream ends when the client hangs up or the agent stops.
//!
//! `status` and `stop` are answered whatever `v` says, so a client can always
//! find and replace an agent of an older protocol. They are the only messages
//! exchanged between different builds, so `Request` and `Status` must stay
//! readable by older and newer ones.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const PROTOCOL_VERSION: u32 = 4;

/// The longest line the agent reads, large enough for `import` of a big export.
pub const MAX_LINE: usize = 64 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    pub v: u32,
    #[serde(flatten)]
    pub command: Command,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "kebab-case")]
pub enum Command {
    Status,
    Stop,
    /// First run: create the device key and store, leaving it unlocked.
    Setup {
        passphrase: Zeroizing<String>,
        device_name: String,
    },
    Unlock {
        passphrase: Zeroizing<String>,
        /// Idle timeout in seconds; `None` uses the config file, `Some(0)` never locks.
        timeout_secs: Option<u64>,
    },
    Lock,
    /// Streams [`Change`]s until the client hangs up or the agent stops.
    Watch,
    VaultCreate {
        name: String,
    },
    VaultList,
    VaultRename {
        vault: String,
        name: String,
    },
    VaultDefault {
        vault: String,
    },
    Devices {
        vault: Option<String>,
    },
    DeviceRemove {
        vault: Option<String>,
        device: String,
    },
    Sync {
        vault: Option<String>,
    },
    /// Emits `ticket`, then `joining` (answered if `confirm`), then replies `vault`.
    Join {
        confirm: bool,
    },
    /// Emits `pairing` (answered if `confirm`), then replies `device`.
    Pair {
        ticket: String,
        vault: Option<String>,
        confirm: bool,
    },
    /// Creates an item; replies `item`.
    ItemNew {
        vault: Option<String>,
        kind: String,
        name: Option<String>,
        fields: Vec<FieldInput>,
    },
    /// Finds exactly one item, with all field values; replies `item`.
    ItemGet {
        vault: Option<String>,
        query: Vec<String>,
    },
    /// Finds exactly one item and computes its current one-time code from
    /// its `otp` field; replies `code`. The secret itself never leaves.
    ItemCode {
        vault: Option<String>,
        query: Vec<String>,
    },
    /// Lists matching items without field values; replies `items`.
    ItemList {
        vault: Option<String>,
        query: Vec<String>,
        kind: Option<String>,
    },
    /// Sets fields and/or the name (`Some("")` clears it); replies `item`.
    ItemSet {
        vault: Option<String>,
        query: Vec<String>,
        fields: Vec<FieldInput>,
        name: Option<String>,
    },
    ItemUnset {
        vault: Option<String>,
        query: Vec<String>,
        field: String,
    },
    ItemRemove {
        vault: Option<String>,
        query: Vec<String>,
    },
    /// Imports another password manager's export (the text of the file, see
    /// [`crate::export`]); the agent detects the format. Items already in the
    /// vault, or earlier in the export, are skipped as duplicates. With
    /// `apply` it creates all new items or none, in as few entries as fit;
    /// without, it writes nothing. Replies `import`.
    Import {
        vault: Option<String>,
        export: Zeroizing<String>,
        apply: bool,
    },
}

/// A field as typed by the user. Without `kind`, the agent uses the item
/// type's field type, else the field's current type, else `text`.
#[derive(Clone, Serialize, Deserialize)]
pub struct FieldInput {
    pub name: String,
    pub kind: Option<String>,
    pub value: String,
}

impl std::fmt::Debug for FieldInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FieldInput")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("value", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Message {
    Event {
        event: Event,
    },
    /// Streamed by `watch`.
    Change {
        #[serde(flatten)]
        change: Change,
    },
    Ok {
        reply: Reply,
    },
    Error {
        code: ErrorCode,
        message: String,
    },
}

/// What changed in the agent. Vaults are named by id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "change", rename_all = "kebab-case")]
pub enum Change {
    /// The first change: the stream is live. Fetch what you show now.
    Watching,
    Locked,
    Unlocked,
    /// The vault list changed: a vault was created, joined or renamed, its
    /// members changed, or the default moved.
    Vaults,
    /// Items in `vault` changed, written here or received by sync.
    Items {
        vault: String,
    },
    /// Devices were added to or removed from `vault`.
    Devices {
        vault: String,
    },
    /// Changes were dropped because the watcher fell behind. Fetch everything.
    Resync,
    /// The agent is stopping, which locks the store. The stream ends.
    Stopping,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorCode {
    /// The request needs the store unlocked.
    Locked,
    /// No device is set up yet.
    NotInitialized,
    /// The request's protocol version is not supported.
    Version,
    Failed,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
pub enum Event {
    /// The new device's pairing ticket.
    Ticket { ticket: String },
    /// The joining side's confirmation code and the vault it is joining.
    Joining {
        code: String,
        vault: String,
        inviter: DeviceInfo,
    },
    /// The inviting side's confirmation code.
    Pairing { code: String, device: String },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Answer {
    pub answer: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "kebab-case")]
pub enum Reply {
    Status(Box<Status>),
    Done,
    Vault {
        vault: VaultInfo,
    },
    Vaults {
        vaults: Vec<VaultInfo>,
    },
    /// A device added to (`pair`) or removed from (`device-remove`) a vault.
    Device {
        vault: VaultInfo,
        device: DeviceInfo,
    },
    Devices {
        devices: Vec<DeviceInfo>,
    },
    Sync {
        peers: Vec<PeerSync>,
    },
    Item {
        item: ItemInfo,
    },
    Items {
        items: Vec<ItemInfo>,
    },
    Import {
        report: ImportReport,
    },
    Code {
        code: Code,
    },
}

/// A one-time code and when it stops being valid.
#[derive(Clone, Serialize, Deserialize)]
pub struct Code {
    pub code: Zeroizing<String>,
    /// Seconds each code lasts.
    pub period: u64,
    /// Unix seconds when the next code takes over.
    pub valid_until: u64,
}

impl fmt::Debug for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Code")
            .field("code", &"<redacted>")
            .field("period", &self.period)
            .field("valid_until", &self.valid_until)
            .finish()
    }
}

/// What an import did, or would do. Counts only, never values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportReport {
    pub source: ImportSource,
    /// New items by item type; duplicates are not counted here.
    pub new: BTreeMap<String, usize>,
    /// Items already in the vault, or earlier in the export.
    pub duplicates: usize,
    /// Items not imported, by reason.
    pub skipped: Vec<Tally>,
    /// Values not imported or imported differently, by reason.
    pub warnings: Vec<Tally>,
    /// What deadbolt has no place for (folders, favorites, attachments, ...).
    pub dropped: Vec<Tally>,
}

/// The app an export came from, detected from its content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImportSource {
    Bitwarden,
    OnePassword,
    ApplePasswords,
    /// A CSV with recognizable columns, such as a browser's export.
    Csv,
}

impl fmt::Display for ImportSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Bitwarden => "Bitwarden",
            Self::OnePassword => "1Password",
            Self::ApplePasswords => "Apple Passwords",
            Self::Csv => "CSV",
        })
    }
}

/// The item types clients name, in the order they list them: the type, then
/// what one and several are called.
pub const KINDS: [(&str, &str, &str); 5] = [
    ("login", "login", "logins"),
    ("card", "card", "cards"),
    ("note", "secure note", "secure notes"),
    ("ssh", "SSH key", "SSH keys"),
    ("identity", "identity", "identities"),
];

/// What `count` items of type `kind` are called: "secure note", "SSH keys".
/// A type this version doesn't know is called by its identifier.
pub fn noun(kind: &str, count: usize) -> &str {
    KINDS
        .iter()
        .find(|(k, ..)| *k == kind)
        .map_or(kind, |(_, one, many)| if count == 1 { one } else { many })
}

/// The field an item is for, which clients copy or print by default: a
/// login's password, a card's number, a secure note's body, an SSH key's
/// private key, an identity's email. `None` for a type this version
/// doesn't know.
pub fn primary_field(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "login" => "password",
        "card" => "number",
        "note" => "notes",
        "ssh" => "private-key",
        "identity" => "email",
        _ => return None,
    })
}

/// A count of something, named in the singular and the plural.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tally {
    pub count: usize,
    pub one: String,
    pub many: String,
}

impl fmt::Display for Tally {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = if self.count == 1 {
            &self.one
        } else {
            &self.many
        };
        write!(f, "{} {what}", self.count)
    }
}

impl ImportReport {
    /// How many new items of type `kind`.
    pub fn count(&self, kind: &str) -> usize {
        self.new.get(kind).copied().unwrap_or(0)
    }

    /// How many new items in all.
    pub fn total(&self) -> usize {
        self.new.values().sum()
    }

    /// New items by type, in [`KINDS`] order then by identifier, leaving out
    /// types with none: `[("login", 12), ("note", 3)]`.
    pub fn counts(&self) -> Vec<(&str, usize)> {
        let known = KINDS.iter().map(|(kind, ..)| *kind);
        let other = self
            .new
            .keys()
            .map(String::as_str)
            .filter(|k| !KINDS.iter().any(|(kind, ..)| kind == k));
        known
            .chain(other)
            .map(|kind| (kind, self.count(kind)))
            .filter(|(_, n)| *n > 0)
            .collect()
    }

    /// The report as lines of text; `applied` is false for a preview.
    pub fn lines(&self, applied: bool) -> Vec<String> {
        // Logins and cards always, the other types when there are some.
        let mut kinds = vec!["login", "card"];
        kinds.extend(
            self.counts()
                .into_iter()
                .map(|(kind, _)| kind)
                .filter(|kind| !matches!(*kind, "login" | "card")),
        );
        let counts: Vec<String> = kinds
            .into_iter()
            .map(|kind| format!("{} {}", noun(kind, 2), self.count(kind)))
            .collect();
        let mut lines = vec![format!(
            "{} {} from {} ({})",
            if applied {
                "imported"
            } else {
                "dry run: would import"
            },
            self.total(),
            self.source,
            counts.join(", ")
        )];
        if self.duplicates > 0 {
            let duplicates = Tally {
                count: self.duplicates,
                one: "duplicate".into(),
                many: "duplicates".into(),
            };
            lines.push(format!("skipped {duplicates}"));
        }
        lines.extend(self.skipped.iter().map(|t| format!("skipped {t}")));
        lines.extend(self.warnings.iter().map(|t| format!("warning: {t}")));
        if !self.dropped.is_empty() {
            let dropped: Vec<String> = self.dropped.iter().map(Tally::to_string).collect();
            lines.push(format!("dropped: {}", dropped.join(", ")));
        }
        lines
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemInfo {
    pub id: String,
    /// Shortest unique id prefix, at least 4 characters.
    pub short: String,
    pub kind: String,
    /// The name, or one derived from the fields.
    pub label: String,
    /// What the item is, if anything says: a login's username, a card's
    /// expiry, an SSH key's comment or fingerprint, an identity's email or
    /// phone. Never a secure note's body.
    pub detail: Option<String>,
    /// Known fields in schema order, then extra fields by name. Empty in lists.
    pub fields: Vec<FieldInfo>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct FieldInfo {
    pub name: String,
    pub kind: String,
    pub value: String,
}

impl std::fmt::Debug for FieldInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FieldInfo")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("value", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub pid: u32,
    pub version: String,
    pub protocol: u32,
    /// The agent's executable, so a client that can't use it can say which one runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    /// The store directory this agent serves.
    pub home: String,
    pub initialized: bool,
    pub unlocked: bool,
    /// Seconds until the idle timeout locks the store.
    pub locks_in_secs: Option<u64>,
    pub device: Option<DeviceInfo>,
    pub vaults: Vec<VaultInfo>,
    pub peers_online: usize,
    pub peers: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultInfo {
    pub id: String,
    pub name: String,
    pub default: bool,
    pub members: usize,
    /// Whether this device is still a member.
    pub member: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: String,
    pub name: Option<String>,
    pub this: bool,
    pub connected: bool,
    /// Unix seconds of the last successful sync with this device.
    pub last_seen: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerSync {
    pub device: DeviceInfo,
    pub sent: usize,
    pub received: usize,
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_debug_redacts_values() {
        let input = FieldInput {
            name: "password".into(),
            kind: None,
            value: "private-marker".into(),
        };
        let info = FieldInfo {
            name: "notes".into(),
            kind: "secret".into(),
            value: "private-marker".into(),
        };
        for debug in [format!("{input:?}"), format!("{info:?}")] {
            assert!(debug.contains("<redacted>"), "{debug}");
            assert!(!debug.contains("private-marker"), "{debug}");
        }
    }

    #[test]
    fn import_reports_read_as_lines() {
        let tally = |count, one: &str, many: &str| Tally {
            count,
            one: one.into(),
            many: many.into(),
        };
        let report = ImportReport {
            source: ImportSource::OnePassword,
            new: [("login".into(), 3), ("card".into(), 1)].into(),
            duplicates: 2,
            skipped: vec![tally(1, "secure note", "secure notes")],
            warnings: vec![tally(2, "URL kept as text", "URLs kept as text")],
            dropped: vec![tally(1, "favorite", "favorites"), tally(3, "tag", "tags")],
        };
        assert_eq!(
            report.lines(true),
            [
                "imported 4 from 1Password (logins 3, cards 1)",
                "skipped 2 duplicates",
                "skipped 1 secure note",
                "warning: 2 URLs kept as text",
                "dropped: 1 favorite, 3 tags",
            ]
        );
        let kinds = ImportReport {
            source: ImportSource::Bitwarden,
            new: [
                ("identity".into(), 1),
                ("note".into(), 2),
                ("ssh".into(), 1),
                ("future".into(), 1),
            ]
            .into(),
            duplicates: 0,
            skipped: vec![],
            warnings: vec![],
            dropped: vec![],
        };
        assert_eq!(
            kinds.lines(true),
            [
                "imported 5 from Bitwarden (logins 0, cards 0, secure notes 2, SSH keys 1, identities 1, future 1)"
            ]
        );
        assert_eq!(
            kinds.counts(),
            [("note", 2), ("ssh", 1), ("identity", 1), ("future", 1)]
        );
        assert_eq!(
            (noun("ssh", 1), noun("identity", 2)),
            ("SSH key", "identities")
        );
        let empty = ImportReport {
            source: ImportSource::ApplePasswords,
            new: BTreeMap::new(),
            duplicates: 1,
            skipped: vec![],
            warnings: vec![],
            dropped: vec![],
        };
        assert_eq!(
            empty.lines(false),
            [
                "dry run: would import 0 from Apple Passwords (logins 0, cards 0)",
                "skipped 1 duplicate",
            ]
        );
        let json = serde_json::to_string(&Reply::Import { report: empty }).unwrap();
        assert!(json.contains(r#""source":"apple-passwords""#), "{json}");
    }

    #[test]
    fn watch_round_trips_as_flat_json_lines() {
        let request = serde_json::to_string(&Request {
            v: PROTOCOL_VERSION,
            command: Command::Watch,
        })
        .unwrap();
        assert_eq!(request, r#"{"v":4,"cmd":"watch"}"#);
        assert!(matches!(
            serde_json::from_str::<Request>(&request).unwrap().command,
            Command::Watch
        ));
        let changes = [
            (Change::Watching, r#"{"type":"change","change":"watching"}"#),
            (Change::Locked, r#"{"type":"change","change":"locked"}"#),
            (Change::Unlocked, r#"{"type":"change","change":"unlocked"}"#),
            (Change::Vaults, r#"{"type":"change","change":"vaults"}"#),
            (
                Change::Items { vault: "ab".into() },
                r#"{"type":"change","change":"items","vault":"ab"}"#,
            ),
            (
                Change::Devices { vault: "ab".into() },
                r#"{"type":"change","change":"devices","vault":"ab"}"#,
            ),
            (Change::Resync, r#"{"type":"change","change":"resync"}"#),
            (Change::Stopping, r#"{"type":"change","change":"stopping"}"#),
        ];
        for (change, json) in changes {
            let line = serde_json::to_string(&Message::Change {
                change: change.clone(),
            })
            .unwrap();
            assert_eq!(line, json);
            match serde_json::from_str::<Message>(&line).unwrap() {
                Message::Change { change: back } => assert_eq!(back, change),
                other => panic!("expected a change, got {other:?}"),
            }
        }
    }
}
