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

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const PROTOCOL_VERSION: u32 = 3;

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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldInput {
    pub name: String,
    pub kind: Option<String>,
    pub value: String,
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
}

/// What an import did, or would do. Counts only, never values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportReport {
    pub source: ImportSource,
    /// New logins and cards; duplicates are not counted here.
    pub logins: usize,
    pub cards: usize,
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
    /// The report as lines of text; `applied` is false for a preview.
    pub fn lines(&self, applied: bool) -> Vec<String> {
        let mut lines = vec![format!(
            "{} {} from {} (logins {}, cards {})",
            if applied {
                "imported"
            } else {
                "dry run: would import"
            },
            self.logins + self.cards,
            self.source,
            self.logins,
            self.cards
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
    /// Login username or card expiry, if any.
    pub detail: Option<String>,
    /// Known fields in schema order, then extra fields by name. Empty in lists.
    pub fields: Vec<FieldInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldInfo {
    pub name: String,
    pub kind: String,
    pub value: String,
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
    fn import_reports_read_as_lines() {
        let tally = |count, one: &str, many: &str| Tally {
            count,
            one: one.into(),
            many: many.into(),
        };
        let report = ImportReport {
            source: ImportSource::OnePassword,
            logins: 3,
            cards: 1,
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
        let empty = ImportReport {
            source: ImportSource::ApplePasswords,
            logins: 0,
            cards: 0,
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
        assert_eq!(request, r#"{"v":3,"cmd":"watch"}"#);
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
