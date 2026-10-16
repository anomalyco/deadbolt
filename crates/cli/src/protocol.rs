//! The control protocol between the CLI and the agent.
//!
//! Line-delimited JSON over the agent's Unix socket, one request per
//! connection:
//!
//! ```text
//! client -> agent   Request   {"v":1,"cmd":"...",...}
//! agent  -> client  Message*  {"type":"event",...}         interactive commands only
//! client -> agent   Answer    {"answer":true}               after an event that asks
//! agent  -> client  Message   {"type":"ok",...} | {"type":"error",...}   final
//! ```
//!
//! `status` and `stop` are answered whatever `v` says, so a client can always
//! find and replace an agent of another version.

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;

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
        passphrase: String,
        device_name: String,
    },
    Unlock {
        passphrase: String,
        /// Idle timeout in seconds; `None` uses the config file, `Some(0)` never locks.
        timeout_secs: Option<u64>,
    },
    Lock,
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
    Sync,
    /// Interactive: emits `ticket`, then `confirm-join` (answered), then replies `joined`.
    Join,
    /// Interactive: emits `confirm-pair` (answered), then replies `paired`.
    Pair {
        ticket: String,
        vault: Option<String>,
    },
    // Item commands (set/get/ls/rm/history) go here, each carrying `vault: Option<String>`.
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Message {
    Event { event: Event },
    Ok { reply: Reply },
    Error { code: ErrorCode, message: String },
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
    /// Asks the joining user to compare the code and accept the vault.
    ConfirmJoin {
        code: String,
        vault: String,
        inviter: DeviceInfo,
    },
    /// Asks the inviting user to compare the code.
    ConfirmPair { code: String, device: String },
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
    Devices {
        vault: VaultInfo,
        devices: Vec<DeviceInfo>,
    },
    Sync {
        peers: Vec<PeerSync>,
    },
    Joined {
        vault: VaultInfo,
    },
    Paired {
        vault: VaultInfo,
        device: DeviceInfo,
    },
    Removed {
        vault: VaultInfo,
        device: DeviceInfo,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub pid: u32,
    pub version: String,
    pub protocol: u32,
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
