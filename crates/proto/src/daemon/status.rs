//! What a daemon says about itself: its `Status`, and the vaults, devices and
//! peers it reports.

use serde::{Deserialize, Serialize};

use super::CallerInfo;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub pid: u32,
    pub version: String,
    pub protocol: u32,
    /// The daemon's executable, so a client that can't use it can say which one runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    /// The store directory this daemon serves.
    pub home: String,
    pub initialized: bool,
    pub unlocked: bool,
    /// Seconds until the idle timeout locks the store.
    pub locks_in_secs: Option<u64>,
    pub device: Option<DeviceInfo>,
    pub vaults: Vec<VaultInfo>,
    pub peers_online: usize,
    pub peers: usize,
    /// Whether this device has Touch ID hardware and an enrolled finger.
    pub touch_id_available: bool,
    /// Whether Touch ID unlock is turned on in config.toml.
    pub touch_id_enabled: bool,
    /// Whether the locked store can be unlocked with Touch ID right now.
    pub touch_id_ready: bool,
    /// Whether Touch ID is enabled on this store, but its enrolled slot was
    /// reset (expired after 14 days, fingerprint set changed, or passphrase changed).
    pub touch_id_reset: bool,
    /// How the daemon sees the client asking (`deadbolt debug whoami`).
    pub caller: CallerInfo,
    /// A newer Deadbolt for this install, from the daemon's background
    /// check; `deadbolt update` installs it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update: Option<UpdateInfo>,
}

/// A newer Deadbolt the daemon's background check found (docs/releasing.md,
/// "Updater").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateInfo {
    pub version: String,
    /// How this Deadbolt is installed: `app`, `curl`, `standalone`, `brew`,
    /// `npm`, `pnpm`, `bun`, `yarn` or `package` (a JavaScript package
    /// manager that didn't say it has it).
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultInfo {
    pub id: String,
    pub name: String,
    pub default: bool,
    pub members: usize,
    /// Whether this device is still a member.
    pub member: bool,
    /// Present when the history could not be loaded. Membership is unknown,
    /// `members` is zero, and the encrypted entries remain on disk.
    pub error: Option<String>,
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
