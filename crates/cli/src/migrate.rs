//! DELETABLE(v1-migrate): remove once existing v1 users have migrated to v2.
//!
//! What the CLI says when an unlock moved a v1 store to v2, and
//! `deadbolt migrate`, which is that unlock asked for by name.

use std::io::Write;

#[cfg(feature = "v1-migrate")]
use anyhow::{Result, bail};
use zeroize::Zeroizing;

#[cfg(feature = "v1-migrate")]
use crate::client;
#[cfg(feature = "v1-migrate")]
use crate::paths::Paths;
#[cfg(feature = "v1-migrate")]
use crate::protocol::Command;
use crate::protocol::{MigratedVault, Reply};

/// `deadbolt migrate`: unlocks a v1 store, which moves it to v2, and shows
/// every moved vault's new recovery kit.
#[cfg(feature = "v1-migrate")]
pub async fn run(paths: &Paths, json: bool, from_stdin: bool) -> Result<()> {
    let status = client::ensure_running(paths).await?;
    if !status.v1_store {
        if status.initialized {
            bail!("this device is already on v2: there is nothing to migrate");
        }
        bail!("there is no v1 store (store.redb) in {}", status.home);
    }
    let passphrase = crate::prompt::passphrase(from_stdin, false)?;
    let command = Command::Unlock {
        passphrase,
        timeout_secs: None,
    };
    let migrated = match client::simple(paths, command).await? {
        Reply::Unlocked { migrated } => migrated,
        Reply::Done => Vec::new(),
        _ => bail!("unexpected reply"),
    };
    if json {
        println!("{}", to_json(&migrated)?.as_str());
    } else {
        print(&migrated, false);
    }
    Ok(())
}

/// The vaults an unlock moved, if it moved any.
pub fn migrated(reply: Reply) -> Vec<MigratedVault> {
    match reply {
        Reply::Unlocked { migrated } => migrated,
        _ => Vec::new(),
    }
}

/// Says what moved and shows each vault's kit, on stdout or (inside
/// another command, whose stdout is its own) stderr. Says nothing when
/// nothing moved.
pub fn print(migrated: &[MigratedVault], stderr: bool) {
    if migrated.is_empty() {
        return;
    }
    let mut text = Zeroizing::new(String::new());
    let vaults = match migrated.len() {
        1 => "1 vault".to_owned(),
        n => format!("{n} vaults"),
    };
    text.push_str(&format!(
        "Upgraded to Deadbolt v2: moved {vaults} from store.redb, under the same passphrase.\n\
         The old store is kept beside it as store.redb.v1.bak.\n\
         Every vault has a new recovery kit below. Your other devices need to\n\
         upgrade too, then pair again with `deadbolt join`.\n"
    ));
    for moved in migrated {
        let default = if moved.vault.default {
            " (default)"
        } else {
            ""
        };
        let items = match moved.items {
            1 => "1 item".to_owned(),
            n => format!("{n} items"),
        };
        text.push_str(&format!("\nVault {}{default}: {items}\n", moved.vault.name));
        text.push_str(&crate::recovery::kit_text(
            &moved.vault.id,
            moved.recovery_kit.expose(),
        ));
    }
    text.push('\n');
    let written = if stderr {
        std::io::stderr().write_all(text.as_bytes())
    } else {
        std::io::stdout().write_all(text.as_bytes())
    };
    if let Err(error) = written {
        tracing::warn!("showing the migrated vaults' kits: {error}");
    }
}

/// `{"migrated": [{vault, name, default, items, recovery_kit}], "backup"}`
/// as one line, built in wiped memory.
#[cfg(feature = "v1-migrate")]
fn to_json(migrated: &[MigratedVault]) -> serde_json::Result<Zeroizing<String>> {
    #[derive(serde::Serialize)]
    struct Vault<'a> {
        vault: &'a str,
        name: &'a str,
        default: bool,
        items: usize,
        recovery_kit: &'a str,
    }
    #[derive(serde::Serialize)]
    struct Out<'a> {
        migrated: Vec<Vault<'a>>,
        backup: &'a str,
    }
    let out = Out {
        migrated: migrated
            .iter()
            .map(|m| Vault {
                vault: &m.vault.id,
                name: &m.vault.name,
                default: m.vault.default,
                items: m.items,
                recovery_kit: m.recovery_kit.expose(),
            })
            .collect(),
        backup: "store.redb.v1.bak",
    };
    let mut bytes = Zeroizing::new(Vec::new());
    serde_json::to_writer(&mut *bytes, &out)?;
    let text = std::mem::take(&mut *bytes);
    Ok(Zeroizing::new(String::from_utf8(text).unwrap_or_else(
        |e| String::from_utf8_lossy(e.as_bytes()).into_owned(),
    )))
}
