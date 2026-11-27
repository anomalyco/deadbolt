//! DELETABLE(v1-migrate): remove once existing v1 users have migrated to v2.
//!
//! What the CLI says when an unlock moved a v1 store to v2, and
//! `deadbolt migrate`, which is that unlock asked for by name.

use std::io::Write;

use anyhow::Result;
#[cfg(feature = "v1-migrate")]
use anyhow::bail;
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
        let mut text = to_json(&migrated)?;
        text.push('\n');
        std::io::stdout().write_all(text.as_bytes())?;
    } else {
        print(&migrated, false)?;
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
pub fn print(migrated: &[MigratedVault], stderr: bool) -> Result<()> {
    if stderr {
        write(migrated, &mut std::io::stderr())
    } else {
        write(migrated, &mut std::io::stdout())
    }
}

fn write(migrated: &[MigratedVault], out: &mut impl Write) -> Result<()> {
    if migrated.is_empty() {
        return Ok(());
    }
    let mut text = Zeroizing::new(String::new());
    let vaults = match migrated.len() {
        1 => "1 vault".to_owned(),
        n => format!("{n} vaults"),
    };
    text.push_str(&format!(
        "Upgraded to Deadbolt v2: moved {vaults} from store.redb, under the same passphrase.\n\
         The old store is kept beside it as store.redb.v1.bak.\n\
         Every vault has a new recovery kit below.\n\
         \n\
         On your other devices, don't unlock after updating: that would make\n\
         a separate copy of each vault there. Move their store.redb aside\n\
         (keep it as a backup), then pair with this device: `deadbolt join`.\n"
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
    out.write_all(text.as_bytes())?;
    out.flush()?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_broken_output_pipe_is_an_error() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let moved = MigratedVault {
            vault: crate::protocol::VaultInfo {
                id: "id".into(),
                name: "personal".into(),
                default: true,
                members: 1,
                member: true,
                error: None,
            },
            items: 0,
            recovery_kit: crate::protocol::Secret::new("test kit"),
        };
        let error = write(&[moved], &mut Broken).unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::BrokenPipe
        );
    }
}
