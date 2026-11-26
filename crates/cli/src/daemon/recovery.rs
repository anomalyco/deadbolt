//! The recovery kit and parking commands: `recovery-rotate`,
//! `device-remove-stolen`, `vault-confirm-reinstated` and `vault-status`.

use std::collections::HashSet;

use anyhow::{Result, bail};
use deadbolt_core::v2::RecoverySecret;

use super::Daemon;
use crate::protocol::{Command, Reply, Secret};

impl Daemon {
    pub(super) fn recovery_command(&self, command: Command) -> Result<Reply> {
        match command {
            Command::DeviceRemoveStolen {
                vault,
                device,
                since_secs,
            } => {
                let (vault, device) = self.with(|s| {
                    let id = s.resolve(vault.as_deref())?;
                    let target = s.resolve_device(&id, &device)?;
                    if target == s.id {
                        bail!("cannot remove this device; remove it from another device");
                    }
                    let info = s.device_info(&target, &HashSet::new());
                    s.remove_stolen(id, target, since_secs.map(|secs| secs.saturating_mul(1000)))?;
                    self.refresh(s);
                    Ok((s.vault_info(&id), info))
                })?;
                self.sync_now.notify_one();
                Ok(Reply::Device { vault, device })
            }
            Command::VaultConfirmReinstated { vault, device } => {
                let vault = self.with(|s| {
                    let id = s.resolve(vault.as_deref())?;
                    let device = super::session::unhex(&device)
                        .map(deadbolt_core::DeviceId::from_bytes)
                        .or_else(|_| s.resolve_device(&id, &device))?;
                    s.confirm_reinstated(id, device)?;
                    Ok(s.vault_info(&id))
                })?;
                self.sync_now.notify_one();
                Ok(Reply::Vault { vault })
            }
            Command::VaultStatus { vault } => Ok(Reply::VaultStates {
                vaults: self.with(|s| {
                    let ids = match vault {
                        Some(query) => vec![s.resolve(Some(&query))?],
                        None => s.vaults.keys().copied().collect(),
                    };
                    ids.iter()
                        .map(|id| super::remote::vault_state(s, id))
                        .collect()
                })?,
            }),
            Command::RecoveryRotate { vault, words } => {
                let (vault, kit) = self.with(|s| {
                    let id = s.resolve(vault.as_deref())?;
                    let new = new_recovery_secret()?;
                    let kit = s.rotate_recovery(id, words.expose(), &new)?;
                    Ok((s.vault_info(&id), kit))
                })?;
                drop(words);
                self.sync_now.notify_one();
                Ok(Reply::RecoveryRotated {
                    vault,
                    recovery_kit: Secret::new(kit.as_str()),
                })
            }
            _ => bail!("not a recovery command"),
        }
    }
}

/// A fresh recovery root, its entropy drawn into a locked, wiped page.
fn new_recovery_secret() -> Result<RecoverySecret> {
    let mut entropy = deadbolt_os::mem::LockedSecret::<32>::new();
    getrandom::fill(&mut entropy[..])?;
    Ok(RecoverySecret::from_bytes(*entropy))
}
