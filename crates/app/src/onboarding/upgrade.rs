//! DELETABLE(v1-migrate): remove once existing v1 users have migrated to v2.
//!
//! An unlock that moved a v1 store to v2 comes back with a new recovery kit
//! for every vault it moved. They show here one at a time, on the same save
//! step a created vault uses, and the vault opens after the last.

use deadbolt_client::{Launch, Paths};
use deadbolt_proto::daemon::{Command, MigratedVault, Reply, Status};
use rune::Tx;

use super::worker::RecoveryKit;
use super::{Recovery, Step};
use crate::daemon::{Done, Failure};
use crate::model::{App, Screen};

/// Sends an unlock and reads its reply: [`Done::Upgraded`] when it moved
/// vaults, [`Done::Unlocked`] otherwise.
pub(crate) async fn unlock(paths: &Paths, launch: &Launch, command: Command) -> Done {
    let result = async {
        deadbolt_client::ensure_running(paths, launch).await?;
        let reply = deadbolt_client::simple(paths, command).await?;
        let status = deadbolt_client::status(paths).await;
        Ok::<_, deadbolt_client::Error>((reply, status))
    }
    .await
    .map_err(Failure::from);
    match result {
        Err(failure) => Done::Unlocked(Err(failure)),
        Ok((_, None)) => Done::Unlocked(Err(Failure {
            code: None,
            message: "The daemon stopped.".into(),
        })),
        Ok((Reply::Unlocked { migrated }, Some(status))) if !migrated.is_empty() => {
            Done::Upgraded {
                status: Box::new(status),
                migrated,
            }
        }
        Ok((_, Some(status))) => Done::Unlocked(Ok(status)),
    }
}

impl Recovery {
    /// The next moved vault's kit, carrying the ones after it.
    pub(super) fn take_next(&mut self) -> Option<Box<Recovery>> {
        if self.then.is_empty() {
            return None;
        }
        let mut next = self.then.remove(0);
        next.then = std::mem::take(&mut self.then);
        Some(Box::new(next))
    }
}

impl App {
    /// The unlock moved these vaults: show each one's words before the vault
    /// opens. A lock or close drops them all, like a created vault's.
    pub(crate) fn on_upgraded(
        &mut self,
        status: Status,
        migrated: Vec<MigratedVault>,
        tx: &mut Tx,
    ) {
        let of = migrated.len();
        let mut kits = migrated.into_iter().enumerate().map(|(i, moved)| Recovery {
            id: super::short(&moved.vault.id).to_owned(),
            vault: moved.vault.name,
            kit: RecoveryKit::new(moved.recovery_kit.expose()),
            then: Vec::new(),
            moved: Some((i + 1, of)),
        });
        let Some(mut first) = kits.next() else {
            self.unlocking = false;
            return self.on_status(status, tx);
        };
        first.then = kits.collect();
        self.unlocking = false;
        self.forget_onboarding();
        self.status = Some(status);
        self.show(Screen::Onboarding);
        let o = &mut self.onboarding;
        o.device_ready = true;
        o.step = Step::Recovery(Box::new(first));
        tx.animated();
    }
}

/// What the save step says about a moved vault's words: the `n`th of `of`.
pub(super) fn about(n: usize, of: usize) -> String {
    let which = if of > 1 {
        format!("Vault {n} of {of} moved")
    } else {
        "This vault moved".to_owned()
    };
    format!(
        "Upgraded to Deadbolt v2. {which} under the same passphrase, with these \
         24 words as its new recovery kit. Deadbolt won’t show them again."
    )
}
