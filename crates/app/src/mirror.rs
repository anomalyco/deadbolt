//! Syncing from 1Password: Settings' "Sync from 1Password" has the agent
//! mirror 1Password into the default vault, as `deadbolt sync 1password`
//! does, and shows what it did. The agent runs 1Password's CLI; the app only
//! asks, and gets back counts.

use deadbolt_client::protocol::MirrorReport;
use rune::{El, Transition, Tx, col, text};
use rune_kit::Kit;

use crate::agent::{Failure, Job};
use crate::model::App;

#[derive(Default)]
pub struct Mirror {
    pub syncing: bool,
    /// What the last sync did ("12 updated, 3 added"), or why it failed.
    pub result: Option<Result<String, String>>,
    /// The sync running: a reply to an earlier one is dropped.
    seq: u64,
}

impl Mirror {
    /// Forgets the last sync, and drops the reply to one running.
    pub(crate) fn forget(&mut self) {
        self.seq += 1;
        self.syncing = false;
        self.result = None;
    }
}

impl App {
    pub fn sync_one_password(&mut self) {
        if self.mirror.syncing {
            return;
        }
        self.mirror.syncing = true;
        self.mirror.result = None;
        self.mirror.seq += 1;
        self.agent.send(Job::SyncOnePassword {
            seq: self.mirror.seq,
        });
    }

    /// The list follows on its own: the agent's writes come in on the watch.
    pub(crate) fn on_mirrored(
        &mut self,
        seq: u64,
        result: Result<MirrorReport, Failure>,
        tx: &mut Tx,
    ) {
        if !self.mirror.syncing || seq != self.mirror.seq {
            return;
        }
        self.mirror.syncing = false;
        match result {
            Ok(report) => self.mirror.result = Some(Ok(report.summary())),
            Err(failure) if failure.locked() => {
                self.mirror.result = None;
                self.on_locked(tx);
            }
            Err(failure) => self.mirror.result = Some(Err(failure.message)),
        }
    }
}

/// Settings' row: what the last sync did, under its label, and the button.
pub fn setting(s: &App, k: &Kit) -> (El, El) {
    let m = &s.mirror;
    let button = crate::settings::button(if m.syncing { "Syncing…" } else { "Sync now" })
        .disabled(m.syncing)
        .on_press(|s: &mut App| s.sync_one_password())
        .build(k)
        .key("op-sync-button");
    let line = match &m.result {
        Some(Ok(summary)) => text(summary.clone())
            .key("op-sync-result")
            .font(k.ty.text_small)
            .color(k.c.text_base),
        Some(Err(message)) => text(message.clone())
            .key("op-sync-error")
            .font(k.ty.small_medium)
            .color(k.c.danger.fg),
        None => text("Copies new and changed items from the 1Password app")
            .key("about")
            .font(crate::view::theme::FACT.lh(16.0))
            .color(k.c.text_faint),
    };
    let line = line.wrap().w_full().transition(Transition::opacity());
    (col().key("op-sync").w_full().child(line), button)
}
