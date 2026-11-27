//! What the vault shows in the item's place: one pane at a time, so two can
//! never be open together. Every view, key and drop check reads `App::pane`.

use crate::model::{App, Screen};

/// The pane in the vault's main area. Settings, Recently Deleted and
/// Security sit in the item's place; the install page covers the whole
/// vault; Import is the import view in the detail pane.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum VaultPane {
    /// The selected item (or the list's empty state).
    #[default]
    Item,
    /// ⌘,
    Settings,
    /// Recently Deleted (⇧⌘⌫).
    Trash,
    /// Security (⇧⌘H).
    Security,
    /// The command installer's page.
    Install,
    /// Import Passwords… (⇧⌘I, or an export dropped on the window).
    Import,
}

impl VaultPane {
    /// Settings, Recently Deleted and Security take the item page's place
    /// and toolbar; the item, the import view and the install page don't.
    pub fn replaces_item(self) -> bool {
        matches!(
            self,
            VaultPane::Settings | VaultPane::Trash | VaultPane::Security
        )
    }
}

impl App {
    /// Switches the vault's pane, tidying up the one it leaves. The only
    /// place `pane` changes, apart from scenes and tests.
    pub(crate) fn set_pane(&mut self, pane: VaultPane) {
        if pane == VaultPane::Install && self.installer.is_none() {
            return;
        }
        if self.pane == pane {
            return;
        }
        self.health.pending_fix = None;
        match std::mem::replace(&mut self.pane, pane) {
            VaultPane::Item => {}
            // Its file, preview and notice go with it, so nothing of it stays
            // behind the next pane; an import already confirmed runs on.
            VaultPane::Import => {
                self.drop_import();
            }
            VaultPane::Settings => {
                self.nav.row = 0;
                self.hotkey.recorder.cancel();
                self.hotkey.reset_error = None;
                self.touch_id_error = None;
                self.activity.forget();
            }
            VaultPane::Trash => self.trash.forget(),
            VaultPane::Security => {
                self.health.row = 0;
                self.health.error = None;
            }
            // Having seen the page answers the vault's offer.
            VaultPane::Install => {
                if let Some(installer) = &mut self.installer {
                    installer.dismiss();
                }
            }
        }
    }

    /// Back to the item when `pane` is the one showing.
    pub(crate) fn close_pane(&mut self, pane: VaultPane) {
        if self.pane == pane {
            self.set_pane(VaultPane::Item);
        }
    }

    pub fn settings_open(&self) -> bool {
        self.pane == VaultPane::Settings
    }

    pub fn trash_open(&self) -> bool {
        self.pane == VaultPane::Trash
    }

    pub fn security_open(&self) -> bool {
        self.pane == VaultPane::Security
    }

    /// The install page is showing in place of the vault.
    pub fn installing(&self) -> bool {
        self.screen == Screen::Vault && self.pane == VaultPane::Install
    }

    /// The detail pane shows the import view rather than an item: it's the
    /// pane, or a file is being chosen, read, previewed or imported. A drag
    /// over the window shows it too, while it lasts (`App::drop_hovering`).
    pub fn import_showing(&self) -> bool {
        self.pane == VaultPane::Import || self.import.phase != crate::import::Phase::Idle
    }
}
