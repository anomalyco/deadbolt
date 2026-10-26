//! Importing another password manager's export. A file dropped on the window
//! or picked with Choose File… is read on the agent thread and previewed (the
//! agent says what it would import); confirming imports it. The export's
//! text never leaves that thread: the UI holds only the agent's report.
//! Locking, or the agent stopping, forgets an import wherever it was.

pub mod view;

use std::path::{Path, PathBuf};
use std::time::Duration;

use deadbolt_client::protocol::{ErrorCode, ImportReport, Tally};
use rune::{FileDialogOptions, Key, KeyEvent, Tx};

use crate::agent::{ImportFailure, Job};
use crate::model::{App, Screen};
use crate::onboarding::{Notice, Severity};

/// What the window takes from a drag, and Choose File… offers.
pub const EXTENSIONS: &[&str] = &["1pux", "csv", "json"];
/// The menu item, also ⇧⌘I in the main window.
pub const MENU: &str = "Import Passwords…";
/// How long "Imported 12 from 1Password" stays.
const IMPORTED_FOR: f64 = 2.4;

#[derive(Default)]
pub struct Import {
    /// The import view is showing in the detail pane. An empty vault always
    /// shows the drop zone.
    pub open: bool,
    /// A file the window takes is being dragged over it.
    pub hover: bool,
    pub phase: Phase,
    /// Why the last file wasn't previewed or imported.
    pub error: Option<Notice>,
    /// "Imported 12 from 1Password", and when.
    pub imported: Option<(String, f64)>,
    /// Tells the current file's replies from older ones; bumped on forgetting.
    seq: u64,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub enum Phase {
    #[default]
    Idle,
    /// Choose File…'s dialog is up.
    Choosing,
    /// Reading the file and asking the agent what it would import.
    Reading {
        path: PathBuf,
        name: String,
    },
    Preview(Preview),
    Importing(Preview),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Preview {
    /// Read again to import, so the text is never kept.
    pub path: PathBuf,
    pub name: String,
    pub report: ImportReport,
}

impl Preview {
    pub fn new_items(&self) -> usize {
        self.report.logins + self.report.cards
    }
}

impl Import {
    /// The detail pane shows the import view rather than an item.
    pub fn showing(&self) -> bool {
        self.open || self.hover || self.phase != Phase::Idle
    }

    /// The preview or the import it confirmed.
    pub fn preview(&self) -> Option<(&Preview, bool)> {
        match &self.phase {
            Phase::Preview(p) => Some((p, false)),
            Phase::Importing(p) => Some((p, true)),
            _ => None,
        }
    }

    pub fn busy(&self) -> bool {
        matches!(
            self.phase,
            Phase::Choosing | Phase::Reading { .. } | Phase::Importing(_)
        )
    }
}

impl App {
    /// "Import Passwords…": the import view, in the vault.
    pub fn show_import(&mut self) {
        if self.screen != Screen::Vault || self.panel.is_some() {
            return;
        }
        if let Some(installer) = &mut self.installer {
            installer.open = false;
        }
        self.close_settings();
        self.import.open = true;
    }

    /// Files dropped on the window: the first one it takes is previewed.
    pub fn drop_files(&mut self, files: &[PathBuf]) {
        self.import.hover = false;
        if let Some(path) = files.iter().find(|p| takes(p)) {
            self.read_export(path.clone());
        }
    }

    pub fn drop_hover(&mut self, over: bool) {
        self.import.hover = over && self.screen == Screen::Vault;
    }

    pub fn choose_file(&mut self) {
        if self.import.busy() {
            return;
        }
        self.import.seq += 1;
        self.import.phase = Phase::Choosing;
        self.import.error = None;
        self.import.open = true;
        let options = FileDialogOptions {
            title: MENU.trim_end_matches('…').into(),
            ..FileDialogOptions::default()
        }
        .filter("Exports", EXTENSIONS);
        self.agent
            .choose_file(self.dialogs.clone(), options, self.import.seq);
    }

    fn read_export(&mut self, path: PathBuf) {
        if matches!(self.import.phase, Phase::Importing(_)) {
            return;
        }
        self.import.seq += 1;
        self.import.phase = Phase::Reading {
            name: name(&path),
            path: path.clone(),
        };
        self.import.error = None;
        self.import.open = true;
        self.agent.send(Job::Import {
            path,
            apply: false,
            seq: self.import.seq,
        });
    }

    /// The preview's primary button: imports what's new, or with nothing new, closes.
    pub fn confirm_import(&mut self) {
        let Phase::Preview(preview) = &self.import.phase else {
            return;
        };
        if preview.new_items() == 0 {
            self.cancel_import();
            return;
        }
        let preview = preview.clone();
        self.import.seq += 1;
        self.agent.send(Job::Import {
            path: preview.path.clone(),
            apply: true,
            seq: self.import.seq,
        });
        self.import.phase = Phase::Importing(preview);
    }

    /// Closes the import view, dropping the preview or a file still being
    /// read. An import already confirmed runs to its end.
    pub fn cancel_import(&mut self) {
        if matches!(self.import.phase, Phase::Importing(_)) {
            return;
        }
        self.import.seq += 1;
        self.import.phase = Phase::Idle;
        self.import.error = None;
        self.import.open = false;
    }

    /// Forgets the import wherever it was, and drops replies still on their way.
    pub(crate) fn forget_import(&mut self) {
        let seq = self.import.seq + 1;
        self.import = Import {
            seq,
            ..Import::default()
        };
    }

    pub(crate) fn on_imported(
        &mut self,
        seq: u64,
        apply: bool,
        result: Result<ImportReport, ImportFailure>,
        tx: &mut Tx,
    ) {
        if seq != self.import.seq || self.screen != Screen::Vault {
            return;
        }
        let (path, file) = match &self.import.phase {
            Phase::Reading { path, name } if !apply => (path.clone(), name.clone()),
            Phase::Importing(p) if apply => (p.path.clone(), p.name.clone()),
            _ => return,
        };
        match result {
            Ok(report) if apply && report.logins + report.cards > 0 => {
                let n = report.logins + report.cards;
                self.import.imported =
                    Some((format!("Imported {n} from {}", report.source), self.clock));
                tx.wake_after(Duration::from_secs_f64(IMPORTED_FOR));
                self.import.phase = Phase::Idle;
                self.import.open = false;
                self.search.focused = true;
            }
            // A preview; or an import that found nothing new by then (imported
            // meanwhile from another device or the CLI) shows that instead.
            Ok(report) => {
                self.import.phase = Phase::Preview(Preview {
                    path,
                    name: file,
                    report,
                });
            }
            Err(ImportFailure::Agent(f)) if f.locked() => self.on_locked(tx),
            Err(failure) => {
                self.import.phase = Phase::Idle;
                self.import.error = Some(problem(failure, &file, apply));
            }
        }
    }

    pub(crate) fn on_chosen(&mut self, seq: u64, result: Result<Option<PathBuf>, String>) {
        if seq != self.import.seq || self.import.phase != Phase::Choosing {
            return;
        }
        self.import.phase = Phase::Idle;
        match result {
            Ok(Some(path)) => self.read_export(path),
            Ok(None) => {}
            Err(message) => {
                self.import.error = Some(Notice {
                    severity: Severity::Danger,
                    title: "Couldn't show the file dialog".into(),
                    body: sentence(&message),
                })
            }
        }
    }

    /// Ends "Imported 12 from 1Password" once its time is up. True when it went.
    pub(crate) fn tick_import(&mut self, now: f64) -> bool {
        let gone = self
            .import
            .imported
            .as_ref()
            .is_some_and(|(_, at)| now - at >= IMPORTED_FOR - 1e-3);
        if gone {
            self.import.imported = None;
        }
        gone
    }

    /// Keys while the import view shows: Return imports from a preview and
    /// Escape closes it. ⇧⌘I opens it. `None` for keys it leaves alone.
    pub(crate) fn import_key(&mut self, ev: &KeyEvent) -> Option<bool> {
        if self.screen != Screen::Vault || self.panel.is_some() {
            return None;
        }
        if ev.is_command('i') && ev.mods.shift && !ev.mods.alt && !ev.mods.ctrl {
            self.show_import();
            return Some(true);
        }
        let plain = ev.mods == rune::Mods::default();
        match ev.key {
            Key::Enter if plain => match self.import.phase {
                Phase::Preview(_) => {
                    self.confirm_import();
                    Some(true)
                }
                Phase::Importing(_) => Some(true),
                _ => None,
            },
            Key::Escape if self.import.showing() || self.import.error.is_some() => {
                self.cancel_import();
                Some(true)
            }
            _ => None,
        }
    }
}

/// Whether the window takes this file from a drag.
pub fn takes(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| EXTENSIONS.iter().any(|x| x.eq_ignore_ascii_case(e)))
}

fn name(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}

/// What went wrong, coloured by how serious it is: a file that isn't an
/// export (or one the agent can't map) is the person's to change; a read or
/// agent failure is ours.
fn problem(failure: ImportFailure, file: &str, apply: bool) -> Notice {
    let not_export = |message: &str| Notice {
        severity: Severity::Caution,
        title: format!("{file} isn't an export Deadbolt can read"),
        // The drop zone lists what it can read; the agent's own list would repeat it.
        body: sentence(message.split("; import a ").next().unwrap_or(message)),
    };
    match failure {
        ImportFailure::NotExport(message) => not_export(&message),
        ImportFailure::Agent(f) if !apply && f.code == Some(ErrorCode::Failed) => {
            not_export(&f.message)
        }
        ImportFailure::Read(message) => Notice {
            severity: Severity::Danger,
            title: format!("Couldn't open {file}"),
            body: sentence(&message),
        },
        ImportFailure::Agent(f) => Notice {
            severity: Severity::Danger,
            title: if apply {
                format!("Couldn't import {file}")
            } else {
                format!("Couldn't read {file}")
            },
            body: sentence(&f.message),
        },
    }
}

/// A message as a sentence: capitalised, with a full stop.
fn sentence(message: &str) -> String {
    let mut chars = message.trim().chars();
    let mut out: String = match chars.next() {
        Some(c) => c.to_uppercase().chain(chars).collect(),
        None => return String::new(),
    };
    if !out.ends_with(['.', '!', '?']) {
        out.push('.');
    }
    out
}

pub fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// "12 new logins · 3 cards", "1 new login", "2 new cards".
pub fn new_items(report: &ImportReport) -> String {
    match (report.logins, report.cards) {
        (0, cards) => format!(
            "{} new {}",
            cards,
            if cards == 1 { "card" } else { "cards" }
        ),
        (logins, 0) => format!(
            "{logins} new {}",
            if logins == 1 { "login" } else { "logins" }
        ),
        (logins, cards) => format!(
            "{logins} new {} · {}",
            if logins == 1 { "login" } else { "logins" },
            plural(cards, "card", "cards")
        ),
    }
}

/// What won't come across, quieter under the counts.
pub fn details(report: &ImportReport) -> Vec<String> {
    let list = |tallies: &[Tally]| {
        tallies
            .iter()
            .map(Tally::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut lines = Vec::new();
    if !report.skipped.is_empty() {
        lines.push(format!("Skipped {}", list(&report.skipped)));
    }
    lines.extend(report.warnings.iter().map(Tally::to_string));
    if !report.dropped.is_empty() {
        lines.push(format!(
            "No place in Deadbolt for {}",
            list(&report.dropped)
        ));
    }
    lines
}

/// The primary button: "Import 12 items".
pub fn import_label(n: usize) -> String {
    format!("Import {}", plural(n, "item", "items"))
}

#[cfg(test)]
mod tests {
    use deadbolt_client::protocol::ImportSource;

    use super::*;

    fn report(logins: usize, cards: usize) -> ImportReport {
        ImportReport {
            source: ImportSource::OnePassword,
            logins,
            cards,
            duplicates: 0,
            skipped: Vec::new(),
            warnings: Vec::new(),
            dropped: Vec::new(),
        }
    }

    #[test]
    fn counts_read_naturally() {
        assert_eq!(new_items(&report(12, 3)), "12 new logins · 3 cards");
        assert_eq!(new_items(&report(1, 1)), "1 new login · 1 card");
        assert_eq!(new_items(&report(1, 0)), "1 new login");
        assert_eq!(new_items(&report(0, 2)), "2 new cards");
        assert_eq!(import_label(1), "Import 1 item");
        assert_eq!(import_label(15), "Import 15 items");
    }

    #[test]
    fn the_window_takes_exports_only() {
        for file in ["a.1pux", "b.CSV", "c.json"] {
            assert!(takes(Path::new(file)), "{file}");
        }
        for file in ["a.txt", "b", "c.zip"] {
            assert!(!takes(Path::new(file)), "{file}");
        }
    }

    #[test]
    fn problems_are_coloured_by_whose_they_are() {
        let agent = |code| {
            ImportFailure::Agent(crate::agent::Failure {
                code,
                message: "not a known JSON export; import a 1Password .1pux or .csv, an Apple Passwords or browser .csv, or a Bitwarden .json export".into(),
            })
        };
        let n = problem(agent(Some(ErrorCode::Failed)), "x.json", false);
        assert_eq!(n.severity, Severity::Caution);
        assert_eq!(n.title, "x.json isn't an export Deadbolt can read");
        assert_eq!(n.body, "Not a known JSON export.");
        assert_eq!(
            problem(agent(Some(ErrorCode::Failed)), "x.json", true).severity,
            Severity::Danger
        );
        assert_eq!(
            problem(agent(None), "x.json", false).severity,
            Severity::Danger
        );
        let read = problem(
            ImportFailure::Read("permission denied".into()),
            "x.csv",
            false,
        );
        assert_eq!(
            (read.severity, read.title.as_str(), read.body.as_str()),
            (
                Severity::Danger,
                "Couldn't open x.csv",
                "Permission denied."
            )
        );
    }
}
