//! Importing another password manager's export. A file dropped on the window
//! or picked with Choose File… is read on the agent thread and previewed (the
//! agent says what it would import); confirming imports it. The export's
//! text never leaves that thread: the UI holds only the agent's report.
//! Locking, or the agent stopping, forgets an import wherever it was.

pub mod view;

use std::path::{Path, PathBuf};
use std::time::Duration;

use deadbolt_client::protocol::{ErrorCode, ImportReport, Tally, noun};
use rune::{FileDialogOptions, Key, KeyEvent, Tx};

use crate::agent::{ImportFailure, Imported, Job};
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
    /// A file the window takes is being dragged over it. Read it through
    /// `App::drop_hovering`, which ignores it while the window takes no drops.
    pub(crate) hover: bool,
    pub phase: Phase,
    /// Why the last file wasn't previewed or imported.
    pub error: Option<Notice>,
    /// "Imported 12 from 1Password", and when.
    pub imported: Option<(String, f64)>,
    /// Tells the current file's replies from older ones; bumped on forgetting.
    seq: u64,
    /// Choose File…'s dialog is up, answering for this `seq`. It outlives
    /// a cancel or a lock, and a Choose File… meanwhile takes it over rather
    /// than asking for a second (which Rune refuses).
    dialog: Option<u64>,
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
    /// The export as previewed: it imports only while the file still has it.
    pub digest: blake3::Hash,
    /// The file changed between the last preview and Import, so this is a
    /// fresh preview and nothing was imported.
    pub changed: bool,
}

impl Preview {
    pub fn new_items(&self) -> usize {
        self.report.total()
    }

    /// Nothing new, and that's because it's all here already (rather than
    /// the export holding nothing Deadbolt takes).
    pub fn all_here(&self) -> bool {
        self.new_items() == 0 && self.report.duplicates > 0
    }
}

impl Import {
    /// The detail pane shows the import view rather than an item. A drag
    /// over the window shows it too, while it lasts (`App::drop_hovering`).
    pub fn showing(&self) -> bool {
        self.open || self.phase != Phase::Idle
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
        if self.screen != Screen::Vault || self.panel.is_some() || !self.leave_edit() {
            return;
        }
        self.edit.delete = None;
        if let Some(installer) = self.installer.as_mut().filter(|i| i.open) {
            installer.close();
        }
        self.close_settings();
        self.import.open = true;
    }

    /// The window takes dropped files: the vault is showing, not the install page.
    pub fn accepts_drops(&self) -> bool {
        self.screen == Screen::Vault && !self.installing() && !self.editing() && !self.deleting()
    }

    /// An export is being dragged over the window, which would take it.
    pub fn drop_hovering(&self) -> bool {
        self.import.hover && self.accepts_drops()
    }

    /// Files dropped on the window: the first one it takes is previewed.
    pub fn drop_files(&mut self, files: &[PathBuf]) {
        self.import.hover = false;
        if let Some(path) = files.iter().find(|p| takes(p)) {
            self.read_export(path.clone());
        }
    }

    pub fn drop_hover(&mut self, over: bool) {
        self.import.hover = over && self.accepts_drops();
    }

    /// Files dropped that aren't exports: says so, unless an export dropped
    /// with them is being read.
    pub fn drop_rejected(&mut self, files: &[PathBuf]) {
        self.import.hover = false;
        let Some(file) = files.first() else { return };
        if !self.accepts_drops() || self.import.busy() {
            return;
        }
        self.import.seq += 1;
        self.import.phase = Phase::Idle;
        self.import.open = true;
        self.import.error = Some(Notice {
            severity: Severity::Caution,
            title: format!("{} isn't an export Deadbolt can read", name(file)),
            body: "Drop a .1pux, .csv or .json export.".into(),
        });
    }

    pub fn choose_file(&mut self, tx: &mut Tx) {
        if self.import.busy() {
            return;
        }
        self.import.seq += 1;
        // The view opens once there's a file (or the dialog fails), so
        // cancelling it leaves the vault as it was.
        self.import.phase = Phase::Choosing;
        self.import.error = None;
        let options = FileDialogOptions {
            title: MENU.trim_end_matches('…').into(),
            ..FileDialogOptions::default()
        }
        .filter("Exports", EXTENSIONS);
        if self.import.dialog.replace(self.import.seq).is_none() {
            tx.open_file(options, |s: &mut App, result, _| {
                if let Some(seq) = s.import.dialog.take() {
                    s.on_chosen(seq, result.map_err(|e| e.to_string()));
                }
            });
        }
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
            apply: None,
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
            apply: Some(preview.digest),
            seq: self.import.seq,
        });
        self.import.phase = Phase::Importing(preview);
    }

    /// Closes the import view, dropping the preview or a file still being
    /// read. An import already confirmed runs to its end.
    pub fn cancel_import(&mut self) {
        self.import.hover = false;
        if matches!(self.import.phase, Phase::Importing(_)) {
            return;
        }
        self.import.seq += 1;
        self.import.phase = Phase::Idle;
        self.import.error = None;
        self.import.open = false;
        // A search typed while it showed now picks the item that shows.
        self.keep_selection_visible();
    }

    /// Forgets the import wherever it was, and drops replies still on their way.
    pub(crate) fn forget_import(&mut self) {
        let seq = self.import.seq + 1;
        self.import = Import {
            seq,
            dialog: self.import.dialog,
            ..Import::default()
        };
    }

    pub(crate) fn on_imported(
        &mut self,
        seq: u64,
        applied: bool,
        result: Result<Imported, ImportFailure>,
        tx: &mut Tx,
    ) {
        if seq != self.import.seq || self.screen != Screen::Vault {
            return;
        }
        let (path, file, previewed) = match &self.import.phase {
            Phase::Reading { path, name } => (path.clone(), name.clone(), None),
            Phase::Importing(p) => (p.path.clone(), p.name.clone(), Some(p.digest)),
            _ => return,
        };
        match result {
            Ok(Imported::Done(report)) if report.total() > 0 => {
                let n = report.total();
                self.import.imported =
                    Some((format!("Imported {n} from {}", report.source), self.clock));
                tx.wake_after(Duration::from_secs_f64(IMPORTED_FOR));
                self.import.phase = Phase::Idle;
                self.import.open = false;
                self.search.focused = true;
            }
            // An import that found nothing new by then (imported meanwhile
            // from another device or the CLI) says so in place of the preview.
            Ok(Imported::Done(report)) => {
                let Some(digest) = previewed else { return };
                self.import.phase = Phase::Preview(Preview {
                    path,
                    name: file,
                    report,
                    digest,
                    changed: false,
                });
            }
            Ok(Imported::Preview {
                report,
                digest,
                changed,
            }) => {
                self.import.phase = Phase::Preview(Preview {
                    path,
                    name: file,
                    report,
                    digest,
                    changed,
                });
            }
            Err(ImportFailure::Agent(f)) if f.locked() => self.on_locked(tx),
            Err(failure) => {
                self.import.phase = Phase::Idle;
                self.import.error = Some(problem(failure, &file, applied));
            }
        }
        // A search typed while the import ran now picks the item that shows.
        if !self.import.showing() {
            self.keep_selection_visible();
        }
    }

    fn on_chosen(&mut self, seq: u64, result: Result<Option<PathBuf>, String>) {
        if seq != self.import.seq || self.import.phase != Phase::Choosing {
            return;
        }
        self.import.phase = Phase::Idle;
        match result {
            Ok(Some(path)) => self.read_export(path),
            // Cancelled: the vault stays as it was.
            Ok(None) => {}
            // Linux without a FileChooser portal lands here; dropping still works.
            Err(message) => {
                self.import.open = true;
                self.import.error = Some(Notice {
                    severity: Severity::Caution,
                    title: "Couldn't show the file dialog".into(),
                    body: format!(
                        "{} Drag the export onto this window instead.",
                        sentence(&message)
                    ),
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
    /// Escape closes it. ⇧⌘I opens it. The item under the view is hidden, so
    /// Return and ⇧Return never copy from it, and ↑↓ go back to it as it was
    /// selected before moving anything. `None` for keys it leaves alone.
    pub(crate) fn import_key(&mut self, ev: &KeyEvent) -> Option<bool> {
        if self.screen != Screen::Vault || self.panel.is_some() {
            return None;
        }
        if is_shortcut(ev) {
            self.show_import();
            return Some(true);
        }
        let showing = self.import.showing() || self.drop_hovering();
        match ev.key {
            Key::Enter if showing => {
                if ev.mods == rune::Mods::default() {
                    self.confirm_import();
                }
                Some(true)
            }
            // An empty vault has nothing to go back to, and its preview stays.
            Key::Up | Key::Down if showing => {
                if !self.items.is_empty() {
                    self.sidebar.set_open(true);
                    self.cancel_import();
                }
                Some(true)
            }
            Key::Escape if showing || self.import.error.is_some() => {
                self.cancel_import();
                Some(true)
            }
            _ => None,
        }
    }
}

/// ⇧⌘I, Import Passwords…'s key.
pub fn is_shortcut(ev: &KeyEvent) -> bool {
    ev.is_command('i') && ev.mods.shift && !ev.mods.alt && !ev.mods.ctrl
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

/// "12 new logins · 3 cards · 2 secure notes", "1 new login", "2 new SSH keys".
pub fn new_items(report: &ImportReport) -> String {
    let counts = report.counts();
    if counts.is_empty() {
        return "0 new items".to_owned();
    }
    counts
        .iter()
        .enumerate()
        .map(|(i, &(kind, n))| {
            let new = if i == 0 { "new " } else { "" };
            format!("{n} {new}{}", noun(kind, n))
        })
        .collect::<Vec<_>>()
        .join(" · ")
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

/// The preview's line when nothing in the export is new: it's all here
/// already, or there's nothing Deadbolt takes in it (the details say why).
pub fn nothing_new(p: &Preview, vault: &str) -> String {
    if p.all_here() {
        format!("Everything in this export is already in {vault}")
    } else {
        "Nothing in this export can be imported".to_owned()
    }
}

/// Over a fresh preview when Import found the file changed since the last.
pub fn changed(file: &str) -> Notice {
    Notice {
        severity: Severity::Caution,
        title: format!("{file} changed since the preview"),
        body: "Nothing was imported. This is what it holds now.".to_owned(),
    }
}

/// The primary button: "Import 12 items".
pub fn import_label(n: usize) -> String {
    format!("Import {}", plural(n, "item", "items"))
}

#[cfg(test)]
mod tests {
    use deadbolt_client::protocol::ImportSource;

    use super::*;

    fn report(counts: &[(&str, usize)]) -> ImportReport {
        ImportReport {
            source: ImportSource::OnePassword,
            new: counts.iter().map(|&(k, n)| (k.to_owned(), n)).collect(),
            duplicates: 0,
            skipped: Vec::new(),
            warnings: Vec::new(),
            dropped: Vec::new(),
        }
    }

    #[test]
    fn counts_read_naturally() {
        let r = |counts: &[(&str, usize)]| new_items(&report(counts));
        assert_eq!(r(&[("login", 12), ("card", 3)]), "12 new logins · 3 cards");
        assert_eq!(r(&[("login", 1), ("card", 1)]), "1 new login · 1 card");
        assert_eq!(r(&[("login", 1), ("card", 0)]), "1 new login");
        assert_eq!(r(&[("card", 2)]), "2 new cards");
        assert_eq!(
            r(&[("note", 3), ("login", 2), ("identity", 1), ("ssh", 2)]),
            "2 new logins · 3 secure notes · 2 SSH keys · 1 identity"
        );
        assert_eq!(r(&[("ssh", 1)]), "1 new SSH key");
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
