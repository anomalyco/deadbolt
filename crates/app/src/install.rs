//! Installing the command only creates a symlink to the bundle's helper, or
//! repoints one of ours after the app moved. Existing commands belong to
//! their installer; neither files nor somebody else's links are replaced.
//! Scans and installs run off the UI thread: PATH can name slow or
//! unreadable directories.
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rune::{Tx, Waker};

use crate::binary;
use crate::onboarding::COPIED_FOR;

#[derive(Clone, Debug, PartialEq)]
pub enum Existing {
    /// A link to this app's helper.
    Ours,
    /// A link to another Deadbolt bundle's helper, live or not: the app moved,
    /// was deleted, or ran from a disk image. Ours to repoint.
    Moved(PathBuf),
    Homebrew,
    Cargo,
    Other,
}

impl Existing {
    fn ours(&self) -> bool {
        matches!(self, Existing::Ours | Existing::Moved(_))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    #[error("Deadbolt is damaged: its deadbolt helper is missing. Reinstall Deadbolt.")]
    MissingHelper,
    #[error(
        "Move Deadbolt to Applications first. A command linked to this copy would stop working once it's moved or ejected."
    )]
    Temporary,
    #[error("{} already exists. Remove it with its installer, then try again.", .0.display())]
    Taken(PathBuf),
    #[error("Couldn't check {}: {}", .0.display(), .1)]
    Inspect(PathBuf, io::Error),
    #[error("Couldn't create {}: {}", .0.display(), .1)]
    CreateDir(PathBuf, io::Error),
    #[error("Couldn't link {}: {}", .0.display(), .1)]
    Link(PathBuf, io::Error),
}

pub fn existing(link: &Path, source: &Path) -> io::Result<Option<Existing>> {
    let metadata = match fs::symlink_metadata(link) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if metadata.file_type().is_symlink() {
        let target = fs::read_link(link)?;
        let target = if target.is_absolute() {
            target
        } else {
            link.parent().unwrap_or(Path::new(".")).join(target)
        };
        if target == source
            || fs::canonicalize(&target)
                .ok()
                .zip(fs::canonicalize(source).ok())
                .is_some_and(|(a, b)| a == b)
        {
            return Ok(Some(Existing::Ours));
        }
        if binary::is_helper(&target) {
            return Ok(Some(Existing::Moved(target)));
        }
        if target
            .components()
            .any(|c| c.as_os_str() == "Cellar" || c.as_os_str() == "Homebrew")
        {
            return Ok(Some(Existing::Homebrew));
        }
    }
    Ok(Some(
        if link.components().any(|c| c.as_os_str() == ".cargo") {
            Existing::Cargo
        } else {
            Existing::Other
        },
    ))
}

/// A copy running from a disk image or under App Translocation goes away, and
/// a link to it would dangle.
pub fn temporary(source: &Path) -> bool {
    source.starts_with("/Volumes")
        || source
            .components()
            .any(|c| c.as_os_str() == "AppTranslocation")
}

/// Links `destination` to `source`. `symlink` is the no-clobber operation: a
/// file created after inspection also wins, and a dangling symlink that isn't
/// ours is preserved. Only a link to a moved Deadbolt is replaced.
pub fn install(source: &Path, destination: &Path) -> Result<(), InstallError> {
    if temporary(source) {
        return Err(InstallError::Temporary);
    }
    if !binary::executable(source) {
        return Err(InstallError::MissingHelper);
    }
    let link = |at: &Path| {
        std::os::unix::fs::symlink(source, at).map_err(|e| InstallError::Link(at.into(), e))
    };
    match existing(destination, source).map_err(|e| InstallError::Inspect(destination.into(), e))? {
        Some(Existing::Ours) => Ok(()),
        // Link beside it, then rename over it: the command never goes missing.
        Some(Existing::Moved(_)) => {
            let fresh = destination.with_file_name(format!(".deadbolt-{}", std::process::id()));
            match fs::remove_file(&fresh) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => {
                    return Err(InstallError::Link(fresh, e));
                }
                _ => {}
            }
            link(&fresh)?;
            fs::rename(&fresh, destination).map_err(|e| {
                fs::remove_file(&fresh).ok();
                InstallError::Link(destination.into(), e)
            })
        }
        Some(_) => Err(InstallError::Taken(destination.into())),
        None => {
            let parent = destination.parent().unwrap_or(Path::new("/"));
            fs::create_dir_all(parent).map_err(|e| InstallError::CreateDir(parent.into(), e))?;
            link(destination)
        }
    }
}

fn writable(path: &Path) -> bool {
    let mut parent = path;
    while !parent.exists() {
        let Some(next) = parent.parent() else {
            return false;
        };
        parent = next;
    }
    parent.is_dir() && rustix::fs::access(parent, rustix::fs::Access::WRITE_OK).is_ok()
}

pub fn destination(home: &Path, path: &[PathBuf]) -> (PathBuf, bool) {
    let preferred = [
        home.join(".local/bin"),
        PathBuf::from("/opt/homebrew/bin"),
        PathBuf::from("/usr/local/bin"),
    ];
    let dir = preferred
        .iter()
        .find(|p| path.contains(p) && writable(p))
        .or_else(|| preferred.iter().find(|p| writable(p)))
        .or_else(|| preferred.iter().find(|p| path.contains(p)))
        .unwrap_or(&preferred[0]);
    (dir.join("deadbolt"), path.contains(dir))
}

pub fn quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

/// What's installed, and where the link goes.
#[derive(Clone, Debug, PartialEq)]
pub struct Scan {
    /// Where the link is or would go: ours if one exists, else the best directory.
    pub destination: PathBuf,
    /// Whether the app's own PATH has that directory.
    pub on_path: bool,
    /// The first `deadbolt` found, ours before anybody else's.
    pub found: Option<(PathBuf, Existing)>,
    /// The directory isn't writable without an administrator.
    pub manual: bool,
}

impl Scan {
    pub fn installed(&self) -> bool {
        matches!(self.found, Some((_, Existing::Ours)))
    }
}

/// Looks for `deadbolt` in `search` ([`binary::search_dirs`]: PATH, then the
/// usual places a Finder launch's PATH lacks). Directories that can't be read
/// count as not having one.
pub fn scan(source: &Path, home: &Path, path: &OsStr, search: &[PathBuf]) -> Scan {
    let dirs: Vec<PathBuf> = std::env::split_paths(path)
        .filter(|p| p.is_absolute())
        .collect();
    let (mut destination, _) = destination(home, &dirs);
    let mut found: Vec<(PathBuf, Existing)> = search
        .iter()
        .map(|dir| dir.join("deadbolt"))
        .chain(std::iter::once(destination.clone()))
        .filter_map(|p| match existing(&p, source) {
            Ok(Some(kind)) => Some((p, kind)),
            Ok(None) | Err(_) => None,
        })
        .collect();
    let found = match found.iter().position(|(_, kind)| kind.ours()) {
        Some(i) => Some(found.swap_remove(i)),
        None => found.into_iter().next(),
    };
    if let Some((at, kind)) = &found
        && kind.ours()
    {
        destination = at.clone();
    }
    let dir = destination.parent().unwrap_or(Path::new("/"));
    Scan {
        on_path: dirs.iter().any(|d| d == dir),
        manual: !writable(dir),
        destination,
        found,
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Copied {
    Command,
    Path,
}

struct Outcome {
    scan: Scan,
    error: Option<String>,
    installing: bool,
}

/// Runs scans and installs on short-lived threads and posts what they find.
struct Live {
    home: PathBuf,
    path: OsString,
    search: Vec<PathBuf>,
    results: Sender<Outcome>,
    inbox: Receiver<Outcome>,
    waker: Arc<Mutex<Option<Waker>>>,
}

pub struct Installer {
    /// The install page is showing, in place of the vault.
    pub open: bool,
    /// The vault's one-time offer was answered; remembered across launches.
    pub offered: bool,
    pub source: PathBuf,
    /// The latest scan; `None` until the first one lands.
    pub scan: Option<Scan>,
    /// A scan or install is running.
    pub busy: bool,
    pub error: Option<String>,
    /// Which command was copied, and when on the app's clock.
    pub copied: Option<(Copied, f64)>,
    marker: Option<PathBuf>,
    live: Option<Live>,
}

impl Installer {
    pub fn live(source: PathBuf, home: PathBuf, marker: PathBuf) -> Self {
        let (results, inbox) = channel();
        let path = std::env::var_os("PATH").unwrap_or_default();
        let search = binary::search_dirs(&path, Some(&home));
        let mut state = Self {
            open: false,
            offered: marker.exists(),
            source,
            scan: None,
            busy: false,
            error: None,
            copied: None,
            marker: Some(marker),
            live: Some(Live {
                home,
                path,
                search,
                results,
                inbox,
                waker: Arc::default(),
            }),
        };
        state.refresh();
        state
    }

    /// For scenes and tests: a fresh Mac with nothing installed, never touching disk.
    pub fn fixture() -> Self {
        Self {
            open: false,
            offered: false,
            source: "/Applications/Deadbolt.app/Contents/Helpers/deadbolt".into(),
            scan: Some(Scan {
                destination: "/Users/dax/.local/bin/deadbolt".into(),
                on_path: true,
                found: None,
                manual: false,
            }),
            busy: false,
            error: None,
            copied: None,
            marker: None,
            live: None,
        }
    }

    pub fn set_waker(&self, waker: Waker) {
        if let Some(live) = &self.live {
            *live.waker.lock().unwrap_or_else(|e| e.into_inner()) = Some(waker);
        }
    }

    pub fn installed(&self) -> bool {
        self.scan.as_ref().is_some_and(Scan::installed)
    }

    /// Whether the vault should offer the command: not answered yet, and
    /// nothing else already provides it.
    pub fn offering(&self) -> bool {
        !self.offered
            && !self.open
            && self
                .scan
                .as_ref()
                .is_some_and(|s| matches!(s.found, None | Some((_, Existing::Moved(_)))))
    }

    pub fn refresh(&mut self) {
        self.run(false);
    }

    pub fn apply(&mut self) {
        if self.live.is_none() {
            if let Some(scan) = &mut self.scan {
                scan.found = Some((scan.destination.clone(), Existing::Ours));
            }
            return;
        }
        self.run(true);
    }

    fn run(&mut self, installing: bool) {
        let Some(live) = &self.live else {
            return;
        };
        self.error = None;
        self.busy = true;
        let (source, home) = (self.source.clone(), live.home.clone());
        let (path, search) = (live.path.clone(), live.search.clone());
        let (results, waker) = (live.results.clone(), live.waker.clone());
        let work = move || {
            let mut error = None;
            if installing {
                let before = scan(&source, &home, &path, &search);
                // Somebody else's command wins; the page says whose.
                if before.found.as_ref().is_none_or(|(_, kind)| kind.ours())
                    && let Err(e) = install(&source, &before.destination)
                {
                    error = Some(e.to_string());
                }
            }
            let outcome = Outcome {
                scan: scan(&source, &home, &path, &search),
                error,
                installing,
            };
            if results.send(outcome).is_ok()
                && let Some(wake) = waker.lock().unwrap_or_else(|e| e.into_inner()).clone()
            {
                wake();
            }
        };
        if let Err(e) = std::thread::Builder::new()
            .name("deadbolt-install".into())
            .spawn(work)
        {
            self.busy = false;
            self.error = Some(format!("Couldn't check for the command: {e}"));
        }
    }

    /// Applies finished work and lets a "Copied" lapse. True when anything changed.
    pub fn poll(&mut self, now: f64) -> bool {
        let mut changed = false;
        if self
            .copied
            .is_some_and(|(_, at)| now - at >= COPIED_FOR - 1e-3)
        {
            self.copied = None;
            changed = true;
        }
        let outcomes: Vec<Outcome> = match &self.live {
            Some(live) => live.inbox.try_iter().collect(),
            None => Vec::new(),
        };
        for outcome in outcomes {
            changed = true;
            self.busy = false;
            self.error = outcome.error;
            self.scan = Some(outcome.scan);
            if outcome.installing && self.installed() {
                self.answer();
            }
        }
        changed
    }

    pub fn copy(&mut self, which: Copied, now: f64, tx: &mut Tx) {
        let command = match which {
            Copied::Command => self.command(),
            Copied::Path => self.path_command(),
        };
        tx.copy(command);
        self.copied = Some((which, now));
        tx.wake_after(Duration::from_secs_f64(COPIED_FOR));
    }

    pub fn copied(&self, which: Copied, now: f64) -> bool {
        self.copied
            .is_some_and(|(c, at)| c == which && now - at < COPIED_FOR)
    }

    /// Opens the install page with a fresh scan.
    pub fn show(&mut self) {
        self.open = true;
        self.refresh();
    }

    /// Leaves the install page. Having seen it answers the vault's offer.
    pub fn close(&mut self) {
        self.open = false;
        self.answer();
    }

    /// "Not now" on the vault's offer.
    pub fn dismiss(&mut self) {
        self.answer();
    }

    fn answer(&mut self) {
        self.offered = true;
        if let Some(marker) = &self.marker {
            let result = marker
                .parent()
                .map_or(Ok(()), fs::create_dir_all)
                .and_then(|()| fs::write(marker, b"1\n"));
            if let Err(e) = result {
                eprintln!("Couldn't save the command offer's answer: {e}");
            }
        }
    }

    fn destination(&self) -> PathBuf {
        self.scan.as_ref().map_or_else(
            || PathBuf::from("/usr/local/bin/deadbolt"),
            |s| s.destination.clone(),
        )
    }

    pub fn command(&self) -> String {
        let destination = self.destination();
        if let Some(Scan {
            found: Some((_, Existing::Moved(_))),
            ..
        }) = &self.scan
        {
            return format!(
                "sudo ln -sfh {} {}",
                quote(&self.source),
                quote(&destination)
            );
        }
        let dir = destination.parent().unwrap_or(Path::new("/usr/local/bin"));
        format!(
            "sudo mkdir -p {} && sudo ln -s {} {}",
            quote(dir),
            quote(&self.source),
            quote(&destination)
        )
    }

    pub fn path_command(&self) -> String {
        let destination = self.destination();
        format!(
            "export PATH={}:\"$PATH\"",
            quote(destination.parent().unwrap_or(Path::new(".")))
        )
    }
}

// -------------------------------------------------------------------------------------------
// Views: the install page, the vault's one-time offer, and the footer's Settings.

impl crate::model::App {
    /// Opens the install page over the vault. It takes no drops, so a drag in
    /// progress is forgotten: the window won't hear when it ends.
    pub fn show_installer(&mut self) {
        if let Some(i) = &mut self.installer {
            self.import.hover = false;
            i.show();
        }
    }
}

mod view {
    use rune::{El, Transition, col, row, text};
    use rune_kit::{Button, ButtonVariant, ControlSize, Kit};

    use super::{Copied, Existing, InstallError, Installer, quote, temporary};
    use crate::model::App;
    use crate::onboarding::view::{PANEL_W, bar, muted, page as centred, title};
    use crate::view::Paged;

    fn installer(s: &mut App) -> Option<&mut Installer> {
        s.installer.as_mut()
    }

    /// A command to run, with a Copy button that confirms in place.
    fn command(i: &Installer, k: &Kit, now: f64, which: Copied) -> El {
        let (key, line, label) = match which {
            Copied::Command => ("command", i.command(), "Copy command"),
            Copied::Path => ("path-command", i.path_command(), "Copy PATH command"),
        };
        let copied = i.copied(which, now);
        col()
            .key(key)
            .w_full()
            .gap(8.0)
            .items_start()
            .child(
                text(line)
                    .key("line")
                    .font(k.ty.mono)
                    .color(k.c.text_base)
                    .wrap()
                    .w_full(),
            )
            .child(
                Button::new(if copied { "Copied" } else { label })
                    .variant(ButtonVariant::Neutral)
                    .control_size(ControlSize::Large)
                    .icon(if copied {
                        k.glyph.check_small
                    } else {
                        k.glyph.copy
                    })
                    .on_press_tx(move |s: &mut App, tx: &mut rune::Tx| {
                        let now = s.clock;
                        if let Some(i) = installer(s) {
                            i.copy(which, now, tx);
                        }
                    })
                    .build(k)
                    .key(if copied { "copied" } else { "copy" })
                    .transition(Transition::blur_replace()),
            )
    }

    fn action(k: &Kit, label: &str, busy: bool, press: fn(&mut Installer)) -> El {
        Button::new(label)
            .variant(ButtonVariant::Contrast)
            .control_size(ControlSize::Large)
            .disabled(busy)
            .on_press(move |s: &mut App| {
                if let Some(i) = installer(s) {
                    press(i);
                }
            })
            .build(k)
            .key("action")
    }

    /// The install page, in place of the vault.
    pub fn page(s: &App, k: &Kit) -> Paged {
        let Some(i) = &s.installer else {
            return col().into();
        };
        let mut body = col().w_full().gap(14.0).items_start();
        let key = match &i.scan {
            None => {
                body = body
                    .child(title(k, "title", "Install the deadbolt command"))
                    .child(muted(k, "about", "Checking for an existing command…"));
                "checking"
            }
            Some(_) if temporary(&i.source) => {
                body = body
                    .child(title(k, "title", "Install the deadbolt command"))
                    .child(muted(k, "about", InstallError::Temporary.to_string()));
                "temporary"
            }
            Some(scan) if scan.installed() => {
                body = body
                    .child(title(k, "title", "Command installed"))
                    .child(muted(
                        k,
                        "about",
                        format!("{} links to this app.", scan.destination.display()),
                    ))
                    .child(muted(
                        k,
                        "undo",
                        format!("To undo: rm {}", quote(&scan.destination)),
                    ));
                "installed"
            }
            Some(scan) => match &scan.found {
                Some((path, Existing::Moved(target))) => {
                    body = body
                        .child(title(k, "title", "Repair the deadbolt command"))
                        .child(muted(
                            k,
                            "about",
                            format!(
                                "{} links to a Deadbolt that moved or was deleted ({}).",
                                path.display(),
                                target.display()
                            ),
                        ));
                    if scan.manual {
                        body = body
                            .child(muted(
                                k,
                                "manual",
                                "Administrator access is needed. Run this in your terminal:",
                            ))
                            .child(command(i, k, s.clock, Copied::Command));
                    } else {
                        let label = if i.busy {
                            "Repairing…"
                        } else {
                            "Point it at this app"
                        };
                        body = body.child(action(k, label, i.busy, Installer::apply));
                    }
                    "moved"
                }
                Some((path, kind)) => {
                    let name = match kind {
                        Existing::Homebrew => "a Homebrew install",
                        Existing::Cargo => "a Cargo install",
                        _ => "an existing command",
                    };
                    let label = if i.busy { "Checking…" } else { "Check again" };
                    body = body
                        .child(title(k, "title", "Install the deadbolt command"))
                        .child(muted(
                            k,
                            "about",
                            format!(
                                "Found {name} at {}. Remove it with its installer to use this app's command.",
                                path.display()
                            ),
                        ))
                        .child(
                            Button::new(label)
                                .variant(ButtonVariant::Neutral)
                                .control_size(ControlSize::Large)
                                .disabled(i.busy)
                                .on_press(|s: &mut App| {
                                    if let Some(i) = installer(s) {
                                        i.refresh();
                                    }
                                })
                                .build(k)
                                .key("action"),
                        );
                    "existing"
                }
                None => {
                    body = body
                        .child(title(k, "title", "Install the deadbolt command"))
                        .child(muted(
                            k,
                            "about",
                            "Use Deadbolt from your terminal and coding agents.",
                        ));
                    if scan.manual {
                        body = body
                            .child(muted(
                                k,
                                "manual",
                                "Administrator access is needed. Run this in your terminal:",
                            ))
                            .child(command(i, k, s.clock, Copied::Command));
                    } else {
                        let label = if i.busy {
                            "Installing…"
                        } else {
                            "Install command"
                        };
                        body = body
                            .child(muted(
                                k,
                                "location",
                                format!("Links {}", scan.destination.display()),
                            ))
                            .child(action(k, label, i.busy, Installer::apply));
                    }
                    "install"
                }
            },
        };
        if let Some(scan) = &i.scan
            && !scan.on_path
            && matches!(key, "install" | "installed")
        {
            body = body
                .child(muted(
                    k,
                    "path",
                    "If your terminal can't find deadbolt, add this to your shell profile:",
                ))
                .child(command(i, k, s.clock, Copied::Path));
        }
        let mut panel = col()
            .key("panel")
            .w(PANEL_W)
            .gap(14.0)
            .child(body.key(key).transition(Transition::blur_replace()));
        if let Some(error) = &i.error {
            panel = panel.child(
                text(error.clone())
                    .key("install-error")
                    .font(k.ty.text_small)
                    .color(k.c.danger.fg)
                    .wrap()
                    .w_full()
                    .transition(Transition::opacity()),
            );
        }
        let back = bar(k, "Back", &crate::onboarding::view::CHEVRON_LEFT, |s| {
            if let Some(i) = installer(s) {
                i.close();
            }
        });
        centred("install-command", Some(back), panel)
    }

    /// The vault's one-time offer, above the copy notice.
    pub fn offer(s: &App, k: &Kit) -> Option<El> {
        let i = s.installer.as_ref().filter(|i| i.offering())?;
        let moved = matches!(
            i.scan.as_ref().and_then(|s| s.found.as_ref()),
            Some((_, Existing::Moved(_)))
        );
        let (head, about, label) = if moved {
            (
                "Your deadbolt command needs repair",
                "It links to a Deadbolt that moved or was deleted.",
                "Repair…",
            )
        } else {
            (
                "Use Deadbolt from your terminal",
                "Install the deadbolt command for your shell and coding agents.",
                "Install…",
            )
        };
        let mut card = col()
            .key("command-offer")
            .role("status")
            .w(crate::view::NOTICE_W)
            .self_center()
            .padding(12.0)
            .gap(10.0)
            .radius(k.radius.lg)
            .fill(k.c.layer_01)
            .transition(Transition::offset(0.0, 12.0).combined(Transition::opacity()));
        for shadow in k.shadow_layers(&k.elevation.floating) {
            card = card.box_shadow(shadow);
        }
        Some(
            card.child(
                col()
                    .key("text")
                    .w_full()
                    .gap(2.0)
                    .child(text(head).font(k.ty.ui_medium).color(k.c.text_strong))
                    .child(muted(k, "about", about)),
            )
            .child(
                row()
                    .key("actions")
                    .gap(8.0)
                    .child(
                        Button::new(label)
                            .variant(ButtonVariant::Neutral)
                            .control_size(ControlSize::Large)
                            .on_press(|s: &mut App| s.show_installer())
                            .build(k)
                            .key("open"),
                    )
                    .child(
                        Button::new("Not now")
                            .variant(ButtonVariant::Ghost)
                            .control_size(ControlSize::Large)
                            .on_press(|s: &mut App| {
                                if let Some(i) = installer(s) {
                                    i.dismiss();
                                }
                            })
                            .build(k)
                            .key("dismiss"),
                    ),
            ),
        )
    }

    /// Settings' way to the install page, when the app has a command to install.
    pub fn setting(s: &App, k: &Kit) -> Option<El> {
        let i = s.installer.as_ref()?;
        let label = if i.installed() {
            "deadbolt command…"
        } else {
            "Install deadbolt command…"
        };
        Some(
            Button::new(label)
                .variant(ButtonVariant::Ghost)
                .control_size(ControlSize::Large)
                .on_press(|s: &mut App| {
                    s.close_settings();
                    s.show_installer();
                })
                .build(k)
                .key("install"),
        )
    }
}

pub use view::{offer, page, setting};

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn helper(dir: &Path, app: &str) -> PathBuf {
        let source = dir.join(app).join("Contents/Helpers/deadbolt");
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::write(&source, "binary").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
        source
    }

    #[test]
    fn installs_once_and_preserves_every_other_entry() {
        let dir = tempfile::tempdir().unwrap();
        let source = helper(dir.path(), "Deadbolt.app");
        let link = dir.path().join("bin/deadbolt");
        install(&source, &link).unwrap();
        install(&source, &link).unwrap();
        assert_eq!(existing(&link, &source).unwrap(), Some(Existing::Ours));
        fs::remove_file(&link).unwrap();
        fs::write(&link, "cargo install").unwrap();
        assert!(matches!(
            install(&source, &link),
            Err(InstallError::Taken(_))
        ));
        assert_eq!(fs::read_to_string(&link).unwrap(), "cargo install");
        fs::remove_file(&link).unwrap();
        symlink("/missing/Cellar/deadbolt/1/bin/deadbolt", &link).unwrap();
        assert_eq!(existing(&link, &source).unwrap(), Some(Existing::Homebrew));
        assert!(install(&source, &link).is_err());
        assert_eq!(
            fs::read_link(&link).unwrap(),
            Path::new("/missing/Cellar/deadbolt/1/bin/deadbolt")
        );
    }

    #[test]
    fn a_link_to_a_moved_app_is_ours_and_gets_repointed() {
        let dir = tempfile::tempdir().unwrap();
        let source = helper(dir.path(), "Applications/Deadbolt.app");
        let link = dir.path().join("bin/deadbolt");
        fs::create_dir_all(link.parent().unwrap()).unwrap();
        for old in [
            // Deleted, a disk image, App Translocation: all dangling now.
            "/Users/dax/Downloads/Deadbolt.app/Contents/Helpers/deadbolt",
            "/Volumes/Deadbolt/Deadbolt.app/Contents/Helpers/deadbolt",
            "/private/var/folders/x/T/AppTranslocation/1/d/Deadbolt.app/Contents/Helpers/deadbolt",
        ] {
            fs::remove_file(&link).ok();
            symlink(old, &link).unwrap();
            assert_eq!(
                existing(&link, &source).unwrap(),
                Some(Existing::Moved(old.into()))
            );
            install(&source, &link).unwrap();
            assert_eq!(fs::read_link(&link).unwrap(), source);
            assert_eq!(fs::read_dir(link.parent().unwrap()).unwrap().count(), 1);
        }
    }

    #[test]
    fn a_disk_image_or_translocated_copy_refuses_to_install() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("bin/deadbolt");
        for source in [
            "/Volumes/Deadbolt/Deadbolt.app/Contents/Helpers/deadbolt",
            "/private/var/folders/x/T/AppTranslocation/1/d/Deadbolt.app/Contents/Helpers/deadbolt",
        ] {
            let error = install(Path::new(source), &link).unwrap_err();
            assert!(matches!(error, InstallError::Temporary));
            assert!(
                error
                    .to_string()
                    .starts_with("Move Deadbolt to Applications first")
            );
        }
        assert!(fs::symlink_metadata(&link).is_err());
        assert!(!temporary(Path::new(
            "/Applications/Deadbolt.app/Contents/Helpers/deadbolt"
        )));
    }

    #[test]
    fn a_missing_helper_says_reinstall() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("Deadbolt.app/Contents/Helpers/deadbolt");
        let error = install(&source, &dir.path().join("deadbolt")).unwrap_err();
        assert!(matches!(error, InstallError::MissingHelper));
        assert!(error.to_string().contains("Reinstall Deadbolt"));
    }

    #[test]
    fn writable_path_and_missing_path_are_distinct() {
        let home = tempfile::tempdir().unwrap();
        let bin = home.path().join(".local/bin");
        assert_eq!(
            destination(home.path(), std::slice::from_ref(&bin)),
            (bin.join("deadbolt"), true)
        );
        assert_eq!(destination(home.path(), &[]), (bin.join("deadbolt"), false));
    }

    #[test]
    fn a_finder_path_still_finds_a_cargo_install() {
        let home = tempfile::tempdir().unwrap();
        let source = helper(home.path(), "Deadbolt.app");
        let cargo = home.path().join(".cargo/bin/deadbolt");
        fs::create_dir_all(cargo.parent().unwrap()).unwrap();
        fs::write(&cargo, "cargo").unwrap();
        let finder = OsStr::new("/usr/bin:/bin:/usr/sbin:/sbin");
        // The app's list, less the machine-wide places this test can't control.
        let search: Vec<_> = binary::search_dirs(finder, Some(home.path()))
            .into_iter()
            .filter(|d| !d.starts_with("/opt/homebrew") && !d.starts_with("/usr/local"))
            .collect();
        let found = scan(&source, home.path(), finder, &search);
        assert_eq!(found.found, Some((cargo.clone(), Existing::Cargo)));
        // Our own link elsewhere is what the page reports.
        let ours = home.path().join(".local/bin/deadbolt");
        install(&source, &ours).unwrap();
        let found = scan(&source, home.path(), finder, &search);
        assert!(found.installed());
        assert_eq!(found.destination, ours);
    }

    #[test]
    fn unreadable_directories_count_as_empty() {
        let home = tempfile::tempdir().unwrap();
        let source = helper(home.path(), "Deadbolt.app");
        let locked = home.path().join("locked");
        fs::create_dir(&locked).unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let found = scan(
            &source,
            home.path(),
            locked.as_os_str(),
            std::slice::from_ref(&locked),
        );
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(found.found, None);
        assert_eq!(found.destination, home.path().join(".local/bin/deadbolt"));
        assert!(!found.manual);
    }

    #[test]
    fn shell_paths_are_quoted() {
        assert_eq!(
            quote(Path::new("/Dax's Mac/Deadbolt.app")),
            "'/Dax'\\''s Mac/Deadbolt.app'"
        );
    }

    #[test]
    fn cargo_and_foreign_symlinks_are_identified_without_replacing_them() {
        let dir = tempfile::tempdir().unwrap();
        let cargo = dir.path().join(".cargo/bin/deadbolt");
        fs::create_dir_all(cargo.parent().unwrap()).unwrap();
        fs::write(&cargo, "cargo").unwrap();
        let source = dir.path().join("bundle/deadbolt");
        assert_eq!(existing(&cargo, &source).unwrap(), Some(Existing::Cargo));
        let link = dir.path().join("deadbolt");
        symlink("some-other-app", &link).unwrap();
        assert_eq!(existing(&link, &source).unwrap(), Some(Existing::Other));
    }

    #[test]
    fn the_offer_is_answered_once_but_the_fixture_never_touches_disk() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("config/app-command-offered");
        let mut state = Installer::fixture();
        assert!(state.offering());
        state.dismiss();
        assert!(!state.offering());
        assert!(!marker.exists());
        state.marker = Some(marker.clone());
        state.offered = false;
        state.show();
        assert!(!state.offering(), "not while the page is open");
        state.close();
        assert!(!state.offering());
        assert_eq!(fs::read_to_string(marker).unwrap(), "1\n");
    }
}
