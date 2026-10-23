//! Installing the command only creates a symlink. Existing commands belong to
//! their installer; neither files nor somebody else's links are replaced.
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq)]
pub enum Existing {
    Ours,
    Homebrew,
    Cargo,
    Other,
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

/// `symlink` is the no-clobber operation: a file created after inspection also
/// wins. Even a dangling symlink is preserved.
pub fn install(source: &Path, destination: &Path) -> io::Result<()> {
    if !crate::binary::executable(source) {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "The bundled command is missing or isn't executable. Reinstall Deadbolt.",
        ));
    }
    match existing(destination, source)? {
        Some(Existing::Ours) => return Ok(()),
        Some(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "{} already exists. Remove it with its installer, then try again.",
                    destination.display()
                ),
            ));
        }
        None => {}
    }
    let parent = destination
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "No install directory"))?;
    fs::create_dir_all(parent)?;
    std::os::unix::fs::symlink(source, destination)
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

pub struct Installer {
    pub open: bool,
    pub settings_open: bool,
    pub source: PathBuf,
    pub destination: PathBuf,
    pub on_path: bool,
    pub found: Option<(PathBuf, Existing)>,
    pub installed: bool,
    pub error: Option<String>,
    pub manual: bool,
    marker: Option<PathBuf>,
    path: Vec<PathBuf>,
    live: bool,
}

impl Installer {
    pub fn live(source: PathBuf, home: PathBuf, marker: PathBuf) -> Self {
        let path: Vec<_> = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .filter(|p| p.is_absolute())
            .collect();
        let (destination, on_path) = destination(&home, &path);
        let open = !marker.exists();
        let mut state = Self {
            open,
            settings_open: false,
            source,
            destination,
            on_path,
            found: None,
            installed: false,
            error: None,
            manual: false,
            marker: Some(marker),
            path,
            live: true,
        };
        state.refresh();
        state
    }

    pub fn fixture() -> Self {
        Self {
            open: true,
            settings_open: false,
            source: "/Applications/Deadbolt.app/Contents/Helpers/deadbolt".into(),
            destination: "/Users/dax/.local/bin/deadbolt".into(),
            on_path: true,
            found: None,
            installed: false,
            error: None,
            manual: false,
            marker: None,
            path: vec![],
            live: false,
        }
    }

    pub fn refresh(&mut self) {
        if !self.live {
            return;
        }
        self.error = None;
        self.found = self
            .path
            .iter()
            .map(|p| p.join("deadbolt"))
            .chain(std::iter::once(self.destination.clone()))
            .find_map(|p| match existing(&p, &self.source) {
                Ok(Some(kind)) => Some((p, kind)),
                Ok(None) => None,
                Err(e) => {
                    self.error = Some(e.to_string());
                    None
                }
            });
        self.installed = self
            .found
            .as_ref()
            .is_some_and(|(_, k)| *k == Existing::Ours);
        if let Some((path, Existing::Ours)) = &self.found {
            self.destination = path.clone();
            self.on_path = path
                .parent()
                .is_some_and(|p| self.path.iter().any(|dir| dir == p));
        }
        self.manual = !writable(self.destination.parent().unwrap_or(Path::new("/")));
    }

    pub fn apply(&mut self) {
        if !self.live {
            self.installed = true;
            return;
        }
        self.refresh();
        if self.error.is_some() || self.found.is_some() {
            return;
        }
        match install(&self.source, &self.destination) {
            Ok(()) => {
                self.installed = true;
                self.remember();
            }
            Err(e) => self.error = Some(e.to_string()),
        }
    }

    fn remember(&mut self) {
        if let Some(marker) = &self.marker {
            let result = marker
                .parent()
                .map_or(Ok(()), fs::create_dir_all)
                .and_then(|()| fs::write(marker, b"1\n"));
            if let Err(e) = result {
                self.error = Some(format!("Couldn't save this choice: {e}"));
            }
        }
    }

    pub fn dismiss(&mut self) {
        self.error = None;
        self.remember();
        if let Some(error) = &self.error {
            eprintln!("{error}; the command offer may appear again next launch");
        }
        self.open = false;
    }

    pub fn command(&self) -> String {
        let dir = self
            .destination
            .parent()
            .unwrap_or(Path::new("/usr/local/bin"));
        format!(
            "sudo mkdir -p {} && sudo ln -s {} {}",
            quote(dir),
            quote(&self.source),
            quote(&self.destination)
        )
    }

    pub fn path_command(&self) -> String {
        format!(
            "export PATH={}:\"$PATH\"",
            quote(self.destination.parent().unwrap_or(Path::new(".")))
        )
    }
}

pub fn view(s: &crate::model::App, k: &rune_kit::Kit) -> rune::El {
    use rune::{TextStyle, col, row, text};
    use rune_kit::{Button, ButtonSize, ButtonVariant};
    let Some(state) = &s.installer else {
        return col();
    };
    let line = |key: &str, value: String| {
        text(value)
            .key(key)
            .font(k.ty.text_small)
            .color(k.c.text_muted)
            .wrap()
            .w_full()
    };
    let location = state
        .found
        .as_ref()
        .filter(|(_, kind)| *kind == Existing::Ours)
        .map_or(&state.destination, |(path, _)| path);
    let title = if state.installed {
        "Command installed"
    } else {
        "Install the deadbolt command"
    };
    let mut body = col()
        .key("install-body")
        .w_full()
        .gap(16.0)
        .child(
            text(title)
                .key("title")
                .font(TextStyle::new(18.0, 500.0))
                .color(k.c.text_strong),
        )
        .child(line(
            "intro",
            if state.installed {
                format!("{} links to this app.", location.display())
            } else {
                "Use Deadbolt from your terminal and coding agents.".into()
            },
        ));
    if state.installed {
        body = body.child(line("undo", format!("To undo: rm {}", quote(location))));
    } else if let Some((path, kind)) = &state.found {
        let name = match kind {
            Existing::Homebrew => "a Homebrew install",
            Existing::Cargo => "a Cargo install",
            Existing::Other => "an existing command",
            Existing::Ours => "this app's command",
        };
        body = body
            .child(line(
                "existing",
                format!(
                    "Found {name} at {}. Remove it with its installer to use this app's command.",
                    path.display()
                ),
            ))
            .child(
                Button::new("Check again")
                    .size(ButtonSize::Large)
                    .on_press(|s: &mut crate::model::App| {
                        if let Some(i) = &mut s.installer {
                            i.refresh();
                        }
                    })
                    .build(k)
                    .min_h(44.0),
            );
    } else if state.manual {
        let command = state.command();
        body = body
            .child(line(
                "manual",
                "Administrator access is needed. Run this in your terminal:".into(),
            ))
            .child(line("command", command.clone()))
            .child(
                Button::new("Copy command")
                    .size(ButtonSize::Large)
                    .on_press_tx(move |_: &mut crate::model::App, tx: &mut rune::Tx| {
                        tx.copy(command.clone())
                    })
                    .build(k)
                    .min_h(44.0),
            );
    } else {
        body = body
            .child(line(
                "location",
                format!("Link at {}", state.destination.display()),
            ))
            .child(
                Button::new("Install command")
                    .variant(ButtonVariant::Contrast)
                    .size(ButtonSize::Large)
                    .on_press(|s: &mut crate::model::App| {
                        if let Some(i) = &mut s.installer {
                            i.apply();
                        }
                    })
                    .build(k)
                    .min_h(44.0),
            );
    }
    if !state.on_path && (state.found.is_none() || state.installed) {
        let command = state.path_command();
        body = body.child(line("path", "This app can't see that directory on PATH. If your terminal can't find deadbolt, add this to your shell profile:".into()))
            .child(line("path-command", command.clone()))
            .child(Button::new("Copy PATH command").size(ButtonSize::Large).on_press_tx(move |_: &mut crate::model::App, tx: &mut rune::Tx| tx.copy(command.clone())).build(k).min_h(44.0));
    }
    if let Some(error) = &state.error {
        body = body.child(
            text(error.clone())
                .key("install-error")
                .font(k.ty.text_small)
                .color(k.c.danger.fg)
                .wrap()
                .w_full(),
        );
    }
    let footer = row().w(440.0).self_center().py(12.0).child(
        Button::new(if state.installed { "Done" } else { "Not now" })
            .size(ButtonSize::Large)
            .on_press(|s: &mut crate::model::App| {
                if let Some(i) = &mut s.installer {
                    i.dismiss();
                }
            })
            .build(k)
            .min_h(44.0),
    );
    col()
        .key("install-command")
        .w_full()
        .child(
            col()
                .key("install-scroll")
                .w_full()
                .grow(1.0)
                .center_y()
                .scroll(rune::ScrollSpec {
                    stick_bottom: false,
                })
                .child(
                    col()
                        .w(440.0)
                        .py(32.0)
                        .gap(24.0)
                        .child(crate::onboarding::view::wordmark(k, 40.0))
                        .child(body),
                ),
        )
        .child(footer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn installs_once_and_preserves_every_other_entry() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("bundled");
        fs::write(&source, "binary").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
        let link = dir.path().join("bin/deadbolt");
        install(&source, &link).unwrap();
        install(&source, &link).unwrap();
        assert_eq!(existing(&link, &source).unwrap(), Some(Existing::Ours));
        fs::remove_file(&link).unwrap();
        fs::write(&link, "cargo install").unwrap();
        assert_eq!(
            install(&source, &link).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
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
    fn first_run_choice_persists_but_fixture_never_touches_disk() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("config/app-command-offered");
        let mut state = Installer::fixture();
        state.dismiss();
        assert!(!state.open);
        assert!(!marker.exists());
        state.marker = Some(marker.clone());
        state.open = true;
        state.dismiss();
        assert!(!state.open);
        assert_eq!(fs::read_to_string(marker).unwrap(), "1\n");
    }
}
