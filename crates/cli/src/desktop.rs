//! `deadbolt desktop install`: a Linux desktop entry, so app launchers list
//! Deadbolt and open it with `deadbolt app`. On macOS, Deadbolt.app is that.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::browser::write_atomic;

/// The entry's and icon's name, and the app's Wayland app id and X11
/// `WM_CLASS` (`rune::set_app_id` in `crates/app`), which desktops match.
pub const ID: &str = "pw.deadbolt.Deadbolt";
/// The red keyhole of `crates/app/scripts/icon.swift`.
const ICON: &str = include_str!("../assets/deadbolt.svg");

const MACOS: &str = "On macOS, Deadbolt.app is the launcher: open it from Applications, \
Spotlight or the Dock, or run `deadbolt app`.";

struct Files {
    entry: PathBuf,
    icon: PathBuf,
}

impl Files {
    fn get() -> Result<Self> {
        Self::from_vars(|name| crate::config::env(name).ok())
    }

    /// Under `$XDG_DATA_HOME`, else `~/.local/share`.
    fn from_vars(vars: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let var = |name: &str| vars(name).filter(|v| !v.is_empty()).map(PathBuf::from);
        let data = match var("XDG_DATA_HOME") {
            Some(data) => data,
            None => var("HOME").context("HOME is not set")?.join(".local/share"),
        };
        Ok(Self {
            entry: data.join("applications").join(format!("{ID}.desktop")),
            icon: data
                .join("icons/hicolor/scalable/apps")
                .join(format!("{ID}.svg")),
        })
    }

    fn write(&self, program: &Path) -> Result<()> {
        let entry = entry(program)?;
        write_atomic(&self.icon, ICON)?;
        write_atomic(&self.entry, &entry)
    }

    /// Removes both, returning those that were there.
    fn remove(&self) -> Result<Vec<&Path>> {
        let mut removed = Vec::new();
        for path in [&self.entry, &self.icon] {
            match std::fs::remove_file(path) {
                Ok(()) => removed.push(path.as_path()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).with_context(|| format!("removing {}", path.display())),
            }
        }
        Ok(removed)
    }
}

/// The desktop entry that runs `program app`.
fn entry(program: &Path) -> Result<String> {
    let program = program
        .to_str()
        .context("the path of this binary is not UTF-8")?;
    if program.chars().any(char::is_control) {
        bail!("the path of this binary has control characters");
    }
    Ok(format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=Deadbolt\n\
         GenericName=Password Manager\n\
         Comment=A decentralized password manager\n\
         Exec={} app\n\
         Icon={ID}\n\
         Terminal=false\n\
         Categories=Utility;Security;\n\
         Keywords=password;passwords;passkey;vault;\n\
         StartupWMClass={ID}\n",
        exec_arg(program)
    ))
}

/// `arg` as one argument of an `Exec` key: quoted when it has a reserved
/// character, `%` doubled, then escaped as a string value.
fn exec_arg(arg: &str) -> String {
    const RESERVED: &str = " \t\n\"'\\><~|&;$*?#()`";
    let quoted = if arg.chars().any(|c| RESERVED.contains(c)) {
        let mut out = String::from('"');
        for c in arg.chars() {
            if matches!(c, '"' | '`' | '$' | '\\') {
                out.push('\\');
            }
            out.push(c);
        }
        out.push('"');
        out
    } else {
        arg.to_owned()
    };
    quoted.replace('%', "%%").replace('\\', "\\\\")
}

/// Writes the entry and its icon for this binary; run again to update them.
pub fn install() -> Result<()> {
    if cfg!(target_os = "macos") {
        println!("{MACOS}");
        return Ok(());
    }
    let files = Files::get()?;
    let program = crate::app::this_binary()?;
    files.write(&program)?;
    println!("Wrote {}", files.entry.display());
    println!("Wrote {}", files.icon.display());
    println!(
        "Deadbolt is in your app launcher; it opens with `{} app`.\n\
         Run this again if you move that binary.",
        program.display()
    );
    Ok(())
}

/// Removes the entry and its icon.
pub fn uninstall() -> Result<()> {
    if cfg!(target_os = "macos") {
        println!("{MACOS}");
        return Ok(());
    }
    let files = Files::get()?;
    let removed = files.remove()?;
    for path in &removed {
        println!("Removed {}", path.display());
    }
    if removed.is_empty() {
        println!("Deadbolt had no desktop entry.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_entry_opens_this_binarys_app_from_the_launcher() {
        assert_eq!(
            entry(Path::new("/home/kit/.local/bin/deadbolt")).unwrap(),
            "[Desktop Entry]\n\
             Type=Application\n\
             Name=Deadbolt\n\
             GenericName=Password Manager\n\
             Comment=A decentralized password manager\n\
             Exec=/home/kit/.local/bin/deadbolt app\n\
             Icon=pw.deadbolt.Deadbolt\n\
             Terminal=false\n\
             Categories=Utility;Security;\n\
             Keywords=password;passwords;passkey;vault;\n\
             StartupWMClass=pw.deadbolt.Deadbolt\n"
        );
        assert!(entry(Path::new("/bin/dead\nbolt")).is_err());
    }

    #[test]
    fn exec_paths_are_quoted_and_escaped() {
        assert_eq!(exec_arg("/usr/bin/deadbolt"), "/usr/bin/deadbolt");
        assert_eq!(
            exec_arg("/opt/my apps/deadbolt"),
            "\"/opt/my apps/deadbolt\""
        );
        assert_eq!(exec_arg("/opt/100%/deadbolt"), "/opt/100%%/deadbolt");
        // `$` is escaped inside the quotes, then the backslash as a string value.
        assert_eq!(exec_arg("/opt/$x/deadbolt"), "\"/opt/\\\\$x/deadbolt\"");
    }

    #[test]
    fn files_go_under_the_xdg_data_directory() {
        let files = Files::from_vars(|name| match name {
            "HOME" => Some("/home/kit".into()),
            _ => None,
        })
        .unwrap();
        assert_eq!(
            files.entry,
            Path::new("/home/kit/.local/share/applications/pw.deadbolt.Deadbolt.desktop")
        );
        assert_eq!(
            files.icon,
            Path::new(
                "/home/kit/.local/share/icons/hicolor/scalable/apps/pw.deadbolt.Deadbolt.svg"
            )
        );
        let xdg = Files::from_vars(|name| match name {
            "HOME" => Some("/home/kit".into()),
            "XDG_DATA_HOME" => Some("/data".into()),
            _ => None,
        })
        .unwrap();
        assert_eq!(
            xdg.entry,
            Path::new("/data/applications/pw.deadbolt.Deadbolt.desktop")
        );
    }

    #[test]
    fn installing_twice_and_uninstalling_twice_is_fine() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().to_str().unwrap().to_owned();
        let files =
            Files::from_vars(|name| (name == "XDG_DATA_HOME").then(|| data.clone())).unwrap();
        let program = Path::new("/usr/bin/deadbolt");
        files.write(program).unwrap();
        files.write(program).unwrap();
        assert_eq!(
            std::fs::read_to_string(&files.entry).unwrap(),
            entry(program).unwrap()
        );
        assert_eq!(std::fs::read_to_string(&files.icon).unwrap(), ICON);
        assert_eq!(
            files.remove().unwrap(),
            [files.entry.as_path(), files.icon.as_path()]
        );
        assert!(files.remove().unwrap().is_empty());
    }

    #[test]
    fn the_icon_is_an_svg() {
        assert!(ICON.starts_with("<svg") && ICON.trim_end().ends_with("</svg>"));
    }
}
