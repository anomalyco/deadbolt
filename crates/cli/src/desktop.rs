//! `deadbolt desktop install`: a Linux desktop entry, so app launchers list
//! Deadbolt and open it with `deadbolt app`. The app's first opening writes
//! it too (`ensure`). On macOS, Deadbolt.app is that.

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

    /// Whether there's no entry at all, not even a dangling link.
    fn missing(&self) -> bool {
        self.entry.symlink_metadata().is_err()
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

/// The desktop entry that runs `program app`. `StartupNotify` is what has
/// launchers (GLib's and KDE's) hand it an activation token, which a running
/// app needs for the compositor to let it come forward.
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
         StartupNotify=true\n\
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

/// The command a launcher entry runs for `exe` (symlinks resolved): the
/// package manager's own link to it when npm or bun installed it
/// (`<prefix>/bin/deadbolt`, bun's `~/.bun/bin/deadbolt`, or
/// `node_modules/.bin/deadbolt`), which stays put when an update or a
/// fallback moves the platform package; else `exe`.
pub fn launcher_program(exe: &Path) -> PathBuf {
    // npm nests the platform package under the wrapper's own node_modules,
    // so every node_modules up the path is a candidate; a global prefix's
    // bin first.
    let modules: Vec<&Path> = exe
        .ancestors()
        .filter(|dir| dir.file_name().is_some_and(|n| n == "node_modules"))
        .collect();
    let global = modules.iter().filter_map(|m| {
        let lib = m.parent()?;
        if lib.file_name()? == "lib" {
            return lib.parent().map(|p| p.join("bin/deadbolt"));
        }
        // bun: `<BUN_INSTALL>/install/global/node_modules`, linked from
        // `<BUN_INSTALL>/bin`.
        m.ends_with("install/global/node_modules")
            .then(|| m.ancestors().nth(3).map(|root| root.join("bin/deadbolt")))?
    });
    let local = modules.iter().map(|m| m.join(".bin/deadbolt"));
    global
        .chain(local)
        .find(|link| link.canonicalize().is_ok_and(|real| real == exe))
        .unwrap_or_else(|| exe.to_path_buf())
}

/// Writes the entry and its icon for this binary; run again to update them.
pub fn install() -> Result<()> {
    if cfg!(target_os = "macos") {
        println!("{MACOS}");
        return Ok(());
    }
    let files = Files::get()?;
    let program = launcher_program(&crate::app::this_binary()?);
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

/// The first time the app opens on Linux: writes the entry and its icon
/// for `program` unless an entry is already there, whichever binary it
/// opens (`desktop install` rewrites it). Best effort: the app opens either
/// way.
pub fn ensure(program: &Path) {
    let Ok(files) = Files::get() else { return };
    if !files.missing() {
        return;
    }
    match files.write(program) {
        Ok(()) => eprintln!(
            "Added Deadbolt to your app launcher ({}); `deadbolt desktop uninstall` removes it.",
            files.entry.display()
        ),
        Err(error) => tracing::warn!("adding Deadbolt to the app launcher: {error:#}"),
    }
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
             StartupNotify=true\n\
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
    fn the_first_opening_writes_an_entry_only_where_there_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().to_str().unwrap().to_owned();
        let files =
            Files::from_vars(|name| (name == "XDG_DATA_HOME").then(|| data.clone())).unwrap();
        assert!(files.missing());
        files.write(Path::new("/opt/other/deadbolt")).unwrap();
        assert!(!files.missing());
    }

    #[test]
    fn an_npm_install_launches_through_npms_link() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let exe = root.join(
            "lib/node_modules/@deadbolt/cli/node_modules/@deadbolt/cli-linux-x64/bin/deadbolt",
        );
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, "").unwrap();
        // Before npm links it, and outside npm: the binary itself.
        assert_eq!(launcher_program(&exe), exe);
        let elsewhere = root.join("opt/deadbolt");
        assert_eq!(launcher_program(&elsewhere), elsewhere);
        let wrapper = root.join("lib/node_modules/@deadbolt/cli/bin/deadbolt");
        std::fs::create_dir_all(wrapper.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&exe, &wrapper).unwrap();
        let bin = root.join("bin/deadbolt");
        std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&wrapper, &bin).unwrap();
        assert_eq!(launcher_program(&exe), bin);
        // A link to another deadbolt isn't this one's.
        let other = root.join("lib/node_modules/@deadbolt/cli-linux-x64-musl/bin/deadbolt");
        std::fs::create_dir_all(other.parent().unwrap()).unwrap();
        std::fs::write(&other, "").unwrap();
        assert_eq!(launcher_program(&other), other);
    }

    #[test]
    fn a_bun_install_launches_through_buns_link() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let exe = root.join("install/global/node_modules/@deadbolt/cli-linux-x64/bin/deadbolt");
        std::fs::create_dir_all(exe.parent().unwrap()).unwrap();
        std::fs::write(&exe, "").unwrap();
        assert_eq!(launcher_program(&exe), exe);
        let wrapper = root.join("install/global/node_modules/@deadbolt/cli/bin/deadbolt");
        std::fs::create_dir_all(wrapper.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&exe, &wrapper).unwrap();
        let bin = root.join("bin/deadbolt");
        std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&wrapper, &bin).unwrap();
        assert_eq!(launcher_program(&exe), bin);
    }

    #[test]
    fn the_icon_is_an_svg() {
        assert!(ICON.starts_with("<svg") && ICON.trim_end().ends_with("</svg>"));
    }
}
